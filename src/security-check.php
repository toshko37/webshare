<?php
// WebShare Security Check
// Included at the top of every protected PHP file.
// Handles: session auth, remember-me, migration from .htpasswd, first-run setup.

if (!defined('USERS_FILE'))    define('USERS_FILE',    __DIR__ . '/.users.json');
if (!defined('SESSIONS_DIR'))  define('SESSIONS_DIR',  __DIR__ . '/.sessions/');
if (!defined('HTPASSWD_FILE')) define('HTPASSWD_FILE', __DIR__ . '/.htpasswd');

// Start session with secure cookie settings
if (session_status() === PHP_SESSION_NONE) {
    $__secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $__secure,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
    unset($__secure);
}

// ── Migration / first-run ──────────────────────────────────────────────────
if (!file_exists(USERS_FILE)) {
    _sc_showSetupPage();
    exit;
}

// ── Check authentication ───────────────────────────────────────────────────
function _sc_isAuthenticated() {
    // 1. Valid PHP session
    if (isset($_SESSION['username'])) {
        $sessFile = SESSIONS_DIR . session_id() . '.json';
        if (!file_exists($sessFile)) {
            // Session was revoked (Logoff ALL or closed by admin)
            session_unset();
            session_destroy();
            return false;
        }
        // Update last_active at most once per 60 s to reduce I/O
        $meta = json_decode(file_get_contents($sessFile), true) ?? [];
        if (time() - ($meta['last_active'] ?? 0) > 60) {
            $meta['last_active'] = time();
            file_put_contents($sessFile, json_encode($meta, JSON_PRETTY_PRINT), LOCK_EX);
        }
        return true;
    }

    // 2. Remember-me cookie
    if (isset($_COOKIE['ws_remember'])) {
        return _sc_tryRememberMe($_COOKIE['ws_remember']);
    }

    return false;
}

function _sc_tryRememberMe($token) {
    $tokenHash = hash('sha256', $token);
    if (!is_dir(SESSIONS_DIR)) return false;

    foreach (glob(SESSIONS_DIR . '*.json') as $file) {
        $meta = json_decode(file_get_contents($file), true);
        if (!$meta || !isset($meta['remember_token'])) continue;
        if (!hash_equals($meta['remember_token'], $tokenHash)) continue;
        if (($meta['remember_expires'] ?? 0) <= time()) break;

        // Restore session
        session_regenerate_id(true);
        $_SESSION['username']   = $meta['username'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        unlink($file);

        $newMeta = [
            'username'         => $meta['username'],
            'ip'               => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent'       => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'created'          => time(),
            'last_active'      => time(),
            'remember_me'      => true,
            'remember_token'   => $tokenHash,
            'remember_expires' => $meta['remember_expires']
        ];
        file_put_contents(SESSIONS_DIR . session_id() . '.json', json_encode($newMeta, JSON_PRETTY_PRINT), LOCK_EX);
        return true;
    }
    return false;
}

if (!_sc_isAuthenticated()) {
    $redirect = urlencode($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: /login.php?redirect=' . $redirect);
    exit;
}

// Ensure CSRF token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Migration / first-run setup page ──────────────────────────────────────
function _sc_showSetupPage() {
    $hasHtpasswd = file_exists(HTPASSWD_FILE);
    $htUsers = [];
    if ($hasHtpasswd) {
        foreach (file(HTPASSWD_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) $htUsers[] = $parts[0];
        }
    }

    // Handle POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['action']) && $_POST['action'] === 'migrate' && !empty($htUsers)) {
            _sc_handleMigration($htUsers);
            return;
        }
        if (isset($_POST['action']) && $_POST['action'] === 'setup') {
            _sc_handleFirstRun();
            return;
        }
    }

    if ($hasHtpasswd && !empty($htUsers)) {
        _sc_renderMigrationForm($htUsers);
    } else {
        _sc_renderSetupForm();
    }
}

function _sc_handleMigration($htUsers) {
    $users = [];
    foreach ($htUsers as $i => $user) {
        $pass = $_POST['pass_' . $user] ?? '';
        if (strlen($pass) < 4) {
            _sc_renderMigrationForm($htUsers, "Паролата за \"$user\" трябва да е поне 4 символа.");
            return;
        }
        $users[$user] = [
            'password_hash' => password_hash($pass, PASSWORD_BCRYPT, ['cost' => 12]),
            'role'          => ($i === 0) ? 'admin' : 'user',
            'created'       => time()
        ];
    }
    if (!is_dir(SESSIONS_DIR)) mkdir(SESSIONS_DIR, 0700, true);
    file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT), LOCK_EX);
    if (file_exists(HTPASSWD_FILE)) unlink(HTPASSWD_FILE);
    header('Location: /login.php');
    exit;
}

function _sc_handleFirstRun() {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
        _sc_renderSetupForm('Невалидно потребителско име (3-20 знака, a-z 0-9 - _)');
        return;
    }
    if (strlen($password) < 4) {
        _sc_renderSetupForm('Паролата трябва да е поне 4 символа.');
        return;
    }
    $users = [$username => [
        'password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'role'          => 'admin',
        'created'       => time()
    ]];
    if (!is_dir(SESSIONS_DIR)) mkdir(SESSIONS_DIR, 0700, true);
    file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT), LOCK_EX);
    header('Location: /login.php');
    exit;
}

function _sc_pageHeader($title) {
    echo '<!DOCTYPE html><html lang="bg"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>' . $title . '</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:"Segoe UI",sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);
             min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
        .card{background:white;border-radius:12px;padding:36px;width:100%;max-width:460px;
              box-shadow:0 20px 60px rgba(0,0,0,.3)}
        h1{font-size:22px;color:#333;margin-bottom:6px}
        p.sub{color:#666;font-size:14px;margin-bottom:24px;line-height:1.5}
        .group{margin-bottom:16px}
        label{display:block;font-size:13px;font-weight:600;color:#555;margin-bottom:5px}
        input[type=text],input[type=password]{width:100%;padding:10px 13px;border:1.5px solid #ddd;
               border-radius:8px;font-size:14px;outline:none}
        input:focus{border-color:#667eea}
        .btn{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);
             color:white;border:none;border-radius:8px;font-size:15px;font-weight:600;
             cursor:pointer;margin-top:8px}
        .btn:hover{opacity:.9}
        .error{background:#fee2e2;border:1px solid #fca5a5;color:#dc2626;
               padding:10px 13px;border-radius:8px;margin-bottom:16px;font-size:13px}
        .user-block{background:#f8f8f8;border:1px solid #eee;border-radius:8px;
                    padding:14px 16px;margin-bottom:12px}
        .user-block strong{display:block;margin-bottom:8px;color:#333}
    </style></head><body><div class="card">';
}

function _sc_renderMigrationForm($users, $error = '') {
    _sc_pageHeader('WebShare – Миграция');
    echo '<h1>🔄 Миграция на потребители</h1>';
    echo '<p class="sub">Открити са потребители от стария .htpasswd. Задайте нови пароли за всеки, за да завършите прехода.</p>';
    if ($error) echo '<div class="error">' . htmlspecialchars($error) . '</div>';
    echo '<form method="POST"><input type="hidden" name="action" value="migrate">';
    foreach ($users as $u) {
        echo '<div class="user-block"><strong>👤 ' . htmlspecialchars($u) . '</strong>';
        echo '<div class="group"><label>Нова парола</label>';
        echo '<input type="password" name="pass_' . htmlspecialchars($u) . '" required minlength="4" placeholder="Минимум 4 знака"></div></div>';
    }
    echo '<button class="btn" type="submit">Завърши миграцията →</button></form></div></body></html>';
}

function _sc_renderSetupForm($error = '') {
    _sc_pageHeader('WebShare – Първоначална настройка');
    echo '<h1>🛠️ Начална настройка</h1>';
    echo '<p class="sub">Създайте администраторски акаунт за достъп до WebShare.</p>';
    if ($error) echo '<div class="error">' . htmlspecialchars($error) . '</div>';
    echo '<form method="POST"><input type="hidden" name="action" value="setup">';
    echo '<div class="group"><label>Потребителско Име</label>';
    echo '<input type="text" name="username" value="' . htmlspecialchars($_POST['username'] ?? '') . '" required autofocus pattern="[a-zA-Z0-9_-]{3,20}"></div>';
    echo '<div class="group"><label>Парола</label>';
    echo '<input type="password" name="password" required minlength="4"></div>';
    echo '<button class="btn" type="submit">Създай акаунт →</button></form></div></body></html>';
}
