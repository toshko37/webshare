<?php
// WebShare Login Page
// No security-check.php here - this IS the login page

if (session_status() === PHP_SESSION_NONE) {
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
}

define('USERS_FILE', __DIR__ . '/.users.json');
define('SESSIONS_DIR', __DIR__ . '/.sessions/');
define('LOGIN_ATTEMPTS_FILE', __DIR__ . '/.login-attempts.json');
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_SECONDS', 900); // 15 min

function loadUsers() {
    if (!file_exists(USERS_FILE)) return [];
    return json_decode(file_get_contents(USERS_FILE), true) ?? [];
}

function _loginGetClientIp() {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function checkRateLimit($ip) {
    if (!file_exists(LOGIN_ATTEMPTS_FILE)) return true;
    $data = json_decode(file_get_contents(LOGIN_ATTEMPTS_FILE), true) ?? [];
    $entry = $data[$ip] ?? null;
    if (!$entry) return true;
    if (time() - $entry['time'] > LOCKOUT_SECONDS) return true;
    return $entry['count'] < MAX_LOGIN_ATTEMPTS;
}

function getLockoutRemaining($ip) {
    if (!file_exists(LOGIN_ATTEMPTS_FILE)) return 0;
    $data = json_decode(file_get_contents(LOGIN_ATTEMPTS_FILE), true) ?? [];
    $entry = $data[$ip] ?? null;
    if (!$entry) return 0;
    $remaining = LOCKOUT_SECONDS - (time() - $entry['time']);
    return max(0, $remaining);
}

function recordFailedAttempt($ip) {
    $data = file_exists(LOGIN_ATTEMPTS_FILE)
        ? (json_decode(file_get_contents(LOGIN_ATTEMPTS_FILE), true) ?? [])
        : [];
    $entry = $data[$ip] ?? ['count' => 0, 'time' => time()];
    if (time() - $entry['time'] > LOCKOUT_SECONDS) {
        $entry = ['count' => 0, 'time' => time()];
    }
    $entry['count']++;
    $entry['time'] = time();
    $data[$ip] = $entry;
    file_put_contents(LOGIN_ATTEMPTS_FILE, json_encode($data), LOCK_EX);
}

function clearRateLimit($ip) {
    if (!file_exists(LOGIN_ATTEMPTS_FILE)) return;
    $data = json_decode(file_get_contents(LOGIN_ATTEMPTS_FILE), true) ?? [];
    unset($data[$ip]);
    file_put_contents(LOGIN_ATTEMPTS_FILE, json_encode($data), LOCK_EX);
}

function createSession($username, $rememberMe, $ip, $userAgent) {
    session_regenerate_id(true);
    $_SESSION['username'] = $username;
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    if (!is_dir(SESSIONS_DIR)) {
        mkdir(SESSIONS_DIR, 0700, true);
    }

    $meta = [
        'username'    => $username,
        'ip'          => $ip,
        'user_agent'  => $userAgent,
        'created'     => time(),
        'last_active' => time(),
        'remember_me' => $rememberMe
    ];

    if ($rememberMe) {
        $rememberToken = bin2hex(random_bytes(32));
        $meta['remember_token']   = hash('sha256', $rememberToken);
        $meta['remember_expires'] = time() + 30 * 24 * 3600;
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
        setcookie('ws_remember', $rememberToken, [
            'expires'  => time() + 30 * 24 * 3600,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }

    file_put_contents(SESSIONS_DIR . session_id() . '.json', json_encode($meta, JSON_PRETTY_PRINT), LOCK_EX);
}

function tryRememberMe() {
    if (!isset($_COOKIE['ws_remember'])) return false;
    $token = $_COOKIE['ws_remember'];
    $tokenHash = hash('sha256', $token);
    if (!is_dir(SESSIONS_DIR)) return false;

    foreach (glob(SESSIONS_DIR . '*.json') as $file) {
        $meta = json_decode(file_get_contents($file), true);
        if (!$meta || !isset($meta['remember_token'])) continue;
        if (!hash_equals($meta['remember_token'], $tokenHash)) continue;
        if (($meta['remember_expires'] ?? 0) <= time()) break;

        // Valid remember-me → restore session
        session_regenerate_id(true);
        $_SESSION['username']   = $meta['username'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        unlink($file);

        $newMeta = [
            'username'        => $meta['username'],
            'ip'              => _loginGetClientIp(),
            'user_agent'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'created'         => time(),
            'last_active'     => time(),
            'remember_me'     => true,
            'remember_token'  => $tokenHash,
            'remember_expires'=> $meta['remember_expires']
        ];
        file_put_contents(SESSIONS_DIR . session_id() . '.json', json_encode($newMeta, JSON_PRETTY_PRINT), LOCK_EX);
        return true;
    }
    return false;
}

// Already logged in?
if (isset($_SESSION['username']) && file_exists(SESSIONS_DIR . session_id() . '.json')) {
    header('Location: ' . ($_GET['redirect'] ?? '/'));
    exit;
}

// Remember-me auto-login
if (!isset($_SESSION['username']) && tryRememberMe()) {
    header('Location: ' . ($_GET['redirect'] ?? '/'));
    exit;
}

$error = '';
$ip = _loginGetClientIp();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username   = trim($_POST['username'] ?? '');
    $password   = $_POST['password'] ?? '';
    $rememberMe = isset($_POST['remember_me']);

    if (!checkRateLimit($ip)) {
        $mins = ceil(getLockoutRemaining($ip) / 60);
        $error = "Твърде много неуспешни опити. Изчакайте $mins мин.";
    } elseif (empty($username) || empty($password)) {
        $error = 'Въведете потребителско име и парола.';
    } else {
        $users = loadUsers();
        if (isset($users[$username]) && password_verify($password, $users[$username]['password_hash'])) {
            clearRateLimit($ip);
            createSession($username, $rememberMe, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '');
            require_once __DIR__ . '/audit-log.php';
            writeAuditLog('login', "User logged in from $ip");
            header('Location: ' . ($_GET['redirect'] ?? '/'));
            exit;
        } else {
            recordFailedAttempt($ip);
            $error = 'Невалидно потребителско име или парола.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShare - Вход</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 40px;
            width: 100%;
            max-width: 380px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 { font-size: 28px; color: #333; font-weight: 700; }
        .logo p  { color: #888; font-size: 14px; margin-top: 4px; }
        .form-group { margin-bottom: 18px; }
        label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #555;
            margin-bottom: 6px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 11px 14px;
            border: 1.5px solid #ddd;
            border-radius: 8px;
            font-size: 15px;
            transition: border-color 0.2s;
            outline: none;
        }
        input[type="text"]:focus,
        input[type="password"]:focus { border-color: #667eea; }
        .remember-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 22px;
        }
        .remember-row label {
            margin: 0;
            font-weight: normal;
            color: #555;
            cursor: pointer;
        }
        input[type="checkbox"] {
            width: 16px;
            height: 16px;
            cursor: pointer;
            accent-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 13px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .error {
            background: #fee2e2;
            border: 1px solid #fca5a5;
            color: #dc2626;
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 18px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <h1>📁 WebShare</h1>
            <p>Влезте в системата</p>
        </div>
        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="POST">
            <div class="form-group">
                <label for="username">Потребителско Име</label>
                <input type="text" id="username" name="username"
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                       autofocus autocomplete="username" required>
            </div>
            <div class="form-group">
                <label for="password">Парола</label>
                <input type="password" id="password" name="password"
                       autocomplete="current-password" required>
            </div>
            <div class="remember-row">
                <input type="checkbox" id="remember_me" name="remember_me">
                <label for="remember_me">Помни ме (30 дни)</label>
            </div>
            <button type="submit" class="btn">Вход →</button>
        </form>
    </div>
</body>
</html>
