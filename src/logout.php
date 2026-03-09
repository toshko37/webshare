<?php
// WebShare Logout

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

define('SESSIONS_DIR', __DIR__ . '/.sessions/');

$sessFile = SESSIONS_DIR . session_id() . '.json';
if (file_exists($sessFile)) {
    $meta = json_decode(file_get_contents($sessFile), true) ?? [];
    if (!empty($meta['remember_me'])) {
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
        setcookie('ws_remember', '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
    unlink($sessFile);
}

if (isset($_SESSION['username'])) {
    require_once __DIR__ . '/audit-log.php';
    writeAuditLog('logout', 'User logged out');
}

$_SESSION = [];
session_destroy();

header('Location: /login.php');
exit;
