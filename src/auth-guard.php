<?php
/**
 * Brute-force protection for anonymous password forms and a fail2ban hook.
 * Docs: docs/security-hardening.md (repository root, not served)
 *
 * - ws_attempts_blocked() / ws_attempt_failed() / ws_attempt_clear(): per-IP
 *   failure counters in a sliding window, one JSON file, flock-protected.
 * - ws_log_auth_failure(): one line per failure in the PHP error log
 *   (FPM pool: /var/log/fpm-php.webshare.log), read by the fail2ban jail
 *   "webshare". Format is fixed; the fail2ban filter depends on it:
 *   "WebShare auth failure: where=<scope> ip=<ip>"
 */

if (!defined('WS_AUTH_ATTEMPTS_FILE')) {
    define('WS_AUTH_ATTEMPTS_FILE', __DIR__ . '/.auth-attempts.json');
}

function ws_auth_client_ip() {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/** Run $fn on the decoded attempts file under an exclusive lock; $fn returns [newData, result] */
function ws_attempts_update(callable $fn) {
    $fh = @fopen(WS_AUTH_ATTEMPTS_FILE, 'c+');
    if (!$fh) {
        return $fn([])[1]; // storage unavailable: fail open, the form still works
    }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $data = json_decode($raw ?: '[]', true) ?: [];
    // Drop entries older than a day so the file stays small
    $now = time();
    foreach ($data as $k => $e) {
        if (!isset($e['time']) || $now - $e['time'] > 86400) unset($data[$k]);
    }
    [$data, $result] = $fn($data);
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

/** Seconds until the key may try again, 0 when not blocked */
function ws_attempts_blocked($scope, $max, $window, $ip = null) {
    $key = $scope . '|' . ($ip ?? ws_auth_client_ip());
    $data = @json_decode((string)@file_get_contents(WS_AUTH_ATTEMPTS_FILE), true) ?: [];
    $e = $data[$key] ?? null;
    if (!$e || time() - $e['time'] > $window || $e['count'] < $max) return 0;
    return max(1, $window - (time() - $e['time']));
}

function ws_attempt_failed($scope, $window, $ip = null) {
    $ip = $ip ?? ws_auth_client_ip();
    $key = $scope . '|' . $ip;
    ws_attempts_update(function ($data) use ($key, $window) {
        $e = $data[$key] ?? null;
        if (!$e || time() - $e['time'] > $window) $e = ['count' => 0, 'time' => time()];
        $e['count']++;
        $e['time'] = time();
        $data[$key] = $e;
        return [$data, null];
    });
    ws_log_auth_failure($scope, $ip);
}

function ws_attempt_clear($scope, $ip = null) {
    $key = $scope . '|' . ($ip ?? ws_auth_client_ip());
    ws_attempts_update(function ($data) use ($key) {
        unset($data[$key]);
        return [$data, null];
    });
}

/** fail2ban hook, see the header for the format */
function ws_log_auth_failure($where, $ip = null) {
    $ip = $ip ?? ws_auth_client_ip();
    $where = preg_replace('/[^a-z0-9_-]/i', '', (string)$where);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
    error_log("WebShare auth failure: where=$where ip=$ip");
}

/**
 * U2: only same-site relative paths may be used as a post-login redirect.
 * Rejects absolute URLs, scheme-relative "//host", "/\\host" and control characters.
 */
function ws_safe_redirect($dest, $fallback = '/') {
    $dest = (string)$dest;
    if ($dest === '' || $dest[0] !== '/' || (isset($dest[1]) && ($dest[1] === '/' || $dest[1] === '\\'))
        || preg_match('/[\x00-\x1F\x7F\\\\]/', $dest)) {
        return $fallback;
    }
    return $dest;
}
