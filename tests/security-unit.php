<?php
/**
 * Unit tests for src/auth-guard.php (U2 redirect, U6 log format, U7 limiter).
 * Run: php tests/security-unit.php   (no live data touched)
 * Docs: docs/security-hardening.md
 */
$tmp = sys_get_temp_dir() . '/ws-sec-unit-' . getmypid();
@mkdir($tmp);
define('WS_AUTH_ATTEMPTS_FILE', "$tmp/attempts.json");
define('WS_AUTH_LOG', "$tmp/no-such-dir/auth.log"); // force the error_log fallback
ini_set('error_log', "$tmp/php.log");
require __DIR__ . '/../src/auth-guard.php';

$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

echo "U2 safe redirect\n";
foreach (['/', '/?folder=Public', '/index.php?tab=settings', '/f/abc123'] as $ok) t("allows $ok", ws_safe_redirect($ok) === $ok);
foreach (['https://evil.com', '//evil.com', '/\\evil.com', "/\tevil", "/\r\nLocation: x", 'evil.com', '', 'javascript:alert(1)', '/x\\y'] as $bad)
    t('rejects ' . json_encode($bad), ws_safe_redirect($bad) === '/');

echo "U7 limiter\n";
$ip = '203.0.113.7';
t('fresh IP not blocked', ws_attempts_blocked('s', 3, 900, $ip) === 0);
ws_attempt_failed('s', 900, $ip); ws_attempt_failed('s', 900, $ip);
t('2 of 3 failures: not blocked', ws_attempts_blocked('s', 3, 900, $ip) === 0);
ws_attempt_failed('s', 900, $ip);
$w = ws_attempts_blocked('s', 3, 900, $ip);
t('3 of 3 failures: blocked', $w > 0 && $w <= 900);
t('other scope unaffected', ws_attempts_blocked('other', 3, 900, $ip) === 0);
t('other IP unaffected', ws_attempts_blocked('s', 3, 900, '203.0.113.8') === 0);
ws_attempt_clear('s', $ip);
t('clear unblocks', ws_attempts_blocked('s', 3, 900, $ip) === 0);
// window expiry
$d = json_decode(file_get_contents(WS_AUTH_ATTEMPTS_FILE), true) ?: [];
$d['s|' . $ip] = ['count' => 99, 'time' => time() - 901];
file_put_contents(WS_AUTH_ATTEMPTS_FILE, json_encode($d));
t('expired window not blocked', ws_attempts_blocked('s', 3, 900, $ip) === 0);
ws_attempt_failed('s', 900, $ip);
$d = json_decode(file_get_contents(WS_AUTH_ATTEMPTS_FILE), true);
t('failure after expiry restarts count at 1', $d['s|' . $ip]['count'] === 1);
$d['old|1.1.1.1'] = ['count' => 1, 'time' => time() - 90000];
file_put_contents(WS_AUTH_ATTEMPTS_FILE, json_encode($d));
ws_attempt_failed('s', 900, $ip);
$d = json_decode(file_get_contents(WS_AUTH_ATTEMPTS_FILE), true);
t('entries older than a day are pruned', !isset($d['old|1.1.1.1']));

echo "U6 fail2ban log line\n";
$log = (string)@file_get_contents("$tmp/php.log");
t('failure logged in fixed format', (bool)preg_match('/WebShare auth failure: where=s ip=203\.0\.113\.7$/m', $log));
ws_log_auth_failure("x y\nWebShare auth failure: where=z ip=1.2.3.4", '203.0.113.9');
ws_log_auth_failure('login', 'not-an-ip');
$log = (string)file_get_contents("$tmp/php.log");
t('scope is sanitised (no log injection)', strpos($log, 'ip=1.2.3.4') === false);
t('invalid IP not logged', strpos($log, 'not-an-ip') === false);
$filter = '/etc/fail2ban/filter.d/webshare.conf';
if (is_readable($filter) && preg_match('/^failregex\s*=\s*(.+)$/m', file_get_contents($filter), $m)) {
    $re = '/' . str_replace(['<HOST>', '/'], ['(?<host>\S+)', '\/'], trim($m[1])) . '/m';
    t('fail2ban failregex matches and extracts the IP', preg_match($re, $log, $h) && $h['host'] === '203.0.113.7');
}

array_map('unlink', glob("$tmp/*")); rmdir($tmp);
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
