<?php
/**
 * Upload guard unit tests (docs/upload-guard.md). Run: php tests/upload-guard-unit.php
 * Uses a temporary directory, never touches live passes or config.
 */
$tmp = sys_get_temp_dir() . '/ugtest-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700, true);
define('UG_DIR', "$tmp/passes/");
define('UG_KEY_FILE', "$tmp/key");
define('UG_STATE_FILE', "$tmp/state.json");
define('UG_FLAG_ON', "$tmp/flag-on");
define('UG_FLAG_CURL', "$tmp/flag-curl");
require __DIR__ . '/../src/upload-guard.php';

$pass = 0; $fail = 0;
function t($name, $cond) { global $pass, $fail; if ($cond) { $pass++; echo "  PASS  $name\n"; } else { $fail++; echo "  FAIL  $name\n"; } }
function issue($cfg) { $_SERVER['REMOTE_ADDR'] = '203.0.113.' . random_int(1, 250); return @ug_issue_pass($cfg, 'pow'); }

echo "== Config\n";
$c = ug_config([]);
t('default mode is verified', $c['mode'] === 'verified');
t('legacy open_upload=false maps to login', ug_config(['open_upload' => false])['mode'] === 'login');
t('explicit mode wins over legacy flag', ug_config(['open_upload' => false, 'upload_guard' => ['mode' => 'open']])['mode'] === 'open');
t('turnstile without keys falls back to pow', ug_config(['upload_guard' => ['provider' => 'turnstile']])['provider_effective'] === 'pow');
$s = ug_sanitize_config(['pass_max_files' => '-5', 'max_file_mb' => '999999', 'mode' => 'evil', 'x' => 1], ug_defaults());
t('sanitize clamps minimum', $s['pass_max_files'] === 1);
t('sanitize clamps maximum', $s['max_file_mb'] === 10240);
t('sanitize ignores invalid mode', $s['mode'] === 'verified');
t('sanitize drops unknown keys', !isset($s['x']));
$s = ug_sanitize_config(['turnstile_secret' => ''], ['turnstile_secret' => 'keep'] + ug_defaults());
t('empty secret keeps stored secret', $s['turnstile_secret'] === 'keep');

echo "== Flags\n";
ug_sync_flags(['mode' => 'verified', 'curl_without_pass' => true]);
t('verified creates pre-filter flag', file_exists(UG_FLAG_ON));
t('curl_without_pass creates curl flag', file_exists(UG_FLAG_CURL));
ug_sync_flags(['mode' => 'open', 'curl_without_pass' => true]);
t('open mode removes both flags', !file_exists(UG_FLAG_ON) && !file_exists(UG_FLAG_CURL));

echo "== Proof-of-work\n";
$ch = ug_create_challenge($c);
$n = null;
for ($i = 0; $i <= $ch['maxnumber']; $i++) { if (hash('sha256', $ch['salt'] . $i) === $ch['challenge']) { $n = $i; break; } }
$sol = ['salt' => $ch['salt'], 'number' => $n, 'challenge' => $ch['challenge'], 'signature' => $ch['signature']];
t('tampered signature rejected', ug_verify_pow(['signature' => str_repeat('0', 64)] + $sol) === 'bad_signature');
t('valid solution accepted', ug_verify_pow($sol) === true);
t('replay rejected', ug_verify_pow($sol) === 'replayed');
$salt = 'aa?expires=' . (time() - 1); $chal = hash('sha256', $salt . '1');
t('expired challenge rejected', ug_verify_pow(['salt' => $salt, 'number' => 1, 'challenge' => $chal, 'signature' => hash_hmac('sha256', $chal, ug_secret())]) === 'expired');
t('malformed payload rejected', ug_verify_pow([]) === 'malformed');

echo "== Passes\n";
$p = issue($c);
t('code has 8 symbols from the alphabet', (bool)preg_match('/^[' . UG_CODE_ALPHABET . ']{8}$/', $p['code']));
t('lookup by code works with dash and lowercase', ug_load_pass_by_code(strtolower(ug_format_code($p['code'])))['id'] === $p['id']);
$_SERVER['HTTP_X_UPLOAD_PASS'] = ug_format_code($p['code']);
$_SERVER['REQUEST_TIME'] = time();
[$cur, $why] = ug_current_pass();
t('header code is accepted', $cur && $cur['id'] === $p['id']);
// Expiry is checked against the request start
ug_locked_update(ug_pass_file($p['id']), function (&$x) { $x['expires'] = time() - 10; });
$_SERVER['REQUEST_TIME'] = time() - 60;
[$cur] = ug_current_pass();
t('pass valid at request start is accepted', $cur !== null);
$_SERVER['REQUEST_TIME'] = time();
[$cur, $why] = ug_current_pass();
t('expired pass rejected with reason', $cur === null && $why === 'expired');
$p2 = issue($c);
ug_revoke_pass($p2['id']);
$_SERVER['HTTP_X_UPLOAD_PASS'] = $p2['code'];
[$cur, $why] = ug_current_pass();
t('revoked pass rejected with reason', $cur === null && $why === 'revoked');
unset($_SERVER['HTTP_X_UPLOAD_PASS']);
$_COOKIE = [];
[$cur, $why] = ug_current_pass();
t('no pass gives reason missing', $cur === null && $why === 'missing');

echo "== Per-IP limit\n";
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
$lim = ['passes_per_ip_hour' => 2] + $c;
@ug_issue_pass($lim, 'pow'); @ug_issue_pass($lim, 'pow');
t('limit reached after N passes', ug_ip_may_verify($lim) === 'ip_pass_limit');
$_SERVER['REMOTE_ADDR'] = '198.51.100.8';
t('other IP is not affected', ug_ip_may_verify($lim) === true);
for ($i = 0; $i < 30; $i++) ug_record_failure();
t('30 failures block the IP', ug_ip_may_verify($lim) === 'ip_fail_limit');

echo "== Upload checks\n";
$dir = "$tmp/files/"; mkdir($dir . '_public', 0700, true);
$q = ['pass_max_files' => 2, 'pass_max_mb' => 1, 'max_file_mb' => 1, 'daily_cap_mb' => 3, 'min_free_gb' => 0] + $c;
$p3 = issue($q);
t('normal file allowed', ug_check_upload($q, $p3, 1000, 'report.pdf', $dir) === null);
foreach (['x.php', 'x.PHP', 'x.php.jpg', '.htaccess', '.user.ini', 'a.phtml', 'b.phar'] as $bad) {
    t("blocked: $bad", (ug_check_upload($q, $p3, 10, $bad, $dir)[0] ?? '') === 'blocked_type');
}
t('allowed: php-notes.txt', ug_check_upload($q, $p3, 10, 'php-notes.txt', $dir) === null);
t('file over max size rejected', (ug_check_upload($q, $p3, 2 * 1048576, 'big.bin', $dir)[0] ?? '') === 'file_too_large');
file_put_contents($dir . '_public/a.txt', 'a'); file_put_contents($dir . '_public/b.txt', 'b');
$p3 = ug_record_upload($p3, 'a.txt', 'a.txt', '_public', 600000);
t('pass size quota enforced', (ug_check_upload($q, $p3, 600000, 'c.txt', $dir)[0] ?? '') === 'quota_bytes');
$p3 = ug_record_upload($p3, 'b.txt', 'b.txt', '_public', 1);
t('pass file quota enforced', (ug_check_upload($q, $p3, 1, 'c.txt', $dir)[0] ?? '') === 'quota_files');
$p4 = issue($q);
ug_record_upload(null, 'x', 'x', '_public', 3 * 1048576);
t('daily cap enforced', (ug_check_upload($q, $p4, 1000, 'd.txt', $dir)[0] ?? '') === 'daily_cap');
t('disk floor enforced', (ug_check_upload(['min_free_gb' => 100000, 'daily_cap_mb' => 999999] + $q, $p4, 1, 'e.txt', $dir)[0] ?? '') === 'disk_low');

echo "== Stop button\n";
t('foreign pass cannot delete', ug_delete_recent($p4, 'a.txt', "$tmp/files") === null && file_exists($dir . '_public/a.txt'));
t('own pass deletes its file', ug_delete_recent($p3, 'a.txt', "$tmp/files") === 'a.txt' && !file_exists($dir . '_public/a.txt'));
t('quota refunded after delete', ug_load_pass($p3['id'])['bytes'] === 1);
t('null pass deletes nothing', ug_delete_recent(null, 'b.txt', "$tmp/files") === null);

echo "== Cleanup\n";
ug_locked_update(ug_pass_file($p4['id']), function (&$x) { $x['expires'] = time() - 8 * 86400; });
t('old passes removed', ug_cleanup() >= 1 && ug_load_pass($p4['id']) === null);

exec('rm -rf ' . escapeshellarg($tmp));
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
