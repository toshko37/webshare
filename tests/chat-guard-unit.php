<?php
/**
 * Chat guard unit tests (F8). Run: php tests/chat-guard-unit.php (temporary state only)
 * Docs: docs/chat-guard.md
 */
$tmp = sys_get_temp_dir() . '/ws-cg-' . getmypid();
mkdir($tmp);
define('UG_DIR', "$tmp/passes/");
define('UG_KEY_FILE', "$tmp/key");
define('UG_STATE_FILE', "$tmp/ug-state.json");
define('UG_FLAG_ON', "$tmp/flag-on");
define('UG_FLAG_CURL', "$tmp/flag-curl");
define('CG_STATE_FILE', "$tmp/cg-state.json");
require __DIR__ . '/../src/chat-guard.php';
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }
function solve() {
    $c = ug_create_challenge(['pow_maxnumber' => 2000]);
    for ($n = 0; $n <= $c['maxnumber']; $n++) if (hash('sha256', $c['salt'] . $n) === $c['challenge']) return $c + ['number' => $n];
}
$_SERVER['REMOTE_ADDR'] = '203.0.113.50';
$cfg = cg_config(['chat_guard' => ['per_ip_hour' => 3, 'max_active' => 5]]);

t('defaults', cg_defaults() === ['enabled' => true, 'per_ip_hour' => 10, 'max_active' => 300]);
t('sanitize clamps values', cg_sanitize(['enabled' => 1, 'per_ip_hour' => -4, 'max_active' => 10 ** 9]) === ['enabled' => true, 'per_ip_hour' => 1, 'max_active' => 100000]);
t('missing proof is refused', cg_check_create(null, [], $cfg)[0] === 'chat_verify_required');
t('valid proof is accepted', cg_check_create(solve(), [], $cfg) === null);
$p = solve();
cg_check_create($p, [], $cfg);
t('a proof cannot be used twice', cg_check_create($p, [], $cfg)[0] === 'chat_verify_failed');
for ($i = 0; $i < 3; $i++) cg_record_create();
t('per-IP limit after N chats', cg_check_create(solve(), [], $cfg)[0] === 'chat_ip_limit');
$_SERVER['REMOTE_ADDR'] = '203.0.113.51';
t('another IP is not affected', cg_check_create(solve(), [], $cfg) === null);
$active = array_fill(0, 5, ['expires' => time() + 100]);
t('max active chats reached', cg_check_create(solve(), $active, $cfg)[0] === 'chat_capacity');
$expired = array_fill(0, 5, ['expires' => time() - 1]);
t('expired chats do not count', cg_check_create(solve(), $expired, $cfg) === null);
t('disabled guard allows everything', cg_check_create(null, $active, cg_config(['chat_guard' => ['enabled' => false]])) === null);

exec('rm -rf ' . escapeshellarg($tmp));
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
