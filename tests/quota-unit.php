<?php
/**
 * Quota unit tests (F1). Run: php tests/quota-unit.php  (temporary directories only)
 * Docs: docs/quotas.md
 */
$tmp = sys_get_temp_dir() . '/ws-quota-' . getmypid();
foreach (['files/alice/sub', 'files/bob', 'files/_public', 'data'] as $d) mkdir("$tmp/$d", 0700, true);
define('FILES_BASE_DIR', "$tmp/files/");
define('WS_DATA_DIR', "$tmp/data/");
define('USERS_FILE', "$tmp/data/users.json");
file_put_contents(USERS_FILE, json_encode(['admin' => ['role' => 'admin'], 'alice' => ['role' => 'user', 'quota_mb' => 1], 'bob' => ['role' => 'user']]));
file_put_contents("$tmp/data/.config.json", json_encode(['default_quota_mb' => 0]));
require __DIR__ . '/../src/quota.php';
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

file_put_contents("$tmp/files/alice/a.bin", str_repeat('x', 600000));
file_put_contents("$tmp/files/alice/sub/b.bin", str_repeat('x', 300000));
t('usage counts subfolders', quota_usage('alice') === 900000);
t('per-user quota', quota_mb('alice') === 1);
t('no quota, no default: unlimited', quota_mb('bob') === 0 && quota_check('bob', 10 ** 12) === null);
t('upload that fits is allowed', quota_check('alice', 100000) === null);
t('upload that does not fit is refused', is_string(quota_check('alice', 200000)));
t('subfolder uploads count to the owner', is_string(quota_check('alice/sub', 200000)));
t('Public folder has no quota', quota_check('_public', 10 ** 12) === null);
t('unknown folder has no owner', quota_owner('ghost') === null);
file_put_contents("$tmp/data/.config.json", json_encode(['default_quota_mb' => 2]));
t('site default applies to users without their own value', quota_mb('bob') === 2);
t('explicit 0 means unlimited even with a default', quota_set('alice', 0) && quota_mb('alice') === 0);
t('null returns the user to the default', quota_set('alice', null) && quota_mb('alice') === 2);
t('unknown user cannot get a quota', quota_set('ghost', 5) === false);
$i = quota_info('alice');
t('quota_info percent', $i['quota'] === 2 * 1048576 && $i['percent'] === (int)round(900000 * 100 / (2 * 1048576)));

exec('rm -rf ' . escapeshellarg($tmp));
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
