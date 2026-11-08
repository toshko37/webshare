<?php
/**
 * Trash unit tests (F2). Run: php tests/trash-unit.php  (temporary directories only)
 * Docs: docs/trash.md
 */
$tmp = sys_get_temp_dir() . '/ws-trash-' . getmypid();
foreach (['files/alice/sub', 'files/bob', 'files/_public', 'data', 'trash'] as $d) mkdir("$tmp/$d", 0700, true);
define('FILES_BASE_DIR', "$tmp/files/");
define('WS_TRASH_DIR', "$tmp/trash/");
define('WS_DATA_DIR', "$tmp/data/");
define('USERS_FILE', "$tmp/data/users.json");
file_put_contents(USERS_FILE, json_encode(['admin' => ['role' => 'admin'], 'alice' => ['role' => 'user'], 'bob' => ['role' => 'user']]));
file_put_contents("$tmp/data/.config.json", json_encode(['trash_days' => 30]));
require __DIR__ . '/../src/trash.php';

$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

// Fixtures: a shared, encrypted file with metadata
file_put_contents("$tmp/files/alice/report.pdf", 'PDF-DATA');
file_put_contents("$tmp/files/alice/sub/secret.txt.enc", 'ENC');
file_put_contents("$tmp/files/bob/report.pdf", 'BOB');
file_put_contents("$tmp/data/.tokens.json", json_encode([
    'tokA' => ['filename' => 'report.pdf', 'folder' => 'alice', 'created' => 1],
    'tokB' => ['filename' => 'report.pdf', 'folder' => 'bob', 'created' => 1]]));
file_put_contents("$tmp/data/.files-meta.json", json_encode(['alice/report.pdf' => ['uploader' => 'alice']]));
file_put_contents("$tmp/data/.encryption-keys.json", json_encode(['alice/sub/secret.txt.enc' => ['created_by' => 'alice']]));

echo "move to trash\n";
$r = trash_move_file('alice', 'report.pdf', 'alice');
t('file moved', $r['success'] && !file_exists("$tmp/files/alice/report.pdf") && is_file("$tmp/trash/{$r['id']}"));
$tok = ws_json_read("$tmp/data/.tokens.json");
t('its share link is detached', !isset($tok['tokA']));
t("bob's same-named file and link untouched", isset($tok['tokB']) && is_file("$tmp/files/bob/report.pdf"));
t('file metadata detached', !isset(ws_json_read("$tmp/data/.files-meta.json")['alice/report.pdf']));
$r2 = trash_move_file('alice/sub', 'secret.txt.enc', 'alice');
t('encryption metadata detached', $r2['success'] && !isset(ws_json_read("$tmp/data/.encryption-keys.json")['alice/sub/secret.txt.enc']));
t('missing file reports an error', !trash_move_file('alice', 'nope.txt', 'alice')['success']);

echo "visibility\n";
t('alice sees her 2 items', count(trash_list('alice')) === 2);
t('bob sees none of them', count(trash_list('bob')) === 0);
t('admin sees all', count(trash_list('admin')) === 2);
t('bob cannot restore alice\'s file', !trash_restore($r['id'], 'bob')['success']);
t('bob cannot delete alice\'s file', !trash_delete($r['id'], 'bob')['success']);
file_put_contents("$tmp/files/_public/p.txt", 'x');
$rp = trash_move_file('_public', 'p.txt', 'bob');
t('Public file deleted by bob: bob sees it', count(trash_list('bob')) === 1);
t('Public file deleted by bob: alice does not', count(trash_list('alice')) === 2);

echo "restore\n";
$res = trash_restore($r['id'], 'alice');
t('file back in place with content', $res['success'] && file_get_contents("$tmp/files/alice/report.pdf") === 'PDF-DATA');
t('share link restored', (ws_json_read("$tmp/data/.tokens.json")['tokA']['folder'] ?? '') === 'alice');
t('metadata restored', isset(ws_json_read("$tmp/data/.files-meta.json")['alice/report.pdf']));
$r3 = trash_move_file('alice', 'report.pdf', 'alice');
file_put_contents("$tmp/files/alice/report.pdf", 'NEW');
$res = trash_restore($r3['id'], 'alice');
t('name taken: restored as "report (restored).pdf"', $res['success'] && $res['name'] === 'report (restored).pdf' && file_get_contents("$tmp/files/alice/report.pdf") === 'NEW');
t('restored share link follows the new name', (ws_json_read("$tmp/data/.tokens.json")['tokA']['filename'] ?? '') === 'report (restored).pdf');
$res = trash_restore($r2['id'], 'alice');
t('encryption metadata restored', $res['success'] && isset(ws_json_read("$tmp/data/.encryption-keys.json")['alice/sub/secret.txt.enc']));

echo "folders (deleted user)\n";
$rf = trash_move_folder('bob', 'admin', 'User bob');
t('folder moved', $rf['success'] && !is_dir("$tmp/files/bob") && is_dir("$tmp/trash/{$rf['id']}"));
t('only admin sees a folder item', count(array_filter(trash_list('admin'), fn($i) => $i['type'] === 'folder')) === 1 && count(trash_list('bob')) === 1);
$res = trash_restore($rf['id'], 'admin');
t('folder restored with its files', $res['success'] && file_get_contents("$tmp/files/bob/report.pdf") === 'BOB');

echo "delete, purge, off\n";
$rd = trash_move_file('alice', 'report.pdf', 'alice');
t('delete permanently removes the data', trash_delete($rd['id'], 'alice')['success'] && !file_exists("$tmp/trash/{$rd['id']}"));
$old = trash_move_file('alice', 'report (restored).pdf', 'alice');
ws_json_update(WS_TRASH_INDEX, function (&$a) use ($old) { $a[$old['id']]['deleted_at'] = time() - 31 * 86400; });
t('purge removes items older than trash_days', trash_purge(true) === 1 && !file_exists("$tmp/trash/{$old['id']}"));
t('purge is throttled to once an hour', trash_purge() === 0);
t('empty removes everything visible', trash_empty('admin') >= 1 && count(trash_list('admin')) === 0);
file_put_contents("$tmp/data/.config.json", json_encode(['trash_days' => 0]));
file_put_contents("$tmp/files/alice/gone.txt", 'x');
$r0 = trash_move_file('alice', 'gone.txt', 'alice');
t('trash off: file deleted immediately', $r0['success'] && $r0['id'] === null && !file_exists("$tmp/files/alice/gone.txt"));

exec('rm -rf ' . escapeshellarg($tmp));
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
