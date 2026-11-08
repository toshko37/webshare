<?php
/**
 * Concurrency test for src/json-store.php (I4): parallel processes must not lose updates.
 * Run: php tests/json-store-test.php
 * Docs: docs/security-plan-2.md
 */
$tmp = sys_get_temp_dir() . '/ws-json-' . getmypid();
mkdir($tmp);
$lib = realpath(__DIR__ . '/../src/json-store.php');
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

// Runs $code in $n parallel PHP processes, $iter times each
function parallel($n, $iter, $code) {
    $procs = [];
    for ($i = 0; $i < $n; $i++) {
        $procs[] = proc_open([PHP_BINARY, '-r', "for (\$k = 0; \$k < $iter; \$k++) { $code }"], [], $pipes);
    }
    foreach ($procs as $p) proc_close($p);
}
$N = 8; $ITER = 50; $EXPECT = $N * $ITER;

require $lib;
echo "ws_json_update: $N processes x $ITER updates\n";
$f = "$tmp/a.json";
parallel($N, $ITER, "require '$lib'; ws_json_update('$f', function (&\$d) { \$d['n'] = (\$d['n'] ?? 0) + 1; \$d['k'][] = getmypid(); });");
$d = ws_json_read($f);
t("counter is exactly $EXPECT", ($d['n'] ?? 0) === $EXPECT);
t("all $EXPECT appended items are kept", count($d['k'] ?? []) === $EXPECT);

echo "ws_json_mutex + load/save (the pattern used in share.php, t.php, index.php)\n";
$f = "$tmp/b.json";
parallel($N, $ITER, "require '$lib'; ws_json_mutex('$f'); \$d = ws_json_read('$f'); \$d['n'] = (\$d['n'] ?? 0) + 1; file_put_contents('$f', json_encode(\$d), LOCK_EX); ws_json_mutex_release('$f');");
t("counter is exactly $EXPECT", (ws_json_read($f)['n'] ?? 0) === $EXPECT);

echo "mixed: mutex writers and ws_json_update writers on the same file\n";
$f = "$tmp/c.json";
$a = proc_open([PHP_BINARY, '-r', "require '$lib'; for (\$k = 0; \$k < 100; \$k++) { ws_json_mutex('$f'); \$d = ws_json_read('$f'); \$d['n'] = (\$d['n'] ?? 0) + 1; file_put_contents('$f', json_encode(\$d), LOCK_EX); ws_json_mutex_release('$f'); }"], [], $p1);
$b = proc_open([PHP_BINARY, '-r', "require '$lib'; for (\$k = 0; \$k < 100; \$k++) ws_json_update('$f', function (&\$d) { \$d['n'] = (\$d['n'] ?? 0) + 1; });"], [], $p2);
proc_close($a); proc_close($b);
t('counter is exactly 200', (ws_json_read($f)['n'] ?? 0) === 200);

echo "behaviour\n";
t('missing file reads as default', ws_json_read("$tmp/none.json", ['x' => 1]) === ['x' => 1]);
ws_json_update("$tmp/d.json", function (&$d) { $d['a'] = 1; });
t('returning false skips the write', ws_json_update("$tmp/d.json", function (&$d) { $d['a'] = 2; return false; }) === false && ws_json_read("$tmp/d.json")['a'] === 1);
file_put_contents("$tmp/e.json", '{broken');
ws_json_update("$tmp/e.json", function (&$d) { $d['ok'] = 1; });
t('corrupt file is kept as .corrupt-* copy', count(glob("$tmp/e.json.corrupt-*")) === 1);
symlink("$tmp/real.json", "$tmp/link.json");
file_put_contents("$tmp/real.json", '{}');
ws_json_update("$tmp/link.json", function (&$d) { $d['v'] = 1; });
t('symlink is preserved and its target updated', is_link("$tmp/link.json") && ws_json_read("$tmp/real.json")['v'] === 1);
ws_json_mutex("$tmp/f.json");
t('update inside a held mutex does not deadlock', ws_json_update("$tmp/f.json", function (&$d) { $d['x'] = 1; return 'done'; }) === 'done');
ws_json_mutex_release("$tmp/f.json");

exec('rm -rf ' . escapeshellarg($tmp));
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
