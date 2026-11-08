<?php
/**
 * Keeps the file lists in sync (group 4): src/manifest.txt is the source of truth
 * for the installers; live-update.php has its own arrays; every listed file must exist,
 * and every PHP file in src/ must be listed (a missing file breaks fresh installs).
 * Run: php tests/manifest-test.php
 */
$src = __DIR__ . '/../src';
$manifest = array_values(array_filter(array_map('trim', file("$src/manifest.txt")), fn($l) => $l !== '' && $l[0] !== '#'));
$pass = $fail = 0;
function t($name, $ok, $detail = '') { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . ($ok || $detail === '' ? '' : ": $detail") . "\n"; }

$missing = array_filter($manifest, fn($f) => !is_file("$src/$f"));
t('every manifest entry exists in src/', !$missing, implode(', ', $missing));

$php = array_map('basename', glob("$src/*.php"));
$unlisted = array_diff($php, $manifest);
t('every src/*.php is in the manifest', !$unlisted, implode(', ', $unlisted));

$lu = file_get_contents("$src/live-update.php");
preg_match('/\$phpFiles = \[(.*?)\];/s', $lu, $m1);
preg_match('/\$otherFiles = \[(.*?)\];/s', $lu, $m2);
preg_match_all("/'([^']+)'/", $m1[1] . $m2[1], $m);
$liveList = $m[1];
$notInLive = array_diff(array_filter($manifest, fn($f) => strpos($f, '/') === false), $liveList);
t('live-update.php downloads every top-level manifest file', !$notInLive, implode(', ', $notInLive));
$notInManifest = array_diff($liveList, $manifest);
t('live-update.php lists nothing outside the manifest', !$notInManifest, implode(', ', $notInManifest));

foreach (['get-webshare.sh', 'install.sh', 'update.sh', 'update-remote.sh'] as $inst) {
    $s = file_get_contents(__DIR__ . "/../installer/$inst");
    t("$inst reads manifest.txt", strpos($s, '"$SOURCE_URL/manifest.txt"') !== false);
    preg_match('/if \[ \$\{#PHP_FILES\[@\]\} -eq 0 \]; then\s+PHP_FILES=\((.*?)\)/s', $s, $fb);
    preg_match_all('/"([^"]+)"/', $fb[1] ?? '', $fm);
    $diff = array_merge(array_diff($manifest, $fm[1]), array_diff($fm[1], $manifest));
    t("$inst fallback list equals the manifest", !$diff, implode(', ', $diff));
    t("$inst runs harden.sh", strpos($s, 'installer/harden.sh') !== false);
}
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
