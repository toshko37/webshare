<?php
/**
 * Release signature tests (F5). Run as root on the release server: php tests/release-sign-test.php
 * Signs test manifests with the real release key (skipped where the key is not readable).
 */
require __DIR__ . '/../src/release-verify.php';
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

echo "paths\n";
foreach (['index.php', 'assets/quill/quill.js', '.htaccess', 'user.ini.txt'] as $p) t("allowed: $p", ws_release_path_ok($p));
foreach (['../x.php', '/etc/passwd', 'a/../b', 'a\\b', "a\0b", '', '.', 'x/./y', 'a b.php'] as $p) t('rejected: ' . json_encode($p), !ws_release_path_ok($p));

$keyFile = getenv('WS_SIGNING_KEY') ?: '/root/.config/webshare/release-signing.key';
if (!is_readable($keyFile)) { echo "signing key not readable, signature tests skipped\n"; }
else {
    echo "signatures\n";
    $sk = base64_decode(trim(file_get_contents($keyFile)));
    $m = json_encode(['version' => '9.9.9', 'files' => ['index.php' => str_repeat('a', 64)]]);
    $sig = base64_encode(sodium_crypto_sign_detached($m, $sk));
    t('valid signature accepted', ws_release_verify_manifest($m, $sig)['ok']);
    t('one changed byte in the manifest rejected', !ws_release_verify_manifest(str_replace('9.9.9', '9.9.8', $m), $sig)['ok']);
    $other = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
    t('signature by an unknown key rejected', !ws_release_verify_manifest($m, base64_encode(sodium_crypto_sign_detached($m, $other)))['ok']);
    t('garbage signature rejected', !ws_release_verify_manifest($m, 'abc')['ok']);
    $evil = json_encode(['version' => '9.9.9', 'files' => ['../../etc/cron.d/x' => str_repeat('a', 64)]]);
    t('signed manifest with a traversal path still rejected', !ws_release_verify_manifest($evil, base64_encode(sodium_crypto_sign_detached($evil, $sk)))['ok']);
    $bad = json_encode(['version' => '9.9.9', 'files' => ['index.php' => 'nothex']]);
    t('signed manifest with a bad hash rejected', !ws_release_verify_manifest($bad, base64_encode(sodium_crypto_sign_detached($bad, $sk)))['ok']);
}
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
