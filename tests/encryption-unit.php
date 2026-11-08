<?php
/**
 * Unit tests for src/encryption.php: format v2 (KDF, chunks, tamper/truncation),
 * v1 compatibility and streaming memory use.
 * Run: php -d memory_limit=128M tests/encryption-unit.php [--big]
 * Docs: docs/security-plan-2.md
 */
require __DIR__ . '/../src/encryption.php';
$tmp = sys_get_temp_dir() . '/ws-enc-unit-' . getmypid();
mkdir($tmp);
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }

foreach (['empty' => 0, 'small' => 1000, 'exact chunk' => WSE2_CHUNK, 'chunk+1' => WSE2_CHUNK + 1, '3.5 chunks' => (int)(WSE2_CHUNK * 3.5)] as $label => $size) {
    $src = "$tmp/src-$size";
    file_put_contents($src, $size ? random_bytes($size) : '');
    $r = encryptFile($src, "$tmp/out-$size", 'correct horse');
    t("$label: encrypt", $r['success'] && is_file("$tmp/out-$size.enc"));
    $enc = "$tmp/out-$size.enc";
    t("$label: v2 header", substr(file_get_contents($enc, false, null, 0, 4), 0, 4) === 'WSE2');
    $d = decryptFile($enc, 'correct horse');
    t("$label: round trip", $d['success'] && $d['data'] === file_get_contents($src));
    t("$label: wrong password rejected", !decryptFile($enc, 'wrong')['success']);
    $ctx = decryptOpen($enc, 'correct horse');
    t("$label: plaintext size from header", $ctx['size'] === $size);
    if (!empty($ctx['fh'])) fclose($ctx['fh']);
}

echo "tamper / truncation\n";
$src = "$tmp/t"; file_put_contents($src, random_bytes(WSE2_CHUNK * 2 + 100));
encryptFile($src, "$tmp/t", 'pw');
$enc = "$tmp/t.enc"; $orig = file_get_contents($enc);
$bad = $orig; $bad[WSE2_HEADER_LEN + WSE2_CHUNK + 50] = chr(ord($bad[WSE2_HEADER_LEN + WSE2_CHUNK + 50]) ^ 1);
file_put_contents($enc, $bad);
$ctx = decryptOpen($enc, 'pw');
t('flipped bit in chunk 2: open ok (chunk 1 intact)', $ctx['success']);
t('flipped bit in chunk 2: stream fails', !decryptStream($ctx, function () {}));
file_put_contents($enc, substr($orig, 0, WSE2_HEADER_LEN + 2 * (WSE2_CHUNK + WSE2_TAG)));
$ctx = decryptOpen($enc, 'pw');
t('last chunk cut off: detected', !$ctx['success'] || !decryptStream($ctx, function () {}));
$bad = $orig; $bad[20] = chr(ord($bad[20]) ^ 1);   // salt
file_put_contents($enc, $bad);
t('modified header: rejected', !decryptOpen($enc, 'pw')['success']);
$r = decryptFileTo($enc, 'pw', "$tmp/should-not-exist");
t('decryptFileTo leaves no file on failure', !$r['success'] && !file_exists("$tmp/should-not-exist"));

echo "v1 compatibility\n";
$plain = random_bytes(5000);
$iv = random_bytes(16); $tag = '';
$ct = openssl_encrypt($plain, 'aes-256-gcm', hash('sha256', 'old', true), OPENSSL_RAW_DATA, $iv, $tag);
file_put_contents("$tmp/v1.enc", $iv . $tag . $ct);
$d = decryptFile("$tmp/v1.enc", 'old');
t('v1 file decrypts', $d['success'] && $d['data'] === $plain);
t('v1 wrong password rejected', !decryptFile("$tmp/v1.enc", 'nope')['success']);
$iv = 'WSE2' . random_bytes(12);  // v1 whose random IV starts with the v2 magic
$ct = openssl_encrypt($plain, 'aes-256-gcm', hash('sha256', 'old', true), OPENSSL_RAW_DATA, $iv, $tag);
file_put_contents("$tmp/v1m.enc", $iv . $tag . $ct);
$d = decryptFile("$tmp/v1m.enc", 'old');
t('v1 file with "WSE2" IV still decrypts', $d['success'] && $d['data'] === $plain);

echo "I3 metadata key\n";
t('key id includes folder', encryptionKeyId('a.txt.enc', 'dimo/sub') === 'dimo/sub/a.txt.enc');
t('verify by decryption, no metadata needed', verifyEncryptionPassword('x', 'old', "$tmp/v1.enc") && !verifyEncryptionPassword('x', 'bad', "$tmp/v1.enc"));

if (in_array('--big', $argv)) {
    echo "streaming memory (300 MB file, memory_limit " . ini_get('memory_limit') . ")\n";
    $big = "$tmp/big"; $f = fopen($big, 'wb'); for ($i = 0; $i < 300; $i++) fwrite($f, random_bytes(1048576)); fclose($f);
    $h = hash_file('sha256', $big);
    $t0 = microtime(true);
    $r = encryptFile($big, $big, 'pw');
    $te = microtime(true) - $t0; $t0 = microtime(true);
    $r2 = decryptFileTo("$big.enc", 'pw', "$big.out");
    $td = microtime(true) - $t0;
    t(sprintf('300 MB encrypt %.1fs, decrypt %.1fs, peak memory %d MB', $te, $td, memory_get_peak_usage(true) >> 20),
        $r['success'] && $r2['success'] && hash_file('sha256', "$big.out") === $h && memory_get_peak_usage(true) < 64 << 20);
}

array_map('unlink', glob("$tmp/*")); rmdir($tmp);
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
