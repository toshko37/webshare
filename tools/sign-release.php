<?php
/**
 * Release signing (F5). Docs: docs/features-plan.md, docs/decisions.md D-026
 *
 *   php tools/sign-release.php --keygen          create the signing key (once)
 *   php tools/sign-release.php <version>         write src/release-manifest.json + .sig
 *   php tools/sign-release.php --verify          check the files in src/ against the signed manifest
 *
 * Key: /root/.config/webshare/release-signing.key (or $WS_SIGNING_KEY); never in the repository.
 */
if (PHP_SAPI !== 'cli') exit(1);
require __DIR__ . '/../src/release-verify.php';

$keyFile = getenv('WS_SIGNING_KEY') ?: '/root/.config/webshare/release-signing.key';
$src = realpath(__DIR__ . '/../src');
$arg = $argv[1] ?? '';

if ($arg === '--keygen') {
    if (file_exists($keyFile)) { fwrite(STDERR, "Key already exists: $keyFile\n"); exit(1); }
    @mkdir(dirname($keyFile), 0700, true);
    $kp = sodium_crypto_sign_keypair();
    file_put_contents($keyFile, base64_encode(sodium_crypto_sign_secretkey($kp)) . "\n");
    chmod($keyFile, 0600);
    echo "Private key: $keyFile\nPublic key (put into WS_RELEASE_PUBKEYS in src/release-verify.php):\n";
    echo base64_encode(sodium_crypto_sign_publickey($kp)) . "\n";
    exit(0);
}

if ($arg === '--verify') {
    $m = file_get_contents("$src/release-manifest.json");
    $sig = trim(file_get_contents("$src/release-manifest.sig"));
    $r = ws_release_verify_manifest($m, $sig);
    if (!$r['ok']) { fwrite(STDERR, "Signature: {$r['error']}\n"); exit(1); }
    $bad = [];
    foreach ($r['manifest']['files'] as $path => $hash) {
        $local = $path === '.htaccess' ? "$src/.htaccess" : "$src/$path";
        if (!is_file($local) || hash_file('sha256', $local) !== $hash) $bad[] = $path;
    }
    echo "Version {$r['manifest']['version']}, " . count($r['manifest']['files']) . " files, signature OK\n";
    if ($bad) { echo "Changed since signing: " . implode(', ', $bad) . "\n"; exit(2); }
    exit(0);
}

if ($arg === '--verify-remote') {
    // Same checks as live-update.php, against the published release on GitHub
    $v = $argv[2] ?? '';
    if (!preg_match('/^\d+\.\d+\.\d+$/', $v)) { fwrite(STDERR, "Usage: --verify-remote <version>\n"); exit(1); }
    $base = "https://raw.githubusercontent.com/toshko37/webshare/v$v/src";
    $get = function ($u) { $c = @file_get_contents($u); return $c === false ? null : $c; };
    $m = $get("$base/release-manifest.json"); $sig = $get("$base/release-manifest.sig");
    if ($m === null || $sig === null) { echo "v$v: not signed\n"; exit(1); }
    $r = ws_release_verify_manifest($m, $sig);
    if (!$r['ok'] || $r['manifest']['version'] !== $v) { echo "v$v: " . ($r['error'] ?? 'version mismatch') . "\n"; exit(1); }
    $bad = [];
    foreach ($r['manifest']['files'] as $path => $hash) {
        $c = $get("$base/$path");
        if ($c === null || !hash_equals($hash, hash('sha256', $c))) $bad[] = $path;
    }
    echo "v$v on GitHub: signature OK, " . (count($r['manifest']['files']) - count($bad)) . '/' . count($r['manifest']['files']) . " files match\n";
    if ($bad) { echo "Mismatch: " . implode(', ', $bad) . "\n"; exit(2); }
    exit(0);
}

$version = $arg;
if (!preg_match('/^\d+\.\d+\.\d+$/', $version)) { fwrite(STDERR, "Usage: sign-release.php <version>|--keygen|--verify\n"); exit(1); }
if (!is_readable($keyFile)) { fwrite(STDERR, "Signing key not found: $keyFile (run --keygen)\n"); exit(1); }
$secret = base64_decode(trim(file_get_contents($keyFile)), true);
if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) { fwrite(STDERR, "Invalid key file\n"); exit(1); }
$pub = base64_encode(sodium_crypto_sign_publickey_from_secretkey($secret));
if (!in_array($pub, WS_RELEASE_PUBKEYS, true)) { fwrite(STDERR, "This key's public half is not in WS_RELEASE_PUBKEYS: installs would reject the release\n"); exit(1); }

$list = array_values(array_filter(array_map('trim', file("$src/manifest.txt")), fn($l) => $l !== '' && $l[0] !== '#'));
$list[] = '.htaccess';
$list[] = 'user.ini.txt';
$list[] = 'manifest.txt';
$files = [];
foreach ($list as $path) {
    if (!ws_release_path_ok($path)) { fwrite(STDERR, "Bad path in manifest: $path\n"); exit(1); }
    if (!is_file("$src/$path")) { fwrite(STDERR, "Missing file: $path\n"); exit(1); }
    $files[$path] = hash_file('sha256', "$src/$path");
}
ksort($files);
$manifest = json_encode(['version' => $version, 'created' => gmdate('c'), 'files' => $files], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
file_put_contents("$src/release-manifest.json", $manifest);
file_put_contents("$src/release-manifest.sig", base64_encode(sodium_crypto_sign_detached($manifest, $secret)) . "\n");
echo "Signed release-manifest.json for $version (" . count($files) . " files)\n";
