<?php
/**
 * Release signature verification (F5). Docs: docs/features-plan.md, D-026
 *
 * A release ships src/release-manifest.json (version + SHA-256 of every file)
 * and src/release-manifest.sig (Ed25519 signature, base64). live-update.php
 * installs nothing unless the signature verifies against one of the keys below
 * and every downloaded file matches its hash.
 */

// Public keys allowed to sign releases (base64). Add the new key here before
// retiring an old one, so installs on older versions still accept the release.
const WS_RELEASE_PUBKEYS = [
    '26hboeSIRIWj+kGUw9QZA5N/pOBjBwU/YRUN96C3H1E=',  // 2026-11-09, /root/.config/webshare/release-signing.key
];

/** Relative path inside src/ without traversal or absolute parts */
function ws_release_path_ok($path) {
    return is_string($path) && $path !== '' && $path[0] !== '/' && strpos($path, '\\') === false
        && strpos($path, "\0") === false && !preg_match('#(^|/)\.\.?(/|$)#', $path)
        && preg_match('#^[A-Za-z0-9._/-]+$#', $path);
}

/**
 * @return array ['ok' => true, 'manifest' => [...]] or ['ok' => false, 'error' => ...]
 */
function ws_release_verify_manifest($manifestJson, $signatureB64) {
    if (!function_exists('sodium_crypto_sign_verify_detached')) {
        return ['ok' => false, 'error' => 'libsodium is not available'];
    }
    $sig = base64_decode(trim((string)$signatureB64), true);
    if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
        return ['ok' => false, 'error' => 'invalid signature format'];
    }
    $valid = false;
    foreach (WS_RELEASE_PUBKEYS as $k) {
        $pk = base64_decode($k, true);
        if ($pk !== false && strlen($pk) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && sodium_crypto_sign_verify_detached($sig, (string)$manifestJson, $pk)) {
            $valid = true;
            break;
        }
    }
    if (!$valid) {
        return ['ok' => false, 'error' => 'signature does not match any trusted release key'];
    }
    $m = json_decode($manifestJson, true);
    if (!is_array($m) || !isset($m['version'], $m['files']) || !is_array($m['files'])
        || !preg_match('/^\d+\.\d+\.\d+$/', $m['version'])) {
        return ['ok' => false, 'error' => 'invalid manifest'];
    }
    foreach ($m['files'] as $path => $hash) {
        if (!ws_release_path_ok($path) || !preg_match('/^[a-f0-9]{64}$/', $hash)) {
            return ['ok' => false, 'error' => "invalid manifest entry: $path"];
        }
    }
    return ['ok' => true, 'manifest' => $m];
}
