<?php
/**
 * WebShare File Encryption System
 * ================================
 * Handles file encryption/decryption with AES-256-GCM
 */

require_once __DIR__ . '/json-store.php';
define('ENCRYPTION_KEYS_FILE', __DIR__ . '/.encryption-keys.json');
define('ENCRYPTION_ALGORITHM', 'aes-256-gcm');
define('ENCRYPTED_EXTENSION', '.enc');

/*
 * File format v2 (since 3.8.0, I1/I2), streamed in 1 MiB chunks:
 *
 *   header (42 bytes):
 *     "WSE2" | version=2 (1) | kdf (1: 1=Argon2id, 2=PBKDF2-SHA256)
 *     | kdf param A (4, BE) | kdf param B (4, BE) | salt (16) | nonce prefix (8) | chunk size (4, BE)
 *       Argon2id: A = opslimit, B = memlimit in KiB.  PBKDF2: A = iterations, B = 0.
 *   chunks: AES-256-GCM ciphertext (same length as the plaintext chunk) + tag (16)
 *     nonce = nonce prefix + chunk index (4, BE)
 *     AAD   = header + chunk index (4, BE) + final flag (1 on the last chunk, else 0)
 *   The final flag makes truncation and reordering fail authentication.
 *   There is always at least one chunk (an empty file has one empty chunk).
 *
 * Format v1 (before 3.8.0): IV (16) | GCM tag (16) | ciphertext, key = SHA-256(password).
 * Still decrypted (in memory, as before); new files are always v2.
 *
 * The password is verified by decryption itself (the GCM tag), not by the
 * .encryption-keys.json entry, which is metadata only (I3).
 */
define('WSE2_MAGIC', 'WSE2');
define('WSE2_HEADER_LEN', 42);
define('WSE2_CHUNK', 1048576);
define('WSE2_TAG', 16);
define('WSE2_KDF_ARGON2ID', 1);
define('WSE2_KDF_PBKDF2', 2);

function encDeriveKey($password, $kdf, $a, $b, $salt) {
    if ($kdf === WSE2_KDF_ARGON2ID) {
        if (!function_exists('sodium_crypto_pwhash')) return null;
        return sodium_crypto_pwhash(32, $password, $salt, $a, $b * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    }
    if ($kdf === WSE2_KDF_PBKDF2) {
        if ($a < 1 || $a > 10000000) return null;
        return hash_pbkdf2('sha256', $password, $salt, $a, 32, true);
    }
    return null;
}

function encNonce($prefix, $i) {
    return $prefix . pack('N', $i);
}

/**
 * Encrypt a file with password (format v2, streamed)
 * @param string $sourcePath Source file path
 * @param string $destPath Destination file path (".enc" is appended when missing)
 * @param string $password Encryption password
 * @return array ['success' => bool, 'encrypted_path', 'encrypted_filename'] or error
 */
function encryptFile($sourcePath, $destPath, $password) {
    if (!is_file($sourcePath)) {
        return ['success' => false, 'error' => 'Source file not found'];
    }
    if (substr($destPath, -4) !== ENCRYPTED_EXTENSION) {
        $destPath .= ENCRYPTED_EXTENSION;
    }
    $in = @fopen($sourcePath, 'rb');
    if (!$in) {
        return ['success' => false, 'error' => 'Failed to read source file'];
    }
    $size = filesize($sourcePath);

    $salt = random_bytes(16);
    if (function_exists('sodium_crypto_pwhash')) {
        $kdf = WSE2_KDF_ARGON2ID; $a = 3; $b = 65536;      // 3 passes, 64 MiB
    } else {
        $kdf = WSE2_KDF_PBKDF2;   $a = 600000; $b = 0;     // OWASP 2023 for PBKDF2-SHA256
    }
    $key = encDeriveKey($password, $kdf, $a, $b, $salt);
    $prefix = random_bytes(8);
    $header = WSE2_MAGIC . chr(2) . chr($kdf) . pack('N', $a) . pack('N', $b) . $salt . $prefix . pack('N', WSE2_CHUNK);

    $tmp = $destPath . '.part-' . bin2hex(random_bytes(4));
    $out = @fopen($tmp, 'wb');
    if (!$out) {
        fclose($in);
        return ['success' => false, 'error' => 'Failed to write encrypted file'];
    }
    $ok = fwrite($out, $header) === WSE2_HEADER_LEN;
    $chunks = max(1, (int)ceil($size / WSE2_CHUNK));
    for ($i = 0; $ok && $i < $chunks; $i++) {
        $plain = $size ? stream_get_contents($in, WSE2_CHUNK) : '';
        if ($plain === false) { $ok = false; break; }
        $final = ($i === $chunks - 1) ? 1 : 0;
        $tag = '';
        $ct = openssl_encrypt($plain, ENCRYPTION_ALGORITHM, $key, OPENSSL_RAW_DATA, encNonce($prefix, $i), $tag,
            $header . pack('N', $i) . chr($final), WSE2_TAG);
        $ok = $ct !== false && fwrite($out, $ct . $tag) === strlen($ct) + WSE2_TAG;
    }
    fclose($in);
    $ok = fclose($out) && $ok;
    if (!$ok || !rename($tmp, $destPath)) {
        @unlink($tmp);
        return ['success' => false, 'error' => 'Encryption failed'];
    }

    return [
        'success' => true,
        'encrypted_path' => $destPath,
        'encrypted_filename' => basename($destPath)
    ];
}

/**
 * Open an encrypted file for streaming decryption. The password is checked
 * here (first chunk for v2, whole file for v1), before anything is output.
 * @return array ['success' => true, 'size' => plaintext bytes, 'head' => first plaintext bytes, ...ctx]
 *               or ['success' => false, 'error' => ...]
 */
function decryptOpen($sourcePath, $password) {
    if (!is_file($sourcePath)) {
        return ['success' => false, 'error' => 'Encrypted file not found'];
    }
    $total = filesize($sourcePath);
    $fh = @fopen($sourcePath, 'rb');
    if (!$fh) {
        return ['success' => false, 'error' => 'Encrypted file not found'];
    }
    $header = fread($fh, WSE2_HEADER_LEN);

    if (strlen($header) === WSE2_HEADER_LEN && substr($header, 0, 4) === WSE2_MAGIC && ord($header[4]) === 2) {
        $kdf = ord($header[5]);
        $a = unpack('N', substr($header, 6, 4))[1];
        $b = unpack('N', substr($header, 10, 4))[1];
        $salt = substr($header, 14, 16);
        $prefix = substr($header, 30, 8);
        $chunk = unpack('N', substr($header, 38, 4))[1];
        $body = $total - WSE2_HEADER_LEN;
        if ($chunk >= 1024 && $chunk <= 64 * WSE2_CHUNK && $body >= WSE2_TAG) {
            $chunks = (int)ceil($body / ($chunk + WSE2_TAG));
            $key = encDeriveKey($password, $kdf, $a, $b, $salt);
            if ($key === null) {
                fclose($fh);
                return ['success' => false, 'error' => 'Unsupported encryption parameters'];
            }
            $ctx = ['success' => true, 'version' => 2, 'fh' => $fh, 'key' => $key, 'header' => $header,
                'prefix' => $prefix, 'chunk' => $chunk, 'chunks' => $chunks, 'index' => 0,
                'size' => $body - $chunks * WSE2_TAG];
            $first = decryptNextChunk($ctx);
            if ($first !== false) {
                $ctx['head'] = $first;
                return $ctx;
            }
            fclose($fh);
            return ['success' => false, 'error' => 'Decryption failed - wrong password?'];
        }
        // Not a valid v2 layout: a v1 file whose random IV starts with "WSE2"; fall through
    }

    // Format v1 (legacy): whole file in memory
    fclose($fh);
    $data = file_get_contents($sourcePath);
    if ($data === false || strlen($data) < 32) {
        return ['success' => false, 'error' => 'Invalid encrypted file'];
    }
    $plain = openssl_decrypt(substr($data, 32), ENCRYPTION_ALGORITHM, hash('sha256', $password, true),
        OPENSSL_RAW_DATA, substr($data, 0, 16), substr($data, 16, 16));
    if ($plain === false) {
        return ['success' => false, 'error' => 'Decryption failed - wrong password?'];
    }
    return ['success' => true, 'version' => 1, 'size' => strlen($plain), 'head' => $plain, 'chunks' => 1, 'index' => 1];
}

/** Decrypt the next v2 chunk; false on authentication failure */
function decryptNextChunk(array &$ctx) {
    $i = $ctx['index'];
    if ($i >= $ctx['chunks']) return false;
    $final = ($i === $ctx['chunks'] - 1) ? 1 : 0;
    $len = $final ? null : $ctx['chunk'] + WSE2_TAG;
    $raw = $len ? fread($ctx['fh'], $len) : stream_get_contents($ctx['fh']);
    if ($raw === false || strlen($raw) < WSE2_TAG) return false;
    $plain = openssl_decrypt(substr($raw, 0, -WSE2_TAG), ENCRYPTION_ALGORITHM, $ctx['key'], OPENSSL_RAW_DATA,
        encNonce($ctx['prefix'], $i), substr($raw, -WSE2_TAG), $ctx['header'] . pack('N', $i) . chr($final));
    if ($plain === false) return false;
    $ctx['index']++;
    return $plain;
}

/**
 * Stream the plaintext of an opened file to $sink (called with each piece).
 * @return bool false if a later chunk fails authentication (file damaged)
 */
function decryptStream(array $ctx, callable $sink) {
    $sink($ctx['head']);
    if ($ctx['version'] === 1) return true;
    while ($ctx['index'] < $ctx['chunks']) {
        $plain = decryptNextChunk($ctx);
        if ($plain === false) { fclose($ctx['fh']); return false; }
        $sink($plain);
    }
    fclose($ctx['fh']);
    return true;
}

/** Decrypt to a file (streamed); the destination is removed on failure */
function decryptFileTo($sourcePath, $password, $destPath) {
    $ctx = decryptOpen($sourcePath, $password);
    if (!$ctx['success']) return $ctx;
    $out = @fopen($destPath, 'wb');
    if (!$out) {
        if (isset($ctx['fh'])) fclose($ctx['fh']);
        return ['success' => false, 'error' => 'Failed to write decrypted file'];
    }
    $ok = decryptStream($ctx, function ($p) use ($out) { fwrite($out, $p); });
    fclose($out);
    if (!$ok) {
        @unlink($destPath);
        return ['success' => false, 'error' => 'Encrypted file is damaged'];
    }
    return ['success' => true, 'size' => $ctx['size']];
}

/**
 * Send a decrypted file to the browser (streamed). Nothing is sent when the
 * password is wrong; the caller shows its form with the returned error.
 */
function decryptToBrowser($sourcePath, $password, $downloadName) {
    $ctx = decryptOpen($sourcePath, $password);
    if (!$ctx['success']) return $ctx;
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->buffer(substr($ctx['head'], 0, 65536)) ?: 'application/octet-stream';
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . $ctx['size']);
    header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($downloadName));
    header('Cache-Control: no-store');
    decryptStream($ctx, function ($p) { echo $p; flush(); });
    return ['success' => true, 'size' => $ctx['size']];
}

/**
 * Decrypt a file into memory (kept for compatibility; prefer the streaming functions)
 * @return array ['success', 'data', 'original_filename'] or error
 */
function decryptFile($sourcePath, $password) {
    $ctx = decryptOpen($sourcePath, $password);
    if (!$ctx['success']) return $ctx;
    $data = '';
    if (!decryptStream($ctx, function ($p) use (&$data) { $data .= $p; })) {
        return ['success' => false, 'error' => 'Encrypted file is damaged'];
    }
    return ['success' => true, 'data' => $data, 'original_filename' => getOriginalFilename(basename($sourcePath))];
}

/**
 * Check if a file is encrypted (by extension)
 * @param string $filename Filename
 * @return bool
 */
function isEncryptedFile($filename) {
    return substr($filename, -4) === ENCRYPTED_EXTENSION;
}

/**
 * Get original filename from encrypted filename
 * @param string $encryptedFilename Filename with .enc extension
 * @return string Original filename
 */
function getOriginalFilename($encryptedFilename) {
    if (isEncryptedFile($encryptedFilename)) {
        return substr($encryptedFilename, 0, -4);
    }
    return $encryptedFilename;
}

/**
 * Store encryption password for a file (for recovery)
 * @param string $filename Encrypted filename
 * @param string $password Password
 * @param string $uploader User who encrypted the file
 */
function storeEncryptionPassword($filename, $password, $uploader, $folder = null) {
    // I3: keyed by folder/name so same-named files in different folders do not collide.
    // Metadata only: the password is verified by decryption itself.
    $entry = [
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'created_at' => time(),
        'created_by' => $uploader,
        'format' => 2
    ];
    $id = encryptionKeyId($filename, $folder);
    ws_json_update(ENCRYPTION_KEYS_FILE, function (&$keys) use ($id, $entry) {   // I4
        $keys[$id] = $entry;
    });
    @chmod(ENCRYPTION_KEYS_FILE, 0600);
}

/**
 * Get stored password for encrypted file
 * @deprecated Password recovery removed for security - always returns null
 * @param string $filename Encrypted filename
 * @return null Always returns null
 */
function getStoredPassword($filename) {
    // Security fix: plain text password storage removed
    // Function kept for backwards compatibility, always returns null
    return null;
}

function encryptionKeyId($filename, $folder = null) {
    return $folder ? trim($folder, '/') . '/' . $filename : $filename;
}

/**
 * Verify the password of an encrypted file.
 * With $path the check is done by decrypting (authoritative, I3); without it,
 * only the stored hash is compared (legacy behaviour).
 */
function verifyEncryptionPassword($filename, $password, $path = null) {
    if ($path !== null) {
        $ctx = decryptOpen($path, $password);
        if (!empty($ctx['fh'])) fclose($ctx['fh']);
        return !empty($ctx['success']);
    }
    $keys = loadEncryptionKeys();
    if (isset($keys[$filename]['password_hash'])) {
        return password_verify($password, $keys[$filename]['password_hash']);
    }
    return false;
}

/**
 * Remove encryption key entry when file is deleted
 * @param string $filename Encrypted filename
 */
function removeEncryptionKey($filename, $folder = null) {
    $id = encryptionKeyId($filename, $folder);
    ws_json_update(ENCRYPTION_KEYS_FILE, function (&$keys) use ($filename, $id) {   // I4
        if (!isset($keys[$filename]) && !isset($keys[$id])) return false;
        unset($keys[$filename], $keys[$id]);
    });
}

/**
 * Load encryption keys from JSON
 * @return array
 */
function loadEncryptionKeys() {
    return ws_json_read(ENCRYPTION_KEYS_FILE);
}

/**
 * Save encryption keys to JSON
 * @param array $keys
 */
function saveEncryptionKeys($keys) {
    file_put_contents(ENCRYPTION_KEYS_FILE, json_encode($keys, JSON_PRETTY_PRINT), LOCK_EX);
    @chmod(ENCRYPTION_KEYS_FILE, 0600);
}

/**
 * Get encryption info for a file
 * @param string $filename Filename
 * @return array|null Info or null if not encrypted
 */
function getEncryptionInfo($filename) {
    if (!isEncryptedFile($filename)) {
        return null;
    }

    $keys = loadEncryptionKeys();
    $info = $keys[$filename] ?? [];

    return [
        'encrypted' => true,
        'original_name' => getOriginalFilename($filename),
        'created_at' => $info['created_at'] ?? null,
        'created_by' => $info['created_by'] ?? null
    ];
}
