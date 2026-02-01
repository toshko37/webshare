<?php
/**
 * WebShare File Encryption System
 * ================================
 * Handles file encryption/decryption with AES-256-GCM
 */

define('ENCRYPTION_KEYS_FILE', __DIR__ . '/.encryption-keys.json');
define('ENCRYPTION_ALGORITHM', 'aes-256-gcm');
define('ENCRYPTED_EXTENSION', '.enc');

/**
 * Encrypt a file with password
 * @param string $sourcePath Source file path
 * @param string $destPath Destination file path (will have .enc added)
 * @param string $password Encryption password
 * @return array Result with success status
 */
function encryptFile($sourcePath, $destPath, $password) {
    if (!file_exists($sourcePath)) {
        return ['success' => false, 'error' => 'Source file not found'];
    }

    // Read file content
    $data = file_get_contents($sourcePath);
    if ($data === false) {
        return ['success' => false, 'error' => 'Failed to read source file'];
    }

    // Generate key from password
    $key = hash('sha256', $password, true);

    // Generate random IV
    $iv = random_bytes(16);

    // Encrypt
    $tag = '';
    $encrypted = openssl_encrypt($data, ENCRYPTION_ALGORITHM, $key, OPENSSL_RAW_DATA, $iv, $tag);

    if ($encrypted === false) {
        return ['success' => false, 'error' => 'Encryption failed'];
    }

    // Combine IV + Tag + Encrypted data
    $output = $iv . $tag . $encrypted;

    // Add .enc extension if not already present
    if (substr($destPath, -4) !== ENCRYPTED_EXTENSION) {
        $destPath .= ENCRYPTED_EXTENSION;
    }

    // Write encrypted file
    if (file_put_contents($destPath, $output) === false) {
        return ['success' => false, 'error' => 'Failed to write encrypted file'];
    }

    return [
        'success' => true,
        'encrypted_path' => $destPath,
        'encrypted_filename' => basename($destPath)
    ];
}

/**
 * Decrypt a file with password
 * @param string $sourcePath Encrypted file path
 * @param string $password Decryption password
 * @return array Result with decrypted data or error
 */
function decryptFile($sourcePath, $password) {
    if (!file_exists($sourcePath)) {
        return ['success' => false, 'error' => 'Encrypted file not found'];
    }

    // Read encrypted file
    $data = file_get_contents($sourcePath);
    if ($data === false || strlen($data) < 32) {
        return ['success' => false, 'error' => 'Invalid encrypted file'];
    }

    // Extract IV, Tag, and encrypted data
    $iv = substr($data, 0, 16);
    $tag = substr($data, 16, 16);
    $encrypted = substr($data, 32);

    // Generate key from password
    $key = hash('sha256', $password, true);

    // Decrypt
    $decrypted = openssl_decrypt($encrypted, ENCRYPTION_ALGORITHM, $key, OPENSSL_RAW_DATA, $iv, $tag);

    if ($decrypted === false) {
        return ['success' => false, 'error' => 'Decryption failed - wrong password?'];
    }

    return [
        'success' => true,
        'data' => $decrypted,
        'original_filename' => getOriginalFilename(basename($sourcePath))
    ];
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
function storeEncryptionPassword($filename, $password, $uploader) {
    $keys = loadEncryptionKeys();

    $keys[$filename] = [
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        // Note: password_plain removed for security - only hash is stored
        'created_at' => time(),
        'created_by' => $uploader
    ];

    saveEncryptionKeys($keys);
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

/**
 * Verify password for encrypted file
 * @param string $filename Encrypted filename
 * @param string $password Password to verify
 * @return bool
 */
function verifyEncryptionPassword($filename, $password) {
    $keys = loadEncryptionKeys();

    if (!isset($keys[$filename])) {
        return false;
    }

    // Verify against stored hash only (plain text fallback removed for security)
    if (isset($keys[$filename]['password_hash'])) {
        return password_verify($password, $keys[$filename]['password_hash']);
    }

    // No hash found - legacy entry without proper hash
    return false;
}

/**
 * Remove encryption key entry when file is deleted
 * @param string $filename Encrypted filename
 */
function removeEncryptionKey($filename) {
    $keys = loadEncryptionKeys();
    unset($keys[$filename]);
    saveEncryptionKeys($keys);
}

/**
 * Load encryption keys from JSON
 * @return array
 */
function loadEncryptionKeys() {
    if (!file_exists(ENCRYPTION_KEYS_FILE)) {
        return [];
    }
    $content = file_get_contents(ENCRYPTION_KEYS_FILE);
    return json_decode($content, true) ?? [];
}

/**
 * Save encryption keys to JSON
 * @param array $keys
 */
function saveEncryptionKeys($keys) {
    file_put_contents(ENCRYPTION_KEYS_FILE, json_encode($keys, JSON_PRETTY_PRINT), LOCK_EX);
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
