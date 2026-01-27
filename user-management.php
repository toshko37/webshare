<?php
/**
 * User Management for WebShare
 * ============================
 * Functions to manage .htpasswd users
 */

// Include folder management
require_once __DIR__ . '/folder-management.php';

define('HTPASSWD_FILE', __DIR__ . '/.htpasswd');

/**
 * Get list of all users from .htpasswd
 */
function getUsers() {
    $users = [];
    if (file_exists(HTPASSWD_FILE)) {
        $lines = file(HTPASSWD_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $users[] = $parts[0];
            }
        }
    }
    return $users;
}

/**
 * Check if user exists
 */
function userExists($username) {
    return in_array($username, getUsers());
}

/**
 * Add new user (uses htpasswd command for Apache-compatible hashes)
 */
function addUser($username, $password) {
    // Validate username
    if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
        return ['success' => false, 'error' => 'Invalid username. Use 3-20 alphanumeric characters, - or _'];
    }

    if (userExists($username)) {
        return ['success' => false, 'error' => 'User already exists'];
    }

    if (strlen($password) < 4) {
        return ['success' => false, 'error' => 'Password must be at least 4 characters'];
    }

    // Use htpasswd command for Apache-compatible hash
    $escapedPassword = escapeshellarg($password);
    $escapedUsername = escapeshellarg($username);
    $escapedFile = escapeshellarg(HTPASSWD_FILE);

    $cmd = "htpasswd -b {$escapedFile} {$escapedUsername} {$escapedPassword} 2>&1";
    exec($cmd, $output, $returnCode);

    if ($returnCode === 0) {
        // Ensure file is readable by Apache
        chmod(HTPASSWD_FILE, 0644);

        // Create user folder
        createUserFolder($username);

        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Failed to add user: ' . implode(' ', $output)];
}

/**
 * Change user password (uses htpasswd command)
 */
function changePassword($username, $newPassword) {
    if (!userExists($username)) {
        return ['success' => false, 'error' => 'User not found'];
    }

    if (strlen($newPassword) < 4) {
        return ['success' => false, 'error' => 'Password must be at least 4 characters'];
    }

    // Use htpasswd command to update password
    $escapedPassword = escapeshellarg($newPassword);
    $escapedUsername = escapeshellarg($username);
    $escapedFile = escapeshellarg(HTPASSWD_FILE);

    $cmd = "htpasswd -b {$escapedFile} {$escapedUsername} {$escapedPassword} 2>&1";
    exec($cmd, $output, $returnCode);

    if ($returnCode === 0) {
        // Ensure file is readable by Apache
        chmod(HTPASSWD_FILE, 0644);
        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Failed to change password: ' . implode(' ', $output)];
}

/**
 * Delete user (uses htpasswd -D command)
 */
function deleteUser($username) {
    if (!userExists($username)) {
        return ['success' => false, 'error' => 'User not found'];
    }

    // Don't allow deleting the last user
    $users = getUsers();
    if (count($users) <= 1) {
        return ['success' => false, 'error' => 'Cannot delete the last user'];
    }

    // Use htpasswd -D to delete user
    $escapedUsername = escapeshellarg($username);
    $escapedFile = escapeshellarg(HTPASSWD_FILE);

    $cmd = "htpasswd -D {$escapedFile} {$escapedUsername} 2>&1";
    exec($cmd, $output, $returnCode);

    if ($returnCode === 0) {
        // Ensure file is readable by Apache
        chmod(HTPASSWD_FILE, 0644);
        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Failed to delete user: ' . implode(' ', $output)];
}

/**
 * Get current authenticated user
 */
function getCurrentUser() {
    return $_SERVER['PHP_AUTH_USER'] ?? $_SERVER['REMOTE_USER'] ?? 'unknown';
}

// ============================================
// File Ownership Tracking
// ============================================

define('FILES_META_FILE', __DIR__ . '/.files-meta.json');

/**
 * Load files metadata
 */
function loadFilesMeta() {
    if (file_exists(FILES_META_FILE)) {
        $content = file_get_contents(FILES_META_FILE);
        return json_decode($content, true) ?? [];
    }
    return [];
}

/**
 * Save files metadata
 */
function saveFilesMeta($data) {
    file_put_contents(FILES_META_FILE, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

/**
 * Record file upload
 * @param string $filename Filename
 * @param string|null $user Uploader username
 * @param string|null $folder Folder name (null = old style, no folder)
 */
function recordFileUpload($filename, $user = null, $folder = null) {
    $meta = loadFilesMeta();

    // Use folder/filename as key if folder is specified
    $key = $folder ? ($folder . '/' . $filename) : $filename;

    $meta[$key] = [
        'uploader' => $user ?? getCurrentUser(),
        'uploaded_at' => time(),
        'folder' => $folder
    ];
    saveFilesMeta($meta);
}

/**
 * Get file owner
 */
function getFileOwner($filename) {
    $meta = loadFilesMeta();
    return $meta[$filename]['uploader'] ?? null;
}

/**
 * Remove file from metadata
 */
function removeFileMeta($filename) {
    $meta = loadFilesMeta();
    unset($meta[$filename]);
    saveFilesMeta($meta);
}

/**
 * Update filename in metadata (for rename)
 */
function renameFileMeta($oldName, $newName) {
    $meta = loadFilesMeta();
    if (isset($meta[$oldName])) {
        $meta[$newName] = $meta[$oldName];
        unset($meta[$oldName]);
        saveFilesMeta($meta);
    }
}

/**
 * Sync files metadata with actual files on disk
 * - Adds metadata for files that exist but have no metadata
 * - Removes metadata for files that no longer exist
 * @return array Stats about what was synced
 */
function syncFilesMeta() {
    $filesDir = __DIR__ . '/files';
    if (!is_dir($filesDir)) {
        return ['added' => 0, 'removed' => 0];
    }

    $meta = loadFilesMeta();
    $actualFiles = [];
    $added = 0;
    $removed = 0;

    // Scan all user folders
    $userFolders = scandir($filesDir);
    foreach ($userFolders as $userFolder) {
        if ($userFolder === '.' || $userFolder === '..' || $userFolder === '.htaccess') {
            continue;
        }

        $userPath = $filesDir . '/' . $userFolder;
        if (!is_dir($userPath)) {
            continue;
        }

        // Determine the owner (folder name = username, except _public)
        $owner = ($userFolder === '_public') ? 'public' : $userFolder;

        // Scan files in user folder (including subfolders up to 3 levels)
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($userPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getFilename() !== '.htaccess') {
                // Get relative path from files directory
                $relativePath = str_replace($filesDir . '/', '', $file->getPathname());
                $actualFiles[$relativePath] = true;

                // Check if metadata exists
                if (!isset($meta[$relativePath])) {
                    // Add missing metadata
                    $meta[$relativePath] = [
                        'uploader' => $owner,
                        'uploaded_at' => $file->getMTime(),
                        'folder' => $userFolder,
                        'synced' => true  // Mark as auto-synced
                    ];
                    $added++;
                }
            }
        }
    }

    // Remove metadata for files that no longer exist
    foreach ($meta as $key => $info) {
        $fullPath = $filesDir . '/' . $key;
        if (!file_exists($fullPath)) {
            unset($meta[$key]);
            $removed++;
        }
    }

    // Save if anything changed
    if ($added > 0 || $removed > 0) {
        saveFilesMeta($meta);
    }

    return ['added' => $added, 'removed' => $removed];
}

// ============================================
// API Key Management
// ============================================

define('API_KEYS_FILE', __DIR__ . '/.api-keys.json');

/**
 * Load API keys
 */
function loadApiKeys() {
    if (file_exists(API_KEYS_FILE)) {
        $content = file_get_contents(API_KEYS_FILE);
        return json_decode($content, true) ?? [];
    }
    return [];
}

/**
 * Save API keys
 */
function saveApiKeys($keys) {
    file_put_contents(API_KEYS_FILE, json_encode($keys, JSON_PRETTY_PRINT), LOCK_EX);
    chmod(API_KEYS_FILE, 0600);
}

/**
 * Generate a new API key for a user
 */
function generateApiKey($username) {
    $keys = loadApiKeys();

    // Generate secure random key (32 bytes = 64 hex chars)
    $apiKey = bin2hex(random_bytes(32));

    $keys[$username] = [
        'key' => $apiKey,
        'created' => time(),
        'last_used' => null
    ];

    saveApiKeys($keys);
    return $apiKey;
}

/**
 * Get user's API key (or null if not set)
 */
function getUserApiKey($username) {
    $keys = loadApiKeys();
    return $keys[$username]['key'] ?? null;
}

/**
 * Validate API key and return username if valid
 */
function validateApiKey($apiKey) {
    $keys = loadApiKeys();

    foreach ($keys as $username => $data) {
        if ($data['key'] === $apiKey) {
            // Update last used timestamp
            $keys[$username]['last_used'] = time();
            saveApiKeys($keys);
            return $username;
        }
    }

    return null;
}

/**
 * Revoke user's API key
 */
function revokeApiKey($username) {
    $keys = loadApiKeys();
    if (isset($keys[$username])) {
        unset($keys[$username]);
        saveApiKeys($keys);
        return true;
    }
    return false;
}
