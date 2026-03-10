<?php
/**
 * User Management for WebShare
 * ============================
 * Session-based auth. Users stored in .users.json
 */

// Include folder management
require_once __DIR__ . '/folder-management.php';

if (!defined('USERS_FILE'))   define('USERS_FILE',   __DIR__ . '/.users.json');
if (!defined('SESSIONS_DIR')) define('SESSIONS_DIR', __DIR__ . '/.sessions/');

// ── User CRUD ─────────────────────────────────────────────────────────────

function loadUsers() {
    if (!file_exists(USERS_FILE)) return [];
    return json_decode(file_get_contents(USERS_FILE), true) ?? [];
}

function saveUsers($users) {
    file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT), LOCK_EX);
}

function getUsers() {
    return array_keys(loadUsers());
}

function userExists($username) {
    $users = loadUsers();
    return isset($users[$username]);
}

function addUser($username, $password, $role = 'user') {
    if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
        return ['success' => false, 'error' => 'Невалидно потребителско име (3-20 знака, a-z 0-9 - _)'];
    }
    if (userExists($username)) {
        return ['success' => false, 'error' => 'Потребителят вече съществува'];
    }
    if (strlen($password) < 4) {
        return ['success' => false, 'error' => 'Паролата трябва да е поне 4 символа'];
    }
    $users = loadUsers();
    $users[$username] = [
        'password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'role'          => $role,
        'created'       => time()
    ];
    saveUsers($users);
    createUserFolder($username);
    return ['success' => true];
}

function changePassword($username, $newPassword) {
    if (!userExists($username)) {
        return ['success' => false, 'error' => 'Потребителят не е намерен'];
    }
    if (strlen($newPassword) < 4) {
        return ['success' => false, 'error' => 'Паролата трябва да е поне 4 символа'];
    }
    $users = loadUsers();
    $users[$username]['password_hash'] = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    saveUsers($users);
    return ['success' => true];
}

function deleteUser($username) {
    if (!userExists($username)) {
        return ['success' => false, 'error' => 'Потребителят не е намерен'];
    }
    $users = loadUsers();
    if (count($users) <= 1) {
        return ['success' => false, 'error' => 'Не може да се изтрие последният потребител'];
    }
    unset($users[$username]);
    saveUsers($users);
    // Close all sessions for deleted user
    logoffAllForUser($username);
    // Delete user's folder and all files inside
    if (function_exists('deleteUserFolder')) {
        deleteUserFolder($username, true);
    }
    return ['success' => true];
}

function setUserRole($username, $role) {
    if (!userExists($username)) return false;
    $users = loadUsers();
    $users[$username]['role'] = $role;
    saveUsers($users);
    return true;
}

/**
 * Get current authenticated user (from session)
 */
function getCurrentUser() {
    return $_SESSION['username'] ?? 'unknown';
}

/**
 * Check if user is admin (role = 'admin' in .users.json)
 */
function isAdmin($username = null) {
    if ($username === null) $username = getCurrentUser();
    $users = loadUsers();
    return ($users[$username]['role'] ?? '') === 'admin';
}

// ── Session Management ────────────────────────────────────────────────────

/**
 * Get all active sessions with metadata
 * Returns array of session info, newest first
 */
function getSessions() {
    if (!is_dir(SESSIONS_DIR)) return [];
    $sessions = [];
    $currentSessId = session_id();

    foreach (glob(SESSIONS_DIR . '*.json') as $file) {
        $meta = json_decode(file_get_contents($file), true);
        if (!$meta) continue;
        $sessId = basename($file, '.json');
        $sessions[] = [
            'id'          => $sessId,
            'username'    => $meta['username'] ?? '?',
            'ip'          => $meta['ip'] ?? '?',
            'user_agent'  => $meta['user_agent'] ?? '',
            'created'     => $meta['created'] ?? 0,
            'last_active' => $meta['last_active'] ?? 0,
            'remember_me' => $meta['remember_me'] ?? false,
            'current'     => ($sessId === $currentSessId)
        ];
    }

    usort($sessions, fn($a, $b) => $b['last_active'] - $a['last_active']);
    return $sessions;
}

/**
 * Close a specific session by ID
 */
function closeSession($sessId) {
    // Validate session ID format (alphanumeric)
    if (!preg_match('/^[a-zA-Z0-9,-]+$/', $sessId)) return false;
    $file = SESSIONS_DIR . $sessId . '.json';
    if (!file_exists($file)) return false;
    unlink($file);
    return true;
}

/**
 * Logoff all sessions (all users)
 */
function logoffAll() {
    if (!is_dir(SESSIONS_DIR)) return 0;
    $count = 0;
    foreach (glob(SESSIONS_DIR . '*.json') as $file) {
        unlink($file);
        $count++;
    }
    return $count;
}

/**
 * Logoff all sessions for a specific user
 */
function logoffAllForUser($username) {
    if (!is_dir(SESSIONS_DIR)) return 0;
    $count = 0;
    foreach (glob(SESSIONS_DIR . '*.json') as $file) {
        $meta = json_decode(file_get_contents($file), true);
        if (($meta['username'] ?? '') === $username) {
            unlink($file);
            $count++;
        }
    }
    return $count;
}

// ── File Ownership Tracking ───────────────────────────────────────────────

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
// API Key Management (Multiple keys + IP binding)
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
 * Migrate old format to new format if needed
 */
function migrateApiKeysFormat(&$keys) {
    $migrated = false;
    foreach ($keys as $username => &$data) {
        // Old format: { "key": "...", "created": ..., "last_used": ... }
        // New format: { "keys": [ { "id": "...", "key": "...", ... } ] }
        if (isset($data['key']) && !isset($data['keys'])) {
            $data = [
                'keys' => [
                    [
                        'id' => bin2hex(random_bytes(4)),
                        'key' => $data['key'],
                        'name' => 'Default',
                        'created' => $data['created'] ?? time(),
                        'last_used' => $data['last_used'] ?? null,
                        'allowed_ips' => null
                    ]
                ]
            ];
            $migrated = true;
        }
    }
    return $migrated;
}

/**
 * Generate a new API key for a user
 * @param string $username
 * @param string $name Optional name/label for the key
 * @param array|null $allowedIps Optional array of allowed IPs/CIDRs
 * @return array ['id' => ..., 'key' => ...]
 */
function generateApiKey($username, $name = null, $allowedIps = null) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    // Initialize user if not exists
    if (!isset($keys[$username])) {
        $keys[$username] = ['keys' => []];
    }

    // Generate secure random key (32 bytes = 64 hex chars)
    $keyId = bin2hex(random_bytes(4));
    $apiKey = bin2hex(random_bytes(32));

    $newKey = [
        'id' => $keyId,
        'key' => $apiKey,
        'name' => $name ?: 'Key ' . (count($keys[$username]['keys']) + 1),
        'created' => time(),
        'last_used' => null,
        'allowed_ips' => $allowedIps
    ];

    $keys[$username]['keys'][] = $newKey;
    saveApiKeys($keys);

    return ['id' => $keyId, 'key' => $apiKey];
}

/**
 * Get user's first API key (backward compatibility)
 */
function getUserApiKey($username) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);
    return $keys[$username]['keys'][0]['key'] ?? null;
}

/**
 * Get all API keys for a user
 * @return array of key objects (without the actual key value for security)
 */
function getUserApiKeys($username) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    if (!isset($keys[$username]['keys'])) {
        return [];
    }

    // Return keys with masked key values for display
    $result = [];
    foreach ($keys[$username]['keys'] as $keyData) {
        $allowedIps = $keyData['allowed_ips'] ?? null;
        $isAllowAll = is_array($allowedIps) && in_array('0.0.0.0/0', $allowedIps);
        $isAutoLearn = ($allowedIps === null || empty($allowedIps));
        $wasLearned = $keyData['learned_ip'] ?? false;

        $result[] = [
            'id' => $keyData['id'],
            'name' => $keyData['name'],
            'key_preview' => substr($keyData['key'], 0, 8) . '...' . substr($keyData['key'], -4),
            'created' => $keyData['created'],
            'last_used' => $keyData['last_used'],
            'allowed_ips' => $allowedIps,
            'is_allow_all' => $isAllowAll,
            'is_auto_learn' => $isAutoLearn,
            'was_learned' => $wasLearned
        ];
    }
    return $result;
}

/**
 * Get full API key by ID (for display after generation)
 */
function getApiKeyById($username, $keyId) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    if (!isset($keys[$username]['keys'])) {
        return null;
    }

    foreach ($keys[$username]['keys'] as $keyData) {
        if ($keyData['id'] === $keyId) {
            return $keyData['key'];
        }
    }
    return null;
}

/**
 * Check if IP matches allowed IPs list (supports CIDR notation)
 * Special values:
 *   - null/empty array: Auto-learn mode (will be set on first use)
 *   - ['0.0.0.0/0']: Allow from anywhere
 */
function isIpAllowed($ip, $allowedIps) {
    // Null = auto-learn mode, handled in validateApiKey
    if ($allowedIps === null || empty($allowedIps)) {
        return true;
    }

    foreach ($allowedIps as $allowed) {
        // 0.0.0.0/0 means allow all
        if ($allowed === '0.0.0.0/0' || $allowed === '::/0') {
            return true;
        }

        if (strpos($allowed, '/') !== false) {
            // CIDR notation
            if (ipInCidr($ip, $allowed)) {
                return true;
            }
        } else {
            // Exact match
            if ($ip === $allowed) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Check if IP is in CIDR range
 */
function ipInCidr($ip, $cidr) {
    list($subnet, $mask) = explode('/', $cidr);

    // Handle IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - (int)$mask);
        return ($ip & $mask) === ($subnet & $mask);
    }

    // For IPv6, do simple prefix matching
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);
        $maskBits = (int)$mask;

        for ($i = 0; $i < $maskBits / 8; $i++) {
            if ($ipBin[$i] !== $subnetBin[$i]) {
                return false;
            }
        }
        return true;
    }

    return false;
}

/**
 * Validate API key and return username if valid
 * Also checks IP restrictions and auto-learns IP if not set
 * @param string $apiKey
 * @param string|null $clientIp Optional client IP to validate
 * @param bool $returnDetails If true, returns array with user and key_id
 * @return string|array|null Username (or array if $returnDetails), null if invalid
 */
function validateApiKey($apiKey, $clientIp = null, $returnDetails = false) {
    $keys = loadApiKeys();
    $migrated = migrateApiKeysFormat($keys);

    if ($clientIp === null) {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? null;
    }

    foreach ($keys as $username => $data) {
        if (!isset($data['keys'])) continue;

        foreach ($data['keys'] as $idx => $keyData) {
            if (hash_equals($keyData['key'], $apiKey)) {
                $allowedIps = $keyData['allowed_ips'];
                $keyId = $keyData['id'];
                $keyName = $keyData['name'];

                // Auto-learn mode: if allowed_ips is null or empty, learn the IP
                if (($allowedIps === null || empty($allowedIps)) && $clientIp) {
                    $keys[$username]['keys'][$idx]['allowed_ips'] = [$clientIp];
                    $keys[$username]['keys'][$idx]['last_used'] = time();
                    $keys[$username]['keys'][$idx]['learned_ip'] = true;
                    saveApiKeys($keys);

                    if ($returnDetails) {
                        return ['user' => $username, 'key_id' => $keyId, 'key_name' => $keyName, 'learned_ip' => $clientIp];
                    }
                    return $username;
                }

                // Check IP restriction (0.0.0.0/0 allows all)
                if (!isIpAllowed($clientIp, $allowedIps)) {
                    return null; // IP not allowed
                }

                // Update last used timestamp
                $keys[$username]['keys'][$idx]['last_used'] = time();
                saveApiKeys($keys);

                if ($returnDetails) {
                    return ['user' => $username, 'key_id' => $keyId, 'key_name' => $keyName];
                }
                return $username;
            }
        }
    }

    // Save if migrated
    if ($migrated) {
        saveApiKeys($keys);
    }

    return null;
}

/**
 * Revoke a specific API key
 * @param string $username
 * @param string|null $keyId If null, revokes all keys (backward compat)
 */
function revokeApiKey($username, $keyId = null) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    if (!isset($keys[$username])) {
        return false;
    }

    if ($keyId === null) {
        // Revoke all keys
        unset($keys[$username]);
        saveApiKeys($keys);
        return true;
    }

    // Revoke specific key
    foreach ($keys[$username]['keys'] as $idx => $keyData) {
        if ($keyData['id'] === $keyId) {
            array_splice($keys[$username]['keys'], $idx, 1);
            if (empty($keys[$username]['keys'])) {
                unset($keys[$username]);
            }
            saveApiKeys($keys);
            return true;
        }
    }

    return false;
}

/**
 * Update allowed IPs for a specific key
 */
function updateApiKeyIps($username, $keyId, $allowedIps) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    if (!isset($keys[$username]['keys'])) {
        return false;
    }

    foreach ($keys[$username]['keys'] as $idx => &$keyData) {
        if ($keyData['id'] === $keyId) {
            $keyData['allowed_ips'] = $allowedIps;
            saveApiKeys($keys);
            return true;
        }
    }

    return false;
}

/**
 * Update API key name
 */
function updateApiKeyName($username, $keyId, $name) {
    $keys = loadApiKeys();
    migrateApiKeysFormat($keys);

    if (!isset($keys[$username]['keys'])) {
        return false;
    }

    foreach ($keys[$username]['keys'] as $idx => &$keyData) {
        if ($keyData['id'] === $keyId) {
            $keyData['name'] = $name;
            saveApiKeys($keys);
            return true;
        }
    }

    return false;
}
