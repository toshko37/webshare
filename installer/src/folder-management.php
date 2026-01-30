<?php
/**
 * WebShare Folder Management System
 * ==================================
 * Handles user folders, permissions, and file operations between folders
 */

define('FILES_BASE_DIR', __DIR__ . '/files/');
define('PUBLIC_FOLDER', '_public');
define('MAX_SUBFOLDER_DEPTH', 3); // Maximum folder nesting level

/**
 * Secure folder path sanitization
 * Prevents path traversal attacks including ....// bypass attempts
 * @param string $folder Raw folder path
 * @return string Sanitized folder path
 */
function secureFolderPath($folder) {
    // First: allow only safe characters
    $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);

    // Loop until no changes (handles ....// → ../ → empty)
    do {
        $prev = $folder;
        $folder = str_replace(['..', './'], '', $folder);
        $folder = preg_replace('#/+#', '/', $folder); // collapse multiple slashes
    } while ($prev !== $folder);

    // Remove leading/trailing slashes
    $folder = trim($folder, '/');

    return $folder;
}

/**
 * Get all available folders for a user
 * @param string $username Current user
 * @return array List of folders the user can access
 */
function getUserFolders($username) {
    $folders = [];

    // Everyone has access to public folder
    $folders[] = [
        'name' => PUBLIC_FOLDER,
        'display' => 'Public',
        'icon' => '📂',
        'path' => FILES_BASE_DIR . PUBLIC_FOLDER . '/',
        'type' => 'public'
    ];

    // User's own folder
    $userFolder = FILES_BASE_DIR . $username . '/';
    if (is_dir($userFolder)) {
        $folders[] = [
            'name' => $username,
            'display' => 'My Files',
            'icon' => '📁',
            'path' => $userFolder,
            'type' => 'own'
        ];
    }

    // Admin can see all user folders
    if ($username === 'admin') {
        $allFolders = glob(FILES_BASE_DIR . '*', GLOB_ONLYDIR);
        foreach ($allFolders as $folder) {
            $folderName = basename($folder);
            // Skip public and admin's own folder (already added)
            if ($folderName === PUBLIC_FOLDER || $folderName === 'admin') {
                continue;
            }
            $folders[] = [
                'name' => $folderName,
                'display' => $folderName,
                'icon' => '👤',
                'path' => $folder . '/',
                'type' => 'user'
            ];
        }
    }

    return $folders;
}

/**
 * Check if user has access to a folder
 * @param string $username Current user
 * @param string $folderName Target folder name
 * @return bool
 */
function canAccessFolder($username, $folderName) {
    // Everyone can access public folder
    if ($folderName === PUBLIC_FOLDER) {
        return true;
    }

    // Users can access their own folder
    if ($folderName === $username) {
        return true;
    }

    // Admin can access all folders
    if ($username === 'admin') {
        return true;
    }

    return false;
}

/**
 * Create folder for new user
 * @param string $username Username
 * @return bool Success
 */
function createUserFolder($username) {
    $folderPath = FILES_BASE_DIR . $username;

    if (!is_dir($folderPath)) {
        if (mkdir($folderPath, 0755, true)) {
            // Try to set ownership to www-data
            @chown($folderPath, 'www-data');
            @chgrp($folderPath, 'www-data');
            return true;
        }
        return false;
    }
    return true; // Already exists
}

/**
 * Delete user folder (only if empty or force)
 * @param string $username Username
 * @param bool $force Delete even if not empty
 * @return bool Success
 */
function deleteUserFolder($username, $force = false) {
    $folderPath = FILES_BASE_DIR . $username;

    if (!is_dir($folderPath)) {
        return true; // Already doesn't exist
    }

    // Check if folder is empty
    $files = array_diff(scandir($folderPath), ['.', '..']);

    if (!empty($files) && !$force) {
        return false; // Folder not empty
    }

    // Delete all files if force
    if ($force) {
        foreach ($files as $file) {
            $filePath = $folderPath . '/' . $file;
            if (is_file($filePath)) {
                unlink($filePath);
            }
        }
    }

    return rmdir($folderPath);
}

/**
 * Move file between folders
 * @param string $filename Filename
 * @param string $fromFolder Source folder name
 * @param string $toFolder Destination folder name
 * @param string $username User performing the action
 * @return array Result with success status
 */
function moveFile($filename, $fromFolder, $toFolder, $username) {
    // Security: validate folder access
    if (!canAccessFolder($username, $fromFolder)) {
        return ['success' => false, 'error' => 'Access denied to source folder'];
    }
    if (!canAccessFolder($username, $toFolder)) {
        return ['success' => false, 'error' => 'Access denied to destination folder'];
    }

    // Build paths
    $sourcePath = FILES_BASE_DIR . $fromFolder . '/' . basename($filename);
    $destPath = FILES_BASE_DIR . $toFolder . '/' . basename($filename);

    // Validate source exists
    if (!file_exists($sourcePath)) {
        return ['success' => false, 'error' => 'Source file not found'];
    }

    // Check if destination exists
    if (file_exists($destPath)) {
        // Generate unique name with unique ID to prevent race conditions
        $info = pathinfo($filename);
        $name = $info['filename'];
        $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
        $uniqueId = bin2hex(random_bytes(4));
        $newFilename = $name . '_' . $uniqueId . $ext;
        $destPath = FILES_BASE_DIR . $toFolder . '/' . $newFilename;
    } else {
        $newFilename = $filename;
    }

    // Move file
    if (rename($sourcePath, $destPath)) {
        // Update metadata
        updateFileMetadataAfterMove($filename, $newFilename, $fromFolder, $toFolder, $username);

        return [
            'success' => true,
            'newFilename' => $newFilename,
            'renamed' => ($newFilename !== $filename)
        ];
    }

    return ['success' => false, 'error' => 'Failed to move file'];
}

/**
 * Update file metadata after move
 */
function updateFileMetadataAfterMove($oldFilename, $newFilename, $fromFolder, $toFolder, $username) {
    $metaFile = __DIR__ . '/.files-meta.json';
    $meta = [];

    if (file_exists($metaFile)) {
        $meta = json_decode(file_get_contents($metaFile), true) ?? [];
    }

    // Build old and new keys (folder/filename)
    $oldKey = $fromFolder . '/' . $oldFilename;
    $newKey = $toFolder . '/' . $newFilename;

    // Also check for old-style keys (just filename)
    if (isset($meta[$oldFilename]) && !isset($meta[$oldKey])) {
        $meta[$oldKey] = $meta[$oldFilename];
        unset($meta[$oldFilename]);
    }

    // Move metadata to new key
    if (isset($meta[$oldKey])) {
        $meta[$newKey] = $meta[$oldKey];
        $meta[$newKey]['folder'] = $toFolder;
        $meta[$newKey]['moved_at'] = time();
        $meta[$newKey]['moved_by'] = $username;
        unset($meta[$oldKey]);
    } else {
        // Create new metadata
        $meta[$newKey] = [
            'folder' => $toFolder,
            'moved_at' => time(),
            'moved_by' => $username
        ];
    }

    file_put_contents($metaFile, json_encode($meta, JSON_PRETTY_PRINT), LOCK_EX);
}

/**
 * Get files in a folder
 * @param string $folderName Folder name
 * @param string $username User requesting (for permission check)
 * @return array List of files
 */
function getFilesInFolder($folderName, $username) {
    if (!canAccessFolder($username, $folderName)) {
        return [];
    }

    $folderPath = FILES_BASE_DIR . $folderName . '/';

    if (!is_dir($folderPath)) {
        return [];
    }

    $files = [];
    $items = scandir($folderPath);

    foreach ($items as $item) {
        // Skip hidden files and directories
        if ($item[0] === '.' || is_dir($folderPath . $item)) {
            continue;
        }

        $filePath = $folderPath . $item;
        $files[] = [
            'name' => $item,
            'folder' => $folderName,
            'size' => filesize($filePath),
            'modified' => filemtime($filePath),
            'path' => $filePath
        ];
    }

    // Sort by modified time (newest first)
    usort($files, fn($a, $b) => $b['modified'] - $a['modified']);

    return $files;
}

/**
 * Get folder path for upload
 * @param string $targetUser Target username (null for public)
 * @return string|null Folder path or null if invalid
 */
function getUploadFolder($targetUser = null) {
    if ($targetUser === null) {
        return FILES_BASE_DIR . PUBLIC_FOLDER . '/';
    }

    $folderPath = FILES_BASE_DIR . $targetUser . '/';

    if (is_dir($folderPath)) {
        return $folderPath;
    }

    return null;
}

/**
 * Validate folder name
 * @param string $name Folder name
 * @return bool
 */
function isValidFolderName($name) {
    // Only alphanumeric, dash, underscore, space
    if (!preg_match('/^[a-zA-Z0-9_\- ]+$/', $name)) {
        return false;
    }

    // Max length
    if (strlen($name) > 50) {
        return false;
    }

    // Reserved names
    $reserved = ['.', '..', '_public', 'public'];
    if (in_array(strtolower($name), $reserved)) {
        return false;
    }

    return true;
}

// ============================================
// SUBFOLDER FUNCTIONS
// ============================================

/**
 * Parse folder path into base folder and subpath
 * @param string $folderPath Full folder path (e.g., "admin/Projects/2024")
 * @return array ['base' => 'admin', 'subpath' => 'Projects/2024', 'parts' => ['Projects', '2024']]
 */
function parseFolderPath($folderPath) {
    $parts = array_filter(explode('/', $folderPath), fn($p) => $p !== '');
    $base = array_shift($parts) ?? '';

    return [
        'base' => $base,
        'subpath' => implode('/', $parts),
        'parts' => $parts,
        'depth' => count($parts)
    ];
}

/**
 * Get full filesystem path for a folder
 * @param string $folderPath Folder path (e.g., "admin/Projects")
 * @return string Full filesystem path
 */
function getFullFolderPath($folderPath) {
    return FILES_BASE_DIR . $folderPath . '/';
}

/**
 * Check if user can access a folder path (including subfolders)
 * @param string $username Current user
 * @param string $folderPath Full folder path
 * @return bool
 */
function canAccessFolderPath($username, $folderPath) {
    $parsed = parseFolderPath($folderPath);
    return canAccessFolder($username, $parsed['base']);
}

/**
 * Get folder depth
 * @param string $folderPath Folder path
 * @return int Depth (0 = root user folder, 1 = first subfolder, etc.)
 */
function getFolderDepth($folderPath) {
    $parsed = parseFolderPath($folderPath);
    return $parsed['depth'];
}

/**
 * Create a subfolder
 * @param string $parentPath Parent folder path (e.g., "admin" or "admin/Projects")
 * @param string $folderName New folder name
 * @param string $username User creating the folder
 * @return array Result
 */
function createSubfolder($parentPath, $folderName, $username) {
    // Validate access
    if (!canAccessFolderPath($username, $parentPath)) {
        return ['success' => false, 'error' => 'Access denied'];
    }

    // Validate folder name
    if (!isValidFolderName($folderName)) {
        return ['success' => false, 'error' => 'Invalid folder name. Use only letters, numbers, dash, underscore, space.'];
    }

    // Check depth limit
    $newPath = $parentPath . '/' . $folderName;
    if (getFolderDepth($newPath) > MAX_SUBFOLDER_DEPTH) {
        return ['success' => false, 'error' => 'Maximum folder depth exceeded (max ' . MAX_SUBFOLDER_DEPTH . ' levels)'];
    }

    $fullPath = getFullFolderPath($newPath);

    // Check if already exists
    if (is_dir($fullPath)) {
        return ['success' => false, 'error' => 'Folder already exists'];
    }

    // Create folder
    if (mkdir($fullPath, 0755, true)) {
        @chown($fullPath, 'www-data');
        @chgrp($fullPath, 'www-data');
        return ['success' => true, 'path' => $newPath];
    }

    return ['success' => false, 'error' => 'Failed to create folder'];
}

/**
 * Delete a subfolder (must be empty)
 * @param string $folderPath Folder path to delete
 * @param string $username User deleting
 * @return array Result
 */
function deleteSubfolder($folderPath, $username) {
    // Validate access
    if (!canAccessFolderPath($username, $folderPath)) {
        return ['success' => false, 'error' => 'Access denied'];
    }

    // Can't delete root user folders
    $parsed = parseFolderPath($folderPath);
    if (empty($parsed['subpath'])) {
        return ['success' => false, 'error' => 'Cannot delete root folder'];
    }

    $fullPath = getFullFolderPath($folderPath);

    if (!is_dir($fullPath)) {
        return ['success' => false, 'error' => 'Folder not found'];
    }

    // Check if empty
    $items = array_diff(scandir($fullPath), ['.', '..']);
    if (!empty($items)) {
        return ['success' => false, 'error' => 'Folder is not empty'];
    }

    if (rmdir($fullPath)) {
        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Failed to delete folder'];
}

/**
 * Get subfolders in a folder
 * @param string $folderPath Parent folder path
 * @param string $username User requesting
 * @return array List of subfolders
 */
function getSubfolders($folderPath, $username) {
    if (!canAccessFolderPath($username, $folderPath)) {
        return [];
    }

    $fullPath = getFullFolderPath($folderPath);

    if (!is_dir($fullPath)) {
        return [];
    }

    $subfolders = [];
    $items = scandir($fullPath);

    foreach ($items as $item) {
        if ($item[0] === '.') continue;

        $itemPath = $fullPath . $item;
        if (is_dir($itemPath)) {
            $subfolders[] = [
                'name' => $item,
                'path' => $folderPath . '/' . $item,
                'modified' => filemtime($itemPath)
            ];
        }
    }

    // Sort alphabetically
    usort($subfolders, fn($a, $b) => strcasecmp($a['name'], $b['name']));

    return $subfolders;
}

/**
 * Get all subfolders recursively for a folder
 * @param string $basePath Base folder path
 * @param string $username User requesting
 * @param int $maxDepth Maximum depth to recurse
 * @return array List of all subfolders with paths
 */
function getAllSubfoldersRecursive($basePath, $username, $maxDepth = 3) {
    $allSubfolders = [];

    $recurse = function($folderPath, $depth, $prefix = '') use (&$recurse, &$allSubfolders, $username, $maxDepth) {
        if ($depth > $maxDepth) return;

        $subs = getSubfolders($folderPath, $username);

        foreach ($subs as $sub) {
            $displayName = $prefix . ($prefix ? '/' : '') . $sub['name'];
            $allSubfolders[] = [
                'name' => $sub['name'],
                'path' => $sub['path'],
                'display' => $displayName,
                'depth' => $depth
            ];

            // Recurse into subfolder
            $recurse($sub['path'], $depth + 1, $displayName);
        }
    };

    $recurse($basePath, 1);

    return $allSubfolders;
}

/**
 * Get files and subfolders in a folder path
 * @param string $folderPath Folder path
 * @param string $username User requesting
 * @return array ['files' => [...], 'subfolders' => [...]]
 */
function getFolderContents($folderPath, $username) {
    if (!canAccessFolderPath($username, $folderPath)) {
        return ['files' => [], 'subfolders' => []];
    }

    $fullPath = getFullFolderPath($folderPath);

    if (!is_dir($fullPath)) {
        return ['files' => [], 'subfolders' => []];
    }

    $files = [];
    $subfolders = [];
    $items = scandir($fullPath);

    foreach ($items as $item) {
        if ($item[0] === '.') continue;

        $itemPath = $fullPath . $item;

        if (is_dir($itemPath)) {
            $subfolders[] = [
                'name' => $item,
                'path' => $folderPath . '/' . $item,
                'modified' => filemtime($itemPath)
            ];
        } else {
            $files[] = [
                'name' => $item,
                'folder' => $folderPath,
                'size' => filesize($itemPath),
                'modified' => filemtime($itemPath),
                'path' => $itemPath
            ];
        }
    }

    // Sort
    usort($subfolders, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    usort($files, fn($a, $b) => $b['modified'] - $a['modified']);

    return ['files' => $files, 'subfolders' => $subfolders];
}

/**
 * Build breadcrumb navigation
 * @param string $folderPath Current folder path
 * @return array Breadcrumb items
 */
function buildBreadcrumb($folderPath) {
    $parsed = parseFolderPath($folderPath);
    $breadcrumb = [];

    // Add base folder
    $breadcrumb[] = [
        'name' => $parsed['base'] === PUBLIC_FOLDER ? 'Public' : ($parsed['base'] ?: 'Home'),
        'path' => $parsed['base']
    ];

    // Add subfolders
    $currentPath = $parsed['base'];
    foreach ($parsed['parts'] as $part) {
        $currentPath .= '/' . $part;
        $breadcrumb[] = [
            'name' => $part,
            'path' => $currentPath
        ];
    }

    return $breadcrumb;
}

/**
 * Move file with subfolder support
 * @param string $filename Filename
 * @param string $fromPath Source folder path
 * @param string $toPath Destination folder path
 * @param string $username User performing action
 * @return array Result
 */
function moveFileToPath($filename, $fromPath, $toPath, $username) {
    // Validate access
    if (!canAccessFolderPath($username, $fromPath)) {
        return ['success' => false, 'error' => 'Access denied to source folder'];
    }
    if (!canAccessFolderPath($username, $toPath)) {
        return ['success' => false, 'error' => 'Access denied to destination folder'];
    }

    $sourcePath = getFullFolderPath($fromPath) . basename($filename);
    $destFolder = getFullFolderPath($toPath);

    if (!file_exists($sourcePath)) {
        return ['success' => false, 'error' => 'Source file not found'];
    }

    if (!is_dir($destFolder)) {
        return ['success' => false, 'error' => 'Destination folder not found'];
    }

    $destPath = $destFolder . basename($filename);
    $newFilename = basename($filename);

    // Handle name collision with unique ID to prevent race conditions
    if (file_exists($destPath)) {
        $info = pathinfo($filename);
        $name = $info['filename'];
        $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
        $uniqueId = bin2hex(random_bytes(4));
        $newFilename = $name . '_' . $uniqueId . $ext;
        $destPath = $destFolder . $newFilename;
    }

    if (rename($sourcePath, $destPath)) {
        return [
            'success' => true,
            'newFilename' => $newFilename,
            'renamed' => ($newFilename !== basename($filename))
        ];
    }

    return ['success' => false, 'error' => 'Failed to move file'];
}
