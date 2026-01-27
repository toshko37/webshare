<?php
// Share Token Management
// =======================
// This script handles generation and management of public share links

header('Content-Type: application/json');

// Include required files
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/user-management.php';

$tokensFile = __DIR__ . '/.tokens.json';
$filesDir = __DIR__ . '/files/';

// Load existing tokens
function loadTokens($tokensFile) {
    if (file_exists($tokensFile)) {
        $content = file_get_contents($tokensFile);
        return json_decode($content, true) ?: [];
    }
    return [];
}

// Save tokens
function saveTokens($tokensFile, $tokens) {
    file_put_contents($tokensFile, json_encode($tokens, JSON_PRETTY_PRINT));
    chmod($tokensFile, 0600); // Make it readable only by owner
}

// Generate unique token (6 characters: alphanumeric)
function generateToken() {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $token = '';
    for ($i = 0; $i < 6; $i++) {
        $token .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $token;
}

// Handle requests
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'generate':
        // Generate a new share link for a file
        $filename = basename($_POST['filename'] ?? '');
        $folder = isset($_POST['folder']) ? $_POST['folder'] : null;

        if (empty($filename)) {
            echo json_encode(['success' => false, 'error' => 'No filename provided']);
            exit;
        }

        // Build file path with folder support
        if ($folder) {
            // Sanitize folder path
            $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);
            $folder = trim($folder, '/');

            // Check folder access
            $currentUser = getCurrentUser();
            if (!canAccessFolderPath($currentUser, $folder)) {
                echo json_encode(['success' => false, 'error' => 'Access denied to folder']);
                exit;
            }

            $filePath = $filesDir . $folder . '/' . $filename;
            $fileKey = $folder . '/' . $filename; // Key for token lookup
        } else {
            $filePath = $filesDir . $filename;
            $fileKey = $filename;
        }

        if (!file_exists($filePath) || !is_file($filePath)) {
            echo json_encode(['success' => false, 'error' => 'File not found']);
            exit;
        }

        // Load existing tokens
        $tokens = loadTokens($tokensFile);

        // Check if file already has a token (check both with and without folder)
        $existingToken = null;
        foreach ($tokens as $token => $data) {
            $tokenKey = isset($data['folder']) ? ($data['folder'] . '/' . $data['filename']) : $data['filename'];
            if ($tokenKey === $fileKey || $data['filename'] === $filename) {
                $existingToken = $token;
                break;
            }
        }

        // If no token exists, generate new one
        if (!$existingToken) {
            // Generate unique token (ensure no collision)
            do {
                $token = generateToken();
            } while (isset($tokens[$token]));

            $tokens[$token] = [
                'filename' => $filename,
                'folder' => $folder,
                'created' => time(),
            ];
            saveTokens($tokensFile, $tokens);

            // Audit log - new share link created
            $folderDisplay = $folder ? " in folder: $folder" : '';
            writeAuditLog('share_create', "Created share link for: $filename$folderDisplay (token: $token)");
        } else {
            $token = $existingToken;
        }

        // Generate share URL (short format)
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $shareUrl = $protocol . '://' . $host . '/p?t=' . $token;

        echo json_encode([
            'success' => true,
            'token' => $token,
            'url' => $shareUrl,
        ]);
        break;

    case 'regenerate':
        // Regenerate share link with new token (invalidates old link)
        $filename = basename($_POST['filename'] ?? '');
        $folder = isset($_POST['folder']) ? $_POST['folder'] : null;

        if (empty($filename)) {
            echo json_encode(['success' => false, 'error' => 'No filename provided']);
            exit;
        }

        // Build file key with folder support
        if ($folder) {
            $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);
            $folder = trim($folder, '/');
            $fileKey = $folder . '/' . $filename;
        } else {
            $fileKey = $filename;
        }

        $tokens = loadTokens($tokensFile);

        // Find and remove old token for this file
        $oldToken = null;
        foreach ($tokens as $token => $data) {
            $tokenKey = isset($data['folder']) ? ($data['folder'] . '/' . $data['filename']) : $data['filename'];
            if ($tokenKey === $fileKey || $data['filename'] === $filename) {
                $oldToken = $token;
                unset($tokens[$token]);
                break;
            }
        }

        // Generate new unique token
        do {
            $newToken = generateToken();
        } while (isset($tokens[$newToken]));

        $tokens[$newToken] = [
            'filename' => $filename,
            'folder' => $folder,
            'created' => time(),
        ];
        saveTokens($tokensFile, $tokens);

        // Audit log
        $folderDisplay = $folder ? " in folder: $folder" : '';
        if ($oldToken) {
            writeAuditLog('share_regenerate', "Regenerated share link for: $filename$folderDisplay (old: $oldToken -> new: $newToken)");
        } else {
            writeAuditLog('share_create', "Created share link for: $filename$folderDisplay (token: $newToken)");
        }

        // Generate share URL
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $shareUrl = $protocol . '://' . $host . '/p?t=' . $newToken;

        echo json_encode([
            'success' => true,
            'token' => $newToken,
            'url' => $shareUrl,
            'oldToken' => $oldToken
        ]);
        break;

    case 'revoke':
        // Revoke a share link
        $filename = basename($_POST['filename'] ?? '');
        $folder = isset($_POST['folder']) ? $_POST['folder'] : null;

        if (empty($filename)) {
            echo json_encode(['success' => false, 'error' => 'No filename provided']);
            exit;
        }

        // Build file key with folder support
        if ($folder) {
            $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);
            $folder = trim($folder, '/');
            $fileKey = $folder . '/' . $filename;
        } else {
            $fileKey = $filename;
        }

        $tokens = loadTokens($tokensFile);

        // Find and remove token for this file
        $removed = false;
        foreach ($tokens as $token => $data) {
            $tokenKey = isset($data['folder']) ? ($data['folder'] . '/' . $data['filename']) : $data['filename'];
            if ($tokenKey === $fileKey || $data['filename'] === $filename) {
                unset($tokens[$token]);
                $removed = true;
                break;
            }
        }

        if ($removed) {
            saveTokens($tokensFile, $tokens);

            // Audit log - share link revoked
            $folderDisplay = $folder ? " from folder: $folder" : '';
            writeAuditLog('share_revoke', "Revoked share link for: $filename$folderDisplay");

            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'No share link found']);
        }
        break;

    case 'status':
        // Check if file has an active share link
        $filename = basename($_GET['filename'] ?? '');
        $folder = isset($_GET['folder']) ? $_GET['folder'] : null;

        if (empty($filename)) {
            echo json_encode(['success' => false, 'error' => 'No filename provided']);
            exit;
        }

        // Build file key with folder support
        if ($folder) {
            $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);
            $folder = trim($folder, '/');
            $fileKey = $folder . '/' . $filename;
        } else {
            $fileKey = $filename;
        }

        $tokens = loadTokens($tokensFile);

        foreach ($tokens as $token => $data) {
            $tokenKey = isset($data['folder']) ? ($data['folder'] . '/' . $data['filename']) : $data['filename'];
            if ($tokenKey === $fileKey || $data['filename'] === $filename) {
                $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
                $host = $_SERVER['HTTP_HOST'];
                $shareUrl = $protocol . '://' . $host . '/p?t=' . $token;

                echo json_encode([
                    'success' => true,
                    'hasShare' => true,
                    'url' => $shareUrl,
                ]);
                exit;
            }
        }

        echo json_encode(['success' => true, 'hasShare' => false]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Invalid action']);
}
