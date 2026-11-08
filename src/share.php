<?php
// Share Token Management
// =======================
// This script handles generation and management of public share links

require_once __DIR__ . '/security-check.php';
if (session_status() === PHP_SESSION_NONE) session_start();
header('Content-Type: application/json');

// CSRF validation for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrfToken)) {
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'CSRF validation failed']));
    }
}

// Include required files
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/user-management.php';

$tokensFile = __DIR__ . '/.tokens.json';
$filesDir = __DIR__ . '/files/';

// Load existing tokens
function loadTokens($tokensFile) {
    return ws_json_read($tokensFile);   // I4: shared lock
}

// Save tokens
function saveTokens($tokensFile, $tokens) {
    file_put_contents($tokensFile, json_encode($tokens, JSON_PRETTY_PRINT), LOCK_EX);
    chmod($tokensFile, 0600); // Make it readable only by owner
}

// Generate unique token (16 bytes = 32 hex characters, 128 bits entropy)
// Old tokens (6 chars) still work for backwards compatibility
function generateToken() {
    return bin2hex(random_bytes(16));
}

// Resolve filename/folder from the request and check access.
// Returns [filename, folder|null, fileKey] or sends an error.
function shareTarget($src) {
    $filename = basename($src['filename'] ?? '');
    $folder = isset($src['folder']) && $src['folder'] !== '' ? secureFolderPath($src['folder']) : null;
    if ($filename === '') {
        echo json_encode(['success' => false, 'error' => 'No filename provided']);
        exit;
    }
    $user = getCurrentUser();
    // Files outside a folder only exist in very old installs: admin only
    if ($folder ? !canAccessFolderPath($user, $folder) : !isAdmin($user)) {
        echo json_encode(['success' => false, 'error' => 'Access denied to folder']);
        exit;
    }
    return [$filename, $folder, $folder ? $folder . '/' . $filename : $filename];
}

// Exact match on folder + name. Matching on the bare name used to hit
// same-named files in other folders (other users' links).
function shareFindToken($tokens, $fileKey) {
    foreach ($tokens as $token => $data) {
        $tokenKey = !empty($data['folder']) ? ($data['folder'] . '/' . ($data['filename'] ?? '')) : ($data['filename'] ?? '');
        if ($tokenKey === $fileKey) return $token;
    }
    return null;
}

function shareUrl($token) {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    return $protocol . '://' . $_SERVER['HTTP_HOST'] . '/p?t=' . $token;
}

// I7: optional expiry, in days from now (0 = never)
const SHARE_EXPIRY_DAYS = [0, 1, 7, 30, 90];

function shareResponse($token, $data, $extra = []) {
    return json_encode(['success' => true, 'token' => $token, 'url' => shareUrl($token),
        'expires' => $data['expires'] ?? null, 'expiry_days' => $data['expiry_days'] ?? 0] + $extra);
}

// Handle requests
$action = $_GET['action'] ?? '';

// I4: actions that change .tokens.json hold its lock from load to save
if (in_array($action, ['generate', 'regenerate', 'set_expiry', 'revoke'], true)) {
    ws_json_mutex($tokensFile);
}

switch ($action) {
    case 'generate':
        [$filename, $folder, $fileKey] = shareTarget($_POST);
        $filePath = $filesDir . $fileKey;
        if (!file_exists($filePath) || !is_file($filePath)) {
            echo json_encode(['success' => false, 'error' => 'File not found']);
            exit;
        }
        $tokens = loadTokens($tokensFile);
        $token = shareFindToken($tokens, $fileKey);
        // An expired link is replaced by a fresh one
        if ($token && !empty($tokens[$token]['expires']) && $tokens[$token]['expires'] < time()) {
            unset($tokens[$token]);
            $token = null;
        }
        if (!$token) {
            do { $token = generateToken(); } while (isset($tokens[$token]));
            $tokens[$token] = ['filename' => $filename, 'folder' => $folder, 'created' => time()];
            saveTokens($tokensFile, $tokens);
            $folderDisplay = $folder ? " in folder: $folder" : '';
            writeAuditLog('share_create', "Created share link for: $filename$folderDisplay (token: $token)");
        }
        echo shareResponse($token, $tokens[$token]);
        break;

    case 'regenerate':
        [$filename, $folder, $fileKey] = shareTarget($_POST);
        $tokens = loadTokens($tokensFile);
        $oldToken = shareFindToken($tokens, $fileKey);
        $expires = null;
        if ($oldToken) {
            // Keep the chosen lifetime, counted from now
            $old = $tokens[$oldToken];
            if (!empty($old['expiry_days'])) $expires = time() + $old['expiry_days'] * 86400;
            unset($tokens[$oldToken]);
        }
        do { $newToken = generateToken(); } while (isset($tokens[$newToken]));
        $tokens[$newToken] = ['filename' => $filename, 'folder' => $folder, 'created' => time()];
        if ($expires) {
            $tokens[$newToken]['expires'] = $expires;
            $tokens[$newToken]['expiry_days'] = $old['expiry_days'];
        }
        saveTokens($tokensFile, $tokens);
        $folderDisplay = $folder ? " in folder: $folder" : '';
        if ($oldToken) {
            writeAuditLog('share_regenerate', "Regenerated share link for: $filename$folderDisplay (old: $oldToken -> new: $newToken)");
        } else {
            writeAuditLog('share_create', "Created share link for: $filename$folderDisplay (token: $newToken)");
        }
        echo shareResponse($newToken, $tokens[$newToken], ['oldToken' => $oldToken]);
        break;

    case 'set_expiry':
        [$filename, $folder, $fileKey] = shareTarget($_POST);
        $days = (int)($_POST['days'] ?? 0);
        if (!in_array($days, SHARE_EXPIRY_DAYS, true)) {
            echo json_encode(['success' => false, 'error' => 'Invalid expiry']);
            exit;
        }
        $tokens = loadTokens($tokensFile);
        $token = shareFindToken($tokens, $fileKey);
        if (!$token) {
            echo json_encode(['success' => false, 'error' => 'No share link found']);
            exit;
        }
        if ($days) {
            $tokens[$token]['expires'] = time() + $days * 86400;
            $tokens[$token]['expiry_days'] = $days;
        } else {
            unset($tokens[$token]['expires'], $tokens[$token]['expiry_days']);
        }
        saveTokens($tokensFile, $tokens);
        $folderDisplay = $folder ? " in folder: $folder" : '';
        writeAuditLog('share_expiry', "Share link for: $filename$folderDisplay expires: " . ($days ? date('d.m.Y H:i', $tokens[$token]['expires']) : 'never'));
        echo shareResponse($token, $tokens[$token]);
        break;

    case 'revoke':
        [$filename, $folder, $fileKey] = shareTarget($_POST);
        $tokens = loadTokens($tokensFile);
        $token = shareFindToken($tokens, $fileKey);
        if ($token) {
            unset($tokens[$token]);
            saveTokens($tokensFile, $tokens);
            $folderDisplay = $folder ? " from folder: $folder" : '';
            writeAuditLog('share_revoke', "Revoked share link for: $filename$folderDisplay");
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'No share link found']);
        }
        break;

    case 'status':
        [$filename, $folder, $fileKey] = shareTarget($_GET);
        $tokens = loadTokens($tokensFile);
        $token = shareFindToken($tokens, $fileKey);
        if ($token) {
            echo shareResponse($token, $tokens[$token], ['hasShare' => true]);
        } else {
            echo json_encode(['success' => true, 'hasShare' => false]);
        }
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Invalid action']);
}
