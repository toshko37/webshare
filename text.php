<?php
// Text Sharing API
// =================
// Creates shared text snippets with rich formatting

// CONFIGURATION - Easy to change
define('TEXT_EXPIRE_HOURS', 24); // ← Change expire time here (in hours)
define('TEXT_MAX_SIZE', 1000000); // 1MB in characters

// Security: HTML sanitizer
require_once __DIR__ . '/html-sanitizer.php';

// Audit logging
require_once __DIR__ . '/audit-log.php';

$textsDir = __DIR__ . '/texts/';
$metadataFile = __DIR__ . '/.texts.json';

// Clean up expired texts on every load
cleanupExpiredTexts($textsDir, $metadataFile);

// Handle text creation (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create'])) {
    header('Content-Type: application/json');

    $html = $_POST['html'] ?? '';

    if (empty($html)) {
        echo json_encode(['success' => false, 'error' => 'No content provided']);
        exit;
    }

    // SECURITY: Sanitize HTML to prevent XSS
    $html = sanitizeHtml($html);

    if (strlen($html) > TEXT_MAX_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Content too large (max 1MB)']);
        exit;
    }

    // Generate unique token
    $token = generateToken(6);
    while (file_exists($textsDir . '.' . $token . '.html')) {
        $token = generateToken(6);
    }

    // Generate edit key
    $editKey = generateToken(12);

    // Save HTML file
    $filePath = $textsDir . '.' . $token . '.html';
    if (!file_put_contents($filePath, $html)) {
        echo json_encode(['success' => false, 'error' => 'Failed to save text']);
        exit;
    }

    // Update metadata
    $metadata = loadMetadata($metadataFile);
    $plainText = strip_tags($html);
    $preview = mb_substr($plainText, 0, 50);
    if (mb_strlen($plainText) > 50) {
        $preview .= '...';
    }

    $metadata[$token] = [
        'created' => time(),
        'expires' => time() + (TEXT_EXPIRE_HOURS * 3600),
        'size' => strlen($html),
        'preview' => $preview,
        'views' => 0,
        'edit_key' => $editKey
    ];

    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_create', "Created text: $token (" . strlen($html) . " chars)");

    $viewUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $token;
    $editUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $token . '?edit=' . $editKey;

    echo json_encode([
        'success' => true,
        'url' => $viewUrl,
        'view_url' => $viewUrl,
        'edit_url' => $editUrl,
        'token' => $token,
        'edit_key' => $editKey
    ]);
    exit;
}

// Handle text deletion (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_text'])) {
    header('Content-Type: application/json');

    $token = $_POST['delete_text'];
    $filePath = $textsDir . '.' . $token . '.html';

    if (file_exists($filePath)) {
        unlink($filePath);

        // Remove from metadata
        $metadata = loadMetadata($metadataFile);
        unset($metadata[$token]);
        saveMetadata($metadataFile, $metadata);

        // Audit log
        writeAuditLog('text_delete', "Deleted text: $token");

        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Text not found']);
    }
    exit;
}

// Handle text extend (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['extend_text'])) {
    header('Content-Type: application/json');

    $token = $_POST['extend_text'];
    $duration = $_POST['duration'] ?? '1d';

    $metadata = loadMetadata($metadataFile);

    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Text not found']);
        exit;
    }

    $currentExpires = $metadata[$token]['expires'];

    switch ($duration) {
        case '1d':
            $newExpires = $currentExpires + (24 * 3600);
            break;
        case '1w':
            $newExpires = $currentExpires + (7 * 24 * 3600);
            break;
        case '1m':
            $newExpires = $currentExpires + (30 * 24 * 3600);
            break;
        case '6m':
            $newExpires = $currentExpires + (180 * 24 * 3600);
            break;
        case 'permanent':
            $newExpires = time() + (10 * 365 * 24 * 3600);
            break;
        default:
            $newExpires = $currentExpires + (24 * 3600);
    }

    $metadata[$token]['expires'] = $newExpires;
    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_extend', "Extended text: $token by $duration");

    // Format new expiration for display
    $expiresIn = $newExpires - time();
    $parts = [];

    $years = floor($expiresIn / (365 * 24 * 3600));
    $expiresIn %= (365 * 24 * 3600);

    $months = floor($expiresIn / (30 * 24 * 3600));
    $expiresIn %= (30 * 24 * 3600);

    $days = floor($expiresIn / (24 * 3600));
    $expiresIn %= (24 * 3600);

    $hours = floor($expiresIn / 3600);
    $minutes = floor(($expiresIn % 3600) / 60);

    if ($years > 0) $parts[] = $years . 'y';
    if ($months > 0) $parts[] = $months . 'm';
    if ($days > 0) $parts[] = $days . 'd';
    if (empty($parts) || ($years == 0 && $months == 0 && $days < 2)) {
        if ($hours > 0) $parts[] = $hours . 'h';
        if ($minutes > 0 || empty($parts)) $parts[] = $minutes . 'm';
    }

    $newExpiresText = implode(' ', $parts);

    echo json_encode([
        'success' => true,
        'new_expires' => $newExpires,
        'new_expires_text' => $newExpiresText
    ]);
    exit;
}

// Handle text set (POST) - sets exact expiration time
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_text'])) {
    header('Content-Type: application/json');

    $token = $_POST['set_text'];
    $duration = $_POST['duration'] ?? '1d';

    $metadata = loadMetadata($metadataFile);

    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Text not found']);
        exit;
    }

    switch ($duration) {
        case '1h':
            $newExpires = time() + 3600;
            break;
        case '1d':
            $newExpires = time() + (24 * 3600);
            break;
        default:
            $newExpires = time() + (24 * 3600);
    }

    $metadata[$token]['expires'] = $newExpires;
    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_set_expiry', "Set text expiry: $token to $duration");

    // Format new expiration for display
    $expiresIn = $newExpires - time();
    $parts = [];
    $h = floor($expiresIn / 3600);
    $m = floor(($expiresIn % 3600) / 60);
    if ($h > 0) $parts[] = $h . 'h';
    if ($m > 0 || empty($parts)) $parts[] = $m . 'm';
    $newExpiresText = implode(' ', $parts);

    echo json_encode([
        'success' => true,
        'new_expires' => $newExpires,
        'new_expires_text' => $newExpiresText
    ]);
    exit;
}

// Helper functions
function generateToken($length = 6) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $token = '';
    for ($i = 0; $i < $length; $i++) {
        $token .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $token;
}

function loadMetadata($file) {
    if (!file_exists($file)) {
        return [];
    }
    $content = file_get_contents($file);
    return json_decode($content, true) ?? [];
}

function saveMetadata($file, $data) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

function cleanupExpiredTexts($textsDir, $metadataFile) {
    $metadata = loadMetadata($metadataFile);
    $now = time();
    $changed = false;

    foreach ($metadata as $token => $info) {
        if ($info['expires'] < $now) {
            // Delete file
            $filePath = $textsDir . '.' . $token . '.html';
            if (file_exists($filePath)) {
                unlink($filePath);
            }

            // Remove from metadata
            unset($metadata[$token]);
            $changed = true;
        }
    }

    if ($changed) {
        saveMetadata($metadataFile, $metadata);
    }
}

// If accessed directly, show error
http_response_code(404);
echo 'Not found';
