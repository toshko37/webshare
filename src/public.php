<?php
// Public File Sharing
// ===================
// This script allows downloading files via public share links (no authentication required)

// Include required files
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/encryption.php';
require_once __DIR__ . '/folder-management.php';
require_once __DIR__ . '/error-page.php';
require_once __DIR__ . '/auth-guard.php';
require_once __DIR__ . '/json-store.php';

$tokensFile = __DIR__ . '/.tokens.json';
$filesDir = __DIR__ . '/files/';

// Get token from URL
$token = $_GET['t'] ?? '';

if (empty($token)) {
    wsErrorPage(400, 'Невалиден линк', 'Линкът е непълен. Провери дали си го копирал целия.');
}

// Load tokens
function loadTokens($tokensFile) {
    return ws_json_read($tokensFile);   // I4: shared lock
}

$tokens = loadTokens($tokensFile);

// Validate token
if (!isset($tokens[$token])) {
    wsErrorPage(404, 'Линкът не е намерен', 'Споделянето е премахнато или линкът е сгрешен. Поискай нов линк от човека, който ти го е пратил.');
}

$fileData = $tokens[$token];

// I7: links with an expiry stop working after it
if (!empty($fileData['expires']) && $fileData['expires'] < time()) {
    wsErrorPage(410, 'Линкът е изтекъл', 'Срокът на този линк изтече на ' . date('d.m.Y H:i', $fileData['expires']) . '. Поискай нов линк от човека, който ти го е пратил.');
}
$filename = basename($fileData['filename']);

// Build file path - handle folder paths from tokens
if (isset($fileData['folder']) && !empty($fileData['folder'])) {
    // Secure folder path sanitization
    $folder = secureFolderPath($fileData['folder']);
    $filePath = $filesDir . $folder . '/' . $filename;
} else {
    $filePath = $filesDir . $filename;
}

// Security check: ensure file exists and is within the files directory
if (!file_exists($filePath) || !is_file($filePath)) {
    wsErrorPage(404, 'Файлът липсва', 'Файлът е изтрит или преместен. Поискай нов линк.');
}

// Security check: prevent directory traversal
$realPath = realpath($filePath);
$realDir = realpath($filesDir);
if (strpos($realPath, $realDir) !== 0) {
    wsErrorPage(403, 'Достъпът е отказан', 'Този линк не дава достъп до файла.');
}

// Check if file is encrypted
$isEncrypted = isEncryptedFile($filename);

// F7: messenger preview bots get a card, not the file (nothing is downloaded or logged)
require_once __DIR__ . '/link-preview.php';
if (lp_is_preview_bot() && $_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!lp_enabled()) {
        lp_bot_page('WebShare', 'Споделен файл');
    }
    $shown = $isEncrypted ? getOriginalFilename($filename) : $filename;
    lp_bot_page('📄 ' . $shown, ($isEncrypted ? 'Криптиран файл · ' : 'Файл · ') . lp_size(filesize($filePath)) . ' · споделен чрез WebShare'
        . (!empty($fileData['expires']) ? ' · валиден до ' . date('d.m.Y', $fileData['expires']) : ''));
}

// Handle encrypted file download
if ($isEncrypted) {
    // Check if password was provided
    // Security: only accept password from POST (not GET - would appear in logs/history)
    $password = $_POST['decrypt_password'] ?? null;

    if (!$password) {
        // Show password form
        showPublicDecryptionForm($filename, $token);
        exit;
    }

    // U7: 10 wrong passwords per IP in 15 minutes
    $wait = ws_attempts_blocked('file-password', 10, 900);
    if ($wait > 0) {
        ws_log_auth_failure('file-password-locked');
        showPublicDecryptionForm($filename, $token, 'Too many wrong passwords. Try again in ' . ceil($wait / 60) . ' min.');
        exit;
    }

    // Decrypt and stream (I2). The password is checked by decryption itself (I3),
    // nothing is sent when it is wrong.
    $originalFilename = getOriginalFilename($filename);
    $result = decryptToBrowser($filePath, $password, $originalFilename);
    if (!$result['success']) {
        if (strpos($result['error'], 'wrong password') !== false) {
            ws_attempt_failed('file-password', 900);
            $result['error'] = 'Invalid password';
        }
        showPublicDecryptionForm($filename, $token, $result['error']);
        exit;
    }
    ws_attempt_clear('file-password');

    // Audit log - public decrypted download
    $fileSizeFormatted = formatFileSize($result['size']);
    writeAuditLog('public_download_decrypted', "File: $originalFilename ($fileSizeFormatted) via token: $token", 'anonymous');
    exit;
}

// Regular (non-encrypted) file download
$fileSize = filesize($filePath);
$mimeType = mime_content_type($filePath);

// Audit log - public download
$fileSizeFormatted = formatFileSize($fileSize);
writeAuditLog('public_download', "File: $filename ($fileSizeFormatted) via token: $token", 'anonymous');

// Set headers for download
header('Content-Type: ' . $mimeType);
header('Content-Length: ' . $fileSize);
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: 0');

// Output file
readfile($filePath);
exit;

/**
 * Format file size for display
 */
function formatFileSize($bytes) {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024, 2) . ' KB';
    if ($bytes < 1073741824) return round($bytes / 1048576, 2) . ' MB';
    return round($bytes / 1073741824, 2) . ' GB';
}

/**
 * Show decryption password form for public downloads
 */
function showPublicDecryptionForm($filename, $token, $error = null) {
    $originalName = getOriginalFilename($filename);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Decrypt File - WebShare</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link rel="apple-touch-icon" href="apple-touch-icon.png">
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        .lock-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 24px;
            color: #333;
            margin: 0 0 10px 0;
        }
        .filename {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            word-break: break-all;
        }
        .error {
            background: #fee2e2;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .info {
            margin-top: 20px;
            color: #666;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔒</div>
        <h1>Encrypted File</h1>
        <p class="filename"><?= htmlspecialchars($originalName) ?></p>

        <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <input type="hidden" name="decrypt_password" id="passwordField">
            <div class="form-group">
                <input type="password" id="passwordInput" placeholder="Enter decryption password" autofocus required>
            </div>
            <button type="submit" onclick="document.getElementById('passwordField').value = document.getElementById('passwordInput').value;">
                Decrypt & Download
            </button>
        </form>

        <p class="info">This file is encrypted. Enter the password provided by the sender.</p>
    </div>
</body>
</html>
    <?php
}
