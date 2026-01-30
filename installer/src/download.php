<?php
// Download file handler
// ====================

// Include required files
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/user-management.php';
require_once __DIR__ . '/encryption.php';

if (!isset($_GET['file'])) {
    die('No file specified');
}

$filename = basename($_GET['file']);
// Handle folder path with secure sanitization
$folder = isset($_GET['folder']) ? secureFolderPath($_GET['folder']) : null;
$subpath = isset($_GET['subpath']) ? $_GET['subpath'] : '';

// Get current user
$currentUser = getCurrentUser();

// Build file path
if ($folder) {
    // Use canAccessFolderPath for subfolders support
    if (!canAccessFolderPath($currentUser, $folder)) {
        http_response_code(403);
        die('Access denied to this folder');
    }

    // Build path - folder already contains full path like "admin/Soft"
    $filePath = FILES_BASE_DIR . $folder . '/' . $filename;
} else {
    // Legacy: try to find file in user's folder first, then _public
    if (file_exists(FILES_BASE_DIR . $currentUser . '/' . $filename)) {
        $filePath = FILES_BASE_DIR . $currentUser . '/' . $filename;
        $folder = $currentUser;
    } elseif (file_exists(FILES_BASE_DIR . '_public/' . $filename)) {
        $filePath = FILES_BASE_DIR . '_public/' . $filename;
        $folder = '_public';
    } else {
        // Fallback to old location (root of files/)
        $filePath = __DIR__ . '/files/' . $filename;
        $folder = null;
    }
}

// Security check: ensure file exists and is within the files directory
if (!file_exists($filePath) || !is_file($filePath)) {
    http_response_code(404);
    die('File not found');
}

// Security check: prevent directory traversal
$realPath = realpath($filePath);
$realDir = realpath(__DIR__ . '/files/');
if (strpos($realPath, $realDir) !== 0) {
    http_response_code(403);
    die('Access denied');
}

// Check if file is encrypted
$isEncrypted = isEncryptedFile($filename);

// Handle encrypted file download
if ($isEncrypted) {
    // Check if password was provided
    // Security: only accept password from POST (not GET - would appear in logs/history)
    $password = $_POST['decrypt_password'] ?? null;

    if (!$password) {
        // Show password form
        showDecryptionForm($filename, $folder, $subpath);
        exit;
    }

    // Verify password first
    if (!verifyEncryptionPassword($filename, $password)) {
        showDecryptionForm($filename, $folder, $subpath, 'Invalid password');
        exit;
    }

    // Decrypt the file
    $decryptResult = decryptFile($filePath, $password);

    if (!$decryptResult['success']) {
        showDecryptionForm($filename, $folder, $subpath, $decryptResult['error']);
        exit;
    }

    // Get original filename and data
    $originalFilename = $decryptResult['original_filename'];
    $decryptedData = $decryptResult['data'];
    $fileSize = strlen($decryptedData);

    // Try to determine mime type from original filename
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->buffer($decryptedData);
    if (!$mimeType) {
        $mimeType = 'application/octet-stream';
    }

    // Audit log - decrypted download
    $fileSizeFormatted = formatFileSize($fileSize);
    $folderDisplay = $folder ? ($folder === '_public' ? 'Public' : $folder) : 'legacy';
    writeAuditLog('download_decrypted', "File: $originalFilename ($fileSizeFormatted) from folder: $folderDisplay");

    // Send decrypted file
    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . $fileSize);
    header('Content-Disposition: attachment; filename="' . $originalFilename . '"');
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: 0');

    echo $decryptedData;
    exit;
}

// Regular (non-encrypted) file download
$fileSize = filesize($filePath);
$mimeType = mime_content_type($filePath);

// Audit log - authenticated download
$fileSizeFormatted = formatFileSize($fileSize);
$folderDisplay = $folder ? ($folder === '_public' ? 'Public' : $folder) : 'legacy';
writeAuditLog('download', "File: $filename ($fileSizeFormatted) from folder: $folderDisplay");

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
 * Show decryption password form
 */
function showDecryptionForm($filename, $folder, $subpath, $error = null) {
    $originalName = getOriginalFilename($filename);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Decrypt File - WebShare</title>
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
        .back-link {
            margin-top: 20px;
            display: block;
            color: #666;
            text-decoration: none;
            font-size: 14px;
        }
        .back-link:hover {
            color: #333;
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

        <a href="/" class="back-link">← Back to Dashboard</a>
    </div>
</body>
</html>
    <?php
}
