<?php
/**
 * WebShare API Upload Endpoint
 * ============================
 * Allows external file uploads using API key authentication
 *
 * Usage:
 *   curl -X POST -H "X-API-Key: YOUR_KEY" -F "file=@document.pdf" https://webshare.example.com/api-upload.php
 */

header('Content-Type: application/json');

// Include required files
require_once __DIR__ . '/user-management.php';
require_once __DIR__ . '/audit-log.php';

// Get API key from header or query parameter
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['key'] ?? $_POST['key'] ?? null;

if (!$apiKey) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'API key required. Use X-API-Key header or key parameter.']);
    exit;
}

// Validate API key and get user (with key details for audit)
$keyInfo = validateApiKey($apiKey, null, true);
if (!$keyInfo) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Invalid API key or IP not allowed']);
    exit;
}
$user = $keyInfo['user'];
$apiKeyId = $keyInfo['key_id'];
$apiKeyName = $keyInfo['key_name'];

// Check if file was uploaded
if (!isset($_FILES['file']) || $_FILES['file']['error'] === UPLOAD_ERR_NO_FILE) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'No file uploaded. Use: -F "file=@filename"']);
    exit;
}

$file = $_FILES['file'];

// Check for upload errors
if ($file['error'] !== UPLOAD_ERR_OK) {
    $errorMessages = [
        UPLOAD_ERR_INI_SIZE => 'File exceeds server limit',
        UPLOAD_ERR_FORM_SIZE => 'File exceeds form limit',
        UPLOAD_ERR_PARTIAL => 'File partially uploaded',
        UPLOAD_ERR_NO_TMP_DIR => 'No temp directory',
        UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk',
        UPLOAD_ERR_EXTENSION => 'Upload blocked by extension',
    ];
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => $errorMessages[$file['error']] ?? 'Upload error']);
    exit;
}

// Sanitize filename
$originalName = basename($file['name']);
$originalName = preg_replace('/[^a-zA-Z0-9._\-\p{L}\p{N}]/u', '_', $originalName);
if (empty($originalName) || $originalName === '.' || $originalName === '..') {
    $originalName = 'uploaded_file_' . time();
}

// Security: Block dangerous file extensions
$dangerousExtensions = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'htaccess', 'htpasswd'];
$extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
if (in_array($extension, $dangerousExtensions)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => "File type not allowed: .$extension"]);
    exit;
}

// Security: Check for double extensions (e.g., file.php.jpg)
$nameParts = explode('.', $originalName);
if (count($nameParts) > 2) {
    foreach ($nameParts as $part) {
        if (in_array(strtolower($part), $dangerousExtensions)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => "File contains dangerous extension: $part"]);
            exit;
        }
    }
}

// Get optional folder parameter (secure sanitization)
$folder = isset($_POST['folder']) ? secureFolderPath($_POST['folder']) : null;

// Determine upload directory
$baseDir = __DIR__ . '/files/';
if ($folder) {
    // Validate folder access
    if (!canAccessFolderPath($user, $folder)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Access denied to folder']);
        exit;
    }
    $uploadDir = $baseDir . $folder . '/';
} else {
    $uploadDir = $baseDir . $user . '/';
}

// Create directory if needed
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Get options
$overwrite = ($_POST['overwrite'] ?? '0') === '1';
$encrypt = ($_POST['encrypt'] ?? '0') === '1';
$encryptPassword = $_POST['encrypt_password'] ?? '';

// Validate encryption options
if ($encrypt && strlen($encryptPassword) < 4) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Encryption password must be at least 4 characters']);
    exit;
}

// Handle filenames
$pathInfo = pathinfo($originalName);
$baseName = $pathInfo['filename'];
$extension = isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';

$finalName = $originalName;
$targetPath = $uploadDir . $finalName;
$wasOverwritten = false;

// Handle existing files
if (file_exists($targetPath)) {
    if ($overwrite) {
        // Delete existing file
        unlink($targetPath);
        $wasOverwritten = true;
    } else {
        // Add datetime suffix (more readable than random)
        $timestamp = date('Ymd_His');
        $finalName = $baseName . '_' . $timestamp . $extension;
        $targetPath = $uploadDir . $finalName;

        // In rare case of same-second upload, add milliseconds
        if (file_exists($targetPath)) {
            $finalName = $baseName . '_' . $timestamp . '_' . substr(microtime(), 2, 3) . $extension;
            $targetPath = $uploadDir . $finalName;
        }
    }
}

// Move uploaded file
if (move_uploaded_file($file['tmp_name'], $targetPath)) {
    $encrypted = false;

    // Encrypt if requested
    if ($encrypt) {
        require_once __DIR__ . '/encryption.php';
        $encryptResult = encryptFile($targetPath, $encryptPassword);
        if ($encryptResult['success']) {
            // Update filename to encrypted version
            $finalName = $encryptResult['filename'];
            $targetPath = $uploadDir . $finalName;
            $encrypted = true;

            // Store encryption key for later decryption
            storeEncryptionPassword($finalName, $encryptPassword, $user);
        } else {
            // Encryption failed, but file is uploaded
            writeAuditLog('api_upload_error', "Encryption failed for $finalName: " . ($encryptResult['error'] ?? 'unknown') . " [key: $apiKeyName ($apiKeyId)]", $user);
        }
    }

    // Record metadata
    recordFileUpload($finalName, $user, $folder ?: $user);

    // Audit log with API key info
    $folderDisplay = $folder ? " to folder: $folder" : '';
    $encryptDisplay = $encrypted ? ' (encrypted)' : '';
    $overwriteDisplay = $wasOverwritten ? ' (overwritten)' : '';
    $keyDisplay = " [key: $apiKeyName ($apiKeyId)]";
    writeAuditLog('api_upload', "API upload: $finalName$folderDisplay$encryptDisplay$overwriteDisplay$keyDisplay", $user);

    echo json_encode([
        'success' => true,
        'filename' => $finalName,
        'originalName' => $originalName,
        'renamed' => ($finalName !== $originalName && !$encrypted),
        'overwritten' => $wasOverwritten,
        'encrypted' => $encrypted,
        'size' => filesize($targetPath),
        'user' => $user,
        'folder' => $folder ?: $user
    ]);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Failed to save file']);
}
