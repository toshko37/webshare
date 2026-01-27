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

// Validate API key and get user
$user = validateApiKey($apiKey);
if (!$user) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Invalid API key']);
    exit;
}

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

// Get optional folder parameter
$folder = isset($_POST['folder']) ? $_POST['folder'] : null;
if ($folder) {
    $folder = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $folder);
    $folder = preg_replace('/\.\./', '', $folder);
    $folder = trim($folder, '/');
}

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

// Handle duplicate filenames
$finalName = $originalName;
$targetPath = $uploadDir . $finalName;
$counter = 1;
$pathInfo = pathinfo($originalName);
$baseName = $pathInfo['filename'];
$extension = isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';

while (file_exists($targetPath)) {
    $finalName = $baseName . '_' . $counter . $extension;
    $targetPath = $uploadDir . $finalName;
    $counter++;
}

// Move uploaded file
if (move_uploaded_file($file['tmp_name'], $targetPath)) {
    // Record metadata
    $metaKey = $folder ? ($folder . '/' . $finalName) : ($user . '/' . $finalName);
    recordFileUpload($finalName, $user, $folder ?: $user);

    // Audit log
    $folderDisplay = $folder ? " to folder: $folder" : '';
    writeAuditLog('api_upload', "API upload by $user: $finalName$folderDisplay", $user);

    echo json_encode([
        'success' => true,
        'filename' => $finalName,
        'originalName' => $originalName,
        'renamed' => ($finalName !== $originalName),
        'size' => filesize($targetPath),
        'user' => $user,
        'folder' => $folder ?: $user
    ]);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Failed to save file']);
}
