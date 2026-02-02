<?php
/**
 * Web Download - Download files from URL
 * ======================================
 * Downloads files from external URLs directly to the server
 */

require_once __DIR__ . '/security-check.php';

// Error handling
set_error_handler(function($errno, $errstr) {
    echo json_encode(['success' => false, 'error' => 'PHP Error: ' . $errstr]);
    exit;
});

header('Content-Type: application/json');

require_once __DIR__ . '/user-management.php';
require_once __DIR__ . '/audit-log.php';

// Get current user and folder
$currentUser = getCurrentUser();
$currentFolder = $_POST['folder'] ?? $currentUser;

// Secure folder path sanitization
$currentFolder = secureFolderPath($currentFolder);

// Set upload directory
$uploadDir = __DIR__ . '/files/' . $currentFolder . '/';

// Ensure directory exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Get URL from request
$url = trim($_POST['url'] ?? '');

if (empty($url)) {
    echo json_encode(['success' => false, 'error' => 'URL is required']);
    exit;
}

// Validate URL format
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    echo json_encode(['success' => false, 'error' => 'Invalid URL format']);
    exit;
}

// Only allow http and https
$parsedUrl = parse_url($url);
if (!in_array($parsedUrl['scheme'] ?? '', ['http', 'https'])) {
    echo json_encode(['success' => false, 'error' => 'Only HTTP and HTTPS URLs are allowed']);
    exit;
}

// SSRF Protection - block internal IPs
$host = $parsedUrl['host'] ?? '';
if (empty($host)) {
    echo json_encode(['success' => false, 'error' => 'Invalid URL - no host']);
    exit;
}

// Resolve hostname to IP
$ip = gethostbyname($host);
if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
    echo json_encode(['success' => false, 'error' => 'Cannot resolve hostname']);
    exit;
}

// Block private/reserved IPs (SSRF protection)
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    echo json_encode(['success' => false, 'error' => 'Internal/private URLs are not allowed']);
    exit;
}

// Check action - info or download
$action = $_POST['action'] ?? 'download';

// Initialize cURL
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_TIMEOUT => 300,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_USERAGENT => 'WebShare/1.0',
    CURLOPT_SSL_VERIFYPEER => true,  // Verify SSL certificates
    CURLOPT_SSL_VERIFYHOST => 2,     // Verify hostname matches certificate
]);

if ($action === 'info') {
    // Just get file info (HEAD request)
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_HEADER, true);

    $response = curl_exec($ch);

    if ($response === false) {
        $error = curl_error($ch);
        curl_close($ch);
        echo json_encode(['success' => false, 'error' => 'Connection failed: ' . $error]);
        exit;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $fileSize = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);

    curl_close($ch);

    if ($httpCode !== 200) {
        echo json_encode(['success' => false, 'error' => "URL returned HTTP $httpCode"]);
        exit;
    }

    // Extract filename from Content-Disposition header first
    $filename = '';
    if (preg_match('/Content-Disposition:.*filename\*?=["\']?(?:UTF-8\'\')?([^"\'\r\n;]+)/i', $response, $matches)) {
        $filename = urldecode($matches[1]);
        $filename = trim($filename, '"\'');
    }

    // Fallback to URL path if no Content-Disposition
    if (empty($filename)) {
        $filename = basename(parse_url($finalUrl, PHP_URL_PATH));
    }

    // Clean filename
    if (empty($filename) || $filename === '/' || $filename === 'p' || $filename === 'download') {
        $filename = 'download_' . time();
    }

    // Remove query string from filename
    if (strpos($filename, '?') !== false) {
        $filename = substr($filename, 0, strpos($filename, '?'));
    }

    // Add extension based on content type if missing
    if (strpos($filename, '.') === false && $contentType) {
        $ext = getExtensionFromMime($contentType);
        if ($ext) {
            $filename .= '.' . $ext;
        }
    }

    // Check if file exists and suggest alternative
    $suggestedFilename = $filename;
    $fileExists = false;
    if (file_exists($uploadDir . $filename)) {
        $fileExists = true;
        $pathInfo = pathinfo($filename);
        $base = $pathInfo['filename'];
        $ext = isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';
        // Use unique ID to prevent race conditions
        $uniqueId = bin2hex(random_bytes(4));
        $suggestedFilename = $base . '_' . $uniqueId . $ext;
    }

    echo json_encode([
        'success' => true,
        'filename' => $filename,
        'suggestedFilename' => $suggestedFilename,
        'fileExists' => $fileExists,
        'size' => $fileSize > 0 ? $fileSize : null,
        'sizeFormatted' => $fileSize > 0 ? formatBytes($fileSize) : 'Unknown',
        'contentType' => $contentType
    ]);
    exit;
}

// Download the file
$maxFileSize = 10 * 1024 * 1024 * 1024; // 10GB
$overwrite = ($_POST['overwrite'] ?? '') === 'true';

// First check size with HEAD and get headers
curl_setopt($ch, CURLOPT_NOBODY, true);
curl_setopt($ch, CURLOPT_HEADER, true);
$headResponse = curl_exec($ch);

if ($headResponse === false) {
    $error = curl_error($ch);
    curl_close($ch);
    echo json_encode(['success' => false, 'error' => 'Connection failed: ' . $error]);
    exit;
}

$fileSize = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);

if ($httpCode !== 200) {
    curl_close($ch);
    echo json_encode(['success' => false, 'error' => "URL returned HTTP $httpCode"]);
    exit;
}

if ($fileSize > 0 && $fileSize > $maxFileSize) {
    curl_close($ch);
    echo json_encode(['success' => false, 'error' => 'File too large. Max size is ' . formatBytes($maxFileSize)]);
    exit;
}

// Get filename from POST or Content-Disposition header
$filename = $_POST['filename'] ?? '';
if (empty($filename) || $filename === 'p' || $filename === 'download') {
    // Try to extract from Content-Disposition header
    if (preg_match('/Content-Disposition:.*filename\*?=["\']?(?:UTF-8\'\')?([^"\'\r\n;]+)/i', $headResponse, $matches)) {
        $filename = urldecode($matches[1]);
        $filename = trim($filename, '"\'');
    }
}
if (empty($filename) || $filename === 'p' || $filename === 'download') {
    $filename = basename(parse_url($finalUrl, PHP_URL_PATH));
    if (empty($filename) || $filename === '/' || $filename === 'p' || $filename === 'download') {
        $filename = 'download_' . time();
    }
    // Remove query string
    if (strpos($filename, '?') !== false) {
        $filename = substr($filename, 0, strpos($filename, '?'));
    }
}

// Sanitize filename - allow UTF-8 letters and numbers
$filename = preg_replace('/[^\p{L}\p{N}._-]/u', '_', $filename);
$filename = preg_replace('/_+/', '_', $filename);
$filename = trim($filename, '_');

if (empty($filename)) {
    $filename = 'download_' . time();
}

// Add extension if missing
if (strpos($filename, '.') === false && $contentType) {
    $ext = getExtensionFromMime($contentType);
    if ($ext) {
        $filename .= '.' . $ext;
    }
}

// Check if file exists
$targetPath = $uploadDir . $filename;
$wasOverwritten = false;

if (file_exists($targetPath)) {
    if ($overwrite) {
        // User chose to overwrite
        unlink($targetPath);
        $wasOverwritten = true;
    } else {
        // Generate unique filename with unique ID to prevent race conditions
        $pathInfo = pathinfo($filename);
        $base = $pathInfo['filename'];
        $ext = isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';
        $uniqueId = bin2hex(random_bytes(4));
        $filename = $base . '_' . $uniqueId . $ext;
        $targetPath = $uploadDir . $filename;
    }
}

// Close HEAD handle and create new one for download
curl_close($ch);

// Download to temp file first
$tempFile = tempnam(sys_get_temp_dir(), 'webshare_');
$fp = fopen($tempFile, 'w');

if (!$fp) {
    echo json_encode(['success' => false, 'error' => 'Cannot create temp file']);
    exit;
}

// Create fresh cURL handle for download
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_FILE => $fp,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_TIMEOUT => 600,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_USERAGENT => 'WebShare/1.0',
    CURLOPT_SSL_VERIFYPEER => true,  // Verify SSL certificates
    CURLOPT_SSL_VERIFYHOST => 2,     // Verify hostname matches certificate
]);

$success = curl_exec($ch);
$error = curl_error($ch);
$downloadedSize = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);

fclose($fp);
curl_close($ch);

if (!$success || $downloadedSize == 0) {
    @unlink($tempFile);
    echo json_encode(['success' => false, 'error' => 'Download failed: ' . ($error ?: 'Empty file')]);
    exit;
}

// Move to target
if (!@rename($tempFile, $targetPath)) {
    // Try copy if rename fails (cross-device)
    if (!@copy($tempFile, $targetPath)) {
        @unlink($tempFile);
        echo json_encode(['success' => false, 'error' => 'Cannot save file to destination']);
        exit;
    }
    @unlink($tempFile);
}

// Set permissions
@chmod($targetPath, 0644);
@chown($targetPath, 'www-data');

// Record in metadata
recordFileUpload($filename, $currentUser, $currentFolder);

// Audit log
$action = $wasOverwritten ? 'web_download_overwrite' : 'web_download';
$details = "Downloaded from URL: $url -> $filename (" . formatBytes($downloadedSize) . ") in folder: $currentFolder";
if ($wasOverwritten) {
    $details .= " [overwritten]";
}
writeAuditLog($action, $details, $currentUser);

echo json_encode([
    'success' => true,
    'filename' => $filename,
    'size' => $downloadedSize,
    'sizeFormatted' => formatBytes($downloadedSize),
    'folder' => $currentFolder,
    'overwritten' => $wasOverwritten
]);

// Helper functions
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function getExtensionFromMime($mime) {
    $mime = strtolower(trim(explode(';', $mime)[0]));
    $map = [
        'text/html' => 'html',
        'text/plain' => 'txt',
        'text/css' => 'css',
        'text/javascript' => 'js',
        'application/javascript' => 'js',
        'application/json' => 'json',
        'application/xml' => 'xml',
        'application/pdf' => 'pdf',
        'application/zip' => 'zip',
        'application/gzip' => 'gz',
        'application/x-tar' => 'tar',
        'application/x-rar-compressed' => 'rar',
        'application/x-7z-compressed' => '7z',
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
        'image/svg+xml' => 'svg',
        'audio/mpeg' => 'mp3',
        'audio/wav' => 'wav',
        'audio/ogg' => 'ogg',
        'video/mp4' => 'mp4',
        'video/webm' => 'webm',
        'video/x-msvideo' => 'avi',
        'application/msword' => 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
    ];
    return $map[$mime] ?? null;
}
