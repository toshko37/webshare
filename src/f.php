<?php
/**
 * Folder Sharing Handler
 * Allows sharing folders with optional password protection and upload capability
 */

session_start();

// Configuration
define('UPLOADS_DIR', __DIR__ . '/files/');
define('FOLDER_SHARES_FILE', __DIR__ . '/.folder-shares.json');
define('SITE_CONFIG_FILE', __DIR__ . '/.config.json');

// Include audit log system
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/error-page.php';
require_once __DIR__ . '/auth-guard.php';

// Load site config
function loadSiteConfig() {
    if (file_exists(SITE_CONFIG_FILE)) {
        return json_decode(file_get_contents(SITE_CONFIG_FILE), true) ?: [];
    }
    return [];
}

// Load folder shares
function loadFolderShares() {
    if (file_exists(FOLDER_SHARES_FILE)) {
        return json_decode(file_get_contents(FOLDER_SHARES_FILE), true) ?: [];
    }
    return [];
}

// Save folder shares
function saveFolderShares($shares) {
    file_put_contents(FOLDER_SHARES_FILE, json_encode($shares, JSON_PRETTY_PRINT));
}

// Send email notification
function sendUploadNotification($folderName, $fileName, $shareToken) {
    $siteConfig = loadSiteConfig();
    $mailConfig = $siteConfig['mail'] ?? [];

    if (empty($mailConfig['enabled']) || empty($mailConfig['smtp_host'])) {
        return false;
    }

    $to = $mailConfig['notify_email'] ?? $mailConfig['smtp_user'] ?? '';
    if (empty($to)) return false;

    $subject = "New file uploaded to shared folder: $folderName";
    $body = "A new file has been uploaded to a shared folder.\n\n";
    $body .= "Folder: $folderName\n";
    $body .= "File: $fileName\n";
    $body .= "Time: " . date('Y-m-d H:i:s') . "\n";
    $body .= "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";

    // Use PHPMailer if available, otherwise use mail()
    $headers = "From: " . ($mailConfig['smtp_user'] ?? 'noreply@' . $_SERVER['HTTP_HOST']) . "\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($to, $subject, $body, $headers);
}

// Get human readable file size
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}

// Get file icon
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'pdf' => '📄', 'doc' => '📝', 'docx' => '📝', 'txt' => '📝',
        'xls' => '📊', 'xlsx' => '📊', 'csv' => '📊',
        'ppt' => '📽️', 'pptx' => '📽️',
        'jpg' => '🖼️', 'jpeg' => '🖼️', 'png' => '🖼️', 'gif' => '🖼️', 'webp' => '🖼️', 'svg' => '🖼️',
        'mp4' => '🎬', 'avi' => '🎬', 'mkv' => '🎬', 'mov' => '🎬', 'webm' => '🎬',
        'mp3' => '🎵', 'wav' => '🎵', 'flac' => '🎵', 'ogg' => '🎵',
        'zip' => '📦', 'rar' => '📦', '7z' => '📦', 'tar' => '📦', 'gz' => '📦',
        'exe' => '⚙️', 'msi' => '⚙️', 'dmg' => '⚙️', 'deb' => '⚙️', 'rpm' => '⚙️',
        'html' => '🌐', 'css' => '🎨', 'js' => '📜', 'php' => '🐘', 'py' => '🐍',
        'json' => '📋', 'xml' => '📋', 'yaml' => '📋', 'yml' => '📋',
    ];
    return $icons[$ext] ?? '📄';
}

// Scan folder recursively
function scanFolderRecursive($path, $basePath = '', $depth = 0) {
    $items = [];
    if (!is_dir($path)) return $items;

    $entries = scandir($path);
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;

        $fullPath = $path . '/' . $entry;
        $relativePath = $basePath ? $basePath . '/' . $entry : $entry;

        if (is_dir($fullPath)) {
            $items[] = [
                'name' => $entry,
                'path' => $relativePath,
                'type' => 'folder',
                'depth' => $depth,
                'children' => scanFolderRecursive($fullPath, $relativePath, $depth + 1)
            ];
        } else {
            $items[] = [
                'name' => $entry,
                'path' => $relativePath,
                'type' => 'file',
                'size' => filesize($fullPath),
                'modified' => filemtime($fullPath),
                'depth' => $depth
            ];
        }
    }

    // Sort: folders first, then files alphabetically
    usort($items, function($a, $b) {
        if ($a['type'] !== $b['type']) {
            return $a['type'] === 'folder' ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });

    return $items;
}

// Flatten folder structure for display
function flattenItems($items, &$result = []) {
    foreach ($items as $item) {
        if ($item['type'] === 'folder') {
            $result[] = $item;
            if (!empty($item['children'])) {
                flattenItems($item['children'], $result);
            }
        } else {
            $result[] = $item;
        }
    }
    return $result;
}

// Create ZIP of folder
function createFolderZip($folderPath, $folderName) {
    $zipName = sys_get_temp_dir() . '/' . $folderName . '_' . time() . '.zip';
    $zip = new ZipArchive();

    if ($zip->open($zipName, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        return false;
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($folderPath, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $file) {
        if (!$file->isDir()) {
            $filePath = $file->getRealPath();
            $relativePath = substr($filePath, strlen($folderPath) + 1);
            $zip->addFile($filePath, $relativePath);
        }
    }

    $zip->close();
    return $zipName;
}

// Get token from request
$token = $_GET['token'] ?? '';
$action = $_GET['action'] ?? '';

// Validate token
if (empty($token) || !preg_match('/^[a-zA-Z0-9]{6,64}$/', $token)) {
    wsErrorPage(404, 'Невалиден линк', 'Линкът към папката е непълен или сгрешен.');
}

// Load share data
$shares = loadFolderShares();
if (!isset($shares[$token])) {
    wsErrorPage(404, 'Папката не е намерена', 'Споделянето е премахнато или линкът е сгрешен. Поискай нов линк.');
}

$share = $shares[$token];

// Check expiration
if (!empty($share['expires']) && $share['expires'] < time()) {
    wsErrorPage(410, 'Линкът е изтекъл', 'Срокът на споделянето е изтекъл. Поискай нов линк.');
}

// Get folder path
$folderPath = UPLOADS_DIR . $share['folder'];
if (!is_dir($folderPath)) {
    wsErrorPage(404, 'Папката липсва', 'Папката е изтрита или преместена.');
}

$folderName = basename($share['folder']);

// Password protection check
$needsPassword = !empty($share['password']);
$isAuthenticated = false;

if ($needsPassword) {
    $sessionKey = 'folder_auth_' . $token;
    if (isset($_SESSION[$sessionKey]) && $_SESSION[$sessionKey] === true) {
        $isAuthenticated = true;
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        // U7: 10 wrong passwords per IP in 15 minutes, across all folder shares
        $wait = ws_attempts_blocked('share-password', 10, 900);
        if ($wait > 0) {
            ws_log_auth_failure('share-password-locked');
            $passwordError = 'Твърде много грешни опити. Опитай пак след ' . ceil($wait / 60) . ' мин.';
        } elseif (password_verify($_POST['password'], $share['password'])) {
            ws_attempt_clear('share-password');
            $_SESSION[$sessionKey] = true;
            $isAuthenticated = true;
        } else {
            ws_attempt_failed('share-password', 900);
            $passwordError = 'Грешна парола';
        }
    }
} else {
    $isAuthenticated = true;
}

// Handle file download
if ($action === 'file' && $isAuthenticated && isset($_GET['path'])) {
    $filePath = $_GET['path'];
    // Sanitize path - prevent directory traversal
    $filePath = str_replace(['..', "\0"], '', $filePath);
    $fullPath = $folderPath . '/' . $filePath;

    if (file_exists($fullPath) && is_file($fullPath) && strpos(realpath($fullPath), realpath($folderPath)) === 0) {
        // Increment view count
        $shares[$token]['views'] = ($shares[$token]['views'] ?? 0) + 1;
        saveFolderShares($shares);

        writeAuditLog('folder_download', "Downloaded: {$share['folder']}/$filePath");

        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . filesize($fullPath));
        readfile($fullPath);
        exit;
    }
    wsErrorPage(404, 'Файлът липсва', 'Файлът е изтрит или преместен.');
}

// Handle ZIP download
if ($action === 'download' && $isAuthenticated) {
    $zipFile = createFolderZip($folderPath, $folderName);
    if ($zipFile && file_exists($zipFile)) {
        writeAuditLog('folder_zip_download', "Downloaded ZIP: {$share['folder']}");

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $folderName . '.zip"');
        header('Content-Length: ' . filesize($zipFile));
        readfile($zipFile);
        unlink($zipFile);
        exit;
    }
    wsErrorPage(500, 'Архивът не можа да се създаде', 'Опитай отново или изтегли файловете един по един.');
}

// Handle file upload
if ($action === 'upload' && $isAuthenticated && !empty($share['allow_upload'])) {
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'error' => 'POST required']);
        exit;
    }

    if (empty($_FILES['file'])) {
        echo json_encode(['success' => false, 'error' => 'No file uploaded']);
        exit;
    }

    $file = $_FILES['file'];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'error' => 'Upload error: ' . $file['error']]);
        exit;
    }

    // Sanitize filename
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file['name']));
    $targetPath = $folderPath . '/' . $filename;

    // Handle duplicate names
    $counter = 1;
    $baseName = pathinfo($filename, PATHINFO_FILENAME);
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    while (file_exists($targetPath)) {
        $filename = $baseName . '_' . $counter . ($ext ? '.' . $ext : '');
        $targetPath = $folderPath . '/' . $filename;
        $counter++;
    }

    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        writeAuditLog('folder_upload', "Uploaded to {$share['folder']}: $filename (" . formatFileSize($file['size']) . ")");

        // Send email notification
        sendUploadNotification($folderName, $filename, $token);

        echo json_encode([
            'success' => true,
            'filename' => $filename,
            'size' => formatFileSize($file['size'])
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to save file']);
    }
    exit;
}

// Handle file delete
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_file']) && $isAuthenticated && !empty($share['allow_delete'])) {
    header('Content-Type: application/json');

    $filePath = $_POST['delete_file'];
    $filePath = str_replace(['..', "\0"], '', $filePath);
    $fullPath = $folderPath . '/' . $filePath;

    if (file_exists($fullPath) && is_file($fullPath) && strpos(realpath($fullPath), realpath($folderPath)) === 0) {
        if (unlink($fullPath)) {
            writeAuditLog('folder_delete', "Deleted from {$share['folder']}: $filePath");
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to delete']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'File not found']);
    }
    exit;
}

// Increment view count for page views
if ($isAuthenticated && $action === '') {
    $shares[$token]['views'] = ($shares[$token]['views'] ?? 0) + 1;
    saveFolderShares($shares);
}

// Get folder contents
$items = [];
if ($isAuthenticated) {
    $items = scanFolderRecursive($folderPath);
    $flatItems = [];
    flattenItems($items, $flatItems);
}

$siteConfig = loadSiteConfig();
$siteName = $siteConfig['site_name'] ?? 'WebShare';
?>
<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($folderName) ?> - <?= htmlspecialchars($siteName) ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 28px;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .header p {
            opacity: 0.9;
            font-size: 14px;
        }

        .content {
            padding: 30px;
        }

        /* Password form */
        .password-form {
            max-width: 400px;
            margin: 50px auto;
            text-align: center;
        }

        .password-form h2 {
            margin-bottom: 20px;
            color: #333;
        }

        .password-form input[type="password"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 15px;
        }

        .password-form input[type="password"]:focus {
            outline: none;
            border-color: #4C51BF;
        }

        .password-form button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
        }

        .password-form button:hover {
            transform: translateY(-2px);
        }

        .error-msg {
            color: #C62828;
            margin-bottom: 15px;
        }

        /* Upload zone */
        .upload-zone {
            border: 3px dashed #ddd;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            transition: all 0.3s;
            cursor: pointer;
        }

        .upload-zone:hover, .upload-zone.dragover {
            border-color: #4C51BF;
            background: rgba(102, 126, 234, 0.05);
        }

        .upload-zone.dragover {
            transform: scale(1.02);
        }

        .upload-zone-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }

        .upload-zone p {
            color: #666;
            margin-bottom: 15px;
        }

        .upload-zone input[type="file"] {
            display: none;
        }

        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: #f0f0f0;
            color: #333;
        }

        .btn-secondary:hover {
            background: #e0e0e0;
            box-shadow: none;
        }

        .btn-danger {
            background: #C62828;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }

        /* File list */
        .file-list {
            border: 1px solid #eee;
            border-radius: 12px;
            overflow: hidden;
        }

        .file-item {
            display: flex;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }

        .file-item:last-child {
            border-bottom: none;
        }

        .file-item:hover {
            background: #f8f9fa;
        }

        .file-item.folder {
            background: #f8f9fa;
        }

        .file-icon {
            font-size: 24px;
            margin-right: 15px;
            width: 30px;
            text-align: center;
        }

        .file-info {
            flex: 1;
            min-width: 0;
        }

        .file-name {
            font-weight: 500;
            color: #333;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .file-meta {
            font-size: 12px;
            color: #6B6B6B;
            margin-top: 3px;
        }

        .file-actions {
            display: flex;
            gap: 8px;
        }

        .indent-1 { padding-left: 40px; }
        .indent-2 { padding-left: 60px; }
        .indent-3 { padding-left: 80px; }
        .indent-4 { padding-left: 100px; }

        /* Actions bar */
        .actions-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .stats {
            color: #666;
            font-size: 14px;
        }

        /* Upload progress */
        .upload-progress {
            display: none;
            margin-top: 20px;
        }

        .upload-progress.show {
            display: block;
        }

        .progress-bar {
            height: 8px;
            background: #eee;
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s;
        }

        .progress-text {
            text-align: center;
            margin-top: 10px;
            color: #666;
            font-size: 14px;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6B6B6B;
        }

        .empty-state-icon {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        /* Toast notifications */
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 15px 25px;
            background: #333;
            color: white;
            border-radius: 8px;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s;
            z-index: 1000;
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        .toast.success {
            background: #27ae60;
        }

        .toast.error {
            background: #C62828;
        }

        @media (max-width: 600px) {
            .container {
                margin: 10px;
                border-radius: 12px;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 22px;
            }

            .content {
                padding: 15px;
            }

            .file-item {
                padding: 12px 15px;
            }

            .file-actions {
                flex-direction: column;
            }

            .actions-bar {
                flex-direction: column;
                align-items: stretch;
            }
        }
        @media (max-width: 600px) {
            .file-name { white-space: normal; overflow-wrap: anywhere; }
        }
    </style>
    <link rel="stylesheet" href="/ui-kit.css?v=<?= (int)@filemtime(__DIR__ . '/ui-kit.css') ?>">
    <script src="/ui-kit.js?v=<?= (int)@filemtime(__DIR__ . '/ui-kit.js') ?>" defer></script>
</head>
<body>
    <div class="container" role="main">
        <div class="header">
            <h1>📁 <?= htmlspecialchars($folderName) ?></h1>
            <p>Споделена папка</p>
        </div>

        <div class="content">
            <?php if (!$isAuthenticated): ?>
                <!-- Password form -->
                <div class="password-form">
                    <h2>🔒 Тази папка е защитена</h2>
                    <?php if (isset($passwordError)): ?>
                        <p class="error-msg"><?= htmlspecialchars($passwordError) ?></p>
                    <?php endif; ?>
                    <form method="POST">
                        <input type="password" name="password" placeholder="Въведи парола" autofocus required>
                        <button type="submit">Отключи</button>
                    </form>
                </div>
            <?php else: ?>
                <!-- Upload zone (if allowed) -->
                <?php if (!empty($share['allow_upload'])): ?>
                <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
                    <div class="upload-zone-icon">📤</div>
                    <p>Пусни файлове тук или кликни за да избереш</p>
                    <input type="file" id="file-input" multiple onchange="handleFiles(this.files)">
                    <button class="btn" type="button" onclick="event.stopPropagation(); document.getElementById('file-input').click()">
                        Избери файлове
                    </button>
                </div>
                <div class="upload-progress" id="upload-progress">
                    <div class="progress-bar">
                        <div class="progress-bar-fill" id="progress-fill"></div>
                    </div>
                    <p class="progress-text" id="progress-text">Качване...</p>
                </div>
                <?php endif; ?>

                <!-- Actions bar -->
                <div class="actions-bar">
                    <div class="stats">
                        <?php
                        $fileCount = 0;
                        $totalSize = 0;
                        foreach ($flatItems as $item) {
                            if ($item['type'] === 'file') {
                                $fileCount++;
                                $totalSize += $item['size'];
                            }
                        }
                        ?>
                        📊 <?= $fileCount ?> файла (<?= formatFileSize($totalSize) ?>)
                    </div>
                    <?php if ($fileCount > 0): ?>
                    <a href="/f/<?= $token ?>/download" class="btn btn-secondary">
                        📦 Изтегли всички (.zip)
                    </a>
                    <?php endif; ?>
                </div>

                <!-- File list -->
                <?php if (empty($flatItems)): ?>
                <div class="empty-state">
                    <div class="empty-state-icon">📂</div>
                    <p>Папката е празна</p>
                    <?php if (!empty($share['allow_upload'])): ?>
                    <p>Качи първия файл!</p>
                    <?php endif; ?>
                </div>
                <?php else: ?>
                <div class="file-list">
                    <?php foreach ($flatItems as $item): ?>
                    <div class="file-item <?= $item['type'] === 'folder' ? 'folder' : '' ?> <?= $item['depth'] > 0 ? 'indent-' . min($item['depth'], 4) : '' ?>">
                        <div class="file-icon">
                            <?= $item['type'] === 'folder' ? '📁' : getFileIcon($item['name']) ?>
                        </div>
                        <div class="file-info">
                            <div class="file-name" title="<?= htmlspecialchars($item['name']) ?>"><?= htmlspecialchars($item['name']) ?></div>
                            <?php if ($item['type'] === 'file'): ?>
                            <div class="file-meta">
                                <?= formatFileSize($item['size']) ?> · <?= date('d.m.Y H:i', $item['modified']) ?>
                            </div>
                            <?php endif; ?>
                        </div>
                        <?php if ($item['type'] === 'file'): ?>
                        <div class="file-actions">
                            <a href="/f/<?= $token ?>?action=file&path=<?= urlencode($item['path']) ?>" class="btn btn-sm">
                                Изтегли
                            </a>
                            <?php if (!empty($share['allow_delete'])): ?>
                            <button class="btn btn-sm btn-danger" onclick="deleteFile('<?= htmlspecialchars($item['path'], ENT_QUOTES) ?>')">
                                Изтрий
                            </button>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <?php if ($isAuthenticated): ?>
    <script>
        const token = '<?= $token ?>';

        // Toast notifications
        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // Drag and drop
        <?php if (!empty($share['allow_upload'])): ?>
        const uploadZone = document.getElementById('upload-zone');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => uploadZone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, () => uploadZone.classList.remove('dragover'), false);
        });

        uploadZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            handleFiles(files);
        }, false);

        // File upload
        async function handleFiles(files) {
            if (files.length === 0) return;

            const progress = document.getElementById('upload-progress');
            const progressFill = document.getElementById('progress-fill');
            const progressText = document.getElementById('progress-text');

            progress.classList.add('show');

            let uploaded = 0;
            const total = files.length;

            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                progressText.textContent = `Качване ${i + 1}/${total}: ${file.name}`;

                try {
                    const formData = new FormData();
                    formData.append('file', file);

                    const response = await fetch(`/f/${token}/upload`, {
                        method: 'POST',
                        body: formData
                    });

                    const data = await response.json();
                    if (data.success) {
                        uploaded++;
                    }
                } catch (error) {
                    console.error('Upload error:', error);
                }

                progressFill.style.width = ((i + 1) / total * 100) + '%';
            }

            progress.classList.remove('show');
            progressFill.style.width = '0%';

            if (uploaded === total) {
                showToast(`Качени ${uploaded} файла`, 'success');
            } else {
                showToast(`Качени ${uploaded}/${total} файла`, uploaded > 0 ? 'success' : 'error');
            }

            // Reload to show new files
            setTimeout(() => location.reload(), 1000);
        }
        <?php endif; ?>

        // Delete file
        <?php if (!empty($share['allow_delete'])): ?>
        async function deleteFile(path) {
            if (!confirm('Сигурен ли си, че искаш да изтриеш този файл?')) return;

            try {
                const formData = new FormData();
                formData.append('delete_file', path);

                const response = await fetch(location.href, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                if (data.success) {
                    showToast('Файлът е изтрит', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showToast(data.error || 'Грешка при изтриване', 'error');
                }
            } catch (error) {
                showToast('Грешка при изтриване', 'error');
            }
        }
        <?php endif; ?>
    </script>
    <?php endif; ?>
</body>
</html>
