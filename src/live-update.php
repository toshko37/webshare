<?php
/**
 * WebShare Live Update
 * Downloads and installs updates directly from webshare.techbg.net
 * Same source as the shell update script
 */

// Prevent any output before JSON
ob_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
set_time_limit(120); // Allow 2 minutes for update

// Clean any accidental output
ob_end_clean();

session_start();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

// CSRF validation for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrfToken)) {
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'CSRF validation failed']));
    }
}

// Global error handler to always return JSON
function jsonError($msg) {
    echo json_encode(['success' => false, 'error' => $msg, 'steps' => []]);
    exit;
}

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'PHP Error: ' . $error['message'], 'steps' => []]);
    }
});

// Check authentication
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Authentication required']);
    exit;
}

// Check if admin (only 'admin' user can update)
$currentUser = $_SERVER['PHP_AUTH_USER'];
if ($currentUser !== 'admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Admin access required']);
    exit;
}

// Load update config
$configFile = __DIR__ . '/.update-config.json';
$config = ['stable' => true]; // Default: use GitHub
if (file_exists($configFile)) {
    $configData = json_decode(file_get_contents($configFile), true);
    if (isset($configData['stable'])) {
        $config['stable'] = (bool)$configData['stable'];
    }
}

// Source URL based on config
if ($config['stable']) {
    // GitHub raw content
    $sourceUrl = 'https://raw.githubusercontent.com/toshko37/webshare/main/src';
} else {
    // Dev server
    $sourceUrl = 'https://webshare.techbg.net/src';
}

// Files to update (same list as update.sh)
$phpFiles = [
    'index.php',
    'upload.php',
    'public.php',
    'download.php',
    't.php',
    'text.php',
    'share.php',
    'folder-management.php',
    'encryption.php',
    'audit-log.php',
    'geo-check.php',
    'user-management.php',
    'html-sanitizer.php',
    'smtp-mailer.php',
    'send-mail.php',
    'web-download.php',
    'api-upload.php',
    'api-scripts.php',
    'check-version.php',
    'do-update.php',
    'live-update.php',
    'p.php',
    'u.php',
    'f.php',
    'get.php',
    'get-speedtest.php',
    'get-update.php',
    'get-update-script.php',
    'security-headers.php'
];

$otherFiles = [
    'favicon.ico',
    'favicon.svg',
    'apple-touch-icon.png',
    'CHANGELOG.md',
    'version.json'
];

$installDir = __DIR__;
$tempDir = sys_get_temp_dir() . '/webshare-live-update-' . getmypid();
$backupDir = $installDir . '/backups/pre-update-' . date('Y-m-d_H-i-s');

$result = [
    'success' => false,
    'message' => '',
    'steps' => [],
    'files_updated' => 0,
    'files_failed' => []
];

// Helper function to download a file
function downloadFile($url, $dest) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => ['User-Agent: WebShare-LiveUpdater']
    ]);
    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($httpCode === 200 && $content !== false && strlen($content) > 0) {
        file_put_contents($dest, $content);
        return true;
    }
    return false;
}

// Helper to recursively delete directory
function deleteDir($dir) {
    if (!is_dir($dir)) return;
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        is_dir($path) ? deleteDir($path) : unlink($path);
    }
    rmdir($dir);
}

try {
    // Step 1: Create temp directory
    $result['steps'][] = ['step' => 'Creating temp directory', 'status' => 'running'];
    if (!mkdir($tempDir, 0755, true)) {
        throw new Exception('Failed to create temp directory');
    }
    $result['steps'][count($result['steps'])-1]['status'] = 'done';

    // Step 2: Download all PHP files to temp
    $result['steps'][] = ['step' => 'Downloading PHP files', 'status' => 'running'];
    $downloadedFiles = [];

    foreach ($phpFiles as $file) {
        $url = "$sourceUrl/$file";
        $dest = "$tempDir/$file";

        if (downloadFile($url, $dest)) {
            $downloadedFiles[] = $file;
        } else {
            $result['files_failed'][] = $file;
        }
    }

    // Download other files
    foreach ($otherFiles as $file) {
        $url = "$sourceUrl/$file";
        $dest = "$tempDir/$file";
        downloadFile($url, $dest); // Optional files, don't fail if missing
    }

    // Download .htaccess (GitHub: .htaccess, Dev: htaccess.txt)
    $htaccessUrl = $config['stable'] ? "$sourceUrl/.htaccess" : "$sourceUrl/htaccess.txt";
    if (downloadFile($htaccessUrl, "$tempDir/.htaccess")) {
        // Update AuthUserFile path if using dev server version
        if (!$config['stable']) {
            $htaccessContent = file_get_contents("$tempDir/.htaccess");
            $installRoot = dirname($installDir); // Go up from src/ to root
            $htaccessContent = str_replace('__HTPASSWD_PATH__', "$installRoot/.htpasswd", $htaccessContent);
            file_put_contents("$tempDir/.htaccess", $htaccessContent);
        }
    }

    // Download .user.ini (GitHub: .user.ini, Dev: user.ini.txt)
    $userIniUrl = $config['stable'] ? "$sourceUrl/.user.ini" : "$sourceUrl/user.ini.txt";
    downloadFile($userIniUrl, "$tempDir/.user.ini");

    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['steps'][count($result['steps'])-1]['detail'] = count($downloadedFiles) . ' files downloaded';

    // Verify critical files were downloaded
    $criticalFiles = ['index.php', 'upload.php', 'folder-management.php'];
    foreach ($criticalFiles as $critical) {
        if (!file_exists("$tempDir/$critical") || filesize("$tempDir/$critical") < 1000) {
            throw new Exception("Critical file failed to download: $critical");
        }
    }

    // Step 3: Create backup
    $result['steps'][] = ['step' => 'Creating backup', 'status' => 'running'];
    if (!is_dir($installDir . '/backups')) {
        mkdir($installDir . '/backups', 0755, true);
    }
    if (!mkdir($backupDir, 0755, true)) {
        throw new Exception('Failed to create backup directory');
    }

    // Backup current PHP files
    foreach (glob($installDir . '/*.php') as $file) {
        copy($file, $backupDir . '/' . basename($file));
    }
    copy($installDir . '/.htaccess', $backupDir . '/.htaccess');

    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['backup_dir'] = $backupDir;

    // Step 4: Install new files
    $result['steps'][] = ['step' => 'Installing update', 'status' => 'running'];
    $installedCount = 0;

    // Copy all downloaded files
    foreach (glob("$tempDir/*") as $file) {
        if (is_file($file)) {
            $filename = basename($file);
            $dest = "$installDir/$filename";
            if (copy($file, $dest)) {
                $installedCount++;
            }
        }
    }

    // Copy .htaccess if exists
    if (file_exists("$tempDir/.htaccess")) {
        copy("$tempDir/.htaccess", "$installDir/.htaccess");
        $installedCount++;
    }

    $result['files_updated'] = $installedCount;
    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['steps'][count($result['steps'])-1]['detail'] = "$installedCount files installed";

    // Step 5: Set permissions
    $result['steps'][] = ['step' => 'Setting permissions', 'status' => 'running'];

    // Set ownership to www-data
    foreach (glob($installDir . '/*.php') as $file) {
        @chown($file, 'www-data');
        @chgrp($file, 'www-data');
        @chmod($file, 0644);
    }

    // Make scripts executable
    foreach (['setup.sh', 'update.sh', 'install-local.sh'] as $script) {
        if (file_exists("$installDir/$script")) {
            @chmod("$installDir/$script", 0755);
        }
    }

    $result['steps'][count($result['steps'])-1]['status'] = 'done';

    // Step 6: Cleanup
    $result['steps'][] = ['step' => 'Cleaning up', 'status' => 'running'];
    deleteDir($tempDir);

    // Clear version cache
    @unlink($installDir . '/.version-check.json');

    // Cleanup old backups (keep last 3)
    $backups = glob($installDir . '/backups/pre-update-*');
    usort($backups, function($a, $b) { return filemtime($b) - filemtime($a); });
    foreach (array_slice($backups, 3) as $oldBackup) {
        deleteDir($oldBackup);
    }

    $result['steps'][count($result['steps'])-1]['status'] = 'done';

    $result['success'] = true;
    $result['message'] = 'Update complete! Page will refresh...';

} catch (Exception $e) {
    $result['success'] = false;
    $result['error'] = $e->getMessage();

    // Mark current step as failed
    if (!empty($result['steps'])) {
        $result['steps'][count($result['steps'])-1]['status'] = 'failed';
    }

    // Cleanup temp directory on error
    if (is_dir($tempDir)) {
        deleteDir($tempDir);
    }
}

// Log the update attempt
require_once __DIR__ . '/audit-log.php';
writeAuditLog(
    $result['success'] ? 'live_update_success' : 'live_update_failed',
    $result['message'] ?? $result['error'] ?? 'Unknown'
);

echo json_encode($result, JSON_PRETTY_PRINT);
