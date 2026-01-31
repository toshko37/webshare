<?php
/**
 * WebShare Update Executor
 * Downloads and installs updates from GitHub releases
 */

session_start();
header('Content-Type: application/json');

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

// Get download URL from request
$input = json_decode(file_get_contents('php://input'), true);
$downloadUrl = $input['download_url'] ?? null;

if (!$downloadUrl) {
    // Try to get from version check
    $versionFile = __DIR__ . '/.version-check.json';
    if (file_exists($versionFile)) {
        $versionData = json_decode(file_get_contents($versionFile), true);
        $downloadUrl = $versionData['download_url'] ?? null;
    }
}

if (!$downloadUrl) {
    echo json_encode(['success' => false, 'error' => 'No download URL provided']);
    exit;
}

// Validate URL is from GitHub
if (!preg_match('#^https://github\.com/toshko37/webshare/#', $downloadUrl) &&
    !preg_match('#^https://api\.github\.com/repos/toshko37/webshare/#', $downloadUrl)) {
    echo json_encode(['success' => false, 'error' => 'Invalid download URL']);
    exit;
}

$installDir = __DIR__;
$tempDir = sys_get_temp_dir() . '/webshare-update-' . time();
$backupDir = __DIR__ . '/backups/pre-update-' . date('Y-m-d_H-i-s');

$result = [
    'success' => false,
    'message' => '',
    'backup_dir' => $backupDir,
    'steps' => []
];

try {
    // Step 1: Create temp directory
    $result['steps'][] = 'Creating temp directory...';
    if (!mkdir($tempDir, 0755, true)) {
        throw new Exception('Failed to create temp directory');
    }

    // Step 2: Download release
    $result['steps'][] = 'Downloading update...';
    $archivePath = $tempDir . '/webshare.tar.gz';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $downloadUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_HTTPHEADER => [
            'User-Agent: WebShare-Updater'
        ]
    ]);
    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$content) {
        throw new Exception("Failed to download update (HTTP {$httpCode})");
    }
    file_put_contents($archivePath, $content);
    $result['steps'][] = 'Download complete (' . round(strlen($content) / 1024) . ' KB)';

    // Step 3: Create backup
    $result['steps'][] = 'Creating backup...';
    if (!mkdir($backupDir, 0755, true)) {
        throw new Exception('Failed to create backup directory');
    }

    // Backup PHP files and config (not user data)
    $filesToBackup = glob($installDir . '/*.php');
    $filesToBackup = array_merge($filesToBackup, glob($installDir . '/.htaccess'));
    $filesToBackup = array_merge($filesToBackup, glob($installDir . '/.user.ini'));

    foreach ($filesToBackup as $file) {
        if (is_file($file)) {
            copy($file, $backupDir . '/' . basename($file));
        }
    }
    $result['steps'][] = 'Backup created';

    // Step 4: Extract archive
    $result['steps'][] = 'Extracting files...';
    $extractDir = $tempDir . '/extracted';
    mkdir($extractDir, 0755, true);

    // Extract tar.gz
    $phar = new PharData($archivePath);
    $phar->extractTo($extractDir);

    // Find the extracted directory (GitHub adds prefix)
    $dirs = glob($extractDir . '/*', GLOB_ONLYDIR);
    $sourceDir = $dirs[0] ?? $extractDir;

    $result['steps'][] = 'Extraction complete';

    // Step 5: Copy new files
    $result['steps'][] = 'Installing update...';

    // Files to update (not user data or config)
    $updatePatterns = ['*.php', '*.ico', '*.svg', '*.png', '.htaccess', '.user.ini', 'setup.sh', 'update.sh', 'install-local.sh', 'version.json'];
    $updatedFiles = 0;

    foreach ($updatePatterns as $pattern) {
        $files = glob($sourceDir . '/' . $pattern);
        foreach ($files as $file) {
            if (is_file($file)) {
                $dest = $installDir . '/' . basename($file);
                copy($file, $dest);
                $updatedFiles++;
            }
        }
    }

    // Update assets directory
    if (is_dir($sourceDir . '/assets')) {
        $assetFiles = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($sourceDir . '/assets', RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($assetFiles as $file) {
            if ($file->isFile()) {
                $relativePath = str_replace($sourceDir . '/', '', $file->getPathname());
                $destPath = $installDir . '/' . $relativePath;
                $destDir = dirname($destPath);
                if (!is_dir($destDir)) {
                    mkdir($destDir, 0755, true);
                }
                copy($file->getPathname(), $destPath);
                $updatedFiles++;
            }
        }
    }

    $result['steps'][] = "Updated {$updatedFiles} files";

    // Step 6: Set permissions
    $result['steps'][] = 'Setting permissions...';

    // Make scripts executable
    foreach (['setup.sh', 'update.sh', 'install-local.sh'] as $script) {
        if (file_exists($installDir . '/' . $script)) {
            chmod($installDir . '/' . $script, 0755);
        }
    }

    // Set www-data ownership
    if (function_exists('posix_getpwnam')) {
        $wwwData = posix_getpwnam('www-data');
        if ($wwwData) {
            foreach (glob($installDir . '/*.php') as $file) {
                chown($file, 'www-data');
                chgrp($file, 'www-data');
            }
        }
    }

    $result['steps'][] = 'Permissions set';

    // Step 7: Cleanup
    $result['steps'][] = 'Cleaning up...';

    // Remove temp directory
    $deleteDir = function($dir) use (&$deleteDir) {
        if (is_dir($dir)) {
            $files = array_diff(scandir($dir), ['.', '..']);
            foreach ($files as $file) {
                $path = $dir . '/' . $file;
                is_dir($path) ? $deleteDir($path) : unlink($path);
            }
            rmdir($dir);
        }
    };
    $deleteDir($tempDir);

    // Clear version cache to force re-check
    @unlink($installDir . '/.version-check.json');

    $result['steps'][] = 'Cleanup complete';

    $result['success'] = true;
    $result['message'] = 'Update installed successfully! Refreshing...';

} catch (Exception $e) {
    $result['success'] = false;
    $result['error'] = $e->getMessage();
    $result['steps'][] = 'Error: ' . $e->getMessage();

    // Cleanup on error
    if (isset($tempDir) && is_dir($tempDir)) {
        @exec("rm -rf " . escapeshellarg($tempDir));
    }
}

// Log the update attempt
require_once __DIR__ . '/audit-log.php';
$auditLogger = new AuditLogger();
$auditLogger->log(
    $result['success'] ? 'update_success' : 'update_failed',
    $_SERVER['PHP_AUTH_USER'] ?? 'unknown',
    [
        'message' => $result['message'] ?? $result['error'] ?? 'Unknown',
        'steps' => count($result['steps'])
    ]
);

echo json_encode($result, JSON_PRETTY_PRINT);
