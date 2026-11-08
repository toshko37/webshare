<?php
/**
 * WebShare Live Update
 * Downloads and installs the latest signed GitHub release (F5, docs/decisions.md D-026)
 */

require_once __DIR__ . '/security-check.php';
require_once __DIR__ . '/user-management.php';

// Prevent any output before JSON
ob_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
set_time_limit(120); // Allow 2 minutes for update

// Clean any accidental output
ob_end_clean();

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

// Check if admin (security-check.php already handles session auth)
if (!isAdmin(getCurrentUser())) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Admin access required']);
    exit;
}

// Updates come only from GitHub releases (D-023), and only signed ones (F5, D-026):
// files are taken from the release tag, the file list and SHA-256 hashes from
// src/release-manifest.json, which must carry a valid Ed25519 signature.
require_once __DIR__ . '/release-verify.php';
const WS_REPO = 'toshko37/webshare';

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

// Download a URL; returns the body or null
function fetchUrl($url, $timeout = 30) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => ['User-Agent: WebShare-LiveUpdater', 'Accept: application/vnd.github+json']
    ]);
    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($httpCode === 200 && is_string($content)) ? $content : null;
}

// Latest release version: GitHub API, fallback version.json on main
function latestReleaseVersion() {
    $api = fetchUrl('https://api.github.com/repos/' . WS_REPO . '/releases/latest', 15);
    $tag = $api ? (json_decode($api, true)['tag_name'] ?? '') : '';
    if (!preg_match('/^v?(\d+\.\d+\.\d+)$/', $tag, $m)) {
        $vj = fetchUrl('https://raw.githubusercontent.com/' . WS_REPO . '/main/src/version.json', 15);
        $v = $vj ? (json_decode($vj, true)['version'] ?? '') : '';
        if (!preg_match('/^(\d+\.\d+\.\d+)$/', $v, $m)) return null;
    }
    return $m[1];
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
    // Step 1: Find and verify the release
    $result['steps'][] = ['step' => 'Verifying release signature', 'status' => 'running'];
    $version = latestReleaseVersion();
    if (!$version) {
        throw new Exception('Could not determine the latest release from GitHub');
    }
    $sourceUrl = 'https://raw.githubusercontent.com/' . WS_REPO . '/v' . $version . '/src';
    $manifestJson = fetchUrl("$sourceUrl/release-manifest.json");
    $signature = fetchUrl("$sourceUrl/release-manifest.sig");
    if ($manifestJson === null || $signature === null) {
        throw new Exception("Release v$version is not signed (no release-manifest); nothing was changed");
    }
    $verified = ws_release_verify_manifest($manifestJson, $signature);
    if (!$verified['ok']) {
        throw new Exception("Release v$version rejected: " . $verified['error'] . '; nothing was changed');
    }
    $manifest = $verified['manifest'];
    if ($manifest['version'] !== $version) {
        throw new Exception("Release manifest is for v{$manifest['version']}, expected v$version; nothing was changed");
    }
    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['steps'][count($result['steps'])-1]['detail'] = "v$version, " . count($manifest['files']) . ' files, signature OK';
    $result['version'] = $version;

    // Step 2: Download every file and check its hash
    $result['steps'][] = ['step' => 'Downloading files', 'status' => 'running'];
    if (!mkdir($tempDir, 0700, true)) {
        throw new Exception('Failed to create temp directory');
    }
    foreach ($manifest['files'] as $path => $hash) {
        $content = fetchUrl("$sourceUrl/$path");
        if ($content === null) {
            throw new Exception("Download failed: $path; nothing was changed");
        }
        if (!hash_equals($hash, hash('sha256', $content))) {
            throw new Exception("Checksum mismatch: $path; nothing was changed");
        }
        // user.ini.txt is the git copy of .user.ini
        $target = $path === 'user.ini.txt' ? '.user.ini' : $path;
        @mkdir(dirname("$tempDir/$target"), 0700, true);
        file_put_contents("$tempDir/$target", $content);
    }
    file_put_contents("$tempDir/release-manifest.json", $manifestJson);
    file_put_contents("$tempDir/release-manifest.sig", $signature);
    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['steps'][count($result['steps'])-1]['detail'] = count($manifest['files']) . ' files downloaded and verified';

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

    // Copy all verified files (subdirectories and .htaccess / .user.ini included)
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tempDir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $rel = substr($file->getPathname(), strlen($tempDir) + 1);
        $dest = "$installDir/$rel";
        @mkdir(dirname($dest), 0755, true);
        if (copy($file->getPathname(), $dest)) {
            $installedCount++;
        } else {
            $result['files_failed'][] = $rel;
        }
    }

    $result['files_updated'] = $installedCount;
    $result['steps'][count($result['steps'])-1]['status'] = 'done';
    $result['steps'][count($result['steps'])-1]['detail'] = "$installedCount files installed";

    // Step 5: Set permissions
    $result['steps'][] = ['step' => 'Setting permissions', 'status' => 'running'];

    // Ensure .sessions/ directory exists with correct permissions
    $sessionsDir = $installDir . '/.sessions';
    if (!is_dir($sessionsDir)) {
        mkdir($sessionsDir, 0700, true);
        @chown($sessionsDir, 'www-data');
        @chgrp($sessionsDir, 'www-data');
        // Create .htaccess to deny web access
        file_put_contents($sessionsDir . '/.htaccess', "Require all denied\n");
    }

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

    // Clear OPcache so new PHP files are loaded immediately
    if (function_exists('opcache_reset')) {
        @opcache_reset();
    }

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
