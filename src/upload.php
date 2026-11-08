<?php
// Upload-Only Interface
// =====================
// This page allows file uploads without showing existing files.
// Anonymous uploads are regulated by upload-guard.php (see docs/upload-guard.md):
// bot verification -> time-limited upload pass -> quotas and safety limits.

// GeoIP check - block uploads from non-allowed countries
require_once __DIR__ . '/geo-check.php';
checkGeoAccess();

// Load config early (needed for access check)
$config = [];
$configFile = __DIR__ . '/.config.json';
if (file_exists($configFile)) {
    $config = json_decode(file_get_contents($configFile), true) ?: [];
}

// Upload guard: mode verified (default) | open | login
require_once __DIR__ . '/upload-guard.php';
$guardCfg = ug_config($config);
ug_sync_flags($guardCfg);
if (random_int(1, 50) === 1) {
    ug_cleanup();
}

// Login-only mode
if ($guardCfg['mode'] === 'login') {
    require_once __DIR__ . '/security-check.php';
}

// Logged-in users are never subject to the guard or its limits
$sessionUser = ug_session_user();
if (session_status() === PHP_SESSION_ACTIVE) {
    // Release the session lock so a long upload does not block other tabs
    session_write_close();
}
$isAnonymous = ($sessionUser === null);
$guardActive = $isAnonymous && $guardCfg['mode'] === 'verified';

// Include user management for file ownership tracking
require_once __DIR__ . '/user-management.php';

// Include audit log
require_once __DIR__ . '/audit-log.php';

// Include encryption
require_once __DIR__ . '/encryption.php';

// Determine target folder (user or public)
// Accept the target user from the URL (/u/USERNAME -> ?user=) or from the
// POST form field "target_user"/"user" (documented curl usage).
$targetUser = $_GET['user'] ?? $_POST['target_user'] ?? $_POST['user'] ?? null;
$targetFolder = '_public'; // Default to public folder

if ($targetUser !== null) {
    // Validate user exists - if not, silently fallback to public folder
    // This prevents username enumeration attacks
    if (userExists($targetUser)) {
        $targetFolder = $targetUser;
    }
    // If user doesn't exist, $targetFolder remains '_public' (default)
}

$uploadDir = __DIR__ . '/files/' . $targetFolder . '/';
$maxFileSize = 10 * 1024 * 1024 * 1024; // 10GB in bytes

// Ensure upload directory exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

$speedtestUrl = $config['speedtest_url'] ?? '';

// Generate unique filename if file already exists (uses unique ID to prevent race conditions)
function getUniqueFilename($directory, $filename) {
    if (!file_exists($directory . $filename)) {
        return $filename;
    }

    $info = pathinfo($filename);
    $name = $info['filename'];
    $ext = isset($info['extension']) ? '.' . $info['extension'] : '';

    // Use unique ID instead of counter to prevent TOCTOU race condition
    $uniqueId = bin2hex(random_bytes(4)); // 8 hex chars
    return $name . '_' . $uniqueId . $ext;
}

// Check if this is an AJAX request
$isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
          strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

// Check if this is a command-line / non-browser client (curl, wget, etc.).
// Such clients should get a plain-text response instead of the full HTML page,
// otherwise the upload "looks like cat" — a wall of HTML with no confirmation.
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$accept = $_SERVER['HTTP_ACCEPT'] ?? '';
$isCli = !$isAjax && (
    preg_match('/curl|wget|httpie|python-requests|libwww|go-http|okhttp|powershell|invoke-/i', $ua)
    || strpos($accept, 'text/html') === false
);

$selfUrl = (ug_is_https() ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
         . ($targetFolder === '_public' ? '/u' : '/u/' . $targetFolder);
$folderDisplay = $targetFolder === '_public' ? 'Public' : $targetFolder;

// ── Upload guard API: challenge / verify / status (JSON) ──────────────────
if (isset($_GET['guard'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    $guardAction = $_GET['guard'];

    if (!$guardActive) {
        echo json_encode(['success' => true, 'required' => false]);
        exit;
    }

    if ($guardAction === 'challenge') {
        if ($guardCfg['provider_effective'] !== 'pow') {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Proof-of-work is not the active provider']);
            exit;
        }
        echo json_encode(['success' => true] + ug_create_challenge($guardCfg));
        exit;
    }

    if ($guardAction === 'verify' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $may = ug_ip_may_verify($guardCfg);
        if ($may !== true) {
            http_response_code(429);
            echo json_encode(['success' => false, 'code' => $may,
                'error' => 'Too many verifications from your network. Try again in an hour.']);
            exit;
        }
        $input = json_decode(file_get_contents('php://input'), true) ?: [];
        $provider = $guardCfg['provider_effective'];
        $result = $provider === 'turnstile'
            ? ug_verify_turnstile($input['turnstile'] ?? '', $guardCfg)
            : ug_verify_pow($input['pow'] ?? []);
        if ($result !== true) {
            ug_record_failure();
            http_response_code(403);
            echo json_encode(['success' => false, 'code' => 'verification_failed', 'reason' => $result,
                'error' => 'Verification failed. Please try again.']);
            exit;
        }
        $pass = ug_issue_pass($guardCfg, $provider);
        writeAuditLog('upload_pass_issued', 'Pass ' . ug_format_code($pass['code']) . " ($provider) for folder: $folderDisplay, valid until " . date('Y-m-d H:i', $pass['expires']), 'public');
        echo json_encode(['success' => true, 'pass' => ug_pass_public($pass)]);
        exit;
    }

    if ($guardAction === 'status') {
        [$statusPass, $statusReason] = ug_current_pass();
        echo json_encode(['success' => true, 'required' => true,
            'pass' => ug_pass_public($statusPass), 'reason' => $statusReason]);
        exit;
    }

    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Unknown guard action']);
    exit;
}

// Pass presented with this request (anonymous visitors only)
[$pass, $passReason] = $isAnonymous ? ug_current_pass() : [null, null];

// Handle cancelled upload (Stop button).
// Only a file uploaded with THIS pass in the last 15 minutes can be removed.
// (Before v3.7.0 any file with the given name was deleted - see docs/upload-guard.md.)
if (isset($_POST['delete_partial'])) {
    header('Content-Type: application/json');
    $deleted = ug_delete_recent($pass, $_POST['delete_partial'], __DIR__ . '/files');
    if ($deleted) {
        writeAuditLog('public_upload_cancel', "Cancelled upload removed: $deleted from folder: $folderDisplay (pass " . ug_format_code($pass['code']) . ')', 'public');
    }
    echo json_encode(['success' => (bool)$deleted]);
    exit;
}

/**
 * Reject an upload: JSON for AJAX, plain text for CLI, otherwise return the
 * message for the HTML page.
 */
function uploadReject($code, $message, $http, $isAjax, $isCli, $selfUrl, $pass = null) {
    http_response_code($http);
    if ($isAjax) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'guard' => $code, 'error' => $message, 'pass' => ug_pass_public($pass)]);
        exit;
    }
    if ($isCli) {
        header('Content-Type: text/plain; charset=utf-8');
        echo "ERROR: $message\n";
        if ($code === 'pass_required') {
            echo "\nOpen $selfUrl in a browser, confirm you are not a robot and copy your upload code.\n";
            echo "Then upload with:\n  curl -H \"X-Upload-Pass: CODE\" -F \"file=@FILE\" $selfUrl\n";
        }
        exit;
    }
    return $message;
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $guardError = null;

    if ($file['error'] === UPLOAD_ERR_OK && $isAnonymous) {
        // "curl without code" matches the same User-Agent rule as the Apache
        // pre-filter (curl|wget), not the broader $isCli heuristic, which also
        // covers any client that does not ask for HTML.
        $isCurlUa = (bool)preg_match('/curl|wget/i', $ua);
        if ($guardActive && !$pass && !(!empty($guardCfg['curl_without_pass']) && $isCurlUa)) {
            $msg = $passReason === 'expired' ? 'Your upload pass has expired. Please verify again.'
                 : ($passReason === 'revoked' ? 'Your upload pass was revoked.'
                 : 'Upload verification required.');
            $guardError = ['pass_required', $msg, 403];
        } elseif ($guardCfg['mode'] !== 'login') {
            $guardError = ug_check_upload($guardCfg, $pass, (int)$file['size'], basename($file['name']), $uploadDir);
            if ($guardError) {
                writeAuditLog('public_upload_blocked', "Blocked ({$guardError[0]}): " . basename($file['name']) . ' (' . formatBytes($file['size']) . ") to folder: $folderDisplay", 'public');
            }
        }
    }

    // F1: anonymous uploads to /u/<user> count towards that user's quota (Public has none)
    if (!$guardError && $file['error'] === UPLOAD_ERR_OK) {
        require_once __DIR__ . '/quota.php';
        if ($qe = quota_check($targetFolder, (int)$file['size'])) {
            $guardError = ['quota', $qe, 413];
        }
    }

    if ($guardError) {
        // PHP deletes the temporary upload automatically at the end of the request
        $error = uploadReject($guardError[0], $guardError[1], $guardError[2], $isAjax, $isCli, $selfUrl, $pass);
    } elseif ($file['error'] === UPLOAD_ERR_OK) {
        $uploadedSize = (int)$file['size'];
        $originalFilename = basename($file['name']);
        $filename = getUniqueFilename($uploadDir, $originalFilename);
        $targetPath = $uploadDir . $filename;

        if (move_uploaded_file($file['tmp_name'], $targetPath)) {
            $finalFilename = $filename;
            $wasEncrypted = false;

            // Check if encryption is requested
            if (isset($_POST['encrypt']) && $_POST['encrypt'] === '1' && !empty($_POST['encrypt_password'])) {
                $encryptPassword = $_POST['encrypt_password'];
                $encryptedPath = $targetPath . ENCRYPTED_EXTENSION;

                // Encrypt the file
                $encResult = encryptFile($targetPath, $encryptedPath, $encryptPassword);

                if ($encResult['success']) {
                    // Delete original unencrypted file
                    unlink($targetPath);

                    // Update filename to encrypted version
                    $finalFilename = $filename . ENCRYPTED_EXTENSION;
                    $targetPath = $encryptedPath;
                    $wasEncrypted = true;

                    // Store encryption password for recovery
                    $uploaderName = $targetFolder === '_public' ? 'public' : $targetFolder;
                    storeEncryptionPassword($finalFilename, $encryptPassword, $uploaderName, $targetFolder);
                }
                // If encryption fails, keep the original unencrypted file
            }

            // Record file ownership
            $uploaderName = $targetFolder === '_public' ? 'public' : $targetFolder;
            recordFileUpload($finalFilename, $uploaderName, $targetFolder);

            // Upload guard accounting (daily total + pass quota) and owner notification
            if ($isAnonymous) {
                $pass = ug_record_upload($pass, $originalFilename, $finalFilename, $targetFolder, $uploadedSize) ?: $pass;
                ug_notify_owner_deferred($guardCfg, $config, $targetFolder, $finalFilename, $uploadedSize, $pass);
            }

            // Audit log
            $encryptedNote = $wasEncrypted ? ' (encrypted)' : '';
            $passNote = $pass ? ' [pass ' . ug_format_code($pass['code']) . ']' : ($sessionUser ? " [user $sessionUser]" : '');
            writeAuditLog('public_upload', "File: $finalFilename (" . formatBytes(filesize($targetPath)) . ")$encryptedNote to folder: $folderDisplay$passNote", 'public');

            if ($isAjax) {
                // Return JSON for AJAX requests
                header('Content-Type: application/json');
                echo json_encode([
                    'success' => true,
                    'originalName' => $originalFilename,
                    'finalName' => $finalFilename,
                    'renamed' => $finalFilename !== $originalFilename,
                    'encrypted' => $wasEncrypted,
                    'pass' => ug_pass_public($pass)
                ]);
                exit;
            }

            if ($isCli) {
                // Plain-text confirmation for curl/wget and other CLI clients
                header('Content-Type: text/plain; charset=utf-8');
                $note = $finalFilename !== $originalFilename ? ' (renamed, original name was taken)' : '';
                if ($wasEncrypted) {
                    $note .= ' (encrypted)';
                }
                echo "OK: uploaded as $finalFilename$note\n";
                exit;
            }

            if ($finalFilename !== $originalFilename) {
                $success = "Файлът е качен като: $finalFilename (името е било заето)";
            } else {
                $success = "Файлът е качен: $finalFilename";
            }
            if ($wasEncrypted) {
                $success .= " (encrypted)";
            }
        } else {
            if ($isAjax) {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => 'Failed to upload file']);
                exit;
            }
            if ($isCli) {
                header('Content-Type: text/plain; charset=utf-8');
                http_response_code(500);
                echo "ERROR: Failed to upload file\n";
                exit;
            }
            $error = "Файлът не можа да бъде качен.";
        }
    } else {
        $errorMessages = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'Upload stopped by extension',
        ];
        $errorMsg = $errorMessages[$file['error']] ?? 'Unknown upload error';

        if ($isAjax) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => $errorMsg]);
            exit;
        }
        if ($isCli) {
            header('Content-Type: text/plain; charset=utf-8');
            http_response_code(400);
            echo "ERROR: $errorMsg\n";
            exit;
        }
        $error = $errorMsg;
    }
}

// Helper function for file size formatting
function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}
?>
<?php
$pageTitle = $targetFolder === '_public' ? 'Качване на файлове' : "Качване за {$targetFolder}";
// Effective per-file limit shown to the visitor
$limitsApply = $isAnonymous && $guardCfg['mode'] !== 'login';
$effectiveMaxFile = $limitsApply ? min($maxFileSize, ug_mb($guardCfg['max_file_mb'])) : $maxFileSize;
$guardClient = [
    'active'     => $guardActive,
    'provider'   => $guardCfg['provider_effective'],
    'siteKey'    => $guardCfg['provider_effective'] === 'turnstile' ? $guardCfg['turnstile_site_key'] : '',
    'maxFile'    => $effectiveMaxFile,
    'pass'       => ug_pass_public($pass),
    'ttlHours'   => (int)$guardCfg['pass_ttl_hours'],
    'selfUrl'    => $selfUrl,
];
$pageSubtitle = $targetFolder === '_public' ? 'Файловете отиват в общата папка' : "Файловете отиват директно в папката на {$targetFolder}";
?>
<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?> - WebShare</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link rel="apple-touch-icon" href="apple-touch-icon.png">
    <link rel="stylesheet" href="ui-kit.css?v=<?= (int)@filemtime(__DIR__ . '/ui-kit.css') ?>">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            width: 100%;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            position: relative;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            text-align: center;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            text-align: center;
        }
        .alert {
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .upload-section {
            border: 3px dashed #ddd;
            border-radius: 12px;
            padding: 60px 40px;
            text-align: center;
            background: #fafafa;
            transition: all 0.3s;
            cursor: pointer;
        }
        .upload-section:hover {
            border-color: #4C51BF;
            background: #f0f4ff;
            transform: translateY(-2px);
        }
        .upload-section.drag-over {
            border-color: #4C51BF;
            background: #e3e9ff;
            transform: scale(1.02);
        }
        .upload-icon {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.7;
        }
        .upload-section h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 20px;
        }
        .upload-info {
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }
        .btn {
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
            color: white;
            padding: 14px 40px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            margin-top: 20px;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        input[type="file"] {
            display: none;
        }
        .progress-container {
            display: none;
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
        }
        .progress-container.active {
            display: block;
        }
        .progress-bar-wrapper {
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
            margin-bottom: 15px;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #4C51BF 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 14px;
        }
        .upload-stats {
            display: flex;
            justify-content: space-between;
            color: #666;
            font-size: 14px;
        }
        .upload-stats div {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .stat-label {
            font-weight: 600;
            color: #333;
        }
        .btn-stop {
            background: #C62828;
            color: white;
            padding: 10px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            margin-top: 15px;
            transition: all 0.3s;
        }
        .btn-stop:hover {
            background: #B71C1C;
            transform: translateY(-2px);
        }
        /* Success Screen */
        .success-screen {
            display: none;
            text-align: center;
            padding: 40px 20px;
        }
        .success-screen.active {
            display: block;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #2E7D32 0%, #1B5E20 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 40px;
            color: white;
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
        }
        .success-title {
            color: #333;
            font-size: 24px;
            margin-bottom: 20px;
        }
        .uploaded-files {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
            max-height: 200px;
            overflow-y: auto;
        }
        .uploaded-file {
            padding: 10px 15px;
            background: white;
            border-radius: 8px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .uploaded-file:last-child {
            margin-bottom: 0;
        }
        .uploaded-file .file-icon {
            font-size: 20px;
        }
        .uploaded-file .file-name {
            flex: 1;
            color: #333;
            word-break: break-all;
        }
        .uploaded-file .renamed-badge {
            background: #fff3cd;
            color: #856404;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .uploaded-file .encrypted-badge {
            background: #d4edda;
            color: #155724;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .success-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 25px;
        }
        .btn-secondary {
            background: #6c757d;
            color: white;
            padding: 14px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-secondary:hover {
            background: #5a6268;
            transform: translateY(-2px);
        }
        .btn-success {
            background: linear-gradient(135deg, #2E7D32 0%, #1B5E20 100%);
            color: white;
            padding: 14px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 4px 12px rgba(76, 175, 80, 0.4);
        }
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(76, 175, 80, 0.6);
        }
        .speedtest-link {
            position: fixed;
            bottom: 15px;
            right: 15px;
            background: rgba(255,255,255,0.95);
            padding: 10px 18px;
            border-radius: 25px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.2);
            text-decoration: none;
            color: #4C51BF;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s;
        }
        .speedtest-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            color: #764ba2;
        }
        /* Encryption Options */
        .encryption-options {
            margin-top: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
            border: 1px solid #e0e0e0;
        }
        .encrypt-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .encrypt-checkbox {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 15px;
            color: #333;
            gap: 10px;
        }
        .encrypt-checkbox input[type="checkbox"] {
            width: 20px;
            height: 20px;
            cursor: pointer;
            accent-color: #4C51BF;
        }
        .collapse-btn {
            background: none;
            border: none;
            cursor: pointer;
            padding: 5px 10px;
            font-size: 14px;
            color: #4C51BF;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .collapse-btn:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        .encryption-fields {
            margin-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .encryption-fields.collapsed {
            display: none !important;
        }
        .password-field-wrapper {
            position: relative;
        }
        .encryption-fields input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s, box-shadow 0.3s;
            box-sizing: border-box;
        }
        .encryption-fields input[type="password"]:focus {
            outline: none;
            border-color: #4C51BF;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        .encryption-fields input[type="password"].error {
            border-color: #dc3545;
            background: #fff5f5;
            box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.2);
        }
        .encryption-fields input[type="password"].valid {
            border-color: #1E7E34;
            background: #f0fff4;
            box-shadow: 0 0 0 3px rgba(40, 167, 69, 0.15);
        }
        .encryption-fields input[type="password"].invalid {
            border-color: #ffc107;
            background: #fffbeb;
            box-shadow: 0 0 0 3px rgba(255, 193, 7, 0.15);
        }
        .field-error {
            display: none;
            color: #dc3545;
            font-size: 12px;
            margin-top: 4px;
            padding-left: 5px;
        }
        .field-error.visible {
            display: block;
        }
        /* Upload guard */
        .guard-card {
            border: 2px solid #4C51BF;
            background: #f5f7ff;
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 20px;
            text-align: center;
        }
        .guard-card.attention { animation: guardPulse 0.6s ease 2; }
        @keyframes guardPulse { 50% { box-shadow: 0 0 0 6px rgba(102,126,234,0.35); } }
        .guard-card h2 { color: #333; font-size: 17px; margin-bottom: 6px; }
        .guard-card p { color: #555; font-size: 14px; line-height: 1.5; margin-bottom: 14px; }
        .guard-btn {
            display: inline-flex; align-items: center; gap: 10px;
            background: white; border: 2px solid #ccc; border-radius: 8px;
            padding: 12px 20px; font-size: 15px; cursor: pointer; color: #333;
        }
        .guard-btn:hover:not(:disabled) { border-color: #4C51BF; }
        .guard-btn:disabled { cursor: progress; opacity: 0.8; }
        .guard-box {
            width: 22px; height: 22px; border: 2px solid #999; border-radius: 4px;
            display: inline-flex; align-items: center; justify-content: center; font-size: 14px;
        }
        .guard-progress { height: 6px; background: #e0e0e0; border-radius: 3px; overflow: hidden; margin-top: 12px; display: none; }
        .guard-progress div { height: 100%; width: 0; background: #4C51BF; transition: width 0.2s; }
        .guard-error { color: #c0392b; font-size: 13px; margin-top: 10px; display: none; }
        .guard-pending { color: #4C51BF; font-size: 13px; margin-top: 10px; display: none; font-weight: 600; }
        .pass-panel {
            background: #f0fff4; border: 1px solid #b7e4c7; border-radius: 12px;
            padding: 14px 16px; margin-bottom: 20px; font-size: 13px; color: #2d6a4f;
        }
        .pass-panel .pass-row { display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
        .pass-panel details { margin-top: 8px; }
        .pass-panel summary { cursor: pointer; font-weight: 600; }
        .pass-panel code {
            display: block; background: #1e293b; color: #a5f3fc; padding: 10px 12px; border-radius: 8px;
            margin-top: 8px; font-size: 12px; word-break: break-all; white-space: pre-wrap;
        }
        .pass-panel .pass-code { font-family: monospace; font-size: 15px; font-weight: 700; letter-spacing: 1px; }
        .copy-btn {
            margin-top: 6px; background: #2d6a4f; color: white; border: none; border-radius: 6px;
            padding: 6px 12px; font-size: 12px; cursor: pointer;
        }
        /* Locked until verification: muted frame, readable text, clearly still clickable */
        .upload-section.locked { border-style: dashed; border-color: #b8bfe8; background: #f7f8fc; }
        .upload-section.locked .drop-title::after { content: ' 🔒'; }
        .failed-files { background: #fff5f5; border: 1px solid #f5c6cb; border-radius: 12px; padding: 12px 16px; margin: 10px 0; text-align: left; display: none; }
        .failed-files div { font-size: 13px; color: #721c24; padding: 4px 0; word-break: break-word; }
        .drop-title { color: #333; margin-bottom: 10px; font-size: 20px; }
        @media (max-width: 520px) {
            body { flex-direction: column; justify-content: flex-start; padding: 12px; }
            .speedtest-wrap { align-self: flex-end; margin-bottom: 12px; }
            .speedtest-link { position: static; display: inline-block; }
            .container { padding: 24px 18px; }
            .upload-section { padding: 36px 16px; }
            .upload-stats { flex-direction: column; gap: 8px; }
            .success-buttons { flex-direction: column; }
        }
        .encryption-warning {
            font-size: 13px;
            color: #856404;
            background: #fff3cd;
            padding: 10px 15px;
            border-radius: 8px;
            margin-top: 5px;
        }
    </style>
    <script src="ui-kit.js?v=<?= (int)@filemtime(__DIR__ . '/ui-kit.js') ?>" defer></script>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <div role="complementary" aria-label="Speed test" class="speedtest-wrap"><a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank" rel="noopener">🚀 Speed Test</a></div>
    <?php endif; ?>

    <div class="container" role="main">
        <h1>📤 <?= htmlspecialchars($pageTitle) ?></h1>
        <p class="subtitle"><?= htmlspecialchars($pageSubtitle) ?></p>

        <?php if (isset($success)): ?>
            <div class="alert alert-success">✓ <?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-error">✗ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($guardActive): ?>
        <!-- Upload guard: bot verification (docs/upload-guard.md) -->
        <div class="guard-card" id="guardCard" style="<?= $pass ? 'display:none' : '' ?>">
            <h2>🛡️ Потвърди, че не си робот</h2>
            <p>Еднократна проверка преди качване. След нея можеш да качваш файлове
               <?= (int)$guardCfg['pass_ttl_hours'] ?> часа без нова проверка.</p>
            <?php if ($guardCfg['provider_effective'] === 'turnstile'): ?>
                <div id="turnstileWidget" style="display:inline-block"></div>
            <?php else: ?>
                <button type="button" class="guard-btn" id="guardBtn" onclick="startVerification()">
                    <span class="guard-box" id="guardBox"></span>
                    <span id="guardBtnText">Не съм робот</span>
                </button>
                <div class="guard-progress" id="guardProgress"><div id="guardProgressBar"></div></div>
            <?php endif; ?>
            <div class="guard-pending" id="guardPending"></div>
            <div class="guard-error" id="guardError"></div>
        </div>

        <div class="pass-panel" id="passPanel" style="<?= $pass ? '' : 'display:none' ?>">
            <div class="pass-row">
                <span>✅ Проверен до <b id="passExpires"></b></span>
                <span>Остават: <b id="passFiles"></b> файла · <b id="passBytes"></b></span>
            </div>
            <details>
                <summary>Качване от терминал (curl)</summary>
                <div style="margin-top:6px">Код за качване: <span class="pass-code" id="passCode"></span></div>
                <code id="curlCmd"></code>
                <button type="button" class="copy-btn" onclick="copyCurl()">Копирай командата</button>
            </details>
        </div>
        <?php endif; ?>

        <div class="upload-section<?= ($guardActive && !$pass) ? ' locked' : '' ?>" id="dropZone">
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <div onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">📁</div>
                    <h2 class="drop-title">Натисни или пусни файл тук</h2>
                    <p class="upload-info">Максимален размер: <?= formatBytes($effectiveMaxFile) ?></p>
                </div>
                <input type="file" name="file" id="fileInput" multiple>
                <button type="button" class="btn" onclick="document.getElementById('fileInput').click()">
                    Избери файлове
                </button>
            </form>
        </div>

        <!-- Encryption Options -->
        <div class="encryption-options" id="encryptionOptions">
            <div class="encrypt-header">
                <label class="encrypt-checkbox">
                    <input type="checkbox" id="encryptFiles" onchange="toggleEncryptionFields()">
                    <span class="checkmark"></span>
                    🔒 Криптирай файловете с парола
                </label>
                <button type="button" class="collapse-btn" id="collapseBtn" style="display: none;" onclick="toggleEncryptionCollapse()" title="Скрий/Покажи">
                    <span id="collapseIcon">▼</span>
                </button>
            </div>
            <div class="encryption-fields" id="encryptionFields" style="display: none;">
                <div class="password-field-wrapper">
                    <input type="password" id="encryptPassword" placeholder="Парола за криптиране (мин. 4 знака)" autocomplete="new-password" oninput="validatePasswordField()">
                    <span class="field-error" id="encryptPasswordError"></span>
                </div>
                <div class="password-field-wrapper">
                    <input type="password" id="encryptPasswordConfirm" placeholder="Повтори паролата" autocomplete="new-password" oninput="validateConfirmField()">
                    <span class="field-error" id="encryptPasswordConfirmError"></span>
                </div>
                <div class="encryption-warning">
                    ⚠️ Запомни паролата! Ако я забравиш, файловете не могат да бъдат възстановени.
                </div>
            </div>
        </div>

        <!-- Progress Bar -->
        <div class="progress-container" id="progressContainer">
            <div style="margin-bottom: 10px; text-align: center; color: #666; font-size: 14px; font-weight: 600;" id="currentFileName"></div>
            <div class="progress-bar-wrapper">
                <div class="progress-bar" id="progressBar">0%</div>
            </div>
            <div class="upload-stats">
                <div>
                    <span class="stat-label">Скорост</span>
                    <span id="uploadSpeed">0 KB/s</span>
                </div>
                <div>
                    <span class="stat-label">Качени</span>
                    <span id="uploadedSize">0 MB / 0 MB</span>
                </div>
                <div>
                    <span class="stat-label">Оставащо време</span>
                    <span id="timeRemaining">--:--</span>
                </div>
            </div>
            <div style="text-align: center;">
                <button class="btn-stop" id="stopButton" onclick="stopUpload()">Спри качването</button>
            </div>
        </div>

        <!-- Success Screen -->
        <div class="success-screen" id="successScreen">
            <div class="success-icon">✓</div>
            <h2 class="success-title" id="successTitle">Файловете са качени успешно!</h2>
            <div class="uploaded-files" id="uploadedFilesList">
                <!-- Files will be inserted here by JavaScript -->
            </div>
            <div class="failed-files" id="failedFilesList"></div>
            <div class="success-buttons">
                <button class="btn" onclick="window.location.reload()">📤 Качи още файлове</button>
                <button class="btn-secondary" onclick="closeWindow()">✓ Готово</button>
            </div>
        </div>
    </div>

    <script>
        let encryptionCollapsed = false;

        // Toggle encryption fields visibility
        function toggleEncryptionFields() {
            const checkbox = document.getElementById('encryptFiles');
            const fields = document.getElementById('encryptionFields');
            const collapseBtn = document.getElementById('collapseBtn');

            if (checkbox.checked) {
                fields.style.display = 'flex';
                fields.classList.remove('collapsed');
                collapseBtn.style.display = 'block';
                encryptionCollapsed = false;
                document.getElementById('collapseIcon').textContent = '▼';
            } else {
                fields.style.display = 'none';
                collapseBtn.style.display = 'none';
                // Clear passwords and errors when unchecking
                document.getElementById('encryptPassword').value = '';
                document.getElementById('encryptPasswordConfirm').value = '';
                clearFieldError('encryptPassword');
                clearFieldError('encryptPasswordConfirm');
            }
        }

        // Toggle collapse of encryption fields
        function toggleEncryptionCollapse() {
            const fields = document.getElementById('encryptionFields');
            const icon = document.getElementById('collapseIcon');

            encryptionCollapsed = !encryptionCollapsed;

            if (encryptionCollapsed) {
                fields.classList.add('collapsed');
                icon.textContent = '▶';
            } else {
                fields.classList.remove('collapsed');
                icon.textContent = '▼';
            }
        }

        // Clear field error and validation states
        function clearFieldError(fieldId) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            field.classList.remove('error', 'valid', 'invalid');
            errorSpan.classList.remove('visible');
            errorSpan.textContent = '';
        }

        // Show field error
        function showFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            field.classList.remove('valid', 'invalid');
            field.classList.add('error');
            errorSpan.textContent = message;
            errorSpan.classList.add('visible');
        }

        // Real-time validation for password field
        function validatePasswordField() {
            const passField = document.getElementById('encryptPassword');
            const password = passField.value;

            // Clear error state first
            clearFieldError('encryptPassword');

            if (password.length === 0) {
                // Empty - neutral state
                passField.classList.remove('valid', 'invalid', 'error');
            } else if (password.length >= 4) {
                // Valid - green
                passField.classList.remove('invalid', 'error');
                passField.classList.add('valid');
            } else {
                // Too short - neutral/typing state (not error yet)
                passField.classList.remove('valid', 'error');
                // Don't add invalid class while typing, just neutral
            }

            // Also update confirm field if it has content
            const confirmField = document.getElementById('encryptPasswordConfirm');
            if (confirmField.value.length > 0) {
                validateConfirmField();
            }
        }

        // Real-time validation for confirm field
        function validateConfirmField() {
            const passField = document.getElementById('encryptPassword');
            const confirmField = document.getElementById('encryptPasswordConfirm');
            const password = passField.value;
            const confirmPassword = confirmField.value;

            // Clear error state first
            clearFieldError('encryptPasswordConfirm');

            if (confirmPassword.length === 0) {
                // Empty - neutral state
                confirmField.classList.remove('valid', 'invalid', 'error');
            } else if (password === confirmPassword && password.length >= 4) {
                // Matches and valid - green
                confirmField.classList.remove('invalid', 'error');
                confirmField.classList.add('valid');
            } else {
                // Doesn't match - yellow/red
                confirmField.classList.remove('valid', 'error');
                confirmField.classList.add('invalid');
            }
        }

        // Validate encryption password
        function validateEncryption() {
            const checkbox = document.getElementById('encryptFiles');
            if (!checkbox.checked) return { valid: true, password: null };

            // Make sure fields are visible for validation
            if (encryptionCollapsed) {
                toggleEncryptionCollapse();
            }

            const password = document.getElementById('encryptPassword').value;
            const confirmPassword = document.getElementById('encryptPasswordConfirm').value;

            // Clear previous errors
            clearFieldError('encryptPassword');
            clearFieldError('encryptPasswordConfirm');

            let hasError = false;

            if (password.length < 4) {
                showFieldError('encryptPassword', 'Паролата трябва да е поне 4 знака');
                hasError = true;
            }

            if (!hasError && password !== confirmPassword) {
                showFieldError('encryptPasswordConfirm', 'Паролите не съвпадат');
                hasError = true;
            }

            if (hasError) {
                return { valid: false, password: null };
            }

            return { valid: true, password: password };
        }

        // Drag and drop functionality
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        let currentXHR = null;
        let currentFileName = null;
        let uploadQueue = [];
        let isUploading = false;
        let currentFileIndex = 0;
        let uploadedFiles = []; // Track successfully uploaded files
        let totalFiles = 0;
        let encryptionPassword = null; // Store encryption password for upload queue
        let failedFiles = []; // [{name, error}]

        // ── Upload guard (docs/upload-guard.md) ──────────────────────────
        const GUARD = <?= json_encode($guardClient, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES) ?>;
        let pendingFiles = null; // files dropped before verification

        const GUARD_MESSAGES = {
            pass_required: 'Нужна е проверка, че не си робот.',
            quota_files: 'Пропускът изчерпа лимита си за брой файлове. Потвърди отново.',
            quota_bytes: 'Пропускът изчерпа лимита си за обем. Потвърди отново.',
            file_too_large: 'Файлът е по-голям от лимита за анонимно качване.',
            blocked_type: 'Този тип файл не е разрешен за анонимно качване.',
            daily_cap: 'Дневният лимит за анонимни качвания е достигнат. Опитай утре.',
            disk_low: 'Сървърът е с малко свободно място. Анонимното качване е спряно временно.',
            ip_pass_limit: 'Твърде много проверки от твоята мрежа. Опитай след час.',
            ip_fail_limit: 'Твърде много неуспешни проверки. Опитай след час.',
            verification_failed: 'Проверката не мина. Опитай пак.'
        };

        function guardNeedsPass() {
            return GUARD.active && !GUARD.pass;
        }

        function guardUrl(action) {
            const url = new URL(window.location.href);
            url.searchParams.set('guard', action);
            return url.toString();
        }

        function showGuardError(msg) {
            const el = document.getElementById('guardError');
            if (!el) return;
            el.textContent = msg || '';
            el.style.display = msg ? 'block' : 'none';
        }

        function lockForVerification(reasonCode) {
            GUARD.pass = null;
            const card = document.getElementById('guardCard');
            document.getElementById('passPanel').style.display = 'none';
            dropZone.classList.add('locked');
            card.style.display = 'block';
            card.classList.remove('attention');
            void card.offsetWidth;
            card.classList.add('attention');
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
            const box = document.getElementById('guardBox');
            if (box) box.textContent = '';
            const btn = document.getElementById('guardBtn');
            if (btn) btn.disabled = false;
            const txt = document.getElementById('guardBtnText');
            if (txt) txt.textContent = 'Не съм робот';
            if (reasonCode && reasonCode !== 'pass_required') showGuardError(GUARD_MESSAGES[reasonCode] || '');
            if (GUARD.provider === 'turnstile' && window.turnstile && window.turnstileWidgetId !== undefined) {
                turnstile.reset(window.turnstileWidgetId);
            }
            updatePending();
        }

        function updatePending() {
            const el = document.getElementById('guardPending');
            if (!el) return;
            if (pendingFiles && pendingFiles.length) {
                el.textContent = `${pendingFiles.length} файл(а) чакат. Качването започва веднага след проверката.`;
                el.style.display = 'block';
            } else {
                el.style.display = 'none';
            }
        }

        function applyPass(pass) {
            if (!pass) return;
            GUARD.pass = pass;
            if (!GUARD.active) return;
            document.getElementById('guardCard').style.display = 'none';
            dropZone.classList.remove('locked');
            const panel = document.getElementById('passPanel');
            panel.style.display = 'block';
            const exp = new Date(pass.expires * 1000);
            document.getElementById('passExpires').textContent =
                exp.toLocaleDateString('bg-BG') + ' ' + exp.toLocaleTimeString('bg-BG', { hour: '2-digit', minute: '2-digit' });
            document.getElementById('passFiles').textContent = pass.files_left;
            document.getElementById('passBytes').textContent = formatBytes(pass.bytes_left);
            document.getElementById('passCode').textContent = pass.code;
            document.getElementById('curlCmd').textContent =
                `curl -H "X-Upload-Pass: ${pass.code}" -F "file=@ФАЙЛ" ${GUARD.selfUrl}`;
        }

        function copyCurl() {
            const text = document.getElementById('curlCmd').textContent;
            const done = () => {
                const btn = document.querySelector('.copy-btn');
                btn.textContent = 'Копирано ✓';
                setTimeout(() => { btn.textContent = 'Копирай командата'; }, 2000);
            };
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(done).catch(() => {});
            }
        }

        async function sha256Hex(text) {
            const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
            return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Proof-of-work: find n in [0, maxnumber] with sha256(salt + n) === challenge.
        // Hashes are computed in parallel batches to keep it around a second.
        async function solvePow(ch, onProgress) {
            const batch = 500;
            for (let start = 0; start <= ch.maxnumber; start += batch) {
                const jobs = [];
                for (let n = start; n < start + batch && n <= ch.maxnumber; n++) {
                    jobs.push(sha256Hex(ch.salt + n).then(h => h === ch.challenge ? n : -1));
                }
                const found = (await Promise.all(jobs)).find(n => n >= 0);
                if (found !== undefined) return found;
                onProgress(Math.min(1, (start + batch) / ch.maxnumber));
            }
            return null;
        }

        async function sendVerification(body) {
            const res = await fetch(guardUrl('verify'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify(body)
            });
            const data = await res.json().catch(() => ({ success: false }));
            if (!data.success) {
                throw new Error(GUARD_MESSAGES[data.code] || data.error || 'Проверката не мина.');
            }
            return data;
        }

        function onVerified(data) {
            showGuardError('');
            applyPass(data.pass);
            if (pendingFiles && pendingFiles.length) {
                const files = pendingFiles;
                pendingFiles = null;
                updatePending();
                addFilesToQueue(files);
            }
        }

        async function startVerification() {
            const btn = document.getElementById('guardBtn');
            const box = document.getElementById('guardBox');
            const txt = document.getElementById('guardBtnText');
            const prog = document.getElementById('guardProgress');
            const bar = document.getElementById('guardProgressBar');
            showGuardError('');
            if (!window.crypto || !crypto.subtle) {
                showGuardError('Браузърът не поддържа проверката. Използвай HTTPS и съвременен браузър.');
                return;
            }
            btn.disabled = true;
            box.textContent = '⏳';
            txt.textContent = 'Проверявам...';
            prog.style.display = 'block';
            bar.style.width = '0';
            try {
                const chRes = await fetch(guardUrl('challenge'), { credentials: 'same-origin', cache: 'no-store' });
                const ch = await chRes.json();
                if (!ch.success) throw new Error(ch.error || 'Неуспешна проверка.');
                const number = await solvePow(ch, p => { bar.style.width = Math.round(p * 100) + '%'; });
                if (number === null) throw new Error('Проверката не намери решение. Опитай пак.');
                bar.style.width = '100%';
                const data = await sendVerification({ pow: {
                    algorithm: ch.algorithm, challenge: ch.challenge, salt: ch.salt,
                    number: number, signature: ch.signature
                } });
                box.textContent = '✓';
                txt.textContent = 'Потвърдено';
                prog.style.display = 'none';
                onVerified(data);
            } catch (e) {
                box.textContent = '';
                txt.textContent = 'Не съм робот';
                btn.disabled = false;
                prog.style.display = 'none';
                showGuardError(e.message);
            }
        }

        // Cloudflare Turnstile (optional provider)
        window.onTurnstileLoad = function () {
            window.turnstileWidgetId = turnstile.render('#turnstileWidget', {
                sitekey: GUARD.siteKey,
                callback: async function (token) {
                    try {
                        onVerified(await sendVerification({ turnstile: token }));
                    } catch (e) {
                        showGuardError(e.message);
                        turnstile.reset(window.turnstileWidgetId);
                    }
                }
            });
        };
        if (GUARD.active && GUARD.provider === 'turnstile') {
            const ts = document.createElement('script');
            ts.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
            ts.async = true;
            document.head.appendChild(ts);
        }

        if (GUARD.pass) applyPass(GUARD.pass);

        function recordFailure(name, message) {
            failedFiles.push({ name: name, error: message });
        }

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('drag-over');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('drag-over');
            }, false);
        });

        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                addFilesToQueue(files);
            }
        }, false);

        // Auto-upload on file select
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                addFilesToQueue(fileInput.files);
            }
        });

        // Add files to upload queue
        function addFilesToQueue(files) {
            // Validate encryption settings first
            const encResult = validateEncryption();
            if (!encResult.valid) {
                return; // Don't start upload if encryption validation fails
            }

            // Not verified yet: keep the files and ask for verification first
            if (guardNeedsPass()) {
                pendingFiles = Array.from(files);
                lockForVerification('pass_required');
                return;
            }

            encryptionPassword = encResult.password; // Store for upload queue
            failedFiles = [];
            uploadQueue = [];
            Array.from(files).forEach(f => {
                if (GUARD.maxFile && f.size > GUARD.maxFile) {
                    recordFailure(f.name, 'По-голям от лимита ' + formatBytes(GUARD.maxFile) + '.');
                } else {
                    uploadQueue.push(f);
                }
            });
            totalFiles = uploadQueue.length;
            currentFileIndex = 0;
            uploadedFiles = []; // Reset uploaded files list
            if (uploadQueue.length === 0) {
                showSuccessScreen();
                return;
            }
            processQueue();
        }

        // Process upload queue
        function processQueue() {
            if (uploadQueue.length === 0) {
                isUploading = false;
                return;
            }

            if (isUploading) {
                return;
            }

            isUploading = true;
            const file = uploadQueue.shift();
            currentFileIndex++;
            uploadFile(file);
        }

        // Upload file with progress tracking
        function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);

            // Add encryption password if set
            if (encryptionPassword) {
                formData.append('encrypt', '1');
                formData.append('encrypt_password', encryptionPassword);
            }

            currentXHR = new XMLHttpRequest();
            currentFileName = file.name;
            const xhr = currentXHR;

            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            const uploadSpeed = document.getElementById('uploadSpeed');
            const uploadedSize = document.getElementById('uploadedSize');
            const timeRemaining = document.getElementById('timeRemaining');
            const currentFileNameEl = document.getElementById('currentFileName');

            let startTime = Date.now();
            let lastLoaded = 0;
            let lastTime = startTime;

            // Show progress container and file name
            progressContainer.classList.add('active');
            currentFileNameEl.textContent = file.name;

            // Upload progress
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressBar.style.width = percentComplete + '%';

                    // Show file progress with queue info
                    let progressText = Math.round(percentComplete) + '%';
                    if (totalFiles > 1) {
                        progressText += ` - File ${currentFileIndex} of ${totalFiles}`;
                    }
                    progressBar.textContent = progressText;

                    // Calculate speed
                    const currentTime = Date.now();
                    const timeDiff = (currentTime - lastTime) / 1000; // seconds
                    const loadedDiff = e.loaded - lastLoaded;

                    if (timeDiff > 0) {
                        const speed = loadedDiff / timeDiff; // bytes per second
                        uploadSpeed.textContent = formatSpeed(speed);

                        // Calculate time remaining
                        const remaining = e.total - e.loaded;
                        const timeLeft = remaining / speed;
                        timeRemaining.textContent = formatTime(timeLeft);

                        lastLoaded = e.loaded;
                        lastTime = currentTime;
                    }

                    // Update uploaded size
                    uploadedSize.textContent = formatBytes(e.loaded) + ' / ' + formatBytes(e.total);
                }
            });

            // Upload complete
            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    progressBar.style.width = '100%';
                    let progressText = '100%';
                    if (totalFiles > 1) {
                        progressText += ` - File ${currentFileIndex} of ${totalFiles}`;
                    }
                    progressBar.textContent = progressText;

                    // Parse JSON response and track uploaded file
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.pass) applyPass(response.pass);
                        if (response.success) {
                            uploadedFiles.push({
                                originalName: response.originalName,
                                finalName: response.finalName,
                                renamed: response.renamed,
                                encrypted: response.encrypted || false
                            });
                        }
                    } catch (e) {
                        // Fallback if not JSON
                        uploadedFiles.push({
                            originalName: file.name,
                            finalName: file.name,
                            renamed: false
                        });
                    }

                    currentXHR = null;
                    currentFileName = null;
                    isUploading = false;

                    // Check if there are more files in queue
                    if (uploadQueue.length > 0) {
                        // Continue with next file after short delay
                        setTimeout(() => {
                            processQueue();
                        }, 500);
                    } else {
                        // All files uploaded, show success screen
                        setTimeout(() => {
                            showSuccessScreen();
                        }, 500);
                    }
                } else {
                    progressContainer.classList.remove('active');
                    currentXHR = null;
                    currentFileName = null;
                    isUploading = false;

                    let response = {};
                    try { response = JSON.parse(xhr.responseText); } catch (e) {}

                    // Pass missing/expired/exhausted: keep this file and the rest of the queue,
                    // ask for verification, then continue automatically
                    if (['pass_required', 'quota_files', 'quota_bytes'].includes(response.guard) && GUARD.active) {
                        pendingFiles = [file].concat(uploadQueue);
                        uploadQueue = [];
                        lockForVerification(response.guard);
                        return;
                    }
                    if (response.pass) applyPass(response.pass);
                    recordFailure(file.name, GUARD_MESSAGES[response.guard] || response.error || ('Грешка ' + xhr.status));

                    // Continue with next file even on error
                    if (uploadQueue.length > 0) {
                        setTimeout(() => {
                            processQueue();
                        }, 500);
                    } else {
                        showSuccessScreen();
                    }
                }
            });

            // Upload error (network failure or connection closed by the server)
            xhr.addEventListener('error', () => {
                progressContainer.classList.remove('active');
                currentXHR = null;
                currentFileName = null;
                isUploading = false;
                recordFailure(file.name, 'Връзката прекъсна.');

                // Continue with next file
                if (uploadQueue.length > 0) {
                    setTimeout(() => {
                        processQueue();
                    }, 500);
                } else {
                    showSuccessScreen();
                }
            });

            // Upload aborted
            xhr.addEventListener('abort', () => {
                progressContainer.classList.remove('active');
                currentXHR = null;
                currentFileName = null;
                isUploading = false;
            });

            // Send request
            xhr.open('POST', window.location.href, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.send(formData);
        }

        // Stop upload function
        function stopUpload() {
            if (currentXHR) {
                currentXHR.abort();

                // Delete partially uploaded file
                if (currentFileName) {
                    const formData = new FormData();
                    formData.append('delete_partial', currentFileName);

                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    }).then(() => {
                        window.location.reload();
                    });
                }
            }
        }

        // Format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Format speed
        function formatSpeed(bytesPerSecond) {
            return formatBytes(bytesPerSecond) + '/s';
        }

        // Format time (seconds to MM:SS)
        function formatTime(seconds) {
            if (!isFinite(seconds) || seconds < 0) return '--:--';
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            return mins.toString().padStart(2, '0') + ':' + secs.toString().padStart(2, '0');
        }

        // Show success screen
        function showSuccessScreen() {
            // Hide upload form, encryption options and progress
            document.getElementById('dropZone').style.display = 'none';
            document.getElementById('encryptionOptions').style.display = 'none';
            document.getElementById('progressContainer').classList.remove('active');

            // Update title based on file count
            const title = document.getElementById('successTitle');
            if (uploadedFiles.length === 0) {
                title.textContent = 'Нищо не беше качено';
                document.querySelector('.success-icon').textContent = '!';
                document.querySelector('.success-icon').style.background = '#C62828';
                document.getElementById('uploadedFilesList').style.display = 'none';
            } else if (uploadedFiles.length === 1) {
                title.textContent = 'Файлът е качен успешно!';
            } else {
                title.textContent = `${uploadedFiles.length} файла са качени успешно!`;
            }

            const failedEl = document.getElementById('failedFilesList');
            if (failedFiles.length) {
                failedEl.innerHTML = '<b>Не са качени:</b>' + failedFiles.map(f =>
                    `<div>✗ ${escapeHtml(f.name)}: ${escapeHtml(f.error)}</div>`).join('');
                failedEl.style.display = 'block';
            } else {
                failedEl.style.display = 'none';
            }

            // Build file list
            const filesList = document.getElementById('uploadedFilesList');
            filesList.innerHTML = uploadedFiles.map(f => `
                <div class="uploaded-file">
                    <span class="file-icon">${f.encrypted ? '🔒' : '📄'}</span>
                    <span class="file-name">${escapeHtml(f.finalName)}</span>
                    ${f.encrypted ? '<span class="encrypted-badge">криптиран</span>' : ''}
                    ${f.renamed && !f.encrypted ? '<span class="renamed-badge">преименуван</span>' : ''}
                </div>
            `).join('');

            // Show success screen
            document.getElementById('successScreen').classList.add('active');
        }

        // Close window function
        function closeWindow() {
            // Try to close the window/tab
            window.close();
            // If window.close() doesn't work (not opened by script), show message
            setTimeout(() => {
                document.getElementById('successTitle').textContent = 'Можете да затворите този прозорец';
                document.querySelector('.success-buttons').innerHTML = `
                    <button class="btn" onclick="window.location.reload()">📤 Качи още файлове</button>
                `;
            }, 100);
        }

        // Escape HTML helper
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
