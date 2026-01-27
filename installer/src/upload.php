<?php
// Upload-Only Interface
// =====================
// This page allows file uploads without showing existing files

// GeoIP check - block uploads from non-allowed countries
require_once __DIR__ . '/geo-check.php';
checkGeoAccess();

// Include user management for file ownership tracking
require_once __DIR__ . '/user-management.php';

// Include audit log
require_once __DIR__ . '/audit-log.php';

// Include encryption
require_once __DIR__ . '/encryption.php';

// Determine target folder (user or public)
$targetUser = $_GET['user'] ?? null;
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

// Load config for speedtest link
$config = [];
$configFile = __DIR__ . '/.config.json';
if (file_exists($configFile)) {
    $config = json_decode(file_get_contents($configFile), true) ?: [];
}
$speedtestUrl = $config['speedtest_url'] ?? '';

// Generate unique filename if file already exists
function getUniqueFilename($directory, $filename) {
    if (!file_exists($directory . $filename)) {
        return $filename;
    }

    $info = pathinfo($filename);
    $name = $info['filename'];
    $ext = isset($info['extension']) ? '.' . $info['extension'] : '';

    $counter = 1;
    while (file_exists($directory . $name . '_' . $counter . $ext)) {
        $counter++;
    }

    return $name . '_' . $counter . $ext;
}

// Handle partial file deletion (from Stop button)
if (isset($_POST['delete_partial'])) {
    $filename = basename($_POST['delete_partial']);
    $filePath = $uploadDir . $filename;
    if (file_exists($filePath)) {
        unlink($filePath);
    }
    exit;
}

// Check if this is an AJAX request
$isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
          strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] === UPLOAD_ERR_OK) {
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
                    storeEncryptionPassword($finalFilename, $encryptPassword, $uploaderName);
                }
                // If encryption fails, keep the original unencrypted file
            }

            // Record file ownership
            $uploaderName = $targetFolder === '_public' ? 'public' : $targetFolder;
            recordFileUpload($finalFilename, $uploaderName, $targetFolder);

            // Audit log
            $folderDisplay = $targetFolder === '_public' ? 'Public' : $targetFolder;
            $encryptedNote = $wasEncrypted ? ' (encrypted)' : '';
            writeAuditLog('public_upload', "File: $finalFilename (" . formatBytes(filesize($targetPath)) . ")$encryptedNote to folder: $folderDisplay", 'public');

            if ($isAjax) {
                // Return JSON for AJAX requests
                header('Content-Type: application/json');
                echo json_encode([
                    'success' => true,
                    'originalName' => $originalFilename,
                    'finalName' => $finalFilename,
                    'renamed' => $finalFilename !== $originalFilename,
                    'encrypted' => $wasEncrypted
                ]);
                exit;
            }

            if ($finalFilename !== $originalFilename) {
                $success = "File uploaded as: $finalFilename (original name was taken)";
            } else {
                $success = "File uploaded successfully: $finalFilename";
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
            $error = "Failed to upload file.";
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
$pageTitle = $targetFolder === '_public' ? 'Public Upload' : "Upload to {$targetFolder}";
$pageSubtitle = $targetFolder === '_public' ? 'Upload files to the public folder' : "Upload files directly to {$targetFolder}'s folder";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?> - WebShare</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link rel="apple-touch-icon" href="apple-touch-icon.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            border-color: #667eea;
            background: #f0f4ff;
            transform: translateY(-2px);
        }
        .upload-section.drag-over {
            border-color: #667eea;
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
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
            background: #f44336;
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
            background: #da190b;
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
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
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
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
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
            color: #667eea;
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
            accent-color: #667eea;
        }
        .collapse-btn {
            background: none;
            border: none;
            cursor: pointer;
            padding: 5px 10px;
            font-size: 14px;
            color: #667eea;
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
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        .encryption-fields input[type="password"].error {
            border-color: #dc3545;
            background: #fff5f5;
            box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.2);
        }
        .encryption-fields input[type="password"].valid {
            border-color: #28a745;
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
        .encryption-warning {
            font-size: 13px;
            color: #856404;
            background: #fff3cd;
            padding: 10px 15px;
            border-radius: 8px;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank">🚀 Speed Test</a>
    <?php endif; ?>

    <div class="container">
        <h1>📤 <?= htmlspecialchars($pageTitle) ?></h1>
        <p class="subtitle"><?= htmlspecialchars($pageSubtitle) ?></p>

        <?php if (isset($success)): ?>
            <div class="alert alert-success">✓ <?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-error">✗ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="upload-section" id="dropZone">
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <div onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">📁</div>
                    <h3>Click or drag file here</h3>
                    <p class="upload-info">Maximum file size: <?= formatBytes($maxFileSize) ?></p>
                </div>
                <input type="file" name="file" id="fileInput" multiple>
                <button type="button" class="btn" onclick="document.getElementById('fileInput').click()">
                    Choose File
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
                    <span class="stat-label">Speed</span>
                    <span id="uploadSpeed">0 KB/s</span>
                </div>
                <div>
                    <span class="stat-label">Uploaded</span>
                    <span id="uploadedSize">0 MB / 0 MB</span>
                </div>
                <div>
                    <span class="stat-label">Time remaining</span>
                    <span id="timeRemaining">--:--</span>
                </div>
            </div>
            <div style="text-align: center;">
                <button class="btn-stop" id="stopButton" onclick="stopUpload()">Stop Upload</button>
            </div>
        </div>

        <!-- Success Screen -->
        <div class="success-screen" id="successScreen">
            <div class="success-icon">✓</div>
            <h2 class="success-title" id="successTitle">Файловете са качени успешно!</h2>
            <div class="uploaded-files" id="uploadedFilesList">
                <!-- Files will be inserted here by JavaScript -->
            </div>
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

            encryptionPassword = encResult.password; // Store for upload queue
            uploadQueue = Array.from(files);
            totalFiles = uploadQueue.length;
            currentFileIndex = 0;
            uploadedFiles = []; // Reset uploaded files list
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

                    // Continue with next file even on error
                    if (uploadQueue.length > 0) {
                        setTimeout(() => {
                            processQueue();
                        }, 500);
                    } else if (uploadedFiles.length > 0) {
                        // Some files uploaded, show success screen
                        showSuccessScreen();
                    }
                }
            });

            // Upload error
            xhr.addEventListener('error', () => {
                progressContainer.classList.remove('active');
                currentXHR = null;
                currentFileName = null;
                isUploading = false;

                // Continue with next file
                if (uploadQueue.length > 0) {
                    setTimeout(() => {
                        processQueue();
                    }, 500);
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
            if (uploadedFiles.length === 1) {
                title.textContent = 'Файлът е качен успешно!';
            } else {
                title.textContent = `${uploadedFiles.length} файла са качени успешно!`;
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
