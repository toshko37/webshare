<?php
// Webshare - Simple File Sharing Interface
// =========================================

define('WEBSHARE_VERSION', '3.5.1');

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Dynamic base URL for installation scripts
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'your-server.com');

// Start session for login tracking
session_start();

// CSRF Protection - generate token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF validation function
function validateCsrf() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return true;
    }
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

$maxFileSize = 10 * 1024 * 1024 * 1024; // 10GB in bytes

// Include geo functions
require_once __DIR__ . '/geo-check.php';

// Include user management (includes folder-management.php)
require_once __DIR__ . '/user-management.php';

// Include audit log system
require_once __DIR__ . '/audit-log.php';

// Include encryption system
require_once __DIR__ . '/encryption.php';

// Get current user
$currentUser = getCurrentUser();
$isAdmin = ($currentUser === 'admin');

// Get available folders for this user
$userFolders = getUserFolders($currentUser);

// Get current folder path from query param (supports subfolders like "admin/Projects/2024")
$currentFolder = $_GET['folder'] ?? $currentUser;

// Sanitize folder path (secure path traversal prevention)
$currentFolder = secureFolderPath($currentFolder);

// Validate folder access
if (!canAccessFolderPath($currentUser, $currentFolder)) {
    $currentFolder = $currentUser; // Fallback to own folder
}

// Parse folder path for breadcrumb and base folder detection
$folderInfo = parseFolderPath($currentFolder);
$baseFolder = $folderInfo['base'];
$breadcrumb = buildBreadcrumb($currentFolder);

// Set upload directory based on current folder
$uploadDir = getFullFolderPath($currentFolder);

// Ensure folder exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Get folder contents (files + subfolders)
$folderContents = getFolderContents($currentFolder, $currentUser);
$subfolders = $folderContents['subfolders'];

// Check if we can create subfolders (depth limit)
$canCreateSubfolder = (getFolderDepth($currentFolder) < MAX_SUBFOLDER_DEPTH);

// Get all subfolders for the current user's base folder (for move modal)
$allUserSubfolders = getAllSubfoldersRecursive($baseFolder, $currentUser);

// Log login once per session and regenerate session ID (prevent session fixation)
if (!isset($_SESSION['login_logged']) || $_SESSION['login_logged'] !== $currentUser) {
    // Regenerate session ID to prevent session fixation attacks
    session_regenerate_id(true);
    writeAuditLog('login', "User logged in");
    $_SESSION['login_logged'] = $currentUser;
}

// Load general config
$siteConfigFile = __DIR__ . '/.config.json';
$siteConfig = file_exists($siteConfigFile) ? json_decode(file_get_contents($siteConfigFile), true) ?: [] : [];

// CSRF validation for all POST requests (except file uploads which use JavaScript)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_FILES['file']) && !validateCsrf()) {
    http_response_code(403);
    die('CSRF validation failed. Please refresh the page and try again.');
}

// Handle speedtest URL save (admin only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_speedtest']) && $isAdmin) {
    $siteConfig['speedtest_url'] = trim($_POST['speedtest_url'] ?? '');
    file_put_contents($siteConfigFile, json_encode($siteConfig, JSON_PRETTY_PRINT));
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// Handle geo settings save (admin only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_geo']) && $isAdmin) {
    $config = loadGeoConfig();
    $config['enabled'] = isset($_POST['geo_enabled']);
    $countries = array_map('trim', explode(',', $_POST['geo_countries'] ?? 'BG'));
    $countries = array_filter($countries, fn($c) => preg_match('/^[A-Z]{2}$/', $c));
    $config['allowed_countries'] = array_values($countries);
    $config['blocked_message'] = $_POST['geo_message'] ?? 'Access denied from your location';
    saveGeoConfig($config);
    // Audit log
    writeAuditLog('settings', "GeoIP settings updated: " . ($config['enabled'] ? 'enabled' : 'disabled') . ", countries: " . implode(',', $config['allowed_countries']));
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// Handle mail settings save (admin only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_mail']) && $isAdmin) {
    $mailEnabled = isset($_POST['mail_enabled']);

    if ($mailEnabled) {
        // Keep existing password if new one is empty (security: password not shown in form)
        $newPassword = $_POST['smtp_pass'] ?? '';
        $existingPassword = $siteConfig['mail']['smtp_pass'] ?? '';
        $passwordToSave = !empty($newPassword) ? $newPassword : $existingPassword;

        $siteConfig['mail'] = [
            'enabled' => true,
            'smtp_host' => trim($_POST['smtp_host'] ?? ''),
            'smtp_port' => (int)($_POST['smtp_port'] ?? 465),
            'smtp_user' => trim($_POST['smtp_user'] ?? ''),
            'smtp_pass' => $passwordToSave,
            'smtp_encryption' => $_POST['smtp_encryption'] ?? 'ssl',
            'from_name' => trim($_POST['from_name'] ?? 'WebShare')
        ];
    } else {
        $siteConfig['mail'] = ['enabled' => false];
    }

    file_put_contents($siteConfigFile, json_encode($siteConfig, JSON_PRETTY_PRINT));
    writeAuditLog('settings', "Mail settings updated: " . ($mailEnabled ? 'enabled' : 'disabled'));
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// Handle user management actions
$userMessage = null;
$userError = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_action']) && $isAdmin) {
    switch ($_POST['user_action']) {
        case 'add':
            $result = addUser($_POST['new_username'] ?? '', $_POST['new_password'] ?? '');
            if ($result['success']) {
                writeAuditLog('user_add', "Added user: " . $_POST['new_username']);
                $userMessage = 'User added successfully';
            } else {
                $userError = $result['error'];
            }
            break;

        case 'change_password':
            $result = changePassword($_POST['change_username'] ?? '', $_POST['change_password'] ?? '');
            if ($result['success']) {
                writeAuditLog('user_password', "Password changed for: " . $_POST['change_username']);
                $userMessage = 'Password changed successfully';
            } else {
                $userError = $result['error'];
            }
            break;

        case 'delete':
            $result = deleteUser($_POST['delete_username'] ?? '');
            if ($result['success']) {
                writeAuditLog('user_delete', "Deleted user: " . $_POST['delete_username']);
                $userMessage = 'User deleted successfully';
            } else {
                $userError = $result['error'];
            }
            break;
    }
}

// Load geo config for display
$geoConfig = loadGeoConfig();

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

// Handle partial file deletion (from Stop button)
if (isset($_POST['delete_partial'])) {
    $filename = basename($_POST['delete_partial']);
    $filePath = $uploadDir . $filename;
    if (file_exists($filePath)) {
        unlink($filePath);
    }
    exit;
}

// Handle audit log AJAX requests (admin only)
if (isset($_GET['audit_action']) && $isAdmin) {
    header('Content-Type: application/json');

    $action = $_GET['audit_action'];

    if ($action === 'fetch') {
        $page = max(1, intval($_GET['page'] ?? 1));
        $perPage = min(100, max(10, intval($_GET['per_page'] ?? 25)));
        $offset = ($page - 1) * $perPage;

        $filters = [
            'user' => $_GET['filter_user'] ?? '',
            'action' => $_GET['filter_action'] ?? '',
            'ip' => $_GET['filter_ip'] ?? '',
            'country' => $_GET['filter_country'] ?? '',
            'search' => $_GET['filter_search'] ?? '',
            'date_from' => $_GET['filter_date_from'] ?? '',
            'date_to' => $_GET['filter_date_to'] ?? ''
        ];

        $result = readAuditLog($perPage, $offset, $filters);

        echo json_encode([
            'success' => true,
            'entries' => $result['entries'],
            'total' => $result['total'],
            'filtered' => $result['filtered'],
            'page' => $page,
            'per_page' => $perPage,
            'total_pages' => ceil($result['filtered'] / $perPage)
        ]);
        exit;
    }

    if ($action === 'options') {
        $options = getAuditFilterOptions();
        echo json_encode([
            'success' => true,
            'options' => $options
        ]);
        exit;
    }

    if ($action === 'export') {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="audit-log-' . date('Y-m-d') . '.csv"');
        echo exportAuditLogCSV();
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Invalid action']);
    exit;
}

// Handle update source preference (AJAX)
if (isset($_GET['action']) && $_GET['action'] === 'get_update_source') {
    header('Content-Type: application/json');
    $configFile = __DIR__ . '/.update-config.json';
    $config = ['stable' => true];
    if (file_exists($configFile)) {
        $data = json_decode(file_get_contents($configFile), true);
        if (isset($data['stable'])) {
            $config['stable'] = (bool)$data['stable'];
        }
    }
    echo json_encode($config);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'set_update_source') {
    header('Content-Type: application/json');
    validateCsrfToken();

    $useBeta = isset($_POST['use_beta']) && $_POST['use_beta'] === '1';
    $configFile = __DIR__ . '/.update-config.json';
    $config = ['stable' => !$useBeta];

    if (file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT))) {
        // Clear version cache to force re-check with new source
        $cacheFile = __DIR__ . '/.version-check.json';
        if (file_exists($cacheFile)) {
            unlink($cacheFile);
        }
        echo json_encode(['success' => true, 'stable' => $config['stable']]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to save config']);
    }
    exit;
}

// Handle API key actions (AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['api_action'])) {
    header('Content-Type: application/json');
    $currentUser = getCurrentUser();
    $action = $_POST['api_action'];

    if (!validateCsrf()) {
        echo json_encode(['success' => false, 'error' => 'CSRF validation failed']);
        exit;
    }

    if ($action === 'generate') {
        $name = trim($_POST['key_name'] ?? '');
        $ipsRaw = trim($_POST['allowed_ips'] ?? '');

        // Parse IPs (comma or newline separated)
        $allowedIps = null;
        if (!empty($ipsRaw)) {
            $allowedIps = array_filter(array_map('trim', preg_split('/[,\n]+/', $ipsRaw)));
            // Validate each IP/CIDR
            foreach ($allowedIps as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('#^[\d.]+/\d+$#', $ip) && !preg_match('#^[a-f\d:]+/\d+$#i', $ip)) {
                    echo json_encode(['success' => false, 'error' => "Invalid IP/CIDR: $ip"]);
                    exit;
                }
            }
            $allowedIps = array_values($allowedIps);
        }

        $result = generateApiKey($currentUser, $name ?: null, $allowedIps ?: null);
        writeAuditLog('api_key_generate', "Generated API key: {$result['id']}" . ($allowedIps ? " (IP restricted)" : ""), $currentUser);
        echo json_encode(['success' => true, 'key_id' => $result['id'], 'key' => $result['key']]);
        exit;

    } elseif ($action === 'revoke') {
        $keyId = $_POST['key_id'] ?? null;
        if ($keyId && revokeApiKey($currentUser, $keyId)) {
            writeAuditLog('api_key_revoke', "Revoked API key: $keyId", $currentUser);
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Key not found']);
        }
        exit;

    } elseif ($action === 'update_ips') {
        $keyId = $_POST['key_id'] ?? null;
        $ipsRaw = trim($_POST['allowed_ips'] ?? '');

        $allowedIps = null;
        if (!empty($ipsRaw)) {
            $allowedIps = array_filter(array_map('trim', preg_split('/[,\n]+/', $ipsRaw)));
            foreach ($allowedIps as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('#^[\d.]+/\d+$#', $ip) && !preg_match('#^[a-f\d:]+/\d+$#i', $ip)) {
                    echo json_encode(['success' => false, 'error' => "Invalid IP/CIDR: $ip"]);
                    exit;
                }
            }
            $allowedIps = array_values($allowedIps);
        }

        if ($keyId && updateApiKeyIps($currentUser, $keyId, $allowedIps ?: null)) {
            writeAuditLog('api_key_update', "Updated IP restrictions for key: $keyId", $currentUser);
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Key not found']);
        }
        exit;

    } elseif ($action === 'list') {
        $keys = getUserApiKeys($currentUser);
        echo json_encode(['success' => true, 'keys' => $keys]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unknown action']);
    exit;
}

// Handle file encryption/decryption AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['crypt_action'])) {
    header('Content-Type: application/json');

    $action = $_POST['crypt_action'];
    $filename = basename($_POST['filename'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($filename) || empty($password)) {
        echo json_encode(['success' => false, 'error' => 'Missing filename or password']);
        exit;
    }

    $filePath = $uploadDir . $filename;

    if (!file_exists($filePath)) {
        echo json_encode(['success' => false, 'error' => 'File not found']);
        exit;
    }

    if ($action === 'encrypt') {
        // Check if already encrypted
        if (isEncryptedFile($filename)) {
            echo json_encode(['success' => false, 'error' => 'File is already encrypted']);
            exit;
        }

        // Encrypt the file
        $encryptedPath = $filePath . ENCRYPTED_EXTENSION;
        $result = encryptFile($filePath, $encryptedPath, $password);

        if ($result['success']) {
            // Delete original file
            unlink($filePath);

            // Update file metadata
            $newFilename = $filename . ENCRYPTED_EXTENSION;
            renameFileMeta($filename, $newFilename);

            // Store encryption password
            storeEncryptionPassword($newFilename, $password, $currentUser);

            // Audit log
            writeAuditLog('encrypt', "Encrypted file: $filename -> $newFilename in folder: $currentFolder");

            echo json_encode([
                'success' => true,
                'message' => 'File encrypted successfully',
                'newFilename' => $newFilename
            ]);
        } else {
            echo json_encode(['success' => false, 'error' => $result['error']]);
        }
        exit;
    }

    if ($action === 'decrypt') {
        // Check if file is encrypted
        if (!isEncryptedFile($filename)) {
            echo json_encode(['success' => false, 'error' => 'File is not encrypted']);
            exit;
        }

        // Decrypt the file
        $result = decryptFile($filePath, $password);

        if ($result['success']) {
            // Write decrypted content to new file
            $newFilename = getOriginalFilename($filename);
            $newPath = $uploadDir . $newFilename;

            // Check if file already exists
            if (file_exists($newPath)) {
                $newFilename = getUniqueFilename($uploadDir, $newFilename);
                $newPath = $uploadDir . $newFilename;
            }

            if (file_put_contents($newPath, $result['data']) !== false) {
                // Delete encrypted file
                unlink($filePath);

                // Update file metadata
                renameFileMeta($filename, $newFilename);

                // Remove encryption key
                removeEncryptionKey($filename);

                // Audit log
                writeAuditLog('decrypt', "Decrypted file: $filename -> $newFilename in folder: $currentFolder");

                echo json_encode([
                    'success' => true,
                    'message' => 'File decrypted successfully',
                    'newFilename' => $newFilename
                ]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to write decrypted file']);
            }
        } else {
            echo json_encode(['success' => false, 'error' => $result['error']]);
        }
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Invalid action']);
    exit;
}

// Dangerous file extensions that should never be uploaded
$dangerousExtensions = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'htaccess', 'htpasswd'];

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] === UPLOAD_ERR_OK) {
        $originalFilename = basename($file['name']);

        // Security: Check for dangerous file extensions
        $extension = strtolower(pathinfo($originalFilename, PATHINFO_EXTENSION));
        if (in_array($extension, $dangerousExtensions)) {
            $error = "File type not allowed for security reasons: .$extension";
        }

        // Security: Check for double extensions (e.g., file.php.jpg)
        if (!isset($error)) {
            $nameParts = explode('.', $originalFilename);
            if (count($nameParts) > 2) {
                foreach ($nameParts as $part) {
                    if (in_array(strtolower($part), $dangerousExtensions)) {
                        $error = "File contains dangerous extension in name: $part";
                        break;
                    }
                }
            }
        }

        if (!isset($error)) {
            $filename = getUniqueFilename($uploadDir, $originalFilename);
            $targetPath = $uploadDir . $filename;

            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $finalFilename = $filename;
                $wasEncrypted = false;

                // Check if encryption was requested
                $encryptPassword = $_POST['encrypt_password'] ?? '';
                if (!empty($encryptPassword)) {
                    // Encrypt the file
                    $encryptResult = encryptFile($targetPath, $targetPath, $encryptPassword);

                    if ($encryptResult['success']) {
                        // Delete original unencrypted file
                        unlink($targetPath);

                        $finalFilename = $encryptResult['encrypted_filename'];
                        $wasEncrypted = true;

                        // Store password for recovery
                        storeEncryptionPassword($finalFilename, $encryptPassword, $currentUser);
                    } else {
                        // Encryption failed, delete the uploaded file
                        unlink($targetPath);
                        $error = "Encryption failed: " . $encryptResult['error'];
                    }
                }

                if (!isset($error)) {
                    // Record file ownership with folder
                    recordFileUpload($finalFilename, $currentUser, $currentFolder);
                    // Audit log
                    $folderDisplay = $currentFolder === '_public' ? 'Public' : $currentFolder;
                    $encryptedNote = $wasEncrypted ? ' [ENCRYPTED]' : '';
                    $filePath = $uploadDir . $finalFilename;
                    writeAuditLog('upload', "File: $finalFilename (" . formatBytes(filesize($filePath)) . ") in folder: $folderDisplay" . $encryptedNote);

                    if ($wasEncrypted) {
                        $success = "File uploaded and encrypted: $finalFilename";
                    } elseif ($finalFilename !== $originalFilename) {
                        $success = "File uploaded as: $finalFilename (original name was taken)";
                    } else {
                        $success = "File uploaded successfully: $finalFilename";
                    }
                }
            } else {
                $error = "Failed to upload file.";
            }
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
        $error = $errorMessages[$file['error']] ?? 'Unknown upload error';
    }
}

// Handle file renaming (AJAX)
if (isset($_POST['rename']) && isset($_POST['old_name']) && isset($_POST['new_name'])) {
    $oldName = basename($_POST['old_name']);
    $newName = basename($_POST['new_name']);
    $oldPath = $uploadDir . $oldName;
    $newPath = $uploadDir . $newName;

    header('Content-Type: application/json');

    if (!file_exists($oldPath)) {
        echo json_encode(['success' => false, 'error' => 'File not found']);
        exit;
    }

    if (file_exists($newPath)) {
        echo json_encode(['success' => false, 'error' => 'A file with this name already exists']);
        exit;
    }

    if (rename($oldPath, $newPath)) {
        // Update share tokens
        $tokensFile = __DIR__ . '/.tokens.json';
        if (file_exists($tokensFile)) {
            $tokens = json_decode(file_get_contents($tokensFile), true) ?? [];
            foreach ($tokens as $token => &$filename) {
                if ($filename === $oldName) {
                    $filename = $newName;
                }
            }
            file_put_contents($tokensFile, json_encode($tokens, JSON_PRETTY_PRINT));
        }

        // Update file ownership metadata
        renameFileMeta($oldName, $newName);

        // Audit log
        writeAuditLog('rename', "Renamed: $oldName -> $newName");

        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to rename file']);
    }
    exit;
}

// Handle file deletion (AJAX)
if (isset($_POST['delete'])) {
    $filename = basename($_POST['delete']);
    $filePath = $uploadDir . $filename;

    header('Content-Type: application/json');

    if (file_exists($filePath) && is_file($filePath)) {
        if (unlink($filePath)) {
            // Also remove from share tokens
            $tokensFile = __DIR__ . '/.tokens.json';
            if (file_exists($tokensFile)) {
                $tokens = json_decode(file_get_contents($tokensFile), true) ?? [];
                $tokens = array_filter($tokens, function($data) use ($filename, $currentFolder) {
                    // Handle both old format (string) and new format (array)
                    if (is_array($data)) {
                        return $data['filename'] !== $filename;
                    }
                    return $data !== $filename;
                });
                file_put_contents($tokensFile, json_encode($tokens, JSON_PRETTY_PRINT));
            }
            // Remove file ownership metadata (try both old and new key formats)
            removeFileMeta($filename);
            removeFileMeta($currentFolder . '/' . $filename);
            // Audit log
            $folderDisplay = $currentFolder === '_public' ? 'Public' : $currentFolder;
            writeAuditLog('delete', "Deleted file: $filename from folder: $folderDisplay");
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to delete file']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'File not found']);
    }
    exit;
}

// Handle file move between folders (AJAX) - supports subfolders
if (isset($_POST['move_file']) && isset($_POST['to_folder'])) {
    $filename = basename($_POST['move_file']);
    $toFolder = $_POST['to_folder'];

    // Sanitize destination folder path (secure path traversal prevention)
    $toFolder = secureFolderPath($toFolder);

    header('Content-Type: application/json');

    // Validate access to destination folder (supports subfolders)
    if (!canAccessFolderPath($currentUser, $toFolder)) {
        echo json_encode(['success' => false, 'error' => 'Access denied to destination folder']);
        exit;
    }

    // Perform the move (supports subfolders)
    $result = moveFileToPath($filename, $currentFolder, $toFolder, $currentUser);

    if ($result['success']) {
        // Update share tokens if the file had one
        $tokensFile = __DIR__ . '/.tokens.json';
        if (file_exists($tokensFile)) {
            $tokens = json_decode(file_get_contents($tokensFile), true) ?? [];
            foreach ($tokens as $token => &$data) {
                if (is_array($data) && $data['filename'] === $filename) {
                    $data['filename'] = $result['newFilename'];
                    $data['folder'] = $toFolder;
                } elseif ($data === $filename) {
                    // Convert old format to new
                    $tokens[$token] = [
                        'filename' => $result['newFilename'],
                        'folder' => $toFolder,
                        'created' => time()
                    ];
                }
            }
            file_put_contents($tokensFile, json_encode($tokens, JSON_PRETTY_PRINT));
        }

        // Audit log
        $fromDisplay = $currentFolder === '_public' ? 'Public' : $currentFolder;
        $toDisplay = $toFolder === '_public' ? 'Public' : $toFolder;
        writeAuditLog('move', "Moved file: $filename from $fromDisplay to $toDisplay");

        echo json_encode($result);
    } else {
        echo json_encode($result);
    }
    exit;
}

// Handle subfolder creation (AJAX)
if (isset($_POST['create_subfolder']) && isset($_POST['folder_name'])) {
    $folderName = trim($_POST['folder_name']);

    header('Content-Type: application/json');

    $result = createSubfolder($currentFolder, $folderName, $currentUser);

    if ($result['success']) {
        writeAuditLog('folder_create', "Created subfolder: {$result['path']}");
    }

    echo json_encode($result);
    exit;
}

// Handle subfolder deletion (AJAX)
if (isset($_POST['delete_subfolder'])) {
    $subfolderPath = $_POST['delete_subfolder'];

    header('Content-Type: application/json');

    // Security: validate the path is within user's access
    if (!canAccessFolderPath($currentUser, $subfolderPath)) {
        echo json_encode(['success' => false, 'error' => 'Access denied']);
        exit;
    }

    $result = deleteSubfolder($subfolderPath, $currentUser);

    if ($result['success']) {
        writeAuditLog('folder_delete', "Deleted subfolder: $subfolderPath");
    }

    echo json_encode($result);
    exit;
}

// Folder share file
define('FOLDER_SHARES_FILE', __DIR__ . '/.folder-shares.json');

function loadFolderShares() {
    if (file_exists(FOLDER_SHARES_FILE)) {
        return json_decode(file_get_contents(FOLDER_SHARES_FILE), true) ?: [];
    }
    return [];
}

function saveFolderShares($shares) {
    file_put_contents(FOLDER_SHARES_FILE, json_encode($shares, JSON_PRETTY_PRINT));
}

// Handle folder share creation
if (isset($_POST['create_folder_share'])) {
    header('Content-Type: application/json');

    $folderPath = $_POST['folder_path'] ?? '';
    $password = $_POST['share_password'] ?? '';
    $allowUpload = isset($_POST['allow_upload']) && $_POST['allow_upload'] === '1';
    $allowDelete = isset($_POST['allow_delete']) && $_POST['allow_delete'] === '1';

    // Security: validate folder access
    if (!canAccessFolderPath($currentUser, $folderPath)) {
        echo json_encode(['success' => false, 'error' => 'Access denied']);
        exit;
    }

    // Check folder exists
    $fullPath = __DIR__ . '/files/' . $folderPath;
    if (!is_dir($fullPath)) {
        echo json_encode(['success' => false, 'error' => 'Folder not found']);
        exit;
    }

    // Generate token
    $token = bin2hex(random_bytes(16));
    $shares = loadFolderShares();

    // Check if folder already shared
    foreach ($shares as $existingToken => $share) {
        if ($share['folder'] === $folderPath) {
            // Update existing share
            $shares[$existingToken]['password'] = $password ? password_hash($password, PASSWORD_DEFAULT) : null;
            $shares[$existingToken]['allow_upload'] = $allowUpload;
            $shares[$existingToken]['allow_delete'] = $allowDelete;
            saveFolderShares($shares);

            writeAuditLog('folder_share_update', "Updated folder share: $folderPath");

            echo json_encode([
                'success' => true,
                'token' => $existingToken,
                'url' => 'https://' . $_SERVER['HTTP_HOST'] . '/f/' . $existingToken,
                'updated' => true
            ]);
            exit;
        }
    }

    // Create new share
    $shares[$token] = [
        'folder' => $folderPath,
        'password' => $password ? password_hash($password, PASSWORD_DEFAULT) : null,
        'allow_upload' => $allowUpload,
        'allow_delete' => $allowDelete,
        'created' => time(),
        'created_by' => $currentUser,
        'expires' => null,
        'views' => 0
    ];

    saveFolderShares($shares);
    writeAuditLog('folder_share_create', "Created folder share: $folderPath -> $token");

    echo json_encode([
        'success' => true,
        'token' => $token,
        'url' => 'https://' . $_SERVER['HTTP_HOST'] . '/f/' . $token
    ]);
    exit;
}

// Handle folder share deletion
if (isset($_POST['delete_folder_share'])) {
    header('Content-Type: application/json');

    $token = $_POST['delete_folder_share'];
    $shares = loadFolderShares();

    if (!isset($shares[$token])) {
        echo json_encode(['success' => false, 'error' => 'Share not found']);
        exit;
    }

    // Security: only owner or admin can delete
    if ($shares[$token]['created_by'] !== $currentUser && !$isAdmin) {
        echo json_encode(['success' => false, 'error' => 'Access denied']);
        exit;
    }

    $folderPath = $shares[$token]['folder'];
    unset($shares[$token]);
    saveFolderShares($shares);

    writeAuditLog('folder_share_delete', "Deleted folder share: $folderPath");

    echo json_encode(['success' => true]);
    exit;
}

// Handle folder share token regeneration
if (isset($_POST['regenerate_folder_token'])) {
    header('Content-Type: application/json');

    $oldToken = $_POST['regenerate_folder_token'];
    $shares = loadFolderShares();

    if (!isset($shares[$oldToken])) {
        echo json_encode(['success' => false, 'error' => 'Share not found']);
        exit;
    }

    // Security: only owner or admin can regenerate
    if ($shares[$oldToken]['created_by'] !== $currentUser && !$isAdmin) {
        echo json_encode(['success' => false, 'error' => 'Access denied']);
        exit;
    }

    // Generate new token
    $newToken = bin2hex(random_bytes(16));
    $shares[$newToken] = $shares[$oldToken];
    unset($shares[$oldToken]);
    saveFolderShares($shares);

    writeAuditLog('folder_share_regenerate', "Regenerated folder token: $oldToken -> $newToken");

    echo json_encode([
        'success' => true,
        'new_token' => $newToken,
        'new_url' => 'https://' . $_SERVER['HTTP_HOST'] . '/f/' . $newToken
    ]);
    exit;
}

// Sync file metadata with actual files on disk (once per page load)
// This handles files added/deleted manually outside the application
syncFilesMeta();

// Get list of files
$files = [];
$filesMeta = loadFilesMeta();
if (is_dir($uploadDir)) {
    $items = scandir($uploadDir);
    foreach ($items as $item) {
        // Skip hidden files (starting with .), current dir, and parent dir
        if ($item !== '.' && $item !== '..' && substr($item, 0, 1) !== '.') {
            $filePath = $uploadDir . $item;
            if (is_file($filePath)) {
                $files[] = [
                    'name' => $item,
                    'size' => filesize($filePath),
                    'date' => filemtime($filePath),
                    'owner' => $filesMeta[$item]['uploader'] ?? '-',
                ];
            }
        }
    }
}

// Sort by date (newest first)
usort($files, function($a, $b) {
    return $b['date'] - $a['date'];
});

// Get list of shared texts
$textsMetadataFile = __DIR__ . '/.texts.json';
$textsDir = __DIR__ . '/texts/';

// Cleanup expired texts/conversations
if (file_exists($textsMetadataFile)) {
    $textsData = json_decode(file_get_contents($textsMetadataFile), true) ?? [];
    $now = time();
    $changed = false;
    foreach ($textsData as $token => $info) {
        if ($info['expires'] < $now) {
            // Delete both old .html and new .json formats
            $htmlPath = $textsDir . '.' . $token . '.html';
            $jsonPath = $textsDir . '.' . $token . '.json';
            if (file_exists($htmlPath)) {
                unlink($htmlPath);
            }
            if (file_exists($jsonPath)) {
                unlink($jsonPath);
            }
            unset($textsData[$token]);
            $changed = true;
        }
    }
    if ($changed) {
        file_put_contents($textsMetadataFile, json_encode($textsData, JSON_PRETTY_PRINT));
    }
}

// Load conversations for display
$texts = [];
if (file_exists($textsMetadataFile)) {
    $textsData = json_decode(file_get_contents($textsMetadataFile), true) ?? [];
    foreach ($textsData as $token => $info) {
        $texts[] = [
            'token' => $token,
            'preview' => $info['preview'],
            'size' => $info['size'],
            'created' => $info['created'],
            'expires' => $info['expires'],
            'views' => $info['views'],
            'edit_key' => $info['edit_key'] ?? '',
            'message_count' => $info['message_count'] ?? 1,
            'creator' => $info['creator'] ?? ''
        ];
    }
}

// Sort texts by date (newest first)
usort($texts, function($a, $b) {
    return $b['created'] - $a['created'];
});

// Helper function for file size formatting
function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}

/**
 * Parse CHANGELOG.md and return recent versions
 * @param int $limit Number of versions to return
 * @return array Array of ['version' => '3.1.3', 'highlights' => 'Feature description']
 */
function getRecentChanges($limit = 8) {
    $changelogFile = __DIR__ . '/CHANGELOG.md';
    if (!file_exists($changelogFile)) {
        return [];
    }

    $content = file_get_contents($changelogFile);
    $changes = [];

    // Match version headers: ## [3.1.3] - 2026-01-27
    preg_match_all('/^## \[([^\]]+)\] - [\d-]+\s*\n(.*?)(?=^## \[|^---|\z)/ms', $content, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        if (count($changes) >= $limit) break;

        $version = $match[1];
        $body = $match[2];

        // Extract highlights from ### Added or first bullet points
        $highlights = [];

        // Look for **bold** items which are feature names
        preg_match_all('/\*\*([^*]+)\*\*/', $body, $boldMatches);
        if (!empty($boldMatches[1])) {
            $highlights = array_slice($boldMatches[1], 0, 3);
        }

        // If no bold items, get first few list items (truncated)
        if (empty($highlights)) {
            preg_match_all('/^- (.+)$/m', $body, $listMatches);
            if (!empty($listMatches[1])) {
                $items = array_map(function($item) {
                    // Get first part before parentheses for cleaner display
                    if (preg_match('/^([^(]+)/', $item, $m)) {
                        return trim($m[1]);
                    }
                    return mb_substr($item, 0, 50);
                }, array_slice($listMatches[1], 0, 2));
                $highlights = $items;
            }
        }

        $changes[] = [
            'version' => $version,
            'highlights' => implode(', ', $highlights) ?: 'Various improvements'
        ];
    }

    return $changes;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShare - File Manager</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link rel="apple-touch-icon" href="apple-touch-icon.png">

    <!-- Quill.js Rich Text Editor -->
    <link href="assets/quill/quill.snow.css" rel="stylesheet">

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
            position: relative;
        }
        .speed-link {
            position: absolute;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
        }
        .speed-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.5);
        }
        .user-header {
            position: absolute;
            top: 20px;
            right: 140px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .current-user {
            color: #666;
            font-size: 14px;
            font-weight: 500;
        }
        .logout-link {
            color: #dc3545;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            padding: 6px 12px;
            border: 1px solid #dc3545;
            border-radius: 4px;
            transition: all 0.3s;
        }
        .logout-link:hover {
            background: #dc3545;
            color: white;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .alert {
            padding: 12px 20px;
            border-radius: 4px;
            margin-bottom: 20px;
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
            border: 2px dashed #ddd;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            background: #fafafa;
            transition: all 0.3s;
        }
        .upload-section:hover {
            border-color: #4CAF50;
            background: #f1f8f4;
        }
        .upload-section.drag-over {
            border-color: #4CAF50;
            background: #e8f5e9;
        }
        .btn {
            background: #4CAF50;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #45a049;
        }
        .btn-danger {
            background: #f44336;
            padding: 6px 12px;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
            margin-left: 5px;
        }
        .btn-danger:hover {
            background: #da190b;
        }
        .btn-share {
            background: #2196F3;
            padding: 6px 12px;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
            cursor: pointer;
            border: none;
            color: white;
            border-radius: 4px;
        }
        .btn-share:hover {
            background: #0b7dda;
        }
        .btn-ext {
            background: #9C27B0;
            padding: 2px 6px;
            font-size: 11px;
            cursor: pointer;
            border: none;
            color: white;
            border-radius: 3px;
            margin-left: 2px;
        }
        .btn-ext:hover {
            background: #7B1FA2;
        }
        .btn-set {
            background: #FF5722;
            padding: 2px 6px;
            font-size: 11px;
            cursor: pointer;
            border: none;
            color: white;
            border-radius: 3px;
            margin-left: 2px;
        }
        .btn-set:hover {
            background: #E64A19;
        }
        .expires-row {
            white-space: nowrap;
        }
        .btn-rename {
            background: #FF9800;
            padding: 6px 12px;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
            cursor: pointer;
            border: none;
            color: white;
            border-radius: 4px;
            margin-left: 5px;
        }
        .btn-rename:hover {
            background: #F57C00;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #e0e0e0;
        }
        .tab {
            padding: 12px 30px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            color: #666;
            transition: all 0.3s;
        }
        .tab:hover {
            color: #4CAF50;
        }
        .tab.active {
            color: #4CAF50;
            border-bottom-color: #4CAF50;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        /* Folder Navigation */
        .folder-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            flex-wrap: wrap;
        }
        .folder-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 10px 18px;
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            text-decoration: none;
            color: #333;
            font-weight: 500;
            transition: all 0.2s;
        }
        .folder-btn:hover {
            border-color: #4CAF50;
            background: #f0fff0;
        }
        .folder-btn.active {
            background: #4CAF50;
            border-color: #4CAF50;
            color: white;
        }
        .folder-btn .badge {
            font-size: 10px;
            background: rgba(0,0,0,0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }
        .folder-btn.active .badge {
            background: rgba(255,255,255,0.3);
        }
        /* Breadcrumb */
        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px 15px;
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 15px;
            font-size: 14px;
        }
        .breadcrumb-sep {
            color: #999;
        }
        .breadcrumb-link {
            color: #2196F3;
            text-decoration: none;
        }
        .breadcrumb-link:hover {
            text-decoration: underline;
        }
        .breadcrumb-current {
            color: #333;
            font-weight: 600;
        }
        .btn-share-current {
            margin-left: auto;
            padding: 5px 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-share-current:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.4);
        }
        /* Subfolders */
        .subfolders-section {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .subfolders-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            font-weight: 600;
            color: #555;
        }
        .subfolders-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .subfolder-item {
            display: flex;
            align-items: center;
            gap: 5px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 8px 12px;
        }
        .subfolder-link {
            color: #333;
            text-decoration: none;
            font-weight: 500;
        }
        .subfolder-link:hover {
            color: #2196F3;
        }
        .subfolder-actions {
            display: flex;
            gap: 5px;
        }
        .btn-delete-folder, .btn-share-folder {
            background: none;
            border: none;
            cursor: pointer;
            opacity: 0.5;
            padding: 2px;
        }
        .btn-delete-folder:hover, .btn-share-folder:hover {
            opacity: 1;
        }
        .shared-badge {
            font-size: 12px;
            margin-left: 5px;
        }
        .btn-small {
            padding: 6px 12px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn-small:hover {
            background: #45a049;
        }
        .no-subfolders {
            color: #999;
            font-size: 13px;
            margin: 0;
        }
        /* Encryption styles */
        .encrypt-option {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
        }
        .encrypt-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .encrypt-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            font-weight: 500;
        }
        .encrypt-checkbox input {
            width: 18px;
            height: 18px;
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
        #encryptPasswordFields {
            margin-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        #encryptPasswordFields.collapsed {
            display: none !important;
        }
        .password-field-wrapper {
            position: relative;
        }
        #encryptPasswordFields input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
            transition: all 0.3s;
        }
        #encryptPasswordFields input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        #encryptPasswordFields input.valid {
            border-color: #28a745;
            background: #f0fff4;
            box-shadow: 0 0 0 3px rgba(40, 167, 69, 0.15);
        }
        #encryptPasswordFields input.invalid {
            border-color: #ffc107;
            background: #fffbeb;
            box-shadow: 0 0 0 3px rgba(255, 193, 7, 0.15);
        }
        #encryptPasswordFields input.error {
            border-color: #dc3545;
            background: #fff5f5;
            box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.2);
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
        .encrypt-warning {
            color: #856404;
            font-size: 12px;
            margin: 0;
            background: #fff3cd;
            padding: 10px;
            border-radius: 6px;
        }
        /* Web Download styles */
        .web-download-section {
            margin-top: 20px;
            text-align: center;
        }
        .web-download-toggle {
            cursor: pointer;
            color: #667eea;
            font-size: 14px;
            padding: 8px;
            transition: all 0.2s;
        }
        .web-download-toggle:hover {
            color: #5a6fd6;
            text-decoration: underline;
        }
        #webDownloadForm {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            text-align: left;
        }
        .web-download-input-group {
            display: flex;
            gap: 10px;
        }
        .web-download-input-group input {
            flex: 1;
            padding: 10px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        .web-download-input-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .web-download-file-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: #e8f5e9;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 14px;
        }
        #webDownloadFileNameInput {
            font-weight: 500;
            color: #2e7d32;
        }
        #webDownloadFileSize {
            color: #666;
            white-space: nowrap;
            margin-left: 10px;
        }
        .web-download-error {
            color: #c62828;
            background: #ffebee;
            padding: 10px;
            border-radius: 6px;
            font-size: 13px;
            margin-top: 10px;
        }
        .web-download-warning {
            color: #856404;
            background: #fff3cd;
            padding: 10px;
            border-radius: 6px;
            font-size: 13px;
            margin-top: 10px;
        }
        #webDownloadInfo {
            margin-top: 15px;
        }
        #webDownloadProgress {
            margin-top: 15px;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        /* Encrypted file indicator */
        .file-encrypted {
            background: #fff3cd !important;
        }
        .file-encrypted .file-name {
            color: #856404;
        }
        .encrypted-badge {
            display: inline-block;
            background: #ffc107;
            color: #333;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            margin-left: 8px;
        }
        .btn-encrypt {
            background: #6c757d;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .btn-encrypt:hover {
            background: #5a6268;
            transform: scale(1.1);
        }
        .btn-decrypt-action {
            background: #28a745;
        }
        .btn-decrypt-action:hover {
            background: #218838;
        }
        /* Move button */
        .btn-move {
            background: #2196F3;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn-move:hover {
            background: #1976D2;
        }
        /* Move modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal.show {
            display: flex;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 12px;
            min-width: 350px;
            max-width: 90%;
        }
        .modal-content h3 {
            margin-bottom: 20px;
        }
        .changelog-version { margin-bottom: 20px; }
        .changelog-version h4 { color: #1976D2; margin-bottom: 10px; border-bottom: 1px solid #e0e0e0; padding-bottom: 5px; }
        .changelog-version ul { margin: 0; padding-left: 20px; }
        .changelog-version li { margin: 5px 0; color: #555; }
        .changelog-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 8px; }
        .badge-added { background: #e8f5e9; color: #2e7d32; }
        .badge-changed { background: #fff3e0; color: #ef6c00; }
        .badge-fixed { background: #fce4ec; color: #c2185b; }
        .folder-option {
            display: block;
            padding: 12px 15px;
            margin: 8px 0;
            background: #f8f9fa;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .folder-option:hover {
            border-color: #4CAF50;
            background: #f0fff0;
        }
        .folder-option.selected {
            border-color: #4CAF50;
            background: #e8f5e9;
        }
        .modal-buttons {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        /* Crypt modal input styles */
        #cryptModal input[type="password"] {
            transition: all 0.3s;
        }
        #cryptModal input[type="password"].valid {
            border-color: #28a745 !important;
            background: #f0fff4 !important;
            box-shadow: 0 0 0 3px rgba(40, 167, 69, 0.15);
        }
        #cryptModal input[type="password"].invalid {
            border-color: #ffc107 !important;
            background: #fffbeb !important;
            box-shadow: 0 0 0 3px rgba(255, 193, 7, 0.15);
        }
        #cryptModal input[type="password"].error {
            border-color: #dc3545 !important;
            background: #fff5f5 !important;
            box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.2);
        }
        /* Settings styles */
        .settings-section {
            background: white;
            border-radius: 8px;
            padding: 20px;
        }
        .settings-section h2 {
            margin-top: 0;
            margin-bottom: 20px;
            color: #333;
        }
        .setting-group {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .setting-group h3 {
            margin-top: 0;
            margin-bottom: 10px;
            color: #333;
        }
        .setting-desc {
            color: #666;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .setting-row {
            margin-bottom: 15px;
        }
        .setting-row label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #333;
        }
        .setting-row input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        .setting-row small {
            display: block;
            margin-top: 5px;
            color: #888;
            font-size: 12px;
        }
        .setting-info {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-size: 14px;
        }
        .toggle {
            display: flex;
            align-items: center;
            cursor: pointer;
            gap: 15px;
        }
        .toggle input {
            display: none;
        }
        .toggle-slider {
            width: 70px;
            height: 32px;
            background: #dc3545;
            border-radius: 16px;
            position: relative;
            transition: 0.3s;
            border: 2px solid #b02a37;
        }
        .toggle-slider:before {
            content: 'OFF';
            position: absolute;
            width: 28px;
            height: 28px;
            background: white;
            border-radius: 50%;
            top: 0;
            left: 0;
            transition: 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 9px;
            font-weight: bold;
            color: #dc3545;
        }
        .toggle input:checked + .toggle-slider {
            background: #28a745;
            border-color: #1e7e34;
        }
        .toggle input:checked + .toggle-slider:before {
            left: 38px;
            content: 'ON';
            color: #28a745;
        }
        .toggle-label {
            font-weight: 600;
            color: #333;
            font-size: 16px;
        }
        .toggle-status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 600;
        }
        .toggle-status.off {
            background: #f8d7da;
            color: #721c24;
        }
        .toggle-status.on {
            background: #d4edda;
            color: #155724;
        }
        /* User Management Styles */
        .users-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        .user-item {
            display: flex;
            align-items: center;
            gap: 8px;
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
        }
        .user-name {
            font-weight: 600;
            color: #333;
        }
        .user-badge {
            background: #4CAF50;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
        }
        .btn-user-delete {
            background: #dc3545;
            color: white;
            border: none;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 12px;
            line-height: 1;
        }
        .btn-user-delete:hover {
            background: #c82333;
        }
        .user-form-row {
            display: flex;
            gap: 10px;
            margin-top: 8px;
        }
        .user-form-row input,
        .user-form-row select {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .user-form-row input[type="text"],
        .user-form-row input[type="password"] {
            width: 180px;
        }
        .user-form-row select {
            width: 180px;
        }
        .btn-user-add {
            background: #28a745;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn-user-add:hover {
            background: #218838;
        }
        .btn-user-change {
            background: #ffc107;
            color: #333;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn-user-change:hover {
            background: #e0a800;
        }
        .owner-cell {
            color: #666;
            font-size: 13px;
        }
        .btn-save {
            background: #4CAF50;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }
        .btn-save:hover {
            background: #43A047;
        }
        #editor-container {
            height: 300px;
            background: white;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        .char-counter {
            text-align: right;
            color: #999;
            font-size: 13px;
            margin-bottom: 15px;
        }
        .text-item {
            background: white;
            border-radius: 6px;
            padding: 10px 12px;
            margin-bottom: 8px;
            border: 1px solid #e0e0e0;
        }
        .text-item:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .text-item.compact .text-row-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0;
        }
        .text-item.compact .text-preview {
            color: #333;
            font-size: 14px;
            font-weight: 500;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-right: 10px;
        }
        .text-actions-inline {
            display: flex;
            gap: 4px;
            flex-shrink: 0;
        }
        .btn-sm {
            padding: 6px 14px;
            font-size: 13px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            background: #2196F3;
            color: white;
            text-decoration: none;
            font-weight: 500;
        }
        .btn-sm:hover { background: #1976D2; }
        .btn-sm.btn-edit { background: #FF9800; }
        .btn-sm.btn-edit:hover { background: #F57C00; }
        .btn-sm.btn-del { background: #e53935; padding: 6px 10px; }
        .btn-sm.btn-del:hover { background: #c62828; }
        .text-row-bottom {
            display: flex;
            gap: 12px;
            font-size: 12px;
            color: #888;
            align-items: center;
        }
        .extend-btns { margin-left: 2px; }
        .text-preview {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
            line-height: 1.4;
        }
        .text-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            color: #999;
            margin-bottom: 10px;
        }
        .text-actions {
            display: flex;
            gap: 10px;
        }
        .share-url {
            display: none;
            margin-top: 5px;
            padding: 8px;
            background: #e3f2fd;
            border-radius: 4px;
            font-size: 12px;
            word-break: break-all;
        }
        .share-url input {
            width: 100%;
            padding: 5px;
            border: 1px solid #ddd;
            border-radius: 3px;
            font-size: 12px;
        }
        .btn-copy {
            background: #FF9800;
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            margin-top: 5px;
            font-size: 12px;
        }
        .btn-copy:hover {
            background: #F57C00;
        }
        .btn-email {
            background: #2196F3;
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 5px;
        }
        .btn-email:hover {
            background: #1976D2;
        }
        .btn-newid {
            background: #9C27B0;
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn-newid:hover {
            background: #7B1FA2;
        }
        .btn-newid:disabled {
            background: #CE93D8;
            cursor: not-allowed;
        }
        input[type="file"] {
            display: none;
        }
        .progress-container {
            display: none;
            margin-top: 20px;
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
            background: linear-gradient(90deg, #4CAF50 0%, #45a049 100%);
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
        /* Files section header with shortcuts */
        .files-section {
            margin-top: 30px;
        }
        .files-header-row {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .files-header-row h2 {
            color: #333;
            margin: 0;
            white-space: nowrap;
        }
        .folder-shortcuts {
            display: flex;
            flex-wrap: nowrap;
            gap: 6px;
            overflow: hidden;
            align-items: center;
        }
        .folder-shortcut {
            display: inline-flex;
            align-items: center;
            gap: 3px;
            padding: 4px 10px;
            background: #f0f0f0;
            border: 1px solid #ddd;
            border-radius: 12px;
            font-size: 12px;
            color: #333;
            text-decoration: none;
            white-space: nowrap;
            transition: all 0.2s;
        }
        .folder-shortcut:hover {
            background: #e0e0e0;
            border-color: #ccc;
        }
        .folder-shortcut.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-color: transparent;
        }
        .folder-shortcut.active:hover {
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f5f5f5;
            font-weight: 600;
            color: #333;
        }
        tr:hover {
            background: #f9f9f9;
        }
        .file-name {
            color: #2196F3;
            text-decoration: none;
            font-weight: 500;
        }
        .file-name:hover {
            text-decoration: underline;
        }
        .no-files {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        .upload-info {
            margin-top: 15px;
            color: #666;
            font-size: 14px;
        }
        /* Help Tab Styles */
        .help-section h2 {
            color: #333;
            margin-bottom: 10px;
        }
        .help-accordion {
            margin-bottom: 15px;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .help-accordion-btn {
            width: 100%;
            padding: 16px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s;
        }
        .help-accordion-btn:hover {
            filter: brightness(1.1);
        }
        .accordion-icon {
            transition: transform 0.3s;
        }
        .accordion-icon.open {
            transform: rotate(180deg);
        }
        .help-accordion-content {
            max-height: 0;
            overflow: hidden;
            background: #f8f9fa;
            transition: max-height 0.4s ease-out;
        }
        .help-accordion-content.open {
            max-height: 2000px;
            padding: 20px;
        }
        .help-card {
            background: white;
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 15px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }
        .help-card:last-child {
            margin-bottom: 0;
        }
        .help-card h4 {
            margin: 0 0 12px 0;
            color: #333;
            font-size: 14px;
        }
        .code-block {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 14px;
            position: relative;
            overflow-x: auto;
        }
        .code-block.powershell {
            background: #012456;
        }
        .code-block code {
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .code-block .code-var {
            color: #4ec9b0;
            font-style: italic;
        }
        .code-block pre {
            white-space: pre-wrap;
            word-break: break-all;
        }
        .copy-btn {
            position: absolute;
            top: 50%;
            right: 10px;
            transform: translateY(-50%);
            background: #333;
            border: none;
            border-radius: 6px;
            padding: 6px 10px;
            cursor: pointer;
            font-size: 14px;
            opacity: 0.7;
            transition: all 0.2s;
        }
        .copy-btn:hover {
            opacity: 1;
            background: #444;
        }
        .copy-btn.copied {
            background: #22c55e;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!empty($siteConfig['speedtest_url'])): ?>
        <a href="<?= htmlspecialchars($siteConfig['speedtest_url']) ?>" target="_blank" class="speed-link">🚀 Speed Test</a>
        <?php endif; ?>
        <div class="user-header">
            <span class="current-user">👤 <?= htmlspecialchars($currentUser) ?></span>
            <a href="?logout=1" class="logout-link" onclick="return doLogout()">🚪 Logout</a>
        </div>
        <h1><a href="#" onclick="showAboutModal(); return false;" style="color: inherit; text-decoration: none;" title="About WebShare">WebShare</a> <a href="#" id="versionLink" onclick="showUpdateModal(); return false;" style="font-size: 14px; color: #888; font-weight: normal; text-decoration: none;" title="Check for Updates">v<?= WEBSHARE_VERSION ?></a></h1>
        <p class="subtitle">Simple File Sharing System</p>

        <?php if (isset($success)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="switchTab('files')">📁 Files</button>
            <button class="tab" onclick="switchTab('texts')">💬 Chats</button>
            <button class="tab" onclick="switchTab('help')">❓ Help</button>
            <?php if ($isAdmin): ?><button class="tab" onclick="switchTab('settings')">⚙️ Settings</button><?php endif; ?>
            <?php if ($isAdmin): ?><button class="tab" onclick="switchTab('audit')">📊 Audit Log</button><?php endif; ?>
        </div>

        <!-- Files Tab -->
        <div class="tab-content active" id="files-tab">
            <!-- Main Folder Navigation -->
            <div class="folder-nav">
                <?php foreach ($userFolders as $folder): ?>
                    <a href="?folder=<?= urlencode($folder['name']) ?>"
                       class="folder-btn <?= $folder['name'] === $baseFolder ? 'active' : '' ?>">
                        <?= $folder['icon'] ?> <?= htmlspecialchars($folder['display']) ?>
                        <?php if ($folder['type'] === 'own'): ?><span class="badge">You</span><?php endif; ?>
                    </a>
                <?php endforeach; ?>
            </div>

            <!-- Breadcrumb Navigation -->
            <?php if (count($breadcrumb) > 1): ?>
            <?php
                // Check if current folder is shared
                $currentFolderShares = loadFolderShares();
                $currentFolderShared = false;
                $currentFolderToken = null;
                foreach ($currentFolderShares as $token => $share) {
                    if ($share['folder'] === $currentFolder) {
                        $currentFolderShared = true;
                        $currentFolderToken = $token;
                        break;
                    }
                }
            ?>
            <div class="breadcrumb">
                <?php foreach ($breadcrumb as $i => $crumb): ?>
                    <?php if ($i > 0): ?><span class="breadcrumb-sep">/</span><?php endif; ?>
                    <?php if ($i < count($breadcrumb) - 1): ?>
                        <a href="?folder=<?= urlencode($crumb['path']) ?>" class="breadcrumb-link"><?= htmlspecialchars($crumb['name']) ?></a>
                    <?php else: ?>
                        <span class="breadcrumb-current"><?= htmlspecialchars($crumb['name']) ?></span>
                        <?php if ($currentFolderShared): ?><span class="shared-badge">🔗</span><?php endif; ?>
                    <?php endif; ?>
                <?php endforeach; ?>
                <button class="btn-share-current" onclick="showFolderShareModal('<?= htmlspecialchars($currentFolder, ENT_QUOTES) ?>', '<?= $currentFolderToken ?>')" title="Сподели тази папка">🔗 Сподели</button>
            </div>
            <?php endif; ?>

            <!-- Subfolders -->
            <?php if (!empty($subfolders) || $canCreateSubfolder): ?>
            <div class="subfolders-section">
                <div class="subfolders-header">
                    <span>📂 Subfolders</span>
                    <?php if ($canCreateSubfolder): ?>
                    <button class="btn-small" onclick="showCreateFolderModal()">+ New Folder</button>
                    <?php endif; ?>
                </div>
                <?php if (!empty($subfolders)): ?>
                <div class="subfolders-list">
                    <?php
                    $folderShares = loadFolderShares();
                    foreach ($subfolders as $subfolder):
                        $isShared = false;
                        $shareToken = null;
                        foreach ($folderShares as $token => $share) {
                            if ($share['folder'] === $subfolder['path']) {
                                $isShared = true;
                                $shareToken = $token;
                                break;
                            }
                        }
                    ?>
                    <div class="subfolder-item">
                        <a href="?folder=<?= urlencode($subfolder['path']) ?>" class="subfolder-link">
                            📁 <?= htmlspecialchars($subfolder['name']) ?>
                            <?php if ($isShared): ?><span class="shared-badge">🔗</span><?php endif; ?>
                        </a>
                        <div class="subfolder-actions">
                            <button class="btn-share-folder" onclick="showFolderShareModal('<?= htmlspecialchars($subfolder['path'], ENT_QUOTES) ?>', '<?= $shareToken ?>')" title="Share folder">🔗</button>
                            <button class="btn-delete-folder" onclick="deleteSubfolder('<?= htmlspecialchars($subfolder['path'], ENT_QUOTES) ?>')" title="Delete folder">🗑️</button>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php elseif ($canCreateSubfolder): ?>
                <p class="no-subfolders">No subfolders. Click "New Folder" to create one.</p>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <div class="upload-section" id="dropZone">
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div onclick="document.getElementById('fileInput').click()" style="cursor: pointer;">
                    <div style="font-size: 48px; margin-bottom: 10px;">&#128228;</div>
                    <h3>Click to upload or drag and drop</h3>
                    <p class="upload-info">Maximum file size: <?= formatBytes($maxFileSize) ?></p>
                </div>
                <input type="file" name="file" id="fileInput" style="display: none;" multiple>
                <div style="margin-top: 20px;">
                    <button type="button" class="btn" onclick="document.getElementById('fileInput').click()">
                        Choose File
                    </button>
                </div>

                <!-- Web Download Option -->
                <div class="web-download-section">
                    <div class="web-download-toggle" onclick="toggleWebDownload()">
                        <span>📥 или свали от URL</span>
                    </div>
                    <div id="webDownloadForm" style="display: none;">
                        <div class="web-download-input-group">
                            <input type="url" id="webDownloadUrl" placeholder="https://example.com/file.zip" onkeypress="if(event.key==='Enter'){checkWebUrl(); event.preventDefault();}">
                            <button type="button" class="btn btn-small" onclick="checkWebUrl()">Провери</button>
                        </div>
                        <div id="webDownloadInfo" style="display: none;">
                            <div class="web-download-file-info">
                                <input type="text" id="webDownloadFileNameInput" placeholder="Име на файла" style="flex: 1; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                <span id="webDownloadFileSize">-</span>
                            </div>
                            <div id="webDownloadExistsWarning" class="web-download-warning" style="display: none;"></div>
                            <div id="webDownloadOverwrite" style="display: none; margin: 10px 0;">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" id="webDownloadOverwriteCheck">
                                    Презапиши съществуващия файл
                                </label>
                            </div>
                            <button type="button" class="btn btn-primary" onclick="startWebDownload()">Свали</button>
                        </div>
                        <div id="webDownloadProgress" style="display: none;">
                            <div class="progress-bar-wrapper">
                                <div class="progress-bar" id="webDownloadProgressBar">Сваляне...</div>
                            </div>
                        </div>
                        <div id="webDownloadError" class="web-download-error" style="display: none;"></div>
                    </div>
                </div>

                <!-- Encryption Option -->
                <div class="encrypt-option" id="encryptOption">
                    <div class="encrypt-header">
                        <label class="encrypt-checkbox">
                            <input type="checkbox" id="encryptCheck" onchange="toggleEncryptPassword()">
                            🔒 Криптирай с парола
                        </label>
                        <button type="button" class="collapse-btn" id="collapseBtn" style="display: none;" onclick="toggleEncryptCollapse()" title="Скрий/Покажи">
                            <span id="collapseIcon">▼</span>
                        </button>
                    </div>
                    <div id="encryptPasswordFields" style="display: none;">
                        <div class="password-field-wrapper">
                            <input type="password" name="encrypt_password" id="encryptPassword" placeholder="Парола за криптиране (мин. 4 знака)" oninput="validatePasswordField()">
                            <span class="field-error" id="encryptPasswordError"></span>
                        </div>
                        <div class="password-field-wrapper">
                            <input type="password" id="encryptPasswordConfirm" placeholder="Повтори паролата" oninput="validateConfirmField()">
                            <span class="field-error" id="encryptPasswordConfirmError"></span>
                        </div>
                        <p class="encrypt-warning">⚠️ Запомни паролата! Файловете не могат да бъдат възстановени без нея.</p>
                    </div>
                </div>
            </form>
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

        <div class="files-section" id="files-section">
            <div class="files-header-row">
                <h2>Files (<?= count($files) ?>)</h2>
                <!-- Folder shortcuts -->
                <?php
                // Get public and user's own folder
                $publicFolder = array_filter($userFolders, fn($f) => $f['type'] === 'public');
                $publicFolder = reset($publicFolder);
                $myFolder = array_filter($userFolders, fn($f) => $f['type'] === 'own');
                $myFolder = reset($myFolder);
                $mySubfolders = $myFolder ? getAllSubfoldersRecursive($myFolder['name'], $currentUser, 2) : [];
                ?>
                <div class="folder-shortcuts">
                    <?php if ($publicFolder): ?>
                    <a href="?folder=<?= urlencode($publicFolder['name']) ?>"
                       class="folder-shortcut <?= $currentFolder === $publicFolder['name'] ? 'active' : '' ?>">
                        <?= $publicFolder['icon'] ?> <?= htmlspecialchars($publicFolder['display']) ?>
                    </a>
                    <?php endif; ?>
                    <?php if ($myFolder): ?>
                    <a href="?folder=<?= urlencode($myFolder['name']) ?>"
                       class="folder-shortcut <?= $currentFolder === $myFolder['name'] ? 'active' : '' ?>">
                        <?= $myFolder['icon'] ?> <?= htmlspecialchars($myFolder['display']) ?>
                    </a>
                    <?php endif; ?>
                    <?php foreach ($mySubfolders as $sub):
                        $subFolderPath = $myFolder['name'] . '/' . $sub['display'];
                        $isSubActive = ($currentFolder === $subFolderPath);
                    ?>
                    <a href="?folder=<?= urlencode($subFolderPath) ?>"
                       class="folder-shortcut <?= $isSubActive ? 'active' : '' ?>">
                        📂 <?= htmlspecialchars($sub['name']) ?>
                    </a>
                    <?php endforeach; ?>
                </div>
            </div>

            <?php if (empty($files)): ?>
                <div class="no-files">
                    <p>No files uploaded yet.</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Owner</th>
                            <th>Size</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($files as $index => $file):
                            $isEncrypted = isEncryptedFile($file['name']);
                        ?>
                            <tr class="<?= $isEncrypted ? 'file-encrypted' : '' ?>">
                                <td>
                                    <a href="download.php?file=<?= urlencode($file['name']) ?>&folder=<?= urlencode($currentFolder) ?>" class="file-name">
                                        <?php if ($isEncrypted): ?>🔒 <?php endif; ?>
                                        <?= htmlspecialchars($file['name']) ?>
                                    </a>
                                    <?php if ($isEncrypted): ?><span class="encrypted-badge">ENCRYPTED</span><?php endif; ?>
                                </td>
                                <td class="owner-cell"><?= htmlspecialchars($file['owner']) ?></td>
                                <td><?= formatBytes($file['size']) ?></td>
                                <td><?= date('Y-m-d H:i:s', $file['date']) ?></td>
                                <td>
                                    <button class="btn-move" onclick="showMoveModal('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')">
                                        ↔️ Move
                                    </button>
                                    <button class="btn-share" onclick="generateShareLink('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>', <?= $index ?>, '<?= htmlspecialchars($currentFolder, ENT_QUOTES) ?>')">
                                        Share
                                    </button>
                                    <button class="btn-rename" onclick="renameFile('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>', <?= $index ?>)">
                                        Rename
                                    </button>
                                    <button class="btn btn-danger" onclick="deleteFile('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')">
                                        Delete
                                    </button>
                                    <?php if ($isEncrypted): ?>
                                    <button class="btn-encrypt btn-decrypt-action" onclick="showDecryptModal('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')" title="Декриптирай файла">
                                        🔓
                                    </button>
                                    <?php else: ?>
                                    <button class="btn-encrypt" onclick="showEncryptModal('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')" title="Криптирай файла">
                                        🔒
                                    </button>
                                    <?php endif; ?>
                                    <div class="share-url" id="share-<?= $index ?>">
                                        <input type="text" readonly id="url-<?= $index ?>">
                                        <button class="btn-copy" onclick="copyShareLink(<?= $index ?>)">
                                            Copy
                                        </button>
                                        <?php if (!empty($siteConfig['mail']['enabled'])): ?>
                                        <button class="btn-email" onclick="showEmailModal(<?= $index ?>, '<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')" title="Send via Email">
                                            Email
                                        </button>
                                        <?php endif; ?>
                                        <button class="btn-newid" onclick="regenerateShareLink('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>', <?= $index ?>, '<?= htmlspecialchars($currentFolder, ENT_QUOTES) ?>')" title="Generate new link (invalidates old)">
                                            New ID
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        </div><!-- End Files Tab -->

        <!-- Chats Tab -->
        <div class="tab-content" id="texts-tab">
            <div class="upload-section">
                <h3 style="margin-bottom: 20px;">💬 Start New Conversation</h3>
                <p style="color: #666; margin-bottom: 15px; font-size: 14px;">Create a chat room - anyone with the link can join and reply.</p>

                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: 500; font-size: 14px;">Your Name</label>
                    <input type="text" id="chat-author-name" placeholder="Your name" maxlength="30" style="padding: 10px 14px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; width: 200px;">
                </div>

                <div id="editor-container"></div>

                <div class="char-counter">
                    <span id="charCount">0</span> / 1,000,000 characters
                </div>

                <button type="button" class="btn" onclick="shareText()">Start Conversation</button>

                <div class="share-url" id="text-share-result" style="margin-top: 20px;">
                    <div style="margin-bottom: 10px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold; font-size: 12px;">Chat Link (copied to clipboard):</label>
                        <input type="text" readonly id="text-view-url">
                        <button class="btn-copy" onclick="copyTextViewUrl()">Copy</button>
                    </div>
                </div>
            </div>

            <div class="files-section">
                <h2>Conversations (<?= count($texts) ?>)</h2>

                <?php if (empty($texts)): ?>
                    <div class="no-files">
                        <p>No conversations yet.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($texts as $text): ?>
                        <?php
                            $expiresIn = $text['expires'] - time();
                            $parts = [];
                            $y = floor($expiresIn / (365 * 24 * 3600)); $expiresIn %= (365 * 24 * 3600);
                            $mo = floor($expiresIn / (30 * 24 * 3600)); $expiresIn %= (30 * 24 * 3600);
                            $d = floor($expiresIn / (24 * 3600)); $expiresIn %= (24 * 3600);
                            $h = floor($expiresIn / 3600); $m = floor(($expiresIn % 3600) / 60);
                            if ($y > 0) $parts[] = $y . 'y';
                            if ($mo > 0) $parts[] = $mo . 'm';
                            if ($d > 0) $parts[] = $d . 'd';
                            if (empty($parts) || ($y == 0 && $mo == 0 && $d < 2)) {
                                if ($h > 0) $parts[] = $h . 'h';
                                if ($m > 0 || empty($parts)) $parts[] = $m . 'm';
                            }
                            $expiresText = implode(' ', $parts);
                            $msgCount = $text['message_count'] ?? 1;
                        ?>
                        <div class="text-item compact">
                            <div class="text-row-top">
                                <span class="text-preview"><?= htmlspecialchars($text['preview']) ?></span>
                                <span class="text-actions-inline">
                                    <button class="btn-sm" onclick="shareExistingText('<?= $text['token'] ?>')">Share</button>
                                    <a href="/t/<?= $text['token'] ?>" target="_blank" class="btn-sm">Open</a>
                                    <button class="btn-sm btn-del" onclick="deleteText('<?= $text['token'] ?>')">✕</button>
                                </span>
                            </div>
                            <div class="text-row-bottom">
                                <span>💬 <?= $msgCount ?></span>
                                <span>👁️ <?= $text['views'] ?></span>
                                <span>⏰ <strong id="expires-<?= $text['token'] ?>"><?= $expiresText ?></strong></span>
                                <span class="extend-btns"><button class="btn-ext" onclick="extendText('<?= $text['token'] ?>', '1d')">+1d</button><button class="btn-ext" onclick="extendText('<?= $text['token'] ?>', '1w')">+1w</button><button class="btn-ext" onclick="extendText('<?= $text['token'] ?>', '1m')">+1m</button><button class="btn-ext" onclick="extendText('<?= $text['token'] ?>', '6m')">+6m</button><button class="btn-ext" onclick="extendText('<?= $text['token'] ?>', 'permanent')">∞</button><button class="btn-set" onclick="setText('<?= $text['token'] ?>', '1h')">1h</button><button class="btn-set" onclick="setText('<?= $text['token'] ?>', '1d')">1d</button></span>
                            </div>
                            <div class="share-url" id="share-text-<?= $text['token'] ?>">
                                <input type="text" readonly id="url-text-<?= $text['token'] ?>" value="https://<?= $_SERVER['HTTP_HOST'] ?>/t/<?= $text['token'] ?>">
                                <button class="btn-copy" onclick="copyExistingTextLink('<?= $text['token'] ?>')">Copy</button>
                                <?php if (!empty($siteConfig['mail']['enabled'])): ?>
                                <button class="btn-copy" style="background: #2196F3;" onclick="emailChatLink('<?= $text['token'] ?>')">Email</button>
                                <?php endif; ?>
                                <button class="btn-copy" style="background: #ff9800;" onclick="regenerateChatToken('<?= $text['token'] ?>')">New ID</button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div><!-- End Texts Tab -->

        <!-- Help Tab -->
        <div class="tab-content" id="help-tab">
            <?php $currentHost = $_SERVER['HTTP_HOST']; ?>
            <div class="help-section">
                <h2>❓ Help & CLI Upload</h2>
                <p style="color: #666; margin-bottom: 20px;">Upload files directly from command line without a browser.</p>

                <!-- Linux Section -->
                <div class="help-accordion">
                    <button class="help-accordion-btn" onclick="toggleHelpSection('linux')">
                        <span>🐧 Linux / macOS</span>
                        <span class="accordion-icon" id="linux-icon">▼</span>
                    </button>
                    <div class="help-accordion-content" id="linux-content">

                        <div class="help-card">
                            <h4>📤 Basic Upload (to Public folder)</h4>
                            <div class="code-block">
                                <code>curl -F "file=@<span class="code-var">/path/to/file.txt</span>" https://<?= htmlspecialchars($currentHost) ?>/u</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>👤 Upload to Specific User</h4>
                            <div class="code-block">
                                <code>curl -F "file=@<span class="code-var">file.pdf</span>" -F "target_user=<span class="code-var"><?= htmlspecialchars($currentUser) ?></span>" https://<?= htmlspecialchars($currentHost) ?>/u</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>🔒 Upload with Encryption</h4>
                            <div class="code-block">
                                <code>curl -F "file=@<span class="code-var">secret.doc</span>" -F "target_user=<span class="code-var"><?= htmlspecialchars($currentUser) ?></span>" -F "encrypt=1" -F "encrypt_password=<span class="code-var">mypass</span>" https://<?= htmlspecialchars($currentHost) ?>/u</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);">
                            <h4 style="color: #4ade80;">⚡ Quick Alias (add to ~/.bashrc)</h4>
                            <div class="code-block" style="background: #0d1117;">
                                <pre style="color: #c9d1d9; margin: 0; font-size: 13px;"><span style="color: #ff7b72;">webshare</span>() {
    <span style="color: #79c0ff;">curl</span> <span style="color: #a5d6ff;">-F</span> <span style="color: #a5d6ff;">"file=@</span><span style="color: #ffa657;">$1</span><span style="color: #a5d6ff;">"</span> <span style="color: #ffa657;">${2:+-F "target_user=$2"}</span> https://<?= htmlspecialchars($currentHost) ?>/u
}

<span style="color: #8b949e;"># Usage:</span>
<span style="color: #ff7b72;">webshare</span> file.txt              <span style="color: #8b949e;"># upload to public</span>
<span style="color: #ff7b72;">webshare</span> file.txt admin        <span style="color: #8b949e;"># upload to user 'admin'</span>
<span style="color: #ff7b72;">webshare</span> backup.tar.gz <?= htmlspecialchars($currentUser) ?>  <span style="color: #8b949e;"># upload to your folder</span></pre>
                                <button class="copy-btn" onclick="copyCode(this)" style="top: 8px;">📋</button>
                            </div>
                            <p style="color: #8b949e; font-size: 12px; margin-top: 10px;">After adding, run: <code style="background: #21262d; padding: 2px 6px; border-radius: 4px; color: #79c0ff;">source ~/.bashrc</code></p>
                        </div>

                        <div class="help-card">
                            <h4>📁 Upload Multiple Files</h4>
                            <div class="code-block">
                                <code>for f in *.jpg; do curl -F "file=@$f" -F "target_user=<?= htmlspecialchars($currentUser) ?>" https://<?= htmlspecialchars($currentHost) ?>/u; done</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                    </div>
                </div>

                <!-- Windows Section -->
                <div class="help-accordion">
                    <button class="help-accordion-btn" onclick="toggleHelpSection('windows')">
                        <span>🪟 Windows</span>
                        <span class="accordion-icon" id="windows-icon">▼</span>
                    </button>
                    <div class="help-accordion-content" id="windows-content">

                        <div class="help-card">
                            <h4>📤 PowerShell - Basic Upload</h4>
                            <div class="code-block powershell">
                                <code>Invoke-RestMethod -Uri "https://<?= htmlspecialchars($currentHost) ?>/u" -Method Post -Form @{file = Get-Item "<span class="code-var">C:\path\to\file.txt</span>"}</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>👤 PowerShell - Upload to User</h4>
                            <div class="code-block powershell">
                                <code>Invoke-RestMethod -Uri "https://<?= htmlspecialchars($currentHost) ?>/u" -Method Post -Form @{file = Get-Item "<span class="code-var">file.pdf</span>"; target_user = "<span class="code-var"><?= htmlspecialchars($currentUser) ?></span>"}</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>🔒 PowerShell - With Encryption</h4>
                            <div class="code-block powershell">
                                <code>Invoke-RestMethod -Uri "https://<?= htmlspecialchars($currentHost) ?>/u" -Method Post -Form @{file = Get-Item "<span class="code-var">secret.doc</span>"; target_user = "<span class="code-var"><?= htmlspecialchars($currentUser) ?></span>"; encrypt = "1"; encrypt_password = "<span class="code-var">mypass</span>"}</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card" style="background: linear-gradient(135deg, #012456 0%, #1e3a5f 100%);">
                            <h4 style="color: #61dafb;">⚡ PowerShell Function (add to $PROFILE)</h4>
                            <div class="code-block" style="background: #0d1117;">
                                <pre style="color: #c9d1d9; margin: 0; font-size: 13px;"><span style="color: #ff7b72;">function</span> <span style="color: #d2a8ff;">WebShare</span> {
    <span style="color: #ff7b72;">param</span>(
        [<span style="color: #79c0ff;">Parameter</span>(<span style="color: #79c0ff;">Mandatory</span>)]<span style="color: #79c0ff;">[string]</span><span style="color: #ffa657;">$FilePath</span>,
        [<span style="color: #79c0ff;">string</span>]<span style="color: #ffa657;">$User</span> = <span style="color: #a5d6ff;">""</span>
    )
    <span style="color: #ffa657;">$form</span> = @{<span style="color: #79c0ff;">file</span> = Get-Item <span style="color: #ffa657;">$FilePath</span>}
    <span style="color: #ff7b72;">if</span> (<span style="color: #ffa657;">$User</span>) { <span style="color: #ffa657;">$form</span>[<span style="color: #a5d6ff;">"target_user"</span>] = <span style="color: #ffa657;">$User</span> }
    Invoke-RestMethod -Uri <span style="color: #a5d6ff;">"https://<?= htmlspecialchars($currentHost) ?>/u"</span> -Method Post -Form <span style="color: #ffa657;">$form</span>
}

<span style="color: #8b949e;"># Usage:</span>
<span style="color: #d2a8ff;">WebShare</span> <span style="color: #a5d6ff;">"file.txt"</span>                   <span style="color: #8b949e;"># upload to public</span>
<span style="color: #d2a8ff;">WebShare</span> <span style="color: #a5d6ff;">"file.txt"</span> -User admin      <span style="color: #8b949e;"># upload to 'admin'</span>
<span style="color: #d2a8ff;">WebShare</span> <span style="color: #a5d6ff;">"C:\backup.zip"</span> -User <?= htmlspecialchars($currentUser) ?>  <span style="color: #8b949e;"># upload to your folder</span></pre>
                                <button class="copy-btn" onclick="copyCode(this)" style="top: 8px;">📋</button>
                            </div>
                            <p style="color: #8b949e; font-size: 12px; margin-top: 10px;">Open profile: <code style="background: #21262d; padding: 2px 6px; border-radius: 4px; color: #79c0ff;">notepad $PROFILE</code></p>
                        </div>

                        <div class="help-card">
                            <h4>🌐 Using curl (if installed)</h4>
                            <div class="code-block">
                                <code>curl.exe -F "file=@<span class="code-var">C:\path\to\file.txt</span>" https://<?= htmlspecialchars($currentHost) ?>/u</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                    </div>
                </div>

                <!-- Quick Reference -->
                <div class="help-card" style="margin-top: 20px; background: #f0f9ff; border-left: 4px solid #0ea5e9;">
                    <h4 style="color: #0369a1;">📋 Quick Reference</h4>
                    <table style="width: 100%; font-size: 13px; margin-top: 10px;">
                        <tr style="background: #e0f2fe;">
                            <td style="padding: 8px; font-weight: bold;">Parameter</td>
                            <td style="padding: 8px; font-weight: bold;">Description</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px;"><code>file</code></td>
                            <td style="padding: 8px;">The file to upload (required)</td>
                        </tr>
                        <tr style="background: #f8fafc;">
                            <td style="padding: 8px;"><code>target_user</code></td>
                            <td style="padding: 8px;">Username folder to upload to (optional, defaults to public)</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px;"><code>encrypt</code></td>
                            <td style="padding: 8px;">Set to "1" to encrypt the file</td>
                        </tr>
                        <tr style="background: #f8fafc;">
                            <td style="padding: 8px;"><code>encrypt_password</code></td>
                            <td style="padding: 8px;">Password for encryption (min 4 characters)</td>
                        </tr>
                    </table>
                </div>

                <!-- API Upload Section -->
                <div class="help-accordion" style="margin-top: 20px;">
                    <button class="help-accordion-btn" onclick="toggleHelpSection('api')">
                        <span>🔌 API Upload (Right-Click Menu)</span>
                        <span class="accordion-icon" id="api-icon">▼</span>
                    </button>
                    <div class="help-accordion-content" id="api-content">
                        <?php
                        $userApiKeys = getUserApiKeys($currentUser);
                        $userApiKey = getUserApiKey($currentUser); // First key for backward compat
                        ?>

                        <div class="help-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                            <h4 style="color: white;">🔑 Your API Keys</h4>
                            <p style="color: rgba(255,255,255,0.8); font-size: 13px; margin-bottom: 15px;">
                                Manage API keys for uploading files. You can create multiple keys with IP restrictions.
                            </p>

                            <!-- API Keys List -->
                            <div id="apiKeysList" style="background: rgba(255,255,255,0.95); border-radius: 8px; margin-bottom: 15px; max-height: 300px; overflow-y: auto;">
                                <?php if (empty($userApiKeys)): ?>
                                <div style="padding: 20px; text-align: center; color: #666;">
                                    No API keys yet. Create one below.
                                </div>
                                <?php else: ?>
                                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                                    <thead>
                                        <tr style="background: #f0f0f0;">
                                            <th style="padding: 10px; text-align: left;">Name</th>
                                            <th style="padding: 10px; text-align: left;">Key</th>
                                            <th style="padding: 10px; text-align: left;">IP Restrictions</th>
                                            <th style="padding: 10px; text-align: left;">Last Used</th>
                                            <th style="padding: 10px; text-align: center;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                    <?php foreach ($userApiKeys as $keyInfo): ?>
                                        <tr style="border-bottom: 1px solid #eee;" data-key-id="<?= htmlspecialchars($keyInfo['id']) ?>">
                                            <td style="padding: 10px; font-weight: 500;"><?= htmlspecialchars($keyInfo['name']) ?></td>
                                            <td style="padding: 10px;">
                                                <code style="background: #e8e8e8; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
                                                    <?= htmlspecialchars($keyInfo['key_preview']) ?>
                                                </code>
                                            </td>
                                            <td style="padding: 10px;">
                                                <?php if ($keyInfo['is_allow_all']): ?>
                                                    <span style="color: #2196f3; font-size: 12px;" title="Allow from any IP">
                                                        🌍 All IPs
                                                    </span>
                                                    <button onclick="editKeyIps('<?= htmlspecialchars($keyInfo['id']) ?>', '0.0.0.0/0')"
                                                            style="background: none; border: none; cursor: pointer; font-size: 12px;" title="Edit">✏️</button>
                                                <?php elseif ($keyInfo['is_auto_learn']): ?>
                                                    <span style="color: #ff9800; font-size: 12px;" title="Will lock to first IP used">
                                                        🎓 Auto-learn
                                                    </span>
                                                    <button onclick="editKeyIps('<?= htmlspecialchars($keyInfo['id']) ?>', '')"
                                                            style="background: none; border: none; cursor: pointer; font-size: 12px;" title="Set IP manually">✏️</button>
                                                <?php elseif ($keyInfo['allowed_ips']): ?>
                                                    <span style="color: #2e7d32; font-size: 12px;" title="<?= htmlspecialchars(implode(', ', $keyInfo['allowed_ips'])) ?>">
                                                        🔒 <?= count($keyInfo['allowed_ips']) ?> IP<?= $keyInfo['was_learned'] ? ' (learned)' : '' ?>
                                                    </span>
                                                    <button onclick="editKeyIps('<?= htmlspecialchars($keyInfo['id']) ?>', '<?= htmlspecialchars(implode(', ', $keyInfo['allowed_ips'])) ?>')"
                                                            style="background: none; border: none; cursor: pointer; font-size: 12px;" title="Edit IPs">✏️</button>
                                                <?php endif; ?>
                                            </td>
                                            <td style="padding: 10px; font-size: 12px; color: #666;">
                                                <?= $keyInfo['last_used'] ? date('Y-m-d H:i', $keyInfo['last_used']) : 'Never' ?>
                                            </td>
                                            <td style="padding: 10px; text-align: center;">
                                                <button onclick="revokeKey('<?= htmlspecialchars($keyInfo['id']) ?>', '<?= htmlspecialchars($keyInfo['name']) ?>')"
                                                        style="background: #f44336; color: white; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                                    🗑️
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <?php endif; ?>
                            </div>

                            <!-- Add New Key Form -->
                            <div style="background: rgba(255,255,255,0.9); padding: 15px; border-radius: 8px;">
                                <h5 style="margin: 0 0 10px 0; color: #333;">➕ Add New API Key</h5>
                                <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end;">
                                    <div style="flex: 1; min-width: 150px;">
                                        <label style="display: block; font-size: 12px; color: #666; margin-bottom: 4px;">Name (optional)</label>
                                        <input type="text" id="newKeyName" placeholder="e.g., Home PC"
                                               style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                    </div>
                                    <div style="flex: 2; min-width: 200px;">
                                        <label style="display: block; font-size: 12px; color: #666; margin-bottom: 4px;">
                                            Allowed IPs (optional, comma separated)
                                        </label>
                                        <input type="text" id="newKeyIps" placeholder="e.g., 192.168.1.0/24, 10.0.0.5"
                                               style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                    </div>
                                    <button onclick="generateNewKey()" class="btn"
                                            style="background: #4CAF50; border: none; padding: 8px 16px; white-space: nowrap;">
                                        🔑 Generate Key
                                    </button>
                                </div>
                                <p style="font-size: 11px; color: #888; margin: 8px 0 0 0;">
                                    💡 Empty = auto-learn (locks to first IP used) | <code>0.0.0.0/0</code> = allow all | CIDR: <code>192.168.1.0/24</code>
                                </p>
                            </div>
                        </div>

                        <!-- New Key Display Modal (hidden by default) -->
                        <div id="newKeyModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 9999; align-items: center; justify-content: center;">
                            <div style="background: white; padding: 30px; border-radius: 12px; max-width: 600px; width: 90%; text-align: center;">
                                <h3 style="color: #4CAF50; margin-bottom: 15px;">✅ API Key Generated!</h3>
                                <p style="color: #666; margin-bottom: 15px;">Copy this key now - it won't be shown again:</p>
                                <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 15px; word-break: break-all;">
                                    <code id="newKeyValue" style="font-size: 14px; color: #333;"></code>
                                </div>
                                <button onclick="copyNewKey()" class="btn" style="background: #667eea; border: none; padding: 10px 20px; margin-right: 10px;">
                                    📋 Copy Key
                                </button>
                                <button onclick="closeNewKeyModal()" class="btn" style="background: #6c757d; border: none; padding: 10px 20px;">
                                    Close
                                </button>
                            </div>
                        </div>

                        <?php if ($userApiKey): ?>
                        <div class="help-card">
                            <h4>📥 Windows Right-Click Integration</h4>
                            <p style="color: #666; font-size: 13px; margin-bottom: 15px;">
                                Download these files to add "Upload to WebShare" to your right-click menu.
                            </p>

                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
                                <a href="api-scripts.php?type=bat&key=<?= urlencode($userApiKey) ?>" class="btn" style="background: #607D8B; text-decoration: none; padding: 10px 15px;">
                                    📄 upload-webshare.bat
                                </a>
                                <a href="api-scripts.php?type=reg&key=<?= urlencode($userApiKey) ?>" class="btn" style="background: #9C27B0; text-decoration: none; padding: 10px 15px;">
                                    📄 add-menu.reg
                                </a>
                            </div>

                            <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; font-size: 13px;">
                                <strong>Installation:</strong>
                                <ol style="margin: 10px 0 0 0; padding-left: 20px; line-height: 1.8;">
                                    <li>Create folder: <code style="background: #e0e0e0; padding: 2px 6px; border-radius: 3px;">C:\Scripts</code></li>
                                    <li>Save <strong>.bat</strong> file to <code style="background: #e0e0e0; padding: 2px 6px; border-radius: 3px;">C:\Scripts\upload-webshare.bat</code></li>
                                    <li>Double-click the <strong>.reg</strong> file → Click "Yes"</li>
                                    <li>Right-click any file → <strong>"Upload to WebShare"</strong></li>
                                </ol>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>🖥️ Command Line Usage</h4>
                            <div class="code-block" style="background: #263238;">
                                <code style="color: #aed581;">curl -X POST -H "X-API-Key: <span class="code-var">YOUR_KEY</span>" -F "file=@<span class="code-var">file.pdf</span>" <?= htmlspecialchars((isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST']) ?>/api-upload.php</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>📁 Upload to Specific Folder</h4>
                            <p style="color: #666; font-size: 13px; margin-bottom: 10px;">
                                Add <code>folder</code> parameter to upload to a subfolder:
                            </p>
                            <div class="code-block" style="background: #263238;">
                                <code style="color: #aed581;">curl -X POST -H "X-API-Key: <span class="code-var">YOUR_KEY</span>" \<br>&nbsp;&nbsp;-F "file=@<span class="code-var">file.pdf</span>" \<br>&nbsp;&nbsp;-F "folder=<span class="code-var"><?= htmlspecialchars($currentUser) ?>/Projects</span>" \<br>&nbsp;&nbsp;<?= htmlspecialchars((isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST']) ?>/api-upload.php</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>📤 Upload to Shared Folder</h4>
                            <p style="color: #666; font-size: 13px; margin-bottom: 10px;">
                                Upload directly to a shared folder (no API key needed, upload must be enabled):
                            </p>
                            <div class="code-block" style="background: #263238;">
                                <code style="color: #aed581;">curl -X POST -F "file=@<span class="code-var">file.pdf</span>" \<br>&nbsp;&nbsp;<?= htmlspecialchars((isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST']) ?>/f/<span class="code-var">FOLDER_TOKEN</span>/upload</code>
                                <button class="copy-btn" onclick="copyCode(this)">📋</button>
                            </div>
                        </div>

                        <div class="help-card">
                            <h4>📄 PowerShell Script (Alternative)</h4>
                            <p style="color: #666; font-size: 13px; margin-bottom: 10px;">
                                For older Windows without curl, use PowerShell:
                            </p>
                            <a href="api-scripts.php?type=ps1&key=<?= urlencode($userApiKey) ?>" class="btn" style="background: #2196F3; text-decoration: none; padding: 8px 15px;">
                                📄 upload-webshare.ps1
                            </a>
                            <a href="api-scripts.php?type=reg-ps1&key=<?= urlencode($userApiKey) ?>" class="btn" style="background: #9C27B0; text-decoration: none; padding: 8px 15px; margin-left: 10px;">
                                📄 add-menu-ps1.reg
                            </a>
                        </div>
                        <?php endif; ?>

                    </div>
                </div>

            </div>
        </div><!-- End Help Tab -->

        <!-- Settings Tab (Admin Only) -->
        <?php if ($isAdmin): ?>
        <div class="tab-content" id="settings-tab">
            <div class="settings-section">
                <h2>⚙️ Settings</h2>

                <form method="POST" class="settings-form">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <input type="hidden" name="save_geo" value="1">

                    <div class="setting-group">
                        <h3>🌍 Geo Restrictions</h3>
                        <p class="setting-desc">Block public uploads from specific countries. Viewing shared content is always allowed.</p>

                        <div class="setting-row">
                            <label class="toggle">
                                <input type="checkbox" name="geo_enabled" <?= ($geoConfig['enabled'] ?? false) ? 'checked' : '' ?>>
                                <span class="toggle-slider"></span>
                                <span class="toggle-label">Geo Blocking</span>
                                <span class="toggle-status <?= ($geoConfig['enabled'] ?? false) ? 'on' : 'off' ?>">
                                    <?= ($geoConfig['enabled'] ?? false) ? 'ENABLED' : 'DISABLED' ?>
                                </span>
                            </label>
                        </div>

                        <div class="setting-row">
                            <label>Allowed Countries (comma separated ISO codes):</label>
                            <input type="text" name="geo_countries" value="<?= htmlspecialchars(implode(', ', $geoConfig['allowed_countries'] ?? ['BG'])) ?>" placeholder="BG, DE, NL">
                            <small>Examples: BG (Bulgaria), DE (Germany), US (United States), GB (United Kingdom)</small>
                        </div>

                        <div class="setting-row">
                            <label>Blocked Message:</label>
                            <input type="text" name="geo_message" value="<?= htmlspecialchars($geoConfig['blocked_message'] ?? 'Access denied from your location') ?>">
                        </div>

                        <div class="setting-info">
                            <strong>Current Status:</strong><br>
                            <?php $geoInfo = getGeoInfo(); ?>
                            Your IP: <?= htmlspecialchars($geoInfo['ip']) ?><br>
                            Country: <?= htmlspecialchars($geoInfo['country'] ?? 'Unknown') ?><br>
                            Access: <?= $geoInfo['allowed'] ? '✅ Allowed' : '🚫 Blocked' ?>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-save">💾 Save Settings</button>
                </form>

                <!-- User Management Section -->
                <div class="setting-group" style="margin-top: 30px;">
                    <h3>👥 User Management</h3>
                    <p class="setting-desc">Manage users who can access the admin panel. Current user: <strong><?= htmlspecialchars($currentUser) ?></strong></p>

                    <?php if ($userMessage): ?>
                        <div class="alert alert-success" style="margin-bottom: 15px;"><?= htmlspecialchars($userMessage) ?></div>
                    <?php endif; ?>
                    <?php if ($userError): ?>
                        <div class="alert alert-error" style="margin-bottom: 15px;"><?= htmlspecialchars($userError) ?></div>
                    <?php endif; ?>

                    <!-- Existing Users -->
                    <div class="setting-row">
                        <label>Existing Users:</label>
                        <div class="users-list">
                            <?php $users = getUsers(); ?>
                            <?php foreach ($users as $user): ?>
                                <div class="user-item">
                                    <span class="user-name"><?= htmlspecialchars($user) ?></span>
                                    <?php if ($user === $currentUser): ?>
                                        <span class="user-badge">you</span>
                                    <?php endif; ?>
                                    <?php if (count($users) > 1): ?>
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Delete user <?= htmlspecialchars($user) ?>?')">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="user_action" value="delete">
                                            <input type="hidden" name="delete_username" value="<?= htmlspecialchars($user) ?>">
                                            <button type="submit" class="btn-user-delete">✕</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <!-- Add New User -->
                    <form method="POST" class="user-form">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="user_action" value="add">
                        <div class="setting-row">
                            <label>Add New User:</label>
                            <div class="user-form-row">
                                <input type="text" name="new_username" placeholder="Username" required pattern="[a-zA-Z0-9_-]{3,20}">
                                <input type="password" name="new_password" placeholder="Password" required minlength="4">
                                <button type="submit" class="btn-user-add">+ Add</button>
                            </div>
                            <small>Username: 3-20 characters (letters, numbers, - _). Password: min 4 characters.</small>
                        </div>
                    </form>

                    <!-- Change Password -->
                    <form method="POST" class="user-form">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="user_action" value="change_password">
                        <div class="setting-row">
                            <label>Change Password:</label>
                            <div class="user-form-row">
                                <select name="change_username" required>
                                    <option value="">Select user...</option>
                                    <?php foreach ($users as $user): ?>
                                        <option value="<?= htmlspecialchars($user) ?>"><?= htmlspecialchars($user) ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <input type="password" name="change_password" placeholder="New Password" required minlength="4">
                                <button type="submit" class="btn-user-change">Change</button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Speed Test Link Section -->
                <div class="setting-group" style="margin-top: 30px;">
                    <h3>🚀 Speed Test Link</h3>
                    <p class="setting-desc">Add a speed test link that appears on public pages (/u and /t).</p>

                    <?php $currentSpeedtest = $siteConfig['speedtest_url'] ?? ''; ?>

                    <?php if (!empty($currentSpeedtest)): ?>
                    <div class="setting-info" style="margin-bottom: 15px; background: #e8f5e9; border-left: 4px solid #4CAF50;">
                        <strong>Current:</strong>
                        <a href="<?= htmlspecialchars($currentSpeedtest) ?>" target="_blank" style="color: #1976D2; word-break: break-all;">
                            <?= htmlspecialchars($currentSpeedtest) ?>
                        </a>
                    </div>
                    <?php else: ?>
                    <div class="setting-info" style="margin-bottom: 15px; background: #fff3e0; border-left: 4px solid #ff9800;">
                        <strong>Status:</strong> No speed test link configured
                    </div>
                    <?php endif; ?>

                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="save_speedtest" value="1">
                        <div class="setting-row">
                            <label><?= empty($currentSpeedtest) ? 'Speed Test URL:' : 'Change URL:' ?></label>
                            <input type="url" name="speedtest_url" value="<?= htmlspecialchars($currentSpeedtest) ?>" placeholder="https://speed.example.com" style="flex:1; padding: 10px; border: 1px solid #ddd; border-radius: 8px;">
                        </div>
                        <div style="display: flex; gap: 10px; margin-top: 15px;">
                            <button type="submit" class="btn btn-save">💾 <?= empty($currentSpeedtest) ? 'Save' : 'Update' ?></button>
                            <?php if (!empty($currentSpeedtest)): ?>
                            <button type="submit" name="speedtest_url" value="" class="btn" style="background: #f44336;">🗑️ Remove</button>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>

                <!-- Email Settings Section -->
                <?php $mailConfig = $siteConfig['mail'] ?? ['enabled' => false]; ?>
                <div class="setting-group" style="margin-top: 30px;">
                    <h3>📧 Email Settings</h3>
                    <p class="setting-desc">Configure SMTP to enable sharing files via email.</p>

                    <form method="POST" id="mailSettingsForm">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="save_mail" value="1">

                        <div class="setting-row">
                            <label class="toggle">
                                <input type="checkbox" name="mail_enabled" id="mail_enabled" <?= ($mailConfig['enabled'] ?? false) ? 'checked' : '' ?> onchange="toggleMailSettings()">
                                <span class="toggle-slider"></span>
                                <span class="toggle-label">Email Sharing</span>
                                <span class="toggle-status <?= ($mailConfig['enabled'] ?? false) ? 'on' : 'off' ?>">
                                    <?= ($mailConfig['enabled'] ?? false) ? 'ENABLED' : 'DISABLED' ?>
                                </span>
                            </label>
                        </div>

                        <div id="mailSettingsFields" style="<?= ($mailConfig['enabled'] ?? false) ? '' : 'display: none;' ?>">
                            <div class="setting-row">
                                <label>SMTP Host:</label>
                                <input type="text" name="smtp_host" value="<?= htmlspecialchars($mailConfig['smtp_host'] ?? '') ?>" placeholder="mail.example.com">
                            </div>

                            <div class="setting-row" style="display: flex; gap: 15px;">
                                <div style="flex: 1;">
                                    <label>SMTP Port:</label>
                                    <input type="number" name="smtp_port" value="<?= htmlspecialchars($mailConfig['smtp_port'] ?? 465) ?>" placeholder="465">
                                </div>
                                <div style="flex: 1;">
                                    <label>Encryption:</label>
                                    <select name="smtp_encryption" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px;">
                                        <option value="ssl" <?= ($mailConfig['smtp_encryption'] ?? 'ssl') === 'ssl' ? 'selected' : '' ?>>SSL (port 465)</option>
                                        <option value="tls" <?= ($mailConfig['smtp_encryption'] ?? '') === 'tls' ? 'selected' : '' ?>>TLS (port 587)</option>
                                        <option value="none" <?= ($mailConfig['smtp_encryption'] ?? '') === 'none' ? 'selected' : '' ?>>None (port 25)</option>
                                    </select>
                                </div>
                            </div>

                            <div class="setting-row">
                                <label>SMTP Username (email):</label>
                                <input type="text" name="smtp_user" value="<?= htmlspecialchars($mailConfig['smtp_user'] ?? '') ?>" placeholder="noreply@example.com">
                            </div>

                            <div class="setting-row">
                                <label>SMTP Password:</label>
                                <input type="password" name="smtp_pass" value="" placeholder="<?= !empty($mailConfig['smtp_pass']) ? '••••••• (saved)' : 'Enter password' ?>">
                                <?php if (!empty($mailConfig['smtp_pass'])): ?>
                                <small style="color: #666;">Leave empty to keep current password</small>
                                <?php endif; ?>
                            </div>

                            <div class="setting-row">
                                <label>From Name:</label>
                                <input type="text" name="from_name" value="<?= htmlspecialchars($mailConfig['from_name'] ?? 'WebShare') ?>" placeholder="WebShare">
                            </div>

                            <div class="setting-row">
                                <label>Test Email:</label>
                                <div style="display: flex; gap: 10px;">
                                    <input type="email" id="testEmailAddr" placeholder="test@example.com" style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 8px;">
                                    <button type="button" class="btn" style="background: #2196F3;" onclick="testMailSettings()">📧 Test</button>
                                </div>
                                <div id="testMailResult" style="margin-top: 10px; display: none; padding: 10px; border-radius: 6px;"></div>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-save" style="margin-top: 15px;">💾 Save Email Settings</button>
                    </form>
                </div>

                <!-- Installation Instructions -->
                <div class="setting-group" style="margin-top: 30px; background: #f8f9fa; padding: 25px; border-radius: 12px;">
                    <h3>📦 Installation & Update <span style="float: right; font-size: 14px; color: #4CAF50; font-weight: normal;">Current: v<?= WEBSHARE_VERSION ?></span></h3>
                    <p class="setting-desc">Commands for installing and updating (run as root).</p>

                    <div style="margin-top: 20px;">
                        <h4 style="color: #4CAF50; margin-bottom: 10px;">🔄 Update Existing Installation</h4>
                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;">Updates files while preserving users, config and uploaded files:</p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 20px;">curl -fsSL <?= $baseUrl ?>/get-update | bash</code>
                    </div>

                    <div style="margin-top: 20px; padding-top: 15px; border-top: 1px dashed #ddd;">
                        <h4 style="color: #667eea; margin-bottom: 10px;">📤 WebShare (Fresh Install)</h4>
                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;"><strong>With parameters:</strong></p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 12px; word-break: break-all;">curl -fsSL <?= $baseUrl ?>/get | bash -s -- domain.com admin password</code>

                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;"><strong>Interactive:</strong></p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 12px;">curl -fsSL <?= $baseUrl ?>/get | bash</code>

                        <div style="background: #fff8e1; border-left: 4px solid #ffc107; padding: 12px; border-radius: 4px; margin-top: 15px;">
                            <strong style="color: #f57c00;">⚠️ Requirements before installation:</strong>
                            <ul style="margin: 8px 0 0 0; padding-left: 20px; font-size: 13px; color: #666;">
                                <li>Port <strong>443</strong> (HTTPS) must be open for the application</li>
                                <li>Port <strong>80</strong> (HTTP) must be open for SSL certificate generation</li>
                                <li>Domain DNS must point to this server <strong>before</strong> running the installer</li>
                                <li>Apache2 will be installed automatically if not present</li>
                            </ul>
                        </div>
                    </div>

                    <div style="margin-top: 20px; padding-top: 15px; border-top: 1px dashed #ddd;">
                        <h4 style="color: #667eea; margin-bottom: 10px;">🚀 Speed Test (LibreSpeed + GeoIP)</h4>
                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;"><strong>With parameters:</strong></p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 12px; word-break: break-all;">curl -fsSL <?= $baseUrl ?>/get-speedtest | bash -s -- speed.domain.com</code>

                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;"><strong>Interactive:</strong></p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 12px;">curl -fsSL <?= $baseUrl ?>/get-speedtest | bash</code>

                        <p style="font-size: 13px; color: #888; margin-top: 10px;">GeoIP: Enabled by default (BG only). Config: <code style="background:#eee; padding: 2px 6px; border-radius: 4px;">/var/www/speedtest/.geo.json</code></p>
                    </div>

                    <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #ddd;">
                        <h4 style="color: #e53935; margin-bottom: 10px;">🛡️ Block Default Vhost (IP Access)</h4>
                        <p style="font-size: 13px; color: #666; margin-bottom: 8px;">Prevent access via IP or unknown hostnames:</p>
                        <code style="display:block; background: #2d3748; color: #68d391; padding: 12px; border-radius: 8px; font-size: 11px; margin-bottom: 8px; white-space: pre; overflow-x: auto;"># Create catch-all vhost (run as root)
cat > /etc/apache2/sites-available/000-default.conf &lt;&lt;'EOF'
&lt;VirtualHost *:80&gt;
    ServerName localhost
    Redirect 403 /
    ErrorDocument 403 "Forbidden"
&lt;/VirtualHost&gt;

&lt;VirtualHost *:443&gt;
    ServerName localhost
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    Redirect 403 /
    ErrorDocument 403 "Forbidden"
&lt;/VirtualHost&gt;
EOF
systemctl reload apache2</code>
                    </div>
                </div>
            </div>
        </div><!-- End Settings Tab -->

        <!-- Audit Log Tab (Admin Only) -->
        <div class="tab-content" id="audit-tab">
            <div class="settings-section">
                <h2>📊 Audit Log</h2>

                <?php
                $auditStats = getAuditStats();
                $auditOptions = getAuditFilterOptions();
                ?>

                <!-- Statistics -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px;">
                    <div style="background: #e3f2fd; padding: 20px; border-radius: 10px; text-align: center;">
                        <div style="font-size: 28px; font-weight: bold; color: #1565c0;" id="stat-total"><?= $auditStats['total_entries'] ?></div>
                        <div style="color: #666; font-size: 14px;">Total Events</div>
                    </div>
                    <div style="background: #e8f5e9; padding: 20px; border-radius: 10px; text-align: center;">
                        <div style="font-size: 28px; font-weight: bold; color: #2e7d32;"><?= $auditStats['last_24h'] ?></div>
                        <div style="color: #666; font-size: 14px;">Last 24 Hours</div>
                    </div>
                    <div style="background: #fff3e0; padding: 20px; border-radius: 10px; text-align: center;">
                        <div style="font-size: 28px; font-weight: bold; color: #ef6c00;"><?= count($auditStats['users']) ?></div>
                        <div style="color: #666; font-size: 14px;">Active Users</div>
                    </div>
                    <div style="background: #fce4ec; padding: 20px; border-radius: 10px; text-align: center;">
                        <div style="font-size: 28px; font-weight: bold; color: #c2185b;"><?= count($auditStats['countries']) ?></div>
                        <div style="color: #666; font-size: 14px;">Countries</div>
                    </div>
                </div>

                <!-- Filters -->
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                    <h3 style="margin: 0 0 15px 0; color: #333; font-size: 16px;">🔍 Filters</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px;">
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">User</label>
                            <select id="audit-filter-user" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                                <option value="">All Users</option>
                                <?php foreach ($auditOptions['users'] as $user): ?>
                                    <option value="<?= htmlspecialchars($user) ?>"><?= htmlspecialchars($user) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">Action</label>
                            <select id="audit-filter-action" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                                <option value="">All Actions</option>
                                <?php foreach ($auditOptions['actions'] as $action): ?>
                                    <option value="<?= htmlspecialchars($action) ?>"><?= htmlspecialchars($action) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">IP Address</label>
                            <input type="text" id="audit-filter-ip" placeholder="e.g. 192.168" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; box-sizing: border-box;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">Country</label>
                            <select id="audit-filter-country" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                                <option value="">All Countries</option>
                                <?php foreach (array_keys($auditStats['countries']) as $country): ?>
                                    <option value="<?= htmlspecialchars($country === '' ? '_local_' : $country) ?>"><?= htmlspecialchars($country ?: 'Local') ?> (<?= $auditStats['countries'][$country] ?>)</option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">Search in Details</label>
                            <input type="text" id="audit-filter-search" placeholder="Search text..." style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; box-sizing: border-box;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">Date From</label>
                            <input type="date" id="audit-filter-date-from" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; box-sizing: border-box;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: #666; margin-bottom: 5px;">Date To</label>
                            <input type="date" id="audit-filter-date-to" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; box-sizing: border-box;">
                        </div>
                    </div>
                    <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                        <button onclick="loadAuditLog(1)" style="padding: 8px 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px;">Apply Filters</button>
                        <button onclick="clearAuditFilters()" style="padding: 8px 20px; background: #6c757d; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px;">Clear Filters</button>
                        <button onclick="exportAuditLog()" style="padding: 8px 20px; background: #28a745; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px;">📥 Export CSV</button>
                    </div>
                </div>

                <!-- Results info -->
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px;">
                    <div id="audit-results-info" style="color: #666; font-size: 14px;">Loading...</div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <label style="font-size: 13px; color: #666;">Per page:</label>
                        <select id="audit-per-page" onchange="loadAuditLog(1)" style="padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;">
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                    </div>
                </div>

                <!-- Log table -->
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px;" id="audit-table">
                        <thead>
                            <tr style="background: #f5f5f5;">
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Time</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">User</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Action</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Details</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">IP</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Country</th>
                            </tr>
                        </thead>
                        <tbody id="audit-tbody">
                            <tr><td colspan="6" style="text-align: center; padding: 40px; color: #999;">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <div id="audit-pagination" style="display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 20px; flex-wrap: wrap;">
                </div>

            </div>
        </div><!-- End Audit Log Tab -->

        <?php endif; ?>
    </div>

    <script src="assets/quill/quill.js"></script>
    <script>
        // CSRF token for AJAX requests
        var csrfToken = '<?= htmlspecialchars($_SESSION['csrf_token']) ?>';

        // Global variables for audit log
        var currentAuditPage = 1;
        var auditLogLoaded = false;

        // Action colors for audit log
        var actionColors = {
            'upload': '#4CAF50',
            'public_upload': '#8BC34A',
            'download': '#2196F3',
            'public_download': '#03A9F4',
            'download_decrypted': '#00BCD4',
            'delete': '#f44336',
            'rename': '#ff9800',
            'move': '#FF5722',
            'settings': '#9c27b0',
            'user_add': '#4CAF50',
            'user_delete': '#f44336',
            'user_password': '#ff9800',
            'text_create': '#00bcd4',
            'text_update': '#009688',
            'text_extend': '#26A69A',
            'text_delete': '#f44336',
            'share_create': '#3f51b5',
            'share_revoke': '#E91E63',
            'login': '#673AB7',
            'folder_create': '#795548',
            'folder_delete': '#9E9E9E'
        };

        // Escape HTML for safe display
        function escapeHtml(text) {
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Load audit log data
        function loadAuditLog(page) {
            currentAuditPage = page;
            var tbody = document.getElementById('audit-tbody');
            var resultsInfo = document.getElementById('audit-results-info');
            var pagination = document.getElementById('audit-pagination');

            if (!tbody) return;

            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #999;">Loading...</td></tr>';

            var params = new URLSearchParams({
                audit_action: 'fetch',
                page: page,
                per_page: document.getElementById('audit-per-page') ? document.getElementById('audit-per-page').value : 25,
                filter_user: document.getElementById('audit-filter-user') ? document.getElementById('audit-filter-user').value : '',
                filter_action: document.getElementById('audit-filter-action') ? document.getElementById('audit-filter-action').value : '',
                filter_ip: document.getElementById('audit-filter-ip') ? document.getElementById('audit-filter-ip').value : '',
                filter_country: document.getElementById('audit-filter-country') ? document.getElementById('audit-filter-country').value : '',
                filter_search: document.getElementById('audit-filter-search') ? document.getElementById('audit-filter-search').value : '',
                filter_date_from: document.getElementById('audit-filter-date-from') ? document.getElementById('audit-filter-date-from').value : '',
                filter_date_to: document.getElementById('audit-filter-date-to') ? document.getElementById('audit-filter-date-to').value : ''
            });

            fetch('?' + params.toString(), { credentials: 'include' })
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.json();
                })
                .then(function(data) {
                    if (data.success) {
                        renderAuditTable(data.entries);
                        renderAuditPagination(data.page, data.total_pages, data.filtered, data.total);
                        resultsInfo.textContent = 'Showing ' + data.entries.length + ' of ' + data.filtered + ' entries' +
                            (data.filtered !== data.total ? ' (filtered from ' + data.total + ' total)' : '');
                    } else {
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #e74c3c;">Error: ' + (data.error || 'Unknown error') + '</td></tr>';
                    }
                })
                .catch(function(error) {
                    console.error('Audit log error:', error);
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #e74c3c;">Error loading audit log: ' + error.message + '</td></tr>';
                });
        }

        // Render audit table rows
        function renderAuditTable(entries) {
            var tbody = document.getElementById('audit-tbody');

            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #999;">No entries found</td></tr>';
                return;
            }

            var html = '';
            for (var i = 0; i < entries.length; i++) {
                var entry = entries[i];
                var color = actionColors[entry.action] || '#757575';
                html += '<tr style="border-bottom: 1px solid #eee;">' +
                    '<td style="padding: 10px; white-space: nowrap;">' + escapeHtml(entry.timestamp) + '</td>' +
                    '<td style="padding: 10px;"><span style="background: #e3f2fd; padding: 3px 8px; border-radius: 4px;">' + escapeHtml(entry.user) + '</span></td>' +
                    '<td style="padding: 10px;"><span style="background: ' + color + '; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px;">' + escapeHtml(entry.action) + '</span></td>' +
                    '<td style="padding: 10px; max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="' + escapeHtml(entry.details) + '">' + escapeHtml(entry.details) + '</td>' +
                    '<td style="padding: 10px; font-family: monospace; font-size: 12px;">' + escapeHtml(entry.ip) + '</td>' +
                    '<td style="padding: 10px;"><span style="background: #f5f5f5; padding: 3px 8px; border-radius: 4px;">' + escapeHtml(entry.country) + '</span></td>' +
                    '</tr>';
            }
            tbody.innerHTML = html;
        }

        // Render pagination controls
        function renderAuditPagination(currentPage, totalPages, filtered, total) {
            var pagination = document.getElementById('audit-pagination');

            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }

            var html = '';

            if (currentPage > 1) {
                html += '<button onclick="loadAuditLog(' + (currentPage - 1) + ')" style="padding: 8px 12px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;">← Prev</button>';
            }

            var startPage = Math.max(1, currentPage - 2);
            var endPage = Math.min(totalPages, currentPage + 2);

            if (startPage > 1) {
                html += '<button onclick="loadAuditLog(1)" style="padding: 8px 12px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;">1</button>';
                if (startPage > 2) {
                    html += '<span style="padding: 8px;">...</span>';
                }
            }

            for (var i = startPage; i <= endPage; i++) {
                var isActive = i === currentPage;
                html += '<button onclick="loadAuditLog(' + i + ')" style="padding: 8px 12px; border: 1px solid ' + (isActive ? '#667eea' : '#ddd') + '; background: ' + (isActive ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 'white') + '; color: ' + (isActive ? 'white' : '#333') + '; border-radius: 4px; cursor: pointer; font-weight: ' + (isActive ? 'bold' : 'normal') + ';">' + i + '</button>';
            }

            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += '<span style="padding: 8px;">...</span>';
                }
                html += '<button onclick="loadAuditLog(' + totalPages + ')" style="padding: 8px 12px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;">' + totalPages + '</button>';
            }

            if (currentPage < totalPages) {
                html += '<button onclick="loadAuditLog(' + (currentPage + 1) + ')" style="padding: 8px 12px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;">Next →</button>';
            }

            pagination.innerHTML = html;
        }

        // Clear all filters
        function clearAuditFilters() {
            document.getElementById('audit-filter-user').value = '';
            document.getElementById('audit-filter-action').value = '';
            document.getElementById('audit-filter-ip').value = '';
            document.getElementById('audit-filter-country').value = '';
            document.getElementById('audit-filter-search').value = '';
            document.getElementById('audit-filter-date-from').value = '';
            document.getElementById('audit-filter-date-to').value = '';
            loadAuditLog(1);
        }

        // Export audit log as CSV
        function exportAuditLog() {
            window.location.href = '?audit_action=export';
        }

        // Logout function for HTTP Basic Auth
        function doLogout() {
            // Clear credentials by making request with wrong credentials
            var xhr = new XMLHttpRequest();
            xhr.open('GET', window.location.href, true, 'logout', 'logout');
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    window.location.href = '/u';
                }
            };
            xhr.send();

            // Also try the modern way
            if (document.execCommand) {
                document.execCommand('ClearAuthenticationCache', false);
            }

            // Redirect to public page
            setTimeout(function() {
                window.location.href = '/u';
            }, 100);

            return false;
        }

        // Drag and drop functionality
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        let currentXHR = null;
        let currentFileName = null;
        let uploadQueue = [];
        let isUploading = false;
        let currentFileIndex = 0;
        let totalFiles = 0;

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

        // Handle file select via click - start upload
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                addFilesToQueue(fileInput.files);
            }
        });

        // Add files to upload queue
        function addFilesToQueue(files) {
            // Validate encryption settings first
            if (!validateEncryption()) {
                return; // Don't start upload if encryption validation fails
            }

            uploadQueue = Array.from(files);
            totalFiles = uploadQueue.length;
            currentFileIndex = 0;
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
            const encryptCheck = document.getElementById('encryptCheck');
            if (encryptCheck && encryptCheck.checked) {
                const encryptPassword = document.getElementById('encryptPassword').value;
                formData.append('encrypt_password', encryptPassword);
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
                        uploadSpeed.textContent = formatSpeedBytes(speed);

                        // Calculate time remaining
                        const remaining = e.total - e.loaded;
                        const timeLeft = remaining / speed;
                        timeRemaining.textContent = formatTimeSeconds(timeLeft);

                        lastLoaded = e.loaded;
                        lastTime = currentTime;
                    }

                    // Update uploaded size
                    uploadedSize.textContent = formatUploadBytes(e.loaded) + ' / ' + formatUploadBytes(e.total);
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
                        // All files uploaded, reload page
                        setTimeout(() => {
                            window.location.reload();
                        }, 1000);
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
            xhr.send(formData);
        }

        // Stop upload function
        function stopUpload() {
            if (currentXHR) {
                currentXHR.abort();

                // Delete partially uploaded file
                if (currentFileName) {
                    const formData = new FormData();
                    formData.append('csrf_token', csrfToken);
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

        // Format bytes for upload
        function formatUploadBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Format speed
        function formatSpeedBytes(bytesPerSecond) {
            return formatUploadBytes(bytesPerSecond) + '/s';
        }

        // Format time (seconds to MM:SS)
        function formatTimeSeconds(seconds) {
            if (!isFinite(seconds) || seconds < 0) return '--:--';
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            return mins.toString().padStart(2, '0') + ':' + secs.toString().padStart(2, '0');
        }

        let encryptionCollapsed = false;

        // Toggle encryption password fields
        function toggleEncryptPassword() {
            const checkbox = document.getElementById('encryptCheck');
            const fields = document.getElementById('encryptPasswordFields');
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
        function toggleEncryptCollapse() {
            const fields = document.getElementById('encryptPasswordFields');
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

        // Web Download functions
        let webDownloadData = null;

        function toggleWebDownload() {
            const form = document.getElementById('webDownloadForm');
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
            if (form.style.display === 'block') {
                document.getElementById('webDownloadUrl').focus();
            }
        }

        async function checkWebUrl() {
            const url = document.getElementById('webDownloadUrl').value.trim();
            const infoDiv = document.getElementById('webDownloadInfo');
            const errorDiv = document.getElementById('webDownloadError');
            const progressDiv = document.getElementById('webDownloadProgress');

            // Reset state
            infoDiv.style.display = 'none';
            errorDiv.style.display = 'none';
            progressDiv.style.display = 'none';
            webDownloadData = null;

            if (!url) {
                showWebDownloadError('Моля, въведи URL');
                return;
            }

            // Basic URL validation
            if (!url.match(/^https?:\/\/.+/i)) {
                showWebDownloadError('Невалиден URL. Трябва да започва с http:// или https://');
                return;
            }

            // Show checking state
            const checkBtn = document.querySelector('.web-download-input-group button');
            const originalText = checkBtn.textContent;
            checkBtn.textContent = 'Проверка...';
            checkBtn.disabled = true;

            try {
                const formData = new FormData();
                formData.append('url', url);
                formData.append('action', 'info');
                formData.append('folder', '<?= htmlspecialchars($currentFolder) ?>');

                const response = await fetch('web-download.php', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                const result = await response.json();

                if (result.success) {
                    webDownloadData = {
                        url: url,
                        filename: result.suggestedFilename || result.filename,
                        originalFilename: result.filename,
                        fileExists: result.fileExists,
                        size: result.size,
                        sizeFormatted: result.sizeFormatted
                    };

                    // Update filename input
                    const filenameInput = document.getElementById('webDownloadFileNameInput');
                    filenameInput.value = webDownloadData.filename;
                    document.getElementById('webDownloadFileSize').textContent = result.sizeFormatted;

                    // Show/hide file exists warning
                    const existsWarning = document.getElementById('webDownloadExistsWarning');
                    const overwriteOption = document.getElementById('webDownloadOverwrite');
                    if (result.fileExists) {
                        existsWarning.style.display = 'block';
                        existsWarning.innerHTML = '⚠️ Файл <strong>' + result.filename + '</strong> съществува. Ще бъде запазен като <strong>' + result.suggestedFilename + '</strong> или избери презаписване.';
                        overwriteOption.style.display = 'block';
                    } else {
                        existsWarning.style.display = 'none';
                        overwriteOption.style.display = 'none';
                    }
                    document.getElementById('webDownloadOverwriteCheck').checked = false;

                    infoDiv.style.display = 'block';
                } else {
                    showWebDownloadError(result.error || 'Грешка при проверка на URL');
                }
            } catch (error) {
                showWebDownloadError('Грешка при връзка със сървъра');
            } finally {
                checkBtn.textContent = originalText;
                checkBtn.disabled = false;
            }
        }

        async function startWebDownload() {
            if (!webDownloadData) {
                showWebDownloadError('Първо провери URL');
                return;
            }

            const infoDiv = document.getElementById('webDownloadInfo');
            const errorDiv = document.getElementById('webDownloadError');
            const progressDiv = document.getElementById('webDownloadProgress');
            const progressBar = document.getElementById('webDownloadProgressBar');

            // Show progress
            infoDiv.style.display = 'none';
            errorDiv.style.display = 'none';
            progressDiv.style.display = 'block';
            progressBar.textContent = 'Сваляне...';
            progressBar.style.width = '100%';
            progressBar.style.animation = 'pulse 1.5s infinite';

            try {
                // Get filename from input (user may have edited it)
                const filenameInput = document.getElementById('webDownloadFileNameInput');
                const filename = filenameInput.value.trim() || webDownloadData.filename;
                const overwrite = document.getElementById('webDownloadOverwriteCheck').checked;

                const formData = new FormData();
                formData.append('url', webDownloadData.url);
                formData.append('filename', filename);
                formData.append('action', 'download');
                formData.append('folder', '<?= htmlspecialchars($currentFolder) ?>');
                formData.append('overwrite', overwrite ? 'true' : 'false');

                const response = await fetch('web-download.php', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                const result = await response.json();

                if (result.success) {
                    progressBar.style.animation = 'none';
                    progressBar.textContent = 'Готово! ' + result.filename + ' (' + result.sizeFormatted + ')';
                    progressBar.style.background = 'linear-gradient(135deg, #4CAF50 0%, #45a049 100%)';

                    // Reset after 2 seconds and reload
                    setTimeout(() => {
                        document.getElementById('webDownloadForm').style.display = 'none';
                        document.getElementById('webDownloadUrl').value = '';
                        progressDiv.style.display = 'none';
                        progressBar.style.background = '';
                        webDownloadData = null;
                        location.reload();
                    }, 2000);
                } else {
                    progressDiv.style.display = 'none';
                    infoDiv.style.display = 'block';
                    showWebDownloadError(result.error || 'Грешка при сваляне');
                }
            } catch (error) {
                progressDiv.style.display = 'none';
                infoDiv.style.display = 'block';
                showWebDownloadError('Грешка при връзка със сървъра');
            }
        }

        function showWebDownloadError(message) {
            const errorDiv = document.getElementById('webDownloadError');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        // Clear field error and validation states
        function clearFieldError(fieldId) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            if (field) field.classList.remove('error', 'valid', 'invalid');
            if (errorSpan) {
                errorSpan.classList.remove('visible');
                errorSpan.textContent = '';
            }
        }

        // Show field error
        function showFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            if (field) {
                field.classList.remove('valid', 'invalid');
                field.classList.add('error');
            }
            if (errorSpan) {
                errorSpan.textContent = message;
                errorSpan.classList.add('visible');
            }
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
                // Too short - neutral/typing state
                passField.classList.remove('valid', 'error');
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
                // Doesn't match - yellow
                confirmField.classList.remove('valid', 'error');
                confirmField.classList.add('invalid');
            }
        }

        // Show encryption option - now always visible, this function is kept for compatibility
        function showEncryptOption(show) {
            // Encryption option is now always visible
            // This function is kept for compatibility but doesn't hide the section anymore
        }

        // Validate encryption passwords match
        function validateEncryption() {
            const checkbox = document.getElementById('encryptCheck');
            if (!checkbox || !checkbox.checked) return true;

            // Make sure fields are visible for validation
            if (encryptionCollapsed) {
                toggleEncryptCollapse();
            }

            const pass1 = document.getElementById('encryptPassword').value;
            const pass2 = document.getElementById('encryptPasswordConfirm').value;

            // Clear previous errors
            clearFieldError('encryptPassword');
            clearFieldError('encryptPasswordConfirm');

            if (pass1.length < 4) {
                showFieldError('encryptPassword', 'Паролата трябва да е поне 4 знака');
                return false;
            }
            if (pass1 !== pass2) {
                showFieldError('encryptPasswordConfirm', 'Паролите не съвпадат');
                return false;
            }
            return true;
        }

        // Start upload with encryption validation
        function startUpload() {
            if (!validateEncryption()) return;

            const fileInput = document.getElementById('fileInput');
            if (fileInput.files.length > 0) {
                addFilesToQueue(fileInput.files);
            }
        }

        // Share link functionality
        async function generateShareLink(filename, index, folder) {
            const shareDiv = document.getElementById('share-' + index);
            const urlInput = document.getElementById('url-' + index);

            try {
                const formData = new FormData();
                formData.append('filename', filename);
                if (folder) {
                    formData.append('folder', folder);
                }

                const response = await fetch('share.php?action=generate', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    urlInput.value = data.url;
                    shareDiv.style.display = 'block';
                }
            } catch (error) {
                // Silently fail
            }
        }

        async function regenerateShareLink(filename, index, folder) {
            const shareDiv = document.getElementById('share-' + index);
            const urlInput = document.getElementById('url-' + index);
            const btn = event.target;

            try {
                btn.disabled = true;
                btn.textContent = '...';

                const formData = new FormData();
                formData.append('filename', filename);
                if (folder) {
                    formData.append('folder', folder);
                }

                const response = await fetch('share.php?action=regenerate', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    urlInput.value = data.url;
                    shareDiv.style.display = 'block';

                    // Visual feedback
                    btn.textContent = 'Done!';
                    setTimeout(() => {
                        btn.textContent = 'New ID';
                        btn.disabled = false;
                    }, 1500);
                } else {
                    btn.textContent = 'Error';
                    setTimeout(() => {
                        btn.textContent = 'New ID';
                        btn.disabled = false;
                    }, 2000);
                }
            } catch (error) {
                btn.textContent = 'New ID';
                btn.disabled = false;
            }
        }

        function copyShareLink(index) {
            const urlInput = document.getElementById('url-' + index);
            urlInput.select();
            urlInput.setSelectionRange(0, 99999); // For mobile devices

            try {
                navigator.clipboard.writeText(urlInput.value).then(() => {
                    const btn = event.target;
                    const originalText = btn.textContent;
                    btn.textContent = 'Copied!';
                    setTimeout(() => {
                        btn.textContent = originalText;
                    }, 2000);
                }).catch(() => {
                    // Fallback for older browsers
                    document.execCommand('copy');
                });
            } catch (err) {
                document.execCommand('copy');
            }
        }

        // API Key Management Functions
        function generateNewKey() {
            const name = document.getElementById('newKeyName').value.trim();
            const ips = document.getElementById('newKeyIps').value.trim();

            const formData = new FormData();
            formData.append('api_action', 'generate');
            formData.append('key_name', name);
            formData.append('allowed_ips', ips);
            formData.append('csrf_token', csrfToken);

            fetch(window.location.pathname, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Show the new key in modal
                    document.getElementById('newKeyValue').textContent = data.key;
                    document.getElementById('newKeyModal').style.display = 'flex';
                    // Clear form
                    document.getElementById('newKeyName').value = '';
                    document.getElementById('newKeyIps').value = '';
                } else {
                    alert('Error: ' + (data.error || 'Failed to generate key'));
                }
            })
            .catch(error => {
                alert('Network error: ' + error.message);
            });
        }

        function copyNewKey() {
            const key = document.getElementById('newKeyValue').textContent;
            navigator.clipboard.writeText(key).then(() => {
                alert('Key copied to clipboard!');
            });
        }

        function closeNewKeyModal() {
            document.getElementById('newKeyModal').style.display = 'none';
            // Reload page to show updated keys list
            location.reload();
        }

        function revokeKey(keyId, keyName) {
            if (!confirm('Are you sure you want to revoke the API key "' + keyName + '"?\n\nThis cannot be undone.')) {
                return;
            }

            const formData = new FormData();
            formData.append('api_action', 'revoke');
            formData.append('key_id', keyId);
            formData.append('csrf_token', csrfToken);

            fetch(window.location.pathname, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove row from table
                    const row = document.querySelector('tr[data-key-id="' + keyId + '"]');
                    if (row) row.remove();
                    // Check if table is empty
                    const tbody = document.querySelector('#apiKeysList tbody');
                    if (tbody && tbody.children.length === 0) {
                        location.reload();
                    }
                } else {
                    alert('Error: ' + (data.error || 'Failed to revoke key'));
                }
            })
            .catch(error => {
                alert('Network error: ' + error.message);
            });
        }

        function editKeyIps(keyId, currentIps) {
            const newIps = prompt('Enter allowed IPs:\n\n• Empty = Auto-learn (locks to first IP used)\n• 0.0.0.0/0 = Allow from anywhere\n• 192.168.1.100 = Specific IP\n• 192.168.1.0/24 = Subnet (CIDR)\n\nMultiple: comma separated', currentIps);

            if (newIps === null) return; // Cancelled

            const formData = new FormData();
            formData.append('api_action', 'update_ips');
            formData.append('key_id', keyId);
            formData.append('allowed_ips', newIps.trim());
            formData.append('csrf_token', csrfToken);

            fetch(window.location.pathname, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + (data.error || 'Failed to update IPs'));
                }
            })
            .catch(error => {
                alert('Network error: ' + error.message);
            });
        }

        function copyApiKey() {
            const apiKeyDisplay = document.getElementById('apiKeyDisplay');
            if (!apiKeyDisplay) return;
            const apiKey = apiKeyDisplay.textContent;

            navigator.clipboard.writeText(apiKey).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = originalText, 2000);
            });
        }

        // Email share functions
        function showEmailModal(index, filename) {
            const urlInput = document.getElementById('url-' + index);
            if (!urlInput || !urlInput.value) {
                alert('Please generate a share link first by clicking the Share button.');
                return;
            }

            document.getElementById('emailShareUrl').value = urlInput.value;
            document.getElementById('emailFileName').value = filename;
            document.getElementById('emailTo').value = '';
            document.getElementById('emailSenderName').value = '';
            document.getElementById('emailMessage').value = '';
            document.getElementById('emailStatus').style.display = 'none';
            document.getElementById('sendEmailBtn').disabled = false;
            document.getElementById('emailModal').style.display = 'flex';
            document.getElementById('emailTo').focus();
        }

        function closeEmailModal() {
            document.getElementById('emailModal').style.display = 'none';
        }

        function showChangelogModal() {
            document.getElementById('changelogModal').classList.add('show');
        }

        function closeChangelogModal() {
            document.getElementById('changelogModal').classList.remove('show');
        }

        function showAboutModal() {
            document.getElementById('aboutModal').classList.add('show');
        }
        function closeAboutModal() {
            document.getElementById('aboutModal').classList.remove('show');
        }

        // Update system
        let updateData = null;

        function showUpdateModal() {
            document.getElementById('updateModal').classList.add('show');
            // If we don't have data yet, check now
            if (!updateData) {
                checkForUpdates(true);
            } else {
                renderUpdateModal();
            }
        }
        function closeUpdateModal() {
            document.getElementById('updateModal').classList.remove('show');
        }

        function renderUpdateModal() {
            const content = document.getElementById('updateContent');
            const currentVersion = '<?= WEBSHARE_VERSION ?>';

            if (!updateData) {
                content.innerHTML = '<p style="text-align: center; color: #666;">Checking for updates...</p>';
                return;
            }

            let html = '<div style="text-align: center; margin-bottom: 20px;">';
            html += '<p style="margin: 5px 0;"><strong>Current Version:</strong> v' + currentVersion + '</p>';

            // Show update source
            const source = updateData.source || 'unknown';
            const sourceLabel = source === 'github' ? 'GitHub (stable)' : (source === 'dev' ? 'Dev Server (beta)' : source);
            const sourceColor = source === 'github' ? '#4CAF50' : '#ff9800';
            html += '<p style="margin: 5px 0; font-size: 11px;"><span style="background: ' + sourceColor + '; color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px;">' + sourceLabel + '</span></p>';

            if (updateData.error && !updateData.latest_version) {
                html += '<p style="color: #f44336;">' + updateData.error + '</p>';
            } else if (updateData.update_available) {
                html += '<p style="margin: 5px 0;"><strong>Latest Version:</strong> <span style="color: #4CAF50; font-weight: bold;">v' + updateData.latest_version + '</span></p>';
                html += '<p style="color: #4CAF50; margin: 15px 0;">New version available!</p>';
            } else {
                html += '<p style="margin: 5px 0;"><strong>Latest Version:</strong> v' + (updateData.latest_version || currentVersion) + '</p>';
                html += '<p style="color: #888; margin: 15px 0;">You are running the latest version.</p>';
            }

            if (updateData.from_cache) {
                const ageMinutes = Math.round((updateData.cache_age || 0) / 60);
                html += '<p style="font-size: 11px; color: #999;">Last checked: ' + (ageMinutes < 60 ? ageMinutes + ' minutes ago' : Math.round(ageMinutes/60) + ' hours ago') + '</p>';
            }

            html += '</div>';

            // Release notes
            if (updateData.update_available && updateData.release_notes) {
                html += '<div style="background: #f5f5f5; padding: 12px; border-radius: 8px; margin: 15px 0; max-height: 150px; overflow-y: auto;">';
                html += '<p style="margin: 0 0 8px 0; font-weight: bold; font-size: 13px;">Release Notes:</p>';
                html += '<div style="font-size: 12px; color: #555; white-space: pre-wrap;">' + escapeHtml(updateData.release_notes) + '</div>';
                html += '</div>';
            }

            content.innerHTML = html;

            // Update button states - always show Live Update for admins
            const liveUpdateBtn = document.getElementById('liveUpdateBtn');
            if (liveUpdateBtn) {
                // Always show - allows force update even if versions match
                liveUpdateBtn.style.display = 'inline-block';
                // Change color if update available
                if (updateData.update_available) {
                    liveUpdateBtn.style.background = '#4CAF50';
                    liveUpdateBtn.textContent = 'Live Update ↑';
                } else {
                    liveUpdateBtn.style.background = '#607D8B';
                    liveUpdateBtn.textContent = 'Force Update';
                }
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function checkForUpdates(force = false) {
            const content = document.getElementById('updateContent');
            const checkBtn = document.getElementById('checkUpdateBtn');

            if (content) {
                content.innerHTML = '<p style="text-align: center; color: #666;"><span class="spinner"></span> Checking for updates...</p>';
            }
            if (checkBtn) {
                checkBtn.disabled = true;
            }

            try {
                const url = 'check-version.php' + (force ? '?force=1' : '');
                const response = await fetch(url);
                updateData = await response.json();

                // Update version link indicator (subtle)
                const versionLink = document.getElementById('versionLink');
                if (versionLink && updateData.update_available) {
                    versionLink.style.color = '#e65100';
                    versionLink.innerHTML = 'v<?= WEBSHARE_VERSION ?> <span style="color:#4CAF50;font-size:10px;">↑</span>';
                    versionLink.title = 'Update available: v' + updateData.latest_version + ' (click to update)';
                }

                renderUpdateModal();
            } catch (error) {
                if (content) {
                    content.innerHTML = '<p style="text-align: center; color: #f44336;">Failed to check for updates</p>';
                }
            }

            if (checkBtn) {
                checkBtn.disabled = false;
            }
        }

        async function doLiveUpdate() {
            if (!confirm('This will update WebShare from webshare.techbg.net. Continue?')) return;

            const content = document.getElementById('updateContent');
            const liveUpdateBtn = document.getElementById('liveUpdateBtn');
            const checkBtn = document.getElementById('checkUpdateBtn');

            liveUpdateBtn.disabled = true;
            checkBtn.disabled = true;

            // Show progress
            content.innerHTML = '<div style="text-align: left; font-size: 13px;">' +
                '<p style="margin: 5px 0;"><span class="spinner" style="display:inline-block;width:14px;height:14px;margin-right:8px;"></span>Starting update...</p>' +
                '</div>';

            try {
                const response = await fetch('live-update.php', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
                const result = await response.json();

                if (result.success) {
                    // Show success with steps
                    let html = '<div style="text-align: left; font-size: 13px;">';
                    if (result.steps) {
                        result.steps.forEach(step => {
                            const icon = step.status === 'done' ? '✓' : (step.status === 'failed' ? '✗' : '...');
                            const color = step.status === 'done' ? '#4CAF50' : (step.status === 'failed' ? '#f44336' : '#666');
                            html += '<p style="margin: 5px 0; color: ' + color + ';">' + icon + ' ' + step.step;
                            if (step.detail) html += ' <span style="color:#888;">(' + step.detail + ')</span>';
                            html += '</p>';
                        });
                    }
                    html += '<p style="margin: 15px 0 5px 0; color: #4CAF50; font-weight: bold; text-align: center;">Update complete!</p>';
                    html += '<p style="color: #666; text-align: center; font-size: 12px;">Reloading in 2 seconds...</p>';
                    html += '</div>';
                    content.innerHTML = html;
                    setTimeout(() => location.reload(true), 2000);
                } else {
                    // Show error with steps
                    let html = '<div style="text-align: left; font-size: 13px;">';
                    if (result.steps) {
                        result.steps.forEach(step => {
                            const icon = step.status === 'done' ? '✓' : (step.status === 'failed' ? '✗' : '...');
                            const color = step.status === 'done' ? '#4CAF50' : (step.status === 'failed' ? '#f44336' : '#666');
                            html += '<p style="margin: 5px 0; color: ' + color + ';">' + icon + ' ' + step.step + '</p>';
                        });
                    }
                    html += '<p style="margin: 15px 0 5px 0; color: #f44336; text-align: center;">Update failed</p>';
                    html += '<p style="color: #666; text-align: center; font-size: 12px;">' + (result.error || 'Unknown error') + '</p>';
                    html += '</div>';
                    content.innerHTML = html;
                    liveUpdateBtn.disabled = false;
                    checkBtn.disabled = false;
                }
            } catch (error) {
                content.innerHTML = '<p style="text-align: center; color: #f44336;">Update failed: ' + error.message + '</p>';
                liveUpdateBtn.disabled = false;
                checkBtn.disabled = false;
            }
        }

        // Auto-check for updates on page load (non-blocking)
        function initUpdateCheck() {
            const autoCheck = localStorage.getItem('webshare_auto_update_check') !== 'false';
            document.getElementById('autoUpdateCheck').checked = autoCheck;

            // Load beta server preference
            fetch('?action=get_update_source')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('useBetaServer').checked = !data.stable;
                })
                .catch(() => {});

            if (autoCheck) {
                // Delay check to not block page load
                setTimeout(() => checkForUpdates(false), 3000);
            }
        }

        function toggleAutoUpdateCheck() {
            const checked = document.getElementById('autoUpdateCheck').checked;
            localStorage.setItem('webshare_auto_update_check', checked ? 'true' : 'false');
        }

        async function toggleBetaServer() {
            const useBeta = document.getElementById('useBetaServer').checked;
            try {
                await fetch('?action=set_update_source', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrfToken },
                    body: 'use_beta=' + (useBeta ? '1' : '0')
                });
            } catch (e) {
                console.error('Failed to save update source preference');
            }
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', initUpdateCheck);

        async function sendShareEmail() {
            const toEmail = document.getElementById('emailTo').value.trim();
            const shareUrl = document.getElementById('emailShareUrl').value;
            const filename = document.getElementById('emailFileName').value;
            const senderName = document.getElementById('emailSenderName').value.trim();
            const message = document.getElementById('emailMessage').value.trim();
            const statusDiv = document.getElementById('emailStatus');
            const sendBtn = document.getElementById('sendEmailBtn');

            // Validate email
            if (!toEmail || !toEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
                statusDiv.style.display = 'block';
                statusDiv.style.background = '#fee2e2';
                statusDiv.style.color = '#dc2626';
                statusDiv.textContent = 'Please enter a valid email address.';
                return;
            }

            // Show sending status
            sendBtn.disabled = true;
            sendBtn.textContent = 'Sending...';
            statusDiv.style.display = 'block';
            statusDiv.style.background = '#e0f2fe';
            statusDiv.style.color = '#0277bd';
            statusDiv.textContent = 'Sending email...';

            try {
                const formData = new FormData();
                formData.append('email', toEmail);
                formData.append('url', shareUrl);
                formData.append('filename', filename);
                formData.append('sender_name', senderName);
                formData.append('message', message);

                const response = await fetch('send-mail.php', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    statusDiv.style.background = '#d4edda';
                    statusDiv.style.color = '#155724';
                    statusDiv.textContent = 'Email sent successfully!';
                    sendBtn.textContent = 'Sent!';
                    setTimeout(() => {
                        closeEmailModal();
                    }, 2000);
                } else {
                    statusDiv.style.background = '#fee2e2';
                    statusDiv.style.color = '#dc2626';
                    statusDiv.textContent = data.error || 'Failed to send email.';
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Send Email';
                }
            } catch (error) {
                statusDiv.style.background = '#fee2e2';
                statusDiv.style.color = '#dc2626';
                statusDiv.textContent = 'Failed to send email. Please try again.';
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send Email';
            }
        }

        // Close email modal when clicking outside
        document.getElementById('emailModal')?.addEventListener('click', function(e) {
            if (e.target === this) {
                closeEmailModal();
            }
        });

        // Mail settings functions
        function toggleMailSettings() {
            const enabled = document.getElementById('mail_enabled').checked;
            const fields = document.getElementById('mailSettingsFields');
            if (fields) {
                fields.style.display = enabled ? 'block' : 'none';
            }
        }

        async function testMailSettings() {
            const testEmail = document.getElementById('testEmailAddr').value.trim();
            const resultDiv = document.getElementById('testMailResult');

            if (!testEmail || !testEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
                resultDiv.style.display = 'block';
                resultDiv.style.background = '#fee2e2';
                resultDiv.style.color = '#dc2626';
                resultDiv.textContent = 'Please enter a valid email address';
                return;
            }

            // Get form values
            const form = document.getElementById('mailSettingsForm');
            const formData = new FormData(form);
            formData.append('test_email', testEmail);
            formData.delete('save_mail');
            formData.append('test_mail', '1');

            resultDiv.style.display = 'block';
            resultDiv.style.background = '#e0f2fe';
            resultDiv.style.color = '#0277bd';
            resultDiv.textContent = 'Sending test email...';

            try {
                const response = await fetch('send-mail.php?action=test', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    resultDiv.style.background = '#d4edda';
                    resultDiv.style.color = '#155724';
                    resultDiv.textContent = 'Test email sent successfully! Check your inbox.';
                } else {
                    resultDiv.style.background = '#fee2e2';
                    resultDiv.style.color = '#dc2626';
                    resultDiv.textContent = 'Failed: ' + (data.error || 'Unknown error');
                }
            } catch (error) {
                resultDiv.style.background = '#fee2e2';
                resultDiv.style.color = '#dc2626';
                resultDiv.textContent = 'Failed to send test email';
            }
        }

        async function renameFile(oldName, index) {
            const newName = prompt('Enter new filename:', oldName);

            if (!newName || newName === oldName) {
                return;
            }

            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('rename', '1');
                formData.append('old_name', oldName);
                formData.append('new_name', newName);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    window.location.reload();
                }
            } catch (error) {
                // Silently fail
            }
        }

        async function deleteFile(filename) {
            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('delete', filename);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    window.location.reload();
                }
            } catch (error) {
                // Silently fail
            }
        }

        // ========================================
        // Text Sharing Functionality
        // ========================================

        // Initialize Quill Rich Text Editor
        let quill = null;
        if (document.getElementById('editor-container')) {
            quill = new Quill('#editor-container', {
                theme: 'snow',
                modules: {
                    toolbar: [
                        ['bold', 'italic', 'underline', 'strike'],
                        ['blockquote', 'code-block'],
                        [{ 'header': 1 }, { 'header': 2 }],
                        [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                        ['link'],
                        ['clean']
                    ]
                },
                placeholder: 'Type or paste your text here...'
            });

            // Character counter
            quill.on('text-change', function() {
                const text = quill.getText();
                const length = text.length - 1; // Subtract trailing newline
                document.getElementById('charCount').textContent = length.toLocaleString();

                // Warn if approaching limit
                if (length > 900000) {
                    document.getElementById('charCount').style.color = '#f44336';
                } else {
                    document.getElementById('charCount').style.color = '#666';
                }
            });
        }

        // Tab switching function
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });

            // Remove active class from all tab buttons
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');

            // Add active class to correct button
            document.querySelectorAll('.tab').forEach(btn => {
                const tabMap = {'files': 'Files', 'texts': 'Chats', 'help': 'Help', 'settings': 'Settings', 'audit': 'Audit'};
                if (btn.textContent.includes(tabMap[tabName])) {
                    btn.classList.add('active');
                }
            });

            // Save to localStorage (except settings - always start fresh)
            if (tabName !== 'settings') {
                localStorage.setItem('activeTab', tabName);
            }

            // Load audit log when audit tab is opened
            if (tabName === 'audit' && typeof loadAuditLog === 'function') {
                loadAuditLog(1);
            }
        }

        // Help tab accordion toggle
        function toggleHelpSection(section) {
            const content = document.getElementById(section + '-content');
            const icon = document.getElementById(section + '-icon');

            if (content.classList.contains('open')) {
                content.classList.remove('open');
                icon.classList.remove('open');
            } else {
                content.classList.add('open');
                icon.classList.add('open');
            }
        }

        // Copy code to clipboard
        function copyCode(btn) {
            const codeBlock = btn.parentElement;
            const code = codeBlock.querySelector('code, pre');
            let text = code.textContent || code.innerText;

            // Clean up the text
            text = text.trim();

            navigator.clipboard.writeText(text).then(() => {
                const originalText = btn.textContent;
                btn.textContent = '✓';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.classList.remove('copied');
                }, 1500);
            }).catch(err => {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);

                btn.textContent = '✓';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = '📋';
                    btn.classList.remove('copied');
                }, 1500);
            });
        }

        // Restore active tab on page load
        (function() {
            // Check URL parameter first (for direct links)
            const urlParams = new URLSearchParams(window.location.search);
            const tabParam = urlParams.get('tab');
            if (tabParam && document.getElementById(tabParam + '-tab')) {
                switchTab(tabParam);
                return;
            }

            // Check URL hash
            const hash = window.location.hash.replace('#', '');
            if (hash && document.getElementById(hash + '-tab')) {
                switchTab(hash);
                return;
            }

            const savedTab = localStorage.getItem('activeTab');
            // Only restore 'texts' tab, always default to 'files' for others
            if (savedTab === 'texts') {
                const tabElement = document.getElementById(savedTab + '-tab');
                if (tabElement) {
                    switchTab(savedTab);
                }
            }
            // Clean up any old settings value
            if (savedTab === 'settings') {
                localStorage.removeItem('activeTab');
            }
        })();

        // Share text function
        async function shareText() {
            if (!quill) return;

            const html = quill.root.innerHTML;
            const text = quill.getText().trim();
            const authorInput = document.getElementById('chat-author-name');
            const author = authorInput ? authorInput.value.trim() || 'Creator' : 'Creator';

            if (text.length === 0) {
                return;
            }

            if (text.length > 1000000) {
                alert('Text too large. Maximum 1,000,000 characters.');
                return;
            }

            // Save author name to localStorage
            if (authorInput && authorInput.value.trim()) {
                localStorage.setItem('chat_username', authorInput.value.trim());
            }

            try {
                const formData = new FormData();
                formData.append('create', '1');
                formData.append('html', html);
                formData.append('author', author);

                const response = await fetch('/t', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    const viewUrlInput = document.getElementById('text-view-url');
                    const shareResult = document.getElementById('text-share-result');

                    viewUrlInput.value = result.view_url || result.url;
                    shareResult.style.display = 'block';

                    // Save user ID for this conversation
                    if (result.user_id && result.token) {
                        localStorage.setItem('chat_user_id_' + result.token, result.user_id);
                    }

                    // Copy link to clipboard
                    navigator.clipboard.writeText(result.view_url || result.url);

                    // Clear editor
                    quill.setText('');

                    // Reload after showing URL
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                }
            } catch (error) {
                // Silently fail
            }
        }

        // Load saved chat username
        document.addEventListener('DOMContentLoaded', () => {
            const authorInput = document.getElementById('chat-author-name');
            if (authorInput) {
                const savedName = localStorage.getItem('chat_username');
                if (savedName) {
                    authorInput.value = savedName;
                }
            }
        });

        // Copy text view URL
        function copyTextViewUrl() {
            const urlInput = document.getElementById('text-view-url');
            urlInput.select();
            navigator.clipboard.writeText(urlInput.value);
        }

        // Copy text edit URL
        function copyTextEditUrl() {
            const urlInput = document.getElementById('text-edit-url');
            urlInput.select();
            urlInput.setSelectionRange(0, 99999);

            navigator.clipboard.writeText(urlInput.value).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            });
        }

        // Share existing text (toggle share URL)
        function shareExistingText(token) {
            const shareDiv = document.getElementById('share-text-' + token);
            if (shareDiv.style.display === 'block') {
                shareDiv.style.display = 'none';
            } else {
                shareDiv.style.display = 'block';
            }
        }

        // Copy existing text link
        function copyExistingTextLink(token) {
            const urlInput = document.getElementById('url-text-' + token);
            urlInput.select();
            urlInput.setSelectionRange(0, 99999);

            navigator.clipboard.writeText(urlInput.value).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            });
        }

        // Extend text expiration (adds time)
        async function extendText(token, duration) {
            try {
                const formData = new FormData();
                formData.append('extend_text', token);
                formData.append('duration', duration);

                const response = await fetch('text.php', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    const expiresEl = document.getElementById('expires-' + token);
                    if (expiresEl) {
                        expiresEl.textContent = result.new_expires_text;
                    }
                }
            } catch (error) {}
        }

        // Set text expiration (sets exact time)
        async function setText(token, duration) {
            try {
                const formData = new FormData();
                formData.append('set_text', token);
                formData.append('duration', duration);

                const response = await fetch('text.php', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    const expiresEl = document.getElementById('expires-' + token);
                    if (expiresEl) {
                        expiresEl.textContent = result.new_expires_text;
                    }
                }
            } catch (error) {}
        }

        // Delete text
        async function deleteText(token) {
            try {
                const formData = new FormData();
                formData.append('delete_text', token);

                const response = await fetch('text.php', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    window.location.reload();
                }
            } catch (error) {
                // Silently fail
            }
        }

        // Email chat link
        function emailChatLink(token) {
            const url = document.getElementById('url-text-' + token).value;
            currentShareUrl = url;
            currentShareFilename = 'Разговор';
            document.getElementById('emailModal').classList.add('show');
        }

        // Regenerate chat token (New ID)
        async function regenerateChatToken(oldToken) {
            const btn = event.target;
            try {
                btn.disabled = true;
                btn.textContent = '...';

                const formData = new FormData();
                formData.append('regenerate_token', oldToken);

                const response = await fetch('text.php', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    const newToken = data.new_token;

                    // Update URL input
                    const urlInput = document.getElementById('url-text-' + oldToken);
                    urlInput.value = data.new_url;
                    urlInput.id = 'url-text-' + newToken;

                    // Update share div ID
                    const shareDiv = document.getElementById('share-text-' + oldToken);
                    if (shareDiv) {
                        shareDiv.id = 'share-text-' + newToken;
                    }

                    // Update Copy button onclick
                    const copyBtn = urlInput.nextElementSibling;
                    if (copyBtn) {
                        copyBtn.onclick = function() { copyExistingTextLink(newToken); };
                    }

                    // Update Email button onclick (if exists)
                    const emailBtn = shareDiv.querySelector('button[style*="2196F3"]');
                    if (emailBtn) {
                        emailBtn.onclick = function() { emailChatLink(newToken); };
                    }

                    // Update New ID button onclick
                    btn.onclick = function() { regenerateChatToken(newToken); };

                    btn.textContent = 'Done!';
                    setTimeout(() => {
                        btn.textContent = 'New ID';
                        btn.disabled = false;
                    }, 1500);
                } else {
                    btn.textContent = 'Error';
                    setTimeout(() => {
                        btn.textContent = 'New ID';
                        btn.disabled = false;
                    }, 2000);
                }
            } catch (error) {
                btn.textContent = 'New ID';
                btn.disabled = false;
            }
        }

        // ==================
        // Move File Functions
        // ==================
        let moveFileName = null;
        let selectedMoveFolder = null;

        function showMoveModal(filename) {
            moveFileName = filename;
            selectedMoveFolder = null;
            document.getElementById('moveFileName').textContent = filename;

            // Clear previous selection
            document.querySelectorAll('.folder-option').forEach(el => el.classList.remove('selected'));

            document.getElementById('moveModal').classList.add('show');
        }

        function closeMoveModal() {
            document.getElementById('moveModal').classList.remove('show');
            moveFileName = null;
            selectedMoveFolder = null;
        }

        // ======================
        // Folder Share Functions
        // ======================
        let currentShareFolderPath = null;
        let currentShareFolderToken = null;

        function showFolderShareModal(folderPath, existingToken) {
            currentShareFolderPath = folderPath;
            currentShareFolderToken = existingToken && existingToken !== 'null' ? existingToken : null;

            document.getElementById('shareFolderPath').value = folderPath;
            document.getElementById('shareFolderToken').value = currentShareFolderToken || '';
            document.getElementById('shareFolderName').textContent = folderPath.split('/').pop();

            // Reset form
            document.getElementById('folderShareUpload').checked = false;
            document.getElementById('folderShareDelete').checked = false;
            document.getElementById('folderSharePassword').value = '';

            if (currentShareFolderToken) {
                // Existing share - show URL and management buttons
                document.getElementById('folderShareUrl').style.display = 'block';
                document.getElementById('folderShareUrlInput').value = 'https://' + location.host + '/f/' + currentShareFolderToken;
                document.getElementById('btnDeleteFolderShare').style.display = 'inline-block';
                document.getElementById('btnRegenerateFolderToken').style.display = 'inline-block';
                document.getElementById('btnCreateFolderShare').textContent = 'Обнови';
            } else {
                // New share
                document.getElementById('folderShareUrl').style.display = 'none';
                document.getElementById('btnDeleteFolderShare').style.display = 'none';
                document.getElementById('btnRegenerateFolderToken').style.display = 'none';
                document.getElementById('btnCreateFolderShare').textContent = 'Сподели';
            }

            document.getElementById('folderShareModal').classList.add('show');
        }

        function closeFolderShareModal() {
            document.getElementById('folderShareModal').classList.remove('show');
            currentShareFolderPath = null;
            currentShareFolderToken = null;
        }

        async function createFolderShare() {
            const folderPath = document.getElementById('shareFolderPath').value;
            const allowUpload = document.getElementById('folderShareUpload').checked;
            const allowDelete = document.getElementById('folderShareDelete').checked;
            const password = document.getElementById('folderSharePassword').value;

            const formData = new FormData();
            formData.append('create_folder_share', '1');
            formData.append('folder_path', folderPath);
            formData.append('allow_upload', allowUpload ? '1' : '0');
            formData.append('allow_delete', allowDelete ? '1' : '0');
            if (password) formData.append('share_password', password);

            try {
                const response = await fetch(location.href, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();
                if (data.success) {
                    currentShareFolderToken = data.token;
                    document.getElementById('folderShareUrl').style.display = 'block';
                    document.getElementById('folderShareUrlInput').value = data.url;
                    document.getElementById('btnDeleteFolderShare').style.display = 'inline-block';
                    document.getElementById('btnRegenerateFolderToken').style.display = 'inline-block';
                    document.getElementById('btnCreateFolderShare').textContent = 'Обнови';

                    // Copy to clipboard
                    navigator.clipboard.writeText(data.url);
                    alert(data.updated ? 'Споделянето е обновено!' : 'Папката е споделена! Линкът е копиран.');

                    // Reload to update share badges
                    if (!data.updated) location.reload();
                } else {
                    alert('Грешка: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Грешка при споделяне');
            }
        }

        function copyFolderShareUrl() {
            const input = document.getElementById('folderShareUrlInput');
            input.select();
            navigator.clipboard.writeText(input.value);
            alert('Линкът е копиран!');
        }

        async function deleteFolderShare() {
            if (!confirm('Сигурен ли си, че искаш да премахнеш споделянето?')) return;

            const formData = new FormData();
            formData.append('delete_folder_share', currentShareFolderToken);

            try {
                const response = await fetch(location.href, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();
                if (data.success) {
                    alert('Споделянето е премахнато');
                    location.reload();
                } else {
                    alert('Грешка: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Грешка при премахване');
            }
        }

        async function regenerateFolderToken() {
            if (!confirm('Това ще генерира нов линк и ще инвалидира стария. Продължи?')) return;

            const formData = new FormData();
            formData.append('regenerate_folder_token', currentShareFolderToken);

            try {
                const response = await fetch(location.href, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();
                if (data.success) {
                    currentShareFolderToken = data.new_token;
                    document.getElementById('folderShareUrlInput').value = data.new_url;
                    navigator.clipboard.writeText(data.new_url);
                    alert('Новият линк е генериран и копиран!');
                } else {
                    alert('Грешка: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Грешка при генериране');
            }
        }

        function selectMoveFolder(folder, element) {
            selectedMoveFolder = folder;
            document.querySelectorAll('.folder-option').forEach(el => el.classList.remove('selected'));
            element.classList.add('selected');
        }

        async function confirmMove() {
            if (!moveFileName || !selectedMoveFolder) {
                alert('Please select a destination folder');
                return;
            }

            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('move_file', moveFileName);
                formData.append('to_folder', selectedMoveFolder);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    closeMoveModal();
                    window.location.reload();
                } else {
                    alert('Error: ' + (result.error || 'Failed to move file'));
                }
            } catch (error) {
                alert('Error moving file');
            }
        }

        // Close modal when clicking outside
        var moveModal = document.getElementById('moveModal');
        if (moveModal) {
            moveModal.addEventListener('click', function(e) {
                if (e.target === this) {
                    closeMoveModal();
                }
            });
        }

        // ==================
        // Encrypt/Decrypt Functions
        // ==================
        let cryptFileName = null;

        function showEncryptModal(filename) {
            cryptFileName = filename;
            document.getElementById('cryptFileName').textContent = filename;
            document.getElementById('cryptAction').value = 'encrypt';
            document.getElementById('cryptModalTitle').textContent = '🔒 Криптиране на файл';
            document.getElementById('cryptSubmitBtn').textContent = 'Криптирай';
            document.getElementById('cryptConfirmWrapper').style.display = 'block';
            document.getElementById('cryptWarning').style.display = 'block';
            document.getElementById('cryptPassword').value = '';
            document.getElementById('cryptPasswordConfirm').value = '';
            clearCryptFieldError('cryptPassword');
            clearCryptFieldError('cryptPasswordConfirm');
            document.getElementById('cryptModal').classList.add('show');
            document.getElementById('cryptPassword').focus();
        }

        function showDecryptModal(filename) {
            cryptFileName = filename;
            document.getElementById('cryptFileName').textContent = filename;
            document.getElementById('cryptAction').value = 'decrypt';
            document.getElementById('cryptModalTitle').textContent = '🔓 Декриптиране на файл';
            document.getElementById('cryptSubmitBtn').textContent = 'Декриптирай';
            document.getElementById('cryptConfirmWrapper').style.display = 'none';
            document.getElementById('cryptWarning').style.display = 'none';
            document.getElementById('cryptPassword').value = '';
            document.getElementById('cryptPasswordConfirm').value = '';
            clearCryptFieldError('cryptPassword');
            clearCryptFieldError('cryptPasswordConfirm');
            document.getElementById('cryptModal').classList.add('show');
            document.getElementById('cryptPassword').focus();
        }

        function closeCryptModal() {
            document.getElementById('cryptModal').classList.remove('show');
            cryptFileName = null;
        }

        function clearCryptFieldError(fieldId) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            if (field) field.classList.remove('error', 'valid', 'invalid');
            if (errorSpan) {
                errorSpan.classList.remove('visible');
                errorSpan.textContent = '';
            }
        }

        function showCryptFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorSpan = document.getElementById(fieldId + 'Error');
            if (field) {
                field.classList.remove('valid', 'invalid');
                field.classList.add('error');
            }
            if (errorSpan) {
                errorSpan.textContent = message;
                errorSpan.classList.add('visible');
            }
        }

        function validateCryptPassword() {
            const passField = document.getElementById('cryptPassword');
            const password = passField.value;
            const action = document.getElementById('cryptAction').value;

            clearCryptFieldError('cryptPassword');

            if (password.length === 0) {
                passField.classList.remove('valid', 'invalid', 'error');
            } else if (password.length >= 4) {
                passField.classList.remove('invalid', 'error');
                passField.classList.add('valid');
            } else {
                passField.classList.remove('valid', 'error');
            }

            // Update confirm field if encrypting
            if (action === 'encrypt') {
                const confirmField = document.getElementById('cryptPasswordConfirm');
                if (confirmField.value.length > 0) {
                    validateCryptConfirm();
                }
            }
        }

        function validateCryptConfirm() {
            const passField = document.getElementById('cryptPassword');
            const confirmField = document.getElementById('cryptPasswordConfirm');
            const password = passField.value;
            const confirmPassword = confirmField.value;

            clearCryptFieldError('cryptPasswordConfirm');

            if (confirmPassword.length === 0) {
                confirmField.classList.remove('valid', 'invalid', 'error');
            } else if (password === confirmPassword && password.length >= 4) {
                confirmField.classList.remove('invalid', 'error');
                confirmField.classList.add('valid');
            } else {
                confirmField.classList.remove('valid', 'error');
                confirmField.classList.add('invalid');
            }
        }

        async function submitCrypt() {
            const action = document.getElementById('cryptAction').value;
            const password = document.getElementById('cryptPassword').value;
            const confirmPassword = document.getElementById('cryptPasswordConfirm').value;

            // Validate
            clearCryptFieldError('cryptPassword');
            clearCryptFieldError('cryptPasswordConfirm');

            if (password.length < 4) {
                showCryptFieldError('cryptPassword', 'Паролата трябва да е поне 4 знака');
                return;
            }

            if (action === 'encrypt' && password !== confirmPassword) {
                showCryptFieldError('cryptPasswordConfirm', 'Паролите не съвпадат');
                return;
            }

            // Submit
            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('crypt_action', action);
                formData.append('filename', cryptFileName);
                formData.append('password', password);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                const result = await response.json();

                if (result.success) {
                    closeCryptModal();
                    window.location.reload();
                } else {
                    showCryptFieldError('cryptPassword', result.error || 'Operation failed');
                }
            } catch (error) {
                showCryptFieldError('cryptPassword', 'Network error');
            }
        }

        // Close crypt modal when clicking outside
        var cryptModal = document.getElementById('cryptModal');
        if (cryptModal) {
            cryptModal.addEventListener('click', function(e) {
                if (e.target === this) {
                    closeCryptModal();
                }
            });
        }

        // ==================
        // Subfolder Functions
        // ==================
        function showCreateFolderModal() {
            document.getElementById('newFolderName').value = '';
            document.getElementById('createFolderModal').classList.add('show');
            document.getElementById('newFolderName').focus();
        }

        function closeCreateFolderModal() {
            document.getElementById('createFolderModal').classList.remove('show');
        }

        async function createSubfolderSubmit() {
            const folderName = document.getElementById('newFolderName').value.trim();
            if (!folderName) {
                alert('Please enter a folder name');
                return;
            }

            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('create_subfolder', '1');
                formData.append('folder_name', folderName);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    closeCreateFolderModal();
                    window.location.reload();
                } else {
                    alert('Error: ' + (result.error || 'Failed to create folder'));
                }
            } catch (error) {
                alert('Error creating folder');
            }
        }

        async function deleteSubfolder(folderPath) {
            if (!confirm('Delete folder "' + folderPath.split('/').pop() + '"? The folder must be empty.')) {
                return;
            }

            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                formData.append('delete_subfolder', folderPath);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    window.location.reload();
                } else {
                    alert('Error: ' + (result.error || 'Failed to delete folder'));
                }
            } catch (error) {
                alert('Error deleting folder');
            }
        }

        // Handle Enter key in folder name input
        document.addEventListener('DOMContentLoaded', function() {
            // Scroll to files section only when navigating from folder click (not on refresh)
            if (sessionStorage.getItem('scrollToFiles')) {
                sessionStorage.removeItem('scrollToFiles');
                const filesSection = document.getElementById('files-section');
                if (filesSection) {
                    setTimeout(() => {
                        filesSection.scrollIntoView({ behavior: 'auto', block: 'start' });
                        window.scrollBy(0, -20);
                    }, 50);
                }
            }

            // Add click handlers to folder links
            document.querySelectorAll('a[href*="folder="]').forEach(link => {
                link.addEventListener('click', () => {
                    sessionStorage.setItem('scrollToFiles', '1');
                });
            });

            const input = document.getElementById('newFolderName');
            if (input) {
                input.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        createSubfolderSubmit();
                    }
                });
            }

            // Close create folder modal when clicking outside
            const createModal = document.getElementById('createFolderModal');
            if (createModal) {
                createModal.addEventListener('click', function(e) {
                    if (e.target === this) {
                        closeCreateFolderModal();
                    }
                });
            }

            // Load audit log on tab switch
            if (document.getElementById('audit-tab')) {
                loadAuditLog(1);
            }
        });
    </script>

    <!-- Create Folder Modal -->
    <div class="modal" id="createFolderModal">
        <div class="modal-content">
            <h3>📁 New Folder</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Create in: <strong><?= htmlspecialchars($currentFolder) ?></strong>
            </p>
            <input type="text" id="newFolderName" placeholder="Folder name"
                   style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; margin-bottom: 15px; font-size: 14px;">
            <p style="font-size: 12px; color: #999; margin-bottom: 15px;">
                Allowed: letters, numbers, dash, underscore, space. Max 50 chars.
            </p>
            <div class="modal-buttons">
                <button class="btn" style="background: #6c757d;" onclick="closeCreateFolderModal()">Cancel</button>
                <button class="btn" onclick="createSubfolderSubmit()">Create</button>
            </div>
        </div>
    </div>

    <!-- Folder Share Modal -->
    <div class="modal" id="folderShareModal">
        <div class="modal-content" style="max-width: 500px;">
            <h3>🔗 Споделяне на папка</h3>
            <p style="margin-bottom: 20px; color: #666;">
                Папка: <strong id="shareFolderName"></strong>
            </p>

            <input type="hidden" id="shareFolderPath">
            <input type="hidden" id="shareFolderToken">

            <div style="margin-bottom: 15px;">
                <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                    <input type="checkbox" id="folderShareUpload">
                    <span>📤 Позволи качване на файлове</span>
                </label>
            </div>

            <div style="margin-bottom: 15px;">
                <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                    <input type="checkbox" id="folderShareDelete">
                    <span>🗑️ Позволи изтриване на файлове</span>
                </label>
            </div>

            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px;">🔒 Парола (незадължителна):</label>
                <input type="password" id="folderSharePassword" placeholder="Остави празно за без парола" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
            </div>

            <div id="folderShareUrl" style="display: none; margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px;">Линк за споделяне:</label>
                <div style="display: flex; gap: 10px;">
                    <input type="text" id="folderShareUrlInput" readonly style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 6px; background: #f8f9fa;">
                    <button class="btn" onclick="copyFolderShareUrl()">Copy</button>
                </div>
            </div>

            <div style="display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap;">
                <button class="btn" style="background: #6c757d;" onclick="closeFolderShareModal()">Затвори</button>
                <button class="btn" style="background: #e74c3c; display: none;" id="btnDeleteFolderShare" onclick="deleteFolderShare()">Премахни споделяне</button>
                <button class="btn" style="background: #ff9800; display: none;" id="btnRegenerateFolderToken" onclick="regenerateFolderToken()">New ID</button>
                <button class="btn" id="btnCreateFolderShare" onclick="createFolderShare()">Сподели</button>
            </div>
        </div>
    </div>

    <!-- Move File Modal -->
    <div class="modal" id="moveModal">
        <div class="modal-content" style="max-height: 80vh; overflow-y: auto;">
            <h3>📁 Премести файл</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Преместване: <strong id="moveFileName"></strong>
            </p>
            <p style="margin-bottom: 10px; font-weight: 500;">Избери папка:</p>

            <!-- Current user's base folder (root) -->
            <?php if ($currentFolder !== $baseFolder): ?>
            <div class="folder-option" onclick="selectMoveFolder('<?= htmlspecialchars($baseFolder, ENT_QUOTES) ?>', this)">
                📁 <?= $baseFolder === '_public' ? 'Public' : ucfirst($baseFolder) ?> <span style="color: #666; font-size: 12px;">(root)</span>
            </div>
            <?php endif; ?>

            <!-- Current user's subfolders -->
            <?php if (!empty($allUserSubfolders)): ?>
                <?php foreach ($allUserSubfolders as $subfolder): ?>
                    <?php if ($subfolder['path'] !== $currentFolder): ?>
                    <div class="folder-option" onclick="selectMoveFolder('<?= htmlspecialchars($subfolder['path'], ENT_QUOTES) ?>', this)" style="padding-left: <?= 15 + ($subfolder['depth'] * 15) ?>px;">
                        📂 <?= htmlspecialchars($subfolder['display']) ?>
                    </div>
                    <?php endif; ?>
                <?php endforeach; ?>
            <?php endif; ?>

            <!-- Separator if there are other user folders -->
            <?php
            $otherFolders = array_filter($userFolders, fn($f) => $f['name'] !== $baseFolder && $f['name'] !== $currentFolder);
            if (!empty($otherFolders)):
            ?>
            <hr style="margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;">
            <p style="margin-bottom: 10px; font-weight: 500; color: #666; font-size: 12px;">Други папки:</p>
            <?php foreach ($otherFolders as $folder): ?>
                <div class="folder-option" onclick="selectMoveFolder('<?= htmlspecialchars($folder['name'], ENT_QUOTES) ?>', this)">
                    <?= $folder['icon'] ?> <?= htmlspecialchars($folder['display']) ?>
                    <?php if ($folder['type'] === 'user'): ?><span style="color: #666; font-size: 12px;"> (<?= $folder['name'] ?>)</span><?php endif; ?>
                </div>
            <?php endforeach; ?>
            <?php endif; ?>

            <div class="modal-buttons">
                <button class="btn" style="background: #6c757d;" onclick="closeMoveModal()">Отказ</button>
                <button class="btn" onclick="confirmMove()">Премести</button>
            </div>
        </div>
    </div>

    <!-- Encrypt/Decrypt Modal -->
    <div class="modal" id="cryptModal">
        <div class="modal-content">
            <h3 id="cryptModalTitle">🔒 Криптиране на файл</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Файл: <strong id="cryptFileName"></strong>
            </p>
            <input type="hidden" id="cryptAction" value="encrypt">
            <div class="password-field-wrapper" style="margin-bottom: 10px;">
                <input type="password" id="cryptPassword" placeholder="Парола (мин. 4 знака)"
                       style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;"
                       oninput="validateCryptPassword()">
                <span class="field-error" id="cryptPasswordError"></span>
            </div>
            <div class="password-field-wrapper" id="cryptConfirmWrapper" style="margin-bottom: 15px;">
                <input type="password" id="cryptPasswordConfirm" placeholder="Повтори паролата"
                       style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;"
                       oninput="validateCryptConfirm()">
                <span class="field-error" id="cryptPasswordConfirmError"></span>
            </div>
            <p class="encrypt-warning" id="cryptWarning" style="margin-bottom: 15px;">
                ⚠️ Запомни паролата! Файлът не може да бъде възстановен без нея.
            </p>
            <div class="modal-buttons">
                <button class="btn" style="background: #6c757d;" onclick="closeCryptModal()">Отказ</button>
                <button class="btn" id="cryptSubmitBtn" onclick="submitCrypt()">Криптирай</button>
            </div>
        </div>
    </div>

    <!-- Email Share Modal -->
    <div class="modal" id="emailModal">
        <div class="modal-content">
            <h3>📧 Send Link via Email</h3>
            <input type="hidden" id="emailShareUrl">
            <input type="hidden" id="emailFileName">
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 500;">Recipient Email *</label>
                <input type="email" id="emailTo" placeholder="recipient@example.com"
                       style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
            </div>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 500;">Your Name (optional)</label>
                <input type="text" id="emailSenderName" placeholder="John Doe"
                       style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
            </div>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: 500;">Message (optional)</label>
                <textarea id="emailMessage" placeholder="Hi, I'm sharing this file with you..."
                          style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box; min-height: 80px; resize: vertical;"></textarea>
            </div>
            <div id="emailStatus" style="display: none; padding: 10px; border-radius: 6px; margin-bottom: 15px;"></div>
            <div class="modal-buttons">
                <button class="btn" style="background: #6c757d;" onclick="closeEmailModal()">Cancel</button>
                <button class="btn" style="background: #2196F3;" onclick="sendShareEmail()" id="sendEmailBtn">Send Email</button>
            </div>
        </div>
    </div>

    <!-- Update Modal -->
    <div class="modal" id="updateModal">
        <div class="modal-content" style="max-width: 450px;">
            <h3>Software Update</h3>
            <div id="updateContent">
                <p style="text-align: center; color: #666;">Checking for updates...</p>
            </div>
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee;">
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: #666; cursor: pointer;">
                    <input type="checkbox" id="autoUpdateCheck" onchange="toggleAutoUpdateCheck()" checked>
                    Automatically check for updates
                </label>
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: #666; cursor: pointer; margin-top: 8px;">
                    <input type="checkbox" id="useBetaServer" onchange="toggleBetaServer()">
                    Use developer server (beta)
                </label>
            </div>
            <div class="modal-buttons" style="margin-top: 20px;">
                <button id="liveUpdateBtn" class="btn" style="background: #607D8B;" onclick="doLiveUpdate()">Force Update</button>
                <button id="checkUpdateBtn" class="btn" style="background: #2196F3;" onclick="checkForUpdates(true)">Check Now</button>
                <button class="btn" style="background: #6c757d;" onclick="closeUpdateModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- Changelog Modal (kept for direct access) -->
    <div class="modal" id="changelogModal">
        <div class="modal-content" style="max-width: 600px; max-height: 80vh; overflow-y: auto;">
            <h3>Changelog</h3>
            <div id="changelogContent">
                <div class="changelog-version">
                    <h4>v3.1.2 <span class="changelog-badge badge-added">Latest</span></h4>
                    <ul>
                        <li>Clickable version for updates</li>
                        <li>About modal with changelog</li>
                        <li>Auto-update check system</li>
                    </ul>
                </div>
                <div class="changelog-version">
                    <h4>v3.1.1</h4>
                    <ul>
                        <li>API Upload moved to Help tab</li>
                    </ul>
                </div>
                <div class="changelog-version">
                    <h4>v3.1.0</h4>
                    <ul>
                        <li>API Upload with Windows integration</li>
                    </ul>
                </div>
                <div class="changelog-version">
                    <h4>v3.0.x</h4>
                    <ul>
                        <li>Share link token regeneration</li>
                        <li>File metadata sync</li>
                        <li>Web download feature</li>
                        <li>Email sharing</li>
                        <li>Text sharing</li>
                        <li>File encryption</li>
                    </ul>
                </div>
            </div>
            <div class="modal-buttons">
                <a href="CHANGELOG.md" target="_blank" class="btn" style="background: #2196F3; text-decoration: none;">Full Changelog</a>
                <button class="btn" style="background: #6c757d;" onclick="closeChangelogModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- About Modal -->
    <div class="modal" id="aboutModal">
        <div class="modal-content" style="max-width: 550px; max-height: 85vh; overflow-y: auto;">
            <div style="text-align: center; padding-bottom: 15px; border-bottom: 1px solid #eee;">
                <h3 style="font-size: 32px; margin: 0; color: #1976D2;">WebShare</h3>
                <p style="font-size: 14px; color: #888; margin: 5px 0;">Simple File Sharing System</p>
                <p style="font-size: 18px; color: #333; margin: 10px 0;">Version <?= WEBSHARE_VERSION ?></p>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 20px 0; font-size: 13px;">
                <div style="background: #e3f2fd; padding: 10px; border-radius: 6px;">
                    <strong style="color: #1565c0;">File Management</strong>
                    <ul style="margin: 5px 0 0 0; padding-left: 18px; color: #555;">
                        <li>Drag & drop upload</li>
                        <li>Folder organization</li>
                        <li>Web download</li>
                    </ul>
                </div>
                <div style="background: #e8f5e9; padding: 10px; border-radius: 6px;">
                    <strong style="color: #2e7d32;">Security</strong>
                    <ul style="margin: 5px 0 0 0; padding-left: 18px; color: #555;">
                        <li>AES-256 encryption</li>
                        <li>GeoIP filtering</li>
                        <li>Audit logging</li>
                    </ul>
                </div>
                <div style="background: #fff3e0; padding: 10px; border-radius: 6px;">
                    <strong style="color: #ef6c00;">Sharing</strong>
                    <ul style="margin: 5px 0 0 0; padding-left: 18px; color: #555;">
                        <li>Token-based links</li>
                        <li>Email sharing</li>
                        <li>Rich text notes</li>
                    </ul>
                </div>
                <div style="background: #fce4ec; padding: 10px; border-radius: 6px;">
                    <strong style="color: #c2185b;">Integration</strong>
                    <ul style="margin: 5px 0 0 0; padding-left: 18px; color: #555;">
                        <li>API upload</li>
                        <li>Windows context menu</li>
                        <li>Multi-user</li>
                    </ul>
                </div>
            </div>

            <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 15px 0;">
                <h4 style="margin: 0 0 10px 0; color: #333; font-size: 14px;">Recent Changes</h4>
                <div style="font-size: 12px; color: #555; max-height: 120px; overflow-y: auto;">
                    <?php foreach (getRecentChanges(8) as $change): ?>
                    <p style="margin: 5px 0;"><strong>v<?= htmlspecialchars($change['version']) ?></strong> - <?= htmlspecialchars($change['highlights']) ?></p>
                    <?php endforeach; ?>
                </div>
                <a href="CHANGELOG.md" target="_blank" style="display: inline-block; margin-top: 10px; font-size: 12px; color: #1976D2;">View full changelog →</a>
            </div>

            <div style="text-align: center; padding-top: 15px; border-top: 1px solid #eee;">
                <p style="margin: 5px 0; color: #555;">Created by <strong>Todor Karachorbadzhiev</strong></p>
                <p style="margin: 5px 0; font-size: 12px;"><a href="mailto:webshare@techbg.net" style="color: #1976D2; text-decoration: none;">webshare@techbg.net</a></p>
                <p style="margin: 5px 0; font-size: 12px; color: #999;">2025-2026</p>
                <a href="https://github.com/toshko37/webshare" target="_blank" style="display: inline-block; margin-top: 10px; font-size: 13px; color: #1976D2; text-decoration: none;">
                    GitHub Repository →
                </a>
            </div>

            <div class="modal-buttons" style="margin-top: 20px;">
                <button class="btn" style="background: #6c757d;" onclick="closeAboutModal()">Close</button>
            </div>
        </div>
    </div>
</body>
</html>
