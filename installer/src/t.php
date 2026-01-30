<?php
// Public Text Sharing, Viewing & Editing
// =======================================
// /t              → Create text (NO AUTH)
// /t/TOKEN        → View text (NO AUTH)
// /t/TOKEN?edit=KEY → Edit/Extend text (NO AUTH, but needs edit key)

$textsDir = __DIR__ . '/texts/';
$metadataFile = __DIR__ . '/.texts.json';

// Load config for speedtest link
$config = [];
$configFile = __DIR__ . '/.config.json';
if (file_exists($configFile)) {
    $config = json_decode(file_get_contents($configFile), true) ?: [];
}
$speedtestUrl = $config['speedtest_url'] ?? '';

// CONFIGURATION
define('TEXT_EXPIRE_HOURS', 24);
define('TEXT_MAX_SIZE', 1000000);

// Security: HTML sanitizer
require_once __DIR__ . '/html-sanitizer.php';

// Include audit log
require_once __DIR__ . '/audit-log.php';

// GeoIP check - only for CREATE mode (not for viewing shared texts)
require_once __DIR__ . '/geo-check.php';
$token = $_GET['token'] ?? '';
if (empty($token)) {
    // Create mode - check geo
    checkGeoAccess();
}

// Helper functions
function generateToken($length = 32) {
    // Generate cryptographically secure token (128 bits = 32 hex chars)
    return bin2hex(random_bytes($length / 2));
}

function loadMetadata($file) {
    if (!file_exists($file)) {
        return [];
    }
    return json_decode(file_get_contents($file), true) ?? [];
}

function saveMetadata($file, $data) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

// Get URL parameters (token already set above for geo check)
$editKey = $_GET['edit'] ?? '';
$isViewMode = !empty($token);
$hasEditAccess = false;

// Validate edit key if provided (12=old format, 32=new secure format)
if ($isViewMode && !empty($editKey)) {
    if (preg_match('/^[a-zA-Z0-9]{12,64}$/', $editKey)) {
        $metadata = loadMetadata($metadataFile);
        if (isset($metadata[$token]) && isset($metadata[$token]['edit_key']) && hash_equals($metadata[$token]['edit_key'], $editKey)) {
            $hasEditAccess = true;
        }
    }
}

// Handle text UPDATE (POST with edit key)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update']) && !empty($token) && !empty($editKey)) {
    header('Content-Type: application/json');
    
    $metadata = loadMetadata($metadataFile);
    
    if (!isset($metadata[$token]) || $metadata[$token]['edit_key'] !== $editKey) {
        echo json_encode(['success' => false, 'error' => 'Invalid edit key']);
        exit;
    }
    
    $html = $_POST['html'] ?? '';

    if (empty($html)) {
        echo json_encode(['success' => false, 'error' => 'No content']);
        exit;
    }

    // SECURITY: Sanitize HTML to prevent XSS
    $html = sanitizeHtml($html);

    if (strlen($html) > TEXT_MAX_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Content too large']);
        exit;
    }

    // Update file
    $filePath = $textsDir . '.' . $token . '.html';
    if (!file_put_contents($filePath, $html)) {
        echo json_encode(['success' => false, 'error' => 'Failed to save']);
        exit;
    }
    
    // Update metadata
    $plainText = strip_tags($html);
    $preview = mb_substr($plainText, 0, 50);
    if (mb_strlen($plainText) > 50) {
        $preview .= '...';
    }
    
    $metadata[$token]['size'] = strlen($html);
    $metadata[$token]['preview'] = $preview;
    $metadata[$token]['updated'] = time();

    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_update', "Updated text: $token (" . strlen($html) . " chars)", 'anonymous');

    echo json_encode(['success' => true]);
    exit;
}

// Handle text EXTEND (POST with edit key)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['extend']) && !empty($token) && !empty($editKey)) {
    header('Content-Type: application/json');
    
    $metadata = loadMetadata($metadataFile);
    
    if (!isset($metadata[$token]) || $metadata[$token]['edit_key'] !== $editKey) {
        echo json_encode(['success' => false, 'error' => 'Invalid edit key']);
        exit;
    }
    
    $extendBy = $_POST['extend'];
    $currentExpires = $metadata[$token]['expires'];
    
    switch ($extendBy) {
        case '1d':
            $newExpires = $currentExpires + (24 * 3600);
            break;
        case '1w':
            $newExpires = $currentExpires + (7 * 24 * 3600);
            break;
        case '1m':
            $newExpires = $currentExpires + (30 * 24 * 3600);
            break;
        case '6m':
            $newExpires = $currentExpires + (180 * 24 * 3600);
            break;
        case 'permanent':
            $newExpires = time() + (10 * 365 * 24 * 3600); // 10 years
            break;
        default:
            echo json_encode(['success' => false, 'error' => 'Invalid extend option']);
            exit;
    }
    
    $metadata[$token]['expires'] = $newExpires;
    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_extend', "Extended text: $token by $extendBy", 'anonymous');

    echo json_encode(['success' => true, 'new_expires' => $newExpires]);
    exit;
}

// Handle text CREATION (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create'])) {
    header('Content-Type: application/json');

    $html = $_POST['html'] ?? '';

    if (empty($html)) {
        echo json_encode(['success' => false, 'error' => 'No content']);
        exit;
    }

    // SECURITY: Sanitize HTML to prevent XSS
    $html = sanitizeHtml($html);

    if (strlen($html) > TEXT_MAX_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Content too large']);
        exit;
    }

    // Generate unique token (32 hex chars = 128 bits)
    $newToken = generateToken(32);
    while (file_exists($textsDir . '.' . $newToken . '.html')) {
        $newToken = generateToken(32);
    }

    // Generate edit key (32 hex chars = 128 bits)
    $newEditKey = generateToken(32);
    
    // Save file
    $filePath = $textsDir . '.' . $newToken . '.html';
    if (!file_put_contents($filePath, $html)) {
        echo json_encode(['success' => false, 'error' => 'Failed to save']);
        exit;
    }
    
    // Save metadata
    $metadata = loadMetadata($metadataFile);
    
    $plainText = strip_tags($html);
    $preview = mb_substr($plainText, 0, 50);
    if (mb_strlen($plainText) > 50) {
        $preview .= '...';
    }
    
    $metadata[$newToken] = [
        'created' => time(),
        'expires' => time() + (TEXT_EXPIRE_HOURS * 3600),
        'size' => strlen($html),
        'preview' => $preview,
        'views' => 0,
        'edit_key' => $newEditKey
    ];
    
    saveMetadata($metadataFile, $metadata);

    // Audit log
    writeAuditLog('text_create', "Created text: $newToken (" . strlen($html) . " chars)", 'anonymous');

    $viewUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $newToken;
    $editUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $newToken . '?edit=' . $newEditKey;

    echo json_encode([
        'success' => true,
        'view_url' => $viewUrl,
        'edit_url' => $editUrl,
        'token' => $newToken,
        'edit_key' => $newEditKey
    ]);
    exit;
}
// Handle text VIEW (GET with token)
if ($isViewMode) {
    $filePath = $textsDir . '.' . $token . '.html';

    if (!file_exists($filePath)) {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Not Found</title></head><body><h1>Text not found</h1><p>This shared text does not exist or has expired.</p></body></html>';
        exit;
    }

    // Load metadata and increment views
    $metadata = loadMetadata($metadataFile);
    if (isset($metadata[$token])) {
        $metadata[$token]['views']++;
        saveMetadata($metadataFile, $metadata);
        $meta = $metadata[$token];
    } else {
        $meta = ['created' => time(), 'expires' => time() + 3600, 'views' => 1];
    }

    $html = file_get_contents($filePath);
    $plainText = strip_tags($html);
    $created = date('Y-m-d H:i', $meta['created']);
    $expires = date('Y-m-d H:i', $meta['expires']);
    $timeRemaining = $meta['expires'] - time();

    if ($timeRemaining < 0) {
        $expiresText = '<span style="color: #e74c3c;">Expired</span>';
    } elseif ($timeRemaining < 3600) {
        $expiresText = '<span style="color: #e67e22;">' . ceil($timeRemaining / 60) . ' minutes</span>';
    } elseif ($timeRemaining < 86400) {
        $expiresText = ceil($timeRemaining / 3600) . ' hours';
    } else {
        $expiresText = ceil($timeRemaining / 86400) . ' days';
    }

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shared Text - <?= htmlspecialchars(mb_substr($plainText, 0, 30)) ?></title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link href="/assets/quill/quill.snow.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }

        .header p {
            opacity: 0.9;
            font-size: 16px;
        }

        .info-bar {
            background: #f8f9fa;
            padding: 15px 30px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 14px;
            color: #666;
        }

        .info-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .content-area {
            padding: 30px;
        }

        .view-mode .ql-editor {
            padding: 0;
            font-size: 16px;
            line-height: 1.6;
        }

        .edit-mode {
            display: none;
        }

        .edit-mode.active {
            display: block;
        }

        .view-mode.hidden {
            display: none;
        }

        .actions {
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .btn-success {
            background: #28a745;
            color: white;
        }

        .btn-success:hover {
            background: #218838;
        }

        .btn-warning {
            background: #ffc107;
            color: #000;
        }

        .btn-warning:hover {
            background: #e0a800;
        }

        .btn-outline {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }

        .btn-outline:hover {
            background: #667eea;
            color: white;
        }

        .extend-options {
            display: none;
            gap: 8px;
            flex-wrap: wrap;
        }

        .extend-options.show {
            display: flex;
        }

        .extend-btn {
            padding: 8px 16px;
            font-size: 13px;
        }

        #editor-container {
            height: 400px;
            background: white;
        }

        .message {
            padding: 12px 20px;
            margin-bottom: 15px;
            border-radius: 6px;
            font-size: 14px;
        }

        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
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
    </style>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank">🚀 Speed Test</a>
    <?php endif; ?>

    <div class="container">
        <div class="header">
            <h1>📋 Shared Text</h1>
            <p>View and manage your shared content</p>
        </div>

        <div class="info-bar">
            <div class="info-item">
                📅 <strong>Created:</strong> <?= $created ?>
            </div>
            <div class="info-item">
                ⏰ <strong>Expires in:</strong> <?= $expiresText ?>
            </div>
            <div class="info-item">
                👁️ <strong>Views:</strong> <?= $meta['views'] ?>
            </div>
            <div class="info-item">
                📏 <strong>Size:</strong> <?= number_format(strlen($html)) ?> chars
            </div>
        </div>

        <div class="content-area">
            <div id="message-area"></div>

            <!-- View Mode -->
            <div class="view-mode" id="view-mode">
                <div class="ql-editor"><?= $html ?></div>
            </div>

            <!-- Edit Mode -->
            <div class="edit-mode" id="edit-mode">
                <div id="editor-container"></div>
            </div>
        </div>

        <div class="actions">
            <button class="btn btn-secondary" onclick="closeOrBack()" title="Close or go back">✕ Затвори</button>
            <button class="btn btn-primary" onclick="copyText()">📋 Copy Text</button>
            <button class="btn btn-secondary" onclick="copyUrl()">🔗 Copy Link</button>

            <?php if ($hasEditAccess): ?>
                <button class="btn btn-warning" id="edit-btn" onclick="toggleEdit()">✏️ Edit Text</button>
                <button class="btn btn-success" id="save-btn" onclick="saveText()" style="display: none;">💾 Save Changes</button>
                <button class="btn btn-secondary" id="cancel-btn" onclick="cancelEdit()" style="display: none;">❌ Cancel</button>
                <button class="btn btn-outline" onclick="toggleExtend()">⏰ Extend Time</button>

                <div class="extend-options" id="extend-options">
                    <button class="btn extend-btn btn-outline" onclick="extendTime('1d')">+1 Day</button>
                    <button class="btn extend-btn btn-outline" onclick="extendTime('1w')">+1 Week</button>
                    <button class="btn extend-btn btn-outline" onclick="extendTime('1m')">+1 Month</button>
                    <button class="btn extend-btn btn-outline" onclick="extendTime('6m')">+6 Months</button>
                    <button class="btn extend-btn btn-outline" onclick="extendTime('permanent')">♾️ Permanent</button>
                </div>
            <?php endif; ?>

            <a href="/t" class="btn btn-primary" style="margin-left: auto;">💬 Сподели Отговор</a>
        </div>
    </div>

    <script src="/assets/quill/quill.js"></script>
    <script>
        let quill = null;
        let isEditing = false;

        <?php if ($hasEditAccess): ?>
        // Initialize Quill for editing
        quill = new Quill('#editor-container', {
            theme: 'snow',
            modules: {
                toolbar: [
                    ['bold', 'italic', 'underline', 'strike'],
                    ['blockquote', 'code-block'],
                    [{ 'header': 1 }, { 'header': 2 }],
                    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                    [{ 'color': [] }, { 'background': [] }],
                    ['link'],
                    ['clean']
                ]
            }
        });
        <?php endif; ?>

        function showMessage(text, type = 'success') {
            const messageArea = document.getElementById('message-area');
            messageArea.innerHTML = `<div class="message ${type}">${text}</div>`;
            setTimeout(() => {
                messageArea.innerHTML = '';
            }, 5000);
        }

        function copyText() {
            const text = document.querySelector('.view-mode .ql-editor').innerText;
            navigator.clipboard.writeText(text).then(() => {
                showMessage('✅ Text copied to clipboard!');
            });
        }

        function copyUrl() {
            navigator.clipboard.writeText(window.location.href.split('?')[0]).then(() => {
                showMessage('✅ Link copied to clipboard!');
            });
        }

        function closeOrBack() {
            // Try to close if opened as popup, otherwise go back in history
            if (window.opener) {
                window.close();
            } else if (window.history.length > 1) {
                window.history.back();
            } else {
                window.close();
            }
        }

        <?php if ($hasEditAccess): ?>
        function toggleEdit() {
            if (!isEditing) {
                // Switch to edit mode
                const currentHtml = document.querySelector('.view-mode .ql-editor').innerHTML;
                quill.root.innerHTML = currentHtml;

                document.getElementById('view-mode').classList.add('hidden');
                document.getElementById('edit-mode').classList.add('active');
                document.getElementById('edit-btn').style.display = 'none';
                document.getElementById('save-btn').style.display = 'inline-block';
                document.getElementById('cancel-btn').style.display = 'inline-block';

                isEditing = true;
            }
        }

        function cancelEdit() {
            document.getElementById('view-mode').classList.remove('hidden');
            document.getElementById('edit-mode').classList.remove('active');
            document.getElementById('edit-btn').style.display = 'inline-block';
            document.getElementById('save-btn').style.display = 'none';
            document.getElementById('cancel-btn').style.display = 'none';

            isEditing = false;
        }

        function saveText() {
            const html = quill.root.innerHTML;

            const formData = new FormData();
            formData.append('update', '1');
            formData.append('html', html);

            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update view mode with new content
                    document.querySelector('.view-mode .ql-editor').innerHTML = html;
                    cancelEdit();
                    showMessage('✅ Text updated successfully!');

                    // Reload page after 1 second to update metadata
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showMessage('❌ Error: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showMessage('❌ Failed to save text', 'error');
            });
        }

        function toggleExtend() {
            const options = document.getElementById('extend-options');
            options.classList.toggle('show');
        }

        function extendTime(duration) {
            const formData = new FormData();
            formData.append('extend', duration);

            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage('✅ Expiration time extended successfully!');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showMessage('❌ Error: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showMessage('❌ Failed to extend time', 'error');
            });
        }
        <?php endif; ?>
    </script>
</body>
</html>
    <?php
    exit;
}
// CREATE MODE (no token provided)
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Share Text - WebShare</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link href="/assets/quill/quill.snow.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }

        .header p {
            opacity: 0.9;
            font-size: 16px;
        }

        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px 20px;
            margin: 20px 30px;
            border-radius: 6px;
            font-size: 14px;
            color: #1976d2;
        }

        .content-area {
            padding: 30px;
        }

        #editor-container {
            height: 400px;
            background: white;
            margin-bottom: 20px;
        }

        .actions {
            display: flex;
            gap: 10px;
            justify-content: center;
            padding-bottom: 10px;
        }

        .btn {
            padding: 14px 28px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .result {
            display: none;
            margin-top: 30px;
            padding: 20px;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 6px;
        }

        .result.show {
            display: block;
        }

        .result h3 {
            color: #155724;
            margin-bottom: 15px;
        }

        .url-box {
            background: white;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }

        .url-box input {
            flex: 1;
            border: none;
            font-family: monospace;
            font-size: 14px;
            color: #333;
            outline: none;
        }

        .url-box button {
            padding: 6px 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }

        .url-box button:hover {
            background: #5568d3;
        }

        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px 20px;
            margin-top: 15px;
            border-radius: 6px;
            font-size: 13px;
            color: #856404;
        }

        .warning-box strong {
            display: block;
            margin-bottom: 5px;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }

        .loading.show {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
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
    </style>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank">🚀 Speed Test</a>
    <?php endif; ?>

    <div class="container">
        <div class="header">
            <h1>📋 Share Text</h1>
            <p>Create and share formatted text snippets</p>
        </div>

        <div class="info-box">
            ℹ️ <strong>Public sharing:</strong> No authentication required. Texts expire in <?= TEXT_EXPIRE_HOURS ?> hours by default. You can extend this time with the edit link.
        </div>

        <div class="content-area">
            <div id="editor-container"></div>

            <div class="actions">
                <button class="btn btn-primary" onclick="shareText()" id="share-btn">
                    🚀 Share Text
                </button>
                <button class="btn btn-secondary" onclick="clearEditor()">
                    🗑️ Clear
                </button>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Creating shared link...</p>
            </div>

            <div class="result" id="result">
                <h3>✅ Text shared successfully!</h3>

                <div class="url-box">
                    <strong style="min-width: 80px;">View URL:</strong>
                    <input type="text" id="view-url" readonly>
                    <button onclick="copyViewUrl()">Copy</button>
                </div>

                <div class="url-box">
                    <strong style="min-width: 80px;">Edit URL:</strong>
                    <input type="text" id="edit-url" readonly>
                    <button onclick="copyEditUrl()">Copy</button>
                </div>

                <div class="warning-box">
                    <strong>⚠️ Important:</strong>
                    Save the Edit URL to edit or extend the expiration time later. Anyone with the Edit URL can modify the content.
                </div>

                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn btn-primary" onclick="location.href = document.getElementById('view-url').value">
                        👁️ View Shared Text
                    </button>
                    <button class="btn btn-secondary" onclick="createAnother()">
                        ➕ Share Another
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script src="/assets/quill/quill.js"></script>
    <script>
        const quill = new Quill('#editor-container', {
            theme: 'snow',
            modules: {
                toolbar: [
                    ['bold', 'italic', 'underline', 'strike'],
                    ['blockquote', 'code-block'],
                    [{ 'header': 1 }, { 'header': 2 }],
                    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                    [{ 'color': [] }, { 'background': [] }],
                    ['link'],
                    ['clean']
                ]
            },
            placeholder: 'Type or paste your text here...'
        });

        function shareText() {
            const html = quill.root.innerHTML;
            const text = quill.getText().trim();

            if (!text || text.length < 1) {
                alert('Please enter some text to share');
                return;
            }

            const shareBtn = document.getElementById('share-btn');
            const loading = document.getElementById('loading');

            shareBtn.disabled = true;
            loading.classList.add('show');

            const formData = new FormData();
            formData.append('create', '1');
            formData.append('html', html);

            fetch('/t', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                loading.classList.remove('show');
                shareBtn.disabled = false;

                if (data.success) {
                    // Copy view URL to clipboard and close window
                    navigator.clipboard.writeText(data.view_url).then(() => {
                        // Try to close the window/tab
                        window.close();
                        // If window.close() didn't work (not opened via script), redirect to view
                        setTimeout(() => {
                            window.location.href = data.view_url;
                        }, 100);
                    }).catch(() => {
                        // Fallback: redirect to view URL
                        window.location.href = data.view_url;
                    });
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                loading.classList.remove('show');
                shareBtn.disabled = false;
                alert('Failed to share text. Please try again.');
            });
        }

        function clearEditor() {
            if (quill.getText().trim().length > 0) {
                quill.setText('');
            }
        }

        function copyViewUrl() {
            const input = document.getElementById('view-url');
            input.select();
            navigator.clipboard.writeText(input.value).then(() => {
                alert('✅ View URL copied!');
            });
        }

        function copyEditUrl() {
            const input = document.getElementById('edit-url');
            input.select();
            navigator.clipboard.writeText(input.value).then(() => {
                alert('✅ Edit URL copied!');
            });
        }

        function createAnother() {
            document.getElementById('result').classList.remove('show');
            clearEditor();
            quill.focus();
        }

        // Paste support
        document.addEventListener('paste', (e) => {
            if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
                quill.focus();
            }
        });
    </script>
</body>
</html>
