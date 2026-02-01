<?php
// Chat/Conversation System for WebShare
// =====================================
// /t              → Create new conversation (NO AUTH)
// /t/TOKEN        → View/participate in conversation (NO AUTH)
// /t/TOKEN?edit=KEY → Creator edit access (NO AUTH, needs edit key)

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
define('MESSAGE_MAX_LENGTH', 10000);
define('USERNAME_MAX_LENGTH', 30);
define('RATE_LIMIT_MESSAGES', 30); // Per minute
define('RATE_LIMIT_WINDOW', 60);   // Seconds
define('HEARTBEAT_TIMEOUT', 30);   // Seconds before viewer is considered offline
define('POLL_INTERVAL_MESSAGES', 5000); // 5 seconds
define('POLL_INTERVAL_HEARTBEAT', 10000); // 10 seconds

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
    return bin2hex(random_bytes($length / 2));
}

function generateUserId() {
    return 'user_' . bin2hex(random_bytes(8));
}

function generateMessageId() {
    return 'msg_' . bin2hex(random_bytes(8));
}

function loadMetadata($file) {
    if (!file_exists($file)) {
        return [];
    }
    return json_decode(file_get_contents($file), true) ?? [];
}

function saveMetadata($file, $data) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

function loadConversation($jsonPath) {
    if (!file_exists($jsonPath)) {
        return ['messages' => []];
    }
    return json_decode(file_get_contents($jsonPath), true) ?? ['messages' => []];
}

function saveConversation($jsonPath, $conversation) {
    file_put_contents($jsonPath, json_encode($conversation, JSON_PRETTY_PRINT), LOCK_EX);
}

// Migrate old HTML text to new JSON conversation format
function migrateToConversation($token, $textsDir, $metadata) {
    $htmlPath = $textsDir . '.' . $token . '.html';
    $jsonPath = $textsDir . '.' . $token . '.json';

    // Already migrated
    if (file_exists($jsonPath)) {
        return loadConversation($jsonPath);
    }

    // No old file either
    if (!file_exists($htmlPath)) {
        return ['messages' => []];
    }

    // Migrate: HTML → JSON with single message
    $html = file_get_contents($htmlPath);
    $conversation = [
        'messages' => [[
            'id' => generateMessageId(),
            'author' => $metadata['creator'] ?? 'Creator',
            'author_id' => 'legacy_creator',
            'text' => $html,
            'time' => $metadata['created'] ?? time(),
            'edited' => null,
            'deleted' => false,
            'urgent' => false
        ]]
    ];

    saveConversation($jsonPath, $conversation);
    unlink($htmlPath);
    return $conversation;
}

// Sanitize username
function sanitizeUsername($name) {
    $name = strip_tags($name);
    $name = preg_replace('/[<>"\']/', '', $name);
    $name = trim($name);
    if (mb_strlen($name) > USERNAME_MAX_LENGTH) {
        $name = mb_substr($name, 0, USERNAME_MAX_LENGTH);
    }
    return $name ?: 'Гост';
}

// Rate limiting check
function checkRateLimit($userId) {
    $rateLimitFile = sys_get_temp_dir() . '/webshare_rate_' . md5($userId) . '.json';
    $now = time();

    if (file_exists($rateLimitFile)) {
        $data = json_decode(file_get_contents($rateLimitFile), true) ?? ['count' => 0, 'window_start' => $now];
    } else {
        $data = ['count' => 0, 'window_start' => $now];
    }

    // Reset window if expired
    if ($now - $data['window_start'] > RATE_LIMIT_WINDOW) {
        $data = ['count' => 0, 'window_start' => $now];
    }

    if ($data['count'] >= RATE_LIMIT_MESSAGES) {
        return false;
    }

    $data['count']++;
    file_put_contents($rateLimitFile, json_encode($data));
    return true;
}

// Get URL parameters
$editKey = $_GET['edit'] ?? '';
$action = $_GET['action'] ?? '';
$isViewMode = !empty($token);
$hasEditAccess = false;

// Validate edit key if provided
if ($isViewMode && !empty($editKey)) {
    if (preg_match('/^[a-zA-Z0-9]{12,64}$/', $editKey)) {
        $metadata = loadMetadata($metadataFile);
        if (isset($metadata[$token]) && isset($metadata[$token]['edit_key']) && hash_equals($metadata[$token]['edit_key'], $editKey)) {
            $hasEditAccess = true;
        }
    }
}

// ========================================
// API ENDPOINTS (AJAX requests)
// ========================================

// GET MESSAGES
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'messages' && !empty($token)) {
    header('Content-Type: application/json');

    $since = (int)($_GET['since'] ?? 0);
    $jsonPath = $textsDir . '.' . $token . '.json';
    $metadata = loadMetadata($metadataFile);

    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    // Migrate if needed
    $conversation = migrateToConversation($token, $textsDir, $metadata[$token]);

    // Filter messages since timestamp
    $messages = array_filter($conversation['messages'], function($msg) use ($since) {
        return $msg['time'] > $since || ($msg['edited'] && $msg['edited'] > $since);
    });

    // Get viewer count
    $viewers = $metadata[$token]['viewers'] ?? [];
    $now = time();
    $activeViewers = array_filter($viewers, function($v) use ($now) {
        return ($now - $v['last_seen']) < HEARTBEAT_TIMEOUT;
    });

    echo json_encode([
        'success' => true,
        'messages' => array_values($messages),
        'viewer_count' => count($activeViewers),
        'viewers' => array_map(function($v) { return $v['name']; }, $activeViewers),
        'expires' => $metadata[$token]['expires'],
        'last_activity' => $metadata[$token]['last_activity'] ?? $metadata[$token]['created']
    ]);
    exit;
}

// POST MESSAGE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'post' && !empty($token)) {
    header('Content-Type: application/json');

    $text = $_POST['text'] ?? '';
    $author = sanitizeUsername($_POST['author'] ?? 'Guest');
    $authorId = $_POST['author_id'] ?? '';
    $urgent = isset($_POST['urgent']) && $_POST['urgent'] === '1';

    if (empty($text)) {
        echo json_encode(['success' => false, 'error' => 'Empty message']);
        exit;
    }

    if (strlen($text) > MESSAGE_MAX_LENGTH) {
        echo json_encode(['success' => false, 'error' => 'Message too long']);
        exit;
    }

    // Validate author_id
    if (empty($authorId) || !preg_match('/^user_[a-f0-9]{16}$/', $authorId)) {
        echo json_encode(['success' => false, 'error' => 'Invalid user ID']);
        exit;
    }

    // Rate limit check
    if (!checkRateLimit($authorId)) {
        echo json_encode(['success' => false, 'error' => 'Rate limit exceeded']);
        exit;
    }

    $metadata = loadMetadata($metadataFile);
    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    $jsonPath = $textsDir . '.' . $token . '.json';
    $conversation = migrateToConversation($token, $textsDir, $metadata[$token]);

    // Sanitize HTML
    $text = sanitizeHtml($text);

    // Check for ! prefix (urgent)
    $plainText = strip_tags($text);
    if (substr(trim($plainText), 0, 1) === '!') {
        $urgent = true;
    }

    $messageId = generateMessageId();
    $now = time();

    $conversation['messages'][] = [
        'id' => $messageId,
        'author' => $author,
        'author_id' => $authorId,
        'text' => $text,
        'time' => $now,
        'edited' => null,
        'deleted' => false,
        'urgent' => $urgent
    ];

    saveConversation($jsonPath, $conversation);

    // Update metadata
    $metadata[$token]['message_count'] = count($conversation['messages']);
    $metadata[$token]['last_activity'] = $now;
    saveMetadata($metadataFile, $metadata);

    writeAuditLog('chat_message', "Message in conversation: $token by $author", 'anonymous');

    echo json_encode([
        'success' => true,
        'message_id' => $messageId,
        'time' => $now
    ]);
    exit;
}

// EDIT MESSAGE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'edit' && !empty($token)) {
    header('Content-Type: application/json');

    $messageId = $_POST['message_id'] ?? '';
    $text = $_POST['text'] ?? '';
    $authorId = $_POST['author_id'] ?? '';

    if (empty($messageId) || empty($text)) {
        echo json_encode(['success' => false, 'error' => 'Missing data']);
        exit;
    }

    $metadata = loadMetadata($metadataFile);
    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    $jsonPath = $textsDir . '.' . $token . '.json';
    $conversation = migrateToConversation($token, $textsDir, $metadata[$token]);

    $found = false;
    foreach ($conversation['messages'] as &$msg) {
        if ($msg['id'] === $messageId) {
            // Verify ownership
            if ($msg['author_id'] !== $authorId) {
                echo json_encode(['success' => false, 'error' => 'Not authorized']);
                exit;
            }

            $msg['text'] = sanitizeHtml($text);
            $msg['edited'] = time();
            $found = true;
            break;
        }
    }

    if (!$found) {
        echo json_encode(['success' => false, 'error' => 'Message not found']);
        exit;
    }

    saveConversation($jsonPath, $conversation);

    // Update last activity
    $metadata[$token]['last_activity'] = time();
    saveMetadata($metadataFile, $metadata);

    echo json_encode(['success' => true]);
    exit;
}

// DELETE MESSAGE (soft delete)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'delete' && !empty($token)) {
    header('Content-Type: application/json');

    $messageId = $_POST['message_id'] ?? '';
    $authorId = $_POST['author_id'] ?? '';

    if (empty($messageId)) {
        echo json_encode(['success' => false, 'error' => 'Missing message ID']);
        exit;
    }

    $metadata = loadMetadata($metadataFile);
    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    $jsonPath = $textsDir . '.' . $token . '.json';
    $conversation = migrateToConversation($token, $textsDir, $metadata[$token]);

    $found = false;
    foreach ($conversation['messages'] as &$msg) {
        if ($msg['id'] === $messageId) {
            // Verify ownership
            if ($msg['author_id'] !== $authorId) {
                echo json_encode(['success' => false, 'error' => 'Not authorized']);
                exit;
            }

            $msg['deleted'] = true;
            $msg['edited'] = time();
            $found = true;
            break;
        }
    }

    if (!$found) {
        echo json_encode(['success' => false, 'error' => 'Message not found']);
        exit;
    }

    saveConversation($jsonPath, $conversation);

    echo json_encode(['success' => true]);
    exit;
}

// HEARTBEAT (viewer presence)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'heartbeat' && !empty($token)) {
    header('Content-Type: application/json');

    $userId = $_POST['user_id'] ?? '';
    $userName = sanitizeUsername($_POST['user_name'] ?? 'Guest');

    if (empty($userId)) {
        echo json_encode(['success' => false, 'error' => 'Missing user ID']);
        exit;
    }

    $metadata = loadMetadata($metadataFile);
    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    // Initialize viewers array if not exists
    if (!isset($metadata[$token]['viewers'])) {
        $metadata[$token]['viewers'] = [];
    }

    $metadata[$token]['viewers'][$userId] = [
        'name' => $userName,
        'last_seen' => time()
    ];

    // Clean up old viewers
    $now = time();
    $metadata[$token]['viewers'] = array_filter($metadata[$token]['viewers'], function($v) use ($now) {
        return ($now - $v['last_seen']) < HEARTBEAT_TIMEOUT * 2;
    });

    saveMetadata($metadataFile, $metadata);

    // Count active viewers
    $activeViewers = array_filter($metadata[$token]['viewers'], function($v) use ($now) {
        return ($now - $v['last_seen']) < HEARTBEAT_TIMEOUT;
    });

    echo json_encode([
        'success' => true,
        'viewer_count' => count($activeViewers),
        'viewers' => array_map(function($v) { return $v['name']; }, $activeViewers)
    ]);
    exit;
}

// EXTEND TIME
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'extend' && !empty($token)) {
    header('Content-Type: application/json');

    $extendBy = $_POST['extend'] ?? '';

    $metadata = loadMetadata($metadataFile);
    if (!isset($metadata[$token])) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }

    $currentExpires = $metadata[$token]['expires'];

    switch ($extendBy) {
        case '1h':
            $newExpires = $currentExpires + 3600;
            break;
        case '1d':
            $newExpires = $currentExpires + (24 * 3600);
            break;
        case '1w':
            $newExpires = $currentExpires + (7 * 24 * 3600);
            break;
        default:
            echo json_encode(['success' => false, 'error' => 'Invalid extend option']);
            exit;
    }

    $metadata[$token]['expires'] = $newExpires;
    saveMetadata($metadataFile, $metadata);

    writeAuditLog('chat_extend', "Extended conversation: $token by $extendBy", 'anonymous');

    echo json_encode(['success' => true, 'new_expires' => $newExpires]);
    exit;
}

// ========================================
// LEGACY: Handle text UPDATE (POST with edit key)
// ========================================
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

    $html = sanitizeHtml($html);

    if (strlen($html) > TEXT_MAX_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Content too large']);
        exit;
    }

    // For legacy support, update the first message in conversation
    $jsonPath = $textsDir . '.' . $token . '.json';
    $conversation = migrateToConversation($token, $textsDir, $metadata[$token]);

    if (!empty($conversation['messages'])) {
        $conversation['messages'][0]['text'] = $html;
        $conversation['messages'][0]['edited'] = time();
    }

    saveConversation($jsonPath, $conversation);

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

    writeAuditLog('text_update', "Updated text: $token (" . strlen($html) . " chars)", 'anonymous');

    echo json_encode(['success' => true]);
    exit;
}

// ========================================
// LEGACY: Handle text EXTEND (POST with edit key)
// ========================================
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
            $newExpires = time() + (10 * 365 * 24 * 3600);
            break;
        default:
            echo json_encode(['success' => false, 'error' => 'Invalid extend option']);
            exit;
    }

    $metadata[$token]['expires'] = $newExpires;
    saveMetadata($metadataFile, $metadata);

    writeAuditLog('text_extend', "Extended text: $token by $extendBy", 'anonymous');

    echo json_encode(['success' => true, 'new_expires' => $newExpires]);
    exit;
}

// ========================================
// Handle text CREATION (POST)
// ========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create'])) {
    header('Content-Type: application/json');

    $html = $_POST['html'] ?? '';
    $author = sanitizeUsername($_POST['author'] ?? 'Creator');

    if (empty($html)) {
        echo json_encode(['success' => false, 'error' => 'No content']);
        exit;
    }

    $html = sanitizeHtml($html);

    if (strlen($html) > TEXT_MAX_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Content too large']);
        exit;
    }

    // Generate unique token
    $newToken = generateToken(32);
    $jsonPath = $textsDir . '.' . $newToken . '.json';
    while (file_exists($jsonPath)) {
        $newToken = generateToken(32);
        $jsonPath = $textsDir . '.' . $newToken . '.json';
    }

    // Generate edit key and user ID
    $newEditKey = generateToken(32);
    $creatorId = generateUserId();

    // Create conversation with first message
    $now = time();
    $conversation = [
        'messages' => [[
            'id' => generateMessageId(),
            'author' => $author,
            'author_id' => $creatorId,
            'text' => $html,
            'time' => $now,
            'edited' => null,
            'deleted' => false,
            'urgent' => false
        ]]
    ];

    saveConversation($jsonPath, $conversation);

    // Save metadata
    $metadata = loadMetadata($metadataFile);

    $plainText = strip_tags($html);
    $preview = mb_substr($plainText, 0, 50);
    if (mb_strlen($plainText) > 50) {
        $preview .= '...';
    }

    $metadata[$newToken] = [
        'created' => $now,
        'expires' => $now + (TEXT_EXPIRE_HOURS * 3600),
        'size' => strlen($html),
        'preview' => $preview,
        'views' => 0,
        'edit_key' => $newEditKey,
        'creator' => $author,
        'message_count' => 1,
        'last_activity' => $now,
        'viewers' => []
    ];

    saveMetadata($metadataFile, $metadata);

    writeAuditLog('text_create', "Created conversation: $newToken (" . strlen($html) . " chars)", 'anonymous');

    $viewUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $newToken;
    $editUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/t/' . $newToken . '?edit=' . $newEditKey;

    echo json_encode([
        'success' => true,
        'view_url' => $viewUrl,
        'edit_url' => $editUrl,
        'token' => $newToken,
        'edit_key' => $newEditKey,
        'user_id' => $creatorId
    ]);
    exit;
}

// ========================================
// VIEW MODE - Chat UI
// ========================================
if ($isViewMode) {
    $jsonPath = $textsDir . '.' . $token . '.json';
    $htmlPath = $textsDir . '.' . $token . '.html';

    // Check if exists (either format)
    if (!file_exists($jsonPath) && !file_exists($htmlPath)) {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Not Found</title></head><body><h1>Conversation not found</h1><p>This conversation does not exist or has expired.</p></body></html>';
        exit;
    }

    // Load metadata and increment views
    $metadata = loadMetadata($metadataFile);
    if (isset($metadata[$token])) {
        $metadata[$token]['views']++;
        saveMetadata($metadataFile, $metadata);
        $meta = $metadata[$token];
    } else {
        $meta = ['created' => time(), 'expires' => time() + 3600, 'views' => 1, 'creator' => 'Unknown'];
    }

    // Migrate and load conversation
    $conversation = migrateToConversation($token, $textsDir, $meta);

    // Get first message for page title
    $firstMessage = $conversation['messages'][0] ?? null;
    $pageTitle = 'Conversation';
    if ($firstMessage) {
        $plainText = strip_tags($firstMessage['text']);
        $pageTitle = mb_substr($plainText, 0, 30);
        if (mb_strlen($plainText) > 30) $pageTitle .= '...';
    }

    $created = date('Y-m-d H:i', $meta['created']);
    $expires = $meta['expires'];
    $timeRemaining = $expires - time();

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?> - Chat</title>
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
            display: flex;
            flex-direction: column;
        }

        .chat-container {
            max-width: 900px;
            width: 100%;
            margin: 20px auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            display: flex;
            flex-direction: column;
            height: calc(100vh - 40px);
            overflow: hidden;
        }

        .chat-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .chat-header-left {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .chat-header h1 {
            font-size: 20px;
            font-weight: 600;
        }

        .viewer-count {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 14px;
            opacity: 0.9;
        }

        .viewer-dots {
            display: flex;
            gap: 3px;
        }

        .viewer-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #4ade80;
        }

        .chat-header-right {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .countdown {
            font-size: 14px;
            font-family: monospace;
            background: rgba(255,255,255,0.2);
            padding: 5px 10px;
            border-radius: 4px;
        }

        .extend-btn {
            padding: 5px 10px;
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }

        .extend-btn:hover {
            background: rgba(255,255,255,0.3);
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: #f5f5f5;
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .message {
            max-width: 80%;
            display: flex;
            flex-direction: column;
        }

        .message.mine {
            align-self: flex-start;
        }

        .message.others {
            align-self: flex-end;
        }

        .message-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 4px;
            font-size: 12px;
        }

        .message.mine .message-header {
            flex-direction: row;
        }

        .message.others .message-header {
            flex-direction: row-reverse;
        }

        .message-author {
            font-weight: 600;
        }

        .message-time {
            color: #888;
        }

        .message-edited {
            color: #888;
            font-style: italic;
        }

        .message-bubble {
            padding: 12px 16px;
            border-radius: 12px;
            position: relative;
            word-wrap: break-word;
        }

        .message.mine .message-bubble {
            background: #e3f2fd;
            border-bottom-left-radius: 4px;
        }

        .message.others .message-bubble {
            background: white;
            border-bottom-right-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .message.urgent .message-bubble {
            border: 2px solid #ef4444;
            animation: urgent-pulse 1s ease-in-out 3;
        }

        @keyframes urgent-pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            50% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
        }

        .message-bubble .ql-editor {
            padding: 0;
            font-size: 14px;
            line-height: 1.5;
        }

        .message-bubble p {
            margin: 0 0 8px 0;
        }

        .message-bubble p:last-child {
            margin-bottom: 0;
        }

        .message-deleted {
            font-style: italic;
            color: #888;
        }

        .message-actions {
            display: none;
            gap: 5px;
            margin-top: 5px;
        }

        .message.mine:hover .message-actions {
            display: flex;
        }

        .message-action-btn {
            padding: 3px 8px;
            font-size: 11px;
            background: #eee;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }

        .message-action-btn:hover {
            background: #ddd;
        }

        .chat-input {
            background: white;
            border-top: 1px solid #ddd;
            padding: 15px 20px;
        }

        .chat-input-top {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
            align-items: center;
            flex-wrap: wrap;
        }

        .name-input-wrapper {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .name-input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            width: 150px;
        }

        .user-color-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #888;
            flex-shrink: 0;
        }

        .notification-toggles {
            display: flex;
            gap: 5px;
        }

        .notification-toggle {
            padding: 8px 12px;
            background: #f0f0f0;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.2s;
        }

        .notification-toggle.active {
            background: #667eea;
            color: white;
        }

        .notification-toggle:hover {
            transform: scale(1.05);
        }

        .editor-with-send {
            display: flex;
            gap: 10px;
            align-items: flex-end;
            margin-bottom: 10px;
        }

        #editor-container {
            flex: 1;
            border: 1px solid #ddd;
            border-radius: 6px;
            background: white;
        }

        #editor-container .ql-toolbar {
            border: none;
            border-bottom: 1px solid #ddd;
            border-radius: 6px 6px 0 0;
        }

        #editor-container .ql-container {
            border: none;
            border-radius: 0 0 6px 6px;
            min-height: 60px;
            max-height: 150px;
            overflow-y: auto;
        }

        .chat-input-bottom {
            display: flex;
            justify-content: flex-start;
            align-items: center;
        }

        .urgent-hint {
            font-size: 12px;
            color: #888;
        }

        .send-btn {
            width: 50px;
            height: 50px;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .send-btn svg {
            margin-left: 3px;
        }

        .send-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.5);
        }

        .send-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
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
            z-index: 100;
        }

        .speedtest-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }

        /* Edit modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: white;
            padding: 20px;
            border-radius: 12px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #666;
        }

        #edit-editor-container {
            border: 1px solid #ddd;
            border-radius: 6px;
            margin-bottom: 15px;
        }

        #edit-editor-container .ql-toolbar {
            border: none;
            border-bottom: 1px solid #ddd;
        }

        #edit-editor-container .ql-container {
            border: none;
            min-height: 100px;
        }

        .modal-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        @media (max-width: 600px) {
            .chat-container {
                margin: 10px;
                height: calc(100vh - 20px);
            }

            .message {
                max-width: 90%;
            }

            .chat-header {
                padding: 10px 15px;
            }

            .chat-input-top {
                flex-direction: column;
                align-items: stretch;
            }

            .name-input {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank">Speed Test</a>
    <?php endif; ?>

    <div class="chat-container">
        <div class="chat-header">
            <div class="chat-header-left">
                <h1>Разговор</h1>
                <div class="viewer-count">
                    <span id="viewer-count">1</span> онлайн
                    <div class="viewer-dots" id="viewer-dots">
                        <div class="viewer-dot"></div>
                    </div>
                </div>
            </div>
            <div class="chat-header-right">
                <div class="countdown" id="countdown">--:--:--</div>
                <button class="extend-btn" onclick="extendTime('1h')">+1ч</button>
                <button class="extend-btn" onclick="extendTime('1d')">+1д</button>
                <button class="extend-btn" onclick="extendTime('1w')">+1с</button>
            </div>
        </div>

        <div class="chat-messages" id="chat-messages">
            <!-- Messages will be rendered here -->
        </div>

        <div class="chat-input">
            <div class="chat-input-top">
                <div class="name-input-wrapper">
                    <input type="text" class="name-input" id="user-name" placeholder="Гост" maxlength="30">
                    <span class="user-color-dot" id="user-color-dot"></span>
                </div>
                <div class="notification-toggles">
                    <button class="notification-toggle" id="sound-toggle" onclick="toggleSound()" title="Звукови известия">🔇</button>
                    <button class="notification-toggle" id="flash-toggle" onclick="toggleFlash()" title="Мигане на прозореца">💡</button>
                </div>
            </div>
            <div class="editor-with-send">
                <div id="editor-container"></div>
                <button class="send-btn" id="send-btn" onclick="sendMessage()" title="Изпрати (Ctrl+Enter)">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor">
                        <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
                    </svg>
                </button>
            </div>
            <div class="chat-input-bottom">
                <span class="urgent-hint">! = спешно известие &nbsp;|&nbsp; Ctrl+Enter = изпрати</span>
            </div>
        </div>
    </div>

    <!-- Edit Modal -->
    <div class="modal" id="edit-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Редактирай</h3>
                <button class="modal-close" onclick="closeEditModal()">&times;</button>
            </div>
            <div id="edit-editor-container"></div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeEditModal()">Отказ</button>
                <button class="btn btn-primary" onclick="saveEdit()">Запази</button>
            </div>
        </div>
    </div>

    <script src="/assets/quill/quill.js"></script>
    <script>
        // Configuration
        const TOKEN = '<?= htmlspecialchars($token) ?>';
        const POLL_MESSAGES = <?= POLL_INTERVAL_MESSAGES ?>;
        const POLL_HEARTBEAT = <?= POLL_INTERVAL_HEARTBEAT ?>;
        const HAS_EDIT_ACCESS = <?= $hasEditAccess ? 'true' : 'false' ?>;

        // State
        let userId = localStorage.getItem('chat_user_id_' + TOKEN);
        if (!userId) {
            userId = 'user_' + Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
            localStorage.setItem('chat_user_id_' + TOKEN, userId);
        }

        // Random guest color for this session (based on visually distinct hue)
        const guestSessionHue = Math.floor(Math.random() * 360);
        const guestSessionColor = `hsl(${guestSessionHue}, 70%, 45%)`;

        let lastMessageTime = 0;
        let messages = [];
        let soundEnabled = localStorage.getItem('chat_sound') === 'true';
        let flashEnabled = localStorage.getItem('chat_flash') === 'true';
        let expires = <?= $expires ?>;
        let editingMessageId = null;
        let documentHasFocus = true;
        let originalTitle = document.title;
        let flashInterval = null;

        // Audio context for notification beep
        let audioContext = null;

        // Initialize Quill editors
        const quill = new Quill('#editor-container', {
            theme: 'snow',
            modules: {
                toolbar: [
                    ['bold', 'italic', 'underline'],
                    ['code-block'],
                    ['link'],
                    ['clean']
                ]
            },
            placeholder: 'Напиши съобщение...'
        });

        let editQuill = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            // Load saved username
            const savedName = localStorage.getItem('chat_username');
            if (savedName) {
                document.getElementById('user-name').value = savedName;
            }

            // Update color dot
            updateColorDot();

            // Update toggle states
            updateToggleStates();

            // Load initial messages
            fetchMessages();

            // Start polling
            setInterval(fetchMessages, POLL_MESSAGES);
            setInterval(sendHeartbeat, POLL_HEARTBEAT);

            // Send initial heartbeat
            sendHeartbeat();

            // Start countdown
            updateCountdown();
            setInterval(updateCountdown, 1000);

            // Focus tracking
            window.addEventListener('focus', () => {
                documentHasFocus = true;
                stopFlash();
            });
            window.addEventListener('blur', () => {
                documentHasFocus = false;
            });

            // Keyboard shortcut
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'Enter') {
                    sendMessage();
                }
            });

            // Update color dot on name change
            document.getElementById('user-name').addEventListener('input', updateColorDot);

            // Save username on change
            document.getElementById('user-name').addEventListener('change', (e) => {
                localStorage.setItem('chat_username', e.target.value);
            });
        });

        // Color from name hash (guests get session random color)
        function getColorForName(name, isCurrentUser = false) {
            // If it's a guest (empty or "Гост"), use session random color for current user
            if (isCurrentUser && (!name || name === 'Гост' || name === 'Guest')) {
                return guestSessionColor;
            }
            let hash = 0;
            for (let i = 0; i < name.length; i++) {
                hash = name.charCodeAt(i) + ((hash << 5) - hash);
            }
            const hue = Math.abs(hash) % 360;
            return `hsl(${hue}, 70%, 45%)`;
        }

        // Update the color dot next to name input
        function updateColorDot() {
            const nameInput = document.getElementById('user-name');
            const colorDot = document.getElementById('user-color-dot');
            const name = nameInput.value.trim();
            colorDot.style.background = getColorForName(name || 'Гост', true);
        }

        // Fetch messages
        async function fetchMessages() {
            try {
                const response = await fetch(`/t/${TOKEN}?action=messages&since=${lastMessageTime}`);
                const data = await response.json();

                if (data.success) {
                    let hasNewMessages = false;
                    let hasUrgent = false;

                    data.messages.forEach(msg => {
                        const existingIndex = messages.findIndex(m => m.id === msg.id);
                        if (existingIndex >= 0) {
                            messages[existingIndex] = msg;
                        } else {
                            messages.push(msg);
                            if (msg.author_id !== userId) {
                                hasNewMessages = true;
                                if (msg.urgent) hasUrgent = true;
                            }
                        }
                        if (msg.time > lastMessageTime) lastMessageTime = msg.time;
                        if (msg.edited && msg.edited > lastMessageTime) lastMessageTime = msg.edited;
                    });

                    // Sort by time
                    messages.sort((a, b) => a.time - b.time);

                    renderMessages();

                    // Update viewer count
                    updateViewerCount(data.viewer_count, data.viewers);

                    // Update expiration
                    if (data.expires) {
                        expires = data.expires;
                    }

                    // Notifications
                    if (hasNewMessages && !documentHasFocus) {
                        if (soundEnabled || hasUrgent) {
                            playNotificationSound();
                        }
                        if (flashEnabled || hasUrgent) {
                            startFlash();
                        }
                    }
                }
            } catch (e) {
                console.error('Failed to fetch messages:', e);
            }
        }

        // Render messages
        function renderMessages() {
            const container = document.getElementById('chat-messages');
            const wasAtBottom = container.scrollHeight - container.scrollTop <= container.clientHeight + 50;

            container.innerHTML = messages.map(msg => {
                if (msg.deleted) {
                    return `
                        <div class="message ${msg.author_id === userId ? 'mine' : 'others'}">
                            <div class="message-header">
                                <span class="message-author" style="color: ${getColorForName(msg.author)}">${escapeHtml(msg.author)}</span>
                                <span class="message-time">${formatTime(msg.time)}</span>
                            </div>
                            <div class="message-bubble">
                                <span class="message-deleted">Съобщението е изтрито</span>
                            </div>
                        </div>
                    `;
                }

                const editedText = msg.edited ? `<span class="message-edited">(редактирано)</span>` : '';
                const urgentClass = msg.urgent ? ' urgent' : '';

                return `
                    <div class="message ${msg.author_id === userId ? 'mine' : 'others'}${urgentClass}" data-id="${msg.id}">
                        <div class="message-header">
                            <span class="message-author" style="color: ${getColorForName(msg.author)}">${escapeHtml(msg.author)}</span>
                            <span class="message-time">${formatTime(msg.time)} ${editedText}</span>
                        </div>
                        <div class="message-bubble">
                            <div class="ql-editor">${msg.text}</div>
                        </div>
                        ${msg.author_id === userId ? `
                            <div class="message-actions">
                                <button class="message-action-btn" onclick="editMessage('${msg.id}')">Редактирай</button>
                                <button class="message-action-btn" onclick="deleteMessage('${msg.id}')">Изтрий</button>
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('');

            // Scroll to bottom if was at bottom
            if (wasAtBottom) {
                container.scrollTop = container.scrollHeight;
            }
        }

        // Send message
        async function sendMessage() {
            const html = quill.root.innerHTML;
            const text = quill.getText().trim();

            if (!text) return;

            const userName = document.getElementById('user-name').value.trim() || 'Гост';
            const isUrgent = text.startsWith('!') ? '1' : '0';

            document.getElementById('send-btn').disabled = true;

            try {
                const formData = new FormData();
                formData.append('text', html);
                formData.append('author', userName);
                formData.append('author_id', userId);
                formData.append('urgent', isUrgent);

                const response = await fetch(`/t/${TOKEN}?action=post`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    quill.setText('');
                    fetchMessages();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (e) {
                alert('Грешка при изпращане');
            }

            document.getElementById('send-btn').disabled = false;
        }

        // Edit message
        function editMessage(messageId) {
            const msg = messages.find(m => m.id === messageId);
            if (!msg || msg.author_id !== userId) return;

            editingMessageId = messageId;

            // Initialize edit quill if not exists
            if (!editQuill) {
                editQuill = new Quill('#edit-editor-container', {
                    theme: 'snow',
                    modules: {
                        toolbar: [
                            ['bold', 'italic', 'underline'],
                            ['code-block'],
                            ['link'],
                            ['clean']
                        ]
                    }
                });
            }

            editQuill.root.innerHTML = msg.text;
            document.getElementById('edit-modal').classList.add('show');
        }

        // Save edit
        async function saveEdit() {
            if (!editingMessageId) return;

            const html = editQuill.root.innerHTML;
            const text = editQuill.getText().trim();

            if (!text) {
                alert('Съобщението не може да е празно');
                return;
            }

            try {
                const formData = new FormData();
                formData.append('message_id', editingMessageId);
                formData.append('text', html);
                formData.append('author_id', userId);

                const response = await fetch(`/t/${TOKEN}?action=edit`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    closeEditModal();
                    fetchMessages();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (e) {
                alert('Грешка при запазване');
            }
        }

        // Close edit modal
        function closeEditModal() {
            document.getElementById('edit-modal').classList.remove('show');
            editingMessageId = null;
        }

        // Delete message
        async function deleteMessage(messageId) {
            if (!confirm('Изтрий това съобщение?')) return;

            try {
                const formData = new FormData();
                formData.append('message_id', messageId);
                formData.append('author_id', userId);

                const response = await fetch(`/t/${TOKEN}?action=delete`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    fetchMessages();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (e) {
                alert('Грешка при изтриване');
            }
        }

        // Send heartbeat
        async function sendHeartbeat() {
            const userName = document.getElementById('user-name').value.trim() || 'Гост';

            try {
                const formData = new FormData();
                formData.append('user_id', userId);
                formData.append('user_name', userName);

                const response = await fetch(`/t/${TOKEN}?action=heartbeat`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    updateViewerCount(data.viewer_count, data.viewers);
                }
            } catch (e) {
                console.error('Heartbeat failed:', e);
            }
        }

        // Update viewer count display
        function updateViewerCount(count, viewers) {
            document.getElementById('viewer-count').textContent = count;

            const dotsContainer = document.getElementById('viewer-dots');
            dotsContainer.innerHTML = '';

            for (let i = 0; i < Math.min(count, 5); i++) {
                const dot = document.createElement('div');
                dot.className = 'viewer-dot';
                if (viewers && viewers[i]) {
                    dot.style.background = getColorForName(viewers[i]);
                    dot.title = viewers[i];
                }
                dotsContainer.appendChild(dot);
            }

            if (count > 5) {
                const more = document.createElement('span');
                more.textContent = `+${count - 5}`;
                more.style.fontSize = '10px';
                more.style.marginLeft = '3px';
                dotsContainer.appendChild(more);
            }
        }

        // Update countdown
        function updateCountdown() {
            const now = Math.floor(Date.now() / 1000);
            let remaining = expires - now;

            if (remaining < 0) {
                document.getElementById('countdown').textContent = 'Expired';
                document.getElementById('countdown').style.color = '#ef4444';
                return;
            }

            const hours = Math.floor(remaining / 3600);
            const minutes = Math.floor((remaining % 3600) / 60);
            const seconds = remaining % 60;

            document.getElementById('countdown').textContent =
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }

        // Extend time
        async function extendTime(duration) {
            try {
                const formData = new FormData();
                formData.append('extend', duration);

                const response = await fetch(`/t/${TOKEN}?action=extend`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    expires = data.new_expires;
                    updateCountdown();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (e) {
                alert('Грешка при удължаване');
            }
        }

        // Toggle sound
        function toggleSound() {
            soundEnabled = !soundEnabled;
            localStorage.setItem('chat_sound', soundEnabled);
            updateToggleStates();

            if (soundEnabled) {
                // Initialize audio context on user interaction
                if (!audioContext) {
                    audioContext = new (window.AudioContext || window.webkitAudioContext)();
                }
            }
        }

        // Toggle flash
        function toggleFlash() {
            flashEnabled = !flashEnabled;
            localStorage.setItem('chat_flash', flashEnabled);
            updateToggleStates();
        }

        // Update toggle button states
        function updateToggleStates() {
            const soundBtn = document.getElementById('sound-toggle');
            const flashBtn = document.getElementById('flash-toggle');

            soundBtn.textContent = soundEnabled ? '🔔' : '🔇';
            soundBtn.classList.toggle('active', soundEnabled);

            flashBtn.classList.toggle('active', flashEnabled);
        }

        // Play notification sound
        function playNotificationSound() {
            if (!audioContext) {
                audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }

            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.value = 800;
            oscillator.type = 'sine';

            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);

            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.3);
        }

        // Start window flash
        function startFlash() {
            if (flashInterval) return;

            let isOriginal = true;
            flashInterval = setInterval(() => {
                document.title = isOriginal ? '*** Ново съобщение ***' : originalTitle;
                isOriginal = !isOriginal;
            }, 500);
        }

        // Stop window flash
        function stopFlash() {
            if (flashInterval) {
                clearInterval(flashInterval);
                flashInterval = null;
                document.title = originalTitle;
            }
        }

        // Helper: format time
        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }

        // Helper: escape HTML
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
    <?php
    exit;
}

// ========================================
// CREATE MODE (no token provided)
// ========================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Start Conversation - WebShare</title>
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

        .name-row {
            margin-bottom: 20px;
        }

        .name-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #333;
        }

        .name-input-wrapper {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .name-input {
            padding: 12px 16px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 16px;
            width: 200px;
        }

        .user-color-dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #888;
            flex-shrink: 0;
        }

        #editor-container {
            height: 300px;
            background: white;
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 6px;
        }

        #editor-container .ql-toolbar {
            border: none;
            border-bottom: 1px solid #ddd;
        }

        #editor-container .ql-container {
            border: none;
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
        }
    </style>
</head>
<body>
    <?php if ($speedtestUrl): ?>
    <a href="<?= htmlspecialchars($speedtestUrl) ?>" class="speedtest-link" target="_blank">Speed Test</a>
    <?php endif; ?>

    <div class="container">
        <div class="header">
            <h1>Нов Разговор</h1>
            <p>Създай чат стая и сподели линка</p>
        </div>

        <div class="info-box">
            Всеки с линка може да се присъедини и да отговаря. Разговорите изтичат след <?= TEXT_EXPIRE_HOURS ?> часа по подразбиране. Всеки може да удължи времето.
        </div>

        <div class="content-area">
            <div class="name-row">
                <label class="name-label">Твоето Име</label>
                <div class="name-input-wrapper">
                    <input type="text" class="name-input" id="author-name" placeholder="Гост" maxlength="30">
                    <span class="user-color-dot" id="author-color-dot"></span>
                </div>
            </div>

            <div id="editor-container"></div>

            <div class="actions">
                <button class="btn btn-primary" onclick="startConversation()" id="start-btn">
                    Започни Разговор
                </button>
                <button class="btn btn-secondary" onclick="clearEditor()">
                    Изчисти
                </button>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Създаване на разговор...</p>
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
            placeholder: 'Напиши първото си съобщение...'
        });

        // Random guest color for this session
        const guestSessionHue = Math.floor(Math.random() * 360);
        const guestSessionColor = `hsl(${guestSessionHue}, 70%, 45%)`;

        // Color from name hash
        function getColorForName(name) {
            if (!name || name === 'Гост') {
                return guestSessionColor;
            }
            let hash = 0;
            for (let i = 0; i < name.length; i++) {
                hash = name.charCodeAt(i) + ((hash << 5) - hash);
            }
            const hue = Math.abs(hash) % 360;
            return `hsl(${hue}, 70%, 45%)`;
        }

        // Update color dot
        function updateColorDot() {
            const nameInput = document.getElementById('author-name');
            const colorDot = document.getElementById('author-color-dot');
            const name = nameInput.value.trim();
            colorDot.style.background = getColorForName(name || 'Гост');
        }

        // Load saved username
        const savedName = localStorage.getItem('chat_username');
        if (savedName) {
            document.getElementById('author-name').value = savedName;
        }

        // Initialize color dot
        updateColorDot();

        // Update color dot on input
        document.getElementById('author-name').addEventListener('input', updateColorDot);

        function startConversation() {
            const html = quill.root.innerHTML;
            const text = quill.getText().trim();
            const author = document.getElementById('author-name').value.trim() || 'Гост';

            if (!text || text.length < 1) {
                alert('Моля, напиши съобщение за да започнеш разговор');
                return;
            }

            // Save username
            localStorage.setItem('chat_username', author);

            const startBtn = document.getElementById('start-btn');
            const loading = document.getElementById('loading');

            startBtn.disabled = true;
            loading.classList.add('show');

            const formData = new FormData();
            formData.append('create', '1');
            formData.append('html', html);
            formData.append('author', author);

            fetch('/t', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                loading.classList.remove('show');
                startBtn.disabled = false;

                if (data.success) {
                    // Save user ID for this conversation
                    localStorage.setItem('chat_user_id_' + data.token, data.user_id);

                    // Copy link and redirect
                    navigator.clipboard.writeText(data.view_url).then(() => {
                        window.location.href = data.view_url;
                    }).catch(() => {
                        window.location.href = data.view_url;
                    });
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                loading.classList.remove('show');
                startBtn.disabled = false;
                alert('Грешка при създаване. Опитай отново.');
            });
        }

        function clearEditor() {
            if (quill.getText().trim().length > 0) {
                quill.setText('');
            }
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
