<?php
/**
 * Send Share Link via Email
 * =========================
 * Sends file share links to specified email addresses
 */

require_once __DIR__ . '/security-check.php';
session_start();
header('Content-Type: application/json');

// CSRF validation for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrfToken)) {
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'CSRF validation failed']));
    }
}

// Include required files
require_once __DIR__ . '/smtp-mailer.php';
require_once __DIR__ . '/audit-log.php';
require_once __DIR__ . '/user-management.php';

// Handle test email action (uses form data, not config)
if (isset($_GET['action']) && $_GET['action'] === 'test') {
    $testEmail = filter_var($_POST['test_email'] ?? '', FILTER_VALIDATE_EMAIL);

    if (!$testEmail) {
        echo json_encode(['success' => false, 'error' => 'Invalid test email address']);
        exit;
    }

    // Validate domain has MX records (required for receiving email)
    $emailDomain = substr(strrchr($testEmail, "@"), 1);
    if (!checkdnsrr($emailDomain, 'MX')) {
        echo json_encode(['success' => false, 'error' => 'Domain cannot receive email (no MX records): ' . $emailDomain]);
        exit;
    }

    // Get settings from form
    $smtpHost = trim($_POST['smtp_host'] ?? '');
    $smtpPort = (int)($_POST['smtp_port'] ?? 465);
    $smtpUser = trim($_POST['smtp_user'] ?? '');
    $smtpPass = $_POST['smtp_pass'] ?? '';
    $smtpEncryption = $_POST['smtp_encryption'] ?? 'ssl';
    $fromName = trim($_POST['from_name'] ?? 'WebShare');

    if (empty($smtpHost) || empty($smtpUser) || empty($smtpPass)) {
        echo json_encode(['success' => false, 'error' => 'Please fill in all SMTP settings']);
        exit;
    }

    // Create mailer instance with form data
    $mailer = new SmtpMailer($smtpHost, $smtpPort, $smtpUser, $smtpPass, $smtpEncryption);

    // Create test email HTML
    $testHtml = '
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; padding: 40px; background: #f5f5f5;">
        <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <h1 style="color: #667eea; margin: 0 0 20px 0;">WebShare Test Email</h1>
            <p style="color: #333; font-size: 16px; line-height: 1.6;">
                This is a test email from WebShare to verify your SMTP settings are working correctly.
            </p>
            <p style="color: #888; font-size: 14px; margin-top: 30px;">
                Sent at: ' . date('Y-m-d H:i:s') . '<br>
                SMTP Host: ' . htmlspecialchars($smtpHost) . '<br>
                From: ' . htmlspecialchars($smtpUser) . '
            </p>
        </div>
    </body>
    </html>';

    $result = $mailer->send($testEmail, 'WebShare - Test Email', $testHtml, $fromName);

    if ($result) {
        writeAuditLog('mail_test', "Test email sent to $testEmail", getCurrentUser() ?: 'admin');
        echo json_encode(['success' => true, 'message' => 'Test email sent successfully']);
    } else {
        writeAuditLog('mail_test_failed', "Test email failed to $testEmail: " . $mailer->getLastError(), getCurrentUser() ?: 'admin');
        echo json_encode(['success' => false, 'error' => $mailer->getLastError()]);
    }
    exit;
}

// Load configuration
$configFile = __DIR__ . '/.config.json';
$config = [];
if (file_exists($configFile)) {
    $config = json_decode(file_get_contents($configFile), true) ?: [];
}

// Check if mail is configured
if (empty($config['mail']) || empty($config['mail']['enabled'])) {
    echo json_encode(['success' => false, 'error' => 'Email is not configured on this server']);
    exit;
}

$mailConfig = $config['mail'];

// Get POST data
$toEmail = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
$shareUrl = $_POST['url'] ?? '';
$filename = $_POST['filename'] ?? '';
$senderName = $_POST['sender_name'] ?? '';
$message = $_POST['message'] ?? '';

// Validate input
if (!$toEmail) {
    echo json_encode(['success' => false, 'error' => 'Invalid email address']);
    exit;
}

// Validate domain has MX records (required for receiving email)
$emailDomain = substr(strrchr($toEmail, "@"), 1);
if (!checkdnsrr($emailDomain, 'MX')) {
    echo json_encode(['success' => false, 'error' => 'Domain cannot receive email (no MX records): ' . $emailDomain]);
    exit;
}

if (empty($shareUrl)) {
    echo json_encode(['success' => false, 'error' => 'Share URL is required']);
    exit;
}

if (empty($filename)) {
    echo json_encode(['success' => false, 'error' => 'Filename is required']);
    exit;
}

// Validate URL is from this server
$parsedUrl = parse_url($shareUrl);
$serverHost = $_SERVER['HTTP_HOST'];
if (!isset($parsedUrl['host']) || $parsedUrl['host'] !== $serverHost) {
    echo json_encode(['success' => false, 'error' => 'Invalid share URL']);
    exit;
}

// Rate limiting - max 10 emails per minute per IP
$rateLimitFile = __DIR__ . '/.mail-ratelimit.json';
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$now = time();
$rateLimit = [];

if (file_exists($rateLimitFile)) {
    $rateLimit = json_decode(file_get_contents($rateLimitFile), true) ?: [];
}

// Clean old entries (older than 1 minute)
foreach ($rateLimit as $ip => $timestamps) {
    $rateLimit[$ip] = array_filter($timestamps, function($ts) use ($now) {
        return ($now - $ts) < 60;
    });
    if (empty($rateLimit[$ip])) {
        unset($rateLimit[$ip]);
    }
}

// Check current IP
$ipSends = $rateLimit[$clientIp] ?? [];
if (count($ipSends) >= 10) {
    echo json_encode(['success' => false, 'error' => 'Too many emails sent. Please wait a minute.']);
    exit;
}

// Create mailer instance
$mailer = new SmtpMailer(
    $mailConfig['smtp_host'],
    $mailConfig['smtp_port'],
    $mailConfig['smtp_user'],
    $mailConfig['smtp_pass'],
    $mailConfig['smtp_encryption'] ?? 'tls'
);

// Get email template
$htmlBody = getShareEmailTemplate($shareUrl, $filename, $senderName, $message);

// Build subject
$subject = $senderName
    ? "{$senderName} shared a file with you: {$filename}"
    : "File shared with you: {$filename}";

// Send email
$fromName = $mailConfig['from_name'] ?? 'WebShare';
$result = $mailer->send($toEmail, $subject, $htmlBody, $fromName);

if ($result) {
    // Update rate limit
    $rateLimit[$clientIp][] = $now;
    file_put_contents($rateLimitFile, json_encode($rateLimit));

    // Audit log
    $currentUser = getCurrentUser();
    writeAuditLog('share_email', "Sent share link for '$filename' to $toEmail", $currentUser ?: 'anonymous');

    echo json_encode(['success' => true, 'message' => 'Email sent successfully']);
} else {
    $error = $mailer->getLastError();
    writeAuditLog('share_email_failed', "Failed to send share link for '$filename' to $toEmail: $error", $currentUser ?? 'anonymous');

    echo json_encode(['success' => false, 'error' => 'Failed to send email: ' . $error]);
}
