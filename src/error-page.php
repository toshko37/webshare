<?php
/**
 * Styled error page for public links (shared files, folders, chats).
 * Replaces bare die('...') text, which had no title, language or mobile
 * viewport (UI/UX audit X15, docs/ui-ux-audit-2026-11-08.md).
 */
if (!function_exists('wsErrorPage')) {
    /**
     * Send an HTTP status with a small, mobile-friendly page and stop.
     * @param int    $status  HTTP status code
     * @param string $title   Short Bulgarian heading
     * @param string $message One or two sentences explaining what to do
     */
    function wsErrorPage($status, $title, $message = '') {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: text/html; charset=utf-8');
            header('X-Robots-Tag: noindex');
        }
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
        $v = defined('WEBSHARE_VERSION') ? '?v=' . urlencode(WEBSHARE_VERSION) : '';
        echo '<!DOCTYPE html><html lang="bg"><head><meta charset="UTF-8">'
           . '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
           . '<meta name="robots" content="noindex">'
           . '<title>' . $e($title) . ' - WebShare</title>'
           . '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
           . '<link rel="stylesheet" href="/ui-kit.css' . $v . '">'
           . '</head><body class="ws-error-page"><main class="ws-error-card">'
           . '<div class="ws-error-code">Грешка ' . (int)$status . '</div>'
           . '<h1>' . $e($title) . '</h1>'
           . ($message !== '' ? '<p>' . $e($message) . '</p>' : '')
           . '</main></body></html>';
        exit;
    }
}
