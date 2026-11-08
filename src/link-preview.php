<?php
/**
 * Link previews / Open Graph (F7). Docs: docs/link-previews.md, D-030
 *
 * Messengers (Viber, WhatsApp, Telegram, Facebook, Slack, Discord …) fetch a
 * shared link to build a preview card. Folder pages and chats carry OG tags in
 * their HTML. A file link (/p?t=…) normally starts the download at once, so a
 * preview bot gets a tiny HTML page with the tags instead and nothing is
 * downloaded or counted.
 *
 * Setting "link_previews" (default on): show the file/folder name in previews.
 * Off: previews only say "WebShare" (nothing about the content).
 * Chats never reveal their content in a preview.
 */

function lp_enabled() {
    $cfg = @json_decode((string)@file_get_contents(__DIR__ . '/.config.json'), true) ?: [];
    return ($cfg['link_previews'] ?? true) !== false;
}

function lp_is_preview_bot($ua = null) {
    $ua = $ua ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
    return (bool)preg_match('/facebookexternalhit|Facebot|Twitterbot|TelegramBot|WhatsApp|Viber|Slackbot|Slack-ImgProxy|Discordbot|LinkedInBot|SkypeUriPreview|Teams|redditbot|Embedly|vkShare|Pinterest|Mastodon|Signal|iMessage|Applebot|Googlebot-Image/i', $ua);
}

function lp_base_url() {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $host = preg_replace('/[^A-Za-z0-9.\-:\[\]]/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    return ($https ? 'https' : 'http') . '://' . $host;
}

/** OG + Twitter tags; $title/$desc are plain text */
function lp_meta_tags($title, $desc, $path = null) {
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $url = lp_base_url() . ($path ?? strtok($_SERVER['REQUEST_URI'] ?? '/', '#'));
    $img = lp_base_url() . '/og-image.png';
    return "\n    <meta property=\"og:type\" content=\"website\">"
        . "\n    <meta property=\"og:site_name\" content=\"WebShare\">"
        . "\n    <meta property=\"og:title\" content=\"" . $e($title) . "\">"
        . "\n    <meta property=\"og:description\" content=\"" . $e($desc) . "\">"
        . "\n    <meta property=\"og:url\" content=\"" . $e($url) . "\">"
        . "\n    <meta property=\"og:image\" content=\"" . $e($img) . "\">"
        . "\n    <meta property=\"og:image:width\" content=\"1200\">"
        . "\n    <meta property=\"og:image:height\" content=\"630\">"
        . "\n    <meta name=\"twitter:card\" content=\"summary_large_image\">"
        . "\n    <meta name=\"description\" content=\"" . $e($desc) . "\">\n";
}

/** Minimal page for preview bots (no download, no counters) */
function lp_bot_page($title, $desc) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: public, max-age=300');
    echo "<!DOCTYPE html>\n<html lang=\"bg\">\n<head>\n    <meta charset=\"UTF-8\">\n    <title>"
        . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . "</title>" . lp_meta_tags($title, $desc)
        . "</head>\n<body><p>" . htmlspecialchars($desc, ENT_QUOTES, 'UTF-8') . "</p></body>\n</html>\n";
    exit;
}

function lp_size($bytes) {
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < 4) { $bytes /= 1024; $i++; }
    return round($bytes, $i ? 1 : 0) . ' ' . $u[$i];
}
