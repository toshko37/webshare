<?php
/**
 * Security Headers
 * Include this file at the top of any PHP file that serves content
 */

// Prevent MIME type sniffing
header('X-Content-Type-Options: nosniff');

// Prevent clickjacking (allow same origin for iframes)
header('X-Frame-Options: SAMEORIGIN');

// Enable XSS filter in browsers
header('X-XSS-Protection: 1; mode=block');

// Control referrer information
header('Referrer-Policy: strict-origin-when-cross-origin');

// Disable potentially dangerous browser features
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// Force HTTPS for 1 year (only if already on HTTPS)
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
