<?php
/**
 * Security Check - Include at top of protected files
 * Verifies .htaccess exists for authentication protection
 */

if (!file_exists(__DIR__ . '/.htaccess')) {
    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    die('<!DOCTYPE html><html><head><title>Security Error</title></head><body style="font-family:sans-serif;padding:50px;text-align:center;"><h1>Security Configuration Missing</h1><p>The .htaccess file is missing. Access denied for security reasons.</p><p style="color:#666;">Contact the system administrator.</p></body></html>');
}
