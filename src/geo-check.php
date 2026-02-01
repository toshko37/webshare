<?php
/**
 * GeoIP Check for WebShare
 * ========================
 * Include this file at the top of pages that need geo-blocking.
 * Only blocks if geo is enabled and user is not from allowed countries.
 *
 * Usage:
 *   require_once __DIR__ . '/geo-check.php';
 *   checkGeoAccess(); // Blocks if not allowed
 */

// Load Composer autoloader for MaxMind GeoIP
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

// Set timezone to match server (read from system or fallback to Europe/Sofia)
if (!defined('WEBSHARE_TIMEZONE_SET')) {
    define('WEBSHARE_TIMEZONE_SET', true);
    $systemTimezone = @file_get_contents('/etc/timezone');
    $systemTimezone = $systemTimezone ? trim($systemTimezone) : 'Europe/Sofia';
    date_default_timezone_set($systemTimezone);
}

function loadGeoConfig() {
    $configFile = __DIR__ . '/.geo.json';
    if (!file_exists($configFile)) {
        return [
            'enabled' => false,
            'allowed_countries' => ['BG'],
            'blocked_message' => 'Access denied from your location',
            'geoip_database' => '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        ];
    }
    return json_decode(file_get_contents($configFile), true);
}

function saveGeoConfig($config) {
    $configFile = __DIR__ . '/.geo.json';
    file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT));
}

function getClientIP() {
    // Check for proxy headers
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            // Handle comma-separated IPs (X-Forwarded-For)
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            // Validate IP
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function getCountryCode($ip) {
    $config = loadGeoConfig();

    // Check multiple possible locations for GeoIP database
    $dbFile = $config['geoip_database'] ?? null;
    if (!$dbFile || !file_exists($dbFile)) {
        $possiblePaths = [
            __DIR__ . '/GeoLite2-Country.mmdb',
            '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        ];
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                $dbFile = $path;
                break;
            }
        }
    }

    if (!$dbFile || !file_exists($dbFile)) {
        return null; // No database, allow access
    }

    try {
        $reader = new MaxMind\Db\Reader($dbFile);
        $record = $reader->get($ip);
        $reader->close();

        return $record['country']['iso_code'] ?? null;
    } catch (Exception $e) {
        return null; // On error, allow access
    }
}

function isGeoAllowed($ip = null) {
    $config = loadGeoConfig();

    // If geo blocking is disabled, allow all
    if (!($config['enabled'] ?? false)) {
        return true;
    }

    if ($ip === null) {
        $ip = getClientIP();
    }

    // Allow localhost/private IPs
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return true;
    }

    $countryCode = getCountryCode($ip);

    // If we can't determine country, allow access (fail-open)
    if ($countryCode === null) {
        return true;
    }

    $allowedCountries = $config['allowed_countries'] ?? ['BG'];

    return in_array($countryCode, $allowedCountries);
}

function checkGeoAccess() {
    if (!isGeoAllowed()) {
        $config = loadGeoConfig();
        http_response_code(403);

        // Return JSON for AJAX requests
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'error' => $config['blocked_message'] ?? 'Access denied'
            ]);
            exit;
        }

        // Return HTML page for regular requests
        $message = htmlspecialchars($config['blocked_message'] ?? 'Access denied from your location');
        echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        h1 { color: #e53935; margin-bottom: 10px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Access Denied</h1>
        <p>{$message}</p>
    </div>
</body>
</html>
HTML;
        exit;
    }
}

// Get country info for display
function getGeoInfo($ip = null) {
    if ($ip === null) {
        $ip = getClientIP();
    }

    // Check if it's a private/reserved IP (localhost, LAN, etc.)
    $isLocalIP = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;

    if ($isLocalIP) {
        $country = 'Local Network';
    } else {
        $country = getCountryCode($ip) ?? 'Unknown';
    }

    return [
        'ip' => $ip,
        'country' => $country,
        'allowed' => isGeoAllowed($ip)
    ];
}

/**
 * Get country from IP for audit logging
 * Returns "Local" for private/reserved IPs, country code for public IPs
 */
function getCountryFromIP($ip = null) {
    if ($ip === null) {
        $ip = getClientIP();
    }

    // Check if it's a private/reserved IP (localhost, LAN, etc.)
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return 'Local';
    }

    // Try to get country code from GeoIP
    $countryCode = getCountryCode($ip);

    return $countryCode; // Returns null if not found
}
