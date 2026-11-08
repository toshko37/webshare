<?php
// ── Upgrade bridge (since 3.9.1, docs/decisions.md D-031) ────────────────
// Installs on 3.8.1 or older update through their OWN live-update.php, which
// downloads only the files it knew about. Newer code needs more files, so the
// first page load after such an update would end in a fatal error. geo-check.php is
// on every old list and is loaded first by the public pages (copy of security-check.php): it fetches the missing files from the
// signed release (tag of WEBSHARE_VERSION), checks the signature and every
// hash, and only then lets the page continue. Self-contained on purpose.
if (!function_exists('_ws_upgrade_bridge')) {
function _ws_upgrade_bridge($dir) {
    $files = [
        'security-check.php',
        'login.php',
        'logout.php',
        'index.php',
        'upload.php',
        'upload-guard.php',
        'error-page.php',
        'auth-guard.php',
        'json-store.php',
        'release-verify.php',
        'trash.php',
        'quota.php',
        'chat-guard.php',
        'link-preview.php',
        'zip-job.php',
        'public.php',
        'download.php',
        't.php',
        'text.php',
        'share.php',
        'folder-management.php',
        'encryption.php',
        'audit-log.php',
        'geo-check.php',
        'user-management.php',
        'html-sanitizer.php',
        'smtp-mailer.php',
        'send-mail.php',
        'web-download.php',
        'api-upload.php',
        'api-scripts.php',
        'check-version.php',
        'do-update.php',
        'live-update.php',
        'p.php',
        'u.php',
        'f.php',
        'get.php',
        'get-speedtest.php',
        'get-update.php',
        'get-update-script.php',
        'security-headers.php',
        'ui-kit.css',
        'ui-kit.js',
        'favicon.ico',
        'favicon.svg',
        'apple-touch-icon.png',
        'CHANGELOG.md',
        'version.json',
        'robots.txt',
        'og-image.png',
        'assets/quill/quill.js',
        'assets/quill/quill.snow.css',
    ];
    $missing = array_values(array_filter($files, fn($f) => !is_file("$dir/$f")));
    if (!$missing) return;
    $lock = @fopen("$dir/.upgrade-bridge.lock", 'c');
    if ($lock) flock($lock, LOCK_EX);
    $missing = array_values(array_filter($missing, fn($f) => !is_file("$dir/$f")));   // another request may have finished
    if (!$missing) return;
    $fail = function ($why) use ($dir) {
        http_response_code(503);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html lang="bg"><meta charset="utf-8"><title>WebShare: незавършено обновяване</title>'
            . '<body style="font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px">'
            . '<h1>Обновяването не е завършено</h1><p>Липсват файлове от новата версия и не можаха да се изтеглят автоматично ('
            . htmlspecialchars($why) . ').</p><p>Пусни на сървъра: <code>sudo ' . htmlspecialchars(dirname($dir)) . '/installer/update.sh -y</code> '
            . 'или <code>curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/update.sh | sudo INSTALL_DIR=' . htmlspecialchars(dirname($dir)) . ' bash -s -- -y</code></p></body></html>';
        exit;
    };
    if (!function_exists('sodium_crypto_sign_verify_detached') || !function_exists('curl_init')) $fail('php-sodium or php-curl is missing');
    if (!preg_match("/WEBSHARE_VERSION['\"],\s*['\"](\d+\.\d+\.\d+)['\"]/", (string)@file_get_contents("$dir/index.php"), $vm)) $fail('version not found');
    $base = 'https://raw.githubusercontent.com/toshko37/webshare/v' . $vm[1] . '/src/';
    $get = function ($url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 60,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_USERAGENT => 'WebShare-UpgradeBridge']);
        $body = curl_exec($ch);
        $ok = curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200;
        curl_close($ch);
        return $ok && is_string($body) ? $body : null;
    };
    $manifest = $get($base . 'release-manifest.json');
    $sig = base64_decode(trim((string)$get($base . 'release-manifest.sig')), true);
    $pub = base64_decode('26hboeSIRIWj+kGUw9QZA5N/pOBjBwU/YRUN96C3H1E=', true);
    if ($manifest === null || $sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
        || !sodium_crypto_sign_verify_detached($sig, $manifest, $pub)) $fail('release signature could not be verified');
    $hashes = json_decode($manifest, true)['files'] ?? [];
    foreach ($missing as $f) {
        if (!isset($hashes[$f]) || !preg_match('#^[A-Za-z0-9._/-]+$#', $f) || strpos($f, '..') !== false) $fail("$f is not in the signed release");
        $body = $get($base . $f);
        if ($body === null || !hash_equals($hashes[$f], hash('sha256', $body))) $fail("$f could not be downloaded or failed its checksum");
        @mkdir(dirname("$dir/$f"), 0755, true);
        if (file_put_contents("$dir/$f.bridge-tmp", $body) === false || !rename("$dir/$f.bridge-tmp", "$dir/$f")) $fail("$f could not be written");
    }
    if (function_exists('opcache_reset')) @opcache_reset();
    error_log('WebShare upgrade bridge: installed ' . implode(', ', $missing));
}
}
_ws_upgrade_bridge(__DIR__);
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

require_once __DIR__ . '/auth-guard.php';

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

/**
 * Client IP for GeoIP decisions (I14).
 * Proxy headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are set by the
 * client and are trusted ONLY when the direct peer (REMOTE_ADDR) is listed in
 * "trusted_proxies" in .geo.json (IPs or CIDRs, e.g. Cloudflare ranges or a
 * local reverse proxy). Default: no trusted proxies, REMOTE_ADDR only.
 * Docs: docs/security-plan-2.md
 */
function getClientIP() {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $config = loadGeoConfig();
    $trusted = $config['trusted_proxies'] ?? [];
    if (!$trusted || !geoIpInList($remote, $trusted)) {
        return $remote;
    }
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $h) {
        if (!empty($_SERVER[$h]) && filter_var(trim($_SERVER[$h]), FILTER_VALIDATE_IP)) {
            return trim($_SERVER[$h]);
        }
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Right-most address that is not one of our proxies is the real client
        $chain = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
        foreach ($chain as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) break;
            if (!geoIpInList($ip, $trusted)) return $ip;
        }
    }
    return $remote;
}

/** Kept for compatibility; see ws_ip_in_list() in auth-guard.php */
function geoIpInList($ip, array $list) {
    return ws_ip_in_list($ip, $list);
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
            background: linear-gradient(135deg, #4C51BF 0%, #764ba2 100%);
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
