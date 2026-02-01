<?php
/**
 * Version Check API
 * Checks for latest version from GitHub (stable) or webshare.techbg.net (dev)
 *
 * Config: .update-config.json
 * { "stable": true }  - Check GitHub releases (default)
 * { "stable": false } - Check webshare.techbg.net/version.json (for testing)
 */

header('Content-Type: application/json');

// Get current version from index.php (single source of truth)
$indexFile = __DIR__ . '/index.php';
$currentVersion = '0.0.0';
if (file_exists($indexFile)) {
    $indexContent = file_get_contents($indexFile);
    if (preg_match("/WEBSHARE_VERSION['\"],\s*['\"]([^'\"]+)['\"]/", $indexContent, $matches)) {
        $currentVersion = $matches[1];
    }
}
define('WEBSHARE_VERSION', $currentVersion);

$cacheFile = __DIR__ . '/.version-check.json';
$configFile = __DIR__ . '/.update-config.json';
$cacheMaxAge = 86400; // 24 hours in seconds

// Load update config
$config = ['stable' => true]; // Default: use GitHub
if (file_exists($configFile)) {
    $configData = json_decode(file_get_contents($configFile), true);
    if (isset($configData['stable'])) {
        $config['stable'] = (bool)$configData['stable'];
    }
}

$githubRepo = 'toshko37/webshare';
$devVersionUrl = 'https://webshare.techbg.net/src/version.json';

// Check if we should use cache
$useCache = true;
$forceCheck = isset($_GET['force']) && $_GET['force'] === '1';

if ($forceCheck) {
    $useCache = false;
}

// Try to read from cache
if ($useCache && file_exists($cacheFile)) {
    $cache = json_decode(file_get_contents($cacheFile), true);
    if ($cache && isset($cache['checked_at'])) {
        $age = time() - $cache['checked_at'];
        if ($age < $cacheMaxAge) {
            // Return cached result
            $cache['from_cache'] = true;
            $cache['cache_age'] = $age;
            $cache['current_version'] = WEBSHARE_VERSION;
            $cache['update_available'] = version_compare($cache['latest_version'] ?? WEBSHARE_VERSION, WEBSHARE_VERSION, '>');
            echo json_encode($cache);
            exit;
        }
    }
}

// Initialize result
$result = [
    'success' => false,
    'current_version' => WEBSHARE_VERSION,
    'latest_version' => null,
    'update_available' => false,
    'release_url' => null,
    'release_notes' => null,
    'published_at' => null,
    'checked_at' => time(),
    'from_cache' => false,
    'source' => $config['stable'] ? 'github' : 'dev',
    'error' => null
];

// Check if cURL is available
if (!function_exists('curl_init')) {
    $result['error'] = 'cURL extension not installed';
    file_put_contents($cacheFile, json_encode($result, JSON_PRETTY_PRINT));
    echo json_encode($result);
    exit;
}

// Choose source based on config
if ($config['stable']) {
    // ========== STABLE: Check GitHub releases ==========
    $apiUrl = "https://api.github.com/repos/{$githubRepo}/releases/latest";

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $apiUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => [
            'User-Agent: WebShare-UpdateChecker/' . WEBSHARE_VERSION,
            'Accept: application/vnd.github.v3+json'
        ]
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    $curlErrno = curl_errno($ch);
    curl_close($ch);

    if ($curlErrno !== 0) {
        $result['error'] = "cURL error ($curlErrno): $curlError";
    } elseif ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        if ($data && isset($data['tag_name'])) {
            $latestVersion = ltrim($data['tag_name'], 'v');

            $result['success'] = true;
            $result['latest_version'] = $latestVersion;
            $result['update_available'] = version_compare($latestVersion, WEBSHARE_VERSION, '>');
            $result['release_url'] = $data['html_url'] ?? null;
            $result['release_notes'] = $data['body'] ?? null;
            $result['published_at'] = $data['published_at'] ?? null;
            $result['download_url'] = null;

            // Find tar.gz asset
            if (isset($data['assets']) && is_array($data['assets'])) {
                foreach ($data['assets'] as $asset) {
                    if (strpos($asset['name'], '.tar.gz') !== false) {
                        $result['download_url'] = $asset['browser_download_url'];
                        break;
                    }
                }
            }

            // Fallback to tarball_url
            if (!$result['download_url'] && isset($data['tarball_url'])) {
                $result['download_url'] = $data['tarball_url'];
            }
        }
    } elseif ($httpCode === 404) {
        $result['success'] = true;
        $result['latest_version'] = WEBSHARE_VERSION;
        $result['update_available'] = false;
        $result['error'] = 'No releases found';
    } else {
        $result['error'] = "GitHub API error (HTTP {$httpCode})";
    }

} else {
    // ========== DEV: Check webshare.techbg.net ==========
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $devVersionUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => [
            'User-Agent: WebShare-UpdateChecker/' . WEBSHARE_VERSION
        ]
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    $curlErrno = curl_errno($ch);
    curl_close($ch);

    if ($curlErrno !== 0) {
        $result['error'] = "cURL error ($curlErrno): $curlError";
    } elseif ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        if ($data && isset($data['version'])) {
            $latestVersion = $data['version'];

            $result['success'] = true;
            $result['latest_version'] = $latestVersion;
            $result['update_available'] = version_compare($latestVersion, WEBSHARE_VERSION, '>');
            $result['release_notes'] = $data['changelog'] ?? null;
            $result['published_at'] = $data['released'] ?? null;
            $result['download_url'] = $data['download_url'] ?? null;
        }
    } else {
        $result['error'] = "Dev server error (HTTP {$httpCode})";
    }
}

// Save to cache
file_put_contents($cacheFile, json_encode($result, JSON_PRETTY_PRINT));

echo json_encode($result);
