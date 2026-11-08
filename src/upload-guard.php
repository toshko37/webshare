<?php
/**
 * WebShare Upload Guard
 * =====================
 * Regulates anonymous uploads to /u and /u/USERNAME:
 *   - one-time bot verification (self-hosted proof-of-work or Cloudflare Turnstile)
 *   - time-limited "upload pass" (cookie for browsers, short code for curl)
 *   - per-pass quotas, per-IP pass rate limit, daily cap, free-disk floor
 *   - blocking of dangerous file types for anonymous uploads
 *
 * Full documentation: docs/upload-guard.md (repository root, not served)
 */

if (!defined('UG_DIR'))        define('UG_DIR',        __DIR__ . '/.upload-passes/');
if (!defined('UG_KEY_FILE'))   define('UG_KEY_FILE',   __DIR__ . '/.upload-guard.key');
if (!defined('UG_STATE_FILE')) define('UG_STATE_FILE', __DIR__ . '/.upload-guard-state.json');
if (!defined('UG_FLAG_ON'))    define('UG_FLAG_ON',    __DIR__ . '/.upload-guard-on');
if (!defined('UG_FLAG_CURL'))  define('UG_FLAG_CURL',  __DIR__ . '/.upload-guard-curl-open');
if (!defined('UG_COOKIE'))     define('UG_COOKIE',     'ws_upass');

// Code alphabet without look-alike characters (0/O, 1/I/L). 32 symbols = 5 bits each.
const UG_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// Window in which a just-uploaded file may still be removed via the Stop button
const UG_DELETE_WINDOW = 900;

// ── Configuration ──────────────────────────────────────────────────────────

require_once __DIR__ . '/auth-guard.php';

function ug_defaults() {
    return [
        'mode'               => 'verified', // verified | open | login
        'provider'           => 'pow',      // pow | turnstile
        'pow_maxnumber'      => 50000,      // proof-of-work difficulty (average work = half)
        'turnstile_site_key' => '',
        'turnstile_secret'   => '',
        'pass_ttl_hours'     => 24,
        'pass_max_files'     => 20,
        'pass_max_mb'        => 5120,       // 5 GB per pass
        'max_file_mb'        => 2048,       // 2 GB per anonymous file
        'passes_per_ip_hour' => 5,
        'daily_cap_mb'       => 20480,      // 20 GB of anonymous uploads per day
        'min_free_gb'        => 10,
        'curl_without_pass'  => false,
        'block_dangerous'    => true,
        'notify_owner'       => true,
        'trusted_networks'   => [],         // F9: IPs/CIDRs without per-IP limits (e.g. a LAN behind one NAT address)
    ];
}

function ug_load_site_config() {
    $file = __DIR__ . '/.config.json';
    if (!file_exists($file)) return [];
    return json_decode(file_get_contents($file), true) ?: [];
}

/**
 * Effective guard configuration (defaults + saved values + compatibility rules)
 */
function ug_config($siteConfig = null) {
    if ($siteConfig === null) $siteConfig = ug_load_site_config();
    $saved = is_array($siteConfig['upload_guard'] ?? null) ? $siteConfig['upload_guard'] : [];
    $cfg = array_merge(ug_defaults(), $saved);

    // Legacy setting: open_upload=false (before v3.7.0) means login-only
    if (!isset($saved['mode']) && array_key_exists('open_upload', $siteConfig) && $siteConfig['open_upload'] === false) {
        $cfg['mode'] = 'login';
    }
    if (!in_array($cfg['mode'], ['verified', 'open', 'login'], true)) $cfg['mode'] = 'verified';
    if (!in_array($cfg['provider'], ['pow', 'turnstile'], true)) $cfg['provider'] = 'pow';

    // Turnstile without both keys cannot work - fall back to proof-of-work
    $cfg['provider_effective'] = $cfg['provider'];
    if ($cfg['provider'] === 'turnstile' && ($cfg['turnstile_site_key'] === '' || $cfg['turnstile_secret'] === '')) {
        $cfg['provider_effective'] = 'pow';
    }
    return $cfg;
}

/**
 * Sanitize admin input into a storable guard config
 */
function ug_sanitize_config(array $in, array $current) {
    $d = ug_defaults();
    $out = $current;
    $int = function ($key, $min, $max) use ($in, &$out) {
        if (!isset($in[$key])) return;
        $v = (int)$in[$key];
        $out[$key] = max($min, min($max, $v));
    };
    if (isset($in['mode']) && in_array($in['mode'], ['verified', 'open', 'login'], true)) $out['mode'] = $in['mode'];
    if (isset($in['provider']) && in_array($in['provider'], ['pow', 'turnstile'], true)) $out['provider'] = $in['provider'];
    $int('pow_maxnumber', 1000, 1000000);
    $int('pass_ttl_hours', 1, 720);
    $int('pass_max_files', 1, 10000);
    $int('pass_max_mb', 1, 10240);
    $int('max_file_mb', 1, 10240);
    $int('passes_per_ip_hour', 1, 1000);
    $int('daily_cap_mb', 1, 10485760);
    $int('min_free_gb', 0, 100000);
    if (isset($in['turnstile_site_key'])) $out['turnstile_site_key'] = trim(preg_replace('/[^A-Za-z0-9_\-]/', '', $in['turnstile_site_key']));
    // Empty secret field keeps the stored secret (it is never echoed back to the form)
    if (isset($in['turnstile_secret']) && trim($in['turnstile_secret']) !== '') {
        $out['turnstile_secret'] = trim(preg_replace('/[^A-Za-z0-9_\-\.]/', '', $in['turnstile_secret']));
    }
    if (isset($in['trusted_networks'])) {
        $list = is_array($in['trusted_networks']) ? $in['trusted_networks']
            : preg_split('/[\s,]+/', trim((string)$in['trusted_networks']), -1, PREG_SPLIT_NO_EMPTY);
        $out['trusted_networks'] = array_values(array_unique(array_filter(array_map('trim', $list), function ($e) {
            [$ip, $bits] = array_pad(explode('/', $e, 2), 2, null);
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
            if ($bits === null) return true;
            $max = strpos($ip, ':') !== false ? 128 : 32;
            return ctype_digit($bits) && (int)$bits <= $max;
        })));
    }
    foreach (['curl_without_pass', 'block_dangerous', 'notify_owner'] as $b) {
        if (array_key_exists($b, $in)) $out[$b] = (bool)$in[$b];
    }
    // Drop unknown keys
    return array_intersect_key($out + $d, $d);
}

/**
 * Keep the Apache pre-filter flag files in sync with the config.
 * .htaccess checks for these files with -f because it cannot read JSON.
 */
function ug_sync_flags($cfg) {
    $wantOn   = $cfg['mode'] === 'verified';
    $wantCurl = $wantOn && !empty($cfg['curl_without_pass']);
    if ($wantOn !== file_exists(UG_FLAG_ON)) {
        $wantOn ? @touch(UG_FLAG_ON) : @unlink(UG_FLAG_ON);
    }
    if ($wantCurl !== file_exists(UG_FLAG_CURL)) {
        $wantCurl ? @touch(UG_FLAG_CURL) : @unlink(UG_FLAG_CURL);
    }
}

// ── Small helpers ──────────────────────────────────────────────────────────

/**
 * Client IP. Uses REMOTE_ADDR only: proxy headers are client-controlled and
 * would let anyone bypass the per-IP limits. Behind a reverse proxy, configure
 * mod_remoteip in Apache so REMOTE_ADDR carries the real address.
 */
function ug_client_ip() {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function ug_secret() {
    static $secret = null;
    if ($secret !== null) return $secret;
    if (file_exists(UG_KEY_FILE)) {
        $secret = trim(file_get_contents(UG_KEY_FILE));
    }
    if (empty($secret) || strlen($secret) < 32) {
        $secret = bin2hex(random_bytes(32));
        file_put_contents(UG_KEY_FILE, $secret, LOCK_EX);
        @chmod(UG_KEY_FILE, 0600);
    }
    return $secret;
}

/**
 * Atomic read-modify-write of a JSON file under an exclusive lock.
 * $fn receives the decoded array by reference; its return value is passed through.
 */
function ug_locked_update($file, callable $fn) {
    $fp = @fopen($file, 'c+');
    if (!$fp) return null;
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw ?: '[]', true);
    if (!is_array($data)) $data = [];
    $result = $fn($data);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @chmod($file, 0600);
    return $result;
}

function ug_read_json($file) {
    if (!file_exists($file)) return null;
    $fp = @fopen($file, 'r');
    if (!$fp) return null;
    flock($fp, LOCK_SH);
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function ug_prune_state(array &$s) {
    $now = time();
    foreach (($s['used'] ?? []) as $k => $exp) {
        if ($exp < $now) unset($s['used'][$k]);
    }
    foreach (['ip_passes', 'ip_fail'] as $bucket) {
        foreach (($s[$bucket] ?? []) as $ip => $list) {
            $list = array_values(array_filter($list, fn($t) => $t > $now - 3600));
            if ($list) $s[$bucket][$ip] = $list; else unset($s[$bucket][$ip]);
        }
    }
    $keep = date('Y-m-d', $now - 7 * 86400);
    foreach (($s['daily'] ?? []) as $day => $bytes) {
        if ($day < $keep) unset($s['daily'][$day]);
    }
}

function ug_format_code($code) {
    return substr($code, 0, 4) . '-' . substr($code, 4, 4);
}

function ug_normalize_code($code) {
    return preg_replace('/[^A-Z0-9]/', '', strtoupper((string)$code));
}

function ug_is_https() {
    return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
}

function ug_mb($mb) {
    return (int)$mb * 1024 * 1024;
}

// ── Bot verification: proof-of-work (ALTCHA-compatible format) ────────────

function ug_create_challenge($cfg) {
    $max = max(1000, (int)$cfg['pow_maxnumber']);
    $expires = time() + 600;
    $salt = bin2hex(random_bytes(12)) . '?expires=' . $expires;
    $number = random_int(0, $max);
    $challenge = hash('sha256', $salt . $number);
    return [
        'algorithm' => 'SHA-256',
        'challenge' => $challenge,
        'salt'      => $salt,
        'maxnumber' => $max,
        'signature' => hash_hmac('sha256', $challenge, ug_secret()),
    ];
}

/**
 * @return true|string true on success, otherwise an error code
 */
function ug_verify_pow($payload) {
    $salt      = (string)($payload['salt'] ?? '');
    $number    = $payload['number'] ?? null;
    $challenge = (string)($payload['challenge'] ?? '');
    $signature = (string)($payload['signature'] ?? '');

    if ($salt === '' || $challenge === '' || $signature === '' || !is_numeric($number)) return 'malformed';
    if (!preg_match('/\?expires=(\d+)$/', $salt, $m)) return 'malformed';
    $expires = (int)$m[1];
    if ($expires < time()) return 'expired';
    if (!hash_equals(hash_hmac('sha256', $challenge, ug_secret()), $signature)) return 'bad_signature';
    if (!hash_equals($challenge, hash('sha256', $salt . (int)$number))) return 'wrong_answer';

    // Replay protection: each challenge can be redeemed once
    $fresh = ug_locked_update(UG_STATE_FILE, function (&$s) use ($challenge, $expires) {
        ug_prune_state($s);
        if (isset($s['used'][$challenge])) return false;
        $s['used'][$challenge] = $expires;
        return true;
    });
    return $fresh ? true : 'replayed';
}

// ── Bot verification: Cloudflare Turnstile ─────────────────────────────────

function ug_verify_turnstile($token, $cfg) {
    if (!is_string($token) || $token === '' || strlen($token) > 4096) return 'malformed';
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $cfg['turnstile_secret'],
            'response' => $token,
            'remoteip' => ug_client_ip(),
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $raw = curl_exec($ch);
    curl_close($ch);
    if ($raw === false) return 'provider_unreachable';
    $res = json_decode($raw, true);
    return !empty($res['success']) ? true : 'rejected';
}

// ── Passes ─────────────────────────────────────────────────────────────────

/**
 * Check the per-IP limits before running a verification.
 * @return true|string
 */
/** F9: requests from trusted networks are exempt from the per-IP limits */
function ug_ip_trusted($cfg, $ip = null) {
    $list = $cfg['trusted_networks'] ?? [];
    return $list && ws_ip_in_list($ip ?? ug_client_ip(), $list);
}

function ug_ip_may_verify($cfg) {
    $ip = ug_client_ip();
    if (ug_ip_trusted($cfg, $ip)) return true;
    $s = ug_read_json(UG_STATE_FILE) ?? [];
    $hourAgo = time() - 3600;
    $issued = count(array_filter($s['ip_passes'][$ip] ?? [], fn($t) => $t > $hourAgo));
    $failed = count(array_filter($s['ip_fail'][$ip] ?? [], fn($t) => $t > $hourAgo));
    if ($issued >= (int)$cfg['passes_per_ip_hour']) return 'ip_pass_limit';
    if ($failed >= 30) return 'ip_fail_limit';
    return true;
}

function ug_record_failure() {
    $ip = ug_client_ip();
    ug_locked_update(UG_STATE_FILE, function (&$s) use ($ip) {
        ug_prune_state($s);
        $s['ip_fail'][$ip][] = time();
    });
}

function ug_generate_code() {
    $code = '';
    $max = strlen(UG_CODE_ALPHABET) - 1;
    for ($i = 0; $i < 8; $i++) $code .= UG_CODE_ALPHABET[random_int(0, $max)];
    return $code;
}

function ug_ensure_dir() {
    if (!is_dir(UG_DIR)) {
        @mkdir(UG_DIR, 0700, true);
    }
}

function ug_pass_file($id) {
    return UG_DIR . $id . '.json';
}

function ug_code_file($code) {
    return UG_DIR . 'code-' . $code . '.json';
}

/**
 * Create a pass after a successful verification and set the browser cookie.
 */
function ug_issue_pass($cfg, $provider) {
    ug_ensure_dir();
    $ip = ug_client_ip();
    $now = time();

    $id = bin2hex(random_bytes(16));
    do { $code = ug_generate_code(); } while (file_exists(ug_code_file($code)));

    $pass = [
        'id'         => $id,
        'code'       => $code,
        'created'    => $now,
        'expires'    => $now + (int)$cfg['pass_ttl_hours'] * 3600,
        'ip'         => $ip,
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
        'provider'   => $provider,
        'max_files'  => (int)$cfg['pass_max_files'],
        'max_bytes'  => ug_mb($cfg['pass_max_mb']),
        'files'      => [],
        'bytes'      => 0,
        'revoked'    => false,
    ];
    file_put_contents(ug_pass_file($id), json_encode($pass, JSON_PRETTY_PRINT), LOCK_EX);
    file_put_contents(ug_code_file($code), json_encode(['id' => $id, 'expires' => $pass['expires']]), LOCK_EX);
    @chmod(ug_pass_file($id), 0600);
    @chmod(ug_code_file($code), 0600);

    ug_locked_update(UG_STATE_FILE, function (&$s) use ($ip, $now) {
        ug_prune_state($s);
        $s['ip_passes'][$ip][] = $now;
    });

    setcookie(UG_COOKIE, $id, [
        'expires'  => $pass['expires'],
        'path'     => '/',
        'secure'   => ug_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[UG_COOKIE] = $id;
    return $pass;
}

function ug_load_pass($id) {
    if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/', $id)) return null;
    return ug_read_json(ug_pass_file($id));
}

function ug_load_pass_by_code($code) {
    $code = ug_normalize_code($code);
    if (strlen($code) !== 8) return null;
    $ref = ug_read_json(ug_code_file($code));
    return $ref ? ug_load_pass($ref['id'] ?? '') : null;
}

/**
 * Find the pass presented with this request.
 * Sources, in order: X-Upload-Pass header, ?pass= query, POST "pass", cookie.
 * Header/query/POST accept the short code or the full id.
 *
 * Expiry is compared with REQUEST_TIME (start of the request) so that a large
 * upload started while the pass was valid is not rejected at the end.
 *
 * @return array [pass|null, reason|null]  reason: missing|invalid|expired|revoked
 */
function ug_current_pass() {
    $candidates = [];
    foreach ([
        $_SERVER['HTTP_X_UPLOAD_PASS'] ?? null,
        $_GET['pass'] ?? null,
        $_POST['pass'] ?? null,
        $_COOKIE[UG_COOKIE] ?? null,
    ] as $v) {
        if (is_string($v) && trim($v) !== '') $candidates[] = trim($v);
    }
    if (!$candidates) return [null, 'missing'];

    $reason = 'invalid';
    foreach ($candidates as $c) {
        $pass = preg_match('/^[a-f0-9]{32}$/', $c) ? ug_load_pass($c) : ug_load_pass_by_code($c);
        if (!$pass) continue;
        if (!empty($pass['revoked'])) { $reason = 'revoked'; continue; }
        $started = (int)($_SERVER['REQUEST_TIME'] ?? time());
        if ($pass['expires'] < $started) { $reason = 'expired'; continue; }
        return [$pass, null];
    }
    return [null, $reason];
}

/**
 * Public view of a pass for the browser (never includes IP or other passes' data)
 */
function ug_pass_public($pass) {
    if (!$pass) return null;
    return [
        'code'       => ug_format_code($pass['code']),
        'expires'    => $pass['expires'],
        'files_left' => max(0, $pass['max_files'] - count($pass['files'])),
        'bytes_left' => max(0, $pass['max_bytes'] - $pass['bytes']),
        'max_files'  => $pass['max_files'],
        'max_bytes'  => $pass['max_bytes'],
    ];
}

// ── Upload checks ──────────────────────────────────────────────────────────

/**
 * Dangerous names: hidden files (.htaccess, .user.ini) and any server-side
 * script extension in any position (file.php.jpg).
 */
function ug_is_dangerous_name($name) {
    $name = strtolower(basename($name));
    if ($name === '' || $name[0] === '.') return true;
    $bad = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar',
            'cgi', 'pl', 'py', 'shtml', 'htaccess', 'htpasswd', 'asp', 'aspx', 'jsp'];
    $parts = explode('.', $name);
    array_shift($parts); // the part before the first dot is the base name
    foreach ($parts as $p) {
        if (in_array($p, $bad, true)) return true;
    }
    return false;
}

/**
 * Validate an anonymous upload against all limits.
 * @return array|null null when allowed, otherwise ['code', 'message', 'http']
 */
function ug_check_upload($cfg, $pass, $size, $filename, $uploadDir) {
    if (!empty($cfg['block_dangerous']) && ug_is_dangerous_name($filename)) {
        return ['blocked_type', 'This file type is not allowed for anonymous uploads.', 415];
    }
    if ($size > ug_mb($cfg['max_file_mb'])) {
        return ['file_too_large', 'File exceeds the anonymous upload limit of ' . $cfg['max_file_mb'] . ' MB.', 413];
    }
    if ($pass) {
        if (count($pass['files']) >= $pass['max_files']) {
            return ['quota_files', 'Upload pass file limit reached. Verify again for a new pass.', 429];
        }
        if ($pass['bytes'] + $size > $pass['max_bytes']) {
            return ['quota_bytes', 'Upload pass size limit reached. Verify again for a new pass.', 429];
        }
    }
    $s = ug_read_json(UG_STATE_FILE) ?? [];
    $today = $s['daily'][date('Y-m-d')] ?? 0;
    if ($today + $size > ug_mb($cfg['daily_cap_mb'])) {
        return ['daily_cap', 'Daily anonymous upload limit reached. Try again tomorrow.', 429];
    }
    $free = @disk_free_space($uploadDir);
    if ($free !== false && ($free - $size) < (int)$cfg['min_free_gb'] * 1024 * 1024 * 1024) {
        return ['disk_low', 'The server is low on storage. Anonymous uploads are paused.', 507];
    }
    return null;
}

/**
 * Account a successful anonymous upload (daily total and, if present, the pass).
 * @return array|null updated pass
 */
function ug_record_upload($pass, $originalName, $finalName, $folder, $size) {
    $size = (int)$size;
    ug_locked_update(UG_STATE_FILE, function (&$s) use ($size) {
        ug_prune_state($s);
        $day = date('Y-m-d');
        $s['daily'][$day] = ($s['daily'][$day] ?? 0) + $size;
    });
    if (!$pass || !file_exists(ug_pass_file($pass['id']))) return null;
    return ug_locked_update(ug_pass_file($pass['id']), function (&$p) use ($originalName, $finalName, $folder, $size) {
        $p['files'][] = [
            'original' => $originalName,
            'final'    => $finalName,
            'folder'   => $folder,
            'size'     => $size,
            'time'     => time(),
        ];
        $p['bytes'] = ($p['bytes'] ?? 0) + $size;
        return $p;
    });
}

/**
 * Stop button: delete a file only if THIS pass uploaded it in the last 15 min.
 * Replaces the old behaviour that deleted any file with the given name.
 * @return string|null deleted final filename
 */
function ug_delete_recent($pass, $name, $filesBase) {
    $name = basename((string)$name);
    if (!$pass || $name === '') return null;
    return ug_locked_update(ug_pass_file($pass['id']), function (&$p) use ($name, $filesBase) {
        $files = $p['files'] ?? [];
        // Exact stored name first, then the original name (the browser only
        // knows the original name when the upload is aborted). Newest wins.
        foreach (['final', 'original'] as $field) {
            for ($i = count($files) - 1; $i >= 0; $i--) {
                $f = $files[$i];
                if ($f[$field] !== $name || $f['time'] <= time() - UG_DELETE_WINDOW) continue;
                $path = rtrim($filesBase, '/') . '/' . $f['folder'] . '/' . $f['final'];
                if (is_file($path)) @unlink($path);
                $p['bytes'] = max(0, ($p['bytes'] ?? 0) - $f['size']);
                array_splice($p['files'], $i, 1);
                return $f['final'];
            }
        }
        return null;
    });
}

// ── Logged-in users bypass the guard ───────────────────────────────────────

/**
 * Username of a valid logged-in session, without creating sessions for
 * anonymous visitors. read_and_close avoids holding the session lock during
 * long uploads (which would freeze the user's other tabs).
 */
function ug_session_user() {
    if (session_status() === PHP_SESSION_NONE) {
        if (empty($_COOKIE[session_name()])) return null;
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'secure'   => ug_is_https(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start(['read_and_close' => true]);
    }
    $user = $_SESSION['username'] ?? null;
    if (!$user) return null;
    if (!file_exists(__DIR__ . '/.sessions/' . session_id() . '.json')) return null;
    return $user;
}

// ── Admin ──────────────────────────────────────────────────────────────────

function ug_list_passes($includeExpired = false) {
    $out = [];
    if (!is_dir(UG_DIR)) return $out;
    foreach (glob(UG_DIR . '*.json') as $file) {
        if (strpos(basename($file), 'code-') === 0) continue;
        $p = ug_read_json($file);
        if (!$p) continue;
        if (!$includeExpired && ($p['expires'] < time() || !empty($p['revoked']))) continue;
        $out[] = $p;
    }
    usort($out, fn($a, $b) => $b['created'] <=> $a['created']);
    return $out;
}

function ug_revoke_pass($id) {
    $pass = ug_load_pass($id);
    if (!$pass) return false;
    ug_locked_update(ug_pass_file($id), function (&$p) {
        $p['revoked'] = true;
    });
    return $pass;
}

/**
 * Remove passes that expired more than 7 days ago (kept briefly for audits).
 */
function ug_cleanup() {
    if (!is_dir(UG_DIR)) return 0;
    $removed = 0;
    $limit = time() - 7 * 86400;
    foreach (glob(UG_DIR . '*.json') as $file) {
        $p = ug_read_json($file);
        if ($p && ($p['expires'] ?? 0) < $limit) {
            @unlink($file);
            $removed++;
        }
    }
    return $removed;
}

function ug_stats() {
    $s = ug_read_json(UG_STATE_FILE) ?? [];
    return [
        'today_bytes'   => $s['daily'][date('Y-m-d')] ?? 0,
        'active_passes' => count(ug_list_passes()),
    ];
}

// ── Owner notification ─────────────────────────────────────────────────────

/**
 * E-mail the owner about an anonymous upload, after the response has been
 * sent (fastcgi_finish_request) so SMTP latency does not delay the uploader.
 */
function ug_notify_owner_deferred($cfg, $siteConfig, $folder, $fileName, $size, $pass) {
    if (empty($cfg['notify_owner'])) return;
    $mail = $siteConfig['mail'] ?? [];
    if (empty($mail['enabled']) || empty($mail['smtp_host'])) return;
    $to = $mail['notify_email'] ?? $mail['smtp_user'] ?? '';
    if ($to === '') return;

    $ip = ug_client_ip();
    $code = $pass ? ug_format_code($pass['code']) : '—';
    register_shutdown_function(function () use ($mail, $to, $folder, $fileName, $size, $ip, $code) {
        if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();
        require_once __DIR__ . '/smtp-mailer.php';
        $folderDisplay = $folder === '_public' ? 'Public' : $folder;
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
        $sizeMb = round($size / 1048576, 2);
        $html = "<p>Нов анонимен файл в WebShare.</p>"
              . "<table cellpadding='4'>"
              . "<tr><td><b>Папка</b></td><td>{$e($folderDisplay)}</td></tr>"
              . "<tr><td><b>Файл</b></td><td>{$e($fileName)}</td></tr>"
              . "<tr><td><b>Размер</b></td><td>{$e($sizeMb)} MB</td></tr>"
              . "<tr><td><b>IP</b></td><td>{$e($ip)}</td></tr>"
              . "<tr><td><b>Пропуск</b></td><td>{$e($code)}</td></tr>"
              . "<tr><td><b>Време</b></td><td>" . date('Y-m-d H:i:s') . "</td></tr>"
              . "</table>";
        try {
            $mailer = new SmtpMailer($mail['smtp_host'], (int)($mail['smtp_port'] ?? 587),
                $mail['smtp_user'] ?? '', $mail['smtp_pass'] ?? '', $mail['smtp_encryption'] ?? 'tls');
            $mailer->send($to, "WebShare: нов файл в $folderDisplay", $html, $mail['from_name'] ?? 'WebShare');
        } catch (Throwable $t) {
            error_log('upload-guard notify failed: ' . $t->getMessage());
        }
    });
}
