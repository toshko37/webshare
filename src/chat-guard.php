<?php
/**
 * Anonymous chat protection (F8). Docs: docs/chat-guard.md, docs/decisions.md D-029
 *
 * Creating a chat without being logged in needs an invisible proof-of-work
 * (the same signed, expiring, single-use challenge as Upload Guard), and is
 * limited per IP per hour and by the number of active chats. Trusted networks
 * from Upload Guard skip the per-IP limit. Posting into an existing chat needs
 * the private link and is rate limited separately (t.php, I10).
 */
require_once __DIR__ . '/upload-guard.php';
require_once __DIR__ . '/json-store.php';

if (!defined('CG_STATE_FILE')) define('CG_STATE_FILE', __DIR__ . '/.chat-guard-state.json');

function cg_defaults() {
    return ['enabled' => true, 'per_ip_hour' => 10, 'max_active' => 300];
}

function cg_config($siteConfig = null) {
    if ($siteConfig === null) $siteConfig = ug_load_site_config();
    $c = array_merge(cg_defaults(), is_array($siteConfig['chat_guard'] ?? null) ? $siteConfig['chat_guard'] : []);
    $c['enabled'] = (bool)$c['enabled'];
    $c['per_ip_hour'] = max(1, min(1000, (int)$c['per_ip_hour']));
    $c['max_active'] = max(1, min(100000, (int)$c['max_active']));
    return $c;
}

function cg_sanitize(array $in) {
    return cg_config(['chat_guard' => [
        'enabled' => !empty($in['enabled']),
        'per_ip_hour' => $in['per_ip_hour'] ?? 10,
        'max_active' => $in['max_active'] ?? 300,
    ]]);
}

/** A logged-in user creates chats without the check */
function cg_exempt() {
    return ug_session_user() !== null;
}

/**
 * Check a chat creation request.
 * @param array|null $pow  decoded proof-of-work payload from the client
 * @param array $metadata  .texts.json contents (to count active chats)
 * @return array|null null when allowed, else [code, message, http status]
 */
function cg_check_create($pow, array $metadata, $cfg = null) {
    $cfg = $cfg ?? cg_config();
    if (!$cfg['enabled'] || cg_exempt()) return null;

    $active = 0;
    foreach ($metadata as $m) if (($m['expires'] ?? 0) > time()) $active++;
    if ($active >= $cfg['max_active']) {
        return ['chat_capacity', 'Too many active chats right now. Try again later.', 503];
    }

    $ugCfg = ug_config();
    $ip = ug_client_ip();
    if (!ug_ip_trusted($ugCfg, $ip)) {
        $s = ws_json_read(CG_STATE_FILE);
        $recent = array_filter($s['ip_created'][$ip] ?? [], fn($t) => $t > time() - 3600);
        if (count($recent) >= $cfg['per_ip_hour']) {
            return ['chat_ip_limit', 'Too many new chats from your address. Try again in an hour.', 429];
        }
    }

    if (!is_array($pow)) {
        return ['chat_verify_required', 'The browser check is missing. Reload the page and try again.', 403];
    }
    $r = ug_verify_pow($pow);
    if ($r !== true) {
        if ($r !== 'expired') ug_record_failure();
        return ['chat_verify_failed', 'The browser check failed (' . $r . '). Reload the page and try again.', 403];
    }
    return null;
}

function cg_record_create() {
    if (cg_exempt()) return;
    $ip = ug_client_ip();
    ws_json_update(CG_STATE_FILE, function (&$s) use ($ip) {
        $cut = time() - 3600;
        foreach ($s['ip_created'] ?? [] as $k => $list) {
            $s['ip_created'][$k] = array_values(array_filter($list, fn($t) => $t > $cut));
            if (!$s['ip_created'][$k]) unset($s['ip_created'][$k]);
        }
        $s['ip_created'][$ip][] = time();
    });
}
