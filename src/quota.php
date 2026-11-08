<?php
/**
 * Per-user storage quotas (F1). Docs: docs/quotas.md, docs/decisions.md D-028
 *
 * The quota belongs to the owner of a folder tree (files/<user>/...), whoever
 * uploads into it: the user, an admin, an API key, a shared-folder upload or an
 * anonymous upload to /u/<user>. The Public folder has no owner and no quota
 * (Upload Guard limits apply there). The trash does not count (D-028).
 *
 * quota_mb($user)                   0 = unlimited; per-user value or the site default
 * quota_usage($user)                bytes in files/<user>/
 * quota_check($folderPath, $bytes)  null when allowed, otherwise an error message
 * quota_info($user)                 ['quota', 'used', 'free', 'percent'] for the UI
 */
require_once __DIR__ . '/user-management.php';
if (!defined('WS_DATA_DIR')) define('WS_DATA_DIR', __DIR__ . '/');

function quota_site_default() {
    $cfg = ws_json_read(WS_DATA_DIR . '.config.json');
    return max(0, (int)($cfg['default_quota_mb'] ?? 0));
}

function quota_mb($user) {
    $users = loadUsers();
    if (!isset($users[$user])) return 0;
    return array_key_exists('quota_mb', $users[$user]) ? max(0, (int)$users[$user]['quota_mb']) : quota_site_default();
}

function quota_usage($user) {
    static $cache = [];
    if (isset($cache[$user])) return $cache[$user];
    $dir = FILES_BASE_DIR . $user;
    $bytes = 0;
    if (is_dir($dir)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) if ($f->isFile()) $bytes += $f->getSize();
    }
    return $cache[$user] = $bytes;
}

/** Owner of a folder path, or null for Public / unknown folders */
function quota_owner($folderPath) {
    $base = parseFolderPath((string)$folderPath)['base'];
    if ($base === '' || $base === PUBLIC_FOLDER) return null;
    return userExists($base) ? $base : null;
}

/** @return string|null error message when $bytes more would exceed the owner's quota */
function quota_check($folderPath, $bytes) {
    $owner = quota_owner($folderPath);
    if ($owner === null) return null;
    $mb = quota_mb($owner);
    if ($mb <= 0) return null;
    $limit = $mb * 1048576;
    $used = quota_usage($owner);
    if ($used + $bytes <= $limit) return null;
    $fmt = fn($b) => $b >= 1073741824 ? round($b / 1073741824, 2) . ' GB' : round($b / 1048576, 1) . ' MB';
    return "Storage quota exceeded for \"$owner\": " . $fmt($used) . ' of ' . $fmt($limit) . ' used, this file needs ' . $fmt($bytes) . '.';
}

function quota_info($user) {
    $mb = quota_mb($user);
    $used = quota_usage($user);
    $limit = $mb * 1048576;
    return ['quota' => $limit, 'used' => $used, 'free' => $mb ? max(0, $limit - $used) : null,
        'percent' => $mb ? min(100, (int)round($used * 100 / $limit)) : null];
}

/** Admin: set a user's quota (null = follow the site default) */
function quota_set($user, $mb) {
    return ws_json_update(USERS_FILE, function (&$users) use ($user, $mb) {
        if (!isset($users[$user])) return false;
        if ($mb === null) unset($users[$user]['quota_mb']); else $users[$user]['quota_mb'] = max(0, (int)$mb);
        return true;
    }) !== false;
}
