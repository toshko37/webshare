<?php
/**
 * Trash / recycle bin (F2). Docs: docs/trash.md, docs/decisions.md D-027
 *
 * Deleted files are moved (rename, same filesystem) to <install>/trash/, outside
 * the DocumentRoot, and kept for "trash_days" days (Settings, default 30, 0 = off).
 * Share links, file metadata and encryption metadata of the file are stored
 * with the item and come back on restore.
 *
 * trash_move_file($folder, $name, $by)   file -> trash, returns ['success', 'id']
 * trash_move_folder($folder, $by, $label) whole folder -> trash (deleted user)
 * trash_list($user)                       items the user may see (admin: all)
 * trash_restore($id, $user)               back to the original folder (renamed if taken)
 * trash_delete($id, $user)                delete permanently
 * trash_empty($user)                      delete all visible items permanently
 * trash_purge()                           remove expired items (called lazily, at most hourly)
 */
require_once __DIR__ . '/json-store.php';
require_once __DIR__ . '/user-management.php';   // isAdmin(), folder helpers

if (!defined('WS_TRASH_DIR')) define('WS_TRASH_DIR', dirname(__DIR__) . '/trash/');
if (!defined('WS_DATA_DIR'))  define('WS_DATA_DIR', __DIR__ . '/');   // where .tokens.json etc. live (tests override)
define('WS_TRASH_INDEX', WS_TRASH_DIR . 'index.json');

function trash_days() {
    $cfg = ws_json_read(WS_DATA_DIR . '.config.json');
    return isset($cfg['trash_days']) ? max(0, min(365, (int)$cfg['trash_days'])) : 30;
}

function trash_enabled() {
    return trash_days() > 0;
}

function trash_ensure_dir() {
    if (!is_dir(WS_TRASH_DIR)) {
        @mkdir(WS_TRASH_DIR, 0750, true);
    }
    return is_dir(WS_TRASH_DIR) && is_writable(WS_TRASH_DIR);
}

function trash_dir_size($path) {
    if (is_file($path)) return filesize($path);
    $size = 0;
    if (!is_dir($path)) return 0;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) if ($f->isFile()) $size += $f->getSize();
    return $size;
}

function trash_rmrf($path) {
    if (is_link($path) || is_file($path)) return @unlink($path);
    if (!is_dir($path)) return true;
    foreach (array_diff(scandir($path), ['.', '..']) as $e) trash_rmrf("$path/$e");
    return @rmdir($path);
}

/** Take (and remove) the share links, file and encryption metadata of a file */
function trash_detach_metadata($folder, $name) {
    $key = $folder ? "$folder/$name" : $name;
    $tokens = [];
    ws_json_update(WS_DATA_DIR . '.tokens.json', function (&$all) use ($folder, $name, &$tokens) {
        foreach ($all as $t => $d) {
            if (!is_array($d)) continue;
            $f = $d['folder'] ?? null;
            if (($d['filename'] ?? '') === $name && ((string)$f === (string)$folder)) {
                $tokens[$t] = $d;
                unset($all[$t]);
            }
        }
        return $tokens ? true : false;
    });
    $meta = null;
    ws_json_update(WS_DATA_DIR . '.files-meta.json', function (&$all) use ($key, $name, &$meta) {
        foreach ([$key, $name] as $k) {
            if (isset($all[$k])) { $meta = $all[$k]; unset($all[$k]); return true; }
        }
        return false;
    });
    $enc = null;
    if (substr($name, -4) === '.enc') {
        ws_json_update(WS_DATA_DIR . '.encryption-keys.json', function (&$all) use ($key, $name, &$enc) {
            foreach ([$key, $name] as $k) {
                if (isset($all[$k])) { $enc = $all[$k]; unset($all[$k]); return true; }
            }
            return false;
        });
    }
    return ['tokens' => $tokens, 'meta' => $meta, 'enc' => $enc];
}

function trash_attach_metadata($folder, $name, $item) {
    $key = $folder ? "$folder/$name" : $name;
    if (!empty($item['tokens'])) {
        ws_json_update(WS_DATA_DIR . '.tokens.json', function (&$all) use ($item, $folder, $name) {
            foreach ($item['tokens'] as $t => $d) {
                if (isset($all[$t])) continue;   // token reused meanwhile: keep the newer link
                $d['filename'] = $name;
                $d['folder'] = $folder;
                $all[$t] = $d;
            }
        });
    }
    if (!empty($item['meta'])) {
        ws_json_update(WS_DATA_DIR . '.files-meta.json', function (&$all) use ($key, $item) {
            $all[$key] = $item['meta'];
        });
    }
    if (!empty($item['enc'])) {
        ws_json_update(WS_DATA_DIR . '.encryption-keys.json', function (&$all) use ($key, $item) {
            $all[$key] = $item['enc'];
        });
        @chmod(WS_DATA_DIR . '.encryption-keys.json', 0600);
    }
}

/**
 * Move a file to the trash. $folder is the folder path relative to files/
 * (e.g. "dimo", "dimo/sub", "_public"); null only for very old root files.
 */
function trash_move_file($folder, $name, $deletedBy) {
    $name = basename($name);
    $src = FILES_BASE_DIR . ($folder ? $folder . '/' : '') . $name;
    if (!is_file($src)) return ['success' => false, 'error' => 'File not found'];
    if (!trash_enabled()) {
        if (!@unlink($src)) return ['success' => false, 'error' => 'Failed to delete file'];
        trash_detach_metadata($folder, $name);
        return ['success' => true, 'id' => null, 'permanent' => true];
    }
    if (!trash_ensure_dir()) return ['success' => false, 'error' => 'Trash folder is not writable'];
    $id = bin2hex(random_bytes(8));
    $size = filesize($src);
    if (!@rename($src, WS_TRASH_DIR . $id)) return ['success' => false, 'error' => 'Failed to move file to trash'];
    $item = ['id' => $id, 'type' => 'file', 'name' => $name, 'folder' => $folder,
        'size' => $size, 'deleted_at' => time(), 'deleted_by' => $deletedBy] + trash_detach_metadata($folder, $name);
    ws_json_update(WS_TRASH_INDEX, function (&$all) use ($item) { $all[$item['id']] = $item; });
    return ['success' => true, 'id' => $id];
}

/** Move a whole folder (e.g. of a deleted user) to the trash as one item */
function trash_move_folder($folder, $deletedBy, $label = null) {
    $src = rtrim(FILES_BASE_DIR . $folder, '/');
    if (!is_dir($src)) return ['success' => true, 'id' => null];
    if (!trash_enabled()) {
        trash_rmrf($src);
        return ['success' => true, 'id' => null, 'permanent' => true];
    }
    if (!trash_ensure_dir()) return ['success' => false, 'error' => 'Trash folder is not writable'];
    $id = bin2hex(random_bytes(8));
    $size = trash_dir_size($src);
    if (!@rename($src, WS_TRASH_DIR . $id)) return ['success' => false, 'error' => 'Failed to move folder to trash'];
    $item = ['id' => $id, 'type' => 'folder', 'name' => $label ?? basename($folder), 'folder' => $folder,
        'size' => $size, 'deleted_at' => time(), 'deleted_by' => $deletedBy, 'tokens' => [], 'meta' => null, 'enc' => null];
    ws_json_update(WS_TRASH_INDEX, function (&$all) use ($item) { $all[$item['id']] = $item; });
    return ['success' => true, 'id' => $id];
}

/**
 * Admin sees everything. A user sees files from their own folder tree, and
 * files they deleted themselves from the Public folder (not other people's).
 */
function trash_can_see($user, $item) {
    if (isAdmin($user)) return true;
    if (($item['type'] ?? '') !== 'file' || empty($item['folder'])) return false;
    $base = parseFolderPath($item['folder'])['base'];
    if ($base === $user) return true;
    return $base === PUBLIC_FOLDER && ($item['deleted_by'] ?? '') === $user;
}

function trash_list($user) {
    $items = array_values(array_filter(ws_json_read(WS_TRASH_INDEX), fn($i) => trash_can_see($user, $i)));
    usort($items, fn($a, $b) => $b['deleted_at'] <=> $a['deleted_at']);
    $days = trash_days();
    foreach ($items as &$i) {
        $i['expires_at'] = $i['deleted_at'] + $days * 86400;
        unset($i['tokens'], $i['meta'], $i['enc']);
    }
    return $items;
}

function trash_unique_name($dir, $name) {
    if (!file_exists($dir . $name)) return $name;
    $info = pathinfo($name);
    $ext = isset($info['extension']) && $info['extension'] !== '' ? '.' . $info['extension'] : '';
    $base = $info['filename'];
    for ($i = 1; $i < 1000; $i++) {
        $candidate = "$base (restored" . ($i > 1 ? " $i" : '') . ")$ext";
        if (!file_exists($dir . $candidate)) return $candidate;
    }
    return $base . '_' . bin2hex(random_bytes(3)) . $ext;
}

function trash_restore($id, $user) {
    $item = ws_json_read(WS_TRASH_INDEX)[$id] ?? null;
    if (!$item || !trash_can_see($user, $item)) return ['success' => false, 'error' => 'Item not found'];
    $stored = WS_TRASH_DIR . $id;
    if (!file_exists($stored)) {
        ws_json_update(WS_TRASH_INDEX, function (&$all) use ($id) { unset($all[$id]); });
        return ['success' => false, 'error' => 'The trashed data is missing'];
    }
    if ($item['type'] === 'folder') {
        // A deleted user's folder: back to its place, or next to it if taken
        $target = rtrim(FILES_BASE_DIR . $item['folder'], '/');
        if (file_exists($target)) $target .= '-restored-' . date('Ymd-His');
        if (!@rename($stored, $target)) return ['success' => false, 'error' => 'Failed to restore folder'];
        ws_json_update(WS_TRASH_INDEX, function (&$all) use ($id) { unset($all[$id]); });
        return ['success' => true, 'name' => basename($target), 'folder' => dirname(substr($target, strlen(FILES_BASE_DIR)))];
    }
    $folder = $item['folder'];
    $dir = FILES_BASE_DIR . ($folder ? $folder . '/' : '');
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) return ['success' => false, 'error' => 'The original folder no longer exists'];
    $name = trash_unique_name($dir, $item['name']);
    if (!@rename($stored, $dir . $name)) return ['success' => false, 'error' => 'Failed to restore file'];
    trash_attach_metadata($folder, $name, $item);
    ws_json_update(WS_TRASH_INDEX, function (&$all) use ($id) { unset($all[$id]); });
    return ['success' => true, 'name' => $name, 'folder' => $folder, 'renamed' => $name !== $item['name']];
}

function trash_delete($id, $user) {
    $item = ws_json_read(WS_TRASH_INDEX)[$id] ?? null;
    if (!$item || !trash_can_see($user, $item)) return ['success' => false, 'error' => 'Item not found'];
    trash_rmrf(WS_TRASH_DIR . $id);
    ws_json_update(WS_TRASH_INDEX, function (&$all) use ($id) { unset($all[$id]); });
    return ['success' => true, 'item' => $item];
}

function trash_empty($user) {
    $n = 0;
    foreach (trash_list($user) as $i) {
        if (trash_delete($i['id'], $user)['success']) $n++;
    }
    return $n;
}

/** Remove expired items; cheap when called often (runs at most once an hour) */
function trash_purge($force = false) {
    $stamp = WS_TRASH_DIR . '.last-purge';
    if (!$force && is_file($stamp) && time() - filemtime($stamp) < 3600) return 0;
    if (!is_dir(WS_TRASH_DIR)) return 0;
    @touch($stamp);
    $days = trash_days();
    $limit = time() - max(1, $days) * 86400;
    $removed = [];
    ws_json_update(WS_TRASH_INDEX, function (&$all) use ($limit, &$removed) {
        foreach ($all as $id => $i) {
            if (($i['deleted_at'] ?? 0) < $limit) { $removed[] = $id; unset($all[$id]); }
        }
        return $removed ? true : false;
    });
    foreach ($removed as $id) trash_rmrf(WS_TRASH_DIR . $id);
    // Orphans (data without an index entry, e.g. after a crash) older than the limit
    foreach (glob(WS_TRASH_DIR . '[0-9a-f]*') as $p) {
        $id = basename($p);
        if (preg_match('/^[0-9a-f]{16}$/', $id) && filemtime($p) < $limit && !isset(ws_json_read(WS_TRASH_INDEX)[$id])) {
            trash_rmrf($p);
            $removed[] = $id;
        }
    }
    return count($removed);
}

function trash_stats() {
    $all = ws_json_read(WS_TRASH_INDEX);
    return ['items' => count($all), 'bytes' => array_sum(array_column($all, 'size'))];
}
