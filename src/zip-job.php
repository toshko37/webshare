<?php
/**
 * Background ZIP of a shared folder (F7). Docs: docs/link-previews.md, D-030
 *
 * The page starts a job and gets an id at once; the archive is built after the
 * response is sent (fastcgi_finish_request), so big folders no longer hit the
 * request timeout. The page polls the status and then downloads the file.
 * Jobs live in <install>/tmp/zip/ (outside the DocumentRoot) for one hour.
 * Large and already-compressed files are stored, not deflated (much faster).
 */
require_once __DIR__ . '/json-store.php';

if (!defined('ZJ_DIR')) define('ZJ_DIR', dirname(__DIR__) . '/tmp/zip/');
define('ZJ_TTL', 3600);

function zj_dir() {
    if (!is_dir(ZJ_DIR)) @mkdir(ZJ_DIR, 0700, true);
    return ZJ_DIR;
}

function zj_status_file($id) { return zj_dir() . $id . '.json'; }
function zj_zip_file($id)    { return zj_dir() . $id . '.zip'; }

function zj_cleanup() {
    foreach (glob(zj_dir() . '*') as $f) {
        if (filemtime($f) < time() - ZJ_TTL) @unlink($f);
    }
}

function zj_valid_id($id) { return is_string($id) && preg_match('/^[a-f0-9]{32}$/', $id); }

/** Start (or reuse) a job for $owner; returns the job id */
function zj_start($sourceDir, $name, $owner) {
    zj_cleanup();
    foreach (glob(zj_dir() . '*.json') as $sf) {
        $s = ws_json_read($sf);
        if (($s['owner'] ?? '') === $owner && in_array($s['status'] ?? '', ['running', 'done'], true)
            && ($s['source_mtime'] ?? 0) === zj_tree_mtime($sourceDir)) {
            return basename($sf, '.json');   // same folder, unchanged: reuse
        }
    }
    $id = bin2hex(random_bytes(16));
    ws_json_update(zj_status_file($id), function (&$s) use ($name, $owner, $sourceDir) {
        $s = ['status' => 'queued', 'name' => $name, 'owner' => $owner, 'created' => time(),
            'progress' => 0, 'source_mtime' => zj_tree_mtime($sourceDir)];
    });
    return $id;
}

/** Latest modification time in a folder tree (to know if a finished ZIP is still current) */
function zj_tree_mtime($dir) {
    $m = filemtime($dir) ?: 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $f) {
        $m = max($m, $f->getMTime());
    }
    return $m;
}

function zj_set($id, array $fields) {
    ws_json_update(zj_status_file($id), function (&$s) use ($fields) { $s = $fields + $s; });
}

/** Build the archive (call after the response was sent) */
function zj_build($id, $sourceDir) {
    $s = ws_json_read(zj_status_file($id));
    if (($s['status'] ?? '') !== 'queued') return;
    zj_set($id, ['status' => 'running']);
    $base = realpath($sourceDir);   // real path: src/files is a symlink (relative names must use the same base)
    $part = zj_zip_file($id) . '.part';
    $zip = new ZipArchive();
    if ($base === false || $zip->open($part, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        zj_set($id, ['status' => 'failed', 'error' => 'Cannot create the archive']);
        return;
    }
    $stored = '/\.(zip|rar|7z|gz|bz2|xz|zst|jpg|jpeg|png|gif|webp|heic|mp3|mp4|m4a|mkv|mov|avi|webm|pdf|docx|xlsx|pptx|odt|enc|iso)$/i';
    $count = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS)) as $f) {
        if (!$f->isFile()) continue;
        $rel = substr($f->getRealPath(), strlen($base) + 1);
        $zip->addFile($f->getRealPath(), $rel);
        if ($f->getSize() > 20 * 1048576 || preg_match($stored, $rel)) {
            $zip->setCompressionName($rel, ZipArchive::CM_STORE);
        }
        $count++;
    }
    zj_set($id, ['files' => $count]);
    $last = 0;
    $zip->registerProgressCallback(0.02, function ($r) use ($id, &$last) {
        if ($r - $last >= 0.05) { $last = $r; zj_set($id, ['progress' => (int)round($r * 100)]); }
    });
    if (!$zip->close() || !rename($part, zj_zip_file($id))) {
        @unlink($part);
        zj_set($id, ['status' => 'failed', 'error' => 'Archive could not be written']);
        return;
    }
    zj_set($id, ['status' => 'done', 'progress' => 100, 'size' => filesize(zj_zip_file($id)), 'finished' => time()]);
}

function zj_status($id, $owner) {
    if (!zj_valid_id($id)) return null;
    $s = ws_json_read(zj_status_file($id));
    if (!$s || ($s['owner'] ?? '') !== $owner) return null;
    unset($s['owner'], $s['source_mtime']);
    return $s;
}

/** Stream a finished archive; false when not available */
function zj_send($id, $owner) {
    $s = zj_status($id, $owner);
    if (!$s || $s['status'] !== 'done' || !is_file(zj_zip_file($id))) return false;
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/zip');
    header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($s['name'] . '.zip'));
    header('Content-Length: ' . filesize(zj_zip_file($id)));
    readfile(zj_zip_file($id));
    return true;
}
