<?php
/**
 * Locked JSON storage (I4). Docs: docs/security-plan-2.md
 *
 * ws_json_read($file)            shared lock, returns the decoded array ([] when missing/empty)
 * ws_json_update($file, $fn)     exclusive lock for the whole read-modify-write:
 *                                $fn(array &$data) changes $data; return false to skip writing.
 *                                Returns whatever $fn returns.
 *
 * Writes are done in place (truncate + write under the lock), so file owner,
 * mode and the src/ -> ../ symlinks are preserved. Readers use a shared lock,
 * so they never see a half-written file.
 */

if (!function_exists('ws_json_read')) {

function ws_json_read($file, $default = []) {
    $fh = @fopen($file, 'rb');
    if (!$fh) return $default;
    flock($fh, LOCK_SH);
    $raw = stream_get_contents($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    if ($raw === false || $raw === '') return $default;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function ws_json_update($file, callable $fn, $flags = JSON_PRETTY_PRINT) {
    // Same lock file as ws_json_mutex(), so load...save code paths and these
    // updates exclude each other. Skipped when this request already holds it.
    $real = realpath($file) ?: $file;
    $mutex = null;
    if (empty($GLOBALS['__ws_json_mutex'][$real])) {
        $mutex = @fopen($real . '.lock', 'c');
        if ($mutex) flock($mutex, LOCK_EX);
    }
    try {
        return ws_json_update_locked($file, $fn, $flags);
    } finally {
        if ($mutex) { flock($mutex, LOCK_UN); fclose($mutex); }
    }
}

function ws_json_update_locked($file, callable $fn, $flags) {
    $fh = @fopen($file, 'c+');
    if (!$fh) {
        // Cannot open for writing: run the change on a copy so callers still get a result
        $data = ws_json_read($file);
        return $fn($data);
    }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $data = ($raw !== false && $raw !== '') ? json_decode($raw, true) : [];
    if (!is_array($data)) {
        // Corrupt file: keep a copy instead of silently replacing it with an empty list
        if ($raw !== '' && $raw !== false) @file_put_contents($file . '.corrupt-' . date('Ymd-His'), $raw);
        $data = [];
    }
    $result = $fn($data);
    if ($result !== false) {
        $json = json_encode($data, $flags);
        if ($json !== false) {
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, $json);
            fflush($fh);
        }
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

}

if (!function_exists('ws_json_mutex')) {
/**
 * Exclusive lock for a read-modify-write that spans several statements
 * (load ... change ... save). Held until ws_json_mutex_release() or the end of
 * the request. Uses a separate "<file>.lock" next to the real file, so the
 * data file itself can still be written with LOCK_EX by the existing save code.
 */
function ws_json_mutex($file) {
    $real = realpath($file) ?: $file;
    if (!empty($GLOBALS['__ws_json_mutex'][$real])) return $GLOBALS['__ws_json_mutex'][$real];
    $fh = @fopen($real . '.lock', 'c');
    if (!$fh) return null;   // no lock possible (read-only dir): behave as before
    flock($fh, LOCK_EX);
    $GLOBALS['__ws_json_mutex'][$real] = $fh;   // keep the handle (and lock) alive
    return $fh;
}

function ws_json_mutex_release($file) {
    $real = realpath($file) ?: $file;
    if (!empty($GLOBALS['__ws_json_mutex'][$real])) {
        flock($GLOBALS['__ws_json_mutex'][$real], LOCK_UN);
        fclose($GLOBALS['__ws_json_mutex'][$real]);
        unset($GLOBALS['__ws_json_mutex'][$real]);
    }
}
}
