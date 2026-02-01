<?php
/**
 * WebShare Audit Log System
 * Records all user actions for security and compliance
 * With log rotation support
 */

// Include geo functions for country lookup
require_once __DIR__ . '/geo-check.php';

define('AUDIT_LOG_FILE', __DIR__ . '/.audit.json');
define('AUDIT_MAX_ENTRIES', 500);      // Entries per file
define('AUDIT_MAX_ARCHIVES', 10);      // Number of archive files to keep (total: 500 * 11 = 5500 entries)

/**
 * Get archive file path by index
 * @param int $index Archive index (1-based)
 * @return string File path
 */
function getAuditArchivePath($index) {
    return __DIR__ . '/.audit.' . $index . '.json';
}

/**
 * Rotate audit log archives
 * Called when current log exceeds max entries
 */
function rotateAuditLog($overflow) {
    if (empty($overflow)) return;

    // Delete oldest archive if at max
    $oldestArchive = getAuditArchivePath(AUDIT_MAX_ARCHIVES);
    if (file_exists($oldestArchive)) {
        unlink($oldestArchive);
    }

    // Shift existing archives (9 -> 10, 8 -> 9, etc.)
    for ($i = AUDIT_MAX_ARCHIVES - 1; $i >= 1; $i--) {
        $from = getAuditArchivePath($i);
        $to = getAuditArchivePath($i + 1);
        if (file_exists($from)) {
            rename($from, $to);
        }
    }

    // Write overflow to archive.1
    $archivePath = getAuditArchivePath(1);
    file_put_contents($archivePath, json_encode($overflow, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

/**
 * Write an entry to the audit log
 * @param string $action Action type (login, upload, download, delete, settings, etc.)
 * @param string $details Additional details about the action
 * @param string|null $user Username (null = use current user)
 */
function writeAuditLog($action, $details = '', $user = null) {
    $logFile = AUDIT_LOG_FILE;

    // Load existing log
    $log = [];
    if (file_exists($logFile)) {
        $content = file_get_contents($logFile);
        $log = json_decode($content, true) ?? [];
    }

    // Get user info
    if ($user === null) {
        $user = $_SERVER['PHP_AUTH_USER'] ?? 'anonymous';
    }

    // Get IP and country
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $country = 'N/A';
    if (function_exists('getCountryFromIP')) {
        $country = getCountryFromIP($ip) ?? 'N/A';
    }

    // Create log entry
    $entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'unix_time' => time(),
        'user' => $user,
        'action' => $action,
        'details' => $details,
        'ip' => $ip,
        'country' => $country,
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200)
    ];

    // Add to beginning of log (newest first)
    array_unshift($log, $entry);

    // Check if rotation needed
    if (count($log) > AUDIT_MAX_ENTRIES) {
        // Split: keep first 500, rotate the rest
        $overflow = array_slice($log, AUDIT_MAX_ENTRIES);
        $log = array_slice($log, 0, AUDIT_MAX_ENTRIES);

        rotateAuditLog($overflow);
    }

    // Save log with file locking
    file_put_contents($logFile, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

/**
 * Read all available audit logs (current + archives)
 * @return array Combined log entries
 */
function readAllAuditLogs() {
    $allLogs = [];

    // Read current log
    if (file_exists(AUDIT_LOG_FILE)) {
        $log = json_decode(file_get_contents(AUDIT_LOG_FILE), true) ?? [];
        $allLogs = array_merge($allLogs, $log);
    }

    // Read archives (1 to max)
    for ($i = 1; $i <= AUDIT_MAX_ARCHIVES; $i++) {
        $archivePath = getAuditArchivePath($i);
        if (file_exists($archivePath)) {
            $archive = json_decode(file_get_contents($archivePath), true) ?? [];
            $allLogs = array_merge($allLogs, $archive);
        } else {
            break; // No more archives
        }
    }

    return $allLogs;
}

/**
 * Get total entry count across all logs
 * @return int Total entries
 */
function getAuditTotalCount() {
    $total = 0;

    if (file_exists(AUDIT_LOG_FILE)) {
        $log = json_decode(file_get_contents(AUDIT_LOG_FILE), true) ?? [];
        $total += count($log);
    }

    for ($i = 1; $i <= AUDIT_MAX_ARCHIVES; $i++) {
        $archivePath = getAuditArchivePath($i);
        if (file_exists($archivePath)) {
            $archive = json_decode(file_get_contents($archivePath), true) ?? [];
            $total += count($archive);
        } else {
            break;
        }
    }

    return $total;
}

/**
 * Read audit log entries with advanced filtering
 * Supports reading across archived logs
 * @param int $limit Number of entries to return
 * @param int $offset Starting offset
 * @param array $filters Associative array of filters
 * @return array ['entries' => [...], 'total' => count, 'filtered' => count]
 */
function readAuditLog($limit = 100, $offset = 0, $filters = []) {
    // Check if we need archives (when offset + limit > current log size or filters applied)
    $needsArchives = !empty($filters) || $offset >= AUDIT_MAX_ENTRIES || ($offset + $limit) > AUDIT_MAX_ENTRIES;

    if ($needsArchives) {
        // Read all logs for filtering/deep pagination
        $log = readAllAuditLogs();
    } else {
        // Just read current log (faster for recent entries)
        $log = [];
        if (file_exists(AUDIT_LOG_FILE)) {
            $log = json_decode(file_get_contents(AUDIT_LOG_FILE), true) ?? [];
        }
    }

    $totalEntries = $needsArchives ? count($log) : getAuditTotalCount();

    // Apply filters
    $filterUser = $filters['user'] ?? null;
    $filterAction = $filters['action'] ?? null;
    $filterIP = $filters['ip'] ?? null;
    $filterCountry = $filters['country'] ?? null;
    $filterSearch = $filters['search'] ?? null;
    $filterDateFrom = $filters['date_from'] ?? null;
    $filterDateTo = $filters['date_to'] ?? null;

    $hasFilters = $filterUser || $filterAction || $filterIP || $filterCountry || $filterSearch || $filterDateFrom || $filterDateTo;

    if ($hasFilters) {
        // Need to read all logs if we have filters and haven't already
        if (!$needsArchives) {
            $log = readAllAuditLogs();
            $totalEntries = count($log);
        }

        if ($filterUser !== null && $filterUser !== '') {
            $log = array_filter($log, fn($e) => $e['user'] === $filterUser);
        }

        if ($filterAction !== null && $filterAction !== '') {
            $log = array_filter($log, fn($e) => $e['action'] === $filterAction);
        }

        if ($filterIP !== null && $filterIP !== '') {
            $log = array_filter($log, fn($e) => strpos($e['ip'], $filterIP) !== false);
        }

        if ($filterCountry !== null && $filterCountry !== '') {
            if ($filterCountry === '_local_') {
                $log = array_filter($log, fn($e) => ($e['country'] ?? '') === '');
            } else {
                $log = array_filter($log, fn($e) => ($e['country'] ?? '') === $filterCountry);
            }
        }

        if ($filterSearch !== null && $filterSearch !== '') {
            $searchLower = mb_strtolower($filterSearch);
            $log = array_filter($log, fn($e) =>
                strpos(mb_strtolower($e['details'] ?? ''), $searchLower) !== false ||
                strpos(mb_strtolower($e['action'] ?? ''), $searchLower) !== false ||
                strpos(mb_strtolower($e['user'] ?? ''), $searchLower) !== false
            );
        }

        if ($filterDateFrom !== null && $filterDateFrom !== '') {
            $fromTime = strtotime($filterDateFrom . ' 00:00:00');
            if ($fromTime) {
                $log = array_filter($log, fn($e) => ($e['unix_time'] ?? 0) >= $fromTime);
            }
        }

        if ($filterDateTo !== null && $filterDateTo !== '') {
            $toTime = strtotime($filterDateTo . ' 23:59:59');
            if ($toTime) {
                $log = array_filter($log, fn($e) => ($e['unix_time'] ?? 0) <= $toTime);
            }
        }

        // Re-index after filtering
        $log = array_values($log);
    }

    $filteredCount = count($log);

    // Apply pagination
    $entries = array_slice($log, $offset, $limit);

    return [
        'entries' => $entries,
        'total' => $totalEntries,
        'filtered' => $filteredCount
    ];
}

/**
 * Simple read for backward compatibility
 */
function readAuditLogSimple($limit = 100, $offset = 0, $filterUser = null, $filterAction = null) {
    $filters = [];
    if ($filterUser) $filters['user'] = $filterUser;
    if ($filterAction) $filters['action'] = $filterAction;

    $result = readAuditLog($limit, $offset, $filters);
    return $result['entries'];
}

/**
 * Get unique values for filter dropdowns
 * Reads from all logs for complete options
 */
function getAuditFilterOptions() {
    $log = readAllAuditLogs();

    $users = [];
    $actions = [];
    $ips = [];

    foreach ($log as $entry) {
        $users[$entry['user']] = true;
        $actions[$entry['action']] = true;
        $ips[$entry['ip']] = true;
    }

    return [
        'users' => array_keys($users),
        'actions' => array_keys($actions),
        'ips' => array_keys($ips)
    ];
}

/**
 * Get audit log statistics
 * @return array Statistics
 */
function getAuditStats() {
    $log = readAllAuditLogs();

    $stats = [
        'total_entries' => count($log),
        'actions' => [],
        'users' => [],
        'countries' => [],
        'last_24h' => 0,
        'archive_count' => 0
    ];

    // Count archives
    for ($i = 1; $i <= AUDIT_MAX_ARCHIVES; $i++) {
        if (file_exists(getAuditArchivePath($i))) {
            $stats['archive_count']++;
        } else {
            break;
        }
    }

    $dayAgo = time() - 86400;

    foreach ($log as $entry) {
        // Count actions
        $action = $entry['action'];
        $stats['actions'][$action] = ($stats['actions'][$action] ?? 0) + 1;

        // Count users
        $user = $entry['user'];
        $stats['users'][$user] = ($stats['users'][$user] ?? 0) + 1;

        // Count countries
        $country = $entry['country'];
        $stats['countries'][$country] = ($stats['countries'][$country] ?? 0) + 1;

        // Count last 24h
        if (($entry['unix_time'] ?? 0) > $dayAgo) {
            $stats['last_24h']++;
        }
    }

    // Sort by count
    arsort($stats['actions']);
    arsort($stats['users']);
    arsort($stats['countries']);

    return $stats;
}

/**
 * Clear audit log (admin only)
 * Also clears all archives
 */
function clearAuditLog() {
    // Delete archives
    for ($i = 1; $i <= AUDIT_MAX_ARCHIVES; $i++) {
        $archivePath = getAuditArchivePath($i);
        if (file_exists($archivePath)) {
            unlink($archivePath);
        }
    }

    // Clear main log but keep a record
    $logFile = AUDIT_LOG_FILE;
    file_put_contents($logFile, json_encode([
        [
            'timestamp' => date('Y-m-d H:i:s'),
            'unix_time' => time(),
            'user' => $_SERVER['PHP_AUTH_USER'] ?? 'admin',
            'action' => 'audit_cleared',
            'details' => 'Audit log was cleared',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'country' => 'N/A',
            'user_agent' => ''
        ]
    ], JSON_PRETTY_PRINT));
}

/**
 * Export audit log as CSV
 * Exports all entries including archives
 * @return string CSV content
 */
function exportAuditLogCSV() {
    $log = readAllAuditLogs();

    $csv = "Timestamp,User,Action,Details,IP,Country\n";
    foreach ($log as $entry) {
        $csv .= sprintf(
            '"%s","%s","%s","%s","%s","%s"' . "\n",
            $entry['timestamp'],
            str_replace('"', '""', $entry['user']),
            $entry['action'],
            str_replace('"', '""', $entry['details']),
            $entry['ip'],
            $entry['country']
        );
    }

    return $csv;
}

/**
 * Get audit log info (for display)
 * @return array Info about log files
 */
function getAuditLogInfo() {
    $info = [
        'current_file' => AUDIT_LOG_FILE,
        'current_entries' => 0,
        'archives' => [],
        'total_entries' => 0,
        'max_per_file' => AUDIT_MAX_ENTRIES,
        'max_archives' => AUDIT_MAX_ARCHIVES
    ];

    if (file_exists(AUDIT_LOG_FILE)) {
        $log = json_decode(file_get_contents(AUDIT_LOG_FILE), true) ?? [];
        $info['current_entries'] = count($log);
        $info['total_entries'] = count($log);
    }

    for ($i = 1; $i <= AUDIT_MAX_ARCHIVES; $i++) {
        $archivePath = getAuditArchivePath($i);
        if (file_exists($archivePath)) {
            $archive = json_decode(file_get_contents($archivePath), true) ?? [];
            $count = count($archive);
            $info['archives'][] = [
                'index' => $i,
                'file' => basename($archivePath),
                'entries' => $count
            ];
            $info['total_entries'] += $count;
        } else {
            break;
        }
    }

    return $info;
}
