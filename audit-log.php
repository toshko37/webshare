<?php
/**
 * WebShare Audit Log System
 * Records all user actions for security and compliance
 */

// Include geo functions for country lookup
require_once __DIR__ . '/geo-check.php';

define('AUDIT_LOG_FILE', __DIR__ . '/.audit.json');
define('AUDIT_MAX_ENTRIES', 1000); // Keep last 1000 entries

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

    // Trim to max entries
    if (count($log) > AUDIT_MAX_ENTRIES) {
        $log = array_slice($log, 0, AUDIT_MAX_ENTRIES);
    }

    // Save log with file locking
    file_put_contents($logFile, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

/**
 * Read audit log entries with advanced filtering
 * @param int $limit Number of entries to return
 * @param int $offset Starting offset
 * @param array $filters Associative array of filters
 * @return array ['entries' => [...], 'total' => count, 'filtered' => count]
 */
function readAuditLog($limit = 100, $offset = 0, $filters = []) {
    $logFile = AUDIT_LOG_FILE;

    if (!file_exists($logFile)) {
        return ['entries' => [], 'total' => 0, 'filtered' => 0];
    }

    $log = json_decode(file_get_contents($logFile), true) ?? [];
    $totalEntries = count($log);

    // Apply filters
    $filterUser = $filters['user'] ?? null;
    $filterAction = $filters['action'] ?? null;
    $filterIP = $filters['ip'] ?? null;
    $filterCountry = $filters['country'] ?? null;
    $filterSearch = $filters['search'] ?? null;
    $filterDateFrom = $filters['date_from'] ?? null;
    $filterDateTo = $filters['date_to'] ?? null;

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
            // Filter for empty/local entries
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
 */
function getAuditFilterOptions() {
    $logFile = AUDIT_LOG_FILE;

    if (!file_exists($logFile)) {
        return ['users' => [], 'actions' => [], 'ips' => []];
    }

    $log = json_decode(file_get_contents($logFile), true) ?? [];

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
    $logFile = AUDIT_LOG_FILE;

    if (!file_exists($logFile)) {
        return [
            'total_entries' => 0,
            'actions' => [],
            'users' => [],
            'countries' => [],
            'last_24h' => 0
        ];
    }

    $log = json_decode(file_get_contents($logFile), true) ?? [];

    $stats = [
        'total_entries' => count($log),
        'actions' => [],
        'users' => [],
        'countries' => [],
        'last_24h' => 0
    ];

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
 */
function clearAuditLog() {
    $logFile = AUDIT_LOG_FILE;
    if (file_exists($logFile)) {
        // Keep a backup entry
        writeAuditLog('audit_cleared', 'Audit log was cleared');
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
}

/**
 * Export audit log as CSV
 * @return string CSV content
 */
function exportAuditLogCSV() {
    $log = readAuditLog(AUDIT_MAX_ENTRIES, 0);

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
