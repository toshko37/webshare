<?php
// Serve the update script for remote download
// Usage: curl -fsSL https://domain.com/get-update | bash

header('Content-Type: text/plain');
$scriptPath = __DIR__ . '/installer/update-remote.sh';
if (file_exists($scriptPath)) {
    readfile($scriptPath);
} else {
    http_response_code(404);
    echo "Update script not found";
}
