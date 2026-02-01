<?php
// Serve the local update bootstrap script
// This is the small script that goes in each installation

header('Content-Type: text/plain');
$scriptPath = __DIR__ . '/get-update';
if (file_exists($scriptPath)) {
    readfile($scriptPath);
} else {
    http_response_code(404);
    echo "Update script not found";
}
