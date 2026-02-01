<?php
// Serve the installer script
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache');
readfile(__DIR__ . '/../installer/get-webshare.sh');
