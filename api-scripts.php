<?php
/**
 * WebShare API Scripts Download
 * =============================
 * Generates pre-configured scripts for Windows integration
 *
 * Options:
 * - overwrite: Replace existing files (1 = yes)
 * - encrypt: Encrypt uploaded files (1 = yes)
 * - encrypt_password: Password for encryption
 */

require_once __DIR__ . '/user-management.php';

$type = $_GET['type'] ?? '';
$apiKey = $_GET['key'] ?? '';

// Validate API key
$user = validateApiKey($apiKey);
if (!$user) {
    http_response_code(403);
    die('Invalid API key');
}

// Get server URL
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
$serverUrl = $protocol . '://' . $_SERVER['HTTP_HOST'];

switch ($type) {
    case 'bat':
        // Batch script for Windows CMD
        header('Content-Type: application/x-batch');
        header('Content-Disposition: attachment; filename="upload-webshare.bat"');

        echo '@echo off' . "\r\n";
        echo 'setlocal EnableDelayedExpansion' . "\r\n";
        echo 'chcp 65001 >nul 2>&1' . "\r\n";
        echo "\r\n";
        echo 'REM =============================================' . "\r\n";
        echo 'REM WebShare Upload Script' . "\r\n";
        echo 'REM Generated for user: ' . $user . "\r\n";
        echo 'REM =============================================' . "\r\n";
        echo 'REM Options (set to 1 to enable):' . "\r\n";
        echo 'REM   OVERWRITE - Replace existing files' . "\r\n";
        echo 'REM   ENCRYPT   - Encrypt files before upload' . "\r\n";
        echo 'REM =============================================' . "\r\n";
        echo 'REM To REMOVE right-click menu, run as Admin:' . "\r\n";
        echo 'REM   reg delete "HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload" /f' . "\r\n";
        echo 'REM =============================================' . "\r\n";
        echo "\r\n";
        echo 'set WEBSHARE_URL=' . $serverUrl . '/api-upload.php' . "\r\n";
        echo 'set API_KEY=' . $apiKey . "\r\n";
        echo "\r\n";
        echo 'REM === OPTIONS (edit these) ===' . "\r\n";
        echo 'set OVERWRITE=0' . "\r\n";
        echo 'set ENCRYPT=0' . "\r\n";
        echo 'set ENCRYPT_PASSWORD=' . "\r\n";
        echo 'REM =============================' . "\r\n";
        echo "\r\n";
        echo 'if "%~1"=="" (' . "\r\n";
        echo '    echo No file specified' . "\r\n";
        echo '    pause' . "\r\n";
        echo '    exit /b 1' . "\r\n";
        echo ')' . "\r\n";
        echo "\r\n";
        echo 'echo Uploading: %~nx1' . "\r\n";
        echo 'echo.' . "\r\n";
        echo "\r\n";
        echo 'REM Build curl command with options' . "\r\n";
        echo 'set CURL_CMD=curl -s -X POST -H "X-API-Key: %API_KEY%" -F "file=@%~1"' . "\r\n";
        echo "\r\n";
        echo 'if "%OVERWRITE%"=="1" (' . "\r\n";
        echo '    set CURL_CMD=!CURL_CMD! -F "overwrite=1"' . "\r\n";
        echo ')' . "\r\n";
        echo "\r\n";
        echo 'if "%ENCRYPT%"=="1" (' . "\r\n";
        echo '    set CURL_CMD=!CURL_CMD! -F "encrypt=1"' . "\r\n";
        echo '    if not "%ENCRYPT_PASSWORD%"=="" (' . "\r\n";
        echo '        set CURL_CMD=!CURL_CMD! -F "encrypt_password=%ENCRYPT_PASSWORD%"' . "\r\n";
        echo '    ) else (' . "\r\n";
        echo '        echo ERROR: ENCRYPT is enabled but ENCRYPT_PASSWORD is empty!' . "\r\n";
        echo '        pause' . "\r\n";
        echo '        exit /b 1' . "\r\n";
        echo '    )' . "\r\n";
        echo ')' . "\r\n";
        echo "\r\n";
        echo '!CURL_CMD! %WEBSHARE_URL%' . "\r\n";
        echo "\r\n";
        echo 'if %ERRORLEVEL%==0 (' . "\r\n";
        echo '    echo.' . "\r\n";
        echo '    echo Upload complete!' . "\r\n";
        echo ') else (' . "\r\n";
        echo '    echo.' . "\r\n";
        echo '    echo Upload failed!' . "\r\n";
        echo ')' . "\r\n";
        echo "\r\n";
        echo 'echo.' . "\r\n";
        echo 'pause' . "\r\n";
        break;

    case 'ps1':
        // PowerShell script
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="upload-webshare.ps1"');

        echo '# =============================================' . "\r\n";
        echo '# WebShare Upload Script (PowerShell)' . "\r\n";
        echo '# Generated for user: ' . $user . "\r\n";
        echo '# =============================================' . "\r\n";
        echo '# Options (set to $true to enable):' . "\r\n";
        echo '#   $Overwrite - Replace existing files' . "\r\n";
        echo '#   $Encrypt   - Encrypt files before upload' . "\r\n";
        echo '# =============================================' . "\r\n";
        echo '# To REMOVE right-click menu, run as Admin:' . "\r\n";
        echo '#   Remove-Item -Path "HKCR:\\*\\shell\\WebShareUpload" -Recurse -Force' . "\r\n";
        echo '# Or: reg delete "HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload" /f' . "\r\n";
        echo '# =============================================' . "\r\n";
        echo "\r\n";
        echo 'param([string]$FilePath)' . "\r\n";
        echo "\r\n";
        echo '$WebShareUrl = "' . $serverUrl . '/api-upload.php"' . "\r\n";
        echo '$ApiKey = "' . $apiKey . '"' . "\r\n";
        echo "\r\n";
        echo '# === OPTIONS (edit these) ===' . "\r\n";
        echo '$Overwrite = $false' . "\r\n";
        echo '$Encrypt = $false' . "\r\n";
        echo '$EncryptPassword = ""' . "\r\n";
        echo '# =============================' . "\r\n";
        echo "\r\n";
        echo 'if (-not $FilePath -or -not (Test-Path $FilePath)) {' . "\r\n";
        echo '    Write-Host "File not found: $FilePath" -ForegroundColor Red' . "\r\n";
        echo '    Read-Host "Press Enter to exit"' . "\r\n";
        echo '    exit 1' . "\r\n";
        echo '}' . "\r\n";
        echo "\r\n";
        echo '# Validate encrypt options' . "\r\n";
        echo 'if ($Encrypt -and [string]::IsNullOrEmpty($EncryptPassword)) {' . "\r\n";
        echo '    Write-Host "ERROR: Encrypt is enabled but EncryptPassword is empty!" -ForegroundColor Red' . "\r\n";
        echo '    Read-Host "Press Enter to exit"' . "\r\n";
        echo '    exit 1' . "\r\n";
        echo '}' . "\r\n";
        echo "\r\n";
        echo '$FileName = [System.IO.Path]::GetFileName($FilePath)' . "\r\n";
        echo 'Write-Host "Uploading: $FileName" -ForegroundColor Cyan' . "\r\n";
        echo 'if ($Overwrite) { Write-Host "(Overwrite mode)" -ForegroundColor Yellow }' . "\r\n";
        echo 'if ($Encrypt) { Write-Host "(Encryption enabled)" -ForegroundColor Yellow }' . "\r\n";
        echo "\r\n";
        echo 'try {' . "\r\n";
        echo '    $boundary = [System.Guid]::NewGuid().ToString()' . "\r\n";
        echo '    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)' . "\r\n";
        echo '    $fileEnc = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($fileBytes)' . "\r\n";
        echo "\r\n";
        echo '    $bodyLines = @(' . "\r\n";
        echo '        "--$boundary",' . "\r\n";
        echo '        "Content-Disposition: form-data; name=`"file`"; filename=`"$FileName`"",' . "\r\n";
        echo '        "Content-Type: application/octet-stream",' . "\r\n";
        echo '        "",' . "\r\n";
        echo '        $fileEnc,' . "\r\n";
        echo '        "--$boundary"' . "\r\n";
        echo '    )' . "\r\n";
        echo "\r\n";
        echo '    # Add overwrite option' . "\r\n";
        echo '    if ($Overwrite) {' . "\r\n";
        echo '        $bodyLines += @(' . "\r\n";
        echo '            "Content-Disposition: form-data; name=`"overwrite`"",' . "\r\n";
        echo '            "",' . "\r\n";
        echo '            "1",' . "\r\n";
        echo '            "--$boundary"' . "\r\n";
        echo '        )' . "\r\n";
        echo '    }' . "\r\n";
        echo "\r\n";
        echo '    # Add encrypt options' . "\r\n";
        echo '    if ($Encrypt) {' . "\r\n";
        echo '        $bodyLines += @(' . "\r\n";
        echo '            "Content-Disposition: form-data; name=`"encrypt`"",' . "\r\n";
        echo '            "",' . "\r\n";
        echo '            "1",' . "\r\n";
        echo '            "--$boundary",' . "\r\n";
        echo '            "Content-Disposition: form-data; name=`"encrypt_password`"",' . "\r\n";
        echo '            "",' . "\r\n";
        echo '            $EncryptPassword,' . "\r\n";
        echo '            "--$boundary"' . "\r\n";
        echo '        )' . "\r\n";
        echo '    }' . "\r\n";
        echo "\r\n";
        echo '    $bodyLines += "--"' . "\r\n";
        echo '    $body = $bodyLines -join "`r`n"' . "\r\n";
        echo "\r\n";
        echo '    $response = Invoke-RestMethod -Uri $WebShareUrl -Method Post `' . "\r\n";
        echo '        -ContentType "multipart/form-data; boundary=$boundary" `' . "\r\n";
        echo '        -Body $body `' . "\r\n";
        echo '        -Headers @{ "X-API-Key" = $ApiKey }' . "\r\n";
        echo "\r\n";
        echo '    if ($response.success) {' . "\r\n";
        echo '        Write-Host ""' . "\r\n";
        echo '        Write-Host "Upload successful!" -ForegroundColor Green' . "\r\n";
        echo '        Write-Host "Filename: $($response.filename)"' . "\r\n";
        echo '        if ($response.renamed) {' . "\r\n";
        echo '            Write-Host "(Renamed from: $($response.originalName))" -ForegroundColor Yellow' . "\r\n";
        echo '        }' . "\r\n";
        echo '        if ($response.encrypted) {' . "\r\n";
        echo '            Write-Host "(File was encrypted)" -ForegroundColor Cyan' . "\r\n";
        echo '        }' . "\r\n";
        echo '    } else {' . "\r\n";
        echo '        Write-Host ""' . "\r\n";
        echo '        Write-Host "Error: $($response.error)" -ForegroundColor Red' . "\r\n";
        echo '    }' . "\r\n";
        echo '} catch {' . "\r\n";
        echo '    Write-Host ""' . "\r\n";
        echo '    Write-Host "Upload failed: $_" -ForegroundColor Red' . "\r\n";
        echo '}' . "\r\n";
        echo "\r\n";
        echo 'Write-Host ""' . "\r\n";
        echo 'Read-Host "Press Enter to exit"' . "\r\n";
        break;

    case 'reg':
        // Registry file for context menu (BAT version)
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="add-webshare-menu.reg"');

        echo 'Windows Registry Editor Version 5.00' . "\r\n";
        echo "\r\n";
        echo '; WebShare Upload Context Menu (BAT version)' . "\r\n";
        echo '; Generated for user: ' . $user . "\r\n";
        echo '; Double-click this file to add "Upload to WebShare" to right-click menu' . "\r\n";
        echo '; NOTE: First save upload-webshare.bat to C:\\Scripts\\' . "\r\n";
        echo "\r\n";
        echo '[HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload]' . "\r\n";
        echo '@="Upload to WebShare"' . "\r\n";
        echo '"Icon"="shell32.dll,46"' . "\r\n";
        echo "\r\n";
        echo '[HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload\\command]' . "\r\n";
        // In .reg files, backslash needs to be escaped as \\
        // In PHP, \\\\ outputs \\
        echo '@="\\"C:\\\\Scripts\\\\upload-webshare.bat\\" \\"%1\\""' . "\r\n";
        break;

    case 'reg-ps1':
        // Registry file for PowerShell script
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="add-webshare-menu-ps1.reg"');

        echo 'Windows Registry Editor Version 5.00' . "\r\n";
        echo "\r\n";
        echo '; WebShare Upload Context Menu (PowerShell version)' . "\r\n";
        echo '; Generated for user: ' . $user . "\r\n";
        echo '; Double-click this file to add "Upload to WebShare" to right-click menu' . "\r\n";
        echo '; NOTE: First save upload-webshare.ps1 to C:\\Scripts\\' . "\r\n";
        echo "\r\n";
        echo '[HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload]' . "\r\n";
        echo '@="Upload to WebShare"' . "\r\n";
        echo '"Icon"="shell32.dll,46"' . "\r\n";
        echo "\r\n";
        echo '[HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload\\command]' . "\r\n";
        // In .reg files, backslash needs to be escaped as \\
        echo '@="powershell.exe -ExecutionPolicy Bypass -File \\"C:\\\\Scripts\\\\upload-webshare.ps1\\" \\"%1\\""' . "\r\n";
        break;

    case 'reg-remove':
        // Registry file to remove context menu
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="remove-webshare-menu.reg"');

        echo 'Windows Registry Editor Version 5.00' . "\r\n";
        echo "\r\n";
        echo '; Remove WebShare Upload Context Menu' . "\r\n";
        echo '; Double-click this file to remove "Upload to WebShare" from right-click menu' . "\r\n";
        echo "\r\n";
        echo '[-HKEY_CLASSES_ROOT\\*\\shell\\WebShareUpload]' . "\r\n";
        break;

    default:
        http_response_code(400);
        die('Invalid script type. Use: bat, ps1, reg, reg-ps1, or reg-remove');
}
