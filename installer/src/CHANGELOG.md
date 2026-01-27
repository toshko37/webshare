# WebShare Changelog

All notable changes to WebShare will be documented in this file.

## [3.1.6] - 2026-01-27

### Added
- Update source badge in Update modal (GitHub/Dev Server indicator)

## [3.1.5] - 2026-01-27

### Added
- **Dual update source** - Check GitHub (stable) or dev server (beta)
  - Config via `.update-config.json` with `stable` flag
  - Default: stable (GitHub releases)
- **version.json endpoint** - Public version info for update checks

### Fixed
- Version detection now reads from index.php (single source of truth)
- version.json public access in .htaccess

## [3.1.4] - 2026-01-27

### Added
- **Live Update** - One-click update from browser (no SSH needed)
  - Downloads files to temp folder, verifies, then installs
  - Automatic backup before update
  - Progress display with step-by-step status
  - Page auto-refresh after successful update
- **Force Update button** - Update even when versions match

### Fixed
- Update script compatibility (portable sed instead of grep -oP)
- Backup cleanup crash in update script
- isAdmin() function error in update endpoints

## [3.1.3] - 2026-01-27

### Added
- **Auto-update system** - Check for updates from GitHub releases
  - Version number turns red when update available
  - Click version to open Update modal
  - One-click update with automatic backup
  - Auto-check once per day (configurable)
- **Redesigned About modal** - Features grid, dynamic changelog from CHANGELOG.md, GitHub link
- **setup.sh script** - Initialize after git clone
  - Creates directories and config files
  - Downloads GeoIP database and Quill.js
  - Fixes hardcoded paths in .htaccess

### Changed
- Folder navigation now scrolls to files section
- Installer upgraded to v3.0
- Removed hardcoded domain URLs (now dynamic)

### Fixed
- Hardcoded AuthUserFile path in .htaccess (now set by setup.sh)

## [3.1.2] - 2026-01-25

### Added
- **Clickable version number** - Click the version in the header to view recent changelog
- Modal displays last 5 versions with highlights
- Link to full CHANGELOG.md

## [3.1.1] - 2026-01-25

### Changed
- **API Upload moved to Help tab** - Now accessible to all users, not just admin
- Added `api-upload.php` and `api-scripts.php` to public .htaccess exceptions

### Fixed
- Fixed API key file permissions (must be owned by www-data)

## [3.1.0] - 2026-01-25

### Added
- **API Upload with Windows Integration**
  - New `/api-upload.php` endpoint for external file uploads
  - API key authentication per user
  - Generate/regenerate/revoke API keys from Help tab
  - Downloadable pre-configured scripts:
    - `.bat` script for Windows CMD (requires curl)
    - `.ps1` PowerShell script
    - `.reg` file for right-click context menu
  - Command line usage instructions
  - Full audit logging for API uploads

### How to use
1. Go to Help → API Upload section
2. Click "Generate API Key"
3. Download the .bat script and .reg file
4. Save .bat to `C:\Scripts\`
5. Run the .reg file to add context menu
6. Right-click any file → "Upload to WebShare"

## [3.0.9] - 2026-01-24

### Added
- **New ID button for share links** - Regenerate share token to invalidate old links
  - Clicking "New ID" generates a new token and updates the displayed URL
  - Old share links immediately stop working
  - Audit log records token changes

## [3.0.8] - 2026-01-24

### Added
- **File metadata sync** - Automatic synchronization of file metadata with actual files
  - Detects files added manually (via FTP, SSH, etc.) and creates metadata
  - Removes metadata for files that no longer exist
  - Runs automatically on page load

### Changed
- **Update script improvements**
  - Backups now exclude `files/` and `texts/` directories (only software is backed up)
  - Automatically keeps only last 2 backups, older ones are deleted
  - Added install-local.sh and documentation files to update package

## [3.0.7] - 2026-01-20

### Fixed
- Fixed download issue for files in subfolders (removed basename() that was stripping folder paths)
- Fixed web download creating empty files (cURL handle now properly reset for download)
- Removed hardcoded paths - now uses `__DIR__` for portability
- Fixed SSRF protection - removed unnecessary whitelist

### Changed
- Download handler now uses `canAccessFolderPath()` for proper subfolder support
- GeoIP database path lookup simplified to use `__DIR__` and system path only

## [3.0.6] - 2026-01-20

### Added
- **Web Download feature** - Download files from URL directly to server
  - URL validation and SSRF protection
  - File size and name detection from Content-Disposition header
  - Duplicate file detection with suggested alternative names
  - Overwrite option for existing files
  - Audit logging for downloads

### Changed
- UI improvements for web download with editable filename field

## [3.0.5] - 2026-01-19

### Added
- **Email sharing feature** - Send share links via email
  - Custom SMTP mailer class (no external dependencies)
  - Beautiful HTML email templates
  - MX record validation before sending
  - Rate limiting (10 emails/minute/IP)
- Mail settings in Settings tab
  - Enable/disable toggle
  - SMTP configuration (host, port, user, password, encryption)
  - Test email functionality
- Audit logging for email operations

### Fixed
- Share button now works for files in subfolders
- Fixed public.php to use full folder path

### Security
- MX record validation prevents sending to invalid domains

## [3.0.4] - 2026-01-19

### Added
- fail2ban jail for WebShare with maxretry=6
- Custom fail2ban filter for authentication failures

### Changed
- Installer now serves PHP files as plain text (not executed)
- Added .htaccess to installer folder for public access

## [3.0.3] - 2026-01-18

### Added
- Update system with remote update script
- `update.sh` bootstrap script for each installation
- `/get-update` and `/get-update-script` endpoints

### Fixed
- Quill.js assets now use relative paths in t.php
- SSL auto-renewal cron job

## [3.0.2] - 2026-01-18

### Added
- Text sharing with Quill.js rich text editor
- Syntax highlighting for code blocks
- Text expiration (24 hours default)
- Public text viewing via `/t/TOKEN`

## [3.0.1] - 2026-01-17

### Added
- File encryption with AES-256-GCM
- Password-protected file downloads
- Encryption status indicator in file list

## [3.0.0] - 2026-01-16

### Added
- Complete rewrite of WebShare
- Multi-user support with .htpasswd authentication
- Folder system with user folders and subfolders
- File sharing with token-based public links
- GeoIP-based access control
- Audit logging system
- Drag & drop file upload
- File management (rename, move, delete)
- Admin user management
- Settings panel with configuration options

### Security
- CSRF protection
- Directory traversal prevention
- Input sanitization
- Rate limiting

---

## Pre-3.0 History

### [2.0.0] - 2025-12 (approximately)

The original WebShare before the v3 rewrite. Single-file architecture without folder support.

#### Features
- **File Upload & Download** - Drag & drop upload, direct download links
- **Text Sharing** - Quill.js rich text editor with HTML formatting
- **Share Links** - Token-based public links for files
- **Multi-user Support** - Apache Basic Auth with web UI management
- **GeoIP Blocking** - Country-based access restriction (public pages only)
- **XSS Protection** - HTML sanitization for text content
- **Upload Progress** - Real-time progress bar with speed and ETA

#### Limitations (addressed in v3.0)
- No folder/subfolder support
- No file encryption
- No audit logging
- No CSRF protection
- Single flat file storage

### [1.x] - Pre-2025

Early development versions. Basic file upload/download functionality. No version tracking at the time.

---

## Version History Summary

| Version |    Date    | Highlights |
|---------|------------|------------|
|  3.1.3  | 2026-01-27 | Auto-update system, About redesign, setup.sh |
|  3.1.2  | 2026-01-25 | Clickable version shows changelog modal |
|  3.1.1  | 2026-01-25 | API moved to Help tab, permissions fix |
|  3.1.0  | 2026-01-25 | API Upload, Windows right-click integration |
|  3.0.9  | 2026-01-24 | New ID button for share links |
|  3.0.8  | 2026-01-24 | File metadata sync, backup improvements |
|  3.0.7  | 2026-01-20 | Subfolder download fix, web download fix |
|  3.0.6  | 2026-01-20 | Web Download feature |
|  3.0.5  | 2026-01-19 | Email sharing feature |
|  3.0.4  | 2026-01-19 | fail2ban integration |
|  3.0.3  | 2026-01-18 | Update system |
|  3.0.2  | 2026-01-18 | Text sharing |
|  3.0.1  | 2026-01-17 | File encryption |
|  3.0.0  | 2026-01-16 | Complete rewrite - folders, encryption, audit logs |
|  2.0.0  | 2025-12    | Original version - flat file storage, basic sharing |
|  1.x.x  | Pre-2025   | Early development, no version tracking |
