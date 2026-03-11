# WebShare Changelog

All notable changes to WebShare will be documented in this file.

## [3.6.16] - 2026-03-11

### Settings

- **Email Settings UI** – Fixed inconsistent input styling (number, password, email inputs now match text inputs); Port and Encryption are now a clean side-by-side pair; Password placeholder indicates when a password is saved; "Send Test" button is clearly labeled
- **Public Access toggles** – New "Public Access" section in Settings lets admins control whether /t (chat) and /u (upload) are open to anonymous users or require login; defaults to open (existing behavior unchanged)

### Bug Fix

- **Open upload respects access setting** – `/u` and `/u/[username]` now check the Open Upload toggle; if disabled, anonymous visitors are redirected to login

## [3.6.15] - 2026-03-11

### Bug Fix

- **Public pages no longer require login** – `folder-management.php` incorrectly required `security-check.php`, causing `/u` (upload) and any other public page that uses folder management to redirect to the login page

## [3.6.14] - 2026-03-10

### User Management

- **Delete user folder on deletion** – When a user is deleted, their files folder and all contents (including subfolders) are permanently deleted

## [3.6.13] - 2026-03-10

### Bug Fix

- **Country lookup in audit purge/clear** – `audit_purged` and `audit_cleared` entries now correctly resolve the country from the IP address instead of always showing "N/A"; user agent is also recorded

## [3.6.12] - 2026-03-10

### Bug Fixes

- **Admin folder visibility** – Any admin user (not just a user literally named "admin") can now see and manage all users' folders
- **Orphaned folders hidden** – Folders belonging to deleted users no longer appear in the folder list

## [3.6.11] - 2026-03-10

### Bug Fix

- **OPcache cleared after live update** – After installing new files, `opcache_reset()` is called so PHP serves the updated files immediately instead of the cached old versions; fixes the issue where version still showed the old number after a successful update

## [3.6.10] - 2026-03-10

### Update System

- **Page lock during live update** – A full-screen overlay blocks all buttons and interactions while the update is in progress, preventing accidental clicks that could interfere with the update; overlay disappears automatically on completion or error

## [3.6.9] - 2026-03-10

### Bug Fix

- **Tab navigation after reload** – Switching tabs now clears URL parameters (e.g. `?tab=settings&user_msg=...` from Settings actions); any subsequent page reload returns to the correct tab instead of re-applying the old URL

## [3.6.8] - 2026-03-09

### Bug Fix

- **Chat list refreshes after creation** – Page reloads after creating a chat to show the new entry in the list; tab persistence (from v3.6.5) ensures the user returns to the Chats tab automatically

## [3.6.7] - 2026-03-09

### Bug Fix

- **Chat creation no longer navigates away** – Removed the automatic page reload after creating a chat; the link is shown and copied to clipboard, and the user stays on the Chats tab

## [3.6.6] - 2026-03-09

### Bug Fix

- **Settings tab persistence** – Settings tab is now saved and restored like all other tabs; adding/editing users and other settings actions no longer navigate away from Settings

## [3.6.5] - 2026-03-09

### Tab Persistence

- **Stay in current tab** – After any action (chat create/delete, file operations, audit purge, settings changes), the page reloads and returns to the same tab that was active
- **Login always shows Files tab** – After successful login, always starts on the Files (first) tab regardless of which tab was open before logout
- **All tabs saved** – Audit Log and Sessions tabs are now also remembered across page reloads (previously only Chats and Help were saved)

## [3.6.4] - 2026-03-09

### Audit Log – Retention Management

- **Delete old entries** – New "Delete >30d" and "Delete >7d" buttons in the Audit Log tab (admin only)
- **Minimum 7-day retention** – The purge function enforces a minimum of 7 days; entries within the chosen window are always preserved
- **Purge logged** – Each purge action is recorded in the audit log itself (shows how many entries were deleted and the retention period)
- **Auto-reload** – After purging, the log table and page stats refresh automatically

## [3.6.3] - 2026-03-09

### Security & Bug Fixes

- **text.php auth** – Added `security-check.php` to text.php (chat creation was accessible without valid session; CSRF check also had a bypass when session was missing)
- **AJAX session expiry** – When session expires, AJAX calls (audit log, session list) now receive 401 JSON instead of HTML redirect, and the browser is redirected to login
- **Audit log error** – Fixed "Unexpected token '<'" error caused by getting login page HTML instead of JSON after session expiry

## [3.6.2] - 2026-03-09

### Bug Fixes

- **Session close – key mismatch** – Fixed `is_current` vs `current` key mismatch between PHP and JS; the Close button was incorrectly shown for the current session
- **Session close – no redirect** – Closing your own current session now redirects to login instead of silently reloading the session list

## [3.6.1] - 2026-03-09

### Bug Fixes

- **Login function conflict** - Renamed `getClientIp()` in `login.php` to avoid conflict with `geo-check.php` (caused HTTP 500 on login)
- **Session directory permissions** - Fixed `.sessions/` directory ownership (was root, now www-data)
- **Settings tab after user actions** - Used Post-Redirect-Get so adding/changing/deleting users keeps the Settings tab open and shows success message

### Update System Improvements

- **Live-update file list** - Added `security-check.php`, `login.php`, `logout.php` as first entries (ensures auth files are always updated first)
- **Live-update post-install** - Auto-creates `.sessions/` directory with correct permissions if missing
- **Installer** - Removed `.htpasswd` creation; now uses session-based auth from the start
- **Installer** - Added `.sessions/` directory setup with correct permissions
- **Installer** - First visit shows admin account creation wizard (no pre-set credentials)
- **Installer** - Added `security-check.php`, `login.php`, `logout.php` to download file list

## [3.6.0] - 2026-03-09

### Session-Based Authentication (replaces HTTP Basic Auth)

- **Login page** - New `/login.php` with username/password form, rate limiting (5 attempts, 15-min lockout), and "Remember me" (30-day cookie)
- **Logout** - Proper `/logout.php` that clears session and remember-me cookie
- **Multi-user support** - Users stored in `.users.json` with bcrypt-hashed passwords
- **Remember me** - Secure 30-day cookie with server-side token validation
- **Session tracking** - Each login creates a `.sessions/{id}.json` file with IP, device, timestamp

### Sessions Management Tab

- **Active sessions list** - View all sessions with username, IP, device/browser, last active time
- **Close session** - Terminate any specific session remotely (admin can close any, users can close own)
- **Logoff ALL** - Instantly revoke all active sessions (admin: all users; regular: own sessions)
- **Change own password** - Self-service password change without admin

### Migration & First-Run

- **Auto-migration wizard** - Detects old `.htpasswd` on first access after update, prompts for new passwords
- **First-run setup** - If no users exist, shows admin account creation form automatically

### Other Changes

- **Audit log** - Fixed to use PHP session username instead of HTTP Basic Auth
- **Update system** - Removed HTTP Basic Auth checks from `live-update.php` and `do-update.php`
- **Live update** - Added `login.php`, `logout.php`, `security-check.php` to auto-update file list
- **`.htaccess`** - Removed all Basic Auth directives; session auth handles security
- **`.gitignore`** - Added `.users.json`, `.sessions/`, `.login-attempts.json`

## [3.5.6] - 2026-02-09

### Chat Fixes
- **Smart expiration reset** - Messages no longer reset expiration to 24h if time was extended
  - If remaining time is already above 24h (e.g. extended by a week), it stays unchanged
  - Only resets to 24h minimum when remaining time drops below that
- **Selection-safe polling** - Chat no longer breaks text selection when polling for new messages
  - Detects active text selection in the chat area and skips re-render
  - Allows copying text with Ctrl+C without losing selection
- **Copy preserves line breaks** - Copy button now correctly preserves multi-line formatting
  - Text copied to clipboard maintains original line breaks when pasted in Notepad etc.

## [3.5.5] - 2026-02-03

### Chat Improvements
- **Copy button** - Added 📋 icon at bottom-right of each message
  - Click to copy message text to clipboard
  - Shows ✓ checkmark when copied
- **Auto-extend expiration** - Chat expiration resets to 24h when message is sent
  - If chat is used daily, it stays active indefinitely
- **Removed speedtest link** - No longer shown in chat window

### Installer Fixes
- **SSL vhost path fix** - Installer now updates SSL vhost paths after certbot
  - Fixes issue where certbot copied old DocumentRoot paths
- **Added security-check.php** - Missing from installer file list (caused 500 error)
- **Default to current directory** - Installer uses `pwd` as default installation path

## [3.5.4] - 2026-02-02

### Security
- **Admin-only Software Updates** - Only admin users can access update functionality
  - Version link clickable only for admins
  - Update modal hidden for non-admins
  - Backend checks in do-update.php and live-update.php
- **Configurable admin users** - Add `admin_users` array to `.config.json`
  - If not configured, first user in `.htpasswd` is admin
- **.htaccess security check** - Protected PHP files check for .htaccess existence

### Installer
- **Custom installation path** - New `--path` option for get-webshare.sh
  - Example: `--path /var/www/mywebshare`
- **Existing vhost detection** - Warns if Apache vhost points to different path
- **Backups protection** - Added `.htaccess` to backups/ directory

## [3.5.3] - 2026-02-02

### Installer Fixes
- **Preserve existing config files** - Reinstalling no longer overwrites:
  - `.htpasswd` - Keeps existing users and passwords
  - `.config.json`, `.geo.json`, etc. - Keeps all settings
- **Fixed symlink creation** - Symlinks now created only in `src/`, not in data directories
- **Updated README** - Added examples for fully automated installation

### Documentation
- Added installation parameters documentation to README:
  - `domain` - Required domain name
  - `username` - Admin username (default: admin)
  - `password` - Admin password

## [3.5.2] - 2026-02-02

### Update System Fixes
- **Fixed dev server URLs** - Removed incorrect `/src/` path from dev server URLs
  - Dev server DocumentRoot is already `src/`, so URLs don't need `/src/` prefix
  - GitHub uses `/src/` in path, dev server doesn't
- **Created htaccess.txt and user.ini.txt** - Public accessible versions for updates
  - `.htaccess` is protected, so dev server serves `htaccess.txt` instead
  - Install scripts automatically rename and configure paths
- **Apache vhost path checking** - Install script now detects and fixes wrong DocumentRoot paths
- **Removed migration code** - Old structure migration code removed (no longer needed)

### Files Changed
- `live-update.php` - Correct URLs for dev vs GitHub sources
- `check-version.php` - Fixed dev server version check URL
- All installer scripts - Fixed source URLs and htaccess handling

## [3.5.1] - 2026-02-01

### Fixes
- Help tab now restores after page reload
- Git commit author configured

## [3.5.0] - 2026-02-01

### Project Restructuring
- **New `src/` directory structure** - All source code now lives in `src/` folder
  - Cleaner project organization
  - No more file duplication between root and `installer/src/`
  - Data files (.htpasswd, .config.json, etc.) stay in root
  - Symlinks in src/ for seamless access to data
  - Easier maintenance and development

### Update System
- **Dual update sources** - Choose between stable and development servers
  - GitHub (stable): `https://raw.githubusercontent.com/toshko37/webshare/main/src/`
  - Dev server: `https://webshare.techbg.net/`
  - Configure via `--source github|dev` flag or `.update-config.json`
- **Automatic migration** - Update script detects old structure and migrates
  - Moves PHP files to src/
  - Creates necessary symlinks
  - Updates Apache configuration

### Intelligent Installer
- **Existing installation detection** - Automatically detects previous installations
  - Shows what's already configured (users, SSL, vhost, files)
  - Interactive menu with options:
    1. Update software only (preserves everything)
    2. Fresh install (preserves data)
    3. Complete reinstall (clean slate)
    4. Cancel
- **Component checking** - Shows what's installed and what will be installed
  - Apache2, PHP, php-maxminddb, php-xml, Certbot, GeoIP database

### Chat UI Improvements
- **"Затвори" (Close) button** - Returns to chat list (/t)
- **"Изчисти" (Clear) button** - Clears all messages in conversation
  - Red styling for visibility
  - Confirmation dialog before clearing
  - Audit log entry for clear action

### Audit Log Rotation
- **Log file rotation** - Prevents unlimited growth
  - Current log keeps max 500 entries
  - Older entries rotate to archive files (.audit.1.json, .audit.2.json, etc.)
  - Up to 10 archives (total 5500 entries max)
  - Automatic rotation on write
  - Full history accessible for search and export

### Apache Configuration
- **DocumentRoot set to `src/`** - Apache serves from src/ subdirectory
- **Backward compatibility Alias** - `/installer/src/` maps to `/src/`
  - Old update URLs continue to work
  - Seamless transition for existing installations

### Scripts Updated
- `installer/install.sh` v3.1 - Full rewrite with src/ structure
- `installer/update.sh` v3.1 - Migration support, symlink creation
- `installer/get-webshare.sh` v3.0 - Quick installer for new structure

### File Changes
- New: `src/get-update.php`, `src/get-update-script.php`
- Updated: All PHP files for new paths
- Updated: `.htaccess` for new structure

### Breaking Changes
- File paths changed from `/installer/src/` to `/src/`
- Old installations will be automatically migrated on update

---

## [3.4.1] - 2026-02-01

### Added
- **Beta update server option** - New checkbox in Software Update modal
  - "Use developer server (beta)" option
  - Setting saved to `.update-config.json`
  - Clears version cache when switching sources
  - Default: OFF (uses GitHub stable releases)

### Documentation
- Added project origin story ("Как започна всичко") section

---

## [3.4.0] - 2026-02-01

### Added
- **Folder Sharing** - Share entire folders with a single link
  - Anyone with the link can view and download all files in the folder
  - Subfolders are visible and navigable
  - Optional password protection for extra security
  - Optional upload permission (visitors can upload files)
  - Optional delete permission (visitors can delete files)
  - Drag & drop upload zone for visitors
  - File picker button for visitors
  - "Download All" as .zip archive
  - Email notifications when visitors upload files
  - Token regeneration (New ID) to invalidate old links
  - Share badge (🔗) shows which folders are shared
  - Full audit logging for all folder share actions

- **Chat improvements**
  - Bulgarian UI translation (Разговор, Изпрати, etc.)
  - Color dot preview next to username showing user's color
  - Default name "Гост" with random session-based color
  - Visible circular send button with arrow icon
  - Keyboard hint: "Ctrl+Enter = изпрати"
  - Email button for chat links (if mail enabled)
  - New ID button for chat token regeneration
  - Fixed: New ID now works multiple times without reload

### Technical
- New URL routes: `/f/{token}`, `/f/{token}/upload`, `/f/{token}/download`
- New file: `f.php` - folder share handler
- New storage: `data/folder_shares.json`
- Audit log actions: folder_share_create, folder_share_update, folder_share_delete, folder_share_regenerate, folder_upload, folder_download, folder_zip_download, folder_delete

---

## [3.3.0] - 2026-01-31

### Added
- **Chat/Conversation System** - Text sharing transformed into real-time chat platform
  - Every shared text becomes a conversation anyone with the link can join
  - Multi-user chat with different usernames
  - Live viewer count with colored dots (10 second polling)
  - Real-time message updates (5 second polling)
  - Message positioning: own messages left, others' right
  - Author name colors derived from name hash (consistent per user)
  - Edit/Delete own messages (soft delete)
  - Expiration countdown timer with extend buttons (+1h, +1d, +1w)
  - Sound notifications toggle (Web Audio API beep, off by default)
  - Window flash notifications toggle (title blink, off by default)
  - Urgent messages (! prefix) - forces notifications even when muted
  - Automatic migration from old .html format to new .json format
  - Mobile-responsive chat UI

### Changed
- "Texts" tab renamed to "Chats" in main interface
- Shows message count for each conversation
- Simplified conversation creation with author name input
- Text data now stored as JSON with messages array

### Technical
- New API endpoints: messages, post, edit, delete, heartbeat, extend
- Rate limiting: 30 messages/minute per user
- Cryptographic user IDs for message ownership
- File locking for concurrent writes
- Backward compatible with legacy text format

---

## [3.2.0] - 2026-01-29

### Security (14 of 15 issues fixed)
- **CRITICAL**: Removed plain text password storage in encryption system
- **HIGH**: Enabled SSL certificate verification for web downloads
- **HIGH**: Removed password from GET parameters (now POST only)
- **HIGH**: Added CSRF protection to all forms and AJAX endpoints
- **HIGH**: API keys now support IP binding with auto-learn
- **HIGH**: Hidden SMTP password in settings (no longer visible in HTML)
- **MEDIUM**: Strengthened share tokens from 6 to 32 characters (128 bits)
- **MEDIUM**: Improved path traversal protection with secureFolderPath()
- **MEDIUM**: Added security headers (X-Frame-Options, X-XSS-Protection, etc.)
- **MEDIUM**: Added session fixation prevention (session_regenerate_id)
- **MEDIUM**: Added dangerous file extension blocking (php, phar, htaccess)
- **LOW**: Fixed timing attack vulnerability (hash_equals)
- **LOW**: Fixed race condition in file naming (unique ID instead of counter)
- Verified: Command execution (htpasswd) is properly escaped

### Added
- **Multiple API keys per user** - Create unlimited keys with different settings
- **IP auto-learn** - Keys lock to first IP used (empty = auto-learn, 0.0.0.0/0 = any)
- **API upload options** - overwrite=1 (replace files), encrypt=1 (encrypt on upload)
- **DateTime suffix** - Duplicate files get timestamp instead of random chars
- **Close button** - Added to text view page
- **Audit log improvement** - Shows API key name and ID for uploads
- **Remove registry** - Commands included as comments in BAT/PS1 scripts

### Fixed
- .reg file escaping for Windows paths (C:\\Scripts\\ instead of C:\Scripts\)
- Text sharing 32-char tokens with proper .htaccess routing

### Changed
- API key storage format (auto-migrates from old format)
- File duplicate naming: `file_20260129_143052.pdf` instead of `file_a1b2c3d4.pdf`

---

## [3.1.7] - 2026-01-27

### Added
- Welcome files auto-copy during installation (Welcome.txt, Documentation-BG.txt)
- Documentation files in docs/ folder

### Changed
- setup.sh now copies welcome files to files/ when created
- Updated README.md with new features

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
|  3.6.16  | 2026-03-11 | Fix: Email Settings UI, add Public Access toggles |
|  3.6.15  | 2026-03-11 | Fix: /u and other public pages no longer require login |
|  3.6.14  | 2026-03-10 | Fix: delete user folder and files when user is deleted |
|  3.6.13  | 2026-03-10 | Fix: country and user-agent missing in audit purge/clear entries |
|  3.6.12  | 2026-03-10 | Fix: admin folder visibility and orphaned folder cleanup |
|  3.6.11  | 2026-03-10 | Fix: clear OPcache after live update so version updates immediately |
|  3.6.10  | 2026-03-10 | Update: block all interactions with overlay during live update |
|  3.6.9  | 2026-03-10 | Fix: tab no longer reverts to Settings after reload |
|  3.6.8  | 2026-03-09 | Fix: refresh chat list after creation while staying on Chats tab |
|  3.6.7  | 2026-03-09 | Fix: stay on Chats tab after creating a chat |
|  3.6.6  | 2026-03-09 | Fix: Settings tab now persists across reloads like other tabs |
|  3.6.5  | 2026-03-09 | Fix: tab persistence after actions and fresh login always on Files |
|  3.6.4  | 2026-03-09 | Audit log retention management: purge entries older than 7 or 30 days |
|  3.6.3  | 2026-03-09 | Security: fix text.php auth and AJAX session expiry handling |
|  3.6.2  | 2026-03-09 | Fix: session close redirect and current session detection |
|  3.6.1  | 2026-03-09 | Fix login 500 error, session permissions, update system improvements |
|  3.6.0  | 2026-03-09 | Switch to PHP session-based authentication with multi-user support |
|  3.5.6  | 2026-02-09 | Chat: smart expiration, selection-safe polling, copy line breaks |
|  3.5.0  | 2026-02-01 | Project restructuring - src/ folder, audit log rotation, chat buttons |
|  3.4.1  | 2026-02-01 | Beta update server option |
|  3.4.0  | 2026-02-01 | Folder sharing, chat improvements |
|  3.3.0  | 2026-01-31 | Chat/Conversation system - real-time multi-user chat |
|  3.2.0  | 2026-01-29 | Major security update - 14 vulnerabilities fixed |
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

---

## Как започна всичко

Аз съм компютърен инженер и ежедневната ми работа включва ремонт и поддръжка на различни системи. Всеки път се сблъсквах с един и същ проблем — споделянето на файлове между компютри. Когато мрежите са различни и нямат достъп една до друга, това става истинско предизвикателство. Стандартните решения с мрежови папки просто не работят в такива ситуации.

Така се роди идеята за WebShare — нещо просто, с което да прехвърлям файлове и текстови команди от едно място на друго. Поставих си няколко основни изисквания:

- **Без база данни** — всичко да е в обикновени файлове
- **Лесна поддръжка** — да не изисква сложна конфигурация
- **Възможност за клониране** — едно копиране и работи
- **Офлайн режим** — да функционира и без интернет

Един колега видя колко полезно е това и поиска и той да го ползва. Нямаше проблем, но после се появи дилема — не исках той да има достъп до моите файлове, нито пък аз да виждам неговите. Така се роди идеята за мулти-потребителска система, но със запазена обща публична папка за споделяне между всички.

После исках да организирам файловете в различни категории и добавих поддръжка за папки. А щом вече имах папки, защо да не мога да споделям и цели папки? И така, идея по идея, WebShare продължава да се развива.

Вечер, докато гледам сериали и си почивам, отделям по някой час за проекта. Хем натрупвам опит, хем изпитвам удоволствие от нещо, което сам създавам. Така, функция по функция, WebShare се разрасна до това, което е днес.

Не съм професионален програмист — затова и интерфейсът не е най-изпипаният. Но това не е важното. Важното е, че работи точно както си го представях. Четох за добри практики в програмирането и доколкото ми стигат познанията, се опитах да ги приложа.

А тъй като познанията ми в кодирането са на базово ниво, намерих партньор — моят колега AI (Claude). Заедно изградихме проекта от нулата. Всяка функция, всеки ред код е резултат от това сътрудничество между човешка идея и изкуствен интелект.
