# WebShare

**WebShare** is a simple, self-hosted file sharing application with multi-user support, folder organization, file encryption, and one-click updates.

![Version](https://img.shields.io/github/v/release/toshko37/webshare)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

### File Management
- **Drag & Drop Upload** - Upload files by dragging them to the browser
- **Folder System** - Organize files in user folders and subfolders (up to 3 levels)
- **File Operations** - Rename, move, delete files
- **File Sharing** - Generate public links with unique tokens
- **Web Download** - Download files from URL directly to server
- **API Upload** - Upload via API with Windows right-click integration

### Security
- **User Authentication** - Apache Basic Auth with .htpasswd
- **File Encryption** - AES-256-GCM encryption for sensitive files
- **GeoIP Filtering** - Restrict access by country (public pages only)
- **CSRF Protection** - All forms protected against CSRF attacks
- **Audit Logging** - Track all user actions with country detection

### Sharing
- **Public Links** - Share files via short token-based URLs (`/p?t=abc123`)
- **Email Sharing** - Send share links via email (SMTP)
- **Text Sharing** - Share rich text with Quill.js editor
- **Public Upload** - Allow others to upload without seeing existing files (`/u`)

### Updates
- **Live Update** - One-click update from browser (no SSH needed)
- **Auto-check** - Automatic version check from GitHub releases
- **Dual Source** - Check GitHub (stable) or dev server (beta)
- **Shell Update** - Traditional `./update.sh` script

## Quick Start

### Option 1: GitHub Clone (Recommended)

```bash
git clone https://github.com/toshko37/webshare.git
cd webshare
sudo ./setup.sh
htpasswd -c .htpasswd admin
```

### Option 2: Remote Install

```bash
curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash -s -- your-domain.com
```

### Option 3: Manual Setup

1. Download and extract WebShare
2. Run `./setup.sh` to initialize
3. Create admin user: `htpasswd -c .htpasswd admin`
4. Configure Apache virtual host

## Requirements

- **PHP 7.4+** (8.0+ recommended)
- **Apache** with mod_rewrite
- **Extensions**: php-xml, php-curl, php-mbstring
- **Optional**: php-maxminddb (for GeoIP)

## Configuration

### Apache Virtual Host

```apache
<VirtualHost *:443>
    ServerName webshare.example.com
    DocumentRoot /var/www/webshare

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/webshare.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/webshare.example.com/privkey.pem

    <Directory /var/www/webshare>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### Configuration Files

| File | Purpose |
|------|---------|
| `.htpasswd` | User credentials |
| `.config.json` | SMTP and site settings |
| `.geo.json` | GeoIP country filtering |
| `.update-config.json` | Update source (stable/beta) |

## Updating

### From Browser (Live Update)

1. Click version number in header
2. Click **"Live Update"** button
3. Wait for completion and auto-refresh

### From Terminal

```bash
cd /var/www/webshare
./update.sh -y
```

## API Upload

Upload files via command line or scripts:

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" -F "file=@document.pdf" \
  https://your-server.com/api-upload.php
```

Generate API keys in **Help → API Upload** section.

## File Structure

```
webshare/
├── index.php           # Main application
├── files/              # Uploaded files
│   ├── _public/        # Public folder
│   └── [username]/     # User folders
├── texts/              # Shared texts
├── assets/quill/       # Rich text editor
├── .htpasswd           # User credentials
├── .config.json        # Configuration
└── version.json        # Version info
```

## Security

- Always use **HTTPS** in production
- Use **strong passwords** for all users
- Enable **GeoIP filtering** if possible
- Configure **fail2ban** for brute-force protection
- Regular **backups** of files/ and config

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 500 Error | Check `tail -f /var/log/apache2/error.log` |
| 403 Forbidden | Verify .htpasswd exists and permissions |
| Upload fails | Check PHP limits in .htaccess |
| GeoIP not working | Install php-maxminddb |

## Links

- **Repository**: https://github.com/toshko37/webshare
- **Releases**: https://github.com/toshko37/webshare/releases
- **Issues**: https://github.com/toshko37/webshare/issues

## License

MIT License - See [LICENSE](LICENSE) file.

---

**WebShare** - Simple, secure file sharing.
Created by [Todor Karachorbadzhiev](https://github.com/toshko37)
