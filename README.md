# WebShare

**WebShare** is a simple, self-hosted file sharing application with multi-user support, folder organization, file encryption, and email sharing capabilities.

## Features

### File Management
- **Drag & Drop Upload** - Upload files by dragging them to the browser
- **Folder System** - Organize files in user folders and subfolders (up to 3 levels)
- **File Operations** - Rename, move, delete files
- **File Sharing** - Generate public links with optional expiration
- **Web Download** - Download files from URL directly to server

### Security
- **User Authentication** - Apache Basic Auth with .htpasswd
- **File Encryption** - AES-256-GCM encryption for sensitive files
- **GeoIP Filtering** - Restrict access by country
- **CSRF Protection** - All forms protected against CSRF attacks
- **Audit Logging** - Track all user actions

### Sharing
- **Public Links** - Share files via token-based URLs
- **Email Sharing** - Send share links via email (SMTP)
- **Text Sharing** - Share rich text with syntax highlighting

### Additional
- **Multi-language** - Interface supports multiple languages
- **Responsive Design** - Works on desktop and mobile
- **No Database** - All data stored in JSON files

## Requirements

### Minimum
- PHP 7.4 or higher
- Apache with mod_rewrite
- 50MB disk space (plus storage for files)

### Recommended
- PHP 8.0+
- php-xml (for DOMDocument)
- php-curl (for web download)
- php-mbstring (for text handling)
- php-maxminddb (for GeoIP)

## Installation

### Method 1: GitHub Clone (Recommended)

```bash
# Clone the repository
git clone https://github.com/toshko37/webshare.git
cd webshare

# Run setup script
chmod +x setup.sh
./setup.sh

# Create admin user
htpasswd -c .htpasswd admin

# Or use full installer for Apache + SSL setup
sudo ./install-local.sh
```

### Method 2: Remote Install (Quick)

If you have an existing WebShare server, you can install from there:
```bash
curl -fsSL https://your-webshare-server.com/get | bash
```

### Method 3: Manual Installation

1. Download/clone WebShare files
2. Run the setup script:
```bash
./setup.sh
```
3. Create admin user:
```bash
htpasswd -c .htpasswd admin
```
4. Configure Apache virtual host (see below)

### What setup.sh Does

- Creates required directories (`files/`, `texts/`, `backups/`)
- Downloads GeoIP database (GeoLite2-Country.mmdb)
- Installs Composer dependencies
- Creates default configuration files
- Sets correct file permissions

## Configuration

### Apache Virtual Host

```apache
<VirtualHost *:80>
    ServerName webshare.example.com
    DocumentRoot /var/www/webshare

    <Directory /var/www/webshare>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### SSL (Recommended)

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

### Email Settings (Optional)

Configure in Settings tab:
- SMTP Host (e.g., mail.example.com)
- SMTP Port (465 for SSL, 587 for TLS)
- SMTP User
- SMTP Password
- Encryption (SSL/TLS)

### GeoIP Settings (Optional)

Create `.geo.json`:
```json
{
    "enabled": true,
    "allowed_countries": ["BG", "US", "DE"],
    "blocked_countries": [],
    "allow_unknown": false
}
```

## File Structure

```
webshare/
├── index.php           # Main application
├── upload.php          # File upload handler
├── download.php        # File download handler
├── share.php           # Share link generator
├── public.php          # Public file access
├── text.php            # Text storage backend
├── t.php               # Text sharing interface
├── send-mail.php       # Email sending API
├── web-download.php    # URL download handler
├── .htaccess           # Apache configuration
├── .htpasswd           # User credentials
├── .config.json        # Site configuration
├── .geo.json           # GeoIP configuration
├── files/              # User files
│   ├── _public/        # Public folder
│   └── [username]/     # User folders
├── texts/              # Shared texts
└── assets/             # Static assets
    └── quill/          # Quill.js editor
```

## Updating

### Automatic Update

```bash
cd /path/to/webshare
./update.sh
```

### Manual Update

Download new files and replace, preserving:
- `files/` directory
- `texts/` directory
- `.htpasswd`
- `.config.json`
- `.geo.json`
- `GeoLite2-Country.mmdb`

## Troubleshooting

### 500 Internal Server Error
- Check Apache error log: `tail -f /var/log/apache2/error.log`
- Verify PHP is installed: `php -v`
- Check .htaccess is enabled: `AllowOverride All` in Apache config

### 403 Forbidden
- Check file permissions: `ls -la`
- Verify .htpasswd exists and is readable

### Files Not Uploading
- Check PHP upload limits in `.htaccess` or `php.ini`
- Verify `files/` directory is writable

### GeoIP Not Working
- Install php-maxminddb: `apt install php-maxminddb`
- Download database: `GeoLite2-Country.mmdb`

### Email Not Sending
- Verify SMTP settings in Settings tab
- Check MX records for recipient domain
- Test with the Test button before saving

## Security Recommendations

1. **Use HTTPS** - Always use SSL/TLS in production
2. **Strong Passwords** - Use strong passwords for all users
3. **Regular Updates** - Keep WebShare and PHP updated
4. **Backup** - Regularly backup `files/`, `.htpasswd`, and config files
5. **Firewall** - Restrict access to trusted IPs if possible
6. **fail2ban** - Configure fail2ban for brute-force protection

## License

MIT License - See LICENSE file for details.

---

**WebShare** - Simple, secure file sharing.
