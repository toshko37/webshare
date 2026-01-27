# WebShare v2.0

**Self-hosted file and text sharing platform with GeoIP protection**

A simple, secure, and modern file sharing solution for personal or team use. Built with PHP and designed for easy deployment on Debian/Ubuntu servers.

---

## Features

### Core Features
- **File Upload & Download** - Drag & drop or click to upload, direct download links
- **Text Sharing** - Rich text editor (Quill.js) with HTML formatting support
- **Share Links** - Generate public links for files with token-based access
- **Multi-user Support** - Apache Basic Auth with user management UI

### Security Features
- **GeoIP Blocking** - Restrict access by country (public pages only)
- **XSS Protection** - HTML sanitization for text content
- **File Isolation** - Uploaded files protected from direct PHP execution
- **Admin-only Settings** - Configuration restricted to admin user

### User Experience
- **Modern UI** - Clean, responsive design with gradient themes
- **Upload Progress** - Real-time progress bar with speed and ETA
- **Success Screen** - Clear feedback after uploads with file list
- **Auto-rename** - Duplicate filenames automatically renamed (file_1.pdf)

---

## Quick Install

### Requirements
- Debian 11+ or Ubuntu 20.04+
- Root access
- Domain name pointing to server

### One-liner Installation

**With parameters:**
```bash
curl -fsSL https://webshare.techbg.net/get | bash -s -- domain.com admin password
```

**Interactive (prompts for input):**
```bash
curl -fsSL https://webshare.techbg.net/get | bash
```

### What the installer does:
1. Installs Apache, PHP, Certbot, php-maxminddb
2. Downloads and configures WebShare
3. Creates admin user with specified password
4. Sets up SSL certificate (Let's Encrypt)
5. Downloads GeoIP database
6. Configures proper file permissions

---

## Configuration

### File Locations

| File | Purpose |
|------|---------|
| `/var/www/webshare/` | Main application directory |
| `/var/www/webshare/files/` | Uploaded files storage |
| `/var/www/webshare/texts/` | Shared text content |
| `/var/www/webshare/.htpasswd` | User credentials |
| `/var/www/webshare/.geo.json` | GeoIP configuration |
| `/var/www/webshare/.config.json` | Site settings (speedtest URL) |
| `/var/www/webshare/.files-meta.json` | File ownership metadata |
| `/var/www/webshare/.texts.json` | Text sharing metadata |
| `/var/www/webshare/.tokens.json` | Share link tokens |

### GeoIP Configuration

Edit `/var/www/webshare/.geo.json`:

```json
{
    "enabled": true,
    "allowed_countries": ["BG", "RO", "GR"],
    "blocked_message": "Access denied from your location"
}
```

**Country codes:** Use ISO 3166-1 alpha-2 codes (BG, US, DE, etc.)

### PHP Settings

Located in `/var/www/webshare/.user.ini`:

```ini
upload_max_filesize = 10G
post_max_size = 10G
max_execution_time = 7200
max_input_time = 7200
memory_limit = 512M
```

---

## URL Structure

### Public Pages (No Authentication)

| URL | Description |
|-----|-------------|
| `/u` or `/upload` | Public file upload page |
| `/t` | Create new shared text |
| `/t/TOKEN` | View shared text |
| `/p/TOKEN` | Download shared file |

### Protected Pages (Requires Login)

| URL | Description |
|-----|-------------|
| `/` | Main dashboard (Files, Texts, Settings) |
| `/download.php?file=name` | Direct file download |

---

## User Management

### Via Web UI (Admin Only)
1. Login as `admin`
2. Go to **Settings** tab
3. Use **User Management** section to:
   - View existing users
   - Add new users
   - Change passwords
   - Delete users

### Via Command Line

**Add user:**
```bash
htpasswd -b /var/www/webshare/.htpasswd username password
chmod 644 /var/www/webshare/.htpasswd
```

**Delete user:**
```bash
htpasswd -D /var/www/webshare/.htpasswd username
```

**List users:**
```bash
cut -d: -f1 /var/www/webshare/.htpasswd
```

---

## API Endpoints

### File Upload (POST)

**Endpoint:** `/upload.php` or `/u`

**Request:**
```
POST /u
Content-Type: multipart/form-data
X-Requested-With: XMLHttpRequest

file: (binary)
```

**Response (JSON):**
```json
{
    "success": true,
    "originalName": "document.pdf",
    "finalName": "document_1.pdf",
    "renamed": true
}
```

### Text Share (POST)

**Endpoint:** `/text.php`

**Request:**
```
POST /text.php
Content-Type: application/x-www-form-urlencoded

action=create&content=<p>Hello World</p>&hours=24
```

**Response (JSON):**
```json
{
    "success": true,
    "token": "abc123",
    "editKey": "xyz789",
    "url": "/t/abc123",
    "editUrl": "/t/abc123?edit=xyz789"
}
```

### Create Share Link (POST)

**Endpoint:** `/share.php`

**Request:**
```
POST /share.php
Content-Type: application/x-www-form-urlencoded

action=create&file=document.pdf
```

**Response (JSON):**
```json
{
    "success": true,
    "token": "abc123",
    "url": "/p/abc123"
}
```

---

## Security Considerations

### Authentication
- Uses Apache Basic Auth over HTTPS
- Passwords stored as APR1-MD5 hashes
- Session persists until browser closes

### File Security
- Uploaded files stored outside web root logic
- `.htaccess` prevents PHP execution in `/files/`
- File metadata stored in JSON (not database)

### GeoIP Protection
- Applied only to public input pages (`/u`, `/t`)
- Main dashboard accessible from anywhere (has password)
- Uses MaxMind GeoLite2 database
- Fails open (allows access if database unavailable)

### Recommended: Block Default Vhost

Prevent access via IP address:

```bash
cat > /etc/apache2/sites-available/000-default.conf <<'EOF'
<VirtualHost *:80>
    ServerName localhost
    Redirect 403 /
    ErrorDocument 403 "Forbidden"
</VirtualHost>

<VirtualHost *:443>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    Redirect 403 /
    ErrorDocument 403 "Forbidden"
</VirtualHost>
EOF
systemctl reload apache2
```

---

## Speed Test Add-on

Install LibreSpeed with GeoIP protection:

```bash
curl -fsSL https://webshare.techbg.net/get-speedtest | bash -s -- speed.domain.com
```

### Features:
- LibreSpeed (self-hosted speed test)
- GeoIP protection (BG only by default)
- Optional WebShare link

### Configuration:

Edit `/var/www/speedtest/.geo.json`:
```json
{
    "enabled": true,
    "allowed_countries": ["BG"]
}
```

### Link in WebShare:

1. Go to **Settings** > **Speed Test Link**
2. Enter URL (e.g., `https://speed.domain.com`)
3. Save

---

## File Structure

```
/var/www/webshare/
├── index.php              # Main dashboard
├── upload.php             # Public upload page
├── u.php                  # Redirect to upload.php
├── t.php                  # Public text sharing
├── text.php               # Text API endpoint
├── download.php           # File download handler
├── share.php              # Share link generator
├── public.php             # Public file access
├── p.php                  # Redirect to public.php
├── geo-check.php          # GeoIP functions
├── user-management.php    # User management functions
├── html-sanitizer.php     # XSS protection
├── get.php                # Installer script server
├── get-speedtest.php      # Speed test installer server
├── .htaccess              # Apache configuration
├── .htpasswd              # User credentials
├── .user.ini              # PHP settings
├── .geo.json              # GeoIP configuration
├── .config.json           # Site settings
├── .files-meta.json       # File ownership data
├── .texts.json            # Text metadata
├── .tokens.json           # Share tokens
├── GeoLite2-Country.mmdb  # GeoIP database
├── files/                 # Uploaded files
│   └── .htaccess          # Prevent PHP execution
├── texts/                 # Shared text content
└── installer/             # Installation package
    ├── get-webshare.sh    # WebShare installer
    ├── get-speedtest.sh   # Speed test installer
    └── src/               # Source files
```

---

## Troubleshooting

### "Country: Unknown" in GeoIP

```bash
# Check if database exists
ls -la /var/www/webshare/GeoLite2-Country.mmdb

# Download if missing
curl -fsSL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" \
    -o /var/www/webshare/GeoLite2-Country.mmdb
chown www-data:www-data /var/www/webshare/GeoLite2-Country.mmdb

# Check php-maxminddb
php -m | grep maxmind
```

### Permission Denied Errors

```bash
# Fix ownership
chown -R www-data:www-data /var/www/webshare

# Fix file permissions
find /var/www/webshare -type f -exec chmod 644 {} \;
find /var/www/webshare -type d -exec chmod 755 {} \;

# Make .htpasswd readable by Apache
chmod 644 /var/www/webshare/.htpasswd
```

### Upload Fails for Large Files

Edit `/var/www/webshare/.user.ini`:
```ini
upload_max_filesize = 10G
post_max_size = 10G
```

Also check Apache timeout in `/etc/apache2/apache2.conf`:
```apache
Timeout 7200
```

### SSL Certificate Issues

```bash
# Renew certificate
certbot renew

# Force new certificate
certbot --apache -d domain.com --force-renewal
```

### User Locked Out After Password Change

```bash
# Reset .htpasswd permissions
chmod 644 /var/www/webshare/.htpasswd

# Verify file format
cat /var/www/webshare/.htpasswd
# Should show: username:$apr1$...
```

---

## Updates

### Manual Update

```bash
# Backup current installation
cp -r /var/www/webshare /var/www/webshare.bak

# Download latest
curl -fsSL https://webshare.techbg.net/webshare-installer-v2.tar.gz -o /tmp/ws.tar.gz
tar -xzf /tmp/ws.tar.gz -C /tmp

# Update files (preserve config)
cp /tmp/installer/src/*.php /var/www/webshare/
cp /tmp/installer/src/.htaccess /var/www/webshare/

# Cleanup
rm -rf /tmp/ws.tar.gz /tmp/installer
```

---

## License

MIT License - Free for personal and commercial use.

---

## Credits

- **WebShare** - Custom development
- **Quill.js** - Rich text editor
- **LibreSpeed** - Speed test (add-on)
- **MaxMind GeoLite2** - GeoIP database

---

## Support

For issues and feature requests, contact the administrator.
