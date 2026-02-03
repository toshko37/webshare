# WebShare

**WebShare** is a simple, self-hosted file sharing application with multi-user support, folder organization, file encryption, and one-click updates.

![Version](https://img.shields.io/badge/version-3.5.5-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple)

## Features

- **Drag & Drop Upload** - Upload files by dragging them to the browser
- **Folder System** - Organize files in folders and subfolders
- **Folder Sharing** - Share entire folders with a single link
- **File Encryption** - AES-256-GCM encryption for sensitive files
- **Text Sharing** - Rich text editor for sharing formatted text
- **GeoIP Filtering** - Restrict access by country
- **Live Update** - One-click updates from browser
- **API Upload** - Windows right-click integration

## Quick Install

### One-liner (Debian/Ubuntu)

**Interactive** (will prompt for domain and password):
```bash
curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash
```

**With domain only** (will prompt for password):
```bash
curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash -s -- example.com
```

**Fully automated** (no prompts):
```bash
curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash -s -- example.com admin MySecurePass123
```

Parameters: `domain [username] [password]`
- `domain` - Your domain name (required)
- `username` - Admin username (default: admin)
- `password` - Admin password (required if not interactive)

### Manual Install

```bash
# Clone repository
git clone https://github.com/toshko37/webshare.git
cd webshare/installer

# Run installer
sudo ./install.sh your-domain.com
```

### Update Existing Installation

```bash
cd /var/www/webshare
./update.sh
```

Or use **Live Update** from browser (click version number in header).

## Project Structure

```
webshare/
├── src/                    # Source code
│   ├── *.php               # PHP files
│   ├── assets/             # Quill.js editor
│   ├── docs/               # Documentation
│   └── version.json        # Version info
├── installer/
│   ├── install.sh          # Full installer
│   ├── update.sh           # Update script
│   └── get-webshare.sh     # Quick installer
├── README.md               # This file
└── LICENSE
```

## Requirements

- **PHP 7.4+** (8.0+ recommended)
- **Apache** with mod_rewrite, mod_ssl
- **Extensions**: php-xml, php-curl, php-mbstring
- **Optional**: php-maxminddb (for GeoIP)

## Documentation

- [Full Documentation](src/README.md)
- [Changelog](src/CHANGELOG.md)
- [Security Audit](src/SECURITY-AUDIT.md)
- [Документация (BG)](src/README-BG.md)

## Update Sources

WebShare supports two update sources:

| Source | URL | Description |
|--------|-----|-------------|
| **GitHub** (default) | `github.com/toshko37/webshare` | Stable releases |
| **Dev Server** | `webshare.techbg.net` | Beta/testing |

Configure in `.update-config.json`:
```json
{"stable": true}   // GitHub (recommended)
{"stable": false}  // Dev server
```

## License

MIT License - See [LICENSE](LICENSE) file.

---

**WebShare** - Simple, secure file sharing.

Created by [Todor Karachorbadzhiev](https://github.com/toshko37)
