#!/bin/bash

# WebShare Setup Script
# Run this after cloning from GitHub to initialize the installation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       WebShare Setup Script            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "Install directory: ${BLUE}$SCRIPT_DIR${NC}"
echo ""

# Check if running as root or www-data
if [[ $EUID -ne 0 ]] && [[ $(whoami) != "www-data" ]]; then
    echo -e "${YELLOW}Warning: Running as $(whoami). Some operations may require sudo.${NC}"
fi

# 1. Create required directories
echo -e "${GREEN}[1/7] Creating directories...${NC}"
FILES_NEW=false
if [ ! -d "files" ]; then
    FILES_NEW=true
fi
mkdir -p files texts backups assets/quill docs
echo "  ✓ files/, texts/, backups/, assets/quill/, docs/ created"

# Copy welcome files to files/ if it was just created (empty)
if [ "$FILES_NEW" = true ] && [ -d "docs" ]; then
    if [ -f "docs/Welcome.txt" ]; then
        cp "docs/Welcome.txt" "files/"
        echo "  ✓ Welcome.txt added to files/"
    fi
    if [ -f "docs/Документация.txt" ]; then
        cp "docs/Документация.txt" "files/"
        echo "  ✓ Документация.txt added to files/"
    fi
fi

# 2. Install system dependencies
echo -e "${GREEN}[2/7] Checking system dependencies...${NC}"

# Check for PHP
if ! command -v php &> /dev/null; then
    echo -e "${RED}  ✗ PHP not found. Please install PHP 8.0+ first.${NC}"
    exit 1
fi
echo "  ✓ PHP $(php -v | head -n1 | cut -d' ' -f2)"

# Check for Apache
if ! command -v apache2 &> /dev/null && ! command -v httpd &> /dev/null; then
    echo -e "${YELLOW}  ! Apache not found. Install with: sudo apt install apache2${NC}"
fi

# Check for curl
if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}  ! curl not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y curl
fi
echo "  ✓ curl available"

# Check for unzip
if ! command -v unzip &> /dev/null; then
    echo -e "${YELLOW}  ! unzip not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y unzip
fi
echo "  ✓ unzip available"

# 3. Fix hardcoded paths in .htaccess
echo -e "${GREEN}[3/7] Configuring .htaccess...${NC}"
if [ -f ".htaccess" ]; then
    # Replace hardcoded path with current directory
    sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $SCRIPT_DIR/.htpasswd|g" .htaccess
    echo "  ✓ Updated AuthUserFile path to: $SCRIPT_DIR/.htpasswd"
else
    echo -e "${YELLOW}  ! .htaccess not found${NC}"
fi

# Create files/.htaccess for security (block direct access to uploads)
if [ ! -f "files/.htaccess" ]; then
    cat > files/.htaccess << 'HTEOF'
# Protect uploaded files from direct access
# Files should only be downloaded through download.php

# Deny all direct access
Require all denied

# Block PHP execution
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
HTEOF
    echo "  ✓ files/.htaccess created (security)"
else
    echo "  - files/.htaccess already exists"
fi

# Create texts/.htaccess for security
if [ ! -f "texts/.htaccess" ]; then
    cat > texts/.htaccess << 'HTEOF'
# Protect text files from direct access
Require all denied
HTEOF
    echo "  ✓ texts/.htaccess created (security)"
else
    echo "  - texts/.htaccess already exists"
fi

# 4. Install Composer dependencies
echo -e "${GREEN}[4/7] Installing Composer dependencies...${NC}"
if [ -f "composer.json" ]; then
    if command -v composer &> /dev/null; then
        composer install --no-dev --optimize-autoloader 2>/dev/null || {
            echo -e "${YELLOW}  ! Composer install failed, trying with --ignore-platform-reqs${NC}"
            composer install --no-dev --optimize-autoloader --ignore-platform-reqs
        }
        echo "  ✓ Composer dependencies installed"
    else
        echo -e "${YELLOW}  ! Composer not found. Installing...${NC}"
        curl -sS https://getcomposer.org/installer | php
        php composer.phar install --no-dev --optimize-autoloader
        rm -f composer.phar
        echo "  ✓ Composer dependencies installed"
    fi
else
    echo "  - No composer.json found, skipping"
fi

# 5. Download GeoIP database
echo -e "${GREEN}[5/7] Setting up GeoIP database...${NC}"
GEOIP_FILE="GeoLite2-Country.mmdb"
if [ ! -f "$GEOIP_FILE" ]; then
    echo "  Downloading GeoLite2-Country database..."
    if curl -fsSL -o "$GEOIP_FILE" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null; then
        echo "  ✓ GeoIP database downloaded"
    else
        echo -e "${YELLOW}  ! Could not download GeoIP database. GeoIP features will be disabled.${NC}"
        echo -e "${YELLOW}    You can manually download from: https://github.com/P3TERX/GeoLite.mmdb${NC}"
    fi
else
    echo "  ✓ GeoIP database already exists"
fi

# Download Quill.js if not present
echo -e "${GREEN}[6/7] Setting up Quill.js editor...${NC}"
if [ ! -f "assets/quill/quill.js" ]; then
    echo "  Downloading Quill.js..."
    curl -fsSL -o "assets/quill/quill.js" "https://cdn.quilljs.com/1.3.7/quill.min.js" 2>/dev/null || true
    curl -fsSL -o "assets/quill/quill.snow.css" "https://cdn.quilljs.com/1.3.7/quill.snow.css" 2>/dev/null || true
    if [ -f "assets/quill/quill.js" ]; then
        echo "  ✓ Quill.js downloaded"
    else
        echo -e "${YELLOW}  ! Could not download Quill.js. Text editor may not work.${NC}"
    fi
else
    echo "  ✓ Quill.js already exists"
fi

# 6. Create default configuration files
echo -e "${GREEN}[7/7] Creating default configuration...${NC}"

# .htpasswd (empty, user will add via UI or htpasswd command)
if [ ! -f ".htpasswd" ]; then
    touch .htpasswd
    echo "  ✓ .htpasswd created (empty - add users with htpasswd command)"
else
    echo "  - .htpasswd already exists"
fi

# .geo.json
if [ ! -f ".geo.json" ]; then
    echo '{"enabled":false,"allowed_countries":["BG"],"blocked_countries":[]}' > .geo.json
    echo "  ✓ .geo.json created (GeoIP disabled by default)"
else
    echo "  - .geo.json already exists"
fi

# .config.json
if [ ! -f ".config.json" ]; then
    echo '{"mail_enabled":false,"smtp_host":"","smtp_port":587,"smtp_user":"","smtp_pass":"","smtp_encryption":"tls","mail_from":""}' > .config.json
    echo "  ✓ .config.json created"
else
    echo "  - .config.json already exists"
fi

# Empty JSON files for data storage
for file in .files-meta.json .texts.json .tokens.json .audit.json; do
    if [ ! -f "$file" ]; then
        echo '{}' > "$file"
        echo "  ✓ $file created"
    fi
done

if [ ! -f ".api-keys.json" ]; then
    echo '[]' > .api-keys.json
    echo "  ✓ .api-keys.json created"
fi

if [ ! -f ".mail-ratelimit.json" ]; then
    echo '{}' > .mail-ratelimit.json
    echo "  ✓ .mail-ratelimit.json created"
fi

# Set permissions
echo ""
echo -e "${BLUE}Setting permissions...${NC}"
WEB_USER="www-data"

# Check if www-data exists
if id "$WEB_USER" &>/dev/null; then
    # Directories need to be writable
    sudo chown -R $WEB_USER:$WEB_USER files texts backups assets 2>/dev/null || true

    # Config and data files
    sudo chown $WEB_USER:$WEB_USER .htpasswd .geo.json .config.json .files-meta.json .texts.json .tokens.json .audit.json .api-keys.json .mail-ratelimit.json 2>/dev/null || true

    # Sensitive files should be readable only by owner
    chmod 600 .htpasswd .api-keys.json .tokens.json 2>/dev/null || true
    chmod 644 .geo.json .config.json .files-meta.json .texts.json .audit.json .mail-ratelimit.json 2>/dev/null || true

    # Make scripts executable
    chmod +x setup.sh update.sh install-local.sh 2>/dev/null || true

    echo "  ✓ Permissions set for $WEB_USER"
else
    echo -e "${YELLOW}  ! User $WEB_USER not found. Set permissions manually.${NC}"
fi

# Done
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Setup Complete!               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Create first admin user:"
echo -e "     ${YELLOW}sudo htpasswd .htpasswd admin${NC}"
echo -e ""
echo -e "  2. Configure Apache virtual host to point to:"
echo -e "     ${BLUE}$SCRIPT_DIR${NC}"
echo -e ""
echo -e "  3. Enable required Apache modules:"
echo -e "     ${YELLOW}sudo a2enmod rewrite headers ssl${NC}"
echo -e ""
echo -e "  4. Restart Apache:"
echo -e "     ${YELLOW}sudo systemctl restart apache2${NC}"
echo ""
echo -e "Or use the full installer for automatic Apache + SSL setup:"
echo -e "     ${BLUE}sudo ./install-local.sh${NC}"
echo ""
