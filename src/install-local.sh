#!/bin/bash
#
# WebShare Local Installation Script
# ===================================
# Use this script when you've copied the WebShare folder manually
# and need to configure it for the new location.
#
# Usage: sudo ./install-local.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           WebShare Local Installation                    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install-local.sh)${NC}"
    exit 1
fi

# Get installation directory (where this script is located)
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
echo -e "Installation directory: ${GREEN}$INSTALL_DIR${NC}"
echo ""

# Step 1: Check PHP version
echo -e "${BLUE}[1/6] Checking PHP...${NC}"
if command -v php &> /dev/null; then
    PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
    echo -e "  PHP version: ${GREEN}$PHP_VERSION${NC}"

    # Check minimum version (7.4)
    PHP_MAJOR=$(php -r "echo PHP_MAJOR_VERSION;")
    PHP_MINOR=$(php -r "echo PHP_MINOR_VERSION;")
    if [ "$PHP_MAJOR" -lt 7 ] || ([ "$PHP_MAJOR" -eq 7 ] && [ "$PHP_MINOR" -lt 4 ]); then
        echo -e "${RED}  PHP 7.4 or higher is required${NC}"
        exit 1
    fi
else
    echo -e "${RED}  PHP not found. Please install PHP 7.4 or higher.${NC}"
    echo -e "  For Debian/Ubuntu: apt install php php-fpm php-xml php-curl php-mbstring"
    exit 1
fi

# Step 2: Check and install PHP extensions
echo ""
echo -e "${BLUE}[2/6] Checking PHP extensions...${NC}"

check_extension() {
    local ext=$1
    local pkg=$2
    if php -m 2>/dev/null | grep -qi "^$ext$"; then
        echo -e "  $ext: ${GREEN}OK${NC}"
        return 0
    else
        echo -n "  $ext: missing, installing... "
        if apt-get install -y -qq "$pkg" > /dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
            return 0
        else
            echo -e "${YELLOW}skipped (install manually: apt install $pkg)${NC}"
            return 1
        fi
    fi
}

# Required extensions
check_extension "xml" "php-xml"
check_extension "curl" "php-curl"
check_extension "mbstring" "php-mbstring"
check_extension "json" "php-json" || true  # Built-in in PHP 8+

# Optional extensions
echo -n "  maxminddb (GeoIP): "
if php -m 2>/dev/null | grep -qi "maxminddb"; then
    echo -e "${GREEN}OK${NC}"
else
    apt-get install -y -qq php-maxminddb > /dev/null 2>&1 && echo -e "${GREEN}installed${NC}" || echo -e "${YELLOW}skipped (GeoIP will be disabled)${NC}"
fi

# Step 3: Create directories
echo ""
echo -e "${BLUE}[3/6] Setting up directories...${NC}"

mkdir -p "$INSTALL_DIR/files/_public"
mkdir -p "$INSTALL_DIR/files/admin"
mkdir -p "$INSTALL_DIR/texts"
mkdir -p "$INSTALL_DIR/assets/quill"

echo -e "  Directories: ${GREEN}OK${NC}"

# Step 4: Create default config if not exists
echo ""
echo -e "${BLUE}[4/6] Checking configuration...${NC}"

if [ ! -f "$INSTALL_DIR/.config.json" ]; then
    cat > "$INSTALL_DIR/.config.json" << 'EOF'
{
    "speedtest_url": ""
}
EOF
    echo -e "  Created default .config.json"
else
    echo -e "  .config.json: ${GREEN}exists${NC}"
fi

if [ ! -f "$INSTALL_DIR/.htpasswd" ]; then
    echo ""
    echo -e "${YELLOW}No .htpasswd file found. Creating admin user...${NC}"
    read -p "  Enter admin password: " -s ADMIN_PASS
    echo ""
    htpasswd -cb "$INSTALL_DIR/.htpasswd" admin "$ADMIN_PASS"
    mkdir -p "$INSTALL_DIR/files/admin"
    echo -e "  Admin user created: ${GREEN}admin${NC}"
else
    echo -e "  .htpasswd: ${GREEN}exists${NC}"
fi

# Step 5: Download GeoIP database if missing
echo ""
echo -e "${BLUE}[5/6] Checking GeoIP database...${NC}"

if [ ! -f "$INSTALL_DIR/GeoLite2-Country.mmdb" ]; then
    echo -n "  Downloading GeoIP database... "
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    if curl -fsSL "$GEOIP_URL" -o "$INSTALL_DIR/GeoLite2-Country.mmdb" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped (GeoIP will be disabled)${NC}"
    fi
else
    echo -e "  GeoIP database: ${GREEN}exists${NC}"
fi

# Step 6: Set permissions
echo ""
echo -e "${BLUE}[6/6] Setting permissions...${NC}"

# Detect web server user
WEB_USER="www-data"
if id "apache" &>/dev/null; then
    WEB_USER="apache"
elif id "nginx" &>/dev/null; then
    WEB_USER="nginx"
elif id "http" &>/dev/null; then
    WEB_USER="http"
fi

chown -R "$WEB_USER:$WEB_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 644 "$INSTALL_DIR"/*.php 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/.htaccess 2>/dev/null || true
chmod 600 "$INSTALL_DIR"/.*.json 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/.htpasswd 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/files" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/texts" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/assets" 2>/dev/null || true
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true

echo -e "  Owner: ${GREEN}$WEB_USER${NC}"
echo -e "  Permissions: ${GREEN}OK${NC}"

# Get version
VERSION=$(grep -oP "WEBSHARE_VERSION.*?'\K[^']+" "$INSTALL_DIR/index.php" 2>/dev/null || echo "unknown")

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation Complete!                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Version: ${GREEN}$VERSION${NC}"
echo -e "  Location: ${GREEN}$INSTALL_DIR${NC}"
echo -e "  Web user: ${GREEN}$WEB_USER${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Configure your web server (Apache/Nginx) to serve this directory"
echo "  2. Ensure .htaccess is enabled (Apache: AllowOverride All)"
echo "  3. Access WebShare via your browser"
echo ""
echo -e "${BLUE}Apache example vhost:${NC}"
echo "  <VirtualHost *:80>"
echo "      ServerName webshare.example.com"
echo "      DocumentRoot $INSTALL_DIR"
echo "      <Directory $INSTALL_DIR>"
echo "          AllowOverride All"
echo "          Require all granted"
echo "      </Directory>"
echo "  </VirtualHost>"
echo ""
