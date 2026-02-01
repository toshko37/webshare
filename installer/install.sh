#!/bin/bash
#
# WebShare Installer v3.1
# =======================
# Intelligent installer with existing installation detection
# Supports GitHub (stable) and dev server sources
# New src/ directory structure
#
# Usage:
#   sudo ./install.sh domain.com [username] [password]
#   sudo ./install.sh --source dev domain.com
#
# Options:
#   --source github|dev  - Choose update source (default: github)
#   --force              - Skip existing installation check
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Output functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
check_mark() { echo -e "  ${GREEN}[✓]${NC} $1"; }
cross_mark() { echo -e "  ${RED}[✗]${NC} $1 ${YELLOW}$2${NC}"; }

# Check for root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo ./install.sh"
fi

# Default values
SOURCE="github"
FORCE=false
DOMAIN=""
AUTH_USER="admin"
AUTH_PASS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            SOURCE="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            elif [ -z "$AUTH_USER" ] || [ "$AUTH_USER" = "admin" ]; then
                AUTH_USER="$1"
            elif [ -z "$AUTH_PASS" ]; then
                AUTH_PASS="$1"
            fi
            shift
            ;;
    esac
done

# Validate source
if [ "$SOURCE" != "github" ] && [ "$SOURCE" != "dev" ]; then
    error "Invalid source: $SOURCE. Use 'github' or 'dev'"
fi

# Banner
echo ""
echo -e "${CYAN}╦ ╦┌─┐┌┐ ╔═╗┬ ┬┌─┐┬─┐┌─┐${NC}"
echo -e "${CYAN}║║║├┤ ├┴┐╚═╗├─┤├─┤├┬┘├┤ ${NC}"
echo -e "${CYAN}╚╩╝└─┘└─┘╚═╝┴ ┴┴ ┴┴└─└─┘${NC}"
echo ""
echo -e "${BLUE}Installer v3.1${NC} - Source: ${GREEN}$SOURCE${NC}"
echo ""

# Check domain
if [ -z "$DOMAIN" ]; then
    echo "Usage:"
    echo "  sudo ./install.sh <domain> [username] [password]"
    echo ""
    echo "Options:"
    echo "  --source github|dev  - Update source (default: github)"
    echo "  --force              - Skip existing installation check"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh webshare.example.com"
    echo "  sudo ./install.sh webshare.example.com admin mypass123"
    echo "  sudo ./install.sh --source dev webshare.example.com"
    echo ""
    error "Domain is required!"
fi

INSTALL_DIR="/var/www/${DOMAIN}"
SRC_DIR="$INSTALL_DIR/src"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEOIP_DIR="/usr/share/GeoIP"

# ============================================
# Check for existing installation
# ============================================
check_existing_installation() {
    local has_existing=false
    local has_htpasswd=false
    local has_config=false
    local has_ssl=false
    local has_vhost=false
    local ssl_expiry=""

    echo -e "${BLUE}Checking for existing installation...${NC}"
    echo ""

    # Check for index.php (old or new structure)
    if [ -f "$INSTALL_DIR/src/index.php" ] || [ -f "$INSTALL_DIR/index.php" ]; then
        has_existing=true
        check_mark "WebShare installation found"
    fi

    # Check for .htpasswd
    if [ -f "$INSTALL_DIR/.htpasswd" ]; then
        has_htpasswd=true
        local user_count=$(wc -l < "$INSTALL_DIR/.htpasswd")
        check_mark ".htpasswd - $user_count user(s)"
    fi

    # Check for .config.json
    if [ -f "$INSTALL_DIR/.config.json" ]; then
        has_config=true
        check_mark ".config.json"
    fi

    # Check for SSL certificate
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        has_ssl=true
        ssl_expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" 2>/dev/null | cut -d= -f2 || echo "unknown")
        check_mark "SSL certificate (expires: $ssl_expiry)"
    fi

    # Check for Apache vhost
    if [ -f "/etc/apache2/sites-available/${DOMAIN}.conf" ] || [ -f "/etc/apache2/sites-available/webshare.conf" ]; then
        has_vhost=true
        check_mark "Apache virtual host"
    fi

    # Check for user data
    if [ -d "$INSTALL_DIR/files" ] && [ "$(ls -A $INSTALL_DIR/files 2>/dev/null)" ]; then
        local file_count=$(find "$INSTALL_DIR/files" -type f | wc -l)
        check_mark "files/ directory - $file_count file(s)"
    fi

    if [ -d "$INSTALL_DIR/texts" ] && [ "$(ls -A $INSTALL_DIR/texts 2>/dev/null)" ]; then
        local text_count=$(find "$INSTALL_DIR/texts" -type f | wc -l)
        check_mark "texts/ directory - $text_count text(s)"
    fi

    echo ""

    if [ "$has_existing" = true ]; then
        return 0
    else
        return 1
    fi
}

# Show reinstall options
show_reinstall_menu() {
    echo -e "${YELLOW}[!] Existing installation detected!${NC}"
    echo ""
    echo "What would you like to do?"
    echo ""
    echo -e "  ${GREEN}1)${NC} Update software only (recommended)"
    echo "     - Preserves users, files, texts, and configuration"
    echo ""
    echo -e "  ${YELLOW}2)${NC} Fresh install (preserve data)"
    echo "     - Reinstalls software"
    echo "     - Preserves files/, texts/, .htpasswd"
    echo ""
    echo -e "  ${RED}3)${NC} Complete reinstall"
    echo "     - Deletes everything and starts fresh"
    echo "     - WARNING: All data will be lost!"
    echo ""
    echo -e "  ${BLUE}4)${NC} Cancel"
    echo ""
    read -p "Enter choice [1-4]: " choice

    case $choice in
        1)
            echo ""
            info "Running software update..."
            run_update
            exit 0
            ;;
        2)
            echo ""
            info "Fresh install (preserving data)..."
            PRESERVE_DATA=true
            ;;
        3)
            echo ""
            echo -e "${RED}WARNING: This will delete ALL data in $INSTALL_DIR${NC}"
            read -p "Type 'DELETE' to confirm: " confirm
            if [ "$confirm" != "DELETE" ]; then
                echo "Cancelled."
                exit 0
            fi
            info "Complete reinstall..."
            PRESERVE_DATA=false
            rm -rf "$INSTALL_DIR"
            ;;
        4)
            echo "Cancelled."
            exit 0
            ;;
        *)
            error "Invalid choice"
            ;;
    esac
}

# Run update instead of reinstall
run_update() {
    if [ -f "$INSTALL_DIR/installer/update.sh" ]; then
        bash "$INSTALL_DIR/installer/update.sh"
    elif [ -x "$INSTALL_DIR/update.sh" ]; then
        cd "$INSTALL_DIR"
        ./update.sh
    elif [ -f "$SCRIPT_DIR/update.sh" ]; then
        export INSTALL_DIR
        bash "$SCRIPT_DIR/update.sh"
    else
        error "Update script not found. Please run full installation."
    fi
}

# ============================================
# Check components
# ============================================
check_components() {
    echo -e "${BLUE}Checking system components...${NC}"
    echo ""

    local needs_install=false

    # Apache2
    if command -v apache2 &> /dev/null; then
        check_mark "Apache2 - installed"
    else
        cross_mark "Apache2" "- will be installed"
        needs_install=true
    fi

    # PHP
    if command -v php &> /dev/null; then
        local php_ver=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
        check_mark "PHP $php_ver - installed"
    else
        cross_mark "PHP" "- will be installed"
        needs_install=true
    fi

    # php-maxminddb
    if php -m 2>/dev/null | grep -q maxminddb; then
        check_mark "php-maxminddb - installed"
    else
        cross_mark "php-maxminddb" "- will be installed"
        needs_install=true
    fi

    # php-xml
    if php -m 2>/dev/null | grep -q "^xml$"; then
        check_mark "php-xml - installed"
    else
        cross_mark "php-xml" "- will be installed"
        needs_install=true
    fi

    # php-curl
    if php -m 2>/dev/null | grep -q "^curl$"; then
        check_mark "php-curl - installed"
    else
        cross_mark "php-curl" "- will be installed"
        needs_install=true
    fi

    # Certbot
    if command -v certbot &> /dev/null; then
        check_mark "Certbot - installed"
    else
        cross_mark "Certbot" "- will be installed"
        needs_install=true
    fi

    # GeoIP database
    if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ] || [ -f "$INSTALL_DIR/GeoLite2-Country.mmdb" ]; then
        check_mark "GeoIP database - available"
    else
        cross_mark "GeoIP database" "- will be downloaded"
    fi

    echo ""
    return 0
}

# ============================================
# Main installation flow
# ============================================

# Check for existing installation (unless --force)
PRESERVE_DATA=false
if [ "$FORCE" = false ] && [ -d "$INSTALL_DIR" ]; then
    if check_existing_installation; then
        show_reinstall_menu
    fi
fi

# Show component status
check_components

# Generate password if not provided
if [ -z "$AUTH_PASS" ]; then
    AUTH_PASS=$(openssl rand -base64 12)
fi

info "Domain: $DOMAIN"
info "Install dir: $INSTALL_DIR"
info "Source dir: $SRC_DIR"
info "Admin user: $AUTH_USER"
info "Update source: $SOURCE"
echo ""

# ============================================
# 1. Install dependencies
# ============================================
info "Installing dependencies..."

apt-get update -qq

# Apache2
if ! command -v apache2 &> /dev/null; then
    apt-get install -y apache2
fi
success "Apache2 OK"

# PHP
if ! command -v php &> /dev/null; then
    apt-get install -y php php-common php-cli php-fpm php-json php-mbstring libapache2-mod-php
fi
PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
success "PHP $PHP_VERSION OK"

# PHP modules
apt-get install -y php-json php-mbstring php-xml php-dom php-curl libapache2-mod-php 2>/dev/null || true

# MaxMindDB for GeoIP
if ! php -m | grep -q maxminddb; then
    apt-get install -y php${PHP_VERSION}-maxminddb 2>/dev/null || \
    apt-get install -y php-maxminddb 2>/dev/null || \
    warn "php-maxminddb not available. GeoIP will not work."
fi
success "PHP modules OK"

# Certbot
if ! command -v certbot &> /dev/null; then
    apt-get install -y certbot python3-certbot-apache
fi
success "Certbot OK"

# Apache modules
a2enmod rewrite ssl headers 2>/dev/null || true
success "Apache modules OK"

# ============================================
# 2. GeoIP database
# ============================================
info "Setting up GeoIP..."

mkdir -p "$GEOIP_DIR"

if [ ! -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ]; then
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

    if command -v wget &> /dev/null; then
        wget -q -O "$GEOIP_DIR/GeoLite2-Country.mmdb" "$GEOIP_URL" 2>/dev/null || true
    elif command -v curl &> /dev/null; then
        curl -sL -o "$GEOIP_DIR/GeoLite2-Country.mmdb" "$GEOIP_URL" 2>/dev/null || true
    fi

    if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ] && [ -s "$GEOIP_DIR/GeoLite2-Country.mmdb" ]; then
        success "GeoIP database downloaded"
    else
        warn "GeoIP database download failed. GeoIP will not work."
    fi
else
    success "GeoIP database exists"
fi

# ============================================
# 3. Create directory structure
# ============================================
info "Creating directories..."

# Root directory
mkdir -p "$INSTALL_DIR"

# Data directories (in root)
if [ "$PRESERVE_DATA" = false ]; then
    mkdir -p "$INSTALL_DIR/files"
    mkdir -p "$INSTALL_DIR/texts"
fi
mkdir -p "$INSTALL_DIR/backups"
mkdir -p "$INSTALL_DIR/installer"

# Source directory
mkdir -p "$SRC_DIR"
mkdir -p "$SRC_DIR/assets/quill"
mkdir -p "$SRC_DIR/docs"

success "Directories created"

# ============================================
# 4. Download source files to src/
# ============================================
info "Installing source files..."

# Determine source URL
if [ "$SOURCE" = "github" ]; then
    SOURCE_URL="https://raw.githubusercontent.com/toshko37/webshare/main/src"
    INSTALLER_URL="https://raw.githubusercontent.com/toshko37/webshare/main/installer"
else
    SOURCE_URL="https://webshare.techbg.net/src"
    INSTALLER_URL="https://webshare.techbg.net/installer"
fi

# List of files to download
PHP_FILES=(
    "index.php" "upload.php" "public.php" "download.php"
    "t.php" "text.php" "share.php" "folder-management.php"
    "encryption.php" "audit-log.php" "geo-check.php"
    "user-management.php" "html-sanitizer.php" "smtp-mailer.php"
    "send-mail.php" "web-download.php" "api-upload.php"
    "api-scripts.php" "check-version.php" "do-update.php"
    "live-update.php" "p.php" "u.php" "f.php" "get.php"
    "get-speedtest.php" "get-update.php" "get-update-script.php"
    "security-headers.php"
)

OTHER_FILES=(
    "favicon.ico" "favicon.svg" "apple-touch-icon.png"
    "CHANGELOG.md" "version.json"
)

# Download PHP files to src/
for file in "${PHP_FILES[@]}"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$SRC_DIR/$file" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
    fi
done

# Download other files to src/
for file in "${OTHER_FILES[@]}"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$SRC_DIR/$file" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
    fi
done

# Download .htaccess to src/
echo -n "  .htaccess... "
if curl -fsSL "$SOURCE_URL/.htaccess" -o "$SRC_DIR/.htaccess" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
fi

# Download .user.ini to src/
echo -n "  .user.ini... "
if curl -fsSL "$SOURCE_URL/.user.ini" -o "$SRC_DIR/.user.ini" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    # Create default .user.ini
    cat > "$SRC_DIR/.user.ini" << 'PHPINI'
; WebShare PHP Settings
upload_max_filesize = 10G
post_max_size = 10G
max_execution_time = 7200
max_input_time = 7200
memory_limit = 512M
PHPINI
    echo -e "${YELLOW}created default${NC}"
fi

# Download Quill.js assets
echo -n "  Quill.js editor... "
if curl -fsSL "$SOURCE_URL/assets/quill/quill.js" -o "$SRC_DIR/assets/quill/quill.js" 2>/dev/null && \
   curl -fsSL "$SOURCE_URL/assets/quill/quill.snow.css" -o "$SRC_DIR/assets/quill/quill.snow.css" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
fi

# Download installer scripts
echo -n "  installer/update.sh... "
if curl -fsSL "$INSTALLER_URL/update.sh" -o "$INSTALL_DIR/installer/update.sh" 2>/dev/null; then
    chmod +x "$INSTALL_DIR/installer/update.sh"
    echo -e "${GREEN}OK${NC}"
else
    # Copy from local if available
    [ -f "$SCRIPT_DIR/update.sh" ] && cp "$SCRIPT_DIR/update.sh" "$INSTALL_DIR/installer/" && chmod +x "$INSTALL_DIR/installer/update.sh"
    echo -e "${YELLOW}local copy${NC}"
fi

echo -n "  installer/install.sh... "
cp "$0" "$INSTALL_DIR/installer/install.sh" 2>/dev/null || true
chmod +x "$INSTALL_DIR/installer/install.sh" 2>/dev/null || true
echo -e "${GREEN}OK${NC}"

success "Source files installed"

# ============================================
# 5. Create symlinks in src/ for data access
# ============================================
info "Creating symlinks..."

cd "$SRC_DIR"

# Directories
[ ! -L "files" ] && [ ! -e "files" ] && ln -sf ../files files
[ ! -L "texts" ] && [ ! -e "texts" ] && ln -sf ../texts texts
[ ! -L "backups" ] && [ ! -e "backups" ] && ln -sf ../backups backups

# Data files
[ ! -L ".htpasswd" ] && [ ! -e ".htpasswd" ] && ln -sf ../.htpasswd .htpasswd
[ ! -L ".config.json" ] && [ ! -e ".config.json" ] && ln -sf ../.config.json .config.json
[ ! -L ".geo.json" ] && [ ! -e ".geo.json" ] && ln -sf ../.geo.json .geo.json
[ ! -L ".audit.json" ] && [ ! -e ".audit.json" ] && ln -sf ../.audit.json .audit.json
[ ! -L ".tokens.json" ] && [ ! -e ".tokens.json" ] && ln -sf ../.tokens.json .tokens.json
[ ! -L ".texts.json" ] && [ ! -e ".texts.json" ] && ln -sf ../.texts.json .texts.json
[ ! -L ".files-meta.json" ] && [ ! -e ".files-meta.json" ] && ln -sf ../.files-meta.json .files-meta.json
[ ! -L ".folder-shares.json" ] && [ ! -e ".folder-shares.json" ] && ln -sf ../.folder-shares.json .folder-shares.json
[ ! -L ".api-keys.json" ] && [ ! -e ".api-keys.json" ] && ln -sf ../.api-keys.json .api-keys.json
[ ! -L ".encryption-keys.json" ] && [ ! -e ".encryption-keys.json" ] && ln -sf ../.encryption-keys.json .encryption-keys.json
[ ! -L ".mail-ratelimit.json" ] && [ ! -e ".mail-ratelimit.json" ] && ln -sf ../.mail-ratelimit.json .mail-ratelimit.json
[ ! -L ".update-config.json" ] && [ ! -e ".update-config.json" ] && ln -sf ../.update-config.json .update-config.json
[ ! -L ".version-check.json" ] && [ ! -e ".version-check.json" ] && ln -sf ../.version-check.json .version-check.json
[ ! -L "GeoLite2-Country.mmdb" ] && [ ! -e "GeoLite2-Country.mmdb" ] && ln -sf ../GeoLite2-Country.mmdb GeoLite2-Country.mmdb

cd "$INSTALL_DIR"

success "Symlinks created"

# ============================================
# 6. Configuration files (in root)
# ============================================
info "Creating configuration files..."

# GeoIP configuration
if [ ! -f "$INSTALL_DIR/.geo.json" ]; then
    cat > "$INSTALL_DIR/.geo.json" << 'GEOJSON'
{
    "enabled": true,
    "allowed_countries": ["BG"],
    "blocked_message": "Access denied from your location",
    "geoip_database": "/usr/share/GeoIP/GeoLite2-Country.mmdb"
}
GEOJSON
fi

# Update config (determines update source)
cat > "$INSTALL_DIR/.update-config.json" << UPDATECONF
{
    "stable": $([ "$SOURCE" = "github" ] && echo "true" || echo "false")
}
UPDATECONF

# Create other config files if they don't exist
[ -f "$INSTALL_DIR/.files-meta.json" ] || echo "{}" > "$INSTALL_DIR/.files-meta.json"
[ -f "$INSTALL_DIR/.texts.json" ] || echo "{}" > "$INSTALL_DIR/.texts.json"
[ -f "$INSTALL_DIR/.tokens.json" ] || echo "{}" > "$INSTALL_DIR/.tokens.json"
[ -f "$INSTALL_DIR/.audit.json" ] || echo "[]" > "$INSTALL_DIR/.audit.json"
[ -f "$INSTALL_DIR/.api-keys.json" ] || echo "[]" > "$INSTALL_DIR/.api-keys.json"
[ -f "$INSTALL_DIR/.config.json" ] || echo '{"mail_enabled":false}' > "$INSTALL_DIR/.config.json"
[ -f "$INSTALL_DIR/.mail-ratelimit.json" ] || echo "{}" > "$INSTALL_DIR/.mail-ratelimit.json"
[ -f "$INSTALL_DIR/.folder-shares.json" ] || echo "{}" > "$INSTALL_DIR/.folder-shares.json"
[ -f "$INSTALL_DIR/.encryption-keys.json" ] || echo "{}" > "$INSTALL_DIR/.encryption-keys.json"

success "Configuration created"

# ============================================
# 7. Update .htaccess with correct path
# ============================================
info "Configuring .htaccess..."

if [ -f "$SRC_DIR/.htaccess" ]; then
    sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $INSTALL_DIR/.htpasswd|g" "$SRC_DIR/.htaccess"
fi

success ".htaccess configured"

# ============================================
# 8. Files directory protection
# ============================================
info "Protecting files directory..."

cat > "$INSTALL_DIR/files/.htaccess" << 'FILESHT'
# Protect uploaded files from direct access
Require all denied

<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
FILESHT

cat > "$INSTALL_DIR/texts/.htaccess" << 'TEXTSHT'
# Protect text files from direct access
Require all denied
TEXTSHT

success "Directories protected"

# ============================================
# 9. Create/Update .htpasswd
# ============================================
if [ "$PRESERVE_DATA" = false ] || [ ! -f "$INSTALL_DIR/.htpasswd" ]; then
    info "Creating .htpasswd..."
    htpasswd -cb "$INSTALL_DIR/.htpasswd" "$AUTH_USER" "$AUTH_PASS"
    success ".htpasswd created"
else
    info "Preserving existing .htpasswd"
    success ".htpasswd preserved"
fi

# ============================================
# 10. Copy GeoIP database locally
# ============================================
if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ] && [ ! -f "$INSTALL_DIR/GeoLite2-Country.mmdb" ]; then
    cp "$GEOIP_DIR/GeoLite2-Country.mmdb" "$INSTALL_DIR/GeoLite2-Country.mmdb"
    success "GeoIP database copied to installation"
fi

# ============================================
# 11. Permissions
# ============================================
info "Setting permissions..."

# Root directory
chown www-data:www-data "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"

# Data directories
chown -R www-data:www-data "$INSTALL_DIR/files"
chown -R www-data:www-data "$INSTALL_DIR/texts"
chown -R www-data:www-data "$INSTALL_DIR/backups"
chmod 750 "$INSTALL_DIR/files"
chmod 750 "$INSTALL_DIR/texts"
chmod 755 "$INSTALL_DIR/backups"

# Config files in root
chmod 600 "$INSTALL_DIR/.htpasswd" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/.api-keys.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/.tokens.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/.encryption-keys.json" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/.geo.json" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/.config.json" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/.files-meta.json" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/.texts.json" 2>/dev/null || true
chmod 644 "$INSTALL_DIR/.audit.json" 2>/dev/null || true
chown www-data:www-data "$INSTALL_DIR"/.*json 2>/dev/null || true
chown www-data:www-data "$INSTALL_DIR/.htpasswd" 2>/dev/null || true

# Source directory
chown -R www-data:www-data "$SRC_DIR"
chmod 755 "$SRC_DIR"
chmod 644 "$SRC_DIR"/*.php 2>/dev/null || true
chmod 644 "$SRC_DIR/.htaccess" 2>/dev/null || true
chmod 644 "$SRC_DIR/.user.ini" 2>/dev/null || true

# Installer scripts
chmod +x "$INSTALL_DIR/installer"/*.sh 2>/dev/null || true

success "Permissions set"

# ============================================
# 12. Apache Virtual Host (with src/ as DocumentRoot)
# ============================================
info "Creating Apache Virtual Host..."

cat > "/etc/apache2/sites-available/${DOMAIN}.conf" << VHOST
# WebShare - ${DOMAIN}
# Generated by WebShare Installer v3.1

# HTTP to HTTPS redirect
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}

    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)\$ https://%{HTTP_HOST}\$1 [R=301,L]

    ErrorLog \${APACHE_LOG_DIR}/error-${DOMAIN}.log
    CustomLog \${APACHE_LOG_DIR}/access-${DOMAIN}.log combined
</VirtualHost>

# HTTPS VirtualHost
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        ServerAdmin webmaster@${DOMAIN}
        ServerName ${DOMAIN}
        ServerAlias www.${DOMAIN}

        # Source files are in src/ subdirectory
        DocumentRoot ${SRC_DIR}

        <Directory ${SRC_DIR}/>
            Options -Indexes +FollowSymLinks
            AllowOverride All
            Require all granted
        </Directory>

        # Backward compatibility: old update URLs
        Alias /installer/src ${SRC_DIR}
        <Directory ${SRC_DIR}>
            Options -Indexes +FollowSymLinks
            AllowOverride All
            Require all granted
        </Directory>

        SSLEngine on

        ErrorLog \${APACHE_LOG_DIR}/error-${DOMAIN}-ssl.log
        CustomLog \${APACHE_LOG_DIR}/access-${DOMAIN}-ssl.log combined

        <IfModule mod_headers.c>
            Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
            Header always set X-Frame-Options "SAMEORIGIN"
            Header always set X-Content-Type-Options "nosniff"
            Header always set X-XSS-Protection "1; mode=block"
        </IfModule>
    </VirtualHost>
</IfModule>
VHOST

a2ensite "${DOMAIN}.conf" 2>/dev/null || true

success "Virtual Host created"

# ============================================
# 13. SSL Certificate
# ============================================
info "Setting up SSL certificate..."

systemctl reload apache2 2>/dev/null || true

if host "$DOMAIN" &>/dev/null; then
    certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>/dev/null || {
        warn "SSL certificate could not be generated automatically."
        warn "Run manually: certbot --apache -d $DOMAIN"
    }
else
    warn "Domain $DOMAIN not found in DNS."
    warn "Configure DNS and run: certbot --apache -d $DOMAIN"
fi

success "SSL configured"

# ============================================
# 14. SSL auto-renewal cron
# ============================================
info "Setting up SSL auto-renewal..."

CRON_JOB="0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    success "Cron job added (daily at 03:00)"
else
    success "Cron job already exists"
fi

# ============================================
# 15. Final restart
# ============================================
info "Restarting Apache..."

systemctl restart apache2

success "Apache restarted"

# ============================================
# Done!
# ============================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             Installation Complete!                         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "URLs:"
echo -e "  Dashboard:      ${CYAN}https://${DOMAIN}/${NC}"
echo -e "  Public Upload:  ${CYAN}https://${DOMAIN}/u${NC}"
echo -e "  Public Text:    ${CYAN}https://${DOMAIN}/t${NC}"
echo ""
if [ "$PRESERVE_DATA" = false ]; then
    echo "Login credentials:"
    echo -e "  Username: ${GREEN}$AUTH_USER${NC}"
    echo -e "  Password: ${GREEN}$AUTH_PASS${NC}"
    echo ""
fi
echo "Directory structure:"
echo "  Root:    ${INSTALL_DIR}/"
echo "  Source:  ${INSTALL_DIR}/src/"
echo "  Files:   ${INSTALL_DIR}/files/"
echo "  Texts:   ${INSTALL_DIR}/texts/"
echo ""
echo -e "Update source: ${BLUE}$SOURCE${NC}"
echo "To update: ${INSTALL_DIR}/installer/update.sh"
echo "To change source: ${INSTALL_DIR}/.update-config.json"
echo ""

# Save credentials if new installation
if [ "$PRESERVE_DATA" = false ]; then
    cat > "$INSTALL_DIR/CREDENTIALS.txt" << CREDS
WebShare Credentials
====================
Domain: https://${DOMAIN}/
Username: ${AUTH_USER}
Password: ${AUTH_PASS}

Public URLs:
  Upload: https://${DOMAIN}/u
  Text: https://${DOMAIN}/t

Directory Structure:
  Root:   ${INSTALL_DIR}/
  Source: ${INSTALL_DIR}/src/
  Files:  ${INSTALL_DIR}/files/
  Texts:  ${INSTALL_DIR}/texts/

Installed: $(date)
Version: 3.5.0
Update Source: $SOURCE

To update: ./installer/update.sh
CREDS

    chmod 600 "$INSTALL_DIR/CREDENTIALS.txt"
    chown www-data:www-data "$INSTALL_DIR/CREDENTIALS.txt"
    info "Credentials saved to: ${INSTALL_DIR}/CREDENTIALS.txt"
fi
