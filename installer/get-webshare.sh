#!/bin/bash
#
# WebShare Quick Installer v3.3
# =============================
# One-line installer for WebShare
#
# Usage (from GitHub - stable):
#   curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash -s -- domain.com
#   curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash -s -- domain.com admin mypass
#
# Usage (from dev server):
#   curl -fsSL https://webshare.techbg.net/get | sudo bash -s -- --source dev domain.com
#
# Custom installation path:
#   curl -fsSL ... | sudo bash -s -- --path /var/www/mywebshare domain.com admin mypass
#
# Options:
#   --source github|dev   Update source (default: github)
#   --path /path/to/dir   Installation directory (default: /var/www/webshare)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
echo '╦ ╦┌─┐┌┐ ╔═╗┬ ┬┌─┐┬─┐┌─┐'
echo '║║║├┤ ├┴┐╚═╗├─┤├─┤├┬┘├┤ '
echo '╚╩╝└─┘└─┘╚═╝┴ ┴┴ ┴┴└─└─┘'
echo -e "${NC}"
echo -e "${BLUE}Quick Installer v3.3${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    echo ""
    echo "Usage:"
    echo "  curl -fsSL https://raw.githubusercontent.com/toshko37/webshare/main/installer/get-webshare.sh | sudo bash"
    exit 1
fi

# Check OS
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}Error: This installer requires Debian/Ubuntu${NC}"
    exit 1
fi

# Default values
SOURCE="github"
DOMAIN=""
ADMIN_USER="admin"
ADMIN_PASS=""
INSTALL_PATH=""
ARG_INDEX=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            SOURCE="$2"
            shift 2
            ;;
        --path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            ARG_INDEX=$((ARG_INDEX + 1))
            case $ARG_INDEX in
                1) DOMAIN="$1" ;;
                2) ADMIN_USER="$1" ;;
                3) ADMIN_PASS="$1" ;;
            esac
            shift
            ;;
    esac
done

# Validate source
if [ "$SOURCE" != "github" ] && [ "$SOURCE" != "dev" ]; then
    echo -e "${RED}Error: Invalid source '$SOURCE'. Use 'github' or 'dev'${NC}"
    exit 1
fi

# Interactive prompts if needed
if [ -z "$DOMAIN" ]; then
    echo -e "${YELLOW}Enter your domain name:${NC}"
    read -p "> " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Error: Domain is required${NC}"
        exit 1
    fi
fi

if [ -z "$ADMIN_PASS" ]; then
    echo -e "${YELLOW}Enter admin password (user: ${ADMIN_USER}):${NC}"
    read -s -p "> " ADMIN_PASS
    echo ""
    if [ -z "$ADMIN_PASS" ]; then
        echo -e "${RED}Error: Password is required${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}Configuration:${NC}"
echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
echo -e "  Admin:  ${GREEN}${ADMIN_USER}${NC}"
echo -e "  Source: ${GREEN}${SOURCE}${NC}"
echo ""

# Set source URL
if [ "$SOURCE" = "github" ]; then
    SOURCE_URL="https://raw.githubusercontent.com/toshko37/webshare/main/src"
    INSTALLER_URL="https://raw.githubusercontent.com/toshko37/webshare/main/installer"
else
    SOURCE_URL="https://webshare.techbg.net"
    INSTALLER_URL="https://webshare.techbg.net/installer"
fi

# Set installation path (default: /var/www/webshare)
WEBROOT="${INSTALL_PATH:-/var/www/webshare}"
SRC_DIR="$WEBROOT/src"

echo -e "  Path:   ${GREEN}${WEBROOT}${NC}"
echo ""

# ============================================
# Check for existing Apache vhost with different path
# ============================================
EXISTING_VHOST=$(grep -rl "ServerName.*${DOMAIN}" /etc/apache2/sites-available/ 2>/dev/null | head -1)
if [ -n "$EXISTING_VHOST" ]; then
    EXISTING_DOCROOT=$(grep -oP 'DocumentRoot\s+\K[^\s]+' "$EXISTING_VHOST" 2>/dev/null | head -1)
    if [ -n "$EXISTING_DOCROOT" ] && [ "$EXISTING_DOCROOT" != "$SRC_DIR" ]; then
        echo -e "${YELLOW}Warning: Existing vhost found for ${DOMAIN}${NC}"
        echo -e "  Current DocumentRoot: ${EXISTING_DOCROOT}"
        echo -e "  New DocumentRoot:     ${SRC_DIR}"
        echo ""
        echo -e "${YELLOW}The vhost will be updated to the new path.${NC}"
        echo ""
    fi
fi

# ============================================
# 1. Install dependencies
# ============================================
echo -e "${BLUE}[1/8]${NC} Installing dependencies..."
apt-get update -qq
apt-get install -y -qq apache2 php php-cli php-json php-mbstring php-xml php-curl libapache2-mod-php certbot python3-certbot-apache > /dev/null

# Install php-maxminddb if available
if apt-cache show php-maxminddb &> /dev/null; then
    apt-get install -y -qq php-maxminddb > /dev/null 2>&1 || true
fi

echo -e "${GREEN}Dependencies installed${NC}"

# ============================================
# 2. Configure Apache
# ============================================
echo -e "${BLUE}[2/8]${NC} Configuring Apache..."
a2enmod rewrite ssl headers > /dev/null 2>&1

echo -e "${GREEN}Apache configured${NC}"

# ============================================
# 3. Create directory structure
# ============================================
echo -e "${BLUE}[3/8]${NC} Creating directories..."

# Root directories (data)
mkdir -p "$WEBROOT/files" "$WEBROOT/texts" "$WEBROOT/backups" "$WEBROOT/installer"

# Source directory
mkdir -p "$SRC_DIR/assets/quill" "$SRC_DIR/docs"

echo -e "${GREEN}Directories created${NC}"

# ============================================
# 4. Download source files to src/
# ============================================
echo -e "${BLUE}[4/8]${NC} Downloading WebShare files..."

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
    curl -fsSL "$SOURCE_URL/$file" -o "$SRC_DIR/$file" 2>/dev/null || true
done

# Download other files to src/
for file in "${OTHER_FILES[@]}"; do
    curl -fsSL "$SOURCE_URL/$file" -o "$SRC_DIR/$file" 2>/dev/null || true
done

# Download .htaccess to src/ (GitHub: .htaccess, Dev: htaccess.txt)
if [ "$SOURCE" = "github" ]; then
    curl -fsSL "$SOURCE_URL/.htaccess" -o "$SRC_DIR/.htaccess" 2>/dev/null || true
else
    curl -fsSL "$SOURCE_URL/htaccess.txt" -o "$SRC_DIR/.htaccess" 2>/dev/null || true
fi

# Download .user.ini to src/ (GitHub: .user.ini, Dev: user.ini.txt)
if [ "$SOURCE" = "github" ]; then
    curl -fsSL "$SOURCE_URL/.user.ini" -o "$SRC_DIR/.user.ini" 2>/dev/null
else
    curl -fsSL "$SOURCE_URL/user.ini.txt" -o "$SRC_DIR/.user.ini" 2>/dev/null
fi || {
    cat > "$SRC_DIR/.user.ini" << 'PHPINI'
; WebShare PHP Settings
upload_max_filesize = 10G
post_max_size = 10G
max_execution_time = 7200
max_input_time = 7200
memory_limit = 512M
PHPINI
}

# Download Quill.js assets
curl -fsSL "$SOURCE_URL/assets/quill/quill.js" -o "$SRC_DIR/assets/quill/quill.js" 2>/dev/null || true
curl -fsSL "$SOURCE_URL/assets/quill/quill.snow.css" -o "$SRC_DIR/assets/quill/quill.snow.css" 2>/dev/null || true

# Download installer scripts
curl -fsSL "$INSTALLER_URL/update.sh" -o "$WEBROOT/installer/update.sh" 2>/dev/null || true
curl -fsSL "$INSTALLER_URL/install.sh" -o "$WEBROOT/installer/install.sh" 2>/dev/null || true
chmod +x "$WEBROOT/installer"/*.sh 2>/dev/null || true

# Fix .htaccess path (handle both GitHub version and dev version with placeholder)
sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $WEBROOT/.htpasswd|g" "$SRC_DIR/.htaccess" 2>/dev/null || true
sed -i "s|__HTPASSWD_PATH__|$WEBROOT/.htpasswd|g" "$SRC_DIR/.htaccess" 2>/dev/null || true

echo -e "${GREEN}Files downloaded${NC}"

# ============================================
# 5. Create symlinks in src/ for data access
# ============================================
echo -e "${BLUE}[5/8]${NC} Creating symlinks and configuration..."

cd "$SRC_DIR"

# Symlinks to data directories
ln -sf ../files files 2>/dev/null || true
ln -sf ../texts texts 2>/dev/null || true
ln -sf ../backups backups 2>/dev/null || true

# Symlinks to config files
ln -sf ../.htpasswd .htpasswd 2>/dev/null || true
ln -sf ../.config.json .config.json 2>/dev/null || true
ln -sf ../.geo.json .geo.json 2>/dev/null || true
ln -sf ../.audit.json .audit.json 2>/dev/null || true
ln -sf ../.tokens.json .tokens.json 2>/dev/null || true
ln -sf ../.texts.json .texts.json 2>/dev/null || true
ln -sf ../.files-meta.json .files-meta.json 2>/dev/null || true
ln -sf ../.folder-shares.json .folder-shares.json 2>/dev/null || true
ln -sf ../.api-keys.json .api-keys.json 2>/dev/null || true
ln -sf ../.encryption-keys.json .encryption-keys.json 2>/dev/null || true
ln -sf ../.mail-ratelimit.json .mail-ratelimit.json 2>/dev/null || true
ln -sf ../.update-config.json .update-config.json 2>/dev/null || true
ln -sf ../.version-check.json .version-check.json 2>/dev/null || true
ln -sf ../GeoLite2-Country.mmdb GeoLite2-Country.mmdb 2>/dev/null || true

cd "$WEBROOT"

# Security .htaccess for files/
cat > "$WEBROOT/files/.htaccess" << 'HTEOF'
# Protect uploaded files from direct access
Require all denied

<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
HTEOF

# Security .htaccess for texts/
cat > "$WEBROOT/texts/.htaccess" << 'HTEOF'
# Protect text files from direct access
Require all denied
HTEOF

# Security .htaccess for backups/
cat > "$WEBROOT/backups/.htaccess" << 'HTEOF'
# Protect backup files from direct access
Require all denied
HTEOF

# .htpasswd - only create if doesn't exist
if [ ! -f "$WEBROOT/.htpasswd" ]; then
    htpasswd -cb "$WEBROOT/.htpasswd" "$ADMIN_USER" "$ADMIN_PASS" > /dev/null 2>&1
    echo -e "  ${GREEN}Created new .htpasswd${NC}"
else
    echo -e "  ${YELLOW}Preserved existing .htpasswd${NC}"
fi

# Config files in root - only create if don't exist
[ -f "$WEBROOT/.geo.json" ] || echo '{"enabled":false,"allowed_countries":["BG"],"blocked_countries":[]}' > "$WEBROOT/.geo.json"
[ -f "$WEBROOT/.config.json" ] || echo '{"mail_enabled":false}' > "$WEBROOT/.config.json"
[ -f "$WEBROOT/.files-meta.json" ] || echo '{}' > "$WEBROOT/.files-meta.json"
[ -f "$WEBROOT/.texts.json" ] || echo '{}' > "$WEBROOT/.texts.json"
[ -f "$WEBROOT/.tokens.json" ] || echo '{}' > "$WEBROOT/.tokens.json"
[ -f "$WEBROOT/.audit.json" ] || echo '[]' > "$WEBROOT/.audit.json"
[ -f "$WEBROOT/.api-keys.json" ] || echo '[]' > "$WEBROOT/.api-keys.json"
[ -f "$WEBROOT/.mail-ratelimit.json" ] || echo '{}' > "$WEBROOT/.mail-ratelimit.json"
[ -f "$WEBROOT/.folder-shares.json" ] || echo '{}' > "$WEBROOT/.folder-shares.json"
[ -f "$WEBROOT/.encryption-keys.json" ] || echo '{}' > "$WEBROOT/.encryption-keys.json"

# Update source config - always update this one
cat > "$WEBROOT/.update-config.json" << UPDATECONF
{
    "stable": $([ "$SOURCE" = "github" ] && echo "true" || echo "false")
}
UPDATECONF

echo -e "${GREEN}Symlinks and configuration created${NC}"

# ============================================
# 6. Set permissions
# ============================================
echo -e "${BLUE}[6/8]${NC} Setting permissions..."

chown -R www-data:www-data "$WEBROOT"
chmod 600 "$WEBROOT/.htpasswd" "$WEBROOT/.api-keys.json" "$WEBROOT/.tokens.json" "$WEBROOT/.encryption-keys.json"
chmod 644 "$WEBROOT/.geo.json" "$WEBROOT/.config.json" "$WEBROOT/.files-meta.json" "$WEBROOT/.texts.json" "$WEBROOT/.audit.json" "$WEBROOT/.mail-ratelimit.json"
chmod 750 "$WEBROOT/files" "$WEBROOT/texts"
chmod 755 "$SRC_DIR"
chmod 644 "$SRC_DIR"/*.php 2>/dev/null || true

echo -e "${GREEN}Permissions set${NC}"

# ============================================
# 7. Configure virtual host
# ============================================
echo -e "${BLUE}[7/8]${NC} Configuring virtual host..."

cat > "/etc/apache2/sites-available/webshare.conf" << VHEOF
# WebShare - ${DOMAIN}
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${SRC_DIR}

    <Directory ${SRC_DIR}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Backward compatibility for old update URLs
    Alias /installer/src ${SRC_DIR}

    ErrorLog \${APACHE_LOG_DIR}/webshare_error.log
    CustomLog \${APACHE_LOG_DIR}/webshare_access.log combined
</VirtualHost>
VHEOF

a2ensite webshare.conf > /dev/null 2>&1
a2dissite 000-default.conf > /dev/null 2>&1 || true
systemctl reload apache2

echo -e "${GREEN}Virtual host configured${NC}"

# ============================================
# 8. SSL and GeoIP
# ============================================
echo -e "${BLUE}[8/8]${NC} Setting up SSL and GeoIP..."

# SSL
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>/dev/null || {
    echo -e "${YELLOW}Note: SSL setup requires DNS to point to this server${NC}"
    echo -e "${YELLOW}Run manually: certbot --apache -d ${DOMAIN}${NC}"
}

# SSL auto-renewal cron
CRON_JOB="0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
fi

# GeoIP database
GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
if curl -fsSL "$GEOIP_URL" -o "$WEBROOT/GeoLite2-Country.mmdb" 2>/dev/null; then
    chown www-data:www-data "$WEBROOT/GeoLite2-Country.mmdb"
    echo -e "${GREEN}GeoIP database installed${NC}"
else
    echo -e "${YELLOW}Note: GeoIP download failed. Geo-blocking disabled.${NC}"
fi

# ============================================
# Done!
# ============================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             WebShare installed successfully!               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}     https://${DOMAIN}"
echo -e "  ${CYAN}Public Upload:${NC} https://${DOMAIN}/u"
echo -e "  ${CYAN}Text Share:${NC}    https://${DOMAIN}/t"
echo ""
echo -e "  ${CYAN}Admin User:${NC}    ${ADMIN_USER}"
echo -e "  ${CYAN}Update Source:${NC} ${SOURCE}"
echo ""
echo -e "Directory structure:"
echo -e "  Root:   ${WEBROOT}/"
echo -e "  Source: ${WEBROOT}/src/"
echo -e "  Files:  ${WEBROOT}/files/"
echo ""
echo -e "To update: ${YELLOW}${WEBROOT}/installer/update.sh${NC}"
echo ""
