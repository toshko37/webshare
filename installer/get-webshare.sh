#!/bin/bash
#
# WebShare Quick Installer v3.0
# =============================
# One-line installer for WebShare
#
# Usage:
#   curl -fsSL https://webshare.techbg.net/get | bash
#   curl -fsSL https://webshare.techbg.net/get | bash -s -- domain.com [user] [pass]
#   curl -fsSL https://webshare.techbg.net/get | bash -s -- --source dev domain.com
#
# Options:
#   --source github|dev  - Choose update source (default: github)
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
echo -e "${BLUE}Quick Installer v3.0${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    echo ""
    echo "Usage:"
    echo "  curl -fsSL https://webshare.techbg.net/get | sudo bash"
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

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            SOURCE="$2"
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            elif [ "$ADMIN_USER" = "admin" ]; then
                ADMIN_USER="$1"
            elif [ -z "$ADMIN_PASS" ]; then
                ADMIN_PASS="$1"
            fi
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
else
    SOURCE_URL="https://webshare.techbg.net/src"
fi

WEBROOT="/var/www/webshare"

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
mkdir -p "$WEBROOT/files" "$WEBROOT/texts" "$WEBROOT/backups" "$WEBROOT/assets/quill"

echo -e "${GREEN}Directories created${NC}"

# ============================================
# 4. Download source files
# ============================================
echo -e "${BLUE}[4/8]${NC} Downloading WebShare files..."

PHP_FILES=(
    "index.php" "upload.php" "public.php" "download.php"
    "t.php" "text.php" "share.php" "folder-management.php"
    "encryption.php" "audit-log.php" "geo-check.php"
    "user-management.php" "html-sanitizer.php" "smtp-mailer.php"
    "send-mail.php" "web-download.php" "api-upload.php"
    "api-scripts.php" "check-version.php" "do-update.php"
    "live-update.php" "p.php" "u.php" "get.php"
    "get-speedtest.php" "security-headers.php" "f.php"
)

OTHER_FILES=(
    "favicon.ico" "favicon.svg" "apple-touch-icon.png"
    "CHANGELOG.md" "README.md" "README-BG.md" "version.json"
)

# Download PHP files
for file in "${PHP_FILES[@]}"; do
    curl -fsSL "$SOURCE_URL/$file" -o "$WEBROOT/$file" 2>/dev/null || true
done

# Download other files
for file in "${OTHER_FILES[@]}"; do
    curl -fsSL "$SOURCE_URL/$file" -o "$WEBROOT/$file" 2>/dev/null || true
done

# Download .htaccess
curl -fsSL "$SOURCE_URL/.htaccess" -o "$WEBROOT/.htaccess" 2>/dev/null || true

# Download Quill.js assets
curl -fsSL "$SOURCE_URL/assets/quill/quill.js" -o "$WEBROOT/assets/quill/quill.js" 2>/dev/null || true
curl -fsSL "$SOURCE_URL/assets/quill/quill.snow.css" -o "$WEBROOT/assets/quill/quill.snow.css" 2>/dev/null || true

# Download update script
curl -fsSL "https://raw.githubusercontent.com/toshko37/webshare/main/installer/update.sh" -o "$WEBROOT/update.sh" 2>/dev/null || \
curl -fsSL "https://webshare.techbg.net/installer/update.sh" -o "$WEBROOT/update.sh" 2>/dev/null || true
chmod +x "$WEBROOT/update.sh" 2>/dev/null || true

# Fix .htaccess path
sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $WEBROOT/.htpasswd|g" "$WEBROOT/.htaccess" 2>/dev/null || true

echo -e "${GREEN}Files downloaded${NC}"

# ============================================
# 5. Create config files
# ============================================
echo -e "${BLUE}[5/8]${NC} Creating configuration..."

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

# .htpasswd
htpasswd -cb "$WEBROOT/.htpasswd" "$ADMIN_USER" "$ADMIN_PASS" > /dev/null 2>&1

# Config files
echo '{"enabled":false,"allowed_countries":["BG"],"blocked_countries":[]}' > "$WEBROOT/.geo.json"
echo '{"mail_enabled":false,"smtp_host":"","smtp_port":587,"smtp_user":"","smtp_pass":"","smtp_encryption":"tls","mail_from":""}' > "$WEBROOT/.config.json"
echo '{}' > "$WEBROOT/.files-meta.json"
echo '{}' > "$WEBROOT/.texts.json"
echo '{}' > "$WEBROOT/.tokens.json"
echo '{}' > "$WEBROOT/.audit.json"
echo '[]' > "$WEBROOT/.api-keys.json"
echo '{}' > "$WEBROOT/.mail-ratelimit.json"

# Update source config
cat > "$WEBROOT/.update-config.json" << UPDATECONF
{
    "stable": $([ "$SOURCE" = "github" ] && echo "true" || echo "false")
}
UPDATECONF

# PHP config
cat > "$WEBROOT/.user.ini" << 'PHPINI'
; WebShare PHP Settings
upload_max_filesize = 10G
post_max_size = 10G
max_execution_time = 7200
max_input_time = 7200
memory_limit = 512M
PHPINI

echo -e "${GREEN}Configuration created${NC}"

# ============================================
# 6. Set permissions
# ============================================
echo -e "${BLUE}[6/8]${NC} Setting permissions..."

chown -R www-data:www-data "$WEBROOT"
chmod 600 "$WEBROOT/.htpasswd" "$WEBROOT/.api-keys.json" "$WEBROOT/.tokens.json"
chmod 644 "$WEBROOT/.geo.json" "$WEBROOT/.config.json" "$WEBROOT/.files-meta.json" "$WEBROOT/.texts.json" "$WEBROOT/.audit.json" "$WEBROOT/.mail-ratelimit.json"
chmod 750 "$WEBROOT/files" "$WEBROOT/texts"

echo -e "${GREEN}Permissions set${NC}"

# ============================================
# 7. Configure virtual host
# ============================================
echo -e "${BLUE}[7/8]${NC} Configuring virtual host..."

cat > "/etc/apache2/sites-available/webshare.conf" << VHEOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${WEBROOT}

    <Directory ${WEBROOT}>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/webshare_error.log
    CustomLog \${APACHE_LOG_DIR}/webshare_access.log combined
</VirtualHost>
VHEOF

a2ensite webshare.conf > /dev/null 2>&1
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
echo -e "To update: ${YELLOW}cd $WEBROOT && ./update.sh${NC}"
echo ""
echo -e "${BLUE}Enjoy! ${NC}"
