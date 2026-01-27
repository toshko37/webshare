#!/bin/bash
#
# WebShare Quick Installer v3.0
# Usage: curl -fsSL https://your-server.com/get | bash -s -- domain.com [user] [pass]
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
    exit 1
fi

# Check OS
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}Error: This installer requires Debian/Ubuntu${NC}"
    exit 1
fi

# Parse arguments or prompt
DOMAIN="$1"
ADMIN_USER="${2:-admin}"
ADMIN_PASS="$3"

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
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo -e "${BLUE}[1/7]${NC} Downloading WebShare..."
curl -fsSL "https://webshare.techbg.net/webshare-installer-v3.tar.gz" -o webshare.tar.gz
tar -xzf webshare.tar.gz

echo -e "${BLUE}[2/7]${NC} Installing dependencies..."
apt-get update -qq
apt-get install -y -qq apache2 php php-cli php-json php-mbstring php-xml php-curl libapache2-mod-php certbot python3-certbot-apache > /dev/null

# Install php-maxminddb if available
if apt-cache show php-maxminddb &> /dev/null; then
    apt-get install -y -qq php-maxminddb > /dev/null
fi

echo -e "${BLUE}[3/7]${NC} Configuring Apache..."
a2enmod rewrite ssl headers > /dev/null 2>&1

# Create directory structure
WEBROOT="/var/www/webshare"
mkdir -p "$WEBROOT/files" "$WEBROOT/texts" "$WEBROOT/backups" "$WEBROOT/assets/quill"

# Copy files
cp installer/src/*.php "$WEBROOT/"
cp installer/src/*.sh "$WEBROOT/" 2>/dev/null || true
chmod +x "$WEBROOT"/*.sh 2>/dev/null || true
cp installer/src/.htaccess "$WEBROOT/"
cp installer/src/.user.ini "$WEBROOT/"
cp installer/src/*.ico "$WEBROOT/" 2>/dev/null || true
cp installer/src/*.svg "$WEBROOT/" 2>/dev/null || true
cp installer/src/*.png "$WEBROOT/" 2>/dev/null || true
cp -r installer/src/assets/* "$WEBROOT/assets/" 2>/dev/null || true

# Fix hardcoded path in .htaccess
sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $WEBROOT/.htpasswd|g" "$WEBROOT/.htaccess"

# Create files/.htaccess (security)
cat > "$WEBROOT/files/.htaccess" << 'HTEOF'
# Protect uploaded files from direct access
Require all denied

<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
HTEOF

# Create texts/.htaccess (security)
cat > "$WEBROOT/texts/.htaccess" << 'HTEOF'
# Protect text files from direct access
Require all denied
HTEOF

echo -e "${BLUE}[4/7]${NC} Setting up authentication..."
htpasswd -cb "$WEBROOT/.htpasswd" "$ADMIN_USER" "$ADMIN_PASS" > /dev/null 2>&1

# Create config files
echo '{"enabled":false,"allowed_countries":["BG"],"blocked_countries":[]}' > "$WEBROOT/.geo.json"
echo '{"mail_enabled":false,"smtp_host":"","smtp_port":587,"smtp_user":"","smtp_pass":"","smtp_encryption":"tls","mail_from":""}' > "$WEBROOT/.config.json"
echo '{}' > "$WEBROOT/.files-meta.json"
echo '{}' > "$WEBROOT/.texts.json"
echo '{}' > "$WEBROOT/.tokens.json"
echo '{}' > "$WEBROOT/.audit.json"
echo '[]' > "$WEBROOT/.api-keys.json"
echo '{}' > "$WEBROOT/.mail-ratelimit.json"

# Set permissions
chown -R www-data:www-data "$WEBROOT"
chmod 600 "$WEBROOT/.htpasswd" "$WEBROOT/.api-keys.json" "$WEBROOT/.tokens.json"
chmod 644 "$WEBROOT/.geo.json" "$WEBROOT/.config.json" "$WEBROOT/.files-meta.json" "$WEBROOT/.texts.json" "$WEBROOT/.audit.json" "$WEBROOT/.mail-ratelimit.json"

echo -e "${BLUE}[5/7]${NC} Configuring virtual host..."
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

echo -e "${BLUE}[6/7]${NC} Setting up SSL certificate..."
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>/dev/null || {
    echo -e "${YELLOW}Note: SSL setup requires DNS to point to this server${NC}"
    echo -e "${YELLOW}Run manually: certbot --apache -d ${DOMAIN}${NC}"
}

# Setup auto-renewal cron job
CRON_JOB="0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo -e "${GREEN}SSL auto-renewal cron job added${NC}"
fi

# Download GeoIP database
echo -e "${BLUE}[7/7]${NC} Downloading GeoIP database..."
GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
if curl -fsSL "$GEOIP_URL" -o "$WEBROOT/GeoLite2-Country.mmdb" 2>/dev/null; then
    chown www-data:www-data "$WEBROOT/GeoLite2-Country.mmdb"
    echo -e "${GREEN}GeoIP database installed${NC}"
else
    echo -e "${YELLOW}Note: GeoIP download failed. Geo-blocking disabled.${NC}"
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

# Done
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
echo ""
echo -e "${BLUE}Enjoy! ${NC}"
