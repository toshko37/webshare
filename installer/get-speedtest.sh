#!/bin/bash
#
# LibreSpeed Quick Installer
# Usage: curl -fsSL https://webshare.techbg.net/get-speedtest | bash -s -- speed.domain.com
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
echo '╔═╗┌─┐┌─┐┌─┐┌┬┐  ╔╦╗┌─┐┌─┐┌┬┐'
echo '╚═╗├─┘├┤ ├┤  ││   ║ ├┤ └─┐ │ '
echo '╚═╝┴  └─┘└─┘─┴┘   ╩ └─┘└─┘ ┴ '
echo -e "${NC}"
echo -e "${BLUE}LibreSpeed Installer v1.0${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    exit 1
fi

# Check OS
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}Error: This installer requires Debian/Ubuntu${NC}"
    exit 1
fi

# Parse arguments
DOMAIN="$1"
WEBSHARE_URL="$2"

if [ -z "$DOMAIN" ]; then
    echo -e "${YELLOW}Enter speed test domain:${NC}"
    read -p "> " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Error: Domain is required${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}Configuration:${NC}"
echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
if [ -n "$WEBSHARE_URL" ]; then
    echo -e "  Link to WebShare: ${GREEN}${WEBSHARE_URL}${NC}"
fi
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo -e "${BLUE}[1/6]${NC} Installing dependencies..."
apt-get update -qq
apt-get install -y -qq apache2 php php-cli php-gd libapache2-mod-php certbot python3-certbot-apache git > /dev/null

# Install php-maxminddb for GeoIP
if apt-cache show php-maxminddb &> /dev/null; then
    apt-get install -y -qq php-maxminddb > /dev/null
fi

echo -e "${BLUE}[2/6]${NC} Downloading LibreSpeed..."
git clone --depth 1 https://github.com/librespeed/speedtest.git speedtest > /dev/null 2>&1

# Setup web directory
WEBROOT="/var/www/speedtest"
mkdir -p "$WEBROOT"
cp -r speedtest/* "$WEBROOT/"

echo -e "${BLUE}[3/6]${NC} Configuring LibreSpeed..."

# Add WebShare link if provided (will be applied to speedtest.html later)
WEBSHARE_LINK="$WEBSHARE_URL"

# Create telemetry settings (disabled by default)
cat > "$WEBROOT/backend/getIP_telemetry_settings.php" << 'PHPEOF'
<?php
$db_type = "none";
$stats_password = "";
$enable_id_obfuscation = true;
$redact_ip_addresses = true;
PHPEOF

echo -e "${BLUE}[4/6]${NC} Setting up GeoIP protection..."

# Download GeoIP database
GEOIP_URLS=(
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    "https://git.io/GeoLite2-Country.mmdb"
)
for GEOIP_URL in "${GEOIP_URLS[@]}"; do
    if curl -fsSL "$GEOIP_URL" -o "$WEBROOT/GeoLite2-Country.mmdb" 2>/dev/null; then
        echo -e "${GREEN}GeoIP database downloaded${NC}"
        break
    fi
done

# Create geo-check.php
cat > "$WEBROOT/geo-check.php" << 'GEOPHP'
<?php
function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) $ip = trim(explode(',', $ip)[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function getCountryCode($ip) {
    $dbFile = __DIR__ . '/GeoLite2-Country.mmdb';
    if (!file_exists($dbFile)) return null;
    try {
        $r = new MaxMind\Db\Reader($dbFile);
        $rec = $r->get($ip);
        $r->close();
        return $rec['country']['iso_code'] ?? null;
    } catch (Exception $e) { return null; }
}

function checkGeoAccess() {
    $configFile = __DIR__ . '/.geo.json';
    $config = file_exists($configFile) ? json_decode(file_get_contents($configFile), true) : ['enabled' => true, 'allowed_countries' => ['BG']];

    if (!($config['enabled'] ?? true)) return true;

    $ip = getClientIP();

    // Allow private IPs
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return true;

    $country = getCountryCode($ip);
    if ($country === null) return true;

    $allowed = $config['allowed_countries'] ?? ['BG'];
    if (!in_array($country, $allowed)) {
        http_response_code(403);
        die('<!DOCTYPE html><html><head><title>Access Denied</title><style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:linear-gradient(135deg,#667eea,#764ba2);}.box{background:#fff;padding:40px;border-radius:12px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.2);}h1{color:#e53935;}</style></head><body><div class="box"><h1>Access Denied</h1><p>Speed test is not available from your location.</p></div></body></html>');
    }
    return true;
}
GEOPHP

# Create geo config (enabled by default, BG only)
echo '{"enabled":true,"allowed_countries":["BG"]}' > "$WEBROOT/.geo.json"

# Rename original index.html and create PHP wrapper
mv "$WEBROOT/index.html" "$WEBROOT/speedtest.html"

# Add WebShare link if provided
if [ -n "$WEBSHARE_LINK" ]; then
    sed -i 's|</body>|<div style="position:fixed;bottom:10px;right:10px;"><a href="'"$WEBSHARE_LINK"'" style="color:#666;text-decoration:none;font-size:12px;">📤 WebShare</a></div></body>|' "$WEBROOT/speedtest.html"
fi

cat > "$WEBROOT/index.php" << 'INDEXPHP'
<?php
require_once __DIR__ . '/geo-check.php';
checkGeoAccess();
readfile(__DIR__ . '/speedtest.html');
INDEXPHP

# Create .htaccess for clean URLs
cat > "$WEBROOT/.htaccess" << 'HTEOF'
DirectoryIndex index.php
<FilesMatch "^\.">
    Require all denied
</FilesMatch>
HTEOF

# Set permissions
chown -R www-data:www-data "$WEBROOT"

echo -e "${BLUE}[5/6]${NC} Configuring Apache..."
a2enmod rewrite ssl headers > /dev/null 2>&1

cat > "/etc/apache2/sites-available/speedtest.conf" << VHEOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    DocumentRoot ${WEBROOT}

    <Directory ${WEBROOT}>
        AllowOverride All
        Require all granted
    </Directory>

    # Enable CORS for speed test
    <IfModule mod_headers.c>
        Header set Access-Control-Allow-Origin "*"
        Header set Access-Control-Allow-Methods "GET, POST"
        Header set Access-Control-Allow-Headers "Content-Type"
    </IfModule>

    ErrorLog \${APACHE_LOG_DIR}/speedtest_error.log
    CustomLog \${APACHE_LOG_DIR}/speedtest_access.log combined
</VirtualHost>
VHEOF

a2ensite speedtest.conf > /dev/null 2>&1
systemctl reload apache2

echo -e "${BLUE}[6/6]${NC} Setting up SSL..."
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>/dev/null || {
    echo -e "${YELLOW}Note: SSL setup requires DNS to point to this server${NC}"
    echo -e "${YELLOW}Run manually: certbot --apache -d ${DOMAIN}${NC}"
}

# Setup auto-renewal cron job
CRON_JOB="0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo -e "${GREEN}SSL auto-renewal cron job added (daily at 03:00)${NC}"
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

# Done
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           LibreSpeed installed successfully!               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Speed Test:${NC}  https://${DOMAIN}"
echo -e "  ${CYAN}GeoIP:${NC}       Enabled (BG only)"
echo -e "  ${CYAN}Config:${NC}      /var/www/speedtest/.geo.json"
echo ""
echo -e "${YELLOW}To change allowed countries, edit /var/www/speedtest/.geo.json${NC}"
echo -e "${YELLOW}Example: {\"enabled\":true,\"allowed_countries\":[\"BG\",\"RO\"]}${NC}"
echo ""
echo -e "${BLUE}Enjoy! ${NC}"
