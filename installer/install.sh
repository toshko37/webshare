#!/bin/bash
#
# WebShare Installer v2.0
# =======================
# Инсталира WebShare файлово и текстово споделяне
# с GeoIP защита и управление на потребители
#
# Използване:
#   sudo ./install.sh domain.com [username] [password]
#
# Пример:
#   sudo ./install.sh webshare.example.com admin secretpass123
#

set -e

# Цветове за output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции за output
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Проверка за root
if [ "$EUID" -ne 0 ]; then
    error "Моля стартирайте като root: sudo ./install.sh"
fi

# Параметри
DOMAIN=${1:-""}
AUTH_USER=${2:-"admin"}
AUTH_PASS=${3:-"$(openssl rand -base64 12)"}

if [ -z "$DOMAIN" ]; then
    echo ""
    echo "=========================================="
    echo "     WebShare Installer v2.0"
    echo "=========================================="
    echo ""
    echo "Използване:"
    echo "  sudo ./install.sh <domain> [username] [password]"
    echo ""
    echo "Пример:"
    echo "  sudo ./install.sh webshare.example.com"
    echo "  sudo ./install.sh webshare.example.com admin mypass123"
    echo ""
    error "Липсва domain параметър!"
fi

INSTALL_DIR="/var/www/${DOMAIN}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEOIP_DIR="/usr/share/GeoIP"

echo ""
echo "=========================================="
echo "     WebShare Installer v2.0"
echo "=========================================="
echo ""
info "Domain: $DOMAIN"
info "Install dir: $INSTALL_DIR"
info "Auth user: $AUTH_USER"
echo ""

# ============================================
# 1. Инсталиране на зависимости
# ============================================
info "Инсталиране на зависимости..."

apt-get update -qq

# Apache2
if ! command -v apache2 &> /dev/null; then
    info "Инсталиране на Apache2..."
    apt-get install -y apache2
fi
success "Apache2 OK"

# PHP
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2 || echo "")
if [ -z "$PHP_VERSION" ]; then
    info "Инсталиране на PHP..."
    apt-get install -y php php-common php-cli php-fpm php-json php-mbstring
    PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
fi
success "PHP $PHP_VERSION OK"

# PHP модули (включително MaxMindDB за GeoIP)
info "Инсталиране на PHP модули..."
apt-get install -y php-json php-mbstring php-xml php-dom libapache2-mod-php 2>/dev/null || true

# MaxMindDB за GeoIP
if ! php -m | grep -q maxminddb; then
    info "Инсталиране на php-maxminddb за GeoIP..."
    apt-get install -y php${PHP_VERSION}-maxminddb 2>/dev/null || \
    apt-get install -y php-maxminddb 2>/dev/null || \
    warn "php-maxminddb не може да се инсталира. GeoIP няма да работи."
fi
success "PHP модули OK"

# Certbot за SSL
if ! command -v certbot &> /dev/null; then
    info "Инсталиране на Certbot..."
    apt-get install -y certbot python3-certbot-apache
fi
success "Certbot OK"

# Apache модули
info "Активиране на Apache модули..."
a2enmod rewrite ssl headers 2>/dev/null || true
success "Apache модули OK"

# ============================================
# 2. GeoIP база данни
# ============================================
info "Настройване на GeoIP..."

mkdir -p "$GEOIP_DIR"

if [ ! -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ]; then
    info "Изтегляне на GeoLite2-Country.mmdb..."
    # Опитваме няколко източника
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

    if command -v wget &> /dev/null; then
        wget -q -O "$GEOIP_DIR/GeoLite2-Country.mmdb" "$GEOIP_URL" 2>/dev/null || true
    elif command -v curl &> /dev/null; then
        curl -sL -o "$GEOIP_DIR/GeoLite2-Country.mmdb" "$GEOIP_URL" 2>/dev/null || true
    fi

    if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ] && [ -s "$GEOIP_DIR/GeoLite2-Country.mmdb" ]; then
        success "GeoIP база изтеглена"
    else
        warn "GeoIP базата не може да се изтегли. GeoIP няма да работи."
        warn "Ръчно изтеглете GeoLite2-Country.mmdb в $GEOIP_DIR/"
    fi
else
    success "GeoIP база съществува"
fi

# ============================================
# 3. Създаване на директории
# ============================================
info "Създаване на директории..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/files"
mkdir -p "$INSTALL_DIR/texts"
mkdir -p "$INSTALL_DIR/assets/quill"

success "Директории създадени"

# ============================================
# 4. Копиране на файлове
# ============================================
info "Копиране на файлове..."

# Ако има source файлове в installer директорията
if [ -d "$SCRIPT_DIR/src" ]; then
    cp -r "$SCRIPT_DIR/src/"* "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/src/.htaccess" "$INSTALL_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/src/.user.ini" "$INSTALL_DIR/" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/update.sh" 2>/dev/null || true
else
    error "Липсва src директорията с файловете!"
fi

success "Файлове копирани"

# ============================================
# 5. Конфигурационни файлове
# ============================================
info "Създаване на конфигурационни файлове..."

# GeoIP конфигурация
cat > "$INSTALL_DIR/.geo.json" << 'GEOJSON'
{
    "enabled": true,
    "allowed_countries": ["BG"],
    "blocked_message": "Access denied from your location",
    "geoip_database": "/usr/share/GeoIP/GeoLite2-Country.mmdb"
}
GEOJSON

# Files metadata
echo "{}" > "$INSTALL_DIR/.files-meta.json"

# Texts metadata
echo "{}" > "$INSTALL_DIR/.texts.json"

# Share tokens
echo "{}" > "$INSTALL_DIR/.tokens.json"

success "Конфигурации създадени"

# ============================================
# 6. Актуализиране на .htaccess
# ============================================
info "Конфигуриране на .htaccess..."

cat > "$INSTALL_DIR/.htaccess" << 'HTACCESS'
# Webshare Access Control
# =======================

# URL Rewriting for clean URLs
RewriteEngine On

# Rewrite /p to /p.php (preserve query string)
RewriteRule ^p$ p.php [QSA,L]

# Rewrite /upload to /upload.php
RewriteRule ^upload$ upload.php [QSA,L]

# Rewrite /u to /u.php
RewriteRule ^u$ u.php [QSA,L]

# Rewrite /t/TOKEN to /t.php?token=TOKEN (for viewing shared texts)
RewriteRule ^t/([a-zA-Z0-9]{6})$ t.php?token=$1 [QSA,L]

# Rewrite /t to /t.php (for creating texts)
RewriteRule ^t$ t.php [QSA,L]

# Set authentication for the directory
AuthType Basic
AuthName "WebShare - Protected Area"
AuthUserFile INSTALL_DIR/.htpasswd

# Public files - no authentication required
<FilesMatch "^(public|p|upload|u|t)\.php$">
    Satisfy any
    Allow from all
</FilesMatch>

# All other PHP files require authentication
<FilesMatch "^(?!public|p|upload|u|t).*\.php$">
    Require valid-user
</FilesMatch>

# Non-PHP files that need protection
<FilesMatch "\.(json|html|htm|txt)$">
    Require valid-user
</FilesMatch>

# Security Headers
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set X-XSS-Protection "1; mode=block"
</IfModule>

# Disable directory browsing
Options -Indexes

# Protect .htaccess and .htpasswd
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# PHP Configuration for large uploads
php_value upload_max_filesize 10G
php_value post_max_size 10G
php_value max_execution_time 7200
php_value max_input_time 7200
php_value memory_limit 512M
HTACCESS

# Заместване на пътя
sed -i "s|INSTALL_DIR|$INSTALL_DIR|g" "$INSTALL_DIR/.htaccess"

success ".htaccess конфигуриран"

# ============================================
# 7. Files directory .htaccess
# ============================================
info "Защита на files директорията..."

cat > "$INSTALL_DIR/files/.htaccess" << 'FILESHT'
# Protect uploaded files from direct access
# Files should only be downloaded through download.php

# Deny all direct access
Require all denied

# Block PHP execution
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
FILESHT

success "Files директория защитена"

# ============================================
# 8. Създаване на .htpasswd
# ============================================
info "Създаване на .htpasswd..."

htpasswd -cb "$INSTALL_DIR/.htpasswd" "$AUTH_USER" "$AUTH_PASS"
chmod 644 "$INSTALL_DIR/.htpasswd"

success ".htpasswd създаден"

# ============================================
# 9. PHP user.ini
# ============================================
info "Конфигуриране на PHP..."

cat > "$INSTALL_DIR/.user.ini" << 'PHPINI'
; WebShare PHP Settings
upload_max_filesize = 10G
post_max_size = 10G
max_execution_time = 7200
max_input_time = 7200
memory_limit = 512M
PHPINI

success "PHP конфигуриран"

# ============================================
# 10. Права на достъп
# ============================================
info "Настройване на права..."

chown -R www-data:www-data "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR/files"
chmod 750 "$INSTALL_DIR/texts"
chmod 644 "$INSTALL_DIR/.htpasswd"
chmod 644 "$INSTALL_DIR/.geo.json"
chmod 644 "$INSTALL_DIR/.files-meta.json"
chmod 644 "$INSTALL_DIR/.texts.json"
chmod 644 "$INSTALL_DIR/.tokens.json"
chmod 644 "$INSTALL_DIR/files/.htaccess"

success "Права настроени"

# ============================================
# 11. Apache Virtual Host
# ============================================
info "Създаване на Apache Virtual Host..."

cat > "/etc/apache2/sites-available/${DOMAIN}.conf" << VHOST
# HTTP to HTTPS redirect
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias ${DOMAIN}

    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}\$1 [R=301,L]

    ErrorLog \${APACHE_LOG_DIR}/error-${DOMAIN}.log
    CustomLog \${APACHE_LOG_DIR}/access-${DOMAIN}.log combined
</VirtualHost>

# HTTPS VirtualHost
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        ServerAdmin webmaster@${DOMAIN}
        ServerName ${DOMAIN}
        ServerAlias ${DOMAIN}

        DocumentRoot ${INSTALL_DIR}

        # Directory permissions (authentication handled in .htaccess)
        <Directory ${INSTALL_DIR}/>
            Options -Indexes +FollowSymLinks
            AllowOverride All
            Require all granted
        </Directory>

        # SSL Configuration
        SSLEngine on

        # Logging
        ErrorLog \${APACHE_LOG_DIR}/error-${DOMAIN}-ssl.log
        CustomLog \${APACHE_LOG_DIR}/access-${DOMAIN}-ssl.log combined

        # Security headers
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

success "Virtual Host създаден"

# ============================================
# 12. SSL сертификат
# ============================================
info "Генериране на SSL сертификат..."

# Рестарт на Apache за да работи HTTP
systemctl reload apache2 2>/dev/null || true

# Проверка дали домейнът сочи към този сървър
if host "$DOMAIN" &>/dev/null; then
    certbot --apache -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>/dev/null || {
        warn "SSL сертификатът не може да бъде генериран автоматично."
        warn "Ръчно изпълнете: certbot --apache -d $DOMAIN"
    }
else
    warn "Домейнът $DOMAIN не е намерен в DNS."
    warn "Конфигурирайте DNS записа и после изпълнете:"
    warn "  certbot --apache -d $DOMAIN"
fi

success "SSL конфигуриран"

# ============================================
# 13. Настройка на автоматично подновяване на SSL
# ============================================
info "Настройка на автоматично подновяване на SSL сертификат..."

# Добавяне на cron job за certbot renew (ако не съществува)
CRON_JOB="0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    success "Cron job за SSL подновяване добавен (всеки ден в 03:00)"
else
    success "Cron job за SSL подновяване вече съществува"
fi

# ============================================
# 14. Финален рестарт
# ============================================
info "Рестартиране на Apache..."

systemctl restart apache2

success "Apache рестартиран"

# ============================================
# Готово!
# ============================================
echo ""
echo "=========================================="
echo -e "${GREEN}    Инсталацията завърши успешно!${NC}"
echo "=========================================="
echo ""
echo "URL адреси:"
echo "  Dashboard: https://${DOMAIN}/"
echo "  Public Upload: https://${DOMAIN}/u"
echo "  Public Text: https://${DOMAIN}/t"
echo ""
echo "Данни за вход:"
echo "  Username: $AUTH_USER"
echo "  Password: $AUTH_PASS"
echo ""
echo "Директории:"
echo "  Files: ${INSTALL_DIR}/files/"
echo "  Texts: ${INSTALL_DIR}/texts/"
echo ""
echo "Функции:"
echo "  - File upload/download/share"
echo "  - Rich text sharing"
echo "  - GeoIP защита (само BG по подразбиране)"
echo "  - User management (само admin)"
echo "  - File ownership tracking"
echo ""
echo "=========================================="
echo ""

# Записване на данните в файл
cat > "$INSTALL_DIR/CREDENTIALS.txt" << CREDS
WebShare Credentials
====================
Domain: https://${DOMAIN}/
Username: ${AUTH_USER}
Password: ${AUTH_PASS}

Public URLs:
  Upload: https://${DOMAIN}/u
  Text: https://${DOMAIN}/t

Инсталирано на: $(date)
Версия: 2.0
CREDS

chmod 600 "$INSTALL_DIR/CREDENTIALS.txt"
info "Данните са записани в: ${INSTALL_DIR}/CREDENTIALS.txt"
