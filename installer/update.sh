#!/bin/bash
#
# WebShare Remote Update Script
# =============================
# This script is downloaded and executed by the local ./update script
# Do not run this directly - use ./update from your installation
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get install directory from environment or use default
INSTALL_DIR="${INSTALL_DIR:-/var/www/webshare}"
BACKUP_DIR="${INSTALL_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
SOURCE_URL="https://webshare.techbg.net/installer/src"
AUTO_CONFIRM=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            AUTO_CONFIRM=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo ""
echo "The following will be PRESERVED:"
echo "  - files/ directory (all uploaded files)"
echo "  - texts/ directory (shared texts)"
echo "  - .users.json, .tokens.json, .texts.json"
echo "  - .config.json, .geo.json"
echo "  - .htpasswd, .audit-log.json"
echo "  - GeoLite2-Country.mmdb"
echo ""
echo "The following will be UPDATED:"
echo "  - All PHP files"
echo "  - update.sh script"
echo "  - Favicon files"
echo "  - assets/ folder"
echo ""

if [ "$AUTO_CONFIRM" = false ]; then
    read -p "Continue with update? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Update cancelled."
        exit 0
    fi
else
    echo -e "${GREEN}Auto-confirm enabled, proceeding...${NC}"
fi

# Step 1: Create backup (software only, not uploaded files)
echo ""
echo -e "${BLUE}[1/6] Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"

# Copy only software files, exclude files/ and texts/ directories
for item in "$INSTALL_DIR"/*; do
    basename=$(basename "$item")
    if [ "$basename" != "files" ] && [ "$basename" != "texts" ] && [ "$basename" != "installer" ]; then
        cp -r "$item" "$BACKUP_DIR"/ 2>/dev/null || true
    fi
done

# Copy hidden files (configs)
cp "$INSTALL_DIR"/.htaccess "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.htpasswd "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.user.ini "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.config.json "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.geo.json "$BACKUP_DIR"/ 2>/dev/null || true
# Don't backup data files (.files-meta.json, .tokens.json, etc.) - they should stay in place

echo -e "${GREEN}Backup created: $BACKUP_DIR${NC}"

# Cleanup old backups - keep only last 2
echo -n "  Cleaning old backups... "
BACKUP_PARENT=$(dirname "$BACKUP_DIR")
BACKUP_PREFIX=$(basename "$INSTALL_DIR")_backup_
OLD_BACKUPS=$(ls -dt "$BACKUP_PARENT/${BACKUP_PREFIX}"* 2>/dev/null | tail -n +3 || true)
if [ -n "$OLD_BACKUPS" ]; then
    DELETED_COUNT=0
    for old_backup in $OLD_BACKUPS; do
        rm -rf "$old_backup" && DELETED_COUNT=$((DELETED_COUNT + 1))
    done
    echo -e "${GREEN}removed $DELETED_COUNT old backup(s)${NC}"
else
    echo -e "${GREEN}none to remove${NC}"
fi

# Step 2: Check dependencies
echo ""
echo -e "${BLUE}[2/6] Checking dependencies...${NC}"
DEPS_INSTALLED=false

# Check for php-xml (required for DOMDocument)
if ! php -m 2>/dev/null | grep -q "^xml$"; then
    echo -n "  Installing php-xml... "
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq php-xml > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}skipped${NC}"
    DEPS_INSTALLED=true
fi

# Check for php-maxminddb (for GeoIP)
if ! php -m 2>/dev/null | grep -q "maxminddb"; then
    echo -n "  Installing php-maxminddb... "
    apt-get install -y -qq php-maxminddb > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}skipped${NC}"
    DEPS_INSTALLED=true
fi

if [ "$DEPS_INSTALLED" = false ]; then
    echo -e "${GREEN}All dependencies OK${NC}"
fi

# Download GeoIP database if missing
if [ ! -f "$INSTALL_DIR/GeoLite2-Country.mmdb" ]; then
    echo -n "  Downloading GeoIP database... "
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    if curl -fsSL "$GEOIP_URL" -o "$INSTALL_DIR/GeoLite2-Country.mmdb" 2>/dev/null; then
        chown www-data:www-data "$INSTALL_DIR/GeoLite2-Country.mmdb"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
    fi
fi

# Step 3: Download PHP files
echo ""
echo -e "${BLUE}[3/6] Downloading PHP files...${NC}"

PHP_FILES=(
    "index.php"
    "upload.php"
    "public.php"
    "download.php"
    "t.php"
    "text.php"
    "share.php"
    "folder-management.php"
    "encryption.php"
    "audit-log.php"
    "geo-check.php"
    "user-management.php"
    "html-sanitizer.php"
    "smtp-mailer.php"
    "send-mail.php"
    "web-download.php"
    "api-upload.php"
    "api-scripts.php"
    "check-version.php"
    "do-update.php"
    "live-update.php"
    "p.php"
    "u.php"
    "get.php"
    "get-speedtest.php"
)

cd "$INSTALL_DIR"

for file in "${PHP_FILES[@]}"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$file.new" 2>/dev/null; then
        mv "$file.new" "$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# Step 4: Download other files
echo ""
echo -e "${BLUE}[4/6] Downloading assets...${NC}"

# Favicon files
for file in "favicon.ico" "favicon.svg" "apple-touch-icon.png"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$file.new" 2>/dev/null; then
        mv "$file.new" "$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# .htaccess
echo -n "  .htaccess... "
if curl -fsSL "$SOURCE_URL/htaccess.txt" -o ".htaccess.new" 2>/dev/null; then
    mv ".htaccess.new" ".htaccess"
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
    rm -f ".htaccess.new"
fi

# .user.ini
echo -n "  .user.ini... "
if curl -fsSL "$SOURCE_URL/user.ini.txt" -o ".user.ini.new" 2>/dev/null; then
    mv ".user.ini.new" ".user.ini"
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
    rm -f ".user.ini.new"
fi

# Quill.js assets
echo -n "  Quill.js editor... "
mkdir -p "$INSTALL_DIR/assets/quill"
QUILL_OK=true
if ! curl -fsSL "$SOURCE_URL/assets/quill/quill.js" -o "$INSTALL_DIR/assets/quill/quill.js" 2>/dev/null; then
    QUILL_OK=false
fi
if ! curl -fsSL "$SOURCE_URL/assets/quill/quill.snow.css" -o "$INSTALL_DIR/assets/quill/quill.snow.css" 2>/dev/null; then
    QUILL_OK=false
fi
if [ "$QUILL_OK" = true ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
fi

# Update script itself
echo -n "  update.sh... "
if curl -fsSL "https://webshare.techbg.net/get-update-script" -o "$INSTALL_DIR/update.sh.new" 2>/dev/null; then
    mv "$INSTALL_DIR/update.sh.new" "$INSTALL_DIR/update.sh"
    chmod +x "$INSTALL_DIR/update.sh"
    # Remove old update (without .sh) if exists
    rm -f "$INSTALL_DIR/update" 2>/dev/null
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
    rm -f "$INSTALL_DIR/update.sh.new"
fi

# Install local script
echo -n "  install-local.sh... "
if curl -fsSL "$SOURCE_URL/install-local.sh" -o "$INSTALL_DIR/install-local.sh.new" 2>/dev/null; then
    mv "$INSTALL_DIR/install-local.sh.new" "$INSTALL_DIR/install-local.sh"
    chmod +x "$INSTALL_DIR/install-local.sh"
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
    rm -f "$INSTALL_DIR/install-local.sh.new"
fi

# Documentation files
for file in "README.md" "README-BG.md" "CHANGELOG.md"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$file.new" 2>/dev/null; then
        mv "$file.new" "$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# Step 5: Set permissions
echo ""
echo -e "${BLUE}[5/6] Setting permissions...${NC}"
chown -R www-data:www-data "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/*.php 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/*.md 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/*.ico 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/*.svg 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/*.png 2>/dev/null || true
chmod 600 "$INSTALL_DIR"/.*.json 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/.htaccess 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/.htpasswd 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/files" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/texts" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/assets" 2>/dev/null || true
echo -e "${GREEN}Permissions set${NC}"

# Step 6: Verify
echo ""
echo -e "${BLUE}[6/6] Verifying update...${NC}"

# Get new version
NEW_VERSION=$(grep "WEBSHARE_VERSION" "$INSTALL_DIR/index.php" 2>/dev/null | head -1 | sed "s/.*'\([0-9.]*\)'.*/\1/" || echo "unknown")

if [ -f "$INSTALL_DIR/index.php" ] && [ -f "$INSTALL_DIR/folder-management.php" ]; then
    echo -e "${GREEN}Update successful!${NC}"
    echo ""
    echo -e "New version: ${GREEN}${NEW_VERSION}${NC}"
else
    echo -e "${RED}Update may have failed. Check $BACKUP_DIR for backup.${NC}"
    exit 1
fi

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Update Complete!                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "If something went wrong, restore with:"
echo -e "${YELLOW}  cp -r $BACKUP_DIR/* $INSTALL_DIR/"
echo -e "  cp $BACKUP_DIR/.* $INSTALL_DIR/${NC}"
echo ""
echo "Delete backup after verifying:"
echo -e "${YELLOW}  rm -rf $BACKUP_DIR${NC}"
echo ""
