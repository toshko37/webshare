#!/bin/bash
#
# WebShare Update Script v3.0
# ===========================
# Downloads updates from GitHub (stable) or dev server
#
# Usage:
#   ./update.sh                    # Use configured source
#   ./update.sh --source github    # Force GitHub source
#   ./update.sh --source dev       # Force dev server source
#   ./update.sh -y                 # Auto-confirm
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get install directory (can be passed via environment or auto-detect)
if [ -n "$INSTALL_DIR" ]; then
    # Use environment variable
    :
elif [ -f "$(dirname "$0")/index.php" ]; then
    INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
elif [ -f "/var/www/webshare/index.php" ]; then
    INSTALL_DIR="/var/www/webshare"
else
    echo -e "${RED}Error: Cannot determine installation directory${NC}"
    echo "Run from the WebShare directory or set INSTALL_DIR environment variable"
    exit 1
fi

BACKUP_DIR="${INSTALL_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
CONFIG_FILE="$INSTALL_DIR/.update-config.json"
AUTO_CONFIRM=false
SOURCE_OVERRIDE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            AUTO_CONFIRM=true
            shift
            ;;
        --source)
            SOURCE_OVERRIDE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Load config to determine source
if [ -f "$CONFIG_FILE" ]; then
    USE_STABLE=$(grep -o '"stable"[[:space:]]*:[[:space:]]*\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' || echo "true")
else
    USE_STABLE="true"
fi

# Override if specified
if [ -n "$SOURCE_OVERRIDE" ]; then
    if [ "$SOURCE_OVERRIDE" = "github" ]; then
        USE_STABLE="true"
    elif [ "$SOURCE_OVERRIDE" = "dev" ]; then
        USE_STABLE="false"
    else
        echo -e "${RED}Error: Invalid source '$SOURCE_OVERRIDE'. Use 'github' or 'dev'${NC}"
        exit 1
    fi
fi

# Set source URL based on config
if [ "$USE_STABLE" = "true" ]; then
    SOURCE_URL="https://raw.githubusercontent.com/toshko37/webshare/main/src"
    SOURCE_NAME="GitHub (stable)"
else
    SOURCE_URL="https://webshare.techbg.net/src"
    SOURCE_NAME="Dev server"
fi

# Banner
echo ""
echo -e "${CYAN}╦ ╦┌─┐┌┐ ╔═╗┬ ┬┌─┐┬─┐┌─┐${NC}"
echo -e "${CYAN}║║║├┤ ├┴┐╚═╗├─┤├─┤├┬┘├┤ ${NC}"
echo -e "${CYAN}╚╩╝└─┘└─┘╚═╝┴ ┴┴ ┴┴└─└─┘${NC}"
echo ""
echo -e "${BLUE}Update Script v3.0${NC}"
echo -e "Source: ${GREEN}$SOURCE_NAME${NC}"
echo -e "Install: ${CYAN}$INSTALL_DIR${NC}"
echo ""

# Get current version
CURRENT_VERSION="unknown"
if [ -f "$INSTALL_DIR/index.php" ]; then
    CURRENT_VERSION=$(grep "WEBSHARE_VERSION" "$INSTALL_DIR/index.php" 2>/dev/null | head -1 | sed "s/.*'\([0-9.]*\)'.*/\1/" || echo "unknown")
fi
echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"
echo ""

# Check for new version
echo -n "Checking for updates... "
if [ "$USE_STABLE" = "true" ]; then
    # Check GitHub API for latest release
    LATEST_INFO=$(curl -fsSL "https://api.github.com/repos/toshko37/webshare/releases/latest" 2>/dev/null || echo "{}")
    LATEST_VERSION=$(echo "$LATEST_INFO" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"v\?\([^"]*\)".*/\1/' || echo "")
else
    # Check dev server version.json
    VERSION_INFO=$(curl -fsSL "$SOURCE_URL/version.json" 2>/dev/null || echo "{}")
    LATEST_VERSION=$(echo "$VERSION_INFO" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
fi

if [ -n "$LATEST_VERSION" ]; then
    echo -e "${GREEN}$LATEST_VERSION${NC}"
else
    echo -e "${YELLOW}Unable to check${NC}"
    LATEST_VERSION="$CURRENT_VERSION"
fi

echo ""
echo "The following will be PRESERVED:"
echo "  - files/ directory (all uploaded files)"
echo "  - texts/ directory (shared texts)"
echo "  - .users.json, .tokens.json, .texts.json"
echo "  - .config.json, .geo.json"
echo "  - .htpasswd, .audit.json"
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

# Step 1: Create backup
echo ""
echo -e "${BLUE}[1/6] Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"

# Copy software files only (exclude files/ and texts/)
for item in "$INSTALL_DIR"/*; do
    basename=$(basename "$item")
    if [ "$basename" != "files" ] && [ "$basename" != "texts" ] && [ "$basename" != "backups" ]; then
        cp -r "$item" "$BACKUP_DIR"/ 2>/dev/null || true
    fi
done

# Copy hidden config files
cp "$INSTALL_DIR"/.htaccess "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.htpasswd "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.user.ini "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.config.json "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.geo.json "$BACKUP_DIR"/ 2>/dev/null || true
cp "$INSTALL_DIR"/.update-config.json "$BACKUP_DIR"/ 2>/dev/null || true

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

# Check for php-xml
if ! php -m 2>/dev/null | grep -q "^xml$"; then
    echo -n "  Installing php-xml... "
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq php-xml > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}skipped${NC}"
    DEPS_INSTALLED=true
fi

# Check for php-maxminddb
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
    "index.php" "upload.php" "public.php" "download.php"
    "t.php" "text.php" "share.php" "folder-management.php"
    "encryption.php" "audit-log.php" "geo-check.php"
    "user-management.php" "html-sanitizer.php" "smtp-mailer.php"
    "send-mail.php" "web-download.php" "api-upload.php"
    "api-scripts.php" "check-version.php" "do-update.php"
    "live-update.php" "p.php" "u.php" "get.php"
    "get-speedtest.php" "security-headers.php" "f.php"
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
if curl -fsSL "$SOURCE_URL/.htaccess" -o ".htaccess.new" 2>/dev/null; then
    # Preserve the AuthUserFile path
    CURRENT_AUTH_PATH=$(grep "AuthUserFile" ".htaccess" 2>/dev/null | head -1 || echo "")
    mv ".htaccess.new" ".htaccess"
    if [ -n "$CURRENT_AUTH_PATH" ]; then
        sed -i "s|AuthUserFile .*/\.htpasswd|AuthUserFile $INSTALL_DIR/.htpasswd|g" ".htaccess"
    fi
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
    rm -f ".htaccess.new"
fi

# .user.ini
echo -n "  .user.ini... "
if curl -fsSL "$SOURCE_URL/.user.ini" -o ".user.ini.new" 2>/dev/null; then
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

# Documentation files
for file in "README.md" "README-BG.md" "CHANGELOG.md" "version.json"; do
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

# Clear version cache
rm -f "$INSTALL_DIR/.version-check.json"

if [ -f "$INSTALL_DIR/index.php" ] && [ -f "$INSTALL_DIR/folder-management.php" ]; then
    echo -e "${GREEN}Update successful!${NC}"
    echo ""
    echo -e "Version: ${YELLOW}${CURRENT_VERSION}${NC} -> ${GREEN}${NEW_VERSION}${NC}"
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
