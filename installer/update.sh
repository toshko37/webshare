#!/bin/bash
#
# WebShare Update Script v3.2
# ===========================
# Downloads updates from GitHub (stable) or dev server
# Supports both old (root) and new (src/) directory structures
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

# Detect installation directory
detect_install_dir() {
    # Check various locations
    if [ -n "$INSTALL_DIR" ]; then
        # Use environment variable
        :
    elif [ -f "$(dirname "$0")/../src/index.php" ]; then
        # Script in installer/, src/ has files
        INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    elif [ -f "/var/www/webshare/src/index.php" ]; then
        # Default location
        INSTALL_DIR="/var/www/webshare"
    else
        echo -e "${RED}Error: Cannot determine installation directory${NC}"
        echo "Run from the WebShare directory or set INSTALL_DIR environment variable"
        exit 1
    fi

    SRC_DIR="$INSTALL_DIR/src"

    # Verify src directory exists
    if [ ! -d "$SRC_DIR" ]; then
        echo -e "${RED}Error: src/ directory not found${NC}"
        echo "Expected: $SRC_DIR"
        exit 1
    fi
}

detect_install_dir

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
echo -e "${BLUE}Update Script v3.2${NC}"
echo -e "Source: ${GREEN}$SOURCE_NAME${NC}"
echo -e "Install: ${CYAN}$INSTALL_DIR${NC}"
echo -e "Source:  ${CYAN}$SRC_DIR${NC}"
echo ""

# Get current version
CURRENT_VERSION="unknown"
if [ -f "$SRC_DIR/index.php" ]; then
    CURRENT_VERSION=$(grep "WEBSHARE_VERSION" "$SRC_DIR/index.php" 2>/dev/null | head -1 | sed "s/.*'\([0-9.]*\)'.*/\1/" || echo "unknown")
fi
echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"
echo ""

# Check for new version
echo -n "Checking for updates... "
if [ "$USE_STABLE" = "true" ]; then
    LATEST_INFO=$(curl -fsSL "https://api.github.com/repos/toshko37/webshare/releases/latest" 2>/dev/null || echo "{}")
    LATEST_VERSION=$(echo "$LATEST_INFO" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"v\?\([^"]*\)".*/\1/' || echo "")
else
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
echo "  - .config.json, .geo.json, .htpasswd"
echo "  - .audit.json and archives"
echo "  - GeoLite2-Country.mmdb"
echo ""
echo "The following will be UPDATED:"
echo "  - All PHP files (in src/)"
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
echo -e "${BLUE}[1/7] Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"

# Backup PHP files
for item in "$SRC_DIR"/*.php; do
    [ -f "$item" ] && cp "$item" "$BACKUP_DIR"/ 2>/dev/null || true
done

# Copy hidden config files from root
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

# Step 2: Verify structure
echo ""
echo -e "${BLUE}[2/7] Verifying structure...${NC}"
mkdir -p "$SRC_DIR/assets/quill"
mkdir -p "$SRC_DIR/docs"
echo -e "${GREEN}Structure OK${NC}"

# Step 3: Create symlinks in src/ for data access
echo ""
echo -e "${BLUE}[3/7] Creating symlinks...${NC}"

# List of files/dirs that need symlinks
SYMLINKS=(
    "files:../files"
    "texts:../texts"
    "backups:../backups"
    "vendor:../vendor"
    ".htpasswd:../.htpasswd"
    ".config.json:../.config.json"
    ".geo.json:../.geo.json"
    ".audit.json:../.audit.json"
    ".tokens.json:../.tokens.json"
    ".texts.json:../.texts.json"
    ".files-meta.json:../.files-meta.json"
    ".folder-shares.json:../.folder-shares.json"
    ".api-keys.json:../.api-keys.json"
    ".encryption-keys.json:../.encryption-keys.json"
    ".mail-ratelimit.json:../.mail-ratelimit.json"
    ".update-config.json:../.update-config.json"
    ".version-check.json:../.version-check.json"
    "GeoLite2-Country.mmdb:../GeoLite2-Country.mmdb"
)

cd "$SRC_DIR"
for link in "${SYMLINKS[@]}"; do
    name="${link%%:*}"
    target="${link#*:}"
    if [ ! -L "$name" ] && [ ! -e "$name" ]; then
        ln -sf "$target" "$name" 2>/dev/null && echo "  Created: $name -> $target" || true
    fi
done

# Create symlinks for audit log archives
for i in {1..10}; do
    if [ -f "$INSTALL_DIR/.audit.$i.json" ] && [ ! -L ".audit.$i.json" ]; then
        ln -sf "../.audit.$i.json" ".audit.$i.json"
    fi
done

echo -e "${GREEN}Symlinks ready${NC}"

# Step 4: Check dependencies
echo ""
echo -e "${BLUE}[4/7] Checking dependencies...${NC}"
DEPS_INSTALLED=false

if ! php -m 2>/dev/null | grep -q "^xml$"; then
    echo -n "  Installing php-xml... "
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq php-xml > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}skipped${NC}"
    DEPS_INSTALLED=true
fi

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

# Step 5: Download PHP files
echo ""
echo -e "${BLUE}[5/7] Downloading PHP files...${NC}"

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

cd "$SRC_DIR"

for file in "${PHP_FILES[@]}"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$file.new" 2>/dev/null; then
        # Verify it's valid PHP
        if head -1 "$file.new" | grep -q "<?php"; then
            mv "$file.new" "$file"
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}invalid${NC}"
            rm -f "$file.new"
        fi
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# Step 6: Download other files
echo ""
echo -e "${BLUE}[6/7] Downloading assets...${NC}"

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
    mv ".htaccess.new" ".htaccess"
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
mkdir -p "$SRC_DIR/assets/quill"
QUILL_OK=true
if ! curl -fsSL "$SOURCE_URL/assets/quill/quill.js" -o "$SRC_DIR/assets/quill/quill.js" 2>/dev/null; then
    QUILL_OK=false
fi
if ! curl -fsSL "$SOURCE_URL/assets/quill/quill.snow.css" -o "$SRC_DIR/assets/quill/quill.snow.css" 2>/dev/null; then
    QUILL_OK=false
fi
if [ "$QUILL_OK" = true ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}skipped${NC}"
fi

# Documentation files (in src/)
for file in "CHANGELOG.md" "version.json"; do
    echo -n "  $file... "
    if curl -fsSL "$SOURCE_URL/$file" -o "$file.new" 2>/dev/null; then
        mv "$file.new" "$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# Root README files
cd "$INSTALL_DIR"
for file in "README.md" "README-BG.md"; do
    echo -n "  $file (root)... "
    if curl -fsSL "https://raw.githubusercontent.com/toshko37/webshare/main/$file" -o "$file.new" 2>/dev/null; then
        mv "$file.new" "$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$file.new"
    fi
done

# Update installer scripts
mkdir -p "$INSTALL_DIR/installer"
for file in "install.sh" "update.sh" "get-webshare.sh"; do
    echo -n "  installer/$file... "
    if curl -fsSL "https://raw.githubusercontent.com/toshko37/webshare/main/installer/$file" -o "$INSTALL_DIR/installer/$file.new" 2>/dev/null; then
        mv "$INSTALL_DIR/installer/$file.new" "$INSTALL_DIR/installer/$file"
        chmod +x "$INSTALL_DIR/installer/$file"
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}skipped${NC}"
        rm -f "$INSTALL_DIR/installer/$file.new"
    fi
done

# Step 7: Set permissions
echo ""
echo -e "${BLUE}[7/7] Setting permissions...${NC}"

# Root directory
chown www-data:www-data "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"

# Data files in root
chmod 600 "$INSTALL_DIR"/.*.json 2>/dev/null || true
chown www-data:www-data "$INSTALL_DIR"/.*.json 2>/dev/null || true

# src directory
chown -R www-data:www-data "$SRC_DIR"
chmod 755 "$SRC_DIR"
chmod 644 "$SRC_DIR"/*.php 2>/dev/null || true
chmod 644 "$SRC_DIR"/*.md 2>/dev/null || true
chmod 644 "$SRC_DIR"/.htaccess 2>/dev/null || true
chmod 644 "$SRC_DIR"/.user.ini 2>/dev/null || true

# Data directories
chmod -R 755 "$INSTALL_DIR/files" 2>/dev/null || true
chmod -R 755 "$INSTALL_DIR/texts" 2>/dev/null || true
chown -R www-data:www-data "$INSTALL_DIR/files" 2>/dev/null || true
chown -R www-data:www-data "$INSTALL_DIR/texts" 2>/dev/null || true

# Installer scripts
chmod +x "$INSTALL_DIR/installer"/*.sh 2>/dev/null || true

echo -e "${GREEN}Permissions set${NC}"

# Verify
echo ""
echo -e "${BLUE}Verifying update...${NC}"

# Get new version
NEW_VERSION=$(grep "WEBSHARE_VERSION" "$SRC_DIR/index.php" 2>/dev/null | head -1 | sed "s/.*'\([0-9.]*\)'.*/\1/" || echo "unknown")

# Clear version cache
rm -f "$INSTALL_DIR/.version-check.json"
rm -f "$SRC_DIR/.version-check.json"

if [ -f "$SRC_DIR/index.php" ] && [ -f "$SRC_DIR/folder-management.php" ]; then
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
echo -e "${YELLOW}  cp -r $BACKUP_DIR/* $SRC_DIR/"
echo -e "  cp $BACKUP_DIR/.* $SRC_DIR/${NC}"
echo ""
echo "Delete backup after verifying:"
echo -e "${YELLOW}  rm -rf $BACKUP_DIR${NC}"
echo ""
