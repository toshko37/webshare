#!/bin/bash
# ============================================================
# WebShare Release Script
# ============================================================
# Automates all steps for releasing a new version:
#   1. Bumps version in index.php, version.json
#   2. Adds entry to CHANGELOG.md (header + version table)
#   3. Commits, pushes, creates GitHub release
#
# Usage:
#   ./release.sh <version> <title> [--notes-file <file>] [--yes]
#
# Examples:
#   # Interactive - opens editor for changelog:
#   ./release.sh 3.5.7 "Chat: new feature, bug fix"
#
#   # From file (for use with Claude or scripts):
#   ./release.sh 3.5.7 "Chat: new feature" --notes-file /tmp/notes.md
#
#   # Skip confirmation:
#   ./release.sh 3.5.7 "Quick fix" --notes-file /tmp/notes.md --yes
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths (relative to repo root)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
INDEX_PHP="$SRC_DIR/index.php"
VERSION_JSON="$SRC_DIR/version.json"
CHANGELOG_MD="$SRC_DIR/CHANGELOG.md"

# Parse arguments
NEW_VERSION=""
SHORT_DESC=""
NOTES_FILE=""
AUTO_YES=false

while [ $# -gt 0 ]; do
    case "$1" in
        --notes-file)
            NOTES_FILE="$2"
            shift 2
            ;;
        --yes|-y)
            AUTO_YES=true
            shift
            ;;
        *)
            if [ -z "$NEW_VERSION" ]; then
                NEW_VERSION="$1"
            elif [ -z "$SHORT_DESC" ]; then
                SHORT_DESC="$1"
            fi
            shift
            ;;
    esac
done

TODAY=$(date +%Y-%m-%d)

# Validate arguments
if [ -z "$NEW_VERSION" ] || [ -z "$SHORT_DESC" ]; then
    echo -e "${RED}Usage: $0 <version> <short-description> [options]${NC}"
    echo ""
    echo "  version             New version number (e.g. 3.5.7)"
    echo "  short-description   One-line summary for version.json and commit"
    echo ""
    echo "Options:"
    echo "  --notes-file FILE   Read changelog from file instead of opening editor"
    echo "  --yes, -y           Skip confirmation prompt"
    echo ""
    echo "Examples:"
    echo "  $0 3.5.7 \"Chat: new feature, bug fix\""
    echo "  $0 3.5.7 \"Chat fix\" --notes-file /tmp/notes.md"
    echo "  $0 3.5.7 \"Quick fix\" --notes-file /tmp/notes.md --yes"
    exit 1
fi

# Validate version format
if ! echo "$NEW_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo -e "${RED}Error: Version must be in format X.Y.Z (e.g. 3.5.7)${NC}"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(grep -oP "WEBSHARE_VERSION',\s*'\K[^']+" "$INDEX_PHP" 2>/dev/null || echo "unknown")

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  WebShare Release${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  Current version: ${YELLOW}$CURRENT_VERSION${NC}"
echo -e "  New version:     ${GREEN}$NEW_VERSION${NC}"
echo -e "  Description:     $SHORT_DESC"
echo -e "  Date:            $TODAY"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Warning: You have uncommitted changes:${NC}"
    git status --short
    echo ""
    if [ "$AUTO_YES" = false ]; then
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 1
        fi
    fi
fi

# ============================================================
# Step 1: Get changelog entry
# ============================================================
echo -e "${CYAN}Step 1: Changelog...${NC}"

if [ -n "$NOTES_FILE" ]; then
    # Read from file
    if [ ! -f "$NOTES_FILE" ]; then
        echo -e "${RED}Error: Notes file not found: $NOTES_FILE${NC}"
        exit 1
    fi
    CHANGELOG_ENTRY=$(cat "$NOTES_FILE")
    echo -e "  Read from: ${YELLOW}$NOTES_FILE${NC}"
else
    # Open editor
    TMPFILE=$(mktemp /tmp/changelog-XXXXXX.md)
    cat > "$TMPFILE" << TEMPLATE
### Section Title
- **Feature name** - Short description of what it does
  - Additional detail if needed
- **Another change** - Description
TEMPLATE

    EDITOR_CMD="${EDITOR:-nano}"
    echo -e "  Opening ${YELLOW}$EDITOR_CMD${NC}..."
    echo -e "  (Write changelog for v$NEW_VERSION, then save and close)"
    echo ""
    $EDITOR_CMD "$TMPFILE"

    CHANGELOG_ENTRY=$(cat "$TMPFILE")
    rm -f "$TMPFILE"
fi

if [ -z "$CHANGELOG_ENTRY" ]; then
    echo -e "${RED}Error: Empty changelog entry. Aborted.${NC}"
    exit 1
fi

echo -e "  ${GREEN}✓${NC} Changelog ready ($(echo "$CHANGELOG_ENTRY" | wc -l) lines)"

# ============================================================
# Step 2: Update files
# ============================================================
echo -e "${CYAN}Step 2: Updating files...${NC}"

# 2a. Update index.php
sed -i "s/define('WEBSHARE_VERSION', '[^']*')/define('WEBSHARE_VERSION', '$NEW_VERSION')/" "$INDEX_PHP"
echo -e "  ${GREEN}✓${NC} index.php → $NEW_VERSION"

# 2b. Update version.json
# Escape double quotes in SHORT_DESC for JSON
JSON_DESC=$(echo "$SHORT_DESC" | sed 's/"/\\"/g')
cat > "$VERSION_JSON" << EOF
{
    "version": "$NEW_VERSION",
    "released": "$TODAY",
    "changelog": "$JSON_DESC",
    "download_url": "https://webshare.techbg.net/"
}
EOF
echo -e "  ${GREEN}✓${NC} version.json → $NEW_VERSION"

# 2c. Update CHANGELOG.md - insert new section after header line
# Build the new section
NEW_SECTION="## [$NEW_VERSION] - $TODAY

$CHANGELOG_ENTRY"

# Create temp file with updated changelog
{
    # Print first 3 lines (header)
    head -3 "$CHANGELOG_MD"
    echo ""
    # Print new section
    echo "$NEW_SECTION"
    echo ""
    # Print rest of file (skip first 3 lines + optional blank line)
    tail -n +4 "$CHANGELOG_MD" | sed '1{/^$/d}'
} > "${CHANGELOG_MD}.tmp"
mv "${CHANGELOG_MD}.tmp" "$CHANGELOG_MD"
echo -e "  ${GREEN}✓${NC} CHANGELOG.md → new section added"

# 2d. Update version history table
TABLE_ROW="|  $NEW_VERSION  | $TODAY | $SHORT_DESC |"
sed -i "/^|---------|/a $TABLE_ROW" "$CHANGELOG_MD"
echo -e "  ${GREEN}✓${NC} CHANGELOG.md → version table updated"

# ============================================================
# Step 3: Show summary and confirm
# ============================================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Summary${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
git diff --stat
echo ""
echo -e "${YELLOW}Changelog:${NC}"
echo "$CHANGELOG_ENTRY"
echo ""
echo -e "Commit: ${GREEN}v$NEW_VERSION - $SHORT_DESC${NC}"
echo ""

if [ "$AUTO_YES" = false ]; then
    read -p "Proceed with commit, push, and GitHub release? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Changes saved locally but NOT committed.${NC}"
        echo "To undo: git checkout -- src/"
        exit 0
    fi
fi

# ============================================================
# Step 4: Git commit & push
# ============================================================
echo -e "${CYAN}Step 3: Committing and pushing...${NC}"

# Add version files + any other changed src files
git add "$INDEX_PHP" "$VERSION_JSON" "$CHANGELOG_MD"

# Show what's being committed
STAGED=$(git diff --cached --name-only 2>/dev/null)
if [ -n "$STAGED" ]; then
    echo -e "  Files:"
    echo "$STAGED" | sed 's/^/    /'
fi

git commit -m "$(cat <<EOF
v$NEW_VERSION - $SHORT_DESC

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
echo -e "  ${GREEN}✓${NC} Committed"

git push
echo -e "  ${GREEN}✓${NC} Pushed"

# ============================================================
# Step 5: Create GitHub release
# ============================================================
echo -e "${CYAN}Step 4: Creating GitHub release...${NC}"

# Delete existing release with same tag if exists
gh release delete "v$NEW_VERSION" --yes 2>/dev/null || true

gh release create "v$NEW_VERSION" \
    --title "v$NEW_VERSION - $SHORT_DESC" \
    --notes "$CHANGELOG_ENTRY"

echo -e "  ${GREEN}✓${NC} Release created"

# ============================================================
# Done
# ============================================================
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  v$NEW_VERSION released successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  GitHub: https://github.com/toshko37/webshare/releases/tag/v$NEW_VERSION"
echo -e "  Servers can now update via live-update."
echo ""
