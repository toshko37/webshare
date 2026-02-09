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
#   ./release.sh <version> <title> [--hierarchical]
#
# Examples:
#   ./release.sh 3.5.7 "Chat: new feature, bug fix"
#   ./release.sh 3.6.0 "Major redesign" --hierarchical
#
# The script will:
#   - Open your $EDITOR to write changelog details
#   - Show a summary for confirmation before committing
#   - Create git commit, push, and GitHub release
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

# Validate arguments
if [ $# -lt 2 ]; then
    echo -e "${RED}Usage: $0 <version> <short-description>${NC}"
    echo ""
    echo "  version           New version number (e.g. 3.5.7)"
    echo "  short-description One-line summary for version.json and commit"
    echo ""
    echo "Examples:"
    echo "  $0 3.5.7 \"Chat: new feature, bug fix\""
    echo "  $0 3.6.0 \"Major redesign\""
    exit 1
fi

NEW_VERSION="$1"
SHORT_DESC="$2"
TODAY=$(date +%Y-%m-%d)

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

# Check for uncommitted changes (besides what we're about to change)
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Warning: You have uncommitted changes:${NC}"
    git status --short
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# ============================================================
# Step 1: Write changelog entry
# ============================================================
echo -e "${CYAN}Step 1: Writing changelog...${NC}"

TMPFILE=$(mktemp /tmp/changelog-XXXXXX.md)

# Pre-fill template
cat > "$TMPFILE" << 'TEMPLATE'
### Section Title
- **Feature name** - Short description of what it does
  - Additional detail if needed
- **Another change** - Description

TEMPLATE

# Open editor
EDITOR_CMD="${EDITOR:-nano}"
echo -e "Opening ${YELLOW}$EDITOR_CMD${NC} for changelog entry..."
echo -e "(Write the changelog content for v$NEW_VERSION, then save and close)"
echo ""
$EDITOR_CMD "$TMPFILE"

# Read what was written
CHANGELOG_ENTRY=$(cat "$TMPFILE")
rm -f "$TMPFILE"

if [ -z "$CHANGELOG_ENTRY" ] || [ "$CHANGELOG_ENTRY" = "" ]; then
    echo -e "${RED}Error: Empty changelog entry. Aborted.${NC}"
    exit 1
fi

# ============================================================
# Step 2: Update files
# ============================================================
echo -e "${CYAN}Step 2: Updating files...${NC}"

# 2a. Update index.php
sed -i "s/define('WEBSHARE_VERSION', '[^']*')/define('WEBSHARE_VERSION', '$NEW_VERSION')/" "$INDEX_PHP"
echo -e "  ${GREEN}✓${NC} index.php → $NEW_VERSION"

# 2b. Update version.json
cat > "$VERSION_JSON" << EOF
{
    "version": "$NEW_VERSION",
    "released": "$TODAY",
    "changelog": "$SHORT_DESC",
    "download_url": "https://webshare.techbg.net/"
}
EOF
echo -e "  ${GREEN}✓${NC} version.json → $NEW_VERSION"

# 2c. Update CHANGELOG.md - add new section after header
CHANGELOG_HEADER="## [$NEW_VERSION] - $TODAY

$CHANGELOG_ENTRY"

# Insert after "All notable changes..." line
sed -i "/^All notable changes.*$/a\\
\\
$( echo "$CHANGELOG_HEADER" | sed 's/$/\\/' | sed '$ s/\\$//' )" "$CHANGELOG_MD"

# Remove any double blank lines that may have been created
sed -i '/^$/N;/^\n$/d' "$CHANGELOG_MD"
echo -e "  ${GREEN}✓${NC} CHANGELOG.md → new section added"

# 2d. Update version history table
# Find the table header line and add new row after the separator
TABLE_ROW="|  $NEW_VERSION  | $TODAY | $SHORT_DESC |"
sed -i "/^|---------|/a $TABLE_ROW" "$CHANGELOG_MD"
echo -e "  ${GREEN}✓${NC} CHANGELOG.md → version table updated"

# ============================================================
# Step 3: Show summary and confirm
# ============================================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Summary of changes${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
git diff --stat
echo ""
echo -e "${YELLOW}Changelog entry:${NC}"
echo "$CHANGELOG_ENTRY"
echo ""
echo -e "Commit message: ${GREEN}v$NEW_VERSION - $SHORT_DESC${NC}"
echo ""

read -p "Proceed with commit, push, and GitHub release? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Changes are saved locally but NOT committed.${NC}"
    echo "You can review and commit manually, or run: git checkout -- src/"
    exit 0
fi

# ============================================================
# Step 4: Git commit & push
# ============================================================
echo -e "${CYAN}Step 3: Committing and pushing...${NC}"

git add "$INDEX_PHP" "$VERSION_JSON" "$CHANGELOG_MD"

# Also add any other staged changes
STAGED=$(git diff --cached --name-only 2>/dev/null)
if [ -n "$STAGED" ]; then
    echo -e "  Files to commit:"
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
