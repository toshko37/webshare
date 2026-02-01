#!/bin/bash
#
# WebShare Update Script
# ======================
# Run from installation directory to update WebShare
#
# Usage:
#   ./update.sh      - Interactive mode
#   ./update.sh -y   - Auto-confirm (no prompts)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get the directory where this script is located
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATE_URL="https://webshare.techbg.net/get-update"

echo -e "${CYAN}"
echo '╦ ╦┌─┐┌┐ ╔═╗┬ ┬┌─┐┬─┐┌─┐'
echo '║║║├┤ ├┴┐╚═╗├─┤├─┤├┬┘├┤ '
echo '╚╩╝└─┘└─┘╚═╝┴ ┴┴ ┴┴└─└─┘'
echo -e "${NC}"
echo -e "${BLUE}Update Script${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./update.sh)${NC}"
    exit 1
fi

# Check if this is a valid WebShare installation
if [ ! -f "$INSTALL_DIR/index.php" ]; then
    echo -e "${RED}Error: WebShare not found in $INSTALL_DIR${NC}"
    echo "Please run this script from the WebShare installation directory."
    exit 1
fi

# Get current version (portable - works without Perl regex)
CURRENT_VERSION=$(grep "WEBSHARE_VERSION" "$INSTALL_DIR/index.php" 2>/dev/null | head -1 | sed "s/.*'\([0-9.]*\)'.*/\1/" || echo "unknown")
echo -e "Current version: ${YELLOW}${CURRENT_VERSION}${NC}"
echo -e "Install directory: ${CYAN}${INSTALL_DIR}${NC}"
echo ""

# Download and run the remote update script
echo -e "${BLUE}Downloading update script...${NC}"

TEMP_SCRIPT=$(mktemp)
if curl -fsSL "$UPDATE_URL" -o "$TEMP_SCRIPT" 2>/dev/null; then
    chmod +x "$TEMP_SCRIPT"
    # Pass arguments and install directory to the remote script
    INSTALL_DIR="$INSTALL_DIR" bash "$TEMP_SCRIPT" "$@"
    rm -f "$TEMP_SCRIPT"
else
    echo -e "${RED}Error: Failed to download update script${NC}"
    echo "Check your internet connection and try again."
    rm -f "$TEMP_SCRIPT"
    exit 1
fi
