#!/usr/bin/env bash

################################################################################
# iOS App Security Audit - Preflight Check Script (Wrapper)
# Description: Wrapper for Python preflight check tool
# Author: ios-app-security-audit skill
# Version: 1.0.0
# Usage: ./preflight-check.sh [args]
#
# This is a DRY wrapper that delegates to the Python core script.
# If Python is not available, it performs a minimal check and recommends
# installing Python for full functionality.
################################################################################

set -euo pipefail

# Color codes
RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if python3 is available
if command -v python3 &>/dev/null; then
    # Delegate to Python core script
    python3 "$SCRIPT_DIR/preflight_check.py" "$@"
    exit $?
fi

# Fallback: Python not available, perform minimal check
echo ""
echo "${BLUE}========================================${RESET}"
echo "${BLUE}  iOS App Security Audit - Preflight Check  ${RESET}"
echo "${BLUE}========================================${RESET}"
echo ""
echo "${YELLOW}⚠️  Python 3 not found${RESET}"
echo "${YELLOW}    For full preflight check functionality, install Python 3:${RESET}"
echo "${BLUE}    brew install python@3${RESET}     # macOS"
echo "${BLUE}    sudo apt install python3${RESET}   # Debian/Ubuntu"
echo "${BLUE}    sudo pacman -S python${RESET}      # Arch"
echo ""
echo "${BLUE}Performing minimal tool check...${RESET}"
echo ""

# Minimal critical tools check (platform-native only)
minimal_missing=0

# Check for basic tools
check_minimal() {
    local tool=$1
    local critical=$2

    if command -v "$tool" &>/dev/null; then
        echo "${GREEN}✅${RESET} $tool found"
    else
        echo "${RED}❌${RESET} $tool missing"
        if [ "$critical" = "true" ]; then
            minimal_missing=$((minimal_missing + 1))
        fi
    fi
}

echo "${BLUE}Basic Tools:${RESET}"
check_minimal "grep" "true"
check_minimal "frida" "true" 2>/dev/null || true
if [[ "$(uname -s)" == "Darwin" ]]; then
    check_minimal "otool" "true" 2>/dev/null || check_minimal "objdump" "true"
    check_minimal "codesign" "false" 2>/dev/null || true
    check_minimal "security" "false" 2>/dev/null || true
fi
echo ""

# The device toolchain is the same set the Python core checks as CRITICAL.
# Without it the fallback used to report "basic tools available" while the
# core would have failed, so the two paths disagreed on the same machine.
echo "${BLUE}Device Toolchain (libimobiledevice):${RESET}"
check_minimal "ideviceinfo" "true" 2>/dev/null || true
check_minimal "idevicepair" "true" 2>/dev/null || true
check_minimal "ideviceinstaller" "false" 2>/dev/null || true
check_minimal "idevicesyslog" "false" 2>/dev/null || true
check_minimal "afcclient" "false" 2>/dev/null || true
echo ""

# Summary
echo "${BLUE}========================================${RESET}"
if [ $minimal_missing -eq 0 ]; then
    echo "${GREEN}✅ Basic tools available${RESET}"
    echo "${YELLOW}⚠️  Install Python 3 for complete preflight check${RESET}"
    exit 0
else
    echo "${RED}❌ Critical tools missing${RESET}"
    echo "${YELLOW}⚠️  Install Python 3 for complete preflight check${RESET}"
    exit 1
fi
