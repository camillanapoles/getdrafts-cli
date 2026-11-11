#!/usr/bin/env bash

################################################################################
# iOS App Static Analysis Quick Script
# Description: Perform quick static analysis on iOS app (IPA or .app)
# Author: iOS-Pentesting-Skill
# Version: 1.0.0
# Usage: ./quick-static-analysis.sh <path_to_ipa_or_app>
################################################################################

set -euo pipefail

GREEN=$(tput setaf 2 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")

TARGET_PATH="$1"

if [ -z "$TARGET_PATH" ]; then
    echo "${RED}[!] Usage: $0 <path_to_ipa_or_app>${RESET}"
    exit 1
fi

echo "${BLUE}[*] iOS App Static Analysis${RESET}"
echo "${BLUE}[*] Target: $TARGET_PATH${RESET}"
echo ""

# Extract if IPA
if [[ "$TARGET_PATH" == *.ipa ]]; then
    EXTRACT_DIR=$(mktemp -d)
    echo "${BLUE}[*] Extracting IPA...${RESET}"
    unzip -q "$TARGET_PATH" -d "$EXTRACT_DIR"
    APP_PATH=$(find "$EXTRACT_DIR/Payload" -name "*.app" -type d | head -1)
else
    APP_PATH="$TARGET_PATH"
fi

if [ ! -d "$APP_PATH" ]; then
    echo "${RED}[!] Invalid app path${RESET}"
    exit 1
fi

BINARY_NAME=$(basename "$APP_PATH" .app)
BINARY_PATH="$APP_PATH/$BINARY_NAME"

echo "${GREEN}[+] Binary: $BINARY_PATH${RESET}"
echo ""

# Architecture
echo "${BLUE}[*] Architecture:${RESET}"
lipo -info "$BINARY_PATH" 2>/dev/null || file "$BINARY_PATH"
echo ""

# Encryption
echo "${BLUE}[*] Encryption Status:${RESET}"
otool -l "$BINARY_PATH" | rg -A 5 "LC_ENCRYPTION" | rg "cryptid"
if otool -l "$BINARY_PATH" | rg -q "cryptid 1"; then
    echo "${RED}[!] Binary is ENCRYPTED${RESET}"
else
    echo "${GREEN}[+] Binary is NOT encrypted${RESET}"
fi
echo ""

# Info.plist
if [ -f "$APP_PATH/Info.plist" ]; then
    echo "${BLUE}[*] Info.plist Analysis:${RESET}"

    # Bundle ID
    BUNDLE_ID=$(plutil -p "$APP_PATH/Info.plist" 2>/dev/null | rg "CFBundleIdentifier" | rg -o "\"[^\"]+\"" | tr -d '"' | head -1)
    echo "  Bundle ID: $BUNDLE_ID"

    # URL Schemes
    echo ""
    echo "${BLUE}[*] URL Schemes:${RESET}"
    plutil -p "$APP_PATH/Info.plist" 2>/dev/null | rg -A 10 "CFBundleURLTypes" | rg "CFBundleURLSchemes" -A 5 || echo "  No URL schemes"

    # ATS
    echo ""
    echo "${BLUE}[*] App Transport Security:${RESET}"
    if plutil -p "$APP_PATH/Info.plist" 2>/dev/null | rg -q "NSAllowsArbitraryLoads.*true"; then
        echo "${RED}[!] NSAllowsArbitraryLoads is TRUE${RESET}"
    else
        echo "${GREEN}[+] ATS is properly configured${RESET}"
    fi

    # Permissions
    echo ""
    echo "${BLUE}[*] Permissions:${RESET}"
    plutil -p "$APP_PATH/Info.plist" 2>/dev/null | rg "NS.*UsageDescription" | head -10
fi

echo ""
echo "${BLUE}[*] Quick Secrets Scan:${RESET}"
strings "$BINARY_PATH" | rg -i "sk_[a-z0-9]{32}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}" | head -5 || echo "  No obvious secrets found"

echo ""
echo "${GREEN}[+] Analysis complete${RESET}"

# Cleanup
if [ -n "${EXTRACT_DIR:-}" ]; then
    rm -rf "$EXTRACT_DIR"
fi
