#!/usr/bin/env bash

################################################################################
# iOS Screenshot Extractor (Wrapper)
# Description: Extract SplashBoard snapshots from iOS simulator or device
# Author: iOS-Pentesting-Skill
# Version: 1.0.0
# Usage: ./screenshot-extractor.sh <bundle_id> [output_dir]
#
# This is a DRY wrapper that detects the environment (simulator vs device)
# and delegates to the appropriate Python core script.
################################################################################

set -euo pipefail

# Colors
GREEN=$(tput setaf 2 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print usage
usage() {
    echo "${BLUE}Usage:${RESET} $0 <bundle_id> [output_dir]"
    echo ""
    echo "${BLUE}Arguments:${RESET}"
    echo "  bundle_id   Bundle ID of the app (e.g., com.example.app)"
    echo "  output_dir  Output directory for screenshots (default: ./screenshots)"
    echo ""
    echo "${BLUE}Examples:${RESET}"
    echo "  $0 com.example.app"
    echo "  $0 com.example.app /path/to/output"
    echo ""
    exit 1
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

BUNDLE_ID="$1"
OUTPUT_DIR="${2:-./screenshots}"

# Check if python3 is available
if ! command -v python3 &>/dev/null; then
    echo "${RED}[!] Python 3 not found${RESET}"
    echo "${YELLOW}[*] Please install Python 3 to use this script${RESET}"
    exit 1
fi

# Detect environment (simulator vs device)
if xcrun simctl list devices 2>/dev/null | grep -q "Booted"; then
    # Simulator detected
    echo "${GREEN}[*] Simulator detected${RESET}"
    python3 "$SCRIPT_DIR/screenshot_extractor_sim.py" "$BUNDLE_ID" "$OUTPUT_DIR"
elif command -v idevice_id &>/dev/null && idevice_id -l 2>/dev/null | grep -q .; then
    # Device detected (via libimobiledevice)
    echo "${GREEN}[*] iOS device detected${RESET}"
    python3 "$SCRIPT_DIR/screenshot_extractor_device.py" "$BUNDLE_ID" "$OUTPUT_DIR"
else
    echo "${YELLOW}[!] No booted simulator or connected device found${RESET}"
    echo "${YELLOW}[*] Please either:${RESET}"
    echo "    - Boot an iOS simulator with Xcode"
    echo "    - Connect a jailbroken device with libimobiledevice"
    exit 1
fi
