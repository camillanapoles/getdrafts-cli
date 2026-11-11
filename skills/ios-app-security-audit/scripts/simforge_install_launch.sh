#!/usr/bin/env bash
# simforge_install_launch.sh — Boot simulator, install .app, launch, and stream logs.
#
# Usage:
#     ./simforge_install_launch.sh <bundle-id> <path-to-app>
#     ./simforge_install_launch.sh com.example.app /path/to/Payload/YourApp.app
#     ./simforge_install_launch.sh com.example.app /path/to/YourApp.app --no-launch
#     ./simforge_install_launch.sh com.example.app /path/to/YourApp.app --headless
#     (default is visible; use --headless only if you want it in the background)
#
# Steps:
#   1. Boot a simulator (if none booted)
#   2. Install the .app
#   3. Verify the container exists
#   4. Launch the app
#   5. Print the latest crash report path (if any) and tail its reason
#
# Visibility:
#   By default the simulator is launched **visible**.
#   Use --headless only if you explicitly want it in the background.
#   --visible can be used to force visible mode (same as default).

set -euo pipefail

# Directory of this script, so the sibling helpers can be invoked by path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUNDLE_ID="${1:-}"
APP_PATH="${2:-}"
NO_LAUNCH=""
VISIBILITY=""

if [[ -z "$BUNDLE_ID" || -z "$APP_PATH" ]]; then
    echo "Usage: $0 <bundle-id> <path-to-app> [--no-launch] [--headless]"
    exit 1
fi

# Parse remaining flags
for arg in "${@:3}"; do
    case "$arg" in
        --no-launch) NO_LAUNCH="--no-launch" ;;
        --headless) VISIBILITY="headless" ;;
        --visible)  VISIBILITY="visible" ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# If no flag given, default to visible
if [[ -z "$VISIBILITY" ]]; then
    VISIBILITY="visible"
fi

# Pick a simulator: prefer iPhone 17 Pro, fall back to any iPhone
DEVICE_NAME=$(xcrun simctl list devices available 2>/dev/null | \
    rg "iPhone \d+ Pro \(" | head -1 | sed 's/^\s*//' | cut -d'(' -f1 | xargs)
if [[ -z "$DEVICE_NAME" ]]; then
    DEVICE_NAME=$(xcrun simctl list devices available 2>/dev/null | \
        rg "iPhone \w+ \(" | head -1 | sed 's/^\s*//' | cut -d'(' -f1 | xargs)
fi

if [[ -z "$DEVICE_NAME" ]]; then
    echo "ERROR: No iPhone simulator available. Run 'xcrun simctl list devices available'"
    exit 1
fi

echo "=== Using simulator: $DEVICE_NAME (visibility: $VISIBILITY) ==="

# Step 1: Boot
echo "[1/5] Booting simulator..."
if ! xcrun simctl list devices booted 2>/dev/null | rg -q "Booted"; then
    xcrun simctl boot "$DEVICE_NAME"
    sleep 3
    echo "  [OK] Booted"
else
    echo "  [OK] Already booted"
fi

# If user wants the UI visible, open Simulator.app
if [[ "$VISIBILITY" == "visible" ]]; then
    if ! pgrep -f "Simulator.app" > /dev/null 2>&1; then
        open -a Simulator
        sleep 2
        echo "  [OK] Simulator.app UI opened"
    else
        echo "  [OK] Simulator.app already running"
    fi
fi

# Step 2: Install
echo "[2/5] Installing $APP_PATH..."
xcrun simctl install booted "$APP_PATH"
echo "  [OK] Installed"

# Step 3: Verify container
echo "[3/5] Verifying container..."
CONTAINER=$(xcrun simctl get_app_container booted "$BUNDLE_ID" 2>/dev/null || echo "")
if [[ -z "$CONTAINER" ]]; then
    echo "  [FAIL] Container not found for $BUNDLE_ID"
    exit 1
fi
echo "  [OK] Container: $CONTAINER"

if [[ -n "$NO_LAUNCH" ]]; then
    echo "[4/5] --no-launch specified, skipping launch"
    echo "[5/5] Skipped"
    exit 0
fi

# Step 4: Launch
echo "[4/5] Launching $BUNDLE_ID..."
LAUNCH_OUT=$(xcrun simctl launch booted "$BUNDLE_ID" 2>&1)
LAUNCH_EXIT=$?
echo "$LAUNCH_OUT"
if [[ $LAUNCH_EXIT -ne 0 ]]; then
    echo "  [FAIL] Launch returned exit $LAUNCH_EXIT"
    # Try to extract a useful crash report anyway
fi

# Extract PID if present
PID=$(echo "$LAUNCH_OUT" | rg -o ": \d+" | head -1 | rg -o "\d+" || echo "")

sleep 3

# Step 5: Check for crash and report
echo "[5/5] Checking for crash report..."
LATEST_CRASH=$(python3 "$SCRIPT_DIR/simforge_triage.py" --latest --path-only 2>/dev/null || echo "")
if [[ -n "$LATEST_CRASH" ]]; then
    # Check if this crash is for our process
    CRASH_PID=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        f.readline()
        data = json.load(f)
    print(data.get('pid', ''))
except Exception:
    pass
" "$LATEST_CRASH" 2>/dev/null || echo "")
    if [[ -n "$CRASH_PID" && "$CRASH_PID" == "$PID" ]]; then
        echo "  [FAIL] Crash report found for our PID $PID"
        echo "  Latest crash: $LATEST_CRASH"
        echo ""
        echo "  Run: python3 scripts/simforge_triage.py \"$LATEST_CRASH\""
    else
        echo "  [OK] No crash for our PID (or crash is for another process)"
        echo "  Latest crash for any process: $LATEST_CRASH"
    fi
else
    echo "  [OK] No crash reports found"
fi

echo ""
echo "=== Done. ==="
echo "If the app is running, connect with: frida -U $BUNDLE_ID"
