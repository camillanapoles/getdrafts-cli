#!/usr/bin/env bash
# simforge_iterate.sh — Launch, watch for crash, triage, and report (don't auto-fix).
#
# This script implements the "framework-by-framework iteration" pattern:
# launch the app, capture the crash (if any), run triage, and report
# which binary failed. The user decides what to do next.
#
# Usage:
#     ./simforge_iterate.sh <bundle-id>
#     ./simforge_iterate.sh com.example.app
#     ./simforge_iterate.sh com.example.app --iterations 5
#
# For each iteration:
#   1. Launch the app
#   2. Wait for crash (or N seconds)
#   3. Run simforge_triage.py on the latest crash
#   4. Print which binary failed
#   5. Wait for user to fix and press Enter to retry

set -euo pipefail

BUNDLE_ID="${1:-}"
MAX_ITERATIONS="${2:-3}"
if [[ "${2:-}" == "--iterations" ]]; then
    MAX_ITERATIONS="${3:-3}"
fi

if [[ -z "$BUNDLE_ID" ]]; then
    echo "Usage: $0 <bundle-id> [--iterations N]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== SimForge iteration loop for $BUNDLE_ID (max $MAX_ITERATIONS iterations) ==="
echo "Each iteration: launch → wait for crash → triage → report failing binary."
echo "Press Enter after each fix to retry, or Ctrl+C to exit."
echo ""

for ((i = 1; i <= MAX_ITERATIONS; i++)); do
    echo "--- Iteration $i of $MAX_ITERATIONS ---"

    # Get the latest crash report path BEFORE launching (to know what's "new")
    BEFORE_LAUNCH=$(python3 "$SCRIPT_DIR/simforge_triage.py" --latest --path-only 2>/dev/null || echo "")

    # Launch
    LAUNCH_OUT=$(xcrun simctl launch booted "$BUNDLE_ID" 2>&1) || true
    PID=$(echo "$LAUNCH_OUT" | rg -o ": \d+" | head -1 | rg -o "\d+" || echo "")
    if [[ -n "$PID" ]]; then
        echo "  Launched with PID $PID"
    else
        echo "  Launch output: $LAUNCH_OUT"
    fi

    # Wait for crash
    sleep 4

    # Find the latest crash for this PID
    AFTER_LAUNCH=$(python3 "$SCRIPT_DIR/simforge_triage.py" --latest --path-only 2>/dev/null || echo "")
    CRASH_FILE=""

    if [[ "$AFTER_LAUNCH" != "$BEFORE_LAUNCH" && -n "$AFTER_LAUNCH" ]]; then
        # Verify the crash is for our PID
        if [[ -n "$PID" ]]; then
            CRASH_PID=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        f.readline()
        data = json.load(f)
    print(data.get('pid', ''))
except Exception:
    pass
" "$AFTER_LAUNCH" 2>/dev/null || echo "")
            if [[ "$CRASH_PID" == "$PID" ]]; then
                CRASH_FILE="$AFTER_LAUNCH"
            fi
        fi
    fi

    if [[ -z "$CRASH_FILE" ]]; then
        # Maybe the app didn't crash; check if it's still running
        RUNNING=$(xcrun simctl spawn booted launchctl list 2>/dev/null | \
            rg "app<${BUNDLE_ID//./\\.}>" | wc -l | tr -d ' ')
        if [[ "$RUNNING" -gt 0 ]]; then
            echo "  [OK] App is still running (no crash)"
            echo "=== Done. App is running, no further iterations needed. ==="
            exit 0
        else
            echo "  [INFO] No crash report found; app may have exited cleanly or silently"
        fi
        break
    fi

    echo "  [CRASH] Found: $CRASH_FILE"
    echo ""
    echo "  --- Triage output ---"
    python3 "$SCRIPT_DIR/simforge_triage.py" "$CRASH_FILE" 2>/dev/null | head -50 || true
    echo ""
    echo "  --- End triage ---"
    echo ""

    # If not the last iteration, wait for user input
    if [[ $i -lt $MAX_ITERATIONS ]]; then
        echo "Fix the issue (re-sign, copy a lib, edit Info.plist, etc), then press Enter to relaunch."
        read -r _
    fi
done

echo "=== Done. ==="
