#!/usr/bin/env bash
# Build the gomobile AAR from the Go core boundary and drop it into app/libs.
#
# Requirements:
#   - Go 1.21+ (matches go.mod)
#   - Android NDK (gomobile downloads/uses it) — or rely on gomobile's bundled toolchain
#   - `go install golang.org/x/mobile/cmd/gomobile@latest`
#
# Usage:
#   bash android/core-go/build-core.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

mkdir -p android/app/libs

if ! command -v gomobile >/dev/null 2>&1; then
  echo "gomobile not found. Installing..." 
  go install golang.org/x/mobile/cmd/gomobile@latest
fi

echo "Binding android/core-go -> android/app/libs/drafto.aar"
gomobile bind -target=android -o=android/app/libs/drafto.aar ./android/core-go

echo "Done: android/app/libs/drafto.aar"
echo "Uncomment the AAR dependency in app/build.gradle.kts and switch"
echo "EngineFactory to GoDraftoEngine to use the native engine."
