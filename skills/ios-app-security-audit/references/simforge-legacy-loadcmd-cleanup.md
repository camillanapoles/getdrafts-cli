# SimForge Legacy Load Command Cleanup

## Overview

When converting arm64 iOS apps for simulator testing, **SimForge** adds `LC_BUILD_VERSION` with `platform 7` (iOS Simulator) but does **NOT** remove the legacy `LC_VERSION_MIN_IPHONEOS` load command. This creates binaries with **both** load commands, which modern dyld rejects, causing crashes.

This guide explains how to detect and fix this issue using LIEF.

## The Problem

### What Happens

```
Original Framework:
  LC_VERSION_MIN_IPHONEOS (version 10.0, sdk 18.5)

After SimForge convert:
  LC_VERSION_MIN_IPHONEOS (version 10.0, sdk 18.5)  ← Still there!
  LC_BUILD_VERSION (platform 7, minos 14.0, sdk 14.0)  ← Added by SimForge

Result: dyld assertion failure or SIGSEGV on launch
```

### Why It Matters

- **Third-party frameworks** (OneSignal, Facebook SDK, biometric SDKs) often use legacy load commands
- **SimForge** doesn't automatically clean them up
- **Modern dyld** (iOS 17.5+) rejects binaries with mixed version commands
- **Symptom**: App installs successfully but crashes immediately on launch

## Detection

### Step 1: Scan for Mixed Load Commands

```bash
# Check a single binary
otool -l Framework.framework/Binary | grep -A3 "LC_VERSION_MIN\|LC_BUILD"

# Expected good output:
#   cmd LC_BUILD_VERSION
#  platform 7

# Bad output (has both):
#   cmd LC_VERSION_MIN_IPHONEOS
#  version 10.0
#   cmd LC_BUILD_VERSION
#  platform 7
```

### Step 2: Scan All Binaries in an App

```bash
#!/bin/bash
APP_PATH="Payload/YourApp.app"

echo "Scanning for mixed load commands..."
for binary in "$APP_PATH" "$APP_PATH"/Frameworks/*/*.*/ "$APP_PATH"/PlugIns/*/*.*/; do
    if [ -f "$binary" ]; then
        has_version=$(otool -l "$binary" 2>/dev/null | grep -c "LC_VERSION_MIN_IPHONEOS")
        has_build=$(otool -l "$binary" 2>/dev/null | grep -c "LC_BUILD_VERSION")

        if [ "$has_version" -gt 0 ] && [ "$has_build" -gt 0 ]; then
            echo "❌ MIXED: $binary"
        elif [ "$has_build" -gt 0 ]; then
            echo "✅ OK: $binary"
        fi
    fi
done
```

## Solution: LIEF Cleanup

### Using the Provided Script

```bash
# From the scripts directory
python3 simforge_cleanup.py Path/to/app.app
```

### Manual LIEF Cleanup

```python
#!/usr/bin/env python3
import lief
import sys

def cleanup_legacy_loadcmd(binary_path):
    """Remove LC_VERSION_MIN_IPHONEOS if LC_BUILD_VERSION exists."""
    binary = lief.parse(binary_path)
    if not binary:
        print(f"❌ ERROR: Cannot parse {binary_path}")
        return False

    # Check if binary has both commands
    has_version_min = any(
        cmd.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS
        for cmd in binary.commands
    )
    has_build_version = any(
        cmd.command == lief.MachO.LoadCommand.TYPE.BUILD_VERSION
        for cmd in binary.commands
    )

    if not has_version_min:
        print(f"  ✅ {binary_path}: No LC_VERSION_MIN_IPHONEOS (OK)")
        return False

    if not has_build_version:
        print(f"  ⚠️  {binary_path}: Has LC_VERSION_MIN but no LC_BUILD_VERSION (skip)")
        return False

    # Remove LC_VERSION_MIN_IPHONEOS commands
    version_min_indices = [
        idx for idx, cmd in enumerate(binary.commands)
        if cmd.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS
    ]

    print(f"  📌 {binary_path}: Removing {len(version_min_indices)} LC_VERSION_MIN_IPHONEOS")

    # Remove in reverse order to avoid index shifting
    for idx in reversed(version_min_indices):
        binary.remove_command(idx)

    # Write back
    binary.write(binary_path)
    print(f"  ✅ {binary_path}: Cleaned")
    return True

if __name__ == "__main__":
    for path in sys.argv[1:]:
        cleanup_legacy_loadcmd(path)
```

### Usage Example

```bash
# After SimForge conversion
simforge convert Payload/YourApp.app

# Cleanup legacy load commands
python3 cleanup_legacy.py \
    Payload/YourApp.app/YourApp \
    Payload/YourApp.app/Frameworks/OneSignal.framework/OneSignal \
    Payload/YourApp.app/Frameworks/FPBExtractoriOS.framework/FPBExtractoriOS

# Re-sign
codesign -f -s - --all-architectures Payload/YourApp.app

# Install and test
xcrun simctl install booted Payload/YourApp.app
xcrun simctl launch booted com.example.app
```

## Common Frameworks Affected

| Framework | Common In | Symptoms |
|-----------|-----------|----------|
| OneSignal* (all variants) | React Native, Flutter | Crash on init |
| FPBExtractoriOS | Biometric auth apps | dyld assertion |
| Microblink | OCR/document apps | SIGSEGV |
| Facebook SDK* | Social apps | Crash in SDK init |
| Legacy Bolts/Parse | Older RN apps | Early crash |

## Verification

### Post-Cleanup Check

```bash
# Verify all binaries have ONLY LC_BUILD_VERSION
for binary in app.app/*.app app.app/Frameworks/*/*.*/ app.app/PlugIns/*/*.*/; do
    if [ -f "$binary" ]; then
        name=$(basename "$binary")
        result=$(otool -l "$binary" 2>/dev/null | grep "LC_VERSION_MIN_IPHONEOS")
        if [ -n "$result" ]; then
            echo "❌ $name: Still has LC_VERSION_MIN_IPHONEOS"
        else
            echo "✅ $name: Clean"
        fi
    fi
done
```

### Expected Output

```
✅ YourApp: Clean
✅ OneSignalCore: Clean
✅ FPBExtractoriOS: Clean
✅ Microblink: Clean
```

## Integration with SimForge Workflow

### Complete Workflow

```bash
# 1. Convert with SimForge
simforge convert Payload/YourApp.app

# 2. Cleanup legacy load commands (NEW STEP)
python3 simforge_cleanup.py Payload/YourApp.app

# 3. Re-sign
codesign -f -s - --all-architectures Payload/YourApp.app/Frameworks/*/*.*
codesign -f -s - --all-architectures Payload/YourApp.app

# 4. Install
xcrun simctl install booted Payload/YourApp.app

# 5. Launch
xcrun simctl launch booted com.example.app
```

## Troubleshooting

### "Binary cannot be parsed"

**Cause**: Binary is encrypted or corrupted.

**Solution**:
```bash
# Check encryption
otool -l Binary | grep -A3 "LC_ENCRYPTION"
# If cryptid is 1, decrypt with frida-ios-dump first
```

### "Still crashes after cleanup"

**Possible causes**:
1. **Not all binaries were cleaned** - Scan again with detection script
2. **Code signature broken** - Re-sign with `--all-architectures`
3. **Simulator OS mismatch** - Try different iOS runtime

**Diagnostic**:
```bash
# Check crash log
log show --predicate 'process == "YourApp"' --last 2m
# Or for iOS 17.5+
xcrun simctl spawn booted log show --predicate 'process == "YourApp"'
```

### "Framework not found after cleanup"

**Cause**: LIEF wrote to wrong path or binary was renamed.

**Solution**: Verify framework structure matches:
```
Framework.framework/
├── Framework (binary)
├── Info.plist
└── _CodeSignature/
```

## Advanced: Batch Processing

### Process Multiple IPAs

```bash
#!/bin/bash
for ipa in *.ipa; do
    echo "Processing $ipa..."

    # Extract
    unzip -q "$ipa" -d "${ipa%.ipa}"
    app_path=$(find "${ipa%.ipa}/Payload" -name "*.app" -type d | head -1)

    # SimForge
    simforge convert "$app_path"

    # Cleanup (simforge_cleanup.py handles all binaries)
    python3 simforge_cleanup.py "$app_path"

    # Re-sign
    codesign -f -s - --all-architectures "$app_path"

    # Repackage
    cd "${ipa%.ipa}"
    zip -qr "../${ipa%.ipa}_fixed.ipa" Payload/
    cd ..

    echo "✅ ${ipa%.ipa}_fixed.ipa ready"
done
```

## References

- [SimForge iOS Testing Guide](simforge-ios-testing.md) - Main SimForge workflow
- [SimForge Crash Triage](simforge-crash-triage.md) - Crash diagnosis
- [Mach-O Load Commands](macho-binary-analysis.md) - Deep dive into binary structure

## Version History

- **2024-06**: Documented LC_VERSION_MIN_IPHONEOS + LC_BUILD_VERSION issue
- **2024-06**: Added simforge_cleanup.py script
