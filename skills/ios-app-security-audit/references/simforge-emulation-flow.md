# iOS App → iOS Simulator Emulation: Canonical Flow

> Canonical case-agnostic procedure for running an iOS .app on the simulator. This is the "happy path" + the decision points where it can fail. For specific failures, consult `simforge-crash-triage.md` (how to diagnose) and `simforge-compatibility.md` (which SDK/Swift/SimRuntime combinations work).

## Prerequisites

| Requirement | Verification |
|---|---|
| Apple Silicon (arm64) | `uname -m` must return `arm64` |
| Xcode + iOS Simulator runtime | `xcrun simctl list runtimes` |
| Simulator available | `xcrun simctl list devices available` |
| SimForge compiled | `which simforge` or in `~/.local/bin/simforge` |
| vtool (included with Xcode) | `which vtool` |
| **IPA already decrypted** | `otool -l <bin> \| rg -A 1 LC_ENCRYPTION` → `cryptid 0` in the main binary |

> **If the IPA is encrypted (FairPlay):** the simulator CANNOT run it. You need to decrypt it first with `frida-ios-dump` or `bagbak` on a jailbroken physical device. See `simforge-compatibility.md` §"FairPlay / App Store encryption".

### Pre-flight check (execute BEFORE the main flow)

Five 5-second checks that save hours of troubleshooting:

```bash
APP="<path-to-extracted-app>"
BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"

# 1. Is arm64 non-fat? (if not, lipo -thin arm64)
file "$BIN" | rg -q "arm64" || { echo "FAIL: not arm64"; exit 1; }

# 2. Is it decrypted? (cryptid 1 = FairPlay, simulator cannot run it)
otool -l "$BIN" | rg -A 4 LC_ENCRYPTION | rg "cryptid\s+1" \
  && { echo "FAIL: FairPlay encrypted, dump it first"; exit 1; } \
  || echo "OK: decrypted"

# 3. Does Info.plist say "iPhoneOS"? (must be changed to iPhoneSimulator)
plutil -extract CFBundleSupportedPlatforms raw "$APP/Info.plist" | rg -q "iPhoneOS" \
  && echo "WARN: needs CFBundleSupportedPlatforms patch" \
  || echo "OK: already simulator"

# 4. Is there LC_VERSION_MIN_IPHONEOS legacy? (needs vtool in Step 3)
LEGACY=0
for f in "$BIN" $(find "$APP/Frameworks" -type f \( -path "*/*.framework/*" -not -path "*Info.plist" -not -path "*_CodeSignature*" \) 2>/dev/null); do
  [ -f "$f" ] && otool -l "$f" 2>/dev/null | rg -q "LC_VERSION_MIN_IPHONEOS" && LEGACY=$((LEGACY+1))
done
[ $LEGACY -gt 0 ] && echo "INFO: $LEGACY legacy binaries need vtool" || echo "OK: no legacy binaries"

# 5. Is Swift ABI compatible with host toolchain? (subtler crash cause)
APP_SWIFT_VER=$(otool -L "$BIN" 2>/dev/null | rg "libswiftCore.dylib" | rg -o "current version [0-9.]+" | head -1 | awk '{print $3}')
HOST_SWIFT_VER=$(otool -L "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib" 2>/dev/null | rg -o "current version [0-9.]+" | head -1 | awk '{print $3}')
if [ -z "$APP_SWIFT_VER" ]; then
  echo "OK: app is pure ObjC (no Swift ABI dependency)"
elif [ -z "$HOST_SWIFT_VER" ]; then
  echo "WARN: cannot detect host Swift version"
elif [ "$APP_SWIFT_VER" = "0.0.0" ] || [ "$HOST_SWIFT_VER" = "0.0.0" ]; then
  echo "OK: Swift version comparison inconclusive (one side is 0.0.0)"
elif [ "$APP_SWIFT_VER" = "$HOST_SWIFT_VER" ]; then
  echo "OK: Swift ABI matches ($APP_SWIFT_VER)"
else
  echo "FAIL: Swift ABI mismatch (app=$APP_SWIFT_VER, host=$HOST_SWIFT_VER)"
  echo "      See simforge-compatibility.md §2. Likely needs older Xcode."
fi
```

If check #2 (FairPlay) fails: **the simulator cannot run the app** without decrypting first. Exit and obtain a dump with Frida.

If check #5 (Swift ABI) fails: **the simulator cannot run the app** without older Xcode. See `simforge-compatibility.md` §2 for workarounds.

Expected output for an IPA ready for the flow:
```
OK: decrypted
WARN: needs CFBundleSupportedPlatforms patch   (this is normal, Step 4 fixes it)
INFO: 3 legacy binaries need vtool            (normal, Step 3 fixes it)
OK: Swift ABI matches (5.9.0)                  (or "pure ObjC")
```

---

## The 10-Step Canonical Flow

### Step 0 — Backup (DO NOT SKIP)

All patching tools (simforge, vtool) are **in-place destructive** on files. Make backup BEFORE touching anything.

```bash
WORK=/tmp/"<appname>"-work && mkdir -p "$WORK/extracted"
unzip -q /path/to/"<appname>".ipa -d "$WORK/extracted"
APP="$WORK/extracted/Payload/<AppName>.app"
cp -R "$APP" "$WORK/<AppName>.app.original-backup"
```

> **Rule**: if you ever cannot return to the original state, abort.

### Step 1 — Inspect (don't patch blindly)

Before touching anything, understand what you're patching. This determines if the app is "easy" (all modern binaries) or "hard" (legacy frameworks).

```bash
# Main binary
otool -l "$APP/<AppName>" | rg -A 4 "LC_(BUILD_VERSION|VERSION_MIN)"
# Embedded frameworks
for fw in "$APP/Frameworks/"*.framework; do
  binary="$fw/$(basename $fw .framework)"
  echo "=== $(basename $fw) ==="
  otool -l "$binary" 2>/dev/null | rg -A 4 "LC_(BUILD_VERSION|VERSION_MIN)"
done
```

**Classify**:

| Pattern observed | Profile | Expectation |
|---|---|---|
| Only `LC_BUILD_VERSION` in all binaries | **Modern** | Standard flow almost always works |
| Mix of `LC_BUILD_VERSION` and `LC_VERSION_MIN_IPHONEOS` | **Migrated** | Needs `vtool -set-version-min` on legacy ones |
| Some binaries with `LC_VERSION_MIN_IPHONEOS` with `version < 13.0` | **Legacy** | Likely Swift ABI incompatibility → see `simforge-compatibility.md` |
| Binaries with `LC_ENCRYPTION_INFO_64 cryptid 1` | **Encrypted (FairPlay)** | **STOP.** Simulator cannot run this. Decrypt first (see pre-flight check) |

### Step 2 — simforge convert

Patch `LC_BUILD_VERSION` → `PLATFORM_IOSSIMULATOR (7)` in all Mach-O. Recursive over the bundle.

```bash
simforge convert "$APP"
```

Verify (all must say `platform 7`):

```bash
for f in "$APP/<AppName>" $(find "$APP/Frameworks" -type f \( -path "*/*.framework/*" -not -path "*Info.plist" -not -path "*_CodeSignature*" \) 2>/dev/null); do
  [ -f "$f" ] && otool -l "$f" 2>/dev/null | rg -A 1 "LC_BUILD_VERSION" | rg "platform 7" >/dev/null || echo "NOT_CONVERTED: ${f#$APP/}"
done
```

### Step 3 — vtool align (only if Step 1 found `LC_VERSION_MIN_IPHONEOS`)

Legacy frameworks (compiled with Xcode < 13) have `LC_VERSION_MIN_IPHONEOS` saying "iOS device X.Y". Without alignment, the modern simulator dyld rejects the binary. Use the **same minos/sdk** declared in the original `LC_BUILD_VERSION` (or that of the main binary if none).

```bash
# Detect binaries with LC_VERSION_MIN_IPHONEOS
LEGACY_BINS=$(for f in "$APP/<AppName>" $(find "$APP/Frameworks" -type f \( -path "*/*.framework/*" -not -path "*Info.plist" -not -path "*_CodeSignature*" \) 2>/dev/null); do
  [ -f "$f" ] && otool -l "$f" 2>/dev/null | rg -q "LC_VERSION_MIN_IPHONEOS" && echo "$f"
done)

# Patch with vtool (NAME ios, NOT iphonesimulator)
for f in $LEGACY_BINS; do
  vtool -arch arm64 -set-version-min ios "<MINOS>" "<SDK>" -output "$f" "$f" 2>/dev/null
done
```

> **Critical order**: `vtool` invalidates codesig. ALWAYS re-sign after (Step 5).
>
> **⚠️ CAUTION — vtool can corrupt binaries in large apps**: In apps with many frameworks (>=15 frameworks or >=20 Mach-O binaries), applying `vtool` IN ADDITION to `simforge` can create binaries that pass `codesign -v --strict` and `otool -l` but `installd` rejects with `Assertion failed: (err.noError()), function platformAndVersions_block_invoke, file Header.cpp, line 336`. Likely cause: vtool invalidates the signature in a context where simforge already modified internal offsets, and the updated signature ends up with string tables pointing to rotated offsets.
>
> **Workaround**: if `simctl install` fails with `installd` crashing at `Header.cpp:336`:
> 1. Re-extract the IPA from the original.
> 2. **Skip Step 3 completely** (do not use vtool). Only simforge + Info.plist + re-sign.
> 3. For most modern apps (all binaries with `LC_BUILD_VERSION`), `simforge convert` is sufficient — the legacy `LC_VERSION_MIN_IPHONEOS` is only a problem in very old frameworks (Xcode < 13).
>
> **Practical rule**: if the app is from 2023 onwards, **skip Step 3**. If older and frameworks don't convert with simforge alone, try vtool with `vtool -set-build-version 7 18.0 18.0` AND `vtool -set-version-min ios 18.0 18.0` in the SAME batch, and verify that `simctl install` doesn't fail before proceeding.

### Step 4 — Patch `CFBundleSupportedPlatforms` in Info.plists

Modern dyld verifies the bundle's `Info.plist` **AND each framework's**. Both must declare `iPhoneSimulator`.

```bash
# Main bundle
plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' "$APP/Info.plist"

# All frameworks and appex
find "$APP" -name "Info.plist" -path "*/*.framework/Info.plist" -exec \
  plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' {} \;
find "$APP" -name "Info.plist" -path "*/*.appex/Info.plist" -exec \
  plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' {} \;
```

### Step 5 — Re-sign (manual, 4 sub-steps)

**Universal rule**: `codesign --deep` alone is NOT enough. Re-sign the **internal binaries** of frameworks explicitly. The original App Store signature becomes "orphaned" if not removed first.

```bash
# 5.1 Remove ALL existing signatures (may be from App Store)
find "$APP" -type f \( -name "*.dylib" -o -name "$APP_BIN_NAME" -path "*.appex/*" \) \
  -exec codesign --remove-signature {} \;
for fw in "$APP/Frameworks/"*.framework "$APP/PlugIns/"*.appex; do
  [ -d "$fw" ] && codesign --remove-signature "$fw"
done
codesign --remove-signature "$APP"

# 5.2 Sign internal binaries of each framework (what dyld validates)
for fw in "$APP/Frameworks/"*.framework; do
  fw_name=$(basename $fw .framework)
  binary="$fw/$fw_name"
  [ -f "$binary" ] && codesign -f -s - "$binary"
done
[ -f "$APP/PlugIns/"*.appex ] && for appex in "$APP/PlugIns/"*.appex; do
  appex_name=$(basename $appex .appex)
  [ -f "$appex/$appex_name" ] && codesign -f -s - "$appex/$appex_name"
done

# 5.3 Sign the wrappers (framework bundles + appex)
for fw in "$APP/Frameworks/"*.framework "$APP/PlugIns/"*.appex; do
  [ -d "$fw" ] && codesign -f -s - "$fw"
done

# 5.4 Sign the main bundle
codesign -f -s - "$APP"
```

Verify:

```bash
# The most important: the internal binary of the framework (not the bundle)
codesign -v --strict "$APP/Frameworks/<some.framework>/<Some>" && echo "VALID" || echo "INVALID"
# And the full hierarchy
codesign -v --strict "$APP" && echo "BUNDLE VALID" || echo "BUNDLE INVALID"
```

### Step 6 — Boot + Install

```bash
# Choose a simulator compatible with the app's target SDK
# (see simforge-compatibility.md for the matrix)
xcrun simctl boot "iPhone 17 Pro"  # or whatever is available
xcrun simctl install booted "$APP"
xcrun simctl get_app_container booted "<bundle.id>"  # verify installation
```

> **Emulator visibility**: by default, simulators launch **visible**. Only use headless mode when explicitly requested (`--headless` or `simforge_install_launch.sh --headless`).

### Step 7 — Launch + Diagnose loop

```bash
xcrun simctl launch booted "<bundle.id>"
```

Three possible outcomes:

1. **PID returned and process alive** → Success, go to Step 8.
2. **PID returned and immediate crash** → dyld rejected a binary. Go to `simforge-crash-triage.md`.
3. **`SBMainWorkspace` denial** → Info.plist, entitlements, or signature integrity. Re-validate Step 4-5.

### Step 8 — (Optional) Inject dylib

If the goal is dynamic hooking with Frida Gadget:

```bash
# Pre-process the dylib
simforge convert /path/to/frida-gadget.dylib
codesign -f -s - /path/to/frida-gadget.dylib

# Launch with injection
simforge launch --bundleid "<bundle.id>" --dylib /path/to/frida-gadget.dylib

# Connect to Gadget (default port 27042)
frida -H 127.0.0.1:27042 -l "<script.js>"
```

For multiple dylibs (workaround):

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="/path/tweak1.dylib:/path/tweak2.dylib" \
  xcrun simctl launch --console booted "<bundle.id>"
```

### Step 9 — Clean up

```bash
xcrun simctl shutdown booted
rm -rf "$WORK"
# Keep the original .ipa and the .app backup in case you need to iterate
```

### Step 10 — Document failures

If any step fails in an undocumented way, add it to the troubleshooting in `simforge-ios-testing.md` with:

- Exact symptom (dyld / SBMainWorkspace message)
- Identified root cause
- Workaround (if exists)
- When there is NO workaround

---

## Iteration pattern: framework-by-framework

In apps with many frameworks, it's common for launch to **advance one framework per iteration**. Each crash identifies the next broken link in the dependency chain.

```
Launch → crash on Framework_A → fix Framework_A → relaunch
       → crash on Framework_B → fix Framework_B → relaunch
       → ... → app runs ✓
```

That's why it's important **not to re-sign everything at once** without verifying — a signature fix may reveal another framework with another problem (Swift version, missing dependency, etc.). The loop `launch → crash → identify → fix → relaunch` is the canonical pattern.

---

## Quick decision tree

```
Does the app have embedded frameworks with @rpath dependencies?
├── No → The 5-step flow (simforge + sign + install) is sufficient
└── Yes → Apply the full 10-step flow
    Are all binaries arm64?
    ├── No → lipo -thin arm64 first
    └── Yes → Continue
    Is there LC_VERSION_MIN_IPHONEOS in any binary?
    ├── No → Skip Step 3
    └── Yes → Apply Step 3
    Crash with "code signature invalid"?
    ├── Yes → Step 5 executed incorrectly, re-sign internal binaries
    └── No → Continue
    Crash with "incompatible platforms" / "Library missing"?
    ├── Yes → See simforge-compatibility.md before proceeding
    └── No → See simforge-crash-triage.md
```
