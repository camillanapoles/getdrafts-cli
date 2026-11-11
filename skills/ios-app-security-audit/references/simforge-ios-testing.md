# SimForge: iOS Pentesting on Apple Silicon Simulator

> **Source**: [EthanArbuckle/simforge](https://github.com/EthanArbuckle/simforge) — native macOS tool (Objective-C) for running iOS arm64 apps on Apple Silicon simulators and injecting dylibs without a physical device.

## Quick Navigation

This is the **general entry** about SimForge. For specific operations, consult the specialized references:

| Need | Reference |
|---|---|
| Execute the flow step by step (happy path) | `simforge-emulation-flow.md` |
| Diagnose a dyld/SpringBoard crash | `simforge-crash-triage.md` |
| Know if an app is compatible before attempting | `simforge-compatibility.md` |
| **Use the scripts (`simforge_preflight.py`, etc.) end-to-end** | `simforge-scripts-index.md` |
| SimForge overview (what it is, how it works internally) | This document |

> **Practical rule**: before investing time, run the pre-flight check from `simforge-emulation-flow.md` (or `python3 scripts/simforge_preflight.py <app>`). Three to five 5-second commands that save hours.

## Table of Contents

1. [Overview](#overview)
2. [Internal Architecture](#internal-architecture)
3. [Installation](#installation)
4. [Commands and Flows](#commands-and-flows)
5. [Complete Pentesting Flow](#complete-pentesting-flow)
6. [Pentesting Usage Patterns](#pentesting-usage-patterns)
7. [Limitations and Edge Cases](#limitations-and-edge-cases)
8. [Troubleshooting](#troubleshooting) — see also `simforge-crash-triage.md`
9. [When to Use SimForge vs Physical Device](#when-to-use-simforge-vs-physical-device) — see also `simforge-compatibility.md`
10. [Cross References](#cross-references)

---

## Overview

**SimForge** modifies the `LC_BUILD_VERSION` header of arm64 Mach-O binaries so the iOS simulator accepts them as executables, also automating thinning with `lipo`, ad-hoc re-signing, and dylib injection via `DYLD_INSERT_LIBRARIES` (forwarded through `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES`).

### Why it matters for pentesting

- **Eliminates the jailbroken physical device barrier** for most dynamic testing.
- **Allows injecting Frida Gadget / tweaks** into a target app without jailbreak, on a booted simulator.
- **Converts a decrypted IPA** into a simulator-installable bundle with a single command.
- **Allows patching the SimRuntime** (SpringBoard, system frameworks) with tmpfs overlay for system-level check bypasses.

### Requirements

- **macOS 11+** with **Apple Silicon** (M1/M2/M3/M4). Does not work on Intel.
- **Xcode Command Line Tools** (`xcode-select --install`).
- **At least one booted iOS simulator** (`xcrun simctl list devices booted`).
- A **decrypted IPA** (use `frida-ios-dump`, `bagbak`, or similar on a jailbroken device).

---

## Internal Architecture

SimForge consists of 4 Objective-C modules (`simforge/`):

### `platform_changer.m` — The core

Parses and patches the Mach-O header. Key logic:

```objc
// 1. Reads mach_header_64 — validates MH_MAGIC_64 + cputype == CPU_TYPE_ARM64
// 2. Iterates load commands looking for LC_BUILD_VERSION
//    - If exists: patches platform = PLATFORM_IOSSIMULATOR (7),
//                                minos = 0x000e0000 (iOS 14),
//                                sdk   = 0x000e0000
//    - If doesn't exist: injects a new build_version_command at the end of cmds
// 3. If there was no LC_BUILD_VERSION, increments header.ncmds and header.sizeofcmds
// 4. Recursively traverses the bundle (.app / .appex) if it receives a directory
```

**Security implication**: the patched binary ends up with an **invalid code signature** (LC_CODE_SIGNATURE is not updated with the new structure), which is why SimForge documents that `convert` breaks the codesig. Subsequent ad-hoc re-signing (`codesign -f -s -`) is mandatory.

### `simctl.m` — Wrapper over `xcrun simctl`

Three key operations:

- `getSimulatorDevices(YES)` → lists booted simulators via `xcrun simctl list --json -e devices`.
- `isArm64SimulatorPlatform(path)` → confirms a binary is arm64 (`lipo -info`) and has `platform 7` in its `LC_BUILD_VERSION` (`otool -l`).
- `launchAppOnSimulatorWithDylibs(uuid, bundleid, dylibPaths)` → for each dylib:
  1. `lipo -thin arm64` in-place
  2. `convertPlatformToSimulator_single` (goes through the non-recursive route)
  3. `codesign -f -s -` ad-hoc
  4. Sets `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=path1:path2`
  5. `xcrun simctl launch --console <uuid> <bundleid>`

### `tmpfs_overlay.m` — SimRuntime patching

Allows mounting a read-write tmpfs overlay over normally read-only paths in the simulator runtime (e.g., `SpringBoard.app`). Useful for:

- Modifying the SpringBoard binary for system-level jailbreak check bypasses.
- Replacing system frameworks for testing.
- Patching `dyld_sim` or `libSystem.B.dylib` in advanced scenarios.

### `main.m` — CLI dispatcher

Three subcommands: `convert`, `launch`, `makerw`. The `launch` command ties together the entire injection flow.

---

## Installation

### From source (recommended — the repo has no signed binaries)

```bash
# Clone
git clone https://github.com/EthanArbuckle/simforge.git
cd simforge

# Open in Xcode and build (Cmd+R or Product > Build)
open simforge.xcodeproj
# Binary ends up in DerivedData: ~/Library/Developer/Xcode/DerivedData/simforge-*/Build/Products/Debug/simforge

# Or build via CLI
xcodebuild -project simforge.xcodeproj -scheme simforge -configuration Release
# Copy to /usr/local/bin
cp ~/Library/Developer/Xcode/DerivedData/simforge-*/Build/Products/Release/simforge /usr/local/bin/
```

### Verification

```bash
simforge
# Should print the usage with the 3 commands
```

### Pre-flight check

```bash
# Verify there's a booted simulator
xcrun simctl list devices booted
# Verify xcrun works
xcrun simctl list runtimes
```

---

## Commands and Flows

### `simforge convert <path>`

Converts an `.app` (recursive) or a standalone Mach-O binary to simulator platform.

```bash
# Convert a complete bundle (.app with .appex extensions and frameworks)
simforge convert /path/to/Payload/YourApp.app

# Convert a standalone dylib (e.g., Frida Gadget)
simforge convert /path/to/frida-gadget.dylib
```

**Expected output** (one message per patched Mach-O binary):

```
Successfully converted: YourApp.app/PlugIns/Extension.appex/Extension
Successfully converted: YourApp.app/Frameworks/Some.framework/Some
Successfully converted: YourApp.app/YourApp
```

**Operation risk**: it's destructive. Does `r+b` over files. Make a backup first.

### `simforge launch --bundleid <id> --dylib <path>`

Launches an app already installed on a booted simulator, with one or more dylibs injected.

```bash
# Single dylib
simforge launch --bundleid com.example.app --dylib /path/to/tweak.dylib

# The --dylib flag accepts a single path; for multiple you need to call simctl manually
# (see "Multiple injection" below)
```

Pre-conditions (the tool handles them, but good to know):

1. The app **must already be installed** on the booted simulator.
2. The dylib will be **thinned to arm64** automatically.
3. The dylib will be **converted to simulator platform** automatically.
4. The dylib will be **ad-hoc signed** automatically.
5. The spawned process console **streams to stdout** (`--console` internal to `simctl launch`).

### `simforge makerw <path>`

Mounts a read-write tmpfs overlay over a SimRuntime path.

```bash
# Make SpringBoard.app writable to patch it
simforge makerw "/path/to/iOS 18.1.simruntime/.../RuntimeRoot/System/Library/CoreServices/SpringBoard.app"
```

> **Warning**: use carefully. Tmpfs overlays don't survive a simulator reboot and a mispointed path can break the runtime.

---

## Complete Pentesting Flow

### Scenario: inject Frida Gadget into a decrypted app and observe it with `frida -U`

**Step 1 — Obtain the decrypted IPA**

This is **NOT done with SimForge**; done with tools like:

- `frida-ios-dump` on jailbroken device
- `bagbak` on jailbroken device
- Manual dump with `dump-ios.js` (included in `assets/frida-scripts/` of this skill) via `frida -U -f <bundleid> -l assets/frida-scripts/dump-ios.js`

**Step 2 — Extract the `.app`**

```bash
unzip /path/to/your-app-decrypted.ipa -d /path/to/extracted/
cd /path/to/extracted/Payload/
# Bundle ends up as: YourApp.app/
```

**Step 3 — Convert for simulator**

```bash
simforge convert /path/to/extracted/Payload/YourApp.app
```

**Step 4 — Ad-hoc sign (mandatory after `convert`)**

```bash
# Sign frameworks first (order matters)
codesign -f -s - /path/to/Payload/YourApp.app/Frameworks/*

# Then the main bundle
codesign -f -s - /path/to/Payload/YourApp.app
```

**Step 5 — Boot a simulator and install**

```bash
# List simulators
xcrun simctl list devices available

# Boot one (e.g., iPhone 15)
xcrun simctl boot "iPhone 15"
# or: xcrun simctl boot "<UUID>"

# Install the bundle
xcrun simctl install booted /path/to/Payload/YourApp.app
```

**Step 6 — Inject Frida Gadget as dylib**

```bash
# If your Frida Gadget is a .dylib and needs to be arm64-simulator:
simforge convert /path/to/frida-gadget.dylib
codesign -f -s - /path/to/frida-gadget.dylib

# Launch with injection
simforge launch --bundleid com.example.app --dylib /path/to/frida-gadget.dylib
```

**Step 7 — Connect Frida to the Gadget**

```bash
# Gadget opens a port by default (27042) on localhost
# In another terminal:
frida -H 127.0.0.1:27042 -f com.example.app
# or load a script:
frida -H 127.0.0.1:27042 -l ssl-pinning-bypass-ios.js
```

### Scenario: URL scheme testing on simulator

```bash
# With the app installed on the booted simulator, without dylibs:
xcrun simctl openurl booted "myapp://deeplink?token=ATTACKER"

# To see logs live (equivalent to idevicesyslog but for simulator):
log stream --predicate 'process == "YourApp"' --level debug
```

### Scenario: SpringBoard-level check bypass

```bash
# 1. Make SpringBoard.app writable
simforge makerw "<runtimes-path>/iOS 18.1.simruntime/.../RuntimeRoot/System/Library/CoreServices/SpringBoard.app"

# 2. Patch the SpringBoard binary with simforge convert (no valid signature is OK
#    in this context because simctl will tolerate it)
simforge convert "<runtimes-path>/.../SpringBoard.app/SpringBoard"

# 3. Restart the simulator for changes to take effect
xcrun simctl shutdown booted
xcrun simctl boot "iPhone 15"
```

> **Important limitation**: the tmpfs overlay **does NOT persist** between simulator reboots. You'll need to reapply it each time.

---

## Pentesting Usage Patterns

### 1. Injected Frida Gadget

More reliable than spawn vs attach on simulator. See flow above. **Advantage**: you don't need frida-server on the simulator — the Gadget itself opens the port.

### 2. Analysis tweak with Theos / Logos

```bash
# Compile tweak for iOS arm64
make package THEOS_DEVICE_IP=localhost

# The resulting .dylib requires conversion:
simforge convert /path/to/.theos/obj/debug/tweak.dylib
codesign -f -s - /path/to/.theos/obj/debug/tweak.dylib

# Inject it
simforge launch --bundleid com.example.app --dylib /path/to/tweak.dylib
```

### 3. Multiple dylibs (workaround)

`simforge launch` only accepts one `--dylib`. For multiple, call `xcrun simctl launch` directly:

```bash
xcrun simctl launch --console booted com.example.app \
  --setenv SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="/path/tweak1.dylib:/path/tweak2.dylib"
```

> Note: `simctl launch` doesn't accept `--setenv` as a CLI flag in all versions. The portable way is to export the variable before invoking:

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="/path/tweak1.dylib:/path/tweak2.dylib" \
  xcrun simctl launch --console booted com.example.app
```

### 4. Runtime class-dump with Frida (without Gadget)

If you just want dynamic hooking without injected Gadget, you can combine:

```bash
# Spawn with frida-tools pointing to the simulator bundle ID
frida -U -f com.example.app -l binary-class-dump.js
# Where -U resolves to the first USB device; with simulator may require --host
frida --host=127.0.0.1:27042 -f com.example.app -l binary-class-dump.js
```

### 5. Modifying `Info.plist` to open attack surface

```bash
# Change NSAllowsArbitraryLoads to true to force ATS testing
plutil -replace NSAppTransportSecurity.NSAllowsArbitraryLoads -bool true \
  /path/to/Payload/YourApp.app/Info.plist

# Add a URL scheme for deep link testing
plutil -insert CFBundleURLTypes -json '[{"CFBundleURLSchemes":["audit"]}]' \
  /path/to/Payload/YourApp.app/Info.plist

# Re-sign after any plist edit
codesign -f -s - /path/to/Payload/YourApp.app
xcrun simctl install booted /path/to/Payload/YourApp.app
```

### 6. Jailbreak detection bypass on simulator

Apps with jailbreak detection check paths like `/Applications/Cydia.app`, `/private/var/lib/apt`, etc. On simulator, those paths don't exist, **but** the app can detect it's on simulator (`TARGET_OS_SIMULATOR`). An attack variant is to patch those checks at binary level with `jtool2` or Hex editor **before** `simforge convert`, or hook them with Frida Gadget.

---

## Limitations and Edge Cases

### What SimForge **CANNOT** do

- **Does NOT decrypt binaries**. You need the IPA already decrypted.
- **Does NOT work on Intel Macs**. Only Apple Silicon.
- **Does NOT evade "is this a simulator" checks** (`TARGET_OS_SIMULATOR`, `SIMULATOR_*` env vars). For those cases, hook with Frida.
- **Does NOT persist tmpfs overlays** between simulator reboots.
- **Does NOT handle non-arm64 frameworks**. Apps with x86_64/legacy slices don't convert — need to thin to arm64 first (`lipo -thin arm64`).
- **Does NOT provide jailbreak persistence**. The simulator is not jailbroken in the traditional sense — there's no `Cydia`, `Substrate`, `Sileo`, etc. by default.

### Expected behaviors that can confuse

- **Code signature becomes invalid after `convert`**. Ad-hoc sign is mandatory, and even then **Apple Pay / Keychain Sharing / Push** won't work because they require real provisioning.
- **Extensions (`.appex`) and embedded frameworks are also converted** — SimForge traverses the bundle recursively, but sometimes a deep `.appex` isn't processed. Verify with `find . -name '*.appex' -exec sh -c 'otool -l {} | grep -A2 LC_BUILD_VERSION | grep -q "platform 7" || echo NOT_CONVERTED: {}' \;`.
- **Apps with FairPlay or DRM** will fail to launch — the simulator has no FairPlay daemon.
- **Some entitlements don't apply on simulator** (`aps-environment`, `com.apple.developer.in-app-payments`).
- **Frida/Theos dylibs are re-signed on each `launch`** — the operation is idempotent but slow on large dylibs.
- **SimForge adds `LC_BUILD_VERSION` but doesn't remove `LC_VERSION_MIN_IPHONEOS`**. Apps with legacy frameworks (OneSignal, Facebook SDK, biometric SDKs) may have **both** load commands after conversion, causing dyld assertion failures. See [`simforge-legacy-loadcmd-cleanup.md`](simforge-legacy-loadcmd-cleanup.md) for the fix.

### When NOT to use SimForge

- When the app has robust anti-simulator checks you can't hook.
- When critical business logic depends on real hardware (Secure Enclave, sensors, baseband).
- When you need to reproduce a crash reported in production on a real device.

---

## Troubleshooting

> **For structured crash diagnosis**, consult `simforge-crash-triage.md`. That reference has a decision tree by `termination.namespace`+`indicator`, a universal `.ips` parser, and a framework-by-framework iteration pattern.
>
> **For compatibility limitations** (FairPlay, Swift ABI, hardware), consult `simforge-compatibility.md`.
>
> This section covers the **most common operational errors** that don't require deep diagnosis.

### "No booted simulators found"

```bash
xcrun simctl list devices booted
# If none:
xcrun simctl boot "iPhone 15"   # or the name/UUID of an available simulator
open -a Simulator               # GUI alternative
```

### "Failed to sign dylib"

```bash
# Force manual re-sign
codesign --remove-signature /path/to/dylib.dylib
codesign -f -s - /path/to/dylib.dylib

# Verify
codesign -dvv /path/to/dylib.dylib
```

### App crashes immediately on launch

Verify that **all** Mach-Os in the bundle are converted:

```bash
cd /path/to/Payload/YourApp.app
find . -type f \( -perm +111 -o -name '*.dylib' -o -name '*.framework' \) -exec sh -c '
  if file "{}" | grep -q "Mach-O"; then
    otool -l "{}" 2>/dev/null | grep -A 4 LC_BUILD_VERSION | grep -q "platform 7" \
      || echo "NOT_CONVERTED: {}"
  fi
' \;
```

### Injected dylib doesn't load

```bash
# 1. Verify it's arm64
lipo -info /path/to/tweak.dylib
# Expected: Non-fat file: ... is architecture: arm64

# 2. Verify it has platform 7
otool -l /path/to/tweak.dylib | grep -A 4 LC_BUILD_VERSION
# Expected: platform 7

# 3. Verify it's signed
codesign -dvv /path/to/tweak.dylib 2>&1 | head -5

# 4. Check dyld logs on launch
SIMCTL_CHILD_DYLD_PRINT_LIBRARIES=1 xcrun simctl launch --console booted com.example.app
```

### "Path too long" on convert

SimForge uses a 4096 char buffer for paths. In bundles with deeply nested paths (rare but possible), consider copying the bundle to a shorter path:

```bash
cp -R /very/long/path/YourApp.app /tmp/
simforge convert /tmp/YourApp.app
```

### Simulator doesn't start after `makerw`

```bash
# Shut down, delete runtime and recreate
xcrun simctl shutdown all
xcrun simctl erase "iPhone 15"   # ⚠️ deletes all apps from simulator
xcrun simctl boot "iPhone 15"
```

### "Library not loaded: @rpath/SomeFramework" with truncated crash report

Typical symptom in apps with **legacy frameworks** (Bolts 1.9.x, Parse 1.x, etc.) running on modern simulators (iOS 17+). SimForge patches `LC_BUILD_VERSION` but leaves inconsistencies with `LC_VERSION_MIN_IPHONEOS` and the framework's `CFBundleSupportedPlatforms`.

**Diagnosis**:

```bash
# Verify build_version vs version_min inconsistency
otool -l Some.framework/Some | rg -A 4 "LC_(BUILD_VERSION|VERSION_MIN)"
# Typical symptom:
#   LC_BUILD_VERSION     platform 7    minos 14.0 sdk 14.0
#   LC_VERSION_MIN_IPHONEOS  version 8.0 sdk 17.0   ← inconsistent

# Verify the framework's Info.plist
plutil -p Some.framework/Info.plist | rg "CFBundleSupportedPlatforms"
# Typical symptom: ["iPhoneOS"]   ← says "device", dyld rejects it
```

**Complete workaround** (4 steps):

```bash
APP=/path/to/extracted/Payload/YourApp.app
FW="$APP/Frameworks/Some.framework"
BIN="$FW/Some"

# 1. Patch BOTH LC_BUILD_VERSION and LC_VERSION_MIN with vtool (not simforge)
vtool -arch arm64 -set-build-version 7 17.0 17.0 -output "$BIN" "$BIN"
vtool -arch arm64 -set-version-min ios 17.0 17.0   -output "$BIN" "$BIN"

# 2. Change framework CFBundleSupportedPlatforms to simulator
plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' "$FW/Info.plist"

# 3. Change main bundle CFBundleSupportedPlatforms
plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' "$APP/Info.plist"

# 4. Re-sign everything with codesign deep
codesign -f -s - --deep "$APP"
```

**When there's NO workaround**: dyld within very new simulators (iOS 26+) may reject frameworks not compiled with recent Xcode, even after the above workaround. In that case:

- Compile the binary from source targeting modern simulator SDK (`xcodebuild -sdk iphonesimulator`).
- Use `iOSAppResignTool` or `ios_resign` (from jailbreak community) that understand the modern resign flow.
- Escalate to a jailbroken physical device.

### "Simulator device failed to launch" with SBMainWorkspace denial

If the process already **passes dyld** (verify with `log show --predicate 'process == "SpringBoard"'` looking for `Bootstrapping`) but SpringBoard rejects the launch with `NSPOSIXErrorDomain code 153 (E2BIG)`, the problem is usually:

- **Corrupted LC_CODE_SIGNATURE** after modifying the binary with multiple tools (simforge + vtool + codesign). The fix is: `codesign --remove-signature <bin>` then `codesign -f -s - <bin>`.
- **Corrupted load commands** with sizes that don't sum to `sizeofcmds`. Re-extract the IPA from the original and start the flow from scratch, using **only one** patching tool (preferably `vtool` over `simforge` for legacy apps).

### "code signature invalid" on embedded framework

If dyld rejects a specific framework (e.g., `<MyFramework>.framework/<MyFramework>`) with **"code signature invalid"** in the crash report, the problem is that `codesign --deep` doesn't always re-sign the **internal binaries** of frameworks (leaves the original Apple Distribution signature orphaned). Typical symptom:

```text
$ codesign -v --strict Frameworks/Suspect.framework/Suspect
.../Suspect: invalid Info.plist (plist or signature have been modified)
# And in codesign -dvv:
Authority=Apple Distribution: "<Vendor Name>"  ← old signature, not ad-hoc
flags=0x0(none)  ← no ad-hoc flag
```

**Explicit fix** (4 steps, in this order):

```bash
APP=/path/to/Payload/YourApp.app

# 1. Remove ALL existing signatures (including original App Store ones)
find "$APP" -type f \( -name "*.dylib" -o -name "YourApp" -path "*.appex/*" \) -exec codesign --remove-signature {} \;
for fw in "$APP/Frameworks/"*.framework "$APP/PlugIns/"*.appex; do
  [ -d "$fw" ] && codesign --remove-signature "$fw"
done
codesign --remove-signature "$APP"

# 2. Re-sign internal binaries of each framework (what dyld validates)
for fw in "$APP/Frameworks/"*.framework; do
  fw_name=$(basename $fw .framework)
  binary="$fw/$fw_name"
  [ -f "$binary" ] && codesign -f -s - "$binary"
done

# 3. Re-sign the bundle wrappers of each framework
for fw in "$APP/Frameworks/"*.framework "$APP/PlugIns/"*.appex; do
  codesign -f -s - "$fw"
done

# 4. Re-sign the main bundle
codesign -f -s - "$APP"
```

### "incompatible platforms: iOS-simulator - iOS" in crash report (deceptive!)

If dyld reports this on a framework that clearly says `platform 7` in its `LC_BUILD_VERSION`, the problem is **NOT platform** — it's **Swift ABI version mismatch**. The framework requires `libswift*.dylib` with a specific version (e.g., `current version 5.9.0`) and the one available in the current SimRuntime doesn't have it.

**Diagnosis**:

```bash
APP=/path/to/Payload/YourApp.app
FW="$APP/Frameworks/Suspect.framework"

# 1. Check what libswift version the framework requires
otool -L "$FW/$(basename $fw .framework)" | rg "libswift"

# 2. Check what version the SimRuntime provides
SWIFT_RT="/Library/Developer/CoreSimulator/Volumes/iOS_<VERSION>/.../RuntimeRoot/usr/lib/swift"
otool -L "$SWIFT_RT/libswiftCore.dylib" | head -1

# 3. Check what version the local toolchain provides
ls -la /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib
otool -L /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib | head -1
```

**Workarounds** (best to worst):

1. **Install the Xcode version that matches the SDK the app was compiled with** (e.g., Xcode 15.x for apps compiled with Swift 5.9). Use `xcode-select` to alternate between versions. Re-sign with the correct toolchain.
2. **Re-compile the app from source** with current Xcode (when you have code access).
3. **Escalate to a jailbroken physical device** (doesn't require Swift patching, libs come from the OS).
4. **Try with an older simulator runtime** (if available and matches the original SDK).

> **Practical rule**: the SimRuntime must be compatible with the app's original SDK. An app compiled with SDK 18.5 can run on a SimRuntime iOS 18.x or higher if the Swift ABI matches. If not, there's no workaround on the simulator side.

---

## Frida Gadget Injection in Simulator

For dynamic analysis without `frida-server`, inject Frida Gadget directly into the simulator app. This enables runtime hooking, SSL pinning bypass, and method tracing.

### Downloading Frida Gadget

```bash
# Download iOS universal gadget (arm64)
FRIDA_VERSION="17.11.0"  # Match your frida --version
curl -L "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-ios-universal.dylib.xz" | xz -d > frida-gadget.dylib

# Verify architecture
file frida-gadget.dylib
# Expected: Mach-O universal binary with 2 architectures: [arm64:...]
```

### Preparing the Gadget for Simulator

**Option 1: Let SimForge handle it (recommended)**

```bash
# Copy to app bundle
cp frida-gadget.dylib Payload/YourApp.app/Frameworks/

# SimForge launch will patch and inject automatically
simforge launch --bundleid com.example.app --dylib Payload/YourApp.app/Frameworks/frida-gadget.dylib
```

**Option 2: Manual patching**

```bash
# Convert gadget for simulator (adds LC_BUILD_VERSION platform 7)
simforge convert frida-gadget.dylib

# Re-sign the converted gadget
codesign -f -s - frida-gadget.dylib
```

### Launching with Gadget Injection

```bash
# Using SimForge launch (recommended)
simforge launch --bundleid com.example.app --dylib /path/to/frida-gadget.dylib

# Alternative: Using environment variable
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/frida-gadget.dylib \
  xcrun simctl launch booted com.example.app
```

### Connecting to the Gadget

**Default Gadget port for simulator**: `27042` (TCP on localhost)

```bash
# Connect to Gadget (not the process name)
frida -H 127.0.0.1:27042 -n Gadget -l script.js

# Or attach by PID if Gadget detection fails
PID=$(xcrun simctl spawn booted launchctl list | grep com.example.app | awk '{print $1}')
frida -D $(xcrun simctl list devices booted | grep -oE "[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}") -p $PID -l script.js
```

### Verifying Gadget Injection

```javascript
// Simple test script
if (ObjC.available) {
    console.log("✅ ObjC runtime available");
    console.log("Process:", ObjC.classes.JavaScriptContext.length);
} else {
    console.log("❌ ObjC runtime NOT available");
}

// Keep alive
setInterval(() => console.log("Tick..."), 5000);
```

**Expected output**:
```
✅ ObjC runtime available
Process: <number>
Tick...
```

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Connection refused" | Gadget not injected | Verify `simforge launch --dylib` completed |
| "Not a Mach-O" | Gadget corrupt | Re-download from GitHub |
| "Code signature invalid" | Gadget not re-signed | `codesign -f -s - frida-gadget.dylib` |
| Hooks fail silently | Wrong `.implementation` pattern | Use `.implementation` for simulator (Frida 17+) |

> **Reference**: [`references/frida-ios-simulator-workflow.md`](frida-ios-simulator-workflow.md) for complete simulator-specific Frida patterns and limitations.

---

## When to Use SimForge vs Physical Device

> **For detailed compatibility analysis** (FairPlay encryption, Swift ABI mismatch, hardware the simulator doesn't provide, production entitlements), consult `simforge-compatibility.md`. That has matrices, specific workarounds, and a guide for when to escalate to jailbroken physical device.

| Need | SimForge | Jailbroken physical device |
|-----------|:--------:|:-----------------------------:|
| Static analysis of `Info.plist` / strings / class-dump | ✅ same | ✅ same |
| Dynamic hooking with Frida | ✅ via injected Gadget | ✅ via frida-server |
| Network interception with Burp | ✅ simulator system proxy | ✅ device proxy |
| Test Secure Enclave / Face ID | ❌ N/A | ✅ required |
| Bypass (real) jailbreak detection | ⚠️ simulation only | ✅ required |
| Validate payment / IAP logic | ❌ N/A | ✅ required |
| Reproduce hardware-specific crash | ❌ | ✅ |
| Rapid iteration without device | ✅ excellent | ❌ |
| Analyze extensions (`.appex`) in isolation | ✅ easy to isolate | ⚠️ more friction |
| Setup cost | low (Apple Silicon + Xcode) | medium-high (jailbreak + device) |

**Practical rule**: use SimForge as **first iteration** (fast, no device risk). When a finding requires validation against real hardware, escalate to physical device.

---

## Cross References

Within this skill:

- **Frida scripts for runtime hooking** (valid on both sim and device): `assets/frida-scripts/` (see `references/frida-scripts-index.md`).
- **SSL pinning bypass** over Frida Gadget injected in sim: `references/ssl-pinning-bypass-ios.md` + `assets/frida-scripts/ssl-pinning-bypass-ios.js`.
- **Jailbreak detection bypass** on simulator: `assets/frida-scripts/jailbreak-detection-bypass.js`.
- **Binary decryption** (pre-SimForge step): `assets/frida-scripts/dump-ios.js` + `references/macho-binary-analysis.md`.
- **IPA re-signing** after modifications: `references/repackaging-ios-guide.md`.
- **Frida setup** to connect to the Gadget: `references/frida-ios-guide.md`.
- **Environment setup** (Xcode CLI, simulators): `references/environment-setup-ios.md` and `references/tool-installation-ios.md`.
- **Objection as interactive alternative** (over the injected Gadget): `references/objection-ios-guide.md`.

External:

- [EthanArbuckle/simforge — official repo](https://github.com/EthanArbuckle/simforge)
- [Apple — Mach-O File Format (LC_BUILD_VERSION)](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachORuntime/index.html)
- [manpage — simctl launch](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachORuntime/index.html)
