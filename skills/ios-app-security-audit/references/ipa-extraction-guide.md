# IPA Extraction Guide

## Container vs Binary: What You're Extracting

iOS apps have **two distinct targets** for extraction. Conflating them is the #1 source of confusion in iOS pentesting:

| Aspect | **Container** (app sandbox) | **Binary** (Mach-O executable) |
|--------|-----------------------------|---------------------------------|
| **What** | Runtime data: `Documents/`, `Library/Preferences/`, `Library/Caches/`, `tmp/`, SQLite DBs, plists, cookies | The actual app: `MyApp` Mach-O executable, `Info.plist`, `Frameworks/`, embedded resources |
| **Where it lives** | `/var/mobile/Containers/Data/Application/<UUID>/` on device | Inside the `.app` bundle (inside `.ipa` or on device at `/var/containers/Bundle/Application/`) |
| **Jailbreak needed?** | No — accessible via House Arrest / AFC (developer mode) | No for the `.app` bundle structure, but **yes for the decrypted binary** (FairPlay DRM) |
| **Tools** | `afcclient --house-arrest`, `pymobiledevice3 apps afc/pull` | `ipatool download`, `frida-ios-dump`, `bagbak` (jailbreak), SimForge |
| **What you analyze** | Stored data, session tokens, cached responses, user-generated content, Keychain (via backup) | Source code (reconstructed), Info.plist, URL schemes, entitlements, embedded secrets, native code |
| **OWASP MASTG** | MASTG-TEST-0051 (data storage), MASTG-TEST-0052 (keychain) | MASTG-TEST-0001 (code quality), MASTG-TEST-0002 (binary protections) |

**Decision rule**: Start with the **binary** (you need the IPA or decrypted binary for static analysis). Then extract the **container** after installing/running the app to grab runtime data. For Frida/Gadget injection, you need the **binary**. For reading app preferences or user data, you need the **container**.

**Common mistake**: Extracting only the container and trying to do static analysis on the Mach-O — the container doesn't contain the executable, only its runtime artifacts. The reverse mistake is downloading the IPA and forgetting that runtime data (preferences, caches, tokens) lives in a separate sandbox that you can only access by running the app on a device.

## IPA Structure

The iOS App Package (`.ipa`) is essentially a ZIP archive containing the application bundle and supporting files.

### Payload Directory
```
Payload/
├── MyApp.app/
│   ├── MyApp (executable binary)
│   ├── Info.plist
│   ├── _CodeSignature/
│   │   └── CodeResources
│   ├── embedded.mobileprovision
│   ├── Frameworks/
│   │   └── SomeFramework.framework/
│   ├── Plugins/
│   │   └── Extension.appex/
│   ├── Assets.car
│   └── ...
└── ...
```

### Key Components

#### Info.plist
Contains critical app metadata and security configurations:

```xml
<key>CFBundleIdentifier</key>
<string>com.example.myapp</string>

<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>

<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>

<key>LSRequiresIPhoneOS</key>
<true/>
```

Critical security keys to review:
- `CFBundleURLTypes` - URL schemes (deep links)
- `NSAppTransportSecurity` - Network security
- `NSFaceIDUsageDescription` - Biometric permissions
- `NSLocationWhenInUseUsageDescription` - Location access

#### _CodeSignature Directory
Contains code signature information:

```bash
# Check signature
codesign -dv --entitlements :- Payload/MyApp.app

# Output includes:
# - Format
# - Identifier
# - Team Identifier
# - Entitlements
# - Requirements
```

#### embedded.mobileprovision
Provisioning profile with entitlements and app identifier:

```bash
# Extract and decode
security cms -D -i embedded.mobileprovision > profile.plist

# View entitlements
plutil -p profile.plist | grep -A 20 "Entitlements"

# Check application-identifier
plutil -p profile.plist | grep "application-identifier"
```

#### Frameworks Directory
Contains embedded frameworks (dylibs):

```bash
# List frameworks
ls -la Payload/MyApp.app/Frameworks/

# Check framework signatures
codesign -dv Payload/MyApp.app/Frameworks/MyFramework.framework

# Analyze framework binary
otool -L Payload/MyApp.app/Frameworks/MyFramework.framework/MyFramework
```

#### Plugins Directory
Contains app extensions:

```bash
# List extensions
find Payload/MyApp.app/Plugins -name "*.appex"

# Check extension info
plutil -p Payload/MyApp.app/Plugins/Extension.appex/Info.plist

# Verify extension signature
codesign -dv Payload/MyApp.app/Plugins/Extension.appex
```

## Extraction Methods

### 1. Manual Extraction with unzip

```bash
# Extract IPA
unzip app.ipa -d extracted_ipa

# Extract to specific directory
unzip app.ipa -d /path/to/output

# List contents without extracting
unzip -l app.ipa

# Extract specific files
unzip app.ipa Payload/MyApp.app/Info.plist
```

### 2. Using ipa-tool

```bash
# Install
npm install -g ipa-tool

# Extract IPA
ipa-tool extract app.ipa

# Extract to specific directory
ipa-tool extract app.ipa -o output_dir

# Show IPA info
ipa-tool info app.ipa

# Get entitlements
ipa-tool entitlements app.ipa
```

### 3. Xcode Organizer

```bash
# Prerequisites:
# - Mac with Xcode installed
# - Device connected to Mac

# Steps:
# 1. Open Xcode
# 2. Window > Devices and Simulators
# 3. Select device
# 4. Select "Installed Apps"
# 5. Right-click app > "Show in Finder"
# 6. The .ipa is now accessible
```

### 4. Apple Configurator

```bash
# Prerequisites:
# - Mac with Apple Configurator
# - iOS device connected

# Steps:
# 1. Open Apple Configurator
# 2. Select device
# 3. Apps > Show
# 4. Right-click app > Export
# 5. Save .ipa file
```

### 5. App Store Download with ipatool

Download IPA files directly from the iOS App Store using an Apple ID. Useful when you do not have access to a jailbroken device but the target app is publicly available on the App Store.

**ipatool** is a CLI tool that communicates with Apple's iTunes/App Store APIs to search for and download app packages. The downloaded IPA is a **complete fat binary** (all architectures).

> ⚠️ The IPA downloaded by ipatool is **FairPlay DRM encrypted** (the main binary inside `.app` cannot be class-dumped, string-extracted, or analyzed with reverse-engineering tools). For full static analysis, you must decrypt the IPA first — see the **FairPlay DRM** section below.

**Installation:**

```bash
# macOS (recommended)
brew install ipatool

# Linux / Windows — download binary from https://github.com/majd/ipatool/releases
```

**Authentication:**

```bash
ipatool auth login -e apple-id@example.com
# Will prompt for password (and 2FA code if enabled)
# Credentials stored in system keychain — never on a remote server

ipatool auth info    # verify authenticated account
```

> 🔒 **Use a throwaway Apple ID.** Apple's authentication API for ipatool is unofficial and the account may be flagged if used heavily. Never use your personal Apple ID for engagement work.

**Common commands:**

```bash
# Search by name
ipatool search "App Name" --limit 5 --format json

# Download by bundle ID (auto-purchases license for free apps)
ipatool download -b com.example.app --purchase -o target.ipa

# Download a specific version (use list-versions first)
ipatool list-versions -b com.example.app
ipatool download -b com.example.app --external-version-id "<id>" -o target.ipa

# JSON output for scripting
ipatool search "App" --format json | jq '.results[]'
```

**Workflow (acquire → decrypt → analyze):**

1. **Acquire** with ipatool (encrypted IPA)
2. **Inspect what is readable** without decryption: Info.plist, entitlements, embedded.mobileprovision, frameworks list, asset catalogs
3. **Decrypt** before full binary analysis — see FairPlay DRM section below
4. **Analyze** the decrypted IPA

## App Store IPA Extraction

> If you do not have an App Store IPA yet, use **ipatool** (see [App Store Download with ipatool](#5-app-store-download-with-ipatool) above) to acquire one.

### FairPlay DRM

App Store apps are protected with FairPlay DRM:

- Apps are encrypted with AES
- Requires device-specific keys to decrypt
- Cannot be extracted directly from device
- Requires decryption tools

### frida-ios-dump

frida-ios-dump is a popular tool for dumping decrypted apps:

```bash
# Install
git clone https://github.com/AloneMonkey/frida-ios-dump.git
cd frida-ios-dump
pip3 install -r requirements.txt

# List installed apps
python3 dump.py -l

# Dump specific app
python3 dump.py com.example.app

# Dump with custom output directory
python3 dump.py com.example.app -o /path/to/output

# Dump all apps
python3 dump.py -a
```

### dumpdecrypted

Alternative decryption tool:

```bash
# Clone repository
git clone https://github.com/stefanesser/dumpdecrypted.git
cd dumpdecrypted

# Compile for iOS
make

# On jailbroken device:
# 1. Upload dumpdecrypted.dylib to device
# 2. Find encrypted app
ps aux | grep MyApp

# 3. Get PID of app
PID=$(ps aux | grep MyApp | grep -v grep | awk '{print $2}')

# 4. Inject dumpdecrypted
DYLD_INSERT_LIBRARIES=/path/to/dumpdecrypted.dylib /path/to/MyApp

# 5. Decrypted IPA is created in Documents
```

### Clutch (Alternative)

```bash
# Install from Cydia (jailbroken device)
# or compile from source

# List apps
clutch -i

# Dump specific app
clutch com.example.app

# Dump all apps
clutch --all

# Output location
# /var/mobile/Documents/Dumped/
```

## Analyzing the .app Bundle

### Executable Binary

```bash
# Get binary info
file Payload/MyApp.app/MyApp

# Check architecture
lipo -info Payload/MyApp.app/MyApp

# Extract specific architecture
lipo Payload/MyApp.app/MyApp -thin arm64 -output MyApp_arm64

# Analyze with otool
otool -L Payload/MyApp.app/MyApp

# Get imports
otool -oV Payload/MyApp.app/MyApp

# Get classes (Objective-C)
otool -ov Payload/MyApp.app/MyApp | grep "^_OBJC_CLASS"
```

### Info.plist Security Keys

```bash
# Extract Info.plist
plutil -p Payload/MyApp.app/Info.plist

# Check URL schemes
plutil -p Payload/MyApp.app/Info.plist | grep -A 5 "CFBundleURLTypes"

# Check NSAppTransportSecurity
plutil -p Payload/MyApp.app/Info.plist | grep -A 10 "NSAppTransportSecurity"

# Check permissions
plutil -p Payload/MyApp.app/Info.plist | grep "UsageDescription"

# Check for custom schemes
grep -r "myapp://" Payload/MyApp.app/
```

### Code Signature Verification

```bash
# Verify signature
codesign -dv -vvv Payload/MyApp.app

# Check entitlements
codesign -d --entitlements :- Payload/MyApp.app

# Verify all frameworks
codesign -dv Payload/MyApp.app/Frameworks/*

# Verify extensions
codesign -dv Payload/MyApp.app/Plugins/*
```

### Entitlements Extraction

```bash
# Method 1: codesign
codesign -d --entitlements :- Payload/MyApp.app > entitlements.plist

# Method 2: From provisioning profile
security cms -D -i Payload/MyApp.app/embedded.mobileprovision |   plutil -p | grep -A 30 "Entitlements"

# Method 3: Using jtool
jtool --ent Payload/MyApp.app/MyApp
```

## Provisioning Profile Analysis

### Reading embedded.mobileprovision

```bash
# Decode binary plist
security cms -D -i embedded.mobileprovision > profile.plist

# View full profile
plutil -p profile.plist

# Extract application-identifier
plutil -p profile.plist | grep "application-identifier"

# Extract keychain-access-groups
plutil -p profile.plist | grep "keychain-access-groups"

# Extract com.apple.security.application-groups
plutil -p profile.plist | grep "com.apple.security.application-groups"
```

### Understanding Entitlements in Profile

```xml
<key>Entitlements</key>
<dict>
    <key>application-identifier</key>
    <string>TEAMID.com.example.myapp</string>
    
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.myapp</string>
        <string>TEAMID.*</string>
    </array>
    
    <key>get-task-allow</key>
    <false/>
    
    <key>aps-environment</key>
    <string>production</string>
    
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.example.app</string>
    </array>
</dict>
```

### Development vs Distribution Profiles

```bash
# Check if development profile
plutil -p profile.plist | grep "ProvisionedDevices"

# Development profile has:
# - "ProvisionedDevices" array with device UDIDs
# - "GetTaskAllow" usually true

# Distribution profile has:
# - No "ProvisionedDevices" array
# - "GetTaskAllow" false
```

## Code Signature Verification

### Using codesign

```bash
# Verify signature
codesign -v Payload/MyApp.app

# Detailed verification
codesign -dv Payload/MyApp.app

# Very detailed (with requirements)
codesign -dv -vvv Payload/MyApp.app

# Verify all nested code
codesign -v --deep Payload/MyApp.app

# Check signature status
codesign -v Payload/MyApp.app 2>&1

# Expected outputs:
# - "valid on disk"
# - "satisfies its Designated Requirement"
```

### Using jtool

```bash
# Install jtool
# From https://www.newosxbook.com/tools/jtool.html

# Verify signature
jtool --verify Payload/MyApp.app/MyApp

# Get signature blob
jtool --sig Payload/MyApp.app/MyApp

# Get entitlements
jtool --ent Payload/MyApp.app/MyApp

# Get code directory
jtool --codesig Payload/MyApp.app/MyApp
```

### Using swift-structure

```bash
# Install
# From: https://github.com/cfinfante/swift-structure

# Analyze Swift metadata
./swift-structure Payload/MyApp.app/MyApp

# Get Swift type information
./swift-structure -t Payload/MyApp.app/MyApp

# Get protocol conformances
./swift-structure -p Payload/MyApp.app/MyApp
```

### Detecting Modified Binaries

```bash
# Check for signature mismatch
codesign -v Payload/MyApp.app

# Expected output if modified:
# "code object is not signed at all"
# or
# "code signature is not valid"

# Check binary hash
shasum Payload/MyApp.app/MyApp

# Compare with original hash
# If different, binary has been modified

# Check for repackaging indicators
# 1. Different signing certificate
codesign -d -r - Payload/MyApp.app

# 2. Different team identifier
codesign -d -r - Payload/MyApp.app | grep "identifier"

# 3. Missing or invalid CodeResources
ls -la Payload/MyApp.app/_CodeSignature/
```

## OWASP MASTG References

- **MASTG-APP-ARCH-001: Architecture Review**
  - IPA structure analysis
  - App bundle review

- **MASTG-APP-INFO-003: Information Gathering**
  - Binary extraction
  - Metadata extraction

- **MASTG-APP-ANALYSIS-001: Static Analysis**
  - Code signature verification
  - Entitlements analysis
  - Provisioning profile review
