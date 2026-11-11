# Tool Installation Guide for iOS Pentesting

**Detailed installation and troubleshooting guide for each iOS security testing tool.**

## Table of Contents

1. [Installation Quick Reference](#1-installation-quick-reference)
2. [Frida](#2-frida)
3. [Objection](#3-objection)
4. [dsdump](#4-dsdump)
5. [class-dump-swift](#5-class-dump-swift)
6. [jtool2](#6-jtool2)
7. [Hopper Disassembler](#7-hopper-disassembler)
8. [otool](#8-otool-system)
9. [codesign](#9-codesign-system)
10. [plutil](#10-plutil-system)
11. [lipo](#11-lipo-system)
12. [nm](#12-nm-system)
13. [strings](#13-strings-system)
14. [security](#14-security-system)
15. [Python](#15-python)
16. [Additional Tools](#16-additional-tools)
17. [Common Troubleshooting](#17-common-troubleshooting)
18. [libimobiledevice Ecosystem](#18-libimobiledevice-ecosystem)

---

## Platform Support Matrix

This skill supports **macOS** (recommended, full functionality) and **Linux** (~90% compatibility with alternatives).

### macOS Tool → Linux Substitute Quick Reference

| macOS Tool | Linux Alternative | Install Command | Limitations |
|------------|------------------|-----------------|-------------|
| `plutil` | `plistutil` | `sudo apt install libplist-utils` | None - full compatibility |
| `otool` | `llvm-objdump` | `sudo apt install llvm` | Syntax differs, see [linux-ios-analysis-workarounds.md](linux-ios-analysis-workarounds.md) |
| `lipo` | `llvm-lipo` | `sudo apt install llvm (v12+)` | None - full compatibility |
| `codesign` | `ldid` | `sudo apt install ldid` | ONLY for jailbroken devices, NOT for stock devices |
| `security` | Device-based extraction | N/A | Linux keychain different, see workarounds |
| `jtool2` | `llvm-objdump` | `sudo apt install llvm` | Subset of jtool2 features |
| `class-dump` | Frida runtime dump | `pip3 install frida-tools` | Runtime analysis only, no static extraction |
| `dsdump` | Frida runtime dump | `pip3 install frida-tools` | No Linux build, use Frida for runtime |
| `xcrun simctl` | Corellium/Physical device | N/A | iOS Simulator is macOS-only |

### Functionality by Platform

| Skill Phase | macOS | Linux | Notes |
|-------------|-------|-------|-------|
| Phase 0 (Extract) | ✅ Full | ⚠️ 95% | `llvm-objdump` needed for Mach-O analysis |
| Phase 1 (Attack Surface) | ✅ Full | ⚠️ 90% | `plistutil` replaces `plutil` fully |
| Phase 2 (Triage) | ✅ Full | ✅ 100% | Grep-based, fully portable |
| Phase 3 (Data Flow) | ✅ Full | ✅ 100% | Pattern-based, fully portable |
| Phase 4 (Dynamic) | ✅ Full | ⚠️ 85% | No iOS Simulator; use jailbroken device or Corellium |
| Phase 5 (Reporting) | ✅ Full | ✅ 100% | Python-based, fully portable |

**Overall Linux Compatibility: ~90%** with tool alternatives.

For detailed Linux workarounds and analysis patterns, see [linux-ios-analysis-workarounds.md](linux-ios-analysis-workarounds.md).

---

## 1. Installation Quick Reference

### Minimal Toolchain

| Tool | Version | Purpose | Install Command (macOS) | Verify |
|------|---------|---------|------------------------|--------|
| Frida | see [tool-versions.md](tool-versions.md) | Runtime instrumentation | `pip3 install frida-tools` | `frida --version` |
| Objection | 1.11.0+ | Automated exploitation | `pip3 install objection` | `objection --version` |
| dsdump | 0.13+ | Class extraction | `pip3 install dsdump` | `dsdump --version` |
| Python | 3.10+ | Scripting | `brew install python@3.11` | `python3 --version` |
| otool | System | Mach-O analysis | Installed with Xcode CLI | `otool --version` |
| codesign | System | Code signing | Installed with Xcode CLI | `codesign -h` |
| plutil | System | Plist manipulation | Installed with Xcode CLI | `plutil -h` |

### Optional but Recommended

| Tool | Version | Purpose | Install Command | Verify |
|------|---------|---------|----------------|--------|
| class-dump | Latest | ObjC class extraction | `brew install class-dump` | `class-dump --version` |
| jtool2 | Latest | Enhanced otool | Manual download (see section) | `jtool2 -h` |
| SimForge | Latest | Run arm64 iOS apps in simulator (Apple Silicon) | Build from source (see section) | `simforge` |
| Hopper | v4+ | Disassembler | Manual (see section) | `hopper --version` |
| Ghidra | Latest | Disassembler | `brew install --cask ghidra` | `ghidraRun --version` |
| ipatool | Latest | IPA download | `brew install ipatool` | `ipatool --version` |

---

## 2. Frida

### Description
Dynamic instrumentation framework for runtime analysis and manipulation. Essential for hooking methods, bypassing protections, and monitoring app behavior.

### Minimum Version
See [tool-versions.md](tool-versions.md) for the pinned `frida` / `frida-tools` versions (single source of truth).

### Installation

#### macOS (Host)

```bash
# Install Frida tools (pulls the matching frida core)
pip3 install frida-tools

# Or pin the exact versions (see tool-versions.md — the single source of truth)
pip3 install "frida-tools==14.9.0"   # pulls frida core 17.11.0

# Python dependencies of the skill's own scripts (requests + lief)
pip3 install -r requirements.txt

# Upgrade existing installation
pip3 install --upgrade frida frida-tools
```

#### Linux (Host)

```bash
# Install via pip
sudo apt update
sudo apt install python3-pip
pip3 install frida-tools frida

# Or via apt (older versions)
sudo apt install frida
```

#### iOS Device (Jailbroken)

```bash
# Method 1: Via Cydia/Sileo repository
# Add Frida repo: https://build.frida.re
# Install "Frida" package

# Method 2: Manual installation
# Download frida-server for iOS architecture
# From: https://github.com/frida/frida/releases

# Example for iPhone (arm64):
cd /tmp
FRIDA_VERSION=$(frida --version)   # matches your host; pinned version in tool-versions.md
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-universal-${FRIDA_VERSION}.xz

# Extract
xz -d frida-ios-universal-${FRIDA_VERSION}.xz

# Transfer to device via USB (using scp)
scp frida-ios-universal-${FRIDA_VERSION} root@"<device-ip>":/usr/bin/frida-server

# SSH into device and set permissions
ssh root@"<device-ip>"
chmod +x /usr/bin/frida-server

# Run frida-server
/usr/bin/frida-server &
```

### Verification Commands

```bash
# Host - Verify installation
frida --version
frida-ps --version

# Device - Verify frida-server is running
# On device:
ps aux | grep frida-server

# From host - List device processes
frida-ps -U
```

### Common Issues & Solutions

#### Issue: "No such device" error

```bash
# Check if device is detected
frida-ls-devices

# If not detected, ensure:
# 1. Device is connected via USB
# 2. iTunes/Apple Mobile Device Support is installed
# 3. usbmuxd is running (macOS handles this automatically)

# For network connection:
frida-ps -H "<device-ip>":27042
```

#### Issue: "Frida server version mismatch"

```bash
# Check host version
frida --version

# Check device version
ssh root@"<device-ip>" "/usr/bin/frida-server --version"

# Upgrade to matching versions
# Host: pip3 install --upgrade frida
# Device: Download matching version from releases
```

#### Issue: "Unable to start process"

```bash
# Check if app is debuggable
ssh root@"<device-ip>" "cat /var/mobile/Containers/Bundle/Application/*/Info.plist" | grep CFBundleIdentifier

# Kill existing frida-server and restart
ssh root@"<device-ip>" "killall frida-server"
ssh root@"<device-ip>" "/usr/bin/frida-server &"

# Use spawn instead of attach
frida -U -f com.example.app
```

---

## 3. Objection

### Description
Runtime exploration toolkit for iOS. Automates common tasks like hooking, jailbreak detection bypass, and keychain dumping.

### Minimum Version
**1.12.4+**

### Installation

#### macOS

```bash
# Install via pip
pip3 install objection

# Install specific version
pip3 install objection==1.12.4

# Upgrade
pip3 install --upgrade objection
```

#### Linux

```bash
# Install via pip
sudo pip3 install objection

# Or via apt (if available)
sudo apt install objection
```

### Verification Commands

```bash
# Verify installation
objection --version

# List connected devices
objection device list

# Explore an app
objection -g com.example.app explore
```

### Common Issues & Solutions

#### Issue: "No such device" or device not found

```bash
# Check if Frida can see the device
frida-ls-devices

# Ensure objection can use Frida
frida-ps -U

# Try specifying device explicitly
objection -D "<device-id>" -g com.example.app explore
```

#### Issue: "Failed to spawn process"

```bash
# Check if app is installed
objection explore --list-apps | grep com.example.app

# Try spawn explicitly
objection -g com.example.app explore --startup-command "ios jailbreak disable"

# Ensure app bundle identifier is correct
# Use: objection explore --list-apps
```

#### Issue: "Hooking failed" or "method not found"

```bash
# Verify app is actually running
frida-ps -U | grep com.example.app

# Check if app is Objective-C or Swift
# Objective-C methods are easier to hook

# Use class-dump to get method list
class-dump /path/to/app.app/

# Try wildcard matching
ios hooking watch class "*Controller*"
```

---

## 4. dsdump

### Description
Alternative to class-dump for extracting Objective-C class information from Mach-O binaries. Often faster and more reliable for modern binaries.

### Minimum Version
**0.13+**

### Installation

#### macOS

```bash
# Install via pip
pip3 install dsdump

# Install specific version
pip3 install dsdump==0.13.0

# Upgrade
pip3 install --upgrade dsdump
```

#### Linux

```bash
# Install via pip
sudo pip3 install dsdump

# Install dependencies
sudo apt install python3-dev clang
```

### Verification Commands

```bash
# Verify installation
dsdump --version

# Dump classes from IPA
dsdump -o output.txt /path/to/app.app/

# Dump specific class
dsdump -o output.txt -c MyClass /path/to/app.app/

# Get quick overview
dsdump -s /path/to/app.app/
```

### Common Issues & Solutions

#### Issue: "No Objective-C runtime information"

```bash
# Verify binary is Objective-C
otool -l /path/to/binary | grep -A 5 __objc_classlist

# If no __objc_classlist, app may be Swift-only
# Use Swift-specific tools instead

# Try running on encrypted binary (may fail)
# Decrypt first: clutch decrypt com.example.app
```

#### Issue: "ImportError" or missing dependencies

```bash
# Ensure Python dependencies are installed
pip3 install macholib

# Reinstall dsdump
pip3 uninstall dsdump
pip3 install dsdump

# Check Python version (requires 3.6+)
python3 --version
```

---

## 5. class-dump-swift

### Description
Extracts Swift class information from Mach-O binaries. Essential for analyzing Swift applications.

### Minimum Version
**Latest**

### Installation

#### macOS

```bash
# Install class-dump-swift from GitHub
cd /tmp
git clone https://github.com/vimt/ClassDumpSwift.git
cd ClassDumpSwift

# Build
xcodebuild -project ClassDumpSwift.xcodeproj -scheme class-dump-swift
# Or using Swift Package Manager:
swift build -c release

# Copy to /usr/local/bin
sudo cp .build/release/class-dump-swift /usr/local/bin/
sudo chmod +x /usr/local/bin/class-dump-swift

# Verify
class-dump-swift --version
```

#### Linux

```bash
# Not directly supported on Linux
# Use macOS or virtual machine
# Alternative: Analyze Swift binaries using Ghidra or Hopper
```

### Verification Commands

```bash
# Verify installation
class-dump-swift --version

# Dump Swift classes
class-dump-swift /path/to/app.app/

# Output to file
class-dump-swift /path/to/app.app/ > swift_classes.txt

# Get specific class info
class-dump-swift -C MySwiftClass /path/to/app.app/
```

### Common Issues & Solutions

#### Issue: "Build failed" or Xcode not found

```bash
# Ensure Xcode Command Line Tools are installed
xcode-select --install

# Set developer directory
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

# Verify Xcode is installed
which xcodebuild
xcodebuild -version
```

#### Issue: "No Swift reflection metadata"

```bash
# Verify binary has Swift metadata
otool -l /path/to/binary | grep __swift5_types

# If no __swift5_types, Swift metadata may be stripped
# Check for __swift5_ field in load commands

# Try using otool to extract Swift metadata manually
otool -oV /path/to/binary | grep -A 20 "type metadata for"
```

---

## 6. jtool2

### Description
Enhanced otool alternative for Mach-O binary analysis. Provides better disassembly, load command analysis, and debugging capabilities.

> **jtool2 is NOT in Homebrew** (neither core nor cask). It must be downloaded manually from the author's site. On Apple Silicon it requires Rosetta 2 (the official binary is x86_64). Skip this tool if you only need basic Mach-O inspection — `otool` (system) covers the most common cases.

### Minimum Version
**Latest (jtool2)**

### Installation

#### macOS

```bash
# Download from https://newosxbook.com/tools/jtool.html
cd /tmp
wget https://newosxbook.com/tools/jtool/Jtool2.tgz

# Extract
tar -xzf Jtool2.tgz

# Install
sudo cp jtool2 /usr/local/bin/
sudo chmod +x /usr/local/bin/jtool2

# Apple Silicon: binary is x86_64, requires Rosetta 2
# Install Rosetta if not present
softwareupdate --install-rosetta

# Remove quarantine
xattr -d com.apple.quarantine /usr/local/bin/jtool2

# Verify
jtool2 -h
```

#### Linux

```bash
# Not directly supported on Linux
# jtool2 is macOS-specific
# Use otool (via Darling) or Ghidra for Linux
```

### Verification Commands

```bash
# Verify installation
jtool2 -h

# Display Mach-O header
jtool2 -h /path/to/binary

# Display load commands
jtool2 -l /path/to/binary

# Disassemble function
jtool2 -d _main /path/to/binary

# Find strings
jtool2 -s "password" /path/to/binary

# Display symbols
jtool2 -t /path/to/binary
```

### Common Issues & Solutions

#### Issue: "Operation not permitted" or quarantine

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine jtool2

# Or remove recursively for directory
xattr -cr /path/to/directory

# Verify
xattr -l jtool2
```

#### Issue: "Bad CPU type" on Apple Silicon

```bash
# jtool2 may be Intel-only
# Run via Rosetta 2

# Check if jtool2 is Intel binary
file jtool2
# If "x86_64", ensure Rosetta 2 is installed
softwareupdate --install-rosetta

# Or build jtool2 from source for ARM64
# Contact author or find ARM64 build
```

---

## 7. Hopper Disassembler

### Description
Powerful disassembler and decompiler for macOS, iOS, and Linux. Excellent for analyzing Mach-O binaries and understanding app logic.

### Minimum Version
**v4+**

### Installation

#### macOS

```bash
# Download from https://www.hopperapp.com/
# Hopper has a free trial, then requires license

# Install via Homebrew Cask
brew install --cask hopper-disassembler

# Or install manually:
# 1. Download Hopper.dmg
# 2. Mount DMG
# 3. Drag Hopper to Applications

# Verify installation
open -a "Hopper Disassembler v4"

# Create CLI alias (optional)
sudo ln -s /Applications/Hopper\ Disassembler\ v4.app/Contents/MacOS/hopper /usr/local/bin/hopper

# Verify CLI
hopper --version
```

#### Linux

```bash
# Hopper has a Linux version
# Download from https://www.hopperapp.com/download
# Extract and install

cd /tmp
wget https://www.hopperapp.com/Hopper-v4-4.5.29-Linux.tar.xz
tar -xf Hopper-v4-4.5.29-Linux.tar.xz

sudo mv Hopper-v4 /opt/hopper
sudo ln -s /opt/hopper/bin/hopper /usr/local/bin/hopper

# Verify
hopper --version
```

### Verification Commands

```bash
# Verify GUI is installed
open -a "Hopper Disassembler v4"

# Verify CLI (if alias created)
hopper --version

# Decompile binary via CLI
hopper -o /path/to/output /path/to/binary
```

### Common Issues & Solutions

#### Issue: "License expired" or trial limitations

```bash
# Hopper requires license for full features
# Purchase from: https://www.hopperapp.com/

# Alternative free options:
# - Ghidra (free, open-source)
# - Binary Ninja (free tier)
# - IDA Free (limited)
```

#### Issue: "Cannot open encrypted binary"

```bash
# Encrypted iOS apps need to be decrypted first
# Use Clutch or CrackerXI on jailbroken device

# Via Clutch on device:
ssh root@"<device-ip>" "clutch -b com.example.app"

# Or decrypt manually with Frida:
frida -U -f com.example.app -l dump-ios.js
```

---

## 8. otool (System)

### Description
Built-in macOS tool for inspecting Mach-O binaries. Essential for analyzing load commands, symbols, and dependencies.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# otool is included with Xcode Command Line Tools
# Install Xcode CLI if not already installed:
xcode-select --install

# Set developer directory if needed
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

# Verify
which otool
otool --version
```

### Verification Commands

```bash
# Display Mach-O header
otool -h /path/to/binary

# Display load commands
otool -l /path/to/binary

# Display dependencies
otool -L /path/to/binary

# Display Objective-C class list
otool -oV /path/to/binary

# Display section contents
otool -s __TEXT __text /path/to/binary
```

### Common Issues & Solutions

#### Issue: "otool: command not found"

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Set developer directory
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

# Verify
which otool
```

#### Issue: "Malformed Mach-O file"

```bash
# Check file type
file /path/to/binary

# Verify it's actually a Mach-O binary
# If "FAT" or "Universal binary", it's valid
# If "data" or "ASCII", it's not a Mach-O binary

# Try lipo to extract specific architecture
lipo -info /path/to/binary
lipo -thin arm64 -output extracted_binary /path/to/binary
```

---

## 9. codesign (System)

### Description
Built-in macOS tool for code signing verification and manipulation. Essential for analyzing app entitlements and provisioning profiles.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# codesign is included with Xcode Command Line Tools
xcode-select --install

# Verify
which codesign
codesign -h
```

### Verification Commands

```bash
# Verify code signature
codesign -v /path/to/binary

# Display entitlements
codesign -d --entitlements - /path/to/binary

# Display signature information
codesign -dvv /path/to/binary

# Check if binary is ad-hoc signed
codesign -d /path/to/binary | grep "adhoc"

# Verify all signatures in bundle
codesign -v --deep /path/to/app.app/
```

### Common Issues & Solutions

#### Issue: "code object is not signed at all"

```bash
# App may be unsigned (ad-hoc or missing)
# Check signature type:
codesign -d /path/to/binary

# Sign with ad-hoc signature
codesign --force --sign - /path/to/binary

# Sign with self-signed certificate
# 1. Create certificate in Keychain Access
# 2. Sign with:
codesign --force --sign "MyCertificate" /path/to/binary
```

#### Issue: "invalid entitlements" or "resource envelope"

```bash
# This is normal for App Store apps
# Entitlements are embedded in the binary

# Extract and verify entitlements
codesign -d --entitlements - /path/to/binary > entitlements.plist
plutil -lint entitlements.plist

# Modify if needed (for testing)
plutil -replace keychain-access-groups -array '()' entitlements.plist
codesign --force --entitlements entitlements.plist --sign - /path/to/binary
```

---

## 10. plutil (System)

### Description
Built-in macOS tool for plist (property list) manipulation. Essential for analyzing Info.plist and configuration files.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# plutil is included with Xcode Command Line Tools
xcode-select --install

# Verify
which plutil
plutil -h
```

### Verification Commands

```bash
# Verify plist format
plutil -lint /path/to/Info.plist

# Convert to XML (if binary)
plutil -convert xml1 /path/to/Info.plist

# Convert to JSON
plutil -convert json /path/to/Info.plist

# Extract specific key
plutil -extract CFBundleIdentifier raw /path/to/Info.plist

# Display entire plist
plutil -p /path/to/Info.plist
```

### Common Issues & Solutions

#### Issue: "Cannot parse plist"

```bash
# Check if plist is binary
file /path/to/Info.plist

# If binary, convert to XML
plutil -convert xml1 /path/to/Info.plist

# If corrupted, try to fix
plutil -convert binary1 -o fixed.plist /path/to/Info.plist

# Verify
plutil -lint fixed.plist
```

#### Issue: "Invalid data type" when extracting

```bash
# Ensure the key exists
plutil -p /path/to/Info.plist | grep KeyName

# Try using -p to see full plist structure
plutil -p /path/to/Info.plist

# Extract with appropriate type
# -extract keyName raw (string/number)
# -extract keyName xml (XML data)
# -extract keyName json (JSON data)
```

---

## 11. lipo (System)

### Description
Built-in macOS tool for universal binary (fat binary) handling. Essential for extracting specific architectures from iOS apps.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# lipo is included with Xcode Command Line Tools
xcode-select --install

# Verify
which lipo
lipo -version
```

### Verification Commands

```bash
# Display architectures in universal binary
lipo -info /path/to/binary

# Extract arm64 architecture
lipo -thin arm64 -output extracted_arm64 /path/to/binary

# Extract x86_64 architecture
lipo -thin x86_64 -output extracted_x86_64 /path/to/binary

# Create universal binary from multiple
lipo -create arm64_binary x86_64_binary -output universal_binary

# Verify extracted binary
file extracted_arm64
```

### Common Issues & Solutions

#### Issue: "is not a fat file"

```bash
# Binary is already single-architecture
file /path/to/binary
# Shows "Mach-O 64-bit executable arm64" (not FAT)

# No need to extract, use as-is
# Or create universal binary if needed:
lipo -create /path/to/binary -create /path/to/other_arch_binary -output universal
```

#### Issue: "Can't map architecture"

```bash
# Binary doesn't contain requested architecture
lipo -info /path/to/binary

# Check available architectures
# For iOS apps: arm64, arm64e, armv7
# For macOS: x86_64, arm64

# Extract correct architecture
lipo -thin arm64 -output extracted /path/to/binary
```

---

## 12. nm (System)

### Description
Built-in macOS tool for symbol extraction from binaries. Essential for analyzing exported/imported symbols.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# nm is included with Xcode Command Line Tools
xcode-select --install

# Verify
which nm
nm --version
```

### Verification Commands

```bash
# Display all symbols
nm /path/to/binary

# Display only external (undefined) symbols
nm -u /path/to/binary

# Display only defined symbols
nm -g /path/to/binary

# Display in BSD format (default)
nm -gU /path/to/binary

# Display in POSIX format
nm -P /path/to/binary

# Display with line numbers
nm -n /path/to/binary
```

### Common Issues & Solutions

#### Issue: "no symbols" or stripped binary

```bash
# Check if binary is stripped
nm /path/to/binary
# If empty output, binary is stripped

# Try strings instead
strings /path/to/binary | grep -i "function"

# Or use otool for Objective-C class list
otool -oV /path/to/binary

# If Swift, check for Swift metadata
otool -l /path/to/binary | grep __swift5
```

#### Issue: "Mach-O file but wrong architecture"

```bash
# Check binary architecture
file /path/to/binary
lipo -info /path/to/binary

# Extract correct architecture for current system
# On Apple Silicon Mac:
lipo -thin arm64 -output arm64_binary /path/to/binary

# On Intel Mac:
lipo -thin x86_64 -output x86_64_binary /path/to/binary

# Analyze extracted binary
nm arm64_binary
```

---

## 13. strings (System)

### Description
Built-in macOS tool for extracting printable strings from binaries. Essential for finding hardcoded secrets, URLs, and configuration data.

### Minimum Version
**System (included with Xcode CLI)**

### Installation

```bash
# strings is included with Xcode Command Line Tools
xcode-select --install

# Verify
which strings
strings --version
```

### Verification Commands

```bash
# Extract all strings
strings /path/to/binary

# Extract strings of minimum length
strings -n 8 /path/to/binary

# Search for specific pattern
strings /path/to/binary | grep -i "password\|api_key\|secret"

# Count occurrences
strings /path/to/binary | grep -c "http"

# Extract from specific section
strings -a -n 4 /path/to/binary
```

### Common Issues & Solutions

#### Issue: "Too many strings" or overwhelming output

```bash
# Use longer minimum string length
strings -n 10 /path/to/binary

# Filter output with grep
strings -n 8 /path/to/binary | grep -i "api"

# Save to file for analysis
strings /path/to/binary > strings.txt
grep -i "password\|key\|token" strings.txt
```

#### Issue: "Binary is encrypted"

```bash
# Encrypted binaries will show mostly garbage
strings /path/to/binary
# Output will be short and meaningless

# Solution: Decrypt binary first
# Use Clutch on jailbroken device:
ssh root@"<device-ip>" "clutch -b com.example.app"

# Or decrypt with Frida:
frida -U -f com.example.app -l dump-ios.js
```

---

## 14. security (System)

### Description
Built-in macOS tool for keychain and certificate management. Essential for analyzing app certificates and managing test certificates.

### Minimum Version
**System (included with macOS)**

### Installation

```bash
# security is included with macOS
# No installation needed

# Verify
which security
security -h
```

### Verification Commands

```bash
# List all identities
security find-identity

# List all certificates
security find-certificate -a

# Export certificate to PEM
security find-certificate -c "Certificate Name" -p > certificate.pem

# Add certificate to keychain
security add-certificates certificate.pem

# Delete certificate
security delete-certificate -c "Certificate Name"

# Unlock keychain
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

### Common Issues & Solutions

#### Issue: "User interaction is not allowed"

```bash
# Unlock keychain first
security unlock-keychain -p ~/Library/Keychains/login.keychain-db

# Or unlock default keychain
security unlock-keychain

# Set keychain to not lock on sleep
security set-keychain-settings -t 3600 ~/Library/Keychains/login.keychain-db
```

#### Issue: "No such keychain"

```bash
# Check keychain list
security list-keychains

# Add keychain if missing
security create-keychain -p password ~/Library/Keychains/test.keychain

# Set as default
security default-keychain -s ~/Library/Keychains/test.keychain

# Unlock
security unlock-keychain -p ~/Library/Keychains/test.keychain
```

---

## 15. Python

### Description
Scripting language used by Frida, Objection, and many other tools. Python 3.10+ is required for modern versions.

### Minimum Version
**3.10+**

### Installation

#### macOS

```bash
# Install via Homebrew
brew install python@3.11

# Or install via pyenv (for multiple versions)
brew install pyenv
pyenv install 3.11.7
pyenv global 3.11.7

# Verify
python3 --version
which python3
```

#### Linux

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.11 python3-pip

# Fedora
sudo dnf install python3.11 python3-pip

# Arch
sudo pacman -S python python-pip

# Verify
python3 --version
```

### Verification Commands

```bash
# Verify Python version
python3 --version

# Verify pip version
pip3 --version

# Check installed packages
pip3 list | grep frida

# Check Python path
which python3
python3 -c "import sys; print(sys.executable)"
```

### Common Issues & Solutions

#### Issue: "ModuleNotFoundError" when installing packages

```bash
# Ensure pip is upgraded
python3 -m pip install --upgrade pip

# Use python3 -m pip instead of pip3
python3 -m pip install frida-tools

# Check Python path
python3 -c "import sys; print(sys.path)"

# Or install to user directory
python3 -m pip install --user frida-tools
```

#### Issue: "Permission denied" when installing packages

```bash
# Install to user directory
python3 -m pip install --user frida-tools

# Or use virtual environment
python3 -m venv ~/ios-pentest-env
source ~/ios-pentest-env/bin/activate
pip install frida-tools objection dsdump
```

#### Issue: "error: externally-managed-environment" (PEP 668)

**Symptom**: When running `pip install frida-tools` on macOS with Homebrew Python 3.14+, you get:
```
error: externally-managed-environment
× This environment is externally managed
× To install package(s) globally, consider switching to a virtual environment.
```

**Cause**: PEP 668 is enabled in Homebrew Python 3.14+, which blocks global pip installations to prevent breaking system packages.

**Solutions** (pick one):

**Option 1 - pipx (Recommended for isolation)**:
```bash
# Install pipx
brew install pipx

# Install Frida tools via pipx
pipx install frida-tools

# Add to PATH (add to ~/.zshrc or ~/.bash_profile)
export PATH="$HOME/.local/bin:$PATH"

# Verify
frida --version
```

**Option 2 - --break-system-packages (For dev/testing)**:
```bash
# Override PEP 668 protection (use with caution)
python3 -m pip install --break-system-packages frida frida-tools

# Binaries installed at:
# ~/Library/Python/3.14/bin/frida
# ~/Library/Python/3.14/bin/frida-* (various tools)

# Add to PATH temporarily
export PATH="$HOME/Library/Python/3.14/bin:$PATH"
```

**Option 3 - Virtual environment (Cleanest for projects)**:
```bash
# Create dedicated venv
python3 -m venv ~/.ios-pentest-venv

# Activate
source ~/.ios-pentest-venv/bin/activate

# Install
pip install frida frida-tools objection dsdump

# Add activation to shell config for convenience
echo 'source ~/.ios-pentest-venv/bin/activate' >> ~/.zshrc
```

**Post-installation verification**:
```bash
# Check Frida version
frida --version  # Should show 17.x

# List all Frida tools
ls ~/Library/Python/3.14/bin/frida*  # if using Option 2
# or
which frida  # should show path
```

---

## 16. Additional Tools

### ipatool

Download IPAs directly from the iOS App Store. Note: downloaded IPAs are FairPlay encrypted (see [references/ipa-extraction-guide.md](ipa-extraction-guide.md) §5 for full workflow, decryption, and usage).

```bash
# Install (macOS)
brew install ipatool

# Linux/Windows: download binary from https://github.com/majd/ipatool/releases

# Login to Apple ID
ipatool auth login -e apple-id@example.com

# Search for app
ipatool search "App Name"

# Download IPA
ipatool download -b com.example.app --purchase -o target.ipa

# Verify
ipatool --version
```

### pymobiledevice3

Programmatic device access and container extraction. **Recommended over `afcclient` for any automation** (see `references/libimobiledevice-guide.md` §4 for full workflow).

```bash
# Install (recommended: pipx for isolated env)
brew install pipx
pipx install pymobiledevice3

# Alternative: user-site install
python3 -m pip install --user pymobiledevice3
export PATH="$HOME/Library/Python/3.14/bin:$PATH"

# Verify
pymobiledevice3 --version

# Quick usage (no jailbreak needed, works via developer mode)
pymobiledevice3 apps list
pymobiledevice3 apps info com.example.app
pymobiledevice3 apps afc com.example.app      # interactive shell
pymobiledevice3 apps pull com.example.app Documents/local_db.sqlite ./local_db.sqlite
```

### bagbak (Jailbreak-Only)

Dumps decrypted binaries from a jailbroken device. **Requires jailbreak + frida-server running** — on a non-jailbroken device, bagbak will fail with "device not jailbroken" or hang. For non-jailbroken workflows, use Frida Gadget injection instead (see `references/runtime-integrity-bypass.md` §5).

```bash
# Install (macOS/Linux, no Homebrew formula)
git clone https://github.com/meme/bagbak.git
cd bagbak
python3 -m pip install --user .

# Verify
bagbak --version

# Dump an app's decrypted binary
bagbak com.example.app -o ./dumped/
```

### Ghidra

```bash
# Install via Homebrew
brew install --cask ghidra

# Launch
ghidraRun

# Verify
ghidraRun --version
```

### clutch (iOS Device)

```bash
# Install on jailbroken device via Cydia/Sileo
# Add repo: https://cydia.iphonecake.com/

# Or install manually
git clone https://github.com/KJCracks/Clutch.git
cd Clutch
make

# Copy to device
scp clutch root@"<device-ip>":/usr/bin/

# Run on device
ssh root@"<device-ip>" "clutch -b com.example.app"
```

### swift-demangle

```bash
# Install
pip3 install swift-demangle

# Demangle symbol
swift-demangle "$s4App16ViewControllerC9doSomethingyyF"

# Verify
swift-demangle --help
```

---

## 17. Common Troubleshooting

### Tool Not Found

```bash
# Check PATH
echo $PATH

# Add to PATH (add to ~/.zshrc or ~/.bash_profile)
export PATH="/usr/local/bin:$PATH"

# Reinstall tool
pip3 uninstall frida
pip3 install frida

# Check if tool is in different location
which -a frida
```

### Permission Errors

```bash
# Use sudo for system-wide installation
sudo pip3 install frida-tools

# Or install to user directory
pip3 install --user frida-tools

# Check file permissions
ls -la /usr/local/bin/frida
chmod +x /usr/local/bin/frida
```

### Version Mismatches

```bash
# Check all tool versions
frida --version
objection --version
dsdump --version

# Upgrade all packages
pip3 install --upgrade frida frida-tools objection dsdump

# Or pin to specific versions (see tool-versions.md — the single source of truth)
pip3 install "frida-tools==14.9.0"   # pulls frida core 17.11.0
```

### Device Connection Issues

```bash
# Check if device is detected
idevice_id -l

# Restart usbmuxd (macOS)
sudo launchctl stop com.apple.mobile.lockdown
sudo launchctl start com.apple.mobile.lockdown

# Reconnect device via USB
# Try different USB cable
# Try different USB port
```

---

## 18. libimobiledevice Ecosystem

The [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) project provides a FOSS C library and 20 CLI utilities for communicating with iOS devices over USB using native Apple protocols. **No jailbreak required.**

### Sibling Libraries

All five libraries are typically installed transitively by your package manager:

| Library | Purpose |
|---------|---------|
| **libplist** | Apple Property List parser/generator |
| **libusbmuxd** | Client library for usbmuxd |
| **usbmuxd** | USB multiplexer daemon |
| **libimobiledevice-glue** | Shared utility functions |
| **libtatsu** | TSS signing (SHSH blobs, developer images) |

`ideviceinstaller` is a **separate project** (https://github.com/libimobiledevice/ideviceinstaller) and must be installed independently.

### Installation

**macOS:**

```bash
brew install libimobiledevice ideviceinstaller
```

> Do NOT replace the macOS built-in `usbmuxd` with the Homebrew version unless you have a specific reason.

**Debian / Ubuntu (latest from source):**

```bash
sudo apt install build-essential pkg-config checkinstall git autoconf automake \
    libtool-bin libplist-dev libusbmuxd-dev libimobiledevice-glue-dev libssl-dev usbmuxd

git clone https://github.com/libimobiledevice/libtatsu && cd libtatsu && \
    ./autogen.sh && make && sudo make install && cd ..

git clone https://github.com/libimobiledevice/libimobiledevice && cd libimobiledevice && \
    ./autogen.sh --without-cython && make && sudo make install && cd ..

sudo ldconfig
sudo apt install ideviceinstaller
```

**Arch / Manjaro:**

```bash
sudo pacman -S libimobiledevice ideviceinstaller usbmuxd
```

**Fedora / RHEL:**

```bash
sudo dnf install libimobiledevice ideviceinstaller usbmuxd
```

**Windows:** Use WSL2 with the Debian/Ubuntu instructions above.

### Verification

```bash
ideviceinfo -v
ideviceinstaller -v
idevice_id -l
```

> **Full reference**: see `references/libimobiledevice-guide.md` for the complete utility reference table, pentest workflow, troubleshooting, and security notes.

---

## Quick Installation Script

```bash
#!/bin/bash

echo "=== iOS Pentesting Tools Installation ==="
echo ""

# Check Python
echo -n "Python 3: "
python3 --version || { echo "Python 3 not found. Installing..."; brew install python@3.11; }

# Upgrade pip
echo "Upgrading pip..."
python3 -m pip install --upgrade pip

# Install Frida
echo "Installing Frida..."
pip3 install frida frida-tools

# Install Objection
echo "Installing Objection..."
pip3 install objection

# Install dsdump
echo "Installing dsdump..."
pip3 install dsdump

# Install class-dump-swift (if macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Installing class-dump-swift..."
    cd /tmp
    git clone https://github.com/vimt/ClassDumpSwift.git 2>/dev/null || echo "ClassDumpSwift already exists"
    cd ClassDumpSwift
    xcodebuild -project ClassDumpSwift.xcodeproj -scheme class-dump-swift 2>/dev/null || echo "Build failed, may need manual installation"
fi

# Install ipatool
echo "Installing ipatool..."
brew install ipatool

# Verify installations
echo ""
echo "=== Verification ==="
echo -n "Frida: "
frida --version || echo "NOT FOUND"

echo -n "Objection: "
objection --version || echo "NOT FOUND"

echo -n "dsdump: "
dsdump --version || echo "NOT FOUND"

echo -n "ipatool: "
ipatool --version || echo "NOT FOUND"

echo ""
echo "=== Installation Complete ==="
```

Save as `install-ios-tools.sh`, make executable: `chmod +x install-ios-tools.sh`, run: `./install-ios-tools.sh`
