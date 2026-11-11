# Environment Setup & Toolchain for iOS Pentesting

**Complete macOS setup guide for iOS app security auditing. Works with Claude, GPT-4, Llama, or any AI agent.**

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [macOS Configuration](#2-macos-configuration)
3. [Xcode Command Line Tools](#3-xcode-command-line-tools)
4. [Homebrew Installation](#4-homebrew-installation)
5. [iOS-Specific System Tools](#5-ios-specific-system-tools)
6. [Frida Installation](#6-frida-installation)
7. [Objection Installation](#7-objection-installation)
8. [Additional Security Tools](#8-additional-security-tools)
9. [Disassembler Setup](#9-disassembler-setup)
10. [Jailbreak Device Setup](#10-jailbreak-device-setup)
11. [Proxy Configuration](#11-proxy-configuration)
12. [Certificate Setup for iOS](#12-certificate-setup-for-ios)
13. [macOS Security Settings](#13-macos-security-settings)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. System Requirements

### Minimum Hardware/Software

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| macOS Version | macOS 11 (Big Sur) | macOS 14 (Sonoma) or newer |
| RAM | 8 GB | 16 GB+ |
| Storage | 20 GB free | 50 GB+ free |
| Processor | Apple M1 or Intel i5 | Apple M2/M3 or Intel i7+ |

### Supported Device Types

| Device | iOS Version | Jailbreak Support | Notes |
|--------|-------------|-------------------|-------|
| iPhone 8-X | iOS 14-16 | checkra1n, unc0ver | Intel-based Mac recommended |
| iPhone XR-13 | iOS 14-17 | checkra1n, palera1n | Check device compatibility |
| iPhone 14-15 | iOS 16-17 | palera1n | Requires specific firmware |
| iPad (various) | iOS 14-17 | Varies by model | Check jailbreak matrix |

---

## 2. macOS Configuration

### Enable Developer Mode (macOS 13+)

macOS 13+ requires Developer Mode to be enabled for certain debugging tools:

```bash
# Check if Developer Mode is enabled
system_profiler SPDeveloperModeDataType 2>/dev/null | grep -i "developer mode"

# Enable Developer Mode (requires sudo)
sudo /usr/sbin/DevToolsSecurity -enable
sudo dseditgroup -o edit -a $(whoami) -t user _developer
```

### Install Rosetta 2 (Apple Silicon Macs)

For running Intel-based tools on Apple Silicon:

```bash
softwareupdate --install-rosetta
```

---

## 3. Xcode Command Line Tools

### Installation

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Or download full Xcode from App Store (optional but recommended)
# Xcode includes: lldb, otool, lipo, nm, dsymutil, etc.

# Verify installation
xcode-select -p
# Expected output: /Applications/Xcode.app/Contents/Developer or /Library/Developer/CommandLineTools
```

### Verify Tool Availability

```bash
# Check critical tools
which otool lipo nm dsymutil dsdump

# Verify versions
otool --version
lipo -version
nm --version
```

---

## 4. Homebrew Installation

### Install Homebrew

```bash
# Install Homebrew (non-interactive)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add Homebrew to PATH (Apple Silicon)
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"

# Add Homebrew to PATH (Intel)
echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/usr/local/bin/brew shellenv)"

# Verify installation
brew --version
```

### Essential Packages for iOS Pentesting

```bash
# Install essential tools
brew install \
  python3 \
  git \
  wget \
  curl \
  jq \
  tree \
  ripgrep \
  gnu-sed \
  gawk \
  coreutils

# Install security tools
brew install \
  openssl \
  nmap \
  wireshark \
  burp-suite-community  # or burp-suite-pro (manual install)
```

### Python Environment Setup

```bash
# Install Python 3.10+ if not installed
brew install python@3.11

# Verify Python version
python3 --version

# Upgrade pip
python3 -m pip install --upgrade pip

# Create virtual environment (recommended)
python3 -m venv ~/ios-pentest-env
source ~/ios-pentest-env/bin/activate
```

---

## 5. iOS-Specific System Tools

### Built-in macOS Tools for iOS Analysis

These tools are included with Xcode Command Line Tools:

| Tool | Purpose | Verification Command |
|------|---------|---------------------|
| `otool` | Mach-O binary analysis | `otool --version` |
| `lipo` | Universal binary handling | `lipo -version` |
| `codesign` | Code signing verification | `codesign -h` |
| `plutil` | Plist manipulation | `plutil -h` |
| `nm` | Symbol extraction | `nm --version` |
| `strings` | String extraction | `strings --version` |
| `security` | Keychain/certificate management | `security -h` |

### Verify System Tools

```bash
# Test all critical system tools
echo "Testing system tools..."

echo -n "otool: "
otool -l $(which ls) | head -1 && echo "OK" || echo "FAIL"

echo -n "lipo: "
lipo -info $(which ls) | head -1 && echo "OK" || echo "FAIL"

echo -n "codesign: "
codesign -v $(which ls) && echo "OK" || echo "FAIL"

echo -n "plutil: "
plutil -version | head -1 && echo "OK" || echo "FAIL"

echo -n "nm: "
nm -gU $(which ls) | head -1 && echo "OK" || echo "FAIL"

echo -n "strings: "
strings $(which ls) | head -1 && echo "OK" || echo "FAIL"

echo -n "security: "
security find-identity | head -1 && echo "OK" || echo "FAIL"
```

---

## 6. Frida Installation

### Install Frida

```bash
# Install Frida tools via pip
pip3 install frida-tools frida

# Verify installation
frida --version
frida-ps --version
```

### Install Frida on Jailbroken Device

```bash
# Ensure device is connected via USB
# Open Cydia/Sileo on device and add Frida repo:
# URL: https://build.frida.re

# Install via apt (on device via SSH)
ssh root@"<device-ip>"
apt-get update
apt-get install frida

# Or install pre-built server from Frida releases
# Download from: https://github.com/frida/frida/releases
# Transfer to device: scp frida-server-*-*-* root@"<device-ip>":/usr/bin/
# chmod +x /usr/bin/frida-server
```

### Verify Frida Connection

```bash
# List running processes on device (USB)
frida-ps -U

# List running processes on device (network)
frida-ps -H "<device-ip>":27042

# Attach to process (example)
frida -U -f com.example.app
```

### Common Frida Commands

```bash
# Spawn app and attach
frida -U -f com.example.app

# Attach to running process
frida -U com.example.app

# Load script
frida -U -l script.js -f com.example.app

# List installed apps
frida-ps -Ua

# List loaded modules
frida -U com.example.app -e 'Process.enumerateModules()'
```

---

## 7. Objection Installation

### Install Objection

```bash
# Install via pip
pip3 install objection

# Verify installation
objection --version
```

### Objection Basic Usage

```bash
# Connect to device
objection -g com.example.app explore

# Common objection commands
# Once in explore mode:
# ios jailbreak disable   - Disable jailbreak detection
# ios plist read           - Read Info.plist
# ios keychain dump        - Dump keychain
# ios nsuserdefaults read  - Read UserDefaults
# ios pasteboard monitor    - Monitor clipboard
# ios hooking list         - List hookable methods
# ios sslpinning disable   - Disable SSL pinning
```

### Objection Device Exploration

```bash
# Explore installed apps
objection explore

# List all apps
objection explore --list-apps

# Get app information
objection -g com.example.app explore
# Then: ios info
```

---

## 8. Additional Security Tools

### Install class-dump and dsdump

```bash
# Install class-dump (for Objective-C class extraction)
brew install class-dump

# Install dsdump (alternative to class-dump)
pip3 install dsdump

# Verify installations
class-dump --version
dsdump --version
```

### Install jtool2

> **jtool2 is NOT available via Homebrew.** It must be downloaded manually. On Apple Silicon the binary is x86_64 — install Rosetta 2 first.

```bash
# jtool2 is an enhanced otool for Mach-O analysis
# Download from: https://newosxbook.com/tools/jtool.html

# Install manually
cd /tmp
wget https://newosxbook.com/tools/jtool/Jtool2.tgz
tar -xzf Jtool2.tgz
sudo cp jtool2 /usr/local/bin/
sudo chmod +x /usr/local/bin/jtool2
xattr -d com.apple.quarantine /usr/local/bin/jtool2  # Apple Silicon

# Apple Silicon: install Rosetta 2 if not present
softwareupdate --install-rosetta

# Verify installation
jtool2 -h
```

### Install SimForge

> **Apple Silicon only.** SimForge runs arm64 iOS apps in the iOS Simulator with dylib injection (no jailbroken device required). Requires Xcode Command Line Tools.

```bash
# Clone and build
git clone https://github.com/EthanArbuckle/simforge.git
cd simforge
xcodebuild -project simforge.xcodeproj -scheme simforge -configuration Release

# Install (binary ends up in DerivedData)
cp ~/Library/Developer/Xcode/DerivedData/simforge-*/Build/Products/Release/simforge /usr/local/bin/

# Verify
simforge
# Should print the usage with 3 subcommands: convert, launch, list-runtimes
```

### Install swift-demangle

```bash
# For demangling Swift symbols
pip3 install swift-demangle
```

---

## 9. Disassembler Setup

### Hopper Disassembler

```bash
# Download Hopper from: https://www.hopperapp.com/
# Hopper is a paid tool with a free trial

# Create symbolic link for CLI access
sudo ln -s /Applications/Hopper\ Disassembler\ v4.app/Contents/MacOS/hopper /usr/local/bin/hopper

# Verify installation
hopper --version

# Decompile binary
hopper -o /path/to/output /path/to/binary
```

### Alternative: Ghidra

```bash
# Install Ghidra (free, open-source)
brew install --cask ghidra

# Launch Ghidra
ghidraRun

# Or via CLI
ghidraRun /path/to/project
```

---

## 10. Jailbreak Device Setup

### Jailbreak Options

| Tool | iOS Version | Device Type | Difficulty | Notes |
|------|-------------|-------------|------------|-------|
| checkra1n | iOS 12-14 | A5-A11 chips | Easy | USB/DFU mode required |
| unc0ver | iOS 11-13 | Most devices | Medium | Not compatible with A12+ |
| palera1n | iOS 15-17 | A8-A14+ | Medium | Rootless/dirty cow |
| Dopamine | iOS 15-16 | A12-A17 | Easy | Rootless, modern |

### checkra1n Setup (Recommended for iOS 12-14)

```bash
# Download checkra1n
# Mac: https://checkra.in/
# Linux: https://checkra.in/linux

# Connect device in DFU mode
# iPhone 6s-8: Hold Volume + Power → Count to 5 → Release Power, hold Volume → Count to 10
# iPhone X: Hold Volume Up → Count to 3 → Release Volume Up → Hold Side button → Count to 10 → Release Side, hold Volume Up

# Run checkra1n
./checkra1n

# After jailbreak, install Cydia Sileo (optional)
# Open checkra1n helper on device
```

### palera1n Setup (Recommended for iOS 15-17)

```bash
# Clone palera1n
git clone https://github.com/palera1n/palera1n.git
cd palera1n

# Build (if needed)
make

# Prepare device (DFU mode)
# Run palera1n
./palera1n -f -c

# On device, install Zebra/Sileo via helper
```

### Post-Jailbreak Setup

```bash
# SSH into device
# Default credentials: root / alpine
ssh root@"<device-ip>"
# Find device IP: Settings → Wi-Fi → (i) icon

# Change default password
passwd

# Update repositories
apt-get update
apt-get upgrade

# Install essential tools
apt-get install \
  openssh \
  curl \
  wget \
  git \
  python3 \
  python3-pip \
  vim \
  nano \
  tcpdump \
  openssl

# Install Frida server (if not already installed)
# See section 6 above
```

---

## 11. Proxy Configuration

### Burp Suite Setup

```bash
# Install Burp Suite Community Edition
brew install --cask burp-suite-community

# Or install Burp Suite Professional (requires license)
# Download from: https://portswigger.net/burp/pro

# Configure Burp to listen on all interfaces
# Proxy → Options → Add → Bind to port: 8080 → Bind to address: 0.0.0.0
```

### iOS Device Proxy Configuration

```bash
# Find your Mac's IP
ifconfig | grep "inet " | grep -v 127.0.0.1

# Option 1: Configure via Settings
# On device: Settings → Wi-Fi → (i) → HTTP Proxy → Manual
# Server: "<your-mac-ip>"
# Port: 8080

# Option 2: Configure via libimobiledevice
brew install libimobiledevice
ideviceproxy -p 8080 "<device-udid>"

# Verify proxy
curl -x http://"<your-mac-ip>":8080 http://example.com
```

### Proxy Tools

```bash
# Install mitmproxy (alternative to Burp)
pip3 install mitmproxy

# Start mitmproxy
mitmproxy --listen-host 0.0.0.0 --listen-port 8080

# Install mitmproxy certificate on device
# Visit http://mitm.it on device
```

---

## 12. Certificate Setup for iOS

### Create Self-Signed CA Certificate

```bash
# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout ios-ca.key \
  -out ios-ca.crt \
  -days 365 \
  -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=iOS-Test-CA"

# Convert to DER format (iOS requires DER)
openssl x509 -in ios-ca.crt -outform der -out ios-ca.der

# Generate PKCS#12 format (for Burp)
openssl pkcs12 -export -out ios-ca.p12 -inkey ios-ca.key -in ios-ca.crt
```

### Install Certificate on iOS Device

```bash
# Transfer certificate to device
# Option 1: AirDrop (send ios-ca.der)
# Option 2: Upload to web server and download on device
# Option 3: Email to device

# On device:
# 1. Open Settings → General → VPN & Device Management → Install Profile
# 2. Tap ios-ca.der → Install
# 3. Enter device passcode
# 4. Go to Settings → General → About → Certificate Trust Settings
# 5. Enable "Full Trust" for your CA certificate
```

### Install Burp CA Certificate

```bash
# Start Burp Suite
# Proxy → Options → CA Certificate → Export Certificate in DER format

# Transfer DER certificate to device (see above)
# Install and enable full trust (see above)

# Verify certificate installation
# Visit http://burp in Safari
# You should see "Burp Suite" page
```

---

## 13. macOS Security Settings

### Allow Unsigned Binaries

macOS may block unsigned or downloaded binaries. Remove quarantine attribute:

```bash
# Remove quarantine from downloaded tools
xattr -d com.apple.quarantine /path/to/tool

# Example for frida-server
xattr -d com.apple.quarantine frida-server-ios-arm64

# Recursive removal for directory
xattr -cr /path/to/directory
```

### Allow Security Tools

```bash
# Enable Developer Tools security
sudo /usr/sbin/DevToolsSecurity -enable

# Add user to developer group
sudo dseditgroup -o edit -a $(whoami) -t user _developer

# Verify
groups | grep _developer
```

### Disable Gatekeeper (Use with Caution)

```bash
# Check Gatekeeper status
spctl --status

# Disable Gatekeeper (not recommended for daily use)
sudo spctl --master-disable

# Re-enable Gatekeeper
sudo spctl --master-enable

# Allow specific app
sudo spctl --add /path/to/app.app
```

### App Transport Security Configuration

For testing apps that need to bypass ATS:

```bash
# Create ATS exception file (for your test apps)
cat > ~/Library/Mobile\ Documents/com~apple~CloudDocs/ats-exception.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF
```

---

## 14. Troubleshooting

### Common Issues

#### Issue: codesign: command not found

**Solution:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Set developer directory
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

# Verify
which codesign
```

#### Issue: Frida cannot attach to process

**Solution:**
```bash
# Check if frida-server is running on device
ps aux | grep frida

# Restart frida-server on device
ssh root@"<device-ip>" "killall frida-server; /usr/bin/frida-server &"

# Check device connectivity
idevice_id -l
```

#### Issue: Cannot extract IPA from device

**Solution:**
```bash
# Install ipatool (Go binary, not the Python wrapper)
brew install ipatool

# Login to Apple ID
ipatool auth login -e apple-id@example.com

# Download IPA
ipatool download -b com.example.app --purchase -o target.ipa
```

> Note: IPAs downloaded with ipatool are FairPlay encrypted. See [references/ipa-extraction-guide.md](ipa-extraction-guide.md) §5 for the decrypt workflow.

#### Issue: Jailbreak not working

**Solution:**
```bash
# Check iOS version compatibility
# Check device model
# Try different jailbreak tool (see Section 10)

# Use semi-untethered jailbreak if untethered fails
# Example: Taurine, unc0ver
```

#### Issue: Certificate not trusted

**Solution:**
```bash
# On iOS device:
# Settings → General → About → Certificate Trust Settings
# Enable "Full Trust" for your CA certificate

# Restart Safari after enabling trust
killall Safari
```

#### Issue: Cannot install third-party tools

**Solution:**
```bash
# Check if using rootless jailbreak
# Some tools require rootful jailbreak

# Use rootless versions of tools
# Example: Sileo instead of Cydia

# Check package manager
which apt-get
which dpkg
```

---

## Reference Links

- **OWASP MASTG**: https://mas.owasp.org/MASTG/
- **Frida Documentation**: https://frida.re/docs/
- **Objection Documentation**: https://github.com/sensepost/objection
- **iOS Reverse Engineering**: https://github.com/iosre/iOSAppRE
- **Hopper Disassembler**: https://www.hopperapp.com/
- **checkra1n**: https://checkra.in/
- **Burp Suite**: https://portswigger.net/burp

---

## Quick Verification Checklist

Run this to verify your environment is ready:

```bash
#!/bin/bash

echo "=== iOS Pentesting Environment Verification ==="
echo ""

# System checks
echo "System:"
sw_vers
echo ""

# Python
echo -n "Python 3: "
python3 --version | head -1 || echo "NOT FOUND"

# Homebrew
echo -n "Homebrew: "
brew --version | head -1 || echo "NOT FOUND"

# Xcode tools
echo -n "Xcode CLI: "
xcode-select -p > /dev/null 2>&1 && echo "INSTALLED" || echo "NOT FOUND"

# Critical tools
tools=("otool" "lipo" "codesign" "plutil" "nm" "strings" "security")
echo ""
echo "System Tools:"
for tool in "${tools[@]}"; do
    echo -n "$tool: "
    which $tool > /dev/null 2>&1 && echo "OK" || echo "NOT FOUND"
done

# Python packages
echo ""
echo "Python Packages:"
packages=("frida" "frida-tools" "objection" "dsdump")
for pkg in "${packages[@]}"; do
    echo -n "$pkg: "
    pip3 show $pkg > /dev/null 2>&1 && echo "OK" || echo "NOT FOUND"
done

# Device connection
echo ""
echo "Device Connection:"
echo -n "USB Device: "
idevice_id -l 2>/dev/null && echo "CONNECTED" || echo "NOT CONNECTED"

echo ""
echo "=== Verification Complete ==="
```

Save as `verify-ios-env.sh`, make executable: `chmod +x verify-ios-env.sh`, run: `./verify-ios-env.sh`
