# iOS Jailbreak Setup Guide for Mobile Security Testing

## Table of Contents

1. [Overview](#overview)
2. [Supported Jailbreak Methods](#supported-jailbreak-methods)
3. [Jailbreak Methods in Detail](#jailbreak-methods-in-detail)
4. [Post-Jailbreak Setup](#post-jailbreak-setup)
5. [Frida Server Installation](#frida-server-installation)
6. [SSH Configuration](#ssh-configuration)
7. [USB Communication Tools](#usb-communication-tools)
8. [Package Manager Sources](#package-manager-sources)
9. [Non-Jailbreak Alternatives](#non-jailbreak-alternatives)
10. [Troubleshooting](#troubleshooting)
11. [OWASP MASTG References](#owasp-mastg-references)
12. [Security Considerations](#security-considerations)

---

## Overview

Jailbreaking iOS devices is a critical component of mobile application security testing, particularly for dynamic analysis and runtime manipulation. This guide provides comprehensive information on various jailbreak methods, supported iOS versions, and essential post-jailbreak configurations for security testing environments.

### Why Jailbreak for Security Testing?

Jailbreaking enables:
- **Runtime instrumentation**: Hooking and manipulating application behavior
- **Filesystem access**: Inspecting application containers and data stores
- **Process debugging**: Advanced debugging capabilities
- **Network interception**: SSL/TLS certificate installation and proxy setup
- **Dynamic analysis**: Real-time behavior observation and modification

---

## Supported Jailbreak Methods

### Comparison Table

| Method | iOS Support | Device Support | Type | Developer | Notes |
|--------|------------|----------------|------|-----------|-------|
| checkra1n | 12.0 - 14.8.1 | A11 and below | Bootrom exploit | checkra1n team | Semi-untethered, DFU mode |
| unc0ver | 11.0 - 14.8 | A8 - A14 | Kernel exploit | Pwn20wnd | Semi-untethered, Safari-based |
| palera1n (rooted) | 15.0 - 16.6.1 | A8 - A11 | Bootrom | palera1n team | Rootful/Rootless options |
| palera1n (rootless) | 15.0 - 16.6.1 | A12+ | Bootrom | palera1n team | Requires PC for each boot |
| Dopamine | 15.0 - 16.6.1 | A12+ (most) | Kernel | opa334 and others | Semi-untethered, rootless |
| Fugu15 | 16.0 - 16.1.2 | A15 and below | Kernel | Linus Henze | Untethered (early) |

### Device Architecture Compatibility

| Architecture | Devices | Best Jailbreak Method |
|--------------|---------|----------------------|
| A4 | iPhone 4, iPod 4 | checkra1n (older iOS) |
| A5-A11 | iPhone 5s to 8/X | checkra1n, unc0ver |
| A12-A14 | iPhone XS to 12 Pro Max | unc0ver, Dopamine |
| A15-A16 | iPhone 13 to 14 Pro Max | Dopamine, palera1n |
| A17+ | iPhone 15+ | No public jailbreak (as of 2024) |

---

## Jailbreak Methods in Detail

### checkra1n

#### Supported Versions
- iOS 12.0 to 14.8.1
- Supports A11 and below devices

#### Installation Steps

**Prerequisites:**
```bash
# macOS host with checkra1n app or CLI
# USB cable for device connection
# Device in DFU mode (most critical step)

# Verify DFU mode (screen should be black)
system_profiler SPUSBDataType | grep iPhone
```

**Installation Process:**

```bash
# Method 1: Using checkra1n GUI
1. Download checkra1n from https://checkra.in
2. Connect device via USB
3. Put device in DFU mode:
   - iPhone 6s and earlier: Hold Home + Power for 10s, release Power, keep Home for 5s
   - iPhone 7: Hold Volume Down + Power for 10s, release Power, keep Volume Down for 5s
   - iPhone 8 to X: Quick press Volume Up, Volume Down, then hold Side button until DFU
4. Click "Start" in checkra1n app
5. Follow on-screen instructions for bootrom exploit execution
6. Device will reboot with checkra1n loader

# Method 2: Using checkra1n CLI
brew install checkra1n
checkra1n --verbose
# Follow same DFU process as GUI
```

**Post-Installation:**

```bash
# First boot - run checkra1n loader from device
# Install Cydia (recommended) or Sileo
# Reboot to complete jailbreak

# Verification from device
ls /var/mobile/Media/Downloads  # Should have checkra1n folder
```

#### Security Implications

**Pros:**
- Bootrom exploit (cannot be patched by Apple software update)
- Stable across supported versions
- Semi-untethered (can re-jailbreak easily)

**Cons:**
- DFU mode required on every boot
- Older devices only (A11 and below)
- Can be unstable on some devices

#### OWASP MASTG Reference
- MASTG-APP-SEC-0010 (Runtime Manipulation Prevention)
- MASTG-APP-SEC-0011 (Debugging Protection)

---

### unc0ver

#### Supported Versions
- iOS 11.0 to 14.8
- Supports A8 to A14 devices

#### Installation Steps

**Prerequisites:**
```bash
# unc0ver IPA file
# AltStore or Cydia Impactor for sideloading
# Sufficient battery (>50%)
```

**Installation Process:**

```text
# Method 1: Using AltStore (recommended)
1. Install AltStore on macOS and iOS device
2. Download unc0ver IPA from https://unc0ver.dev
3. Open AltStore on Mac, install unc0ver to device
4. Launch unc0ver on device
5. Tap "Jailbreak" button
6. Wait for exploit (device may respring multiple times)

# Method 2: Using Cydia Impactor (legacy)
1. Download unc0ver IPA
2. Connect device to Mac via USB
3. Drag IPA to Cydia Impactor
4. Enter Apple ID credentials for signing (7-day certificate)
5. Unc0ver installs on device
6. Trust developer certificate: Settings > General > Profiles

# Method 3: Using the .deb package (requires Sileo/Cydia already)
# Only for re-installing or updating existing unc0ver jailbreak
wget https://unc0ver.dev/downloads/unc0ver.deb
dpkg -i unc0ver.deb
```

**Post-Installation:**

```bash
# Verification
ls /var/jb  # Rootful jailbreaks
ls /var/mobile/.installed_unc0ver  # Installation markers

# Check for Sileo/Cydia
which sileo
which cydia
```

#### Security Implications

**Pros:**
- Semi-untethered (no DFU mode required)
- Safari-based installation possible
- Wide device support

**Cons:**
- Must be re-installed every 7 days (AltStore) or 1 year (paid dev certificate)
- Can be patched by Apple updates
- May have stability issues on newer iOS versions

#### OWASP MASTG Reference
- MASTG-TEST-0010 (Dynamic Analysis Environment Setup)

---

### palera1n

#### Rootless vs Rootful

| Type | Description | Use Case |
|------|-------------|----------|
| Rootless | Modifies files in `/var/jb` instead of root filesystem | Standard security testing |
| Rootful | Modifies actual root filesystem | Advanced modifications, A8-A11 devices |

#### Supported Versions
- iOS 15.0 to 16.6.1
- A8 to A11: Rootless + Rootful
- A12+: Rootless only

#### Installation Steps (Rootless)

**Prerequisites:**
```bash
# macOS with Xcode (or Linux with checkra1n dependencies)
# palera1n CLI tool
# Device in DFU mode (rootless) or Recovery Mode (rootful)

# Install palera1n CLI
brew install palera1n
```

**Installation Process:**

```bash
# Rootless (recommended for most security testing)
1. Put device in DFU mode
2. Run:
   palera1n --tui --dfuhelper  # For DFU mode help
   palera1n --tui --debug  # For verbose output

# The TUI will guide you through:
# - DFU mode verification
# - Exploit injection
# - Bootstrap installation
# - Sileo/Zebra installation

# Rootful (A8-A11 only)
1. Put device in Recovery Mode
2. Run:
   palera1n --tui --rootful --debug

# Note: Rootless requires PC connection on every boot
# Create bootstrap for on-device re-jailbreak:
palera1n --tui --dfuhelper
```

**Post-Installation:**

```bash
# Verification - rootless
ls /var/jb  # Main jailbreak filesystem

# Install Frida dependencies
sileo install frida

# Verification
which frida-server
```

#### Security Implications

**Pros:**
- Supports modern iOS versions (15-16)
- Clean separation (rootless)
- Actively maintained

**Cons:**
- Rootless requires PC for each boot
- More complex setup than unc0ver/Dopamine
- Limited app compatibility

#### OWASP MASTG Reference
- MASTG-APP-SEC-0012 (Filesystem Integrity Protection)

---

### Dopamine

#### Supported Versions
- iOS 15.0 to 16.6.1
- Most A12+ devices (check compatibility list)

#### Installation Steps

**Prerequisites:**
```bash
# Dopamine IPA or .deb
# Safari browser on device
# Sufficient battery (>50%)
```

**Installation Process:**

```text
# Method 1: Using Safari-based installer
1. Open Safari on device
2. Navigate to: https://github.com/opa334/Dopamine/releases
3. Download latest Dopamine .ipa
4. Tap to install (iOS should prompt)
5. Launch Dopamine
6. Tap "Jailbreak" button
7. Wait for exploit completion

# Method 2: Using AltStore
1. Download Dopamine IPA
2. Install via AltStore
3. Launch Dopamine
4. Tap "Jailbreak"

# Note: Dopamine installs Sileo by default
# Can also install Zebra package manager
```

**Post-Installation:**

```bash
# Verification - rootless
ls /var/jb

# Check installed tweaks
ls /var/jb/Library/MobileSubstrate/DynamicLibraries/

# Enable developer mode (iOS 16+)
# Settings > Privacy & Security > Developer Mode
# Reboot and confirm
```

#### Security Implications

**Pros:**
- Semi-untethered (no PC required for re-jailbreak)
- Modern UI and user experience
- Rootless by design
- Wide device support for A12+

**Cons:**
- Newer method, less battle-tested
- Some tweak compatibility issues
- Rootless limitations for some testing scenarios

#### OWASP MASTG Reference
- MASTG-APP-SEC-0013 (Code Integrity Verification)

---

## Post-Jailbreak Setup

### Essential Tweaks for Security Testing

```bash
# Install via Sileo or command line

# SSH server
sileo install openssh
# or
apt install openssh

# Development tools
sileo install adv-cmds
sileo install coreutils
sileo install vim
sileo install wget
sileo install curl
sileo install unzip

# File system tools
sileo install ifile  # File manager
sileo install filza  # Alternative file manager

# Development utilities
sileo install ldid  # Binary signing
sileo install cycript  # Runtime manipulation
sileo install clutch  # App decryption
sileo install frida
```

### Configuration Files

```bash
# SSH configuration - create directory
mkdir -p /var/jb/var/mobile/.ssh

# SSH daemon - ensure enabled
launchctl load -w /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist

# Check status
ps aux | grep sshd

# Enable password authentication (for initial setup)
vim /var/jb/etc/ssh/sshd_config
# Set: PasswordAuthentication yes

# Change default password
passwd alpine  # Default jailbreak password
# CHANGE THIS IMMEDIATELY
```

### Network Setup

```bash
# Install proxy tools for network interception
sileo install proxyman  # HTTP proxy configuration

# Install certificate utilities
sileo install ca-tools  # Certificate management
```

---

## Frida Server Installation

### Version Matching

**Critical Requirement:** Frida client version on host MUST match Frida server version on device.

```bash
# On host machine
# Check Frida version
frida --version
# Example output: 17.11.0  (pinned version: references/tool-versions.md)

# Download matching server
# Architecture: arm64 (standard), arm64e (devices with PAC)
# Get device architecture from device:
uname -m

# Download the server matching your host (pinned version: references/tool-versions.md)
FRIDA_VERSION=$(frida --version)

# For iOS 16+ (arm64e):
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-arm64e.xz

# For iOS 12-15 (arm64):
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-arm64.xz

# Extract (arm64e example)
xz -d frida-ios-${FRIDA_VERSION}-arm64e.xz
mv frida-ios-${FRIDA_VERSION}-arm64e frida-server
chmod +x frida-server
```

### Installation Methods

#### Method 1: SSH Upload (Standard)

```bash
# Step 1: Install openssh on device (if not already)
sileo install openssh

# Step 2: Connect device to WiFi and get IP
# On device: Settings > WiFi > Tap (i) > IP Address
# Example: 192.168.1.100

# Step 3: SSH to device
ssh root@192.168.1.100
# Default password: alpine

# Step 4: Create Frida directory
mkdir -p /var/jb/usr/bin

# Step 5: Upload frida-server from host
# Exit SSH session (Ctrl+D)
scp frida-server root@192.168.1.100:/var/jb/usr/bin/frida-server

# Step 6: Set permissions and ownership
ssh root@192.168.1.100
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server
```

#### Method 2: USB Muxd (Recommended)

```bash
# On host - install required tools
brew install libusbmuxd usbmuxd libimobiledevice
brew install --HEAD usbmuxd  # For latest version

# Start usbmuxd
brew services start usbmuxd

# Get device UDID
idevice_id -l
# Example: a1b2c3d4e5f6...

# SSH via USB tunnel
iproxy 2222 22 1> /dev/null &

# Now SSH to localhost
ssh -p 2222 root@localhost
# Password: alpine

# Upload frida-server via USB
exit  # From SSH session
scp -P 2222 frida-server root@localhost:/var/jb/usr/bin/frida-server

# SSH back and set permissions
ssh -p 2222 root@localhost
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server
```

#### Method 3: Direct Installation from Sileo

```bash
# On device via Sileo
# Add BigBoss repo if not already:
# Sources > Edit > Add > http://apt.thebigboss.org/repofiles/cydia/

# Install Frida
# Search for "frida" and install frida-server

# This method is easier but may not always have the latest version
```

### Running Frida Server

```bash
# On device (via SSH)
# Standard startup
/var/jb/usr/bin/frida-server

# With debug output
/var/jb/usr/bin/frida-server -D

# As background process (recommended for testing)
/var/jb/usr/bin/frida-server &

# Verify running on host
frida-ps -U
# Should list processes on device

# Test with simple script
frida-ps -U
# Should show output like:
# PID  Name
# ---  ----
# 123  SpringBoard
# 456  backboardd
# ...
```

### Auto-Start Frida Server

```bash
# Create launchd plist for automatic startup
# On device:

cat > /var/jb/Library/LaunchDaemons/re.frida.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>re.frida.server</string>
    <key>Program</key>
    <string>/var/jb/usr/bin/frida-server</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load the service
launchctl load -w /var/jb/Library/LaunchDaemons/re.frida.server.plist

# Verify
launchctl list | grep frida
```

---

## SSH Configuration

### SSH Access Methods

#### WiFi Access

```bash
# Enable SSH server (if not running)
launchctl load -w /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist

# Get device IP
# On device: Settings > WiFi > Tap (i) for connected network

# From host
ssh root@DEVICE_IP
# Example: ssh root@192.168.1.100

# Change default password (IMPORTANT!)
passwd
# Enter new password twice
```

#### USB Access (Recommended)

```bash
# Advantages: No WiFi required, more stable
# Requires: libusbmuxd, usbmuxd on host

# Start iproxy
iproxy 2222 22

# Connect via USB
ssh -p 2222 root@localhost

# Create alias for convenience
echo 'alias ios-ssh="ssh -p 2222 root@localhost"' >> ~/.zshrc
source ~/.zshrc
```

### SSH Key Authentication (Recommended)

```bash
# On host - generate SSH key (if not exists)
ssh-keygen -t ed25519 -C "ios-pentesting" -f ~/.ssh/ios-key
# Leave passphrase empty for convenience during testing

# Copy to device
ssh-copy-id -p 2222 -i ~/.ssh/ios-key.pub root@localhost
# Or manually:
ssh -p 2222 root@localhost
mkdir -p ~/.ssh
cat > ~/.ssh/authorized_keys << 'EOF'
# Paste your public key here from ~/.ssh/ios-key.pub
EOF
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Disable password authentication (more secure)
vim /var/jb/etc/ssh/sshd_config
# Set: PasswordAuthentication no

# Restart SSH
launchctl unload /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist
launchctl load -w /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist
```

### SSH Configuration Tips

```bash
# Create SSH config entry for convenience
cat >> ~/.ssh/config << 'EOF'

Host ios-usb
    HostName localhost
    Port 2222
    User root
    IdentityFile ~/.ssh/ios-key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF

# Now connect with:
ssh ios-usb

# Create host-specific commands
echo 'alias ios-ls="ssh ios-usb ls -la /var/mobile/Containers/Data/Application/"' >> ~/.zshrc
echo 'alias ios-cd="ssh ios-usb cd"' >> ~/.zshrc
```

---

## USB Communication Tools

### usbmuxd

```bash
# USB multiplexing daemon for iOS device communication
# Automatically installed with libimobiledevice

# Start/stop service
brew services start usbmuxd
brew services stop usbmuxd
brew services restart usbmuxd

# Check status
brew services list | grep usbmuxd
```

### iproxy (TCP Port Forwarding)

```bash
# Forward local port to device port
iproxy LOCAL_PORT DEVICE_PORT

# Example: Forward SSH (22) to local 2222
iproxy 2222 22

# Forward multiple ports
iproxy 2222:22 8080:80

# Background mode
iproxy 2222 22 1> /dev/null &
iproxy 27042:27042 1> /dev/null &  # Frida default ports

# Kill iproxy
pkill iproxy
```

### irelay (Alternative)

```bash
# Alternative to iproxy, part of libirecovery
brew install libirecovery

# Usage similar to iproxy
irelay LOCAL_PORT DEVICE_PORT
```

### Device Connection Management

```bash
# List connected devices
idevice_id -l

# Get device info
ideviceinfo

# Get device name
idevicename

# Pair device (if needed)
idevicepair pair

# Unpair
idevicepair unpair
```

---

## Package Manager Sources

### Default Repositories

```bash
# BigBoss (default in Cydia/Sileo)
# URL: http://apt.thebigboss.org/repofiles/cydia/
# Purpose: Tweaks, utilities, tools

# ModMyi (legacy, often default)
# URL: http://apt.modmyi.com/
# Purpose: Themes, tweaks, utilities

# Cydia/Telesphoreo
# URL: http://apt.saurik.com/
# Purpose: Foundation packages, base utilities
```

### Security Testing Specific Repos

```bash
# Add via Sileo or edit sources.list

# Method 1: Via Sileo UI
# Sources > Edit > Add > Enter URL

# Method 2: Command line
echo "deb https://build.frida.re ./" >> /var/jb/etc/apt/sources.list.d/frida.list
echo "deb https://repo.biteyourapple.net/ default main" >> /var/jb/etc/apt/sources.list.d/bite.list

# Update sources
apt update
```

### Essential Security Tools to Install

```bash
# Package installation via apt or Sileo

# Reverse engineering tools
apt install frida
apt install objection
apt install cycript
apt install clutch

# File analysis
apt install class-dump
apt install otool
apt install lipo

# Network tools
apt install tcpdump
apt install nmap
apt install wireshark  # if available

# Development
apt install ldid
apt install theos
apt install logos
```

---

## Non-Jailbreak Alternatives

### AltStore

```bash
# Side-load IPA files without jailbreak
# Limitations:
# - 7-day re-signing requirement (free)
# - 3 apps per device (free)
# - No system-wide modifications
# - Limited to user-space applications

# Installation:
# 1. Install AltServer on Mac
# 2. Install AltStore on device
# 3. Side-load testing IPAs

# Security Testing Limitations:
# - No Frida server
# - No SSH access
# - No filesystem access
# - Cannot instrument system processes
```

### Corellium

```bash
# Cloud-based iOS virtualization
# Advantages:
# - No physical device required
# - Full filesystem access
# - Root access without jailbreak
# - Snapshot/restore capabilities
# - Multiple iOS versions available

# Use Cases:
# - Quick testing without jailbreak setup
# - Automated testing pipelines
# - Testing on multiple iOS versions
# - Educational/training environments

# Limitations:
# - Paid service
# - Requires internet connection
# - Some hardware features not available (camera, GPS)

# Setup:
# 1. Create account at https://corellium.com
# 2. Launch iOS instance
# 3. Install testing tools
# 4. SSH directly into instance
```

### Emulator-Based Testing

```bash
# iOS Simulator (limited security testing)
# Xcode includes iOS simulator
# Limitations:
# - No jailbreak equivalent
# - No system-wide hooks
# - Simulated environment differences
# - Cannot test hardware-specific features

# Use Cases:
# - Initial app functionality testing
# - UI/UX testing
# - Basic API testing

# NOT Suitable for:
# - SSL pinning bypass
# - Filesystem security testing
# - Keychain analysis
# - Dynamic instrumentation
```

### Comparing Jailbreak vs Non-Jailbreak

| Feature | Jailbreak | AltStore | Corellium |
|---------|-----------|----------|-----------|
| System-wide hooks | ✅ | ❌ | ✅ |
| Filesystem access | ✅ | ❌ | ✅ |
| SSH access | ✅ | ❌ | ✅ |
| Frida server | ✅ | ❌ | ✅ |
| Free | ✅ | ✅ | ❌ |
| Physical device | ✅ | ✅ | ❌ |
| Easy setup | ⚠️ | ✅ | ✅ |
| Latest iOS | ⚠️ | ✅ | ⚠️ |

---

## Troubleshooting

### Common Issues

#### Device Not Detected

```bash
# Check usbmuxd status
brew services list | grep usbmuxd

# Restart usbmuxd
brew services restart usbmuxd

# Try different USB port and cable
# Use original Apple cable if possible

# Verify device detection
idevice_id -l
```

#### SSH Connection Refused

```bash
# Check if SSH daemon is running
launchctl list | grep sshd

# Load SSH daemon
launchctl load -w /var/jb/Library/LaunchDaemons/com.openssh.sshd.plist

# Check port 22 is listening
netstat -an | grep 22

# Try different connection method
# If WiFi fails, try USB with iproxy
```

#### Frida Version Mismatch

```bash
# Error: "Failed to enumerate processes: unable to communicate with remote frida-server"

# Solution: Match versions exactly
frida --version  # On host
# Download matching frida-server version for device

# Re-install frida-server
# See installation section above
```

#### Device Won't Enter DFU Mode

```bash
# DFU mode timing is critical
# Practice entering DFU mode multiple times

# Alternative: Use palera1n's DFU helper
palera1n --tui --dfuhelper

# Check device support
# A11 and below: checkra1n
# A12+: palera1n or Dopamine
```

#### Apps Crashing After Jailbreak

```bash
# Disable Mobile Substrate temporarily
# Move tweak dylibs out of active directory
mv /var/jb/Library/MobileSubstrate/DynamicLibraries/* ~/tmp/

# Re-enable selectively
# Only load known-safe tweaks for security testing
```

### Log Analysis

```bash
# View system logs
dmesg

# View crash logs
cat /var/log/syslog

# View jailbreak-specific logs
tail -f /var/jb/var/log/frida-server.log  # If configured

# Check for specific errors
grep -i "error" /var/log/syslog
grep -i "frida" /var/log/syslog
```

---

## OWASP MASTG References

### Relevant Sections

| MASTG Section | Topic | Relevance |
|---------------|-------|-----------|
| MASTG-TEST-0010 | Dynamic Analysis Environment Setup | Jailbreak setup |
| MASTG-TEST-0011 | Runtime Manipulation | Frida server |
| MASTG-APP-SEC-0010 | Runtime Manipulation Prevention | Jailbreak impact |
| MASTG-APP-SEC-0011 | Debugging Protection | Detection bypass |
| MASTG-APP-SEC-0012 | Filesystem Integrity Protection | Rootless vs Rootful |
| MASTG-APP-SEC-0013 | Code Integrity Verification | Jailbreak detection |
| MASTG-TECH-0013 | iOS File System | Filesystem access |
| MASTG-TECH-0014 | iOS IPC Mechanisms | Inter-process communication |

### Testing Checklist

```markdown
- [ ] Device successfully jailbroken
- [ ] SSH access established (WiFi and USB)
- [ ] Frida server installed and version matched
- [ ] Frida server running and accessible from host
- [ ] Package manager (Sileo/Zebra) functional
- [ ] Essential security tools installed
- [ ] Default password changed
- [ ] Device on same network as testing workstation
- [ ] USB tools (iproxy, usbmuxd) working
- [ ] Can list processes via frida-ps -U
```

---

## Security Considerations

### Risks of Jailbreak

```bash
# Security implications:
1. Exploitation of bootrom/kernel vulnerabilities
2. Reduced sandboxing and code signing enforcement
3. Increased attack surface
4. Potential malware infection from untrusted repos

# Best Practices:
- Use dedicated testing device
- Never jailbreak personal device
- Only install trusted packages
- Change default password
- Disable unnecessary services
- Keep jailbreak tools updated
- Do not use jailbroken device for personal data
```

### Legal Considerations

```
- Jailbreaking is legal for security research (DMCA exemption)
- Check local laws and regulations
- Obtain proper authorization before testing
- Do not distribute jailbroken applications
- Respect intellectual property rights
- Follow responsible disclosure practices
```

### Device Management

```bash
# Create separate testing environment
- Use dedicated iOS device for testing
- Keep personal data separate
- Regularly backup before jailbreak
- Document jailbreak method and versions
- Track installed tweaks and versions
```

---

## Summary

This guide covered:
- Four major jailbreak methods (checkra1n, unc0ver, palera1n, Dopamine)
- Device and iOS version compatibility
- Post-jailbreak setup and essential tools
- Frida server installation and configuration
- SSH setup (WiFi and USB)
- USB communication tools
- Package manager sources
- Non-jailbreak alternatives
- Troubleshooting common issues
- OWASP MASTG references
- Security and legal considerations

For comprehensive security testing, a jailbroken device with Frida server provides the most powerful and flexible dynamic analysis environment. Always choose the jailbreak method that best matches your device and iOS version requirements.

---

## References

### Official Sources
- checkra1n: https://checkra.in
- unc0ver: https://unc0ver.dev
- palera1n: https://palera.in
- Dopamine: https://github.com/opa334/Dopamine
- Frida: https://frida.re
- Sileo: https://sileo.app
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Community Resources
- r/jailbreakdevelopers: Reddit community
- jailbreakQA: Q&A platform
- iOSGods: App testing community
- Bug bounty programs: HackerOne, Bugcrowd

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, security researchers
**Prerequisites:** Basic iOS knowledge, command line proficiency, macOS or Linux host machine

## Working in the iOS Simulator (no jailbreak)

This guide focuses on **physical jailbroken devices**. For modern pentests on Apple Silicon Macs you can usually skip the jailbreak entirely and run the app in the iOS Simulator (converted with SimForge) with Frida 17. The simulator workflow has different hooks, syntax, and lifecycle requirements.

For a working recipe — including the Frida 17 arm64e-simulator gotcha, the `.implementation` hook pattern that actually works, the canonical bypass script (`assets/frida-scripts/jailbreak-bypass-ios.js`), and the troubleshooting matrix — see:

> **`references/frida-ios-simulator-workflow.md`**

That document is the single source of truth for simulator-based Frida work. The recommendations there override older examples in this guide when the two conflict (e.g., `--no-pause` was removed in Frida 17, `-N <bundle>` is unreliable on sim, etc.).

