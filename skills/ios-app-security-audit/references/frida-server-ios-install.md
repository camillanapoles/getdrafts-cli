# Frida Server Installation Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture Selection](#architecture-selection)
4. [Version Matching Strategy](#version-matching-strategy)
5. [Installation Methods](#installation-methods)
6. [Frida Server Configuration](#frida-server-configuration)
7. [Verification and Testing](#verification-and-testing)
8. [Advanced Configuration](#advanced-configuration)
9. [Troubleshooting](#troubleshooting)
10. [Updating Frida](#updating-frida)
11. [OWASP MASTG References](#owasp-mastg-references)
12. [Best Practices](#best-practices)

---

## Overview

Frida is a dynamic instrumentation toolkit that enables security researchers to inject JavaScript into running processes on iOS devices. This guide provides detailed instructions for installing Frida server on jailbroken iOS devices, with emphasis on version matching, architecture selection, and troubleshooting common issues.

### What is Frida Server?

Frida server is a daemon that runs on the iOS device and accepts connections from the Frida client on the host machine. It provides:
- Process enumeration
- Module injection
- Runtime manipulation
- Memory inspection and modification
- Network and filesystem access

---

## Prerequisites

### System Requirements

```text
# Host Machine (macOS/Linux)
- Python 3.7+
- pip package manager
- Network connectivity (WiFi or USB)

# iOS Device
- Jailbroken iOS device (iOS 12.0+ recommended)
- Sileo/Cydia package manager
- SSH access (openssh package)
- Sufficient storage (100MB+)

# Hardware
- USB cable for USB connections
- WiFi network for WiFi connections
# Optional: libusbmuxd for USB connections
```

### Software Installation on Host

```bash
# Step 1: Install Python pip (if not already installed)
# On macOS:
brew install python3

# On Ubuntu/Debian:
sudo apt-get install python3-pip

# Step 2: Install Frida client
pip3 install frida

# Step 3: Verify installation
frida --version
# Expected output: 16.x.x (version number)

# Step 4: Install Frida tools (optional but recommended)
pip3 install frida-tools

# Verify tools
frida-ps --help
frida --help
```

### Software Installation on Device

```bash
# SSH into device (WiFi or USB)
ssh root@DEVICE_IP
# or
ssh -p 2222 root@localhost  # Via USB with iproxy

# Step 1: Install OpenSSH (if not installed)
apt install openssh

# Step 2: Install basic utilities
apt install curl
apt install wget
apt install unzip
apt install lsb-core  # For architecture detection

# Step 3: Verify architecture
uname -m
# Expected outputs:
# arm64    - Standard 64-bit (A8-A11, some A12+)
# arm64e   - With Pointer Authentication (A12+ on iOS 12+)
# x86_64   - iOS Simulator (not applicable for real devices)

# Exit SSH for now
exit
```

---

## Architecture Selection

### Understanding ARM64 vs ARM64E

| Architecture | Description | Devices | iOS Version |
|--------------|-------------|---------|-------------|
| arm64 | Standard 64-bit ARM | iPhone 5s - 8/X (A8-A11) | iOS 7+ |
| arm64e | ARM64 with Pointer Authentication Codes (PAC) | iPhone XS and later (A12+) | iOS 12+ |
| arm64e (rootless) | Same as above but with rootless jailbreak | iPhone XS and later | iOS 15+ |

### How to Determine Correct Architecture

```bash
# Method 1: On device via SSH
ssh root@DEVICE_IP
uname -m

# Method 2: From host via Frida (if device already connected)
# This will fail if Frida server not installed, but shows intent
frida-ps -U 2>&1 | grep -i error

# Method 3: Device model lookup
ideviceinfo | grep ProductType
# Lookup ProductType in Apple device model database

# Example device models:
# iPhone9,3  -> iPhone 7      -> A10 -> arm64
# iPhone10,3 -> iPhone 8      -> A11 -> arm64
# iPhone11,2 -> iPhone XS     -> A12 -> arm64e
# iPhone12,1 -> iPhone 11     -> A13 -> arm64e
# iPhone13,3 -> iPhone 12 Pro -> A14 -> arm64e
# iPhone14,2 -> iPhone 13 Pro -> A15 -> arm64e
# iPhone14,5 -> iPhone 13     -> A15 -> arm64e
# iPhone15,3 -> iPhone 14 Pro -> A16 -> arm64e
```

### Architecture Decision Flow

```
Start
  ↓
Get device model number (ideviceinfo)
  ↓
Lookup in Apple device database
  ↓
Is device A12 or newer?
  ↓ Yes
Check iOS version
  ↓
iOS 12+?
  ↓ Yes → arm64e
  ↓ No → arm64
  ↓ No
Use arm64
```

---

## Version Matching Strategy

### Why Version Matching is Critical

Frida uses a client-server architecture where the client and server must use the same protocol version. Mismatched versions will fail with errors like:

```
Failed to enumerate processes: unable to communicate with remote frida-server
Protocol mismatch
```

### Version Matching Procedure

```bash
# Step 1: Check Frida client version on host
frida --version
# Example output: 17.11.0  (pinned version: references/tool-versions.md)

# Step 2: Download matching Frida server
# Base URL: https://github.com/frida/frida/releases/download/VERSION/

# Format: frida-ios-VERSION-ARCHITECTURE.xz

# Example for iOS 16+ (arm64e):
FRIDA_VERSION=$(frida --version)   # matches host; pinned in references/tool-versions.md
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-arm64e.xz

# Example for iOS 12-15 (arm64):
FRIDA_VERSION=$(frida --version)   # matches host; pinned in references/tool-versions.md
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-arm64.xz
```

### Automated Version Matching Script

```bash
#!/bin/bash
# frida-download.sh - Automatically download matching Frida server

# Get Frida version
FRIDA_VERSION=$(frida --version)

echo "Frida client version: $FRIDA_VERSION"

# Detect architecture (default to arm64e for modern devices)
read -p "Enter device architecture (arm64/arm64e): " ARCH
ARCH=${ARCH:-arm64e}

# Download Frida server
DOWNLOAD_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-${ARCH}.xz"
echo "Downloading from: $DOWNLOAD_URL"

wget "$DOWNLOAD_URL"

# Extract
xz -d "frida-ios-${FRIDA_VERSION}-${ARCH}.xz"

# Rename to frida-server
mv "frida-ios-${FRIDA_VERSION}-${ARCH}" frida-server

# Make executable
chmod +x frida-server

echo "Frida server downloaded: frida-server"
echo "Ready to upload to device"
```

### Version Compatibility Matrix

| Frida Version | iOS Support | Notes |
|---------------|-------------|-------|
| 17.11.0 | 12.0 - 26.x | Current stable release (pinned in `references/tool-versions.md`) |
| 15.2.2 | 12.0 - 16.x | Previous stable |
| 14.2.18 | 11.0 - 15.x | Legacy support |
| 12.8.0 | 9.0 - 14.x | Legacy support |

---

## Installation Methods

### Method 1: WiFi SSH Installation

```bash
# Step 1: Connect device to WiFi
# Get device IP address from Settings > WiFi

# Step 2: SSH to device
ssh root@192.168.1.100
# Default password: alpine

# Step 3: Create Frida directory
mkdir -p /var/jb/usr/bin
# For rootless jailbreaks (iOS 15+):
# Directory already exists: /var/jb/usr/bin

# Step 4: Exit SSH to prepare file transfer
exit

# Step 5: Transfer Frida server from host
scp frida-server root@192.168.1.100:/var/jb/usr/bin/frida-server

# Step 6: Set permissions and ownership
ssh root@192.168.1.100
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server
ls -l /var/jb/usr/bin/frida-server
# Should show: -rwxr-xr-x  1 root  wheel

# Step 7: Test execution
/var/jb/usr/bin/frida-server --help
# Should show help output or version info

# Exit SSH
exit
```

### Method 2: USB SSH Installation (Recommended)

```bash
# Step 1: Ensure USB tools are installed on host
brew install libusbmuxd usbmuxd libimobiledevice

# Step 2: Connect device via USB cable

# Step 3: Start iproxy to forward SSH port
iproxy 2222 22


# Step 4: SSH to device via USB
ssh -p 2222 root@localhost
# Password: alpine

# Step 5: Create Frida directory
mkdir -p /var/jb/usr/bin

# Step 6: Exit SSH
exit

# Step 7: Transfer Frida server via USB
scp -P 2222 frida-server root@localhost:/var/jb/usr/bin/frida-server

# Step 8: Set permissions
ssh -p 2222 root@localhost
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server

# Step 9: Verify
ls -l /var/jb/usr/bin/frida-server
/var/jb/usr/bin/frida-server --help

# Exit SSH
exit
```

> **Prerequisite**: `iproxy` only forwards TCP ports — the device must have an SSH daemon (OpenSSH) running. On a non-jailbroken device, there is no SSH server, so `iproxy` has nothing to connect to and the tunnel appears to hang. This is normal, not a bug. To verify the device is jailbroken, check for `/var/jb/` or `/Applications/Cydia.app` via the Files app or `ideviceinfo`.

### Method 3: Direct Package Installation

```bash
# On device via Sileo:

# Option 1: BigBoss repo (may have older versions)
1. Open Sileo
2. Search for "frida-server"
3. Install the package
4. Verify version in package details

# Option 2: Frida official repo (recommended)
# Add Frida repo to Sileo:
1. Sources > Edit > Add
2. Enter: https://build.frida.re/
3. Tap "Add Source"
4. Search for "frida-server"
5. Install latest version

# Verify installation
ssh root@DEVICE_IP
which frida-server
frida-server --version
```

### Method 4: Manual Binary Placement (Advanced)

```bash
# For advanced users who need custom compilation

# Step 1: Download Frida source
git clone --recurse-submodules https://github.com/frida/frida.git
cd frida

# Step 2: Build for iOS (requires iOS SDK)
# This requires macOS with Xcode
make core-ios-device

# Step 3: Locate compiled binary
ls build/frida-ios-device-*-bin/frida-server

# Step 4: Transfer to device (as shown in Method 1 or 2)
```

### Installation Verification

```bash
# On host, verify Frida can connect to device
frida-ps -U
# Should list processes on device

# If successful, output similar to:
# PID  Name
# ---  ----
# 123  SpringBoard
# 456  backboardd
# 789  mediaserverd
# 1011  locationd
# ...
```

---

## Frida Server Configuration

### Basic Configuration

```bash
# On device (via SSH):

# Check Frida server location
which frida-server
# Expected: /var/jb/usr/bin/frida-server

# Make sure binary is executable
chmod +x /var/jb/usr/bin/frida-server

# Check ownership
ls -l /var/jb/usr/bin/frida-server
# Should be: root:wheel

# Create symlink for convenience (optional)
ln -s /var/jb/usr/bin/frida-server /usr/local/bin/frida-server
```

### Running Frida Server

```bash
# On device (via SSH):

# Method 1: Interactive mode (for testing)
/var/jb/usr/bin/frida-server

# You should see output like:
# Frida Server 17.11.0 ("<build-hash>")
# Listening on 127.0.0.1:27042
# Listening on [::]:27042

# Method 2: Background mode (recommended)
/var/jb/usr/bin/frida-server &

# Verify it's running
ps aux | grep frida-server

# Method 3: With debug output
/var/jb/usr/bin/frida-server -D

# Method 4: Redirect to log file
/var/jb/usr/bin/frida-server > /var/tmp/frida-server.log 2>&1 &

# Check logs
tail -f /var/tmp/frida-server.log
```

### Auto-Start Configuration

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
    <key>ProgramArguments</key>
    <array>
        <string>/var/jb/usr/bin/frida-server</string>
        <string>-D</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/tmp/frida-server.out</string>
    <key>StandardErrorPath</key>
    <string>/var/tmp/frida-server.err</string>
</dict>
</plist>
EOF

# Set ownership
chown root:wheel /var/jb/Library/LaunchDaemons/re.frida.server.plist
chmod 644 /var/jb/Library/LaunchDaemons/re.frida.server.plist

# Load the service
launchctl load -w /var/jb/Library/LaunchDaemons/re.frida.server.plist

# Verify it's running
launchctl list | grep frida

# Check logs
tail -f /var/tmp/frida-server.out
tail -f /var/tmp/frida-server.err
```

### Network Configuration

```bash
# By default, Frida server listens on 127.0.0.1:27042 (localhost only)

# To enable remote access (NOT recommended for security):
# Modify the plist to listen on all interfaces

cat > /var/jb/Library/LaunchDaemons/re.frida.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>re.frida.server</string>
    <key>Program</key>
    <string>/var/jb/usr/bin/frida-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/var/jb/usr/bin/frida-server</string>
        <string>-D</string>
        <string>-l</string>
        <string>0.0.0.0</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# WARNING: This exposes Frida server to network access
# Only use on isolated testing networks
```

---

## Verification and Testing

### Basic Connectivity Test

```bash
# On host:

# Test 1: List processes
frida-ps -U

# Expected output:
# PID  Name
# ---  ----
# 1    launchd
# 50   launchd (SpringBoard)
# ...

# Test 2: Get device info
frida-discover -U

# Test 3: Test Frida REPL
frida -U -f com.apple.springboard

# You should enter Frida REPL with prompt:
# [iPhone::SpringBoard]->

# Try a simple command:
# [iPhone::SpringBoard]-> ObjC.available
# Should return: true

# Exit REPL:
# [iPhone::SpringBoard]-> %exit
```

### Application Testing

```bash
# Test 1: Attach to running app
frida -U "Safari"

# Test 2: Spawn app
frida -U -f com.apple.mobilesafari

# Test 3: Load script
frida -U -l script.js -f com.apple.mobilesafari

# Create simple test script:
cat > test.js << 'EOF'
console.log("Frida is working!");
console.log("Device:", ObjC.available);
console.log("Classes:", Object.keys(ObjC.classes).length);

// List some UIKit classes
var uikitClasses = Object.keys(ObjC.classes).filter(function(name) {
    return name.startsWith('UI');
});
console.log("UIKit classes:", uikitClasses.slice(0, 10).join(", "));
EOF

# Run script
frida -U -l test.js -f com.apple.mobilesafari
```

### Memory and Performance Check

```bash
# On device, check Frida server resource usage
ssh root@DEVICE_IP
ps aux | grep frida-server
# Look for CPU and memory usage

# Check for memory leaks over time
watch -n 10 "ps aux | grep frida-server"

# Check file descriptors
lsof -p $(pgrep frida-server)

# Check network connections
netstat -an | grep 27042
```

---

## Advanced Configuration

### Custom Installation Paths

```bash
# If you need to install to a custom path

# Step 1: Create custom directory
mkdir -p /var/jb/opt/frida/bin

# Step 2: Copy binary
cp frida-server /var/jb/opt/frida/bin/frida-server
chmod +x /var/jb/opt/frida/bin/frida-server
chown root:wheel /var/jb/opt/frida/bin/frida-server

# Step 3: Update PATH
echo 'export PATH="/var/jb/opt/frida/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Step 4: Update launchd plist
# Modify Program path to custom location
```

### Multiple Frida Instances

```bash
# Running multiple Frida servers on different ports

# Copy binary
cp /var/jb/usr/bin/frida-server /var/jb/usr/bin/frida-server-2

# Create second plist
cat > /var/jb/Library/LaunchDaemons/re.frida.server2.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>re.frida.server2</string>
    <key>Program</key>
    <string>/var/jb/usr/bin/frida-server-2</string>
    <key>ProgramArguments</key>
    <array>
        <string>/var/jb/usr/bin/frida-server-2</string>
        <string>-l</string>
        <string>127.0.0.1</string>
        <string>-p</string>
        <string>27043</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load second instance
launchctl load -w /var/jb/Library/LaunchDaemons/re.frida.server2.plist
```

### Integration with Other Tools

```bash
# Objection integration
# Objection uses Frida under the hood

# Install objection on host
pip3 install objection

# Test with Frida server running
objection -g com.apple.mobilesafari explore

# Frida with Burp Suite (for SSL pinning bypass)
# See SSL Pinning Bypass guide for details

# Frida with MobSF (Mobile Security Framework)
# MobSF supports dynamic analysis via Frida
```

---

## Troubleshooting

### Common Errors and Solutions

#### Error: "Failed to enumerate processes"

```bash
# Error message:
# Failed to enumerate processes: unable to communicate with remote frida-server

# Solution 1: Check Frida server is running
ssh root@DEVICE_IP
ps aux | grep frida-server

# Solution 2: Restart Frida server
pkill frida-server
/var/jb/usr/bin/frida-server &

# Solution 3: Check version mismatch
frida --version  # On host
/var/jb/usr/bin/frida-server --version  # On device

# Versions MUST match exactly

# Solution 4: Check port 27042
netstat -an | grep 27042

# Solution 5: Try different connection method
# If WiFi fails, try USB with iproxy
```

#### Error: "Permission denied"

```bash
# Error message:
# /var/jb/usr/bin/frida-server: Permission denied

# Solution: Set correct permissions
ssh root@DEVICE_IP
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server

# Verify
ls -l /var/jb/usr/bin/frida-server
# Should be: -rwxr-xr-x  1 root  wheel
```

#### Error: "Protocol mismatch"

```bash
# Error message:
# Protocol mismatch

# Solution: This is a version mismatch
# See "Version Matching Strategy" section

# Quick fix:
# 1. Get host version: frida --version
# 2. Download matching server version
# 3. Replace server binary on device
# 4. Restart Frida server
```

#### Error: "Device not connected"

```bash
# Error message:
# Failed to enumerate processes: device not connected

# Solution 1: Check device connection
idevice_id -l

# Solution 2: Restart usbmuxd
brew services restart usbmuxd

# Solution 3: Try different USB port/cable

# Solution 4: Use WiFi connection if USB fails
frida-ps -H DEVICE_IP  # Instead of -U flag
```

#### Error: Frida server crashes immediately

```bash
# Solution 1: Check with debug mode
/var/jb/usr/bin/frida-server -D

# Solution 2: Check system logs
tail -f /var/log/syslog

# Solution 3: Check for conflicts
ps aux | grep frida

# Solution 4: Try running manually first
/var/jb/usr/bin/frida-server

# Solution 5: Check architecture
uname -m
# Ensure you downloaded correct binary
```

### Log Analysis

```bash
# On device, view Frida server logs

# If using launchd with log files
tail -f /var/tmp/frida-server.out
tail -f /var/tmp/frida-server.err

# Check system logs for Frida-related messages
grep -i frida /var/log/syslog
grep -i "error" /var/log/syslog | grep -i frida

# Check crash logs
ls -la /var/mobile/Library/Logs/CrashReporter/
tail -f /var/mobile/Library/Logs/CrashReporter/FridaServer-*.ips
```

### Performance Issues

```bash
# If Frida is slow or consuming too much resources

# Check resource usage
top | grep frida

# Check for multiple instances
ps aux | grep frida-server

# Restart if necessary
pkill -9 frida-server
/var/jb/usr/bin/frida-server &

# Consider using -D flag for debug to identify issues
```

---

## Updating Frida

### Update Procedure

```bash
# Step 1: Check current version
frida --version  # On host
ssh root@DEVICE_IP "/var/jb/usr/bin/frida-server --version"  # On device

# Step 2: Update Frida client
pip3 install --upgrade frida

# Step 3: Download new matching server
FRIDA_VERSION=$(frida --version)
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-ios-${FRIDA_VERSION}-arm64e.xz

# Step 4: Extract and prepare
xz -d frida-ios-${FRIDA_VERSION}-arm64e.xz
mv frida-ios-${FRIDA_VERSION}-arm64e frida-server
chmod +x frida-server

# Step 5: Backup old server (optional)
ssh root@DEVICE_IP "mv /var/jb/usr/bin/frida-server /var/jb/usr/bin/frida-server.old"

# Step 6: Upload new server
scp frida-server root@DEVICE_IP:/var/jb/usr/bin/frida-server

# Step 7: Set permissions
ssh root@DEVICE_IP "chmod +x /var/jb/usr/bin/frida-server && chown root:wheel /var/jb/usr/bin/frida-server"

# Step 8: Restart Frida server
ssh root@DEVICE_IP "pkill frida-server"
ssh root@DEVICE_IP "/var/jb/usr/bin/frida-server &"

# Step 9: Verify
frida-ps -U
```

### Automated Update Script

```bash
#!/bin/bash
# frida-update.sh - Automated Frida update

# Configuration
DEVICE_IP="192.168.1.100"
DEVICE_USER="root"

# Get new version
pip3 install --upgrade frida
NEW_VERSION=$(frida --version)
echo "Updating to Frida version: $NEW_VERSION"

# Download server
wget "https://github.com/frida/frida/releases/download/${NEW_VERSION}/frida-ios-${NEW_VERSION}-arm64e.xz"

# Extract
xz -d "frida-ios-${NEW_VERSION}-arm64e.xz"
mv "frida-ios-${NEW_VERSION}-arm64e" frida-server
chmod +x frida-server

# Backup old server
ssh ${DEVICE_USER}@${DEVICE_IP} "mv /var/jb/usr/bin/frida-server /var/jb/usr/bin/frida-server.old"

# Upload new server
scp frida-server ${DEVICE_USER}@${DEVICE_IP}:/var/jb/usr/bin/frida-server

# Set permissions and restart
ssh ${DEVICE_USER}@${DEVICE_IP} << 'EOF'
chmod +x /var/jb/usr/bin/frida-server
chown root:wheel /var/jb/usr/bin/frida-server
pkill frida-server
/var/jb/usr/bin/frida-server &
EOF

# Verify
frida-ps -U
echo "Update complete!"
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Frida Relevance |
|---------------|-------|-----------------|
| MASTG-TEST-0010 | Dynamic Analysis Environment Setup | Frida server installation |
| MASTG-TEST-0011 | Runtime Manipulation | Frida instrumentation |
| MASTG-APP-SEC-0010 | Runtime Manipulation Prevention | Detecting Frida usage |
| MASTG-TECH-0016 | Runtime Instrumentation | Frida capabilities |
| MASTG-TECH-0017 | Debugging and Reverse Engineering | Frida debugging |

### Testing Checklist

```markdown
- [ ] Frida client version verified
- [ ] Correct architecture determined (arm64/arm64e)
- [ ] Frida server downloaded matching version
- [ ] Frida server transferred to device
- [ ] Correct permissions set (chmod +x)
- [ ] Ownership set to root:wheel
- [ ] Frida server running and accessible
- [ ] Basic connectivity test passed (frida-ps -U)
- [ ] Application attachment test passed
- [ ] Script execution test passed
```

---

## Best Practices

### Security Best Practices

```bash
# 1. Never run Frida server with remote access enabled
# Default localhost-only binding is secure

# 2. Change default SSH password
passwd alpine  # On device

# 3. Use SSH keys instead of passwords
ssh-copy-id root@DEVICE_IP

# 4. Run Frida server only when needed
# Stop it when not testing:
pkill frida-server

# 5. Monitor Frida server logs for suspicious activity
tail -f /var/tmp/frida-server.out

# 6. Keep Frida updated
# Regularly check for updates and apply security patches
```

### Development Best Practices

```bash
# 1. Use version control for Frida scripts
git init my-frida-scripts
git add script.js
git commit -m "Add SSL pinning bypass script"

```

```javascript
// 2. Create reusable utility functions
// Store common functions in separate files

// 3. Document your scripts
// Script: ssl-pinning-bypass-ios.js
// Purpose: Bypass SSL pinning in NSURLSession
// Tested on: iOS "<version>", Frida "<version>"

// 4. Use error handling
try {
    // Frida code
} catch (e) {
    console.log("Error:", e);
}

// 5. Clean up after testing
// Remove hooks after analysis
Interceptor.revert(targetFunc);
```

### Performance Best Practices

```javascript
// 1. Avoid heavy computations in hooks
// Bad: Expensive operation in hot path
Interceptor.attach(func, {
    onEnter: function(args) {
        // This runs every time function is called
        console.log("Expensive operation");
    }
});

// Good: Only log when necessary
var logCount = 0;
Interceptor.attach(func, {
    onEnter: function(args) {
        if (logCount++ < 100) {  // Limit logs
            console.log("Function called");
        }
    }
});

// 2. Use filter conditions
Interceptor.attach(func, {
    onEnter: function(args) {
        var arg0 = ObjC.Object(args[0]);
        if (arg0.toString().indexOf("sensitive") !== -1) {
            console.log("Sensitive data detected");
        }
    }
});

// 3. Clean up unused hooks
// Keep track of hooks and remove when done
```

---

## Summary

This guide covered:
- Prerequisites for Frida installation
- Architecture selection (arm64 vs arm64e)
- Version matching strategy
- Multiple installation methods
- Basic and advanced configuration
- Verification and testing procedures
- Troubleshooting common issues
- Updating Frida
- Best practices for security and development

Frida server is the foundation for dynamic iOS security testing. Proper installation and configuration are critical for effective security analysis.

---

## References

### Official Documentation
- Frida Documentation: https://frida.re/docs/
- Frida GitHub: https://github.com/frida/frida
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- Frida Examples: https://codeshare.frida.re/
- Frida on GitHub Discussions: https://github.com/frida/frida/discussions
- iOS Reverse Engineering: https://github.com/iosre/iOSAppReverseEngineering

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers
**Prerequisites:** Jailbroken iOS device, macOS/Linux host, command line proficiency
