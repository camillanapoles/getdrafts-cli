# Dynamic Analysis Setup Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Environment Setup](#environment-setup)
4. [Burp Suite Configuration](#burp-suite-configuration)
5. [Frida Connection](#frida-connection)
6. [Objection Workflow](#objection-workflow)
7. [Runtime Analysis](#runtime-analysis)
8. [Network Interception](#network-interception)
9. [SSL Bypass Workflow](#ssl-bypass-workflow)
10. [Evidence Collection](#evidence-collection)
11. [Combining Static and Dynamic](#combining-static-and-dynamic-analysis)
12. [OWASP MASTG References](#owasp-mastg-references)
13. [Simulator-Based Setup](#simulator-based-setup)

---

## Overview

Dynamic analysis is the process of analyzing an iOS application while it's running, providing real-time insights into behavior, data flow, and security controls. This guide provides a comprehensive setup for dynamic iOS security testing including tooling, workflows, and evidence collection.

### Why Dynamic Analysis?

- **Real-time behavior observation**: See app actions as they happen
- **Runtime manipulation**: Modify app behavior at runtime
- **Network traffic interception**: Inspect HTTP/HTTPS communication
- **Data access**: Access app storage and memory
- **Bypass protections**: Test and circumvent security controls

---

## Prerequisites

### Hardware Requirements

| Requirement | Minimum | Recommended |
|-------------|----------|-------------|
| iOS Device | iPhone 7 or later | iPhone 12 or later |
| Jailbreak | iOS 12-14 (checkra1n/unc0ver) | iOS 15-16 (Dopamine/palera1n) |
| Host Machine | macOS 10.15+ | macOS 13+ |
| RAM | 8GB | 16GB+ |
| Storage | 50GB free | 100GB+ free |

### Software Requirements

```bash
# macOS Host

# Python 3.7+
python3 --version

# Frida
pip3 install frida
pip3 install frida-tools

# Objection
pip3 install objection

# Burp Suite (Professional recommended)
# Download: https://portswigger.net/burp/communitydownload

# USB Tools
brew install libusbmuxd usbmuxd libimobiledevice

# Git (for cloning scripts)
brew install git

# SSH Client
# macOS includes ssh client

# Network Tools
brew install nmap
brew install wireshark  # Optional but recommended
```

### Jailbroken Device

```bash
# On Device (via SSH)

# Essential packages
apt install openssh
apt install frida-server
apt install cycript
apt install adv-cmds
apt install coreutils
apt install vim
apt install wget
apt install curl
apt install sqlite3

# Verification
frida-server --version
cycript -v
```

---

## Environment Setup

### Step 1: Device Jailbreak

```bash
# Choose appropriate jailbreak method based on device and iOS version
# See jailbreak-setup-guide.md for details

# Example: Using Dopamine (iOS 15-16)
1. Install Dopamine IPA via AltStore
2. Launch Dopamine
3. Tap "Jailbreak"
4. Wait for completion
5. Device will respring with jailbreak active

# Verify jailbreak
ls /var/jb  # Should exist on rootless jailbreaks
```

### Step 2: Install Frida Server

```bash
# See frida-server-ios-install.md for detailed instructions

# Quick setup:
1. On host: frida --version
2. Download matching frida-server for device
3. Upload to device: scp frida-server root@DEVICE_IP:/var/jb/usr/bin/
4. Set permissions: chmod +x /var/jb/usr/bin/frida-server
5. Start server: /var/jb/usr/bin/frida-server &

# Verify
frida-ps -U
```

### Step 3: SSH Configuration

```bash
# WiFi SSH
ssh root@DEVICE_IP
# Default password: alpine
# CHANGE IT IMMEDIATELY: passwd

# USB SSH (recommended)
iproxy 2222:22
ssh -p 2222 root@localhost

# SSH Keys (recommended)
ssh-keygen -t ed25519 -f ~/.ssh/ios-key
ssh-copy-id -p 2222 -i ~/.ssh/ios-key.pub root@localhost

# Create SSH config
cat >> ~/.ssh/config << 'EOF'

Host ios-usb
    HostName localhost
    Port 2222
    User root
    IdentityFile ~/.ssh/ios-key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF

# Now connect with: ssh ios-usb
```

### Step 4: Directory Setup

```bash
# Create working directories on host
mkdir -p ~/ios-pentesting/logs
mkdir -p ~/ios-pentesting/screenshots
mkdir -p ~/ios-pentesting/captures
mkdir -p ~/ios-pentesting/scripts

# Create session directories
SESSION_NAME="example-app-analysis-$(date +%Y%m%d)"
SESSION_DIR="~/ios-pentesting/sessions/$SESSION_NAME"
mkdir -p $SESSION_DIR
cd $SESSION_DIR

# Session structure
mkdir -p logs
mkdir -p screenshots
mkdir -p network
mkdir -p frida
mkdir -p evidence
```

---

## Burp Suite Configuration

> **Working on the iOS Simulator instead of a device?** Steps 1 and 2 below target physical devices. For the simulator the cert install is a single `xcrun simctl keychain` command and the proxy host is `127.0.0.1`. See `references/simulator-mitm-setup.md` for the canonical simulator flow (also covers Charles, mitmproxy, OWASP ZAP, and Proxyman).

### Step 1: Install Burp CA Certificate on Device

```bash
# Start Burp Suite
java -jar /Applications/Burp\ Suite.app/Contents/java/burpsuite.jar

# Configure Proxy Listener
Proxy > Options > Add
- Binding: All interfaces
- Port: 8080
- Support invisible proxying: Enabled

# Download CA Certificate
http://burp

# On Device via Safari
1. Navigate to http://"<your-computer-ip>":8080
2. Tap "CA Certificate"
3. Install profile
4. Settings > General > About > Certificate Trust Settings
5. Enable "PortSwigger CA"
```

### Step 2: Configure Device Proxy

```text
# Method 1: Via Settings UI
Settings > WiFi > Tap (i) for connected network
Configure Proxy > Manual
- Server: "<your-computer-ip>"
- Port: 8080

# Method 2: Via command line (requires mobileconfig)
# Create mobileconfig file
cat > burp-proxy.mobileconfig << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>Burp Proxy Configuration</string>
            <key>PayloadDisplayName</key>
            <string>Burp Proxy</string>
            <key>PayloadIdentifier</key>
            <string>com.burp.proxy</string>
            <key>PayloadType</key>
            <string>com.apple.proxy.managed.pac</string>
            <key>Proxies</key>
            <dict>
                <key>HTTPEnable</key>
                <true/>
                <key>HTTPPort</key>
                <integer>8080</integer>
                <key>HTTPProxy</key>
                <string>192.168.1.100</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
EOF

# Install profile via Safari
python3 -m http.server 8000
# On device: Navigate to http://"<host-ip>":8000/burp-proxy.mobileconfig
```

### Step 3: Verify Proxy Works

```bash
# Test with Safari
# On device: Navigate to https://example.com

# Check Burp Proxy > HTTP History
# Should see HTTP request and response

# Test with app
# Open app and trigger network request

# Check Burp Proxy > HTTP History
# Should see app's HTTPS requests (after SSL bypass)
```

---

## Frida Connection

### Method 1: WiFi Connection

```bash
# List processes
frida-ps -U

# Attach to running app
frida -U "Example App"

# Spawn new process
frida -U -f com.example.app

# Load script
frida -U -l script.js -f com.example.app

# Save output to file
frida -U -l script.js -f com.example.app -o frida.log &
```

### Method 2: USB Connection (Recommended)

```bash
# Start iproxy
iproxy 27042:27042  # Frida default ports

# Or use custom port
iproxy 27042:27042 1> /dev/null &

# Connect via USB
frida -H localhost -p 27042 -f com.example.app

# Use Objection with USB
objection -N localhost -P 27042 -g com.example.app explore
```

### Method 3: Dynamic Respawn

```bash
# Create respawn script
cat > respawn.sh << 'EOF'
#!/bin/bash

APP_BUNDLE_ID="com.example.app"
FRIDA_SCRIPT="script.js"

while true; do
    echo "[*] Spawning $APP_BUNDLE_ID"
    frida -U -f $APP_BUNDLE_ID -l $FRIDA_SCRIPT

    echo "[*] App terminated, respawning..."
    sleep 2
done
EOF

chmod +x respawn.sh
./respawn.sh
```

---

## Objection Workflow

### Start Objection Session

```text
# Spawn app with Objection
objection -g com.example.app explore

# Attach to running app
objection -N "Example App" explore

# Use USB connection
objection -N localhost -P 27042 -g com.example.app explore
```

### Common Objection Commands

```bash
# Jailbreak detection bypass
ios jailbreak disable

# SSL pinning bypass
ios sslpinning disable

# Keychain operations
ios keychain dump
ios keychain dump --json keychain.json
ios keychain clear

# UserDefaults
ios userdefaults get
ios userdefaults set key value

# Pasteboard
ios pasteboard monitor
ios pasteboard get

# Cookies
ios cookies get
ios cookies get --domain example.com

# Credentials
ios nsurlcredentialstorage dump

# Binary analysis
ios binaries list
ios heap dump_ios

# SQLite
sqlite connect /path/to/database.db
sqlite tables
sqlite execute "SELECT * FROM table"

# Navigation
plugin load objection FridaTrace
frida-trace

# Help
help
help ios
```

### Objection Session Script

```bash
# objection-session.sh - Automated Objection workflow
#!/bin/bash

APP_BUNDLE_ID="com.example.app"
SESSION_DIR="./sessions/$(date +%Y%m%d-%H%M%S)"

mkdir -p $SESSION_DIR
cd $SESSION_DIR

echo "[*] Starting Objection session for $APP_BUNDLE_ID"

# Start Objection
objection -g $APP_BUNDLE_ID explore << 'EOF'
# Bypass protections
ios jailbreak disable
ios sslpinning disable

# Dump keychain
ios keychain dump --json keychain.json

# Dump cookies
ios cookies get > cookies.txt

# Dump user defaults
ios userdefaults get > userdefaults.txt

# Monitor pasteboard
ios pasteboard monitor &
PASTEBOARD_PID=$!

# Start Frida trace
plugin load objection FridaTrace
frida-trace '*'

# Wait for user input
echo "[*] Session active. Press Enter to exit..."
read

# Cleanup
kill $PASTEBOARD_PID
exit
EOF

echo "[*] Session complete. Files saved to $SESSION_DIR"
```

---

## Runtime Analysis

### Class Dumping

```bash
# Method 1: Using Objection
objection -g com.example.app explore
ios heap dump_ios

# Method 2: Using Frida script
frida -U -l binary-class-dump.js -f com.example.app > classes.txt

# Method 3: Using Frida REPL
frida -U -f com.example.app
```

```javascript
// In REPL:
ObjC.classes.MyClass.$ownMethods.join('\n')
```

### Method Tracing

```bash
# Trace all methods in a class
objection -g com.example.app explore
ios heap dump_ios
ios heap list
ios heap search "ClassName"
ios heap print_instances "<class_address>"

# Trace specific method
frida-trace -U -f com.example.app -m "*!*login*"

# Trace with Frida
frida -U -l objc-method-tracer.js -f com.example.app
```

### Memory Inspection

```bash
# Inspect memory with Objection
objection -g com.example.app explore
memory list modules
memory search "password"
memory read "<address>" "<length>"

# Inspect memory with Frida
frida -U -l memory-dumper-ios.js -f com.example.app

# Dump memory regions
frida -U -l memory-dumper-ios.js -f com.example.app
```

### Hooking Specific Methods

```bash
# Create hook script
cat > hook-login.js << 'EOF'
if (ObjC.available) {
    var LoginManager = ObjC.classes.LoginManager;
    var loginMethod = LoginManager["- loginWithUsername:password:"];

    Interceptor.attach(loginMethod, {
        onEnter: function(args) {
            var username = ObjC.Object(args[2]);
            var password = ObjC.Object(args[3]);

            console.log("\n[+] Login method called:");
            console.log("  Username:", username);
            console.log("  Password:", password);
        },
        onLeave: function(retval) {
            console.log("  Return value:", retval);
        }
    });
}
EOF

# Load hook
frida -U -l hook-login.js -f com.example.app
```

---

## Network Interception

### HTTP Interception (No SSL)

```bash
# 1. Start Burp Suite
# 2. Configure device proxy
# 3. Open app
# 4. Trigger HTTP request
# 5. Check Burp Proxy > HTTP History

# Expected: HTTP request and response visible
```

### HTTPS Interception (With SSL Bypass)

```bash
# Step 1: Install Burp CA on device (see above)

# Step 2: Configure device proxy (see above)

# Step 3: Bypass SSL pinning
# Method A: Objection
objection -g com.example.app explore
ios sslpinning disable

# Method B: Frida
frida -U -l ssl-pinning-bypass-ios.js -f com.example.app

# Step 4: Open app and trigger HTTPS request

# Step 5: Check Burp Proxy > HTTP History
# Expected: HTTPS request and response visible

# Alternative: Use frida-trace for SSL
frida-trace -U -f com.example.app -i "*SSL*"
```

### Network Traffic Capture

```bash
# Method 1: Wireshark
# Start Wireshark
/Applications/Wireshark.app/Contents/MacOS/Wireshark

# Capture USB traffic
# Select rmi0 interface
# Filter: tcp.port == 8080

# Method 2: tcpdump
ssh ios-usb "tcpdump -i lo0 -w /tmp/capture.pcap port 8080"
# Or capture all traffic
ssh ios-usb "tcpdump -i anpi0 -w /tmp/capture.pcap"

# Download capture
scp ios-usb:/tmp/capture.pcap ./network/

# Method 3: Proxy logging
# Configure Burp to log to file
Proxy > Options > Misc > Logging
# Save logs to: ./network/burp.log
```

---

## SSL Bypass Workflow

### Complete SSL Bypass Process

```bash
#!/bin/bash
# ssl-bypass-complete.sh - Complete SSL pinning bypass

APP_BUNDLE_ID="com.example.app"

echo "[*] Starting SSL bypass workflow for $APP_BUNDLE_ID"

# Step 1: Verify Burp CA is installed
echo "[+] Step 1: Verifying Burp CA installation..."
# Manual verification required

# Step 2: Configure device proxy
echo "[+] Step 2: Configuring device proxy..."
# Use Settings UI or mobileconfig

# Step 3: Start Burp Suite
echo "[+] Step 3: Starting Burp Suite..."
java -jar /Applications/Burp\ Suite.app/Contents/java/burpsuite.jar > /dev/null 2>&1 &

# Wait for Burp to start
sleep 5

# Step 4: Bypass SSL pinning with Objection
echo "[+] Step 4: Bypassing SSL pinning..."
objection -g $APP_BUNDLE_ID explore << 'EOF'
ios sslpinning disable
# Keep session alive
# Press Ctrl+C when done
EOF

# Alternative: Use Frida for bypass
# frida -U -l ssl-pinning-bypass-ios.js -f $APP_BUNDLE_ID

echo "[*] SSL bypass workflow complete"
echo "[*] App traffic should now be visible in Burp Suite"
```

### Testing SSL Bypass

```bash
# Test 1: Basic HTTPS request
# 1. Start SSL bypass (above)
# 2. Open app
# 3. Trigger HTTPS request
# 4. Check Burp Proxy > HTTP History
# Expected: HTTPS request and response visible

# Test 2: API communication
# 1. Trigger API call in app
# 2. Check Burp Proxy > HTTP History
# 3. Inspect request headers and body
# 4. Inspect response headers and body

# Test 3: Third-party services
# 1. Check for requests to third-party APIs
# 2. Analyze data being sent
# 3. Check for sensitive data in transit
```

---

## Evidence Collection

### Automated Evidence Collection Script

```bash
#!/bin/bash
# collect-evidence.sh - Automated evidence collection

SESSION_DIR="./sessions/$(date +%Y%m%d-%H%M%S)"
mkdir -p $SESSION_DIR/{logs,screenshots,network,frida,evidence,storage}

APP_BUNDLE_ID="com.example.app"

echo "[*] Starting evidence collection for $APP_BUNDLE_ID"
echo "[*] Session directory: $SESSION_DIR"

# 1. Collect system logs
echo "[+] Collecting system logs..."
ssh ios-usb "dmesg" > $SESSION_DIR/logs/dmesg.log
ssh ios-usb "log show --predicate 'process == \"$APP_BUNDLE_ID\"' --last 1h" > $SESSION_DIR/logs/app.log

# 2. Collect app container
echo "[+] Collecting app container..."
APP_CONTAINER=$(ssh ios-usb "find /var/mobile/Containers/Data/Application -name '$APP_BUNDLE_ID' -print -quit")
ssh ios-usb "tar czf /tmp/app_container.tar.gz -C $APP_CONTAINER ." 2>/dev/null
scp ios-usb:/tmp/app_container.tar.gz $SESSION_DIR/storage/
ssh ios-usb "rm /tmp/app_container.tar.gz"

# 3. Dump keychain
echo "[+] Dumping keychain..."
objection -g $APP_BUNDLE_ID explore -s "ios keychain dump --json keychain.json" > /dev/null 2>&1
mv keychain.json $SESSION_DIR/evidence/

# 4. Dump cookies
echo "[+] Dumping cookies..."
objection -g $APP_BUNDLE_ID explore -s "ios cookies get" > $SESSION_DIR/evidence/cookies.txt 2>/dev/null

# 5. Dump user defaults
echo "[+] Dumping user defaults..."
objection -g $APP_BUNDLE_ID explore -s "ios userdefaults get" > $SESSION_DIR/evidence/userdefaults.txt 2>/dev/null

# 6. Collect network traffic
echo "[+] Collecting network traffic..."
# Requires manual interaction or ongoing capture
echo "[!] Start network capture manually with:"
echo "    ssh ios-usb 'tcpdump -i anpi0 -w /tmp/capture.pcap'"
echo "    scp ios-usb:/tmp/capture.pcap $SESSION_DIR/network/"

# 7. Collect screenshots
echo "[+] Collecting screenshots..."
# Requires manual screenshot capture
echo "[!] Take screenshots during session and save to: $SESSION_DIR/screenshots/"

# 8. Run Frida analysis
echo "[+] Running Frida analysis..."
frida -U -l crypto-hook-ios.js -f $APP_BUNDLE_ID -o $SESSION_DIR/frida/crypto.log &
FRIDA_PID=$!
sleep 10
kill $FRIDA_PID

# 9. Generate evidence summary
echo "[+] Generating evidence summary..."
cat > $SESSION_DIR/evidence-summary.md << EOF
# Evidence Collection Summary

**Session**: $SESSION_DIR
**App**: $APP_BUNDLE_ID
**Date**: $(date)

## Collected Evidence

### System Logs
- \`logs/dmesg.log\` - Kernel messages
- \`logs/app.log\` - App-specific logs

### App Storage
- \`storage/app_container.tar.gz\` - App container backup

### Keychain
- \`evidence/keychain.json\` - Keychain dump

### Cookies
- \`evidence/cookies.txt\` - HTTP cookies

### User Defaults
- \`evidence/userdefaults.txt\` - UserDefaults dump

### Network Traffic
- Manual collection required
- Save to: \`network/\`

### Screenshots
- Manual collection required
- Save to: \`screenshots/\`

### Frida Analysis
- \`frida/crypto.log\` - Cryptographic analysis

## Next Steps

1. Review system logs for errors
2. Analyze keychain for sensitive data
3. Examine cookies for authentication tokens
4. Inspect network traffic for vulnerabilities
5. Review screenshots for UI states
EOF

echo "[*] Evidence collection complete"
echo "[*] Summary: $SESSION_DIR/evidence-summary.md"
```

### Manual Evidence Collection Checklist

```markdown
## Evidence Collection Checklist

### Pre-Testing
- [ ] Session directory created
- [ ] App installed on device
- [ ] Device jailbroken and configured
- [ ] Burp Suite CA installed
- [ ] Device proxy configured

### During Testing
- [ ] System logs collected (dmesg, app logs)
- [ ] Frida hooks active and logging
- [ ] Network traffic captured (tcpdump/Burp)
- [ ] Screenshots taken at key moments
- [ ] Keychain dumped
- [ ] Cookies collected
- [ ] UserDefaults collected
- [ ] Class dump performed
- [ ] Method traces captured
- [ ] Memory snapshots taken

### Post-Testing
- [ ] App container backed up
- [ ] SQLite databases copied
- [ ] Shared files collected
- [ ] Evidence summary generated
- [ ] Findings documented in report
```

---

## Combining Static and Dynamic Analysis

### Integrated Analysis Workflow

```bash
#!/bin/bash
# integrated-analysis.sh - Combined static and dynamic analysis

APP_BUNDLE_ID="com.example.app"
IPA_PATH="Example.ipa"

SESSION_DIR="./sessions/$(date +%Y%m%d-%H%M%S)-integrated"
mkdir -p $SESSION_DIR/{static,dynamic,combined}

echo "[*] Starting integrated analysis for $APP_BUNDLE_ID"

# ===== STATIC ANALYSIS =====
echo "[*] Phase 1: Static Analysis"
cd $SESSION_DIR/static

# 1. Extract IPA
echo "[+] Extracting IPA..."
unzip -q $IPA_PATH -d Extracted

# 2. Analyze Info.plist
echo "[+] Analyzing Info.plist..."
plutil -p Extracted/Payload/Example.app/Info.plist > info.plist.json

# 3. Find URL schemes
echo "[+] Finding URL schemes..."
plutil -p Extracted/Payload/Example.app/Info.plist | grep -A5 "CFBundleURLSchemes" > url_schemes.txt

# 4. Find ATS configuration
echo "[+] Analyzing ATS configuration..."
plutil -p Extracted/Payload/Example.app/Info.plist | grep -A20 "NSAppTransportSecurity" > ats_config.txt

# 5. Analyze binaries
echo "[+] Analyzing binaries..."
otool -l Extracted/Payload/Example.app/Example > binary_analysis.txt
strings Extracted/Payload/Example.app/Example | grep -i "key\|secret\|password" > hardcoded_keys.txt

# 6. Class dump
echo "[+] Dumping classes..."
# Use class-dump or Frida
class-dump Extracted/Payload/Example.app/Example > class_dump.txt 2>/dev/null

# ===== DYNAMIC ANALYSIS =====
echo "[*] Phase 2: Dynamic Analysis"
cd ../dynamic

# 1. Start Frida hooks
echo "[+] Starting Frida hooks..."
# NOTE: `comprehensive-hooks.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
frida -U -l comprehensive-hooks.js -f $APP_BUNDLE_ID -o frida.log &
FRIDA_PID=$!

# 2. Start SSL bypass
echo "[+] Bypassing SSL pinning..."
objection -g $APP_BUNDLE_ID explore -s "ios sslpinning disable" > /dev/null 2>&1 &

# 3. Start network capture
echo "[+] Starting network capture..."
ssh ios-usb "tcpdump -i anpi0 -w /tmp/capture.pcap" &
CAPTURE_PID=$!

echo "[!] App is running. Perform your analysis..."
echo "[!] Press Enter to stop capture and proceed..."
read

# 4. Stop capture
echo "[+] Stopping capture..."
kill $CAPTURE_PID
scp ios-usb:/tmp/capture.pcap ./network.pcap

# 5. Collect evidence
echo "[+] Collecting evidence..."
objection -g $APP_BUNDLE_ID explore -s "ios keychain dump --json keychain.json" > /dev/null 2>&1
mv keychain.json evidence/

# ===== COMBINED ANALYSIS =====
echo "[*] Phase 3: Combined Analysis"
cd ../combined

# 1. Correlate findings
echo "[+] Correlating static and dynamic findings..."

# Compare hardcoded keys with keychain
echo "Hardcoded keys found in static analysis:"
cat ../static/hardcoded_keys.txt
echo "\nKeychain entries from dynamic analysis:"
cat ../dynamic/evidence/keychain.json

# Compare URL schemes with observed traffic
echo "\nURL schemes from Info.plist:"
cat ../static/url_schemes.txt
echo "\nObserved network traffic (manual review required):"
echo "Check network.pcap in dynamic/ directory"

# 2. Generate combined report
cat > integrated-analysis-report.md << EOF
# Integrated Analysis Report

**App**: $APP_BUNDLE_ID
**Date**: $(date)

## Static Analysis Findings

### Info.plist Analysis
- URL Schemes: $(cat ../static/url_schemes.txt | grep -c "myapp")
- ATS Configuration: $(cat ../static/ats_config.txt | grep -c "NSAllowsArbitraryLoads")

### Hardcoded Keys
- Keys found: $(grep -c "key\|secret\|password" ../static/hardcoded_keys.txt)
- Files: $(wc -l < ../static/hardcoded_keys.txt)

### Binary Analysis
- Libraries: $(grep -c "LOAD COMMAND" ../static/binary_analysis.txt)
- Entitlements: $(grep -c "entitlements" ../static/binary_analysis.txt)

## Dynamic Analysis Findings

### Keychain
- Items dumped: $(grep -c "account" ../dynamic/evidence/keychain.json)

### Network Traffic
- Capture file: ../dynamic/network.pcap
- Manual analysis required

### Runtime Behavior
- Frida hooks: $(grep -c "Hook installed" ../dynamic/frida.log)
- SSL bypass: Enabled

## Correlations

### 1. Hardcoded Keys vs Keychain
Check if hardcoded keys are also in keychain

### 2. URL Schemes vs Observed Traffic
Check if registered schemes are actually used

### 3. ATS Configuration vs Observed Protocols
Verify if HTTP is used despite ATS restrictions

## Recommendations

1. Remove hardcoded keys from binary
2. Implement proper SSL pinning
3. Restrict URL schemes
4. Review ATS configuration
5. Implement secure key storage

## Next Steps

1. Manual review of network traffic
2. Deeper analysis of crypto implementation
3. Test URL scheme vulnerabilities
4. Verify key encryption at rest
EOF

echo "[*] Integrated analysis complete"
echo "[*] Report: $SESSION_DIR/combined/integrated-analysis-report.md"
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Dynamic Analysis Context |
|---------------|-------|------------------------|
| MASTG-TEST-0010 | Dynamic Analysis Environment Setup | Environment configuration |
| MASTG-TEST-0011 | Runtime Manipulation | Frida/Objection usage |
| MASTG-TEST-0060 | Network Communication Testing | Traffic interception |
| MASTG-TEST-0040 | Data Storage Security Testing | Keychain/storage analysis |
| MASTG-TEST-0030 | Input Validation Testing | Runtime input testing |

---

## Simulator-Based Setup

The "Burp Suite Configuration", "Frida Connection" and "SSL Bypass Workflow" sections above are written for **physical devices** (real iPhone / iPad, often jailbroken). When dynamic analysis targets the **iOS Simulator** instead, the MITM and Frida setup collapses to a few commands.

> **Canonical simulator setup**: `references/simulator-mitm-setup.md` (covers cert install, proxy on `127.0.0.1`, headless env-var launch, transparent-pf fallback, and tool-specific notes for Burp / Charles / mitmproxy / ZAP / Proxyman).

Typical end-to-end stack when you have an app binary (IPA) and a Mac with Xcode:

1. **SimForge** — convert the arm64 iOS app to the simulator platform and inject Frida Gadget (no `frida-server` needed on the simulator).
   ```bash
   simforge convert /path/to/Payload/YourApp.app
   codesign -f -s - /path/to/Payload/YourApp.app
   xcrun simctl install booted /path/to/Payload/YourApp.app
   ```
   Reference: `references/simforge-ios-testing.md`.

2. **MITM cert** — install your proxy's CA into the simulator's System keychain (one command, auto-trusted).
   ```bash
   xcrun simctl keychain booted add-root-cert ~/Downloads/burp-ca.der
   ```

3. **Proxy** — point the app at the host's loopback. For headless/system-wide proxying, deploy a `.mobileconfig` with `com.apple.proxy.managed` (recommended — works for any app, including `NSURLSession` ones that ignore env vars). For interactive/manual setups, set Settings → Wi-Fi → (i) → Configure Proxy → Manual (`127.0.0.1` / your tool's port). For non-proxy-aware apps, use transparent `pf` redirection. The `SIMCTL_CHILD_HTTP_PROXY` / `SIMCTL_CHILD_HTTPS_PROXY` env vars (exported in the calling shell, then passed to `xcrun simctl launch`) only work for apps that read POSIX proxy env vars — **native `NSURLSession` apps ignore them**.
   ```bash
   # .mobileconfig install (headless, system-wide):
   xcrun simctl install booted path/to/burp-proxy.mobileconfig

   # Env-var path (only effective for apps/libraries that read HTTP_PROXY / HTTPS_PROXY):
   SIMCTL_CHILD_HTTP_PROXY=http://127.0.0.1:8080 \
   SIMCTL_CHILD_HTTPS_PROXY=http://127.0.0.1:8080 \
     xcrun simctl launch --console-pty booted com.example.app
   ```
   See `references/simulator-mitm-setup.md` §3b/3c for the full headless-proxy and `pf` options.

4. **Frida** — connect to the Frida Gadget injected by SimForge (use `-n Gadget` to target the auto-registered process name):
   ```bash
   frida -H 127.0.0.1:27042 -n Gadget -l assets/frida-scripts/ssl-pinning-bypass-ios.js
   ```

5. **Capture** — HTTPS requests now appear in Burp / Charles / mitmproxy. If the response body is empty, the app is pinning; the Frida script from step 4 covers the common cases. For Flutter / Cordova / Xamarin / TrustKit, use the framework-specific scripts in `assets/frida-scripts/`.

---

## Summary

This guide covered:
- Comprehensive dynamic analysis prerequisites
- Environment setup for iOS security testing
- Burp Suite configuration for HTTPS interception
- Frida connection methods (WiFi and USB)
- Objection workflow for common tasks
- Runtime analysis techniques (class dumping, method tracing)
- Network traffic interception and SSL bypass
- Evidence collection automation
- Combined static and dynamic analysis

Dynamic analysis provides powerful capabilities for real-time security testing. Proper setup and systematic workflows ensure comprehensive coverage and reproducible results.

---

## References

### Official Documentation
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/
- Frida Documentation: https://frida.re/docs/
- Objection GitHub: https://github.com/sensepost/objection
- Burp Suite Documentation: https://portswigger.net/burp/documentation

### Additional Resources
- iOS Security Guide: https://support.apple.com/guide/security/
- Mobile Security Framework (MobSF): https://github.com/MobSF/Mobile-Security-Framework-MobSF
- iOS Reverse Engineering: https://github.com/iosre/iOSAppReverseEngineering

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, security researchers
**Prerequisites:** Jailbroken iOS device, macOS host, basic networking and security knowledge
