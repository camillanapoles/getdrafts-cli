# Entitlements Security Guide

**Complete guide to analyzing iOS app entitlements for security vulnerabilities.**

## Table of Contents

1. [Overview](#1-overview)
2. [Extracting Entitlements](#2-extracting-entitlements)
3. [Critical Entitlements Analysis](#3-critical-entitlements-analysis)
4. [Provisioning Profile Analysis](#4-provisioning-profile-analysis)
5. [Code Signing Verification](#5-code-signing-verification)
6. [Entitlement Vulnerabilities](#6-entitlement-vulnerabilities)

---

## 1. Overview

### What are Entitlements?

Entitlements are capabilities granted to iOS apps by Apple, allowing access to specific system features and services beyond standard app sandbox permissions.

### Why Audit Entitlements?

- **Excessive privileges**: Apps may request more permissions than necessary, increasing attack surface
- **Data leakage**: Entitlements like `com.apple.security.application-groups` can enable unauthorized data sharing
- **Authentication bypass**: `get-task-allow` entitlement allows debugging and instrumentation
- **API access**: Network-related entitlements can expose network traffic or bypass security controls

### Entitlement Categories

| Category | Entitlements | Risk Level |
|-----------|--------------|------------|
| Keychain | `keychain-access-groups` | Medium |
| App Groups | `application-groups` | High |
| Associated Domains | `associated-domains` | Medium |
| Network | `network-extension`, `NFC` | High |
| Authentication | `get-task-allow` | Critical |
| Background | `BG-processing-scheduler` | Medium |
| Data Protection | `default-data-protection` | Low |
| Platform | `platform-application` | Critical |

---

## 2. Extracting Entitlements

### From IPA

```bash
# Unzip IPA
unzip -q target.ipa "Payload/*.app/"

# Extract entitlements
codesign -d --entitlements - Payload/*.app/ > entitlements.plist

# Format for readability
plutil -convert xml1 entitlements.plist
plutil -p entitlements.plist
```

### From Device

```bash
# Get app path
ssh root@"<device-ip>" "find /var/mobile/Containers/Bundle/Application -name '*.app' | head -1"

# Copy to local
scp root@"<device-ip>":/var/mobile/Containers/Bundle/Application/*/target.app ./target.app

# Extract entitlements
codesign -d --entitlements - ./target.app
```

### From App Store IPA

```bash
# Using ipatool
ipatool download -b com.example.app

# Extract entitlements
unzip target.ipa -d temp/
codesign -d --entitlements - temp/Payload/*.app/

# Or use Objection
objection -g com.example.app explore
ios entitlements dump
```

### Quick Extraction Script

```bash
#!/bin/bash

IPA="${1:-target.ipa}"

if [ ! -f "$IPA" ]; then
    echo "Error: IPA not found"
    exit 1
fi

echo "Extracting entitlements from $IPA..."

# Unzip
unzip -q "$IPA" "Payload/*.app/" -d temp/

# Find app
APP=$(find temp/Payload -name "*.app" -type d | head -1)

if [ -z "$APP" ]; then
    echo "Error: No app found in IPA"
    exit 1
fi

# Extract entitlements
echo ""
echo "Entitlements:"
codesign -d --entitlements - "$APP" | tee entitlements.txt

# Format
plutil -convert xml1 entitlements.txt 2>/dev/null || true

# Clean up
rm -rf temp/
```

---

## 3. Critical Entitlements Analysis

### Entitlement 1: keychain-access-groups

**Risk Level**: Medium

**Description**: Specifies which keychain access groups the app can access. Allows sharing keychain data between apps.

**Security Risk**: 
- Unauthorized data sharing between apps if groups are overly broad
- Sensitive credentials (passwords, tokens) exposed to other apps in same group
- Potential for credential theft if malicious app shares keychain group

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep keychain-access-groups
```

**Example**:
```xml
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.example.app</string>
    <string>$(AppIdentifierPrefix)com.company.shared-data</string>
</array>
```

**Security Check**:
1. Are all keychain groups necessary for app functionality?
2. Are groups shared with other apps? If so, are those apps trusted?
3. Is sensitive data stored in shared keychain groups?

**Remediation**:
- Use app-specific keychain group when possible
- Avoid sharing keychain groups with untrusted apps
- Implement additional access controls (password, biometrics) for sensitive keychain data
- Document all keychain group usage

**Testing**:
```bash
# On jailbroken device, check keychain data
ssh root@"<device-ip>" "security dump-keychain | grep -A 20 'com.example.app'"

# Use Objection to dump keychain
objection -g com.example.app explore
ios keychain dump
```

**OWASP MASTG Reference**: MASTG-TEST-0035 (Local Data Storage)

---

### Entitlement 2: associated-domains

**Risk Level**: Medium

**Description**: Specifies web domains that the app is associated with for Handoff, universal links, and password autofill.

**Security Risk**:
- Universal link hijacking if AASA file is misconfigured
- Credential theft via password autofill
- Phishing opportunities if domains are not properly validated

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep associated-domains
```

**Example**:
```xml
<key>associated-domains</key>
<array>
    <string>applinks:example.com</string>
    <string>webcredentials:example.com</string>
</array>
```

**Security Check**:
1. Are all associated domains legitimate and owned by app developer?
2. Is the AASA (Apple App Site Association) file properly configured at `https://example.com/.well-known/apple-app-site-association`?
3. Are there domains that could be used for phishing?
4. Are password autofill domains properly scoped?

**Remediation**:
- Only include domains you own and control
- Ensure AASA file is properly configured with valid app IDs
- Validate universal link handlers for security
- Limit `webcredentials` to domains where password autofill is actually needed

**Testing**:
```bash
# Fetch AASA file
curl https://example.com/.well-known/apple-app-site-association | plutil -p -

# Test universal link
xcrun simctl openurl booted "https://example.com/path"

# Test password autofill (iOS 12+)
# 1. Save credentials in app
# 2. Trigger password autofill in Safari
# 3. Verify autofill works correctly
```

**OWASP MASTG Reference**: MASTG-TEST-0140 (Improper Platform Usage)

---

### Entitlement 3: aps-environment

**Risk Level**: Medium

**Description**: Specifies the Apple Push Notification service environment (development or production).

**Security Risk**:
- Using development environment in production allows unauthenticated push notifications
- Sensitive data leaked via push notifications if not properly secured

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep aps-environment
```

**Example**:
```xml
<key>aps-environment</key>
<string>development</string>  <!-- Should be "production" for release builds -->
```

**Security Check**:
1. Is `development` used in production builds?
2. Are push notifications encrypted when containing sensitive data?
3. Is device token validation implemented on server?
4. Are push notifications rate-limited to prevent abuse?

**Remediation**:
- Use `production` environment for App Store/TestFlight builds
- Encrypt sensitive data in push notifications (use payload encryption)
- Implement server-side device token validation
- Rate-limit push notifications per device

**Testing**:
```bash
# Test push notification security
# 1. Intercept push notifications (on jailbroken device with tcpdump)
tcpdump -i any -w push.pcap 'port 2195'

# 2. Attempt to send push to development endpoint (should fail in production)
curl --cert development.pem --key development-key.pem \
  -X POST https://api.development.push.apple.com/3/device/"<device-token>" \
  -H "apns-topic: com.example.app" \
  -d '{"aps":{"alert":"test"}}'
```

**OWASP MASTG Reference**: MASTG-TEST-0218 (Push Notifications)

---

### Entitlement 4: application-groups

**Risk Level**: High

**Description**: Allows app to access shared containers with other apps in the same group. Used for app extensions, widgets, and data sharing.

**Security Risk**:
- Data leakage between apps in same group
- Unauthorized access if group is misconfigured
- Malicious app in same group can access sensitive data

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep application-groups
```

**Example**:
```xml
<key>application-groups</key>
<array>
    <string>group.com.company.shared</string>
    <string>group.com.company.widgets</string>
</array>
```

**Security Check**:
1. Are all application groups necessary?
2. Are apps in the same group from the same developer?
3. Is sensitive data stored in shared containers?
4. Are shared containers properly protected with additional access controls?

**Remediation**:
- Minimize use of application groups
- Only share with trusted apps from same developer
- Avoid storing sensitive data in shared containers
- Implement additional encryption for shared data
- Document all shared container usage

**Testing**:
```bash
# On device, check shared containers
ssh root@"<device-ip>" "ls -la /var/mobile/Containers/Shared/AppGroup/"

# Access shared container
ssh root@"<device-ip>" "cat /var/mobile/Containers/Shared/AppGroup/group.com.company.shared/Database.db"

# Use Frida to monitor file access
frida -U -f com.example.app -l file-protection-enumerator.js
```

**OWASP MASTG Reference**: MASTG-TEST-0035 (Local Data Storage)

---

### Entitlement 5: network-extension

**Risk Level**: High

**Description**: Allows app to create network extensions (VPN, DNS proxy, content filter). This is a very powerful entitlement.

**Security Risk**:
- Complete network traffic interception and manipulation
- MITM attacks on all device traffic
- VPN credential theft
- DNS spoofing

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep network-extension
```

**Example**:
```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>packet-tunnel-provider</string>
    <string>app-proxy-provider</string>
</array>
```

**Security Check**:
1. Is network extension absolutely necessary for app functionality?
2. Are VPN credentials properly protected in Keychain?
3. Is DNS filtering properly validated?
4. Is there user consent for VPN installation?

**Remediation**:
- Only use network extension for legitimate VPN/filtering apps
- Implement strong VPN credential protection (Keychain + biometrics)
- Provide clear user consent UI for VPN installation
- Regular security audits of VPN implementation
- Certificate pinning for VPN server authentication

**Testing**:
```bash
# Monitor network extension activity
# 1. Install app with network extension
# 2. Enable VPN extension
# 3. Monitor all device traffic
tcpdump -i any -w vpn-traffic.pcap

# Check VPN status
ssh root@"<device-ip>" "scutil --nc status"

# Check DNS settings
ssh root@"<device-ip>" "scutil --dns"
```

**OWASP MASTG Reference**: MASTG-TEST-0215 (Network Communication)

---

### Entitlement 6: get-task-allow

**Risk Level**: Critical

**Description**: Allows debugger attachment and dynamic instrumentation (Frida, LLDB). **This should NEVER be present in production builds.**

**Security Risk**:
- Complete runtime manipulation possible
- Sensitive data extraction via instrumentation
- Bypass of security checks (root/jailbreak detection, SSL pinning)
- Code injection and modification

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep get-task-allow
```

**Example**:
```xml
<!-- VULNERABLE: get-task-allow present in production build -->
<key>get-task-allow</key>
<true/>

<!-- SECURE: Absent in production build -->
<!-- No get-task-allow key -->
```

**Security Check**:
1. Is `get-task-allow` present in production/TestFlight builds? (CRITICAL)
2. Is build configuration set to Release for production?

**Remediation**:
- **CRITICAL**: Remove `get-task-allow` from all production builds
- Use Archive → Export → App Store distribution (automatically removes)
- Verify entitlements after every production build
- Implement CI/CD checks to reject builds with `get-task-allow`

**Testing**:
```bash
# Attempt to attach debugger
# 1. Launch app
frida-ps -U | grep com.example.app

# 2. Try to attach (should fail in production)
frida -U com.example.app

# 3. If successful: VULNERABLE (get-task-allow present)
# 4. If fails: SECURE (no get-task-allow)

# Verify with LLDB
lldb -n "TargetApp"
# Should fail to attach if get-task-allow is absent
```

**OWASP MASTG Reference**: MASTG-TEST-0083 (Anti-Debugging)

---

### Entitlement 7: default-data-protection

**Risk Level**: Low

**Description**: Specifies default data protection class for app's container file encryption.

**Security Risk**:
- Weak data protection can lead to data exposure on device theft
- Inconsistent protection may lead to sensitive data in plaintext

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep data-protection
```

**Example**:
```xml
<!-- WEAK: No protection -->
<!-- No default-data-protection key -->

<!-- BETTER: Complete protection -->
<key>default-data-protection</key>
<string>NSFileProtectionComplete</string>

<!-- BEST: Complete unless open -->
<key>default-data-protection</key>
<string>NSFileProtectionCompleteUnlessOpen</string>
```

**Security Check**:
1. Is `default-data-protection` set?
2. If set, is it at least `NSFileProtectionComplete`?
3. Are sensitive files explicitly protected with `NSFileProtectionComplete`?
4. Is there consistency between entitlement and actual file protection?

**Remediation**:
- Set `default-data-protection` to `NSFileProtectionCompleteUnlessOpen` or higher
- Explicitly protect sensitive files with appropriate protection class
- Test file encryption by examining app container on jailbroken device
- Document which files need which protection level

**Testing**:
```bash
# On jailbroken device, check file protection
ssh root@"<device-ip>" "ls -la@ /var/mobile/Containers/Data/Application/*/Documents/"

# Look for data protection flags:
# - 0000 (None)
# - 0100 (Complete until first user authentication)
# - 0200 (Complete unless open)
# - 0300 (Complete)

# Extract app and analyze
# 1. Backup app container via idevicebackup2
# 2. Extract backup
# 3. Check if files are encrypted (should be unreadable)
```

**OWASP MASTG Reference**: MASTG-TEST-0035 (Local Data Storage)

---

### Entitlement 8: platform-application

**Risk Level**: Critical

**Description**: Grants system-level privileges. **Only available to Apple system apps.** If present in third-party app, it's a security issue.

**Security Risk**:
- Complete system access
- Bypass of all sandbox restrictions
- Ability to access any data on device
- System-level code execution

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep platform-application
```

**Example**:
```xml
<!-- CRITICAL if present in third-party app -->
<key>platform-application</key>
<true/>
```

**Security Check**:
1. Is `platform-application` present in third-party app? (CRITICAL)
2. If present, report as critical vulnerability

**Remediation**:
- **CRITICAL**: This entitlement should NEVER be in third-party apps
- Report to Apple Security (security@apple.com) if found
- If you're the developer: Remove immediately; this indicates misconfiguration or build issue

**Testing**:
```bash
# Check app type
codesign -d -vvv /path/to/app.app | grep "Authority"

# If Authority shows "Apple iPhone OS Application Signing" but has platform-application:
# This is a CRITICAL security issue
```

**OWASP MASTG Reference**: MASTG-TEST-0000 (General Security Principles)

---

### Entitlement 9: NFC

**Risk Level**: High

**Description**: Allows app to read NFC tags and perform card emulation.

**Security Risk**:
- Unauthorized data reading from NFC tags
- Payment credential theft via card emulation
- Relay attacks on NFC transactions

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep -i nfc
```

**Example**:
```xml
<key>com.apple.developer.nfc.readersession.formats</key>
<array>
    <string>NDEF</string>
    <string>ISO7816</string>
</array>
```

**Security Check**:
1. Is NFC absolutely necessary for app functionality?
2. Are NFC operations properly authenticated?
3. Is sensitive data read from NFC tags properly protected?
4. Is card emulation implemented securely?

**Remediation**:
- Only use NFC for legitimate use cases (payments, access cards)
- Implement user consent for NFC operations
- Validate and sanitize all NFC data
- Use secure elements for payment card emulation
- Implement timeout and retry limits

**Testing**:
```bash
# Test NFC data handling
# 1. Create malicious NFC tag with crafted data
# 2. Scan with app
# 3. Monitor for crashes or data leakage

# Use Frida to intercept NFC operations
# NOTE: `monitor-nfc.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
frida -U -f com.example.app -l monitor-nfc.js
```

**OWASP MASTG Reference**: MASTG-TEST-0220 (Hardware Interactions)

---

### Entitlement 10: inter-app-audio

**Risk Level**: Medium

**Description**: Allows app to participate in Inter-App Audio (IAA) as an audio plugin or host.

**Security Risk**:
- Potential audio data leakage
- Unauthorized access to audio streams
- Privacy implications (recording audio from other apps)

**Detection**:
```bash
codesign -d --entitlements - /path/to/app.app | grep inter-app-audio
```

**Example**:
```xml
<key>inter-app-audio</key>
<true/>
```

**Security Check**:
1. Is IAA necessary for app functionality?
2. Are audio streams properly protected?
3. Is user consent obtained for audio access?

**Remediation**:
- Only use IAA for audio apps (DAWs, instruments)
- Implement proper audio stream protection
- Provide clear user indication when audio is being shared
- Test with malicious audio plugins

**Testing**:
```bash
# Test IAA connection
# 1. Install app with IAA entitlement
# 2. Install another IAA-compatible app
# 3. Connect apps and test audio data exchange

# Monitor audio data with Frida
# NOTE: `monitor-audio.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
frida -U -f com.example.app -l monitor-audio.js
```

---

## 4. Provisioning Profile Analysis

### What is Provisioning Profile?

Provisioning profile contains:
- App ID
- Entitlements
- Device list (for development)
- Certificate information
- Expiration date

### Extracting Provisioning Profile

```bash
# From IPA
unzip -q target.ipa "Payload/*.app/embedded.mobileprovision"

# Convert to readable format
security cms -D -i Payload/*.app/embedded.mobileprovision > profile.plist

# Or use plutil (if embedded.mobileprovision is binary plist)
plutil -convert xml1 -o profile.xml Payload/*.app/embedded.mobileprovision
```

### Analyzing Provisioning Profile

```bash
# Check App ID
plutil -p profile.plist | grep application-identifier

# Check expiration
plutil -p profile.plist | grep ExpirationDate

# Check devices (development profile only)
plutil -p profile.plist | grep ProvisionedDevices

# Check entitlements
plutil -p profile.plist | grep Entitlements -A 20

# Check team identifier
plutil -p profile.plist | grep TeamIdentifier
```

### Security Checks for Provisioning Profile

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Expired profile | **CRITICAL** | ExpirationDate in past | Renew provisioning profile |
| Wildcard App ID | **MEDIUM** | App ID contains `*` (e.g., `*` or `com.company.*`) | Use explicit App ID |
| Too many devices | **MEDIUM** | ProvisionedDevices contains many devices | Remove unused devices |
| Mismatched entitlements | **HIGH** | Entitlements differ from Info.plist | Synchronize entitlements |
| Development in production | **CRITICAL** | `get-task-allow` = true in App Store build | Use production provisioning profile |

### Example Provisioning Profile Analysis

```bash
#!/bin/bash

PROFILE="${1:-embedded.mobileprovision}"

echo "=== Provisioning Profile Analysis ==="
echo ""

# Convert to plist
security cms -D -i "$PROFILE" > temp.plist

# Check expiration
echo "Expiration Date:"
plutil -p temp.plist | grep ExpirationDate
echo ""

# Check App ID
echo "Application Identifier:"
plutil -p temp.plist | grep application-identifier
echo ""

# Check Team
echo "Team Identifier:"
plutil -p temp.plist | grep TeamIdentifier
echo ""

# Check Entitlements
echo "Entitlements:"
plutil -p temp.plist | grep Entitlements -A 50
echo ""

# Check get-task-allow
echo "Debuggable (get-task-allow):"
if plutil -p temp.plist | grep -q "get-task-allow.*true"; then
    echo "  [CRITICAL] App is debuggable (development build)"
else
    echo "  [OK] App is not debuggable (production build)"
fi
echo ""

# Check Wildcard App ID
echo "App ID Type:"
if plutil -p temp.plist | grep -q '\.\*'; then
    echo "  [MEDIUM] Wildcard App ID detected"
else
    echo "  [OK] Explicit App ID"
fi
echo ""

echo "=== Analysis Complete ==="

# Clean up
rm temp.plist
```

---

## 5. Code Signing Verification

### Verify Code Signature

```bash
# Basic verification
codesign -v /path/to/app.app/

# Verbose verification (shows entitlements, requirements)
codesign -dvvv /path/to/app.app/

# Verify all signatures in bundle
codesign -v --deep /path/to/app.app/

# Verify on device
ssh root@"<device-ip>" "codesign -v /var/mobile/Containers/Bundle/Application/*/target.app/"
```

### Check Signature Status

| Status | Meaning | Security Implication |
|--------|---------|---------------------|
| `valid on disk` | Code signature is valid | OK |
| `satisfies its Designated Requirement` | Signature matches requirement | OK |
| `code object is not signed at all` | No signature | CRITICAL: Not signed |
| `invalid entitlements` | Entitlements don't match profile | HIGH: Entitlement mismatch |
| `sealed resource is missing or invalid` | Bundle modified | CRITICAL: Modified bundle |

### Verify Signing Identity

```bash
# Show signing certificate
codesign -dvvv /path/to/app.app/ | grep "Authority"

# Check if signed by Apple (App Store)
# Should show: "Apple iPhone OS Application Signing"

# Check if signed by self (self-signed)
# Will show: "Mac Developer: <name>" or similar
```

### Entitlement Verification

```bash
# Extract and verify entitlements
codesign -d --entitlements - /path/to/app.app/ > entitlements.plist

# Check entitlements against Info.plist
plutil -p entitlements.plist
```

---

## 6. Entitlement Vulnerabilities

### Vulnerability 1: get-task-allow in Production

**Severity**: Critical

**CVSS 4.0 Vector**: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:U`

**Score**: 8.5 (CRITICAL)

**Description**: The app has `get-task-allow` entitlement in production build, allowing runtime instrumentation and debugging.

**Impact**:
- Complete runtime manipulation via Frida/LLDB
- Bypass of all security checks (root/jailbreak detection, SSL pinning)
- Sensitive data extraction
- Code injection and modification

**Exploitation**:
```bash
# Attach Frida to production app
frida -U com.example.app

# Dump memory
frida -U com.example.app -e "Process.enumerateModules().forEach(m => console.log(m.name))"

# Bypass SSL pinning
frida -U com.example.app -l ssl-pinning-bypass-ios.js
```

**Remediation**:
1. Ensure build configuration is set to Release for production
2. Verify entitlements after every production build
3. Implement CI/CD checks to reject builds with `get-task-allow`
4. Use Archive → Export → App Store distribution

**Testing**:
```bash
# Test production build
codesign -d --entitlements - /path/to/production.app/ | grep get-task-allow

# Should return nothing (secure)
# If shows <true/>: VULNERABLE
```

---

### Vulnerability 2: Excessive Keychain Access

**Severity**: High

**CVSS 4.0 Vector**: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U`

**Score**: 7.5 (HIGH)

**Description**: App has excessive `keychain-access-groups` entitlement, accessing more keychain groups than necessary.

**Impact**:
- Unauthorized credential access
- Data leakage between apps
- Potential credential theft if malicious app shares group

**Exploitation**:
```bash
# On jailbroken device, check keychain access
ssh root@"<device-ip>" "security dump-keychain | grep -A 10 'group.com.company.shared'"

# Dump shared keychain data using Objection
objection -g com.example.app explore
ios keychain dump --json > keychain.json
```

**Remediation**:
1. Use app-specific keychain group when possible
2. Avoid sharing keychain groups with untrusted apps
3. Implement additional access controls (password, biometrics)
4. Document all keychain group usage

**Testing**:
```bash
# Test keychain access
# 1. Install two apps in same keychain group
# 2. App A saves data
# 3. App B reads data (should work)
# 4. Verify this is intended behavior
```

---

### Vulnerability 3: Universal Link Hijacking

**Severity**: High

**CVSS 4.0 Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N/E:U`

**Score**: 7.8 (HIGH)

**Description**: App has `associated-domains` entitlement but AASA file is misconfigured, allowing universal link hijacking.

**Impact**:
- Phishing via fraudulent links
- Credential theft
- Unauthorized actions triggered via universal links

**Exploitation**:
```bash
# Test universal link
xcrun simctl openurl booted "https://example.com/path"

# If opens app instead of Safari: working correctly
# If opens wrong app: hijacking possible

# Check AASA file
curl https://example.com/.well-known/apple-app-site-association | plutil -p -
```

**Remediation**:
1. Ensure AASA file is properly configured
2. Validate AASA file before deployment
3. Use HTTPS for AASA file
4. Implement link handler validation
5. Test universal link handlers for security

**Testing**:
```bash
# Test universal link handling
# 1. Create malicious link with path traversal
# 2. Try to open universal link
# 3. Monitor app behavior

# Use Frida to monitor URL handling
frida -U -f com.example.app -l url-scheme-monitor.js
```

---

### Vulnerability 4: Application Group Data Leakage

**Severity**: High

**CVSS 4.0 Vector**: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U`

**Score**: 7.5 (HIGH)

**Description**: App has `application-groups` entitlement and stores sensitive data in shared container without additional protection.

**Impact**:
- Sensitive data accessible to other apps in group
- Unauthorized data sharing
- Privacy violations

**Exploitation**:
```bash
# On jailbroken device, access shared container
ssh root@"<device-ip>" "ls -la /var/mobile/Containers/Shared/AppGroup/"

# Read shared data
ssh root@"<device-ip>" "cat /var/mobile/Containers/Shared/AppGroup/group.com.company.shared/Database.db"

# Use Objection to access shared files
objection -g com.example.app explore
ios file cat /var/mobile/Containers/Shared/AppGroup/group.com.company.shared/secret.txt
```

**Remediation**:
1. Minimize use of application groups
2. Avoid storing sensitive data in shared containers
3. Implement additional encryption for shared data
4. Use app-specific containers for sensitive data
5. Document all shared container usage

**Testing**:
```bash
# Test shared container access
# 1. Install two apps in same group
# 2. App A writes to shared container
# 3. App B reads from shared container
# 4. Verify this is intended
```

---

## Quick Entitlement Audit Script

```bash
#!/bin/bash

APP="${1:-target.app}"

if [ ! -d "$APP" ]; then
    echo "Error: App not found"
    exit 1
fi

echo "=== Entitlement Security Audit ==="
echo ""
echo "Analyzing: $APP"
echo ""

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0

# Extract entitlements
ENTITLEMENTS=$(codesign -d --entitlements - "$APP" 2>/dev/null)

if [ -z "$ENTITLEMENTS" ]; then
    echo "[CRITICAL] Code signature or entitlements not found"
    ((CRITICAL_COUNT++))
    exit 1
fi

# Check get-task-allow
echo "1. Debugging (get-task-allow):"
if echo "$ENTITLEMENTS" | grep -q "get-task-allow.*true"; then
    echo "   [CRITICAL] get-task-allow = true (production build should not have this)"
    ((CRITICAL_COUNT++))
else
    echo "   [OK] get-task-allow not present or false"
fi
echo ""

# Check platform-application
echo "2. Platform Application:"
if echo "$ENTITLEMENTS" | grep -q "platform-application.*true"; then
    echo "   [CRITICAL] platform-application = true (system-level app, not for third-party)"
    ((CRITICAL_COUNT++))
else
    echo "   [OK] platform-application not present"
fi
echo ""

# Check keychain-access-groups
echo "3. Keychain Access Groups:"
if echo "$ENTITLEMENTS" | grep -q "keychain-access-groups"; then
    echo "   [INFO] Keychain access groups found:"
    echo "$ENTITLEMENTS" | grep -A 5 "keychain-access-groups" | grep "string"
    ((MEDIUM_COUNT++))
else
    echo "   [OK] No keychain access groups"
fi
echo ""

# Check application-groups
echo "4. Application Groups:"
if echo "$ENTITLEMENTS" | grep -q "application-groups"; then
    echo "   [HIGH] Application groups found:"
    echo "$ENTITLEMENTS" | grep -A 5 "application-groups" | grep "string"
    ((HIGH_COUNT++))
else
    echo "   [OK] No application groups"
fi
echo ""

# Check associated-domains
echo "5. Associated Domains:"
if echo "$ENTITLEMENTS" | grep -q "associated-domains"; then
    echo "   [MEDIUM] Associated domains found:"
    echo "$ENTITLEMENTS" | grep -A 5 "associated-domains" | grep "string"
    ((MEDIUM_COUNT++))
else
    echo "   [OK] No associated domains"
fi
echo ""

# Check network-extension
echo "6. Network Extension:"
if echo "$ENTITLEMENTS" | grep -q "network-extension"; then
    echo "   [HIGH] Network extension found:"
    echo "$ENTITLEMENTS" | grep -A 5 "network-extension" | grep "string"
    ((HIGH_COUNT++))
else
    echo "   [OK] No network extension"
fi
echo ""

# Summary
echo "=== Summary ==="
echo "Critical: $CRITICAL_COUNT"
echo "High: $HIGH_COUNT"
echo "Medium: $MEDIUM_COUNT"
echo ""

if [ $CRITICAL_COUNT -gt 0 ]; then
    echo "[CRITICAL] App has critical security issues"
    exit 1
elif [ $HIGH_COUNT -gt 0 ]; then
    echo "[HIGH] App has high-severity security issues"
    exit 1
else
    echo "[OK] No critical or high-severity issues found"
fi
```

Save as `audit-entitlements.sh`, make executable: `chmod +x audit-entitlements.sh`, run: `./audit-entitlements.sh target.app`

---

## Reference Links

- **OWASP MASTG**: https://mas.owasp.org/MASTG/
- **Apple Developer Documentation**: https://developer.apple.com/documentation/bundleresources/entitlements
- **iOS Security Guide**: https://support.apple.com/guide/security/welcome/web
