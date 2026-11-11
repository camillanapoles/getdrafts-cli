# Enterprise App Testing Guide

## Table of Contents

1. [Overview](#overview)
2. [Enterprise App Distribution Types](#enterprise-app-distribution-types)
3. [Enterprise App Security Considerations](#enterprise-app-security-considerations)
4. [Testing Methodology](#testing-methodology)
5. [Static Analysis](#static-analysis)
6. [Dynamic Analysis](#dynamic-analysis)
7. [Common Vulnerabilities](#common-vulnerabilities)
8. [Remediation](#remediation)
9. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

Enterprise apps for iOS differ significantly from App Store apps in distribution, security controls, and testing requirements. This guide covers comprehensive security testing for enterprise-signed apps, Volume Purchase Program (VPP) apps, Device Enrollment Program (DEP) apps, and custom distribution methods.

### Why Enterprise App Testing is Different

| Aspect | App Store Apps | Enterprise Apps |
|--------|---------------|-----------------|
| **Distribution** | Apple App Store | Direct installation, OTA, VPP, DEP |
| **Review Process** | Apple App Review | No review or internal review |
| **Code Signing** | Apple Distribution | Enterprise certificate (self-managed) |
| **Entitlements** | Restricted by Apple | Broader, custom entitlements |
| **Updates** | Through App Store | Custom update mechanisms |
| **Debug Mode** | Disabled | Often enabled (get-task-allow) |
| **Protections** | Strict App Store policies | Weaker, organization-controlled |

### Testing Scenarios

1. **In-House/Enterprise-Signed Apps**
   - Apps signed with enterprise certificates
   - Direct installation via .ipa files
   - OTA distribution via manifest.plist

2. **VPP (Volume Purchase Program) Apps**
   - App Store apps purchased in bulk
   - Deployed via MDM (Jamf, Intune, Workspace ONE)
   - Managed app configuration

3. **DEP (Device Enrollment Program) Apps**
   - Automatic app installation on corporate devices
   - Zero-touch provisioning
   - Supervised device requirements

4. **B2B Custom App Store**
   - Private App Store for specific organizations
   - Limited distribution
   - Custom review process

5. **Custom Distribution**
   - OTA via web server
   - TestFlight beta testing
   - Direct USB installation via Xcode

---

## Enterprise App Distribution Types

### 1. In-House/Enterprise-Signed Apps

#### Characteristics
- **Certificate Type**: Enterprise Developer Certificate
- **Authority**: Apple Worldwide Developer Relations Certification Authority
- **Team Identifier**: Custom enterprise team ID
- **Distribution**: Unlimited, no App Store required

#### Detection
```bash
# Check signing authority
codesign -d -vvv YourApp.app | grep "Authority"

# Output for enterprise app:
# Authority: Apple Worldwide Developer Relations Certification Authority
# Authority: [Enterprise Company Name]
# Authority: Apple Root CA

# Check for get-task-allow (debug mode enabled)
codesign -d --entitlements - YourApp.app | grep "get-task-allow"
# get-task-allow: true
```

#### Security Implications
- **Pros**: No App Store review, custom distribution
- **Cons**:
  - Broader entitlements
  - Debug mode often enabled
  - Weaker code signing enforcement
  - Easier to modify/re-sign
  - No sandbox restrictions on some entitlements

#### Testing Checklist
- [ ] Check for debug mode (get-task-allow)
- [ ] Verify entitlements are appropriate
- [ ] Test app re-signing
- [ ] Check for hardcoded test/development URLs
- [ ] Verify certificate trust chain
- [ ] Test OTA distribution security

---

### 2. Volume Purchase Program (VPP) Apps

#### Characteristics
- **Certificate Type**: Apple Distribution Certificate
- **Distribution**: Apple Business Manager / Apple School Manager
- **Management**: MDM-managed licenses
- **Updates**: Controlled by organization

#### Detection
```bash
# Check for managed app configuration
plutil -p Info.plist | grep "com.apple.configuration.managed"

# Check for VPP-specific entitlements
codesign -d --entitlements - YourApp.app | grep -A 10 "com.apple.developer"
```

#### Security Implications
- **Pros**: App Store review, standard security
- **Cons**:
  - Managed app configuration may expose sensitive settings
  - License management via MDM
  - App updates controlled by org
  - May have custom MDM-enforced settings

#### Testing Checklist
- [ ] Extract managed app configuration keys
- [ ] Test configuration key injection
- [ ] Verify MDM-enforced restrictions
- [ ] Test app update mechanism
- [ ] Check for managed app data leakage

---

### 3. Device Enrollment Program (DEP) Apps

#### Characteristics
- **Distribution**: Automatic installation on enrollment
- **Device Type**: Supervised (corporate-owned)
- **Management**: Full MDM control
- **Removal**: Not possible by user

#### Detection
```bash
# Check device supervision status (on device)
/usr/bin/profiles show -type enrollment

# Check for DEP enrollment
/usr/bin/profiles list | grep "com.apple.dep"

# Check if app is removable
/usr/bin/profiles show -type app
```

#### Security Implications
- **Pros**: Strong management control
- **Cons**:
  - Device is fully supervised
  - Advanced MDM commands available
  - User cannot remove MDM
  - Potential for privacy concerns

#### Testing Checklist
- [ ] Test supervised device restrictions
- [ ] Verify MDM command handling
- [ ] Test app installation/removal bypass
- [ ] Check for surveillance capabilities
- [ ] Verify data separation (BYOD vs corporate)

---

## Enterprise App Security Considerations

### 1. Certificate Trust Bypass

#### Problem
Enterprise apps often use custom certificates for internal services. These certificates may be trusted without proper validation, allowing MITM attacks.

#### Detection
```javascript
// Frida: Check for custom certificate validation
if (ObjC.available) {
    // Hook SecTrustEvaluateWithError
    var secMod = Process.findModuleByName('Security');
    var SecTrustEvaluateWithError = secMod ? secMod.findExportByName('SecTrustEvaluateWithError') : null;

    Interceptor.attach(SecTrustEvaluateWithError, {
        onEnter: function(args) {
            var trust = args[0];
            console.log("[*] SecTrustEvaluateWithError called");
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 1) {
                console.log("[+] Certificate trust bypassed");
            }
        }
    });
}
```

#### Testing
1. Intercept HTTPS traffic with proxy (Burp Suite, Charles)
2. Check if app accepts untrusted certificates
3. Test with custom CA certificates
4. Verify certificate pinning implementation

---

### 2. App Group Container Exposure

#### Problem
App group containers allow data sharing between apps. Without proper access controls, any app in the group can read sensitive data.

#### Detection
```bash
# Extract app groups from entitlements
codesign -d --entitlements - YourApp.app | grep "application-groups"

# List app group containers
ls -la /var/mobile/Containers/Shared/AppGroup/

# Find container for specific app
find /var/mobile/Containers/Shared/AppGroup/ -name "*.db"
```

#### Testing
```javascript
// Frida: Dump app group container
// assets/frida-scripts/app-groups-inspector.js

if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager.defaultManager();

    var appGroupContainer = NSFileManager.containerURLForSecurityApplicationGroupIdentifier_(
        "group.com.example.shared"
    );

    console.log("[+] App Group Container: " + appGroupContainer.toString());

    // List files
    var files = NSFileManager.contentsOfDirectoryAtPath_error_(
        appGroupContainer, NULL
    );

    console.log("[+] Files in container:");
    for (var i = 0; i < files.count(); i++) {
        console.log("  - " + files.objectAtIndex_(i));
    }
}
```

---

### 3. Keychain Sharing Weaknesses

#### Problem
Keychain access groups allow multiple apps to share credentials. Weak configuration can expose secrets.

#### Detection
```bash
# Extract keychain access groups
codesign -d --entitlements - YourApp.app | grep "keychain-access-groups"

# Check accessibility level
grep -r "kSecAttrAccessible" . --include="*.swift" --include="*.m"
```

#### Testing
```javascript
// Frida: Dump keychain items in access group
// assets/frida-scripts/keychain-dumper.js

if (ObjC.available) {
    var secMod = Process.findModuleByName('Security');
    var SecItemCopyMatching = new NativeFunction(
        secMod ? secMod.findExportByName('SecItemCopyMatching') : null,
        'int',
        ['pointer', 'pointer']
    );

    var query = ObjC.classes.NSMutableDictionary.alloc().init();
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true),
                            kSecReturnAttributes);
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true),
                            kSecReturnData);
    query.setObject_forKey_(kSecClassGenericPassword, kSecClass);
    query.setObject_forKey_('$(AppIdentifierPrefix)com.example',
                            kSecAttrAccessGroup);

    var result = ptr(0);
    var status = SecItemCopyMatching(query, result);

    if (status == 0) {
        console.log("[+] Keychain items:");
        for (var i = 0; i < result.count(); i++) {
            var item = result.objectAtIndex_(i);
            console.log("  Account: " + item.objectForKey_(kSecAttrAccount));
            console.log("  Service: " + item.objectForKey_(kSecAttrService));
        }
    }
}
```

---

### 4. Managed App Configuration

#### Problem
Managed app configuration can expose sensitive settings or be manipulated by malicious apps.

#### Detection
```bash
# Extract managed configuration keys
plutil -p Info.plist | grep -A 10 "com.apple.configuration.managed"

# Check how app reads configuration
grep -r "managed" . --include="*.swift" --include="*.m"
```

#### Testing
```javascript
// Frida: Inspect managed app configuration
// assets/frida-scripts/managed-app-inspector.js

if (ObjC.available) {
    var UserDefaults = ObjC.classes.NSUserDefaults;
    var sharedDefaults = UserDefaults.alloc().initWithSuiteName_(
        "group.com.example.shared"
    );

    console.log("[+] Managed Configuration Keys:");
    var keys = sharedDefaults.dictionaryRepresentation().allKeys();
    for (var i = 0; i < keys.count(); i++) {
        var key = keys.objectAtIndex_(i);
        var value = sharedDefaults.objectForKey_(key);
        console.log("  " + key + " = " + value);
    }
}
```

---

## Testing Methodology

### Phase 0: Preparation

```bash
# 1. Extract IPA
unzip app.ipa -d extracted/
cd extracted/Payload/YourApp.app/

# 2. Analyze binary
otool -l YourApp | grep -A 5 LC_ENCRYPTION_INFO
lipo -info YourApp

# 3. Check signing
codesign -d -vvv YourApp.app
codesign -d --entitlements - YourApp.app

# 4. Detect enterprise signing
codesign -d -vvv YourApp.app | grep "Authority" | grep "Enterprise"
```

### Phase 1: Static Analysis

```bash
# 1. Check entitlements
codesign -d --entitlements - YourApp.app > entitlements.plist

# 2. Analyze Info.plist
plutil -p Info.plist > info.plist.txt

# 3. Search for enterprise-specific patterns
grep -r "MDMClient" . --include="*.swift" --include="*.m"
grep -r "managed" . --include="*.swift" --include="*.m"
grep -r "appGroup" . --include="*.swift" --include="*.m"

# 4. Check for debug mode
plutil -p Info.plist | grep "get-task-allow"
```

### Phase 2: Dynamic Analysis

```bash
# 1. Install app on device
ideviceinstaller install app.ipa

# 2. Launch with Frida
frida -U -f com.example.app -l mdm-bypass.js

# 3. Test certificate bypass
frida -U -f com.example.app -l enterprise-cert-bypass.js

# 4. Dump app groups
frida -U -f com.example.app -l app-groups-inspector.js

# 5. Inspect keychain
frida -U -f com.example.app -l keychain-dumper.js
```

### Phase 3: Vulnerability Verification

```bash
# 1. Test app re-signing
codesign --remove-signature YourApp.app
codesign -s "iPhone Developer" --force YourApp.app

# 2. Test app modification
# Modify Info.plist or resources
# Re-sign app
codesign -s "iPhone Developer" --force YourApp.app

# 3. Test OTA distribution
# Create manifest.plist
python3 -c "
import plistlib, uuid
manifest = {
    'items': [{
        'assets': [{
            'kind': 'software-package',
            'url': 'https://example.com/app.ipa'
        }],
        'metadata': {
            'bundle-identifier': 'com.example.app',
            'bundle-version': '1.0',
            'kind': 'software'
        }
    }]
}
plistlib.dump(manifest, open('manifest.plist', 'wb'))
"

# 4. Test configuration profile
/usr/bin/profiles install -i /tmp/profile.mobileconfig
```

---

## Static Analysis

### Entitlements Analysis

```bash
# Extract entitlements
codesign -d --entitlements - YourApp.app > entitlements.plist

# Analyze entitlements
python3 -c "
import plistlib, sys

with open('entitlements.plist', 'rb') as f:
    entitlements = plistlib.load(f)

# Check app groups
if 'com.apple.security.application-groups' in entitlements:
    print('[+] App Groups:')
    for group in entitlements['com.apple.security.application-groups']:
        print(f'  - {group}')

# Check keychain access
if 'keychain-access-groups' in entitlements:
    print('[+] Keychain Access Groups:')
    for group in entitlements['keychain-access-groups']:
        print(f'  - {group}')

# Check associated domains
if 'com.apple.developer.associated-domains' in entitlements:
    print('[+] Associated Domains:')
    for domain in entitlements['com.apple.developer.associated-domains']:
        print(f'  - {domain}')

# Check get-task-allow
if 'get-task-allow' in entitlements:
    if entitlements['get-task-allow']:
        print('[!] Debug mode enabled: get-task-allow = true')
    else:
        print('[+] Debug mode disabled: get-task-allow = false')
"
```

### Binary Analysis

```bash
# Check for MDM-related strings
strings YourApp | grep -i "mdm\|managed\|enterprise"

# Check for hardcoded URLs
strings YourApp | grep "http://\|https://"

# Check for API keys
strings YourApp | grep -E "api[_-]?key|secret|password|token"

# Check for debug symbols
otool -l YourApp | grep LC_DYSYMTAB

# Check for encryption
otool -l YourApp | grep -A 5 LC_ENCRYPTION_INFO
```

---

## Dynamic Analysis

### MDM Status Bypass

```javascript
// assets/frida-scripts/mdm-bypass.js

if (ObjC.available) {
    console.log("[*] MDM Bypass Script Started");

    // Hook MDMClient.isDeviceManaged
    try {
        var MDMClient = ObjC.classes.MDMClient;

        if (MDMClient) {
            Interceptor.attach(MDMClient['- isDeviceManaged'].implementation, {
                onLeave: function(retval) {
                    console.log("[+] MDMClient.isDeviceManaged hooked");
                    console.log("[+] Original return: " + retval);
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(false));
                    console.log("[+] Bypassed return: false (unmanaged)");
                }
            });
        }
    } catch (e) {
        console.log("[!] MDMClient not found: " + e.message);
    }

    // Hook profile status
    try {
        var MCProfileConnection = ObjC.classes.MCProfileConnection;

        if (MCProfileConnection) {
            Interceptor.attach(MCProfileConnection['- isManaged'].implementation, {
                onLeave: function(retval) {
                    console.log("[+] MCProfileConnection.isManaged hooked");
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(false));
                }
            });
        }
    } catch (e) {
        console.log("[!] MCProfileConnection not found: " + e.message);
    }

    console.log("[+] MDM bypass hooks installed");
}
```

### Enterprise Certificate Bypass

```javascript
// assets/frida-scripts/enterprise-cert-bypass.js

if (ObjC.available) {
    console.log("[*] Enterprise Certificate Bypass Started");

    // Hook SecTrustEvaluateWithError
    var secMod = Process.findModuleByName('Security');
    var SecTrustEvaluateWithError = secMod ? secMod.findExportByName('SecTrustEvaluateWithError') : null;

    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(
            (trust, error) => {
                console.log("[+] SecTrustEvaluateWithError bypassed");
                return 1; // kCFBooleanTrue
            },
            'int',
            ['pointer', 'pointer']
        ));
        console.log("[+] SecTrustEvaluateWithError hooked");
    }

    // Hook SecTrustEvaluate (deprecated but used)
    var SecTrustEvaluate = secMod ? secMod.findExportByName('SecTrustEvaluate') : null;

    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                console.log("[+] SecTrustEvaluate bypassed");
                retval.replace(0); // errSecSuccess
            }
        });
        console.log("[+] SecTrustEvaluate hooked");
    }

    console.log("[+] Enterprise certificate bypass hooks installed");
}
```

---

## Common Vulnerabilities

### 1. Debug Mode Enabled in Production

**Severity**: MEDIUM (5.0-6.5)
**CWE**: CWE-489 (Active Debug Code)
**OWASP**: M8 (Security Misconfiguration)

**Detection**:
```bash
codesign -d --entitlements - YourApp.app | grep "get-task-allow"
# get-task-allow: true
```

**Impact**:
- Allows debugger attachment
- Easier reverse engineering
- Potential for Frida instrumentation
- Exposes debug information

**Remediation**:
```xml
<!-- Remove from entitlements -->
<key>get-task-allow</key>
<false/>
```

---

### 2. Insecure App Group Configuration

**Severity**: HIGH (7.0-8.0)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**OWASP**: M9 (Insecure Data Storage)

**Detection**:
```bash
codesign -d --entitlements - YourApp.app | grep "application-groups"
# Multiple apps in same group without need
```

**Impact**:
- Cross-app data access
- Privilege escalation
- Data exfiltration

**Remediation**:
- Use dedicated app groups with minimal membership
- Implement encryption for shared data
- Validate access within app group

---

### 3. Weak Keychain Accessibility

**Severity**: HIGH (7.0-8.0)
**CWE**: CWE-922 (Insecure Storage of Sensitive Information)
**OWASP**: M9 (Insecure Data Storage)

**Detection**:
```bash
grep -r "kSecAttrAccessibleWhenUnlocked" . --include="*.swift"
# Should be kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

**Impact**:
- Keychain items accessible when device unlocked
- Potential data extraction via device backups
- No device-bound protection

**Remediation**:
```swift
// Use more restrictive accessibility
kSecAttrAccessibleWhenUnlockedThisDeviceOnly
// or
kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
```

---

### 4. MDM Enrollment Bypass

**Severity**: CRITICAL (9.0+)
**CWE**: CWE-284 (Improper Access Control)
**OWASP**: M8 (Security Misconfiguration)

**Detection**:
```javascript
// Frida: Hook MDM status
// See assets/frida-scripts/mdm-bypass.js
```

**Impact**:
- Complete MDM evasion
- Bypass corporate policies
- Install unauthorized apps

**Remediation**:
- Implement server-side MDM validation
- Use Apple DeviceCheck API
- Add tamper detection

---

## Remediation

### Secure Enterprise App Distribution

1. **Code Signing**:
   ```bash
   # Use production certificates
   codesign -s "Enterprise Developer" --force YourApp.app

   # Verify signing
   codesign -v -v YourApp.app
   ```

2. **Entitlements Review**:
   ```xml
   <!-- Minimal required entitlements only -->
   <key>com.apple.security.application-groups</key>
   <array>
     <string>group.com.example.app1</string>
   </array>

   <key>get-task-allow</key>
   <false/>
   ```

3. **Configuration Security**:
   ```bash
   # Disable test/debug URLs
   # Remove test certificates
   # Remove debugging code
   ```

### MDM Security Best Practices

1. **Profile Security**:
   ```bash
   # Encrypt profiles
   # Sign profiles
   # Validate profile integrity
   ```

2. **App Group Security**:
   ```bash
   # Use dedicated groups
   # Implement encryption
   # Validate access
   ```

3. **Keychain Security**:
   ```bash
   # Use device-bound accessibility
   # Implement access controls
   # Use Secure Enclave where possible
   ```

---

## OWASP MASTG References

| Test ID | Test Name | Enterprise Relevance |
|---------|-----------|---------------------|
| MASTG-STG-001 | Information Gathering | Enterprise app enumeration |
| MASTG-TEST-0002 | Information Gathering | MDM configuration analysis |
| MASTG-TEST-0088 | Local Data Storage | App group container security |
| MASTG-TEST-0135 | Local Data Storage | Keychain sharing security |
| MASTG-TEST-0225 | Network Communication | Per-app VPN security |
| MASTG-TEST-0226 | Network Communication | Enterprise certificate trust |
| MASTG-TEST-0230 | Platform Interaction | Configuration profile abuse |
| MASTG-TEST-0232 | Platform Interaction | MDM enrollment bypass |

---

**Document Version**: 1.0
**Last Updated**: 2025-04-04
**Author**: DragonJAR SAS
**License**: Apache 2.0
