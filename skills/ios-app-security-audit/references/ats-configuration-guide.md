# App Transport Security (ATS) Configuration Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [ATS Fundamentals](#ats-fundamentals)
3. [ATS Configuration Keys](#ats-configuration-keys)
4. [Configuration Examples](#configuration-examples)
5. [Testing Methodology](#testing-methodology)
6. [Bypassing ATS](#bypassing-ats)
7. [iOS 17+ Changes](#ios-17-changes)
8. [Common Misconfigurations](#common-misconfigurations)
9. [Remediation Checklist](#remediation-checklist)
10. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

App Transport Security (ATS) is a security feature introduced in iOS 9 that enforces secure network connections. ATS requires HTTPS with strong encryption by default, helping protect sensitive data in transit. This guide covers ATS configuration, testing, bypassing, and best practices.

### Why Test ATS Configuration?

- **Verify secure defaults**: Ensure ATS enforces HTTPS
- **Test exception policies**: Check for overly permissive exceptions
- **Bypass for security testing**: Allow interception of HTTPS traffic
- **Certificate validation**: Verify proper certificate requirements
- **Configuration review**: Assess ATS configuration security

---

## ATS Fundamentals

### How ATS Works

```
1. App initiates network request
2. ATS examines request configuration
3. If HTTPS and TLS 1.2+ with valid certificate → ALLOWED
4. If HTTP or weak TLS → BLOCKED (unless exception configured)
5. ATS validates:
   - TLS version (>= 1.2)
   - Cipher suites (forward secrecy)
   - Certificate validity
   - Certificate chain
```

### ATS Default Behavior (iOS 9+)

| Requirement | Default | Description |
|-------------|----------|-------------|
| Protocol | HTTPS only | HTTP blocked |
| TLS Version | 1.2+ | TLS 1.0/1.1 blocked |
| Cipher Suites | Forward secrecy only | AES-128/256, ChaCha20-Poly1305 |
| Certificate | Valid certificate chain | Self-signed certs blocked |
| Certificate Transparency | Required | CT logs verification |
| HSTS | Enforced | Strict Transport Security |

### ATS Enforcement Timeline

| iOS Version | ATS Status |
|-------------|------------|
| iOS 9-12.4 | Enforced by default |
| iOS 13-14 | Enforced by default |
| iOS 15-16 | Enforced by default |
| iOS 17+ | Stricter enforcement |

---

## ATS Configuration Keys

### NSAppTransportSecurity Dictionary

```xml
<!-- Info.plist - ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Allow arbitrary loads (NOT RECOMMENDED) -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- Allow local networking (development only) -->
    <key>NSAllowsLocalNetworking</key>
    <false/>

    <!-- Domain-specific exceptions -->
    <key>NSExceptionDomains</key>
    <dict>
        <!-- Exception for specific domain -->
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>

            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>

            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>

            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

### Key Descriptions

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `NSAllowsArbitraryLoads` | Boolean | false | Allow all HTTP/HTTPS |
| `NSAllowsArbitraryLoadsInWebContent` | Boolean | false | Allow HTTP in WKWebView |
| `NSAllowsLocalNetworking` | Boolean | false | Allow localhost connections |
| `NSAllowsArbitraryLoadsForMedia` | Boolean | false | Allow HTTP for media |
| `NSExceptionDomains` | Dictionary | {} | Domain-specific exceptions |
| `NSIncludesSubdomains` | Boolean | false | Include subdomains in exception |
| `NSExceptionAllowsInsecureHTTPLoads` | Boolean | false | Allow HTTP for domain |
| `NSExceptionMinimumTLSVersion` | String | - | Minimum TLS version |
| `NSExceptionRequiresForwardSecrecy` | Boolean | false | Require forward secrecy |
| `NSThirdPartyExceptionAllowsInsecureHTTPLoads` | Boolean | false | Allow HTTP for third-party |
| `NSThirdPartyExceptionMinimumTLSVersion` | String | - | Minimum TLS for third-party |
| `NSThirdPartyExceptionRequiresForwardSecrecy` | Boolean | false | Forward secrecy for third-party |

---

## Configuration Examples

### 1. Secure Configuration (Recommended)

```xml
<!-- Secure ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Enforce HTTPS only -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- Disable local networking in production -->
    <key>NSAllowsLocalNetworking</key>
    <false/>

    <!-- No domain exceptions (HTTPS only) -->
    <key>NSExceptionDomains</key>
    <dict/>
</dict>
```

**Testing**:
```bash
# HTTP request should fail
curl http://api.example.com/data
# Expected: curl: (7) Failed to connect

# HTTPS request should succeed
curl https://api.example.com/data
# Expected: Success
```

---

### 2. Development Configuration

```xml
<!-- Development ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Allow local networking for development -->
    <key>NSAllowsLocalNetworking</key>
    <true/>

    <!-- Allow HTTP for local development server -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <key>NSExceptionDomains</key>
    <dict>
        <!-- Local development server -->
        <key>localhost</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>

        <!-- 127.0.0.1 -->
        <key>127.0.0.1</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>

        <!-- Development API server (if HTTP only) -->
        <key>dev-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**Testing**:
```bash
# Local HTTP request should work
curl http://localhost:8080/api/data
# Expected: Success

# Production HTTPS should still be enforced
curl https://api.example.com/data
# Expected: Success with valid certificate
```

---

### 3. Mixed Configuration (Some Domains Insecure)

```xml
<!-- Mixed ATS Configuration (NOT RECOMMENDED) -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Block HTTP by default -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <key>NSExceptionDomains</key>
    <dict>
        <!-- Legacy API server (HTTP only) -->
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>

        <!-- Partner API with weak TLS -->
        <key>partner.example.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.0</string>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <false/>
        </dict>

        <!-- Analytics endpoint (self-signed cert) -->
        <key>analytics.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <false/>
        </dict>
    </dict>
</dict>
```

**Testing**:
```bash
# Legacy HTTP API should work
curl http://legacy-api.example.com/data
# Expected: Success

# HTTPS API should enforce TLS 1.2+
curl https://api.example.com/data --tlsv1.2
# Expected: Success
curl https://api.example.com/data --tlsv1.1
# Expected: Failure

# Partner API should accept weak TLS
curl https://partner.example.com/data --tlsv1.0
# Expected: Success
```

---

### 4. Very Permissive Configuration (INSECURE!)

```xml
<!-- INSECURE ATS Configuration - DO NOT USE -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Allow all HTTP and HTTPS -->
    <key>NSAllowsArbitraryLoads</key>
    <true/>

    <!-- Allow HTTP in web content -->
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <true/>

    <!-- Allow HTTP for media -->
    <key>NSAllowsArbitraryLoadsForMedia</key>
    <true/>

    <!-- Allow local networking -->
    <key>NSAllowsLocalNetworking</key>
    <true/>

    <!-- No domain-specific rules needed -->
</dict>
```

**Testing**:
```bash
# All requests should work
curl http://any-api.example.com/data
# Expected: Success

curl http://insecure-api.example.com/data
# Expected: Success

# ATS effectively disabled!
```

---

## Testing Methodology

### Step 1: Extract and Analyze ATS Configuration

```bash
# Extract IPA
unzip -q Example.ipa -d Extracted

# Parse Info.plist
plutil -p Extracted/Payload/Example.app/Info.plist | grep -A50 "NSAppTransportSecurity"

# Or convert to XML for easier reading
plutil -convert xml1 Extracted/Payload/Example.app/Info.plist -o -
# Then search for NSAppTransportSecurity
```

### Step 2: Test HTTP/HTTPS Enforcement

```bash
# Test HTTP request (should fail in production)
curl -v http://api.example.com/data

# Expected output:
# curl: (35) schannel: failed to initialize ssl connection: SEC_E_ILLEGAL_MESSAGE
# OR
# curl: (7) Failed to connect to api.example.com port 80: Connection refused

# Test HTTPS request (should succeed with valid cert)
curl -v https://api.example.com/data

# Expected output:
# * TLS 1.2 or TLS 1.3 connection
# * Successful response
```

### Step 3: Test Domain Exceptions

```bash
# Test exception domain (configured to allow HTTP)
curl -v http://legacy-api.example.com/data

# Expected output (if configured):
# * Connection succeeded

# Test non-exception domain (should fail)
curl -v http://other-api.example.com/data

# Expected output:
# * Connection failed (ATS blocked)
```

### Step 4: Test TLS Version Requirements

```bash
# Test with TLS 1.2 (should succeed)
curl -v --tlsv1.2 https://api.example.com/data

# Test with TLS 1.1 (should fail if TLS 1.2+ required)
curl -v --tlsv1.1 https://api.example.com/data

# Expected output:
# * SSL: certificate verification failed
# OR
# * Connection failed
```

### Step 5: Test with Frida

```javascript
// ats-hook.js - Hook ATS-related functions
if (ObjC.available) {
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    // Hook defaultSessionConfiguration
    Interceptor.attach(NSURLSessionConfiguration["- defaultSessionConfiguration"], {
        onLeave: function(retval) {
            var config = ObjC.Object(retval);
            console.log("[*] Default URLSession Configuration");
            console.log("  TLS minimum version:", config.TLSMinimumSupportedProtocolVersion());
            console.log("  Allows arbitrary loads:", config.allowsCellularAccess());
        }
    });

    // Hook ephemeralSessionConfiguration
    Interceptor.attach(NSURLSessionConfiguration["- ephemeralSessionConfiguration"], {
        onLeave: function(retval) {
            var config = ObjC.Object(retval);
            console.log("[*] Ephemeral URLSession Configuration");
            console.log("  TLS minimum version:", config.TLSMinimumSupportedProtocolVersion());
        }
    });

    console.log("[*] ATS hooks installed");
}
```



```bash
// Run:
# NOTE: `ats-hook.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
frida -U -l ats-hook.js -f com.example.app
```

---

## Bypassing ATS

### Method 1: Modifying Info.plist (Jailbroken Device)

```bash
# On jailbroken device, modify Info.plist

# Step 1: Find app container
ssh root@DEVICE_IP
cd /var/mobile/Containers/Data/Application
find . -name "Info.plist" | grep Example

# Step 2: Backup original
cp /path/to/Example.app/Info.plist /path/to/Example.app/Info.plist.backup

# Step 3: Add ATS bypass
plutil -insert NSAppTransportSecurity -dict \
    -string NSAllowsArbitraryLoads -bool YES \
    /path/to/Example.app/Info.plist

# Step 4: Restart app
killall Example

# Step 5: Verify bypass
# HTTP requests should now work
```

### Method 2: Frida Bypass

```javascript
// ats-bypass.js - Disable ATS via Frida
if (ObjC.available) {
    console.log("[*] Disabling ATS...");

    // Method 1: Hook NSURLSessionConfiguration
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    // Hook defaultSessionConfiguration
    Interceptor.attach(NSURLSessionConfiguration["- defaultSessionConfiguration"], {
        onLeave: function(retval) {
            var config = ObjC.Object(retval);

            // Set to allow arbitrary loads
            config.setAllowsCellularAccess_(1);  // Allow any
            config.setAllowsExpensiveNetworkAccess_(1);
            config.setAllowsConstrainedNetworkAccess_(1);

            // Set TLS to minimum
            config.setTLSMinimumSupportedProtocolVersion_(0);

            console.log("[+] Modified URLSession configuration");
        }
    });

    // Method 2: Hook CFNetwork
    var cfNetMod = Process.findModuleByName('CFNetwork');
    var CFNetwork = cfNetMod ? cfNetMod.findExportByName('CFURLConnectionCreateWithProperties') : null;

    if (CFNetwork) {
        Interceptor.attach(CFNetwork, {
            onEnter: function(args) {
                console.log("[+] CFURLConnectionCreateWithProperties called");
            }
        });
    }

    // Method 3: Hook SecTrustEvaluate
    var secMod = Process.findModuleByName('Security');
    var SecTrustEvaluate = secMod ? secMod.findExportByName('SecTrustEvaluate') : null;

    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                console.log("[+] Bypassing SecTrustEvaluate");
                retval.replace(0x1);  // Always return success
            }
        });
    }

    console.log("[*] ATS bypass hooks installed");
}

// Run:
```

```bash
frida -U -l ats-bypass.js -f com.example.app

```
```

### Method 3: Objection Bypass

```bash
# While in Objection session
objection -g com.example.app explore

# Bypass ATS
ios plist patch NSAppTransportSecurity NSAllowsArbitraryLoads true

# Or use built-in command
ios atrule disable

# Verify
# HTTP requests should now work
```

---

## iOS 17+ Changes

### New ATS Requirements

| Feature | iOS 16 | iOS 17+ |
|---------|--------|---------|
| Minimum TLS | 1.2 | 1.2 |
| Certificate Transparency | Optional | Required |
| HSTS | Enforced | Stricter |
| QUIC/HTTP3 | Not supported | Supported |
| TLS 1.3 | Optional | Preferred |

### iOS 17+ ATS Configuration

```xml
<!-- iOS 17+ ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Enforce HTTPS only -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- iOS 17+ specific -->
    <key>NSAllowsArbitraryLoadsForWebContent</key>
    <false/>

    <!-- Certificate Transparency required -->
    <key>NSRequiresCertificateTransparency</key>
    <true/>

    <key>NSExceptionDomains</key>
    <dict>
        <!-- Exception with CT bypass (NOT RECOMMENDED) -->
        <key>example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>

            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>

            <!-- iOS 17+: Disable CT for this domain (INSECURE) -->
            <key>NSRequiresCertificateTransparency</key>
            <false/>
        </dict>
    </dict>
</dict>
```

### Testing iOS 17+ Requirements

```bash
# Test Certificate Transparency
curl -v --ct-policy "Mozilla" https://api.example.com/data

# Expected output:
# * SCTs received

# Test TLS 1.3 (preferred in iOS 17+)
curl -v --tlsv1.3 https://api.example.com/data

# Expected output:
# * TLS 1.3 connection
```

---

## Common Misconfigurations

### 1. NSAllowsArbitraryLoads = true

**Problem**: Disables all ATS protections.

**Config**:
```xml
<key>NSAllowsArbitraryLoads</key>
<true/>
```

**Impact**: All HTTP/HTTPS allowed, no certificate validation.

**Fix**: Remove or set to false.

---

### 2. Production Development Config

**Problem**: Development config deployed to production.

**Config**:
```xml
<key>NSAllowsLocalNetworking</key>
<true/>

<key>NSExceptionDomains</key>
<dict>
    <key>localhost</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
    </dict>
</dict>
```

**Impact**: Local networking enabled, potential security risk.

**Fix**: Remove local networking exceptions in production.

---

### 3. Wide Domain Exceptions

**Problem**: Exception for entire TLD or parent domain.

**Config**:
```xml
<key>NSExceptionDomains</key>
<dict>
    <key>com</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
        <key>NSIncludesSubdomains</key>
        <true/>
    </dict>
</dict>
```

**Impact**: Allows HTTP for all .com domains!

**Fix**: Use specific subdomains only.

---

### 4. Weak TLS Configuration

**Problem**: Allowing TLS 1.0/1.1 or non-forward secrecy.

**Config**:
```xml
<key>NSExceptionMinimumTLSVersion</key>
<string>TLSv1.0</string>

<key>NSExceptionRequiresForwardSecrecy</key>
<false/>
```

**Impact**: Weak cryptography, vulnerable to attacks.

**Fix**: Require TLS 1.2+ and forward secrecy.

---

### 5. Web Content Exemption Abuse

**Problem**: Using web content exemption for all network calls.

**Config**:
```xml
<key>NSAllowsArbitraryLoadsInWebContent</key>
<true/>
```

**Impact**: HTTP allowed in all web views, bypasses ATS.

**Fix**: Only use for legitimate web content, not API calls.

---

## Remediation Checklist

### Production ATS Configuration

```markdown
## ATS Remediation Checklist

### Basic Configuration
- [ ] `NSAllowsArbitraryLoads` set to `false`
- [ ] `NSAllowsArbitraryLoadsInWebContent` set to `false`
- [ ] `NSAllowsArbitraryLoadsForMedia` set to `false`
- [ ] `NSAllowsLocalNetworking` set to `false`

### Domain Exceptions
- [ ] No `NSExceptionDomains` dictionary (ideal)
- [ ] OR: Only necessary exceptions present
- [ ] Exceptions are for specific subdomains (not entire TLD)
- [ ] `NSIncludesSubdomains` only when necessary
- [ ] `NSExceptionAllowsInsecureHTTPLoads` only for legacy APIs
- [ ] `NSExceptionMinimumTLSVersion` is `TLSv1.2` or higher
- [ ] `NSExceptionRequiresForwardSecrecy` set to `true`

### iOS 17+ Specific
- [ ] `NSRequiresCertificateTransparency` set to `true`
- [ ] No CT exceptions unless absolutely necessary

### Testing
- [ ] HTTP requests blocked (except for exceptions)
- [ ] HTTPS requests with TLS 1.2+ succeed
- [ ] HTTPS requests with weak TLS fail
- [ ] Self-signed certificates rejected
- [ ] Certificate chain validated

### Development
- [ ] Separate Info.plist for development and production
- [ ] `NSAllowsLocalNetworking` only in development
- [ ] Development exceptions removed before release
- [ ] Automated tests for ATS configuration
```

### Secure Template

```xml
<!-- Secure ATS Template (Production) -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Enforce HTTPS only -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- Block HTTP in web content -->
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <false/>

    <!-- Block HTTP for media -->
    <key>NSAllowsArbitraryLoadsForMedia</key>
    <false/>

    <!-- No local networking in production -->
    <key>NSAllowsLocalNetworking</key>
    <false/>

    <!-- iOS 17+: Require Certificate Transparency -->
    <key>NSRequiresCertificateTransparency</key>
    <true/>

    <!-- Minimal domain exceptions (if any) -->
    <key>NSExceptionDomains</key>
    <dict>
        <!-- Example: Legacy API with HTTPS but weaker requirements -->
        <!-- REMOVE IF NOT NEEDED -->
        <!--
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <false/>

            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>

            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>

            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
        -->
    </dict>
</dict>
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | ATS Context |
|---------------|-------|------------|
| MASTG-TEST-0060 | Network Communication Testing | ATS configuration |
| MASTG-APP-SEC-0020 | Communication Security | ATS enforcement |
| MASTG-TEST-0065 | TLS Configuration | TLS version testing |
| MASTG-APP-SEC-0025 | Certificate Validation | Certificate checks |

---

## Summary

This guide covered:
- ATS fundamentals and default behavior
- ATS configuration keys and their meanings
- Various configuration examples (secure, development, insecure)
- Comprehensive testing methodology
- ATS bypass techniques (Info.plist, Frida, Objection)
- iOS 17+ specific requirements
- Common misconfigurations and their impacts
- Remediation checklist and secure template

ATS is a critical security feature that protects network communications. Always enforce HTTPS with strong encryption, use minimal domain exceptions, and test configuration thoroughly before deployment.

---

## References

### Official Documentation
- Apple ATS Documentation: https://developer.apple.com/documentation/security/preventing_insecure_network_connections
- ATS Keys Reference: https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- iOS Security Guide: https://support.apple.com/guide/security/welcome/web
- Certificate Transparency: https://certificate.transparency.dev/
- TLS Best Practices: https://wiki.mozilla.org/Security/Server_Side_TLS

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** iOS development knowledge, Info.plist understanding, basic networking concepts
