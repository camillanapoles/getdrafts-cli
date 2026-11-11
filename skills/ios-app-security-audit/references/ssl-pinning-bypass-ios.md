# SSL Pinning Bypass Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [SSL Pinning Fundamentals](#ssl-pinning-fundamentals)
3. [iOS SSL Pinning Implementations](#ios-ssl-pinning-implementations)
4. [Manual Bypass Techniques](#manual-bypass-techniques)
5. [Frida Script Bypass](#frida-script-bypass)
6. [Objection Bypass](#objection-bypass)
7. [Burp Suite Integration](#burp-suite-integration)
8. [Certificate Installation](#certificate-installation)
9. [Testing Methodology](#testing-methodology)
10. [Advanced Bypass Scenarios](#advanced-bypass-scenarios)
11. [Remediation and Best Practices](#remediation-and-best-practices)
12. [OWASP MASTG References](#owasp-mastg-references)
13. [Simulator vs Physical Device](#simulator-vs-physical-device)

---

## Overview

SSL pinning is a security technique that ensures mobile applications only communicate with servers presenting valid, trusted certificates. This guide covers various SSL pinning implementations on iOS, manual bypass techniques, automated bypasses using Frida and Objection, and Burp Suite integration for security testing.

### Why Test SSL Pinning?

- **Verify implementation correctness**: Ensure pinning is properly implemented
- **Test certificate rotation**: Verify app handles certificate updates
- **Assess bypass difficulty**: Evaluate security of pinning mechanism
- **Test error handling**: Verify graceful degradation
- **Certificate transparency**: Check for proper certificate validation

---

## SSL Pinning Fundamentals

### How SSL Pinning Works

```
1. App contains embedded certificate(s) or public key(s)
2. During TLS handshake, server presents certificate
3. App compares server certificate with embedded certificate(s)
4. If match → Connection allowed
5. If mismatch → Connection blocked
```

### Types of SSL Pinning

| Pinning Type | Description | Pros | Cons |
|--------------|-------------|------|------|
| Certificate Pinning | Embed full certificate | Simple to implement | Certificate rotation required |
| Public Key Pinning | Embed public key only | More flexible, handles cert rotation | Slightly more complex |
| Intermediate CA Pinning | Pin intermediate CA | Flexible for multiple hosts | Less security than direct pinning |
| Certificate Transparency | Validate CT logs | Advanced security | Complex implementation |

### Pinning Locations

```bash
# Common locations for pinned certificates:
# 1. App bundle (.cer, .pem, .der files)
# 2. Code as constants or data
# 3. Remote configuration (dynamic pinning)
# 4. Keychain storage

# Finding pinned certificates:
# Extract IPA and search for certificate files
strings Example.app/Example | grep -i "BEGIN CERTIFICATE"
strings Example.app/Example | grep -i "\.cer\|\.pem\|\.der"

# Search in binary:
otool -s __TEXT __cstring Example.app/Example | grep -i "certificate"
```

---

## iOS SSL Pinning Implementations

### 1. SecTrustEvaluateWithError (iOS 12+)

```swift
// Native iOS SSL pinning using Security.framework
import Security

func validateServerTrust(trust: SecTrust) -> Bool {
    var error: CFError?
    let isValid = SecTrustEvaluateWithError(trust, &error)

    if let error = error {
        print("Trust evaluation failed: \(error)")
        return false
    }

    return isValid
}

// Custom validation with pinned certificate
func validatePinnedCertificate(trust: SecTrust) -> Bool {
    guard let pinnedCertData = loadPinnedCertificate() else {
        return false
    }

    // Get server certificate
    guard let serverCert = SecTrustGetCertificateAtIndex(trust, 0) else {
        return false
    }

    let serverCertData = SecCertificateCopyData(serverCert) as Data

    // Compare certificates
    return serverCertData == pinnedCertData
}
```

### 2. NSURLSession Delegate

```swift
// NSURLSession with delegate-based SSL pinning
import Foundation

class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    private let pinnedCertificates: [Data]

    init(certificateNames: [String]) {
        self.pinnedCertificates = certificateNames.compactMap { name in
            guard let path = Bundle.main.path(forResource: name, ofType: "cer") else {
                return nil
            }
            return try? Data(contentsOf: URL(fileURLWithPath: path))
        }
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Validate pinned certificates
        if validatePinnedCertificates(serverTrust: serverTrust) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    private func validatePinnedCertificates(serverTrust: SecTrust) -> Bool {
        // Compare server certificates with pinned certificates
        for index in 0..<SecTrustGetCertificateCount(serverTrust) {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, index) else {
                continue
            }

            let certData = SecCertificateCopyData(cert) as Data

            if pinnedCertificates.contains(certData) {
                return true
            }
        }

        return false
    }
}
```

### 3. AFNetworking AFSecurityPolicy

```objc
// AFNetworking SSL pinning implementation
#import <AFNetworking/AFNetworking.h>

AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];

// Load pinned certificates
NSData *certData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"certificate" ofType:@"cer"]];

// Configure security policy
AFSecurityPolicy *policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
[policy setPinnedCertificates:@[certData]];
[policy setAllowInvalidCertificates:NO];
[policy setValidatesDomainName:YES];

[manager setSecurityPolicy:policy];

// Make request
[manager GET:@"https://api.example.com/data" parameters:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
    NSLog(@"Request successful");
} failure:^(NSURLSessionDataTask *task, NSError *error) {
    NSLog(@"Request failed: %@", error);
}];
```

### 4. Alamofire ServerTrustEvaluating

```swift
// Alamofire SSL pinning with ServerTrustEvaluating
import Alamofire

class PinnedServerTrustEvaluator: ServerTrustEvaluating {
    private let pinnedCertificates: [SecCertificate]

    init(certificateNames: [String]) {
        self.pinnedCertificates = certificateNames.compactMap { name in
            guard let path = Bundle.main.path(forResource: name, ofType: "cer") else {
                return nil
            }
            guard let certData = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return nil
            }
            return SecCertificateCreateWithData(nil, certData as CFData)
        }
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        // Validate server certificate
        guard validatePinnedCertificates(trust: trust) else {
            throw AFError.serverTrustEvaluationFailed(reason: .certificatePinningFailed(host: host))
        }
    }

    private func validatePinnedCertificates(trust: SecTrust) -> Bool {
        // Check if any pinned certificate matches
        for pinnedCert in pinnedCertificates {
            if certificatesMatch(serverTrust: trust, pinnedCertificate: pinnedCert) {
                return true
            }
        }
        return false
    }

    private func certificatesMatch(serverTrust: SecTrust, pinnedCertificate: SecCertificate) -> Bool {
        // Compare certificates
        for index in 0..<SecTrustGetCertificateCount(serverTrust) {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, index) else {
                continue
            }

            if cert == pinnedCertificate {
                return true
            }
        }
        return false
    }
}

// Use custom evaluator
let evaluator = PinnedServerTrustEvaluator(certificateNames: ["api-certificate"])
let session = Session(serverTrustManager: .init(evaluators: ["api.example.com": evaluator]))
```

### 5. TrustKit

```swift
// TrustKit SSL pinning framework
import TrustKit

// Configure TrustKit
let trustKitConfig = [
    kTSKSwizzleNetworkDelegates: false,
    kTSKPinnedDomains: [
        "api.example.com": [
            kTSKEnforcePinning: true,
            kTSKIncludeSubdomains: true,
            kTSKPublicKeyHashes: [
                // HSHA256 hash of Subject Public Key Info
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // Backup key
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="   // Primary key
            ]
        ]
    ]
] as [String : Any]

TrustKit.initSharedInstance(withConfiguration: trustKitConfig)

// TrustKit automatically validates SSL pinning
// for all connections matching configured domains
```

---

## Manual Bypass Techniques

### 1. Binary Patching (Advanced)

```bash
# Disassemble binary to find SSL validation code
otool -tV Example.app/Example > disassembly.txt

# Find SSL validation functions
grep -i "SecTrust\|AFSecurityPolicy\|certificate" disassembly.txt

# Patch validation checks (NOT recommended for production)
# This requires:
# 1. Identifying validation code
# 2. Patching to always return success
# 3. Re-signing the binary

# Example: Patch SecTrustEvaluate to always return success
# Find: SecTrustEvaluate call
# Replace: Always set return value to 1 (success)

# Use tools:
# - Hopper Disassembler
# - IDA Pro
# - radare2
```

### 2. Certificate Replacement

```bash
# Extract app IPA
unzip -q Example.ipa -d Extracted

# Find embedded certificates
find Extracted -name "*.cer" -o -name "*.pem" -o -name "*.der"

# Replace with Burp CA certificate
cp /path/to/BurpCA.cer Extracted/Payload/Example.app/

# Repackage IPA
cd Extracted
zip -r ../Example_Patched.ipa Payload/

# Re-sign and install
codesign --force --sign "Your Certificate" Example_Patched.ipa

# Note: This only works if app reads certificates from bundle
# Some apps hardcode certificate data in binary
```

### 3. Network Level Bypass

```bash
# Use proxy to intercept and modify SSL handshake
# Tools:
# - Burp Suite (recommended)
# - OWASP ZAP
# - mitmproxy

# Method: SSL stripping (only for HTTP → HTTPS redirects)
# - Intercept HTTP request
# - Respond with HTTP (not HTTPS)
# - App may fall back to HTTP

# Note: This doesn't work for pure HTTPS connections
# and many modern apps have HSTS enabled
```

---

## Frida Script Bypass

### Generic SSL Pinning Bypass Script

```javascript
// ssl-pin-bypass.js - Generic iOS SSL pinning bypass
// Works for most common implementations

if (ObjC.available) {
    console.log("[*] Starting SSL pinning bypass");

    // Method 1: Hook SecTrustEvaluate
    var secMod = Process.findModuleByName('Security');
    var SecTrustEvaluate = secMod ? secMod.findExportByName('SecTrustEvaluate') : null;

    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                console.log("[+] Bypassing SecTrustEvaluate");
                retval.replace(0x1);  // kSecTrustResultProceed
            }
        });
    }

    // Method 2: Hook SecTrustEvaluateWithError (iOS 12+)
    var SecTrustEvaluateWithError = secMod ? secMod.findExportByName('SecTrustEvaluateWithError') : null;

    if (SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onEnter: function(args) {
                // args[1] is error pointer
                // Set error to nil (no error)
                args[1].writePointer(ptr(0));
            },
            onLeave: function(retval) {
                console.log("[+] Bypassing SecTrustEvaluateWithError");
                retval.replace(0x1);  // success
            }
        });
    }

    // Method 3: Hook AFSecurityPolicy
    if (ObjC.classes.AFSecurityPolicy) {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;

        // Hook evaluateServerTrust:forDomain:
        Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"], {
            onLeave: function(retval) {
                console.log("[+] Bypassing AFSecurityPolicy");
                retval.replace(ptr(0x1));
            }
        });

        // Hook pinnedCertificateMatchesServerTrust:
        Interceptor.attach(AFSecurityPolicy["- pinnedCertificateMatchesServerTrust:"], {
            onLeave: function(retval) {
                console.log("[+] Bypassing AFSecurityPolicy certificate match");
                retval.replace(ptr(0x1));
            }
        });
    }

    // Method 4: Hook Alamofire
    if (ObjC.classes.Alamofire) {
        console.log("[+] Alamofire detected");
        // Hook ServerTrustEvaluating protocol methods
    }

    // Method 5: Hook TrustKit
    if (ObjC.classes.TrustKit) {
        console.log("[+] TrustKit detected");
        var TrustKit = ObjC.classes.TrustKit;

        // Hook validation methods
        var evaluationMethods = [
            "- evaluateServerTrust:forDomain:",
            "- pinningValidator"
        ];

        evaluationMethods.forEach(function(method) {
            if (TrustKit[method]) {
                Interceptor.attach(TrustKit[method], {
                    onLeave: function(retval) {
                        console.log("[+] Bypassing TrustKit: " + method);
                        retval.replace(ptr(0x1));
                    }
                });
            }
        });
    }

    // Method 6: Hook NSURLSession delegate
    if (ObjC.classes.NSURLSession) {
        console.log("[+] NSURLSession detected");

        // Hook urlSession:didReceiveChallenge:completionHandler:
        // This requires finding the delegate implementation
    }

    console.log("[*] SSL pinning bypass hooks installed");
}
```

### Using the Script

```bash
# Save script as ssl-pin-bypass.js

# Run with Frida — attach to an already-running process
frida -U -l ssl-pinning-bypass-ios.js com.example.app

# Or spawn the app with the script attached from launch (note: -f spawns; the app resumes automatically in Frida 17)
frida -U -l ssl-pinning-bypass-ios.js -f com.example.app

# With Objection
objection -g com.example.app explore
ios sslpinning disable  # Objection's built-in bypass

# Load custom script in Objection
ios scripts load ssl-pin-bypass.js
```

---

## Objection Bypass

### Built-in SSL Pinning Bypass

```bash
# Start Objection session
objection -g com.example.app explore

# Run SSL pinning bypass
ios sslpinning disable

# Output:
# (root) iPhone (com.example.app) > ios sslpinning disable
# [+] SSL pinning bypass disabled for SecTrustEvaluateWithError
# [+] SSL pinning bypass disabled for NSURLSession
# [+] SSL pinning bypass disabled for AFSecurityPolicy
# [+] SSL pinning bypass disabled for WKWebView navigation delegate
# [+] SSL pinning bypass disabled for TrustKit
# [+] App Transport Security bypassed
# [+] Network Security Policy modified

# SSL pinning bypass is now active
```

### Verify Bypass

```bash
# Set up Burp Suite proxy
# 1. Open Burp Suite
# 2. Proxy > Options > Set listening interface (e.g., 8080)
# 3. Download Burp CA certificate

# Install Burp CA on iOS device
# 1. Open Safari on device
# 2. Navigate to http://burp
# 3. Download and install CA certificate
# 4. Settings > General > About > Certificate Trust Settings > Enable

# Configure device to use Burp proxy
# 1. Settings > WiFi > Tap (i) for connected network
# 2. Configure Proxy > Manual
# 3. Server: "<your computer IP>", Port: 8080

# Test network request in app
# If SSL pinning is bypassed, you'll see request in Burp Proxy > HTTP history
```

---

## Burp Suite Integration

### Setting Up Burp Proxy

```bash
# Step 1: Start Burp Suite
java -jar /Applications/Burp\ Suite.app/Contents/java/burpsuite.jar

# Step 2: Configure proxy listener
# Proxy > Options > Add
# - Binding: All interfaces
# - Port: 8080
# - Support invisible proxying: Enabled
# - Generate CA-signed per-host certificates: Disabled

# Step 3: Disable SSL in browser (for testing)
# Proxy > Options > Upstream Proxy Servers
# Add: http://localhost:8080 with SSL disabled
```

### Installing Burp CA Certificate

> **Simulator?** Skip Method 1/2 and use `xcrun simctl keychain booted add-root-cert <burp.der>` (auto-trusted, no UI). Full flow in `references/simulator-mitm-setup.md`.

```bash
# Method 1: Via Safari (recommended for physical devices)

# On iOS device:
# 1. Connect to same network as Burp
# 2. Set device to use Burp proxy (see above)
# 3. Open Safari
# 4. Navigate to: http://burp
# 5. Tap "CA Certificate"
# 6. Install profile

# Enable certificate trust:
# 1. Settings > General > About > Certificate Trust Settings
# 2. Find "PortSwigger CA" and enable it
# 3. Confirm you trust this certificate

# Method 2: Via USB (alternative)

# On host:
# scp /path/to/Burp_CA_Certificate.crt root@DEVICE_IP:/var/mobile/

# On device:
# security add-certificates /var/mobile/Burp_CA_Certificate.crt
```

### Verifying Proxy Works

```bash
# Test proxy with Safari
# 1. Open Safari on device
# 2. Navigate to https://example.com
# 3. Check Burp Proxy > HTTP history
# 4. Should see request and response

# Test with app
# 1. Run app on device
# 2. Trigger network request
# 3. Check Burp Proxy > HTTP history
# 4. If SSL pinning bypassed, you'll see HTTPS traffic

# Common issues:
# - Certificate not installed correctly
# - Certificate trust not enabled
# - SSL pinning not bypassed
# - Proxy configuration incorrect
```

---

## Certificate Installation

> **Working on the iOS Simulator?** The methods on this page (Safari + `mobileconfig`) target **physical devices**. The simulator uses a single `xcrun simctl keychain` command and has no manual trust toggle. See `references/simulator-mitm-setup.md` for the canonical simulator flow.

### Certificate Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| DER | .cer, .der | Binary format, iOS default |
| PEM | .pem | Base64 encoded |
| PKCS#12 | .p12, .pfx | Certificate + private key |
| CRT | .crt | Text or binary |

### Converting Certificates

```bash
# Convert PEM to DER
openssl x509 -inform PEM -outform DER -in cert.pem -out cert.cer

# Convert DER to PEM
openssl x509 -inform DER -outform PEM -in cert.cer -out cert.pem

# Extract certificate from PKCS#12
openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem

# Verify certificate
openssl x509 -in cert.cer -text -noout
```

### Installing Custom Certificates

```bash
# Method 1: Safari (simplest)

# On iOS device:
# 1. Serve certificate file via HTTP server
python3 -m http.server 8000  # On host

# 2. Open Safari on device
# 3. Navigate to http://"<host-ip>":8000/cert.cer
# 4. iOS will prompt to install profile
# 5. Install profile

# 6. Enable trust
# Settings > General > About > Certificate Trust Settings
# Enable the certificate

# Method 2: Configuration Profile

# Create configuration profile (mobileconfig)
cat > cert.mobileconfig << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <dict>
        <key>URL</key>
        <string>http://<host-ip>:8000/cert.cer</string>
    </dict>
    <key>PayloadDisplayName</key>
    <string>Custom Certificate</string>
    <key>PayloadIdentifier</key>
    <string>com.example.cert</string>
    <key>PayloadType</key>
    <string>com.apple.security.root</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789012</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

# Serve and install via Safari
```

---

## Testing Methodology

### SSL Pinning Testing Checklist

```markdown
# SSL Pinning Testing Checklist

## Pre-Testing Setup
- [ ] Jailbroken device or emulator
- [ ] Frida server installed
- [ ] Burp Suite configured
- [ ] CA certificate installed
- [ ] Device proxy configured
- [ ] App installed on device

## Testing Steps

### 1. Baseline Test (No Bypass)
- [ ] Try to intercept HTTPS traffic
- [ ] Verify SSL pinning is active (connection fails)
- [ ] Document error messages

### 2. Frida Bypass Test
- [ ] Load generic Frida bypass script
- [ ] Try to intercept HTTPS traffic
- [ ] Verify bypass success
- [ ] Document bypass method

### 3. Objection Bypass Test
- [ ] Use Objection SSL pinning disable
- [ ] Try to intercept HTTPS traffic
- [ ] Verify bypass success
- [ ] Document bypass method

### 4. Framework-Specific Tests
- [ ] Test AFNetworking implementation
- [ ] Test Alamofire implementation
- [ ] Test TrustKit implementation
- [ ] Test NSURLSession delegate
- [ ] Test SecTrustEvaluateWithError

### 5. Certificate Rotation Test
- [ ] Test with rotated server certificate
- [ ] Verify app handles rotation correctly
- [ ] Check for backup certificate support

### 6. Fallback Test
- [ ] Test with invalid certificate
- [ ] Verify proper error handling
- [ ] Check for fallback mechanisms

### 7. Performance Test
- [ ] Measure connection time
- [ ] Compare with pinning disabled
- [ ] Check for performance impact
```

### Automated Testing Script

```bash
#!/bin/bash
# ssl-pinning-test.sh - Automated SSL pinning testing

APP_BUNDLE_ID="com.example.app"
BURP_PROXY_IP="192.168.1.100"
BURP_PROXY_PORT="8080"

echo "[*] Starting SSL pinning test for $APP_BUNDLE_ID"

# Step 1: Configure device proxy
echo "[*] Configuring device proxy..."
# (Use device settings or mobileconfig)

# Step 2: Test without bypass
echo "[*] Testing without bypass (should fail)..."
# Open app and trigger request

# Step 3: Test with Frida bypass
echo "[*] Testing with Frida bypass..."
frida -U -l ssl-pinning-bypass-ios.js -f $APP_BUNDLE_ID &
sleep 5

# Open app and trigger request
# Check Burp for traffic

# Step 4: Test with Objection bypass
echo "[*] Testing with Objection bypass..."
objection -g $APP_BUNDLE_ID explore -s "ios sslpinning disable"

# Open app and trigger request
# Check Burp for traffic

echo "[*] Test complete"
```

---

## Advanced Bypass Scenarios

### Certificate Pinning with Public Key

```javascript
// Bypass public key pinning
// Public key pinning is harder to bypass than certificate pinning

// Method: Hook SecTrustSetPolicies to remove pinning
var secMod = Process.findModuleByName('Security');
var SecTrustSetPolicies = secMod ? secMod.findExportByName('SecTrustSetPolicies') : null;

if (SecTrustSetPolicies) {
    Interceptor.attach(SecTrustSetPolicies, {
        onEnter: function(args) {
            // args[0]: SecTrustRef
            // args[1]: SecPolicyRef

            // Don't set pinning policy
            console.log("[+] Intercepted SecTrustSetPolicies");
        }
    });
}

// Method: Hook SecTrustCopyPublicKey
var SecTrustCopyPublicKey = secMod ? secMod.findExportByName('SecTrustCopyPublicKey') : null;

if (SecTrustCopyPublicKey) {
    Interceptor.attach(SecTrustCopyPublicKey, {
        onLeave: function(retval) {
            // Return pinned public key instead of server's
            console.log("[+] Intercepted SecTrustCopyPublicKey");
        }
    });
}
```

### Multiple Pinning Layers

```javascript
// Bypass apps with multiple pinning implementations

// Example: App uses both AFNetworking and TrustKit
// Need to bypass both

// AFNetworking bypass
if (ObjC.classes.AFSecurityPolicy) {
    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"], {
        onLeave: function(retval) {
            retval.replace(ptr(0x1));
        }
    });
}

// TrustKit bypass
if (ObjC.classes.TrustKit) {
    var TrustKit = ObjC.classes.TrustKit;
    Interceptor.attach(TrustKit["- evaluateServerTrust:forDomain:"], {
        onLeave: function(retval) {
            retval.replace(ptr(0x1));
        }
    });
}

// NSURLSession bypass
// Hook delegate methods
```

### Dynamic Certificate Loading

```javascript
// Bypass apps that load certificates dynamically

// Hook certificate loading methods
var secMod = Process.findModuleByName('Security');
var SecCertificateCreateWithData = secMod ? secMod.findExportByName('SecCertificateCreateWithData') : null;

if (SecCertificateCreateWithData) {
    Interceptor.attach(SecCertificateCreateWithData, {
        onEnter: function(args) {
            var certData = ObjC.Object(args[1]);
            console.log("[+] Certificate loaded: " + certData);
        },
        onLeave: function(retval) {
            // Could replace with Burp CA certificate
            console.log("[+] Certificate created");
        }
    });
}

// Hook NSData reading (if certificates loaded from files)
if (ObjC.classes.NSData) {
    var NSData = ObjC.classes.NSData;
    Interceptor.attach(NSData["+ dataWithContentsOfFile:"], {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]);
            console.log("[+] Reading file: " + path);
        }
    });
}
```

---

## Remediation and Best Practices

### Implementing SSL Pinning Correctly

```swift
// Best practices for SSL pinning

// 1. Use public key pinning (more flexible)
// 2. Include backup keys for rotation
// 3. Implement proper error handling
// 4. Add certificate transparency
// 5. Monitor pinning failures
// 6. Have a fallback mechanism (with logging)
// 7. Rotate certificates regularly
// 8. Test certificate rotation thoroughly

// Example: Secure public key pinning implementation
func configureServerTrustPinning() {
    let publicKeys: [String] = [
        // Primary key hash (SHA256 of SPKI)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        // Backup key hash
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    ]

    let config = [
        kTSKEnforcePinning: true,
        kTSKIncludeSubdomains: false,
        kTSKPublicKeyHashes: publicKeys,
        kTSKReportUris: ["https://report.example.com"]
    ] as [String : Any]
}
```

### Common Mistakes to Avoid

```swift
// ❌ BAD: Pinning to root CA (too broad)
// ❌ BAD: No backup keys (rotation issues)
// ❌ BAD: Hardcoding certificate data in binary (cannot update)
// ❌ BAD: Allowing any certificate (no validation)
// ❌ BAD: Silent failures (no error logging)
// ❌ BAD: No fallback mechanism (app unusable on rotation)
// ❌ BAD: Pinning to expired certificates
// ❌ BAD: Not handling certificate expiration

// ✅ GOOD: Pin to leaf or intermediate CA
// ✅ GOOD: Include backup keys
// ✅ GOOD: Load certificates from bundle (can update)
// ✅ GOOD: Validate certificate chain
// ✅ GOOD: Log pinning failures
// ✅ GOOD: Implement fallback with warnings
// ✅ GOOD: Monitor certificate expiration
// ✅ GOOD: Implement certificate transparency
```

---

## Advanced Bypass Scenarios (Extended)

### SSL Kill Switch 2 (Cydia Substrate)

SSL Kill Switch 2 is a Cydia Substrate tweak that patches low-level SSL/TLS functions system-wide, disabling certificate validation including pinning in all iOS applications.

#### Installation (Jailbroken Device)

```bash
# Download SSLKillSwitch2 deb from:
# https://github.com/nabla-c0d3/ssl-kill-switch2/releases

# Copy to device via SSH
scp SSLKillSwitch2.deb root@"<device_ip>":/private/

# Install via SSH
ssh root@"<device_ip>"
dpkg -i SSLKillSwitch2.deb
killall -HUP SpringBoard
```

#### Configuration

SSL Kill Switch creates a Settings menu where you can:
- Enable/disable the SSL validation bypass globally
- Exclude specific apps (e.g., Charles Proxy) from bypass

#### Intercepting App Store Traffic

SSL Kill Switch can intercept Apple App Store traffic. See: http://nabla-c0d3.github.io/blog/2013/08/20/intercepting-the-app-stores-traffic-on-ios/

#### Excluding Apps from Bypass

When using Charles Proxy, add it to excluded bundle IDs in SSL Kill Switch config:
- Bundle ID: `com.xk72.Charles`

### Hotspot Method (Flutter & Xamarin)

Flutter and Xamarin apps don't respect system proxy settings. The hotspot method routes traffic through a MacBook Wi-Fi access point.

#### Setup Requirements

- Two mobile devices (one for Bluetooth tethering, one for testing)
- Jailbroken or non-jailbroken iOS device
- MacBook with Wi-Fi

#### Step-by-Step

1. **Configure Bluetooth Tethering on iPhone**:
   - Enable Mobile Data
   - Enable Bluetooth and connect to MacBook
   - Turn on Bluetooth tethering in Settings

2. **Share MacBook Internet via Wi-Fi**:
   - System Preferences → Sharing → Internet Sharing
   - Share from: Bluetooth PAN
   - To computers using: Wi-Fi

3. **Connect iPhone to MacBook Wi-Fi**:
   - iPhone → Wi-Fi → Connect to MacBook's network

4. **Configure pf Rules for Traffic Forwarding**:
   ```bash
   # Create /etc/pf.rules
   rdr pass on bridge100 inet proto tcp from any to any -> 127.0.0.1 port 8080
   
   # Apply rules
   sudo pfctl -f /etc/pf.rules
   sudo sysctl -w net.inet.ip.forwarding=1
   ```

5. **Enable Invisible Proxy in Burp Suite**:
   - Proxy → Options → Edit → Request Handling
   - Enable "Support invisible proxy"

### Certificate Replacement

#### Finding Hardcoded Certificates

```bash
# Extract IPA
unzip app.ipa -d extracted/
cd extracted/Payload/AppName.app/

# Search for certificate files
find . -name "*.cer" -o -name "*.pem" -o -name "*.der" -o -name "*.cert"

# Search for certificates in binary
strings AppName | grep -i "BEGIN CERTIFICATE"

# Search for certificate patterns in binary
otool -s __TEXT __cstring AppName | grep -i certificate
```

#### Replacement Process

```bash
# Copy Burp CA certificate to payload
cp ~/Downloads/BurpCA.cer ./Certificate.cer

# Repackage IPA
zip -r ../app-patched.ipa Payload/
```

### Hash Replacement (Cordova Apps)

Cordova apps often pin certificate SHA256 hashes in config files.

#### Finding Hash Locations

Common locations:
- `www/pinning/pinning.json`
- `www/js/pinning.js`
- `config.xml`

#### Generating Burp Certificate Hash

```bash
# Convert DER to PEM
openssl x509 -inform DER -in cacert.cer -out cacert.pem

# Extract public key and calculate SHA256
openssl x509 -in cacert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

#### Replacing Hash

```bash
# Edit the pinning config file
vim www/pinning/pinning.json

# Replace hash value and repackage
zip -r ../app-patched.ipa Payload/
```

### MITM Proxy Chain (mitmproxy + Burp)

When direct Burp proxying fails, chain mitmproxy with Burp Suite.

#### Setup

```bash
# Install mitmproxy
brew install mitmproxy

# Start mitmweb (browser-based interface)
mitmweb --listen-port 8081 --web-port 8082

# Configure mitmproxy to forward to Burp
# Add to ~/.mitmproxy/mitmproxy.conf:
mode upstream:http://127.0.0.1:8080
ssl_insecure: true
```

#### Certificate Installation

```bash
# Start mitmproxy once to generate certificates
mitmdump

# On iOS device, visit mitm.it to download certificate
# Settings → Install Profile → Certificate Trust Settings → Enable mitmproxy
```

### Info.plist Modification

Some apps store pinning configuration in Info.plist.

#### Keys to Modify

| Key | Type | Effect |
|-----|------|--------|
| `TSKEnforcePinning` | Boolean | Enforce SSL pinning |
| `NSRequiresCertificateTransparency` | Boolean | Require certificate transparency |

#### Modification Process

```bash
# Extract and decompress plist
plutil -convert xml1 Info.plist

# Edit values
# Change <true/> to <false/> for targeted keys

# Repackage and resign
zip -r ../app-patched.ipa Payload/
codesign -f -s "iPhone Distribution: Team" app-patched.ipa
```

### Detection Bypass Order

When bypassing SSL pinning, try techniques in this order:

1. **Objection** (simplest, no device modification)
2. **Frida scripts** (most flexible, per-app)
3. **SSL Kill Switch 2** (system-wide, all apps)
4. **Certificate replacement** (when pinning is file-based)
5. **Hotspot method** (for Flutter/Xamarin)
6. **MITM chain** (when direct proxy fails)

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | SSL Pinning Context |
|---------------|-------|---------------------|
| MASTG-TEST-0060 | Network Communication Testing | SSL pinning verification |
| MASTG-APP-SEC-0020 | Communication Security | Pinning implementation |
| MASTG-APP-SEC-0030 | Cryptographic Verification | Certificate validation |
| MASTG-TEST-0050 | Cryptography Testing | Certificate analysis |
| MASTG-TEST-0061 | Testing Network Communication | SSL/TLS configuration |
| MASTG-APP-0050 | App Transport Security | ATS bypass techniques |

---

## Simulator vs Physical Device

The certificate installation methods described above (Safari + `mobileconfig`) target **physical devices**. When running against the **iOS Simulator**, the flow is materially different and shorter — a single `xcrun simctl keychain booted add-root-cert <cert>` call writes the CA into the simulator's System keychain with auto-trust, and the proxy host is the host's loopback (`127.0.0.1`) rather than its LAN IP.

> **Canonical flow for the simulator**: see `references/simulator-mitm-setup.md`. That guide covers the full pipeline (cert export, `add-root-cert`, proxy configuration, headless env-var launch, transparent-pf fallback, tool-specific notes for Burp/Charles/mitmproxy/ZAP/Proxyman) and is the only place that flow is documented in detail.

Quick reference:

| Concern | Physical device | Simulator |
|---|---|---|
| CA install | Settings → VPN & Device Management → Install profile | `xcrun simctl keychain booted add-root-cert <cert>` |
| Full-trust toggle | Settings → About → Certificate Trust Settings | **Not required** (auto-trusted) |
| Proxy host | Mac's LAN IP (e.g. `192.168.1.100`) | `127.0.0.1` |
| SSL pinning bypass | Frida / Objection on device | Frida / Objection on simulator (SimForge-injected Frida Gadget is the most common path — see `references/simforge-ios-testing.md`) |

When combining SSL pinning bypass with the simulator workflow, the typical stack is:

1. **SimForge** converts the arm64 app for the simulator and injects Frida Gadget (no jailbreak needed).
2. **`xcrun simctl keychain booted add-root-cert`** trusts the proxy CA.
3. **Frida `ssl-pinning-bypass-ios.js`** neutralizes in-app pin checks.
4. **`SIMCTL_CHILD_HTTP(S)_PROXY`** env vars route the app's traffic through Burp/Charles on the host's loopback.

---

## Summary

This guide covered:
- SSL pinning fundamentals and types
- iOS SSL pinning implementations (NSURLSession, AFNetworking, Alamofire, TrustKit)
- Manual bypass techniques (binary patching, certificate replacement)
- Frida script bypass for common implementations
- Objection's built-in SSL pinning disable command
- **8 additional bypass techniques**:
  1. SSL Kill Switch 2 (Cydia Substrate)
  2. Hotspot method (Flutter & Xamarin)
  3. Certificate replacement (hardcoded .cer/.pem files)
  4. Hash replacement (SHA256 pinning in Cordova)
  5. MITM proxy chaining (mitmproxy + Burp)
  6. Info.plist modification
  7. Frida scripts (generic and framework-specific)
  8. Objection (automated Frida-based bypass)
- Burp Suite integration for HTTPS interception
- Certificate installation methods
- Comprehensive testing methodology
- Advanced bypass scenarios
- Remediation and best practices

SSL pinning is a critical security control for iOS applications. Proper implementation requires careful consideration of certificate rotation, error handling, and fallback mechanisms. Testing SSL pinning bypasses helps validate the effectiveness of the implementation.

---

## References

### Official Documentation
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/
- Apple Security Framework: https://developer.apple.com/documentation/security
- AFNetworking: https://github.com/AFNetworking/AFNetworking
- Alamofire: https://github.com/Alamofire/Alamofire
- TrustKit: https://github.com/datatheorem/TrustKit
- SSL Kill Switch 2: https://github.com/nabla-c0d3/ssl-kill-switch2

### Additional Resources
- Frida Documentation: https://frida.re/docs/
- Objection GitHub: https://github.com/sensepost/objection
- Burp Suite Documentation: https://portswigger.net/burp/documentation
- Certificate Pinning Best Practices: https://developer.apple.com/news/
- Appknox SSL Pinning Bypass Guide: https://www.appknox.com/blog/bypass-ssl-pinning-in-ios-app
- Guardsquare SSL Pinning Analysis: https://www.guardsquare.com/blog/ios-ssl-certificate-pinning-bypassing

### Frida Scripts
- SSL Kill Switch 2: Blackbox tool for system-wide SSL validation bypass
- TrustKit bypass: Hook `-[TSKPinningValidator evaluateTrust:forHostname:]`
- NSURLSession bypass: Hook delegate authentication methods
- AFNetworking bypass: Hook `evaluateServerTrust:forDomain:`

---

**Document Version:** 2.0
**Last Updated:** April 2026
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** Jailbroken iOS device, Frida server, Burp Suite, basic iOS development knowledge
**New in v2.0:** 8 additional bypass techniques from Appknox and Guardsquare writeups
