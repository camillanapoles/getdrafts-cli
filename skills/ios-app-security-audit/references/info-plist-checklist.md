# Info.plist Security Checklist

**Complete security audit checklist for iOS app Info.plist analysis.**

## Table of Contents

1. [Overview](#1-overview)
2. [Security-Relevant Keys](#2-security-relevant-keys)
3. [URL Schemes](#3-url-schemes-cfbundleurlschemes)
4. [App Transport Security](#4-app-transport-security-nsapptransportsecurity)
5. [Background Modes](#5-background-modes-uibackgroundmodes)
6. [Privacy Descriptions](#6-privacy-descriptions)
7. [File Sharing](#7-file-sharing-uifilesharingenabled)
8. [App Tracking Transparency](#8-app-tracking-transparency)
9. [Biometric Authentication](#9-biometric-authentication)
10. [Siri Integration](#10-siri-integration)
11. [Other Security Keys](#11-other-security-keys)

---

## 1. Overview

### What is Info.plist?

The Info.plist file is the primary configuration file for iOS apps. It contains metadata about the app, its capabilities, permissions, and security settings.

### Why Security Audit Info.plist?

- **Exposes sensitive app configuration** - reveals app capabilities, URL schemes, and background modes
- **Controls app behavior** - ATS, file sharing, and privacy settings are defined here
- **Indicates security posture** - misconfigurations can lead to vulnerabilities like deep link hijacking, MITM attacks, and data leakage

### How to Extract Info.plist

```bash
# From IPA
unzip -q target.ipa "Payload/*.app/Info.plist"
cp Payload/*.app/Info.plist Info.plist

# From device
ssh root@"<device-ip>" "cat /var/mobile/Containers/Bundle/Application/*/target.app/Info.plist" > Info.plist

# Convert binary plist to XML
plutil -convert xml1 Info.plist

# Verify format
plutil -lint Info.plist
```

---

## 2. Security-Relevant Keys

### Critical Security Keys Overview

| Key | Risk Level | Category | OWASP MASTG Reference |
|-----|------------|----------|----------------------|
| `CFBundleURLSchemes` | Critical | Deep Link Hijacking | MASTG-TEST-0140 |
| `NSAppTransportSecurity` | Critical | Network Security | MASTG-TEST-0215 |
| `UIFileSharingEnabled` | High | Data Leakage | MASTG-TEST-0035 |
| `NSAllowsArbitraryLoads` | Critical | Network Security | MASTG-TEST-0215 |
| `UIBackgroundModes` | Medium | Privacy | MASTG-TEST-0020 |
| `LSSupportsOpeningDocumentsInPlace` | Medium | File Access | MASTG-TEST-0035 |
| `NSUserTrackingUsageDescription` | Medium | Privacy | MASTG-TEST-0038 |
| `NSFaceIDUsageDescription` | Medium | Authentication | MASTG-TEST-0088 |

---

## 3. URL Schemes (CFBundleURLSchemes)

### What It Does

Defines custom URL schemes that the app can handle. Other apps can open your app using these schemes (e.g., `myapp://`).

### Security Risk

**Deep link hijacking**: Malicious apps can register conflicting schemes or exploit vulnerable deep link handlers to perform unauthorized actions, steal data, or redirect users.

### Detection

```bash
# Extract URL schemes from Info.plist
plutil -extract CFBundleURLTypes raw Info.plist

# Or use plutil -p for formatted output
plutil -p Info.plist | grep -A 10 "CFBundleURLSchemes"

# Check for specific schemes
plutil -p Info.plist | grep "http\|https\|file\|itms\|itms-apps\|mailto\|tel"
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Generic Schemes | **CRITICAL** | Schemes like `http://`, `https://`, `file://` | Never use generic schemes; use unique app-specific schemes |
| Duplicate Schemes | **HIGH** | Same scheme across multiple apps | Ensure uniqueness; use reverse-DNS naming |
| Sensitive Schemes | **HIGH** | `itms://`, `itms-apps://`, `sms://`, `tel://` | Avoid App Store scheme abuse; validate all inputs |
| Missing Validation | **CRITICAL** | URL schemes defined but no input validation in app code | Implement deep link validation in application(_:open:options:) |
| Unprotected Schemes | **HIGH** | URL schemes accessible from any app | Use `LSApplicationQueriesSchemes` to declare schemes you query; validate origin |

### Common Vulnerable Patterns

#### Pattern 1: Generic URL Scheme

```xml
<!-- VULNERABLE: Generic scheme -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>http</string>  <!-- CRITICAL: Can hijack all http:// links -->
        </array>
    </dict>
</array>

<!-- SECURE: App-specific scheme -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>com.mycompany.myapp</string>  <!-- UNIQUE -->
        </array>
    </dict>
</array>
```

#### Pattern 2: Missing Input Validation

```swift
// VULNERABLE: No validation of URL parameters
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    let path = url.path  // Directly used without validation
    let query = url.query  // Not sanitized

    // Exploitable: Path traversal, XSS, or command injection
    loadContent(at: path, with: query)
    return true
}

// SECURE: Validate and sanitize
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    // Whitelist allowed paths
    let allowedPaths = ["/home", "/profile", "/settings"]

    guard let path = url.path, allowedPaths.contains(path) else {
        return false
    }

    // Sanitize query parameters
    guard let query = url.query?.components(separatedBy: "&") else {
        return false
    }

    for param in query {
        guard param.range(of: "^[a-zA-Z0-9_]+$", options: .regularExpression) != nil else {
            return false
        }
    }

    loadContent(at: path, with: query)
    return true
}
```

### Test Cases

```bash
# Test deep link hijacking
# Create malicious app with conflicting scheme
xcrun simctl install booted MaliciousApp.app
xcrun simctl launch booted com.malicious.app

# Test path traversal
xcrun simctl openurl booted "myapp://../../../etc/passwd"

# Test XSS via URL parameters
xcrun simctl openurl booted "myapp://home?data=<script>alert('XSS')</script>"

# Test command injection
xcrun simctl openurl booted "myapp://execute?command=rm%20-rf%20/"
```

### OWASP MASTG Reference

- **MASTG-TEST-0140**: Test for Improper Platform Usage (URL Schemes)
- **MASTG-TEST-0047**: Test for Deep Link Hijacking

---

## 4. App Transport Security (NSAppTransportSecurity)

### What It Does

Enforces secure network connections (HTTPS) and prevents cleartext HTTP traffic.

### Security Risk

**MITM attacks**: Disabled or misconfigured ATS allows cleartext HTTP, making the app vulnerable to man-in-the-middle attacks, credential interception, and data tampering.

### Detection

```bash
# Check ATS configuration
plutil -p Info.plist | grep -A 20 "NSAppTransportSecurity"

# Check for arbitrary loads (CRITICAL)
plutil -p Info.plist | grep "NSAllowsArbitraryLoads"

# Check for domain exceptions
plutil -p Info.plist | grep -A 5 "NSExceptionDomains"

# Check TLS version
plutil -p Info.plist | grep "NSMinimumTLSVersion"
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| `NSAllowsArbitraryLoads = true` | **CRITICAL** | Allows all cleartext HTTP | Set to `false` or remove key |
| `NSAllowsArbitraryLoadsInWebContent` | **HIGH** | Allows HTTP in WebView | Restrict to specific domains only |
| `NSAllowsLocalNetworking` | **MEDIUM** | Allows HTTP to localhost | Acceptable for debugging only |
| Missing `NSExceptionDomains` | **LOW** | No domain exceptions defined | Not an issue if `NSAllowsArbitraryLoads = false` |
| Weak TLS Version | **MEDIUM** | `TLSv1.0` or `TLSv1.1` | Require `TLSv1.2` or higher |
| Missing `NSMinimumTLSVersion` | **MEDIUM** | TLS version not specified | Explicitly set to `TLSv1.2` or higher |

### Common Vulnerable Patterns

#### Pattern 1: Completely Disabled ATS

```xml
<!-- VULNERABLE: ATS completely disabled -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- CRITICAL: Allows all HTTP traffic -->
</dict>

<!-- SECURE: ATS enabled with specific exceptions -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>

    <!-- Specific domain exception (use sparingly) -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSTemporaryExceptionMinimumTLSVersion</key>
            <string>TLSv1.1</string>
        </dict>
    </dict>
</dict>
```

#### Pattern 2: Weak TLS Configuration

```xml
<!-- VULNERABLE: Weak TLS version -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSMinimumTLSVersion</key>
    <string>TLSv1.0</string>  <!-- INSECURE: TLSv1.0 is deprecated -->
</dict>

<!-- SECURE: Strong TLS version -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSMinimumTLSVersion</key>
    <string>TLSv1.2</string>  <!-- SECURE: TLSv1.2 or higher -->
</dict>
```

#### Pattern 3: Permissive Domain Exceptions

```xml
<!-- VULNERABLE: Broad domain exception -->
<key>NSExceptionDomains</key>
<dict>
    <key>example.com</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
        <key>NSIncludesSubdomains</key>
        <true/>  <!-- INSECURE: Applies to all subdomains -->
    </dict>
</dict>

<!-- SECURE: Restrictive domain exception -->
<key>NSExceptionDomains</key>
<dict>
    <key>legacy.example.com</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
        <key>NSIncludesSubdomains</key>
        <false/>  <!-- SECURE: Only this specific subdomain -->
        <key>NSExceptionMinimumTLSVersion</key>
        <string>TLSv1.2</string>
    </dict>
</dict>
```

### Testing

```bash
# Test for cleartext HTTP
tcpdump -i any -w capture.pcap 'port 80 and host api.example.com'

# Analyze capture
tcpdump -r capture.pcap -A

# Use Burp Suite to intercept
# Configure device proxy to Burp (127.0.0.1:8080)
# Observe if HTTP traffic is sent in cleartext
```

### OWASP MASTG Reference

- **MASTG-TEST-0215**: Test for Network Communication Issues
- **MASTG-TEST-0216**: Test for SSL/TLS Issues

---

## 5. Background Modes (UIBackgroundModes)

### What It Does

Allows app to continue running in the background for specific purposes (audio, location updates, downloads, etc.).

### Security Risk

**Privacy & battery drain**: Improperly used background modes can lead to unauthorized data collection, location tracking without user knowledge, and excessive battery consumption.

### Detection

```bash
# Check background modes
plutil -p Info.plist | grep -A 20 "UIBackgroundModes"

# List all enabled modes
plutil -p Info.plist | grep -B 5 -A 15 "UIBackgroundModes"
```

### Security Checks

| Mode | Risk Level | Security Implications | Remediation |
|------|------------|----------------------|-------------|
| `audio` | **LOW** | Audio playback continues in background | Document purpose in privacy policy |
| `location` | **HIGH** | Location tracking while app not visible | Require user consent; minimize data collection |
| `voip` | **MEDIUM** | Network calls persist in background | Use PushKit instead where possible |
| `fetch` | **MEDIUM** | Periodic background data fetching | Limit frequency and data collected |
| `processing` | **MEDIUM** | Background processing tasks | Ensure tasks are necessary and efficient |
| `remote-notification` | **LOW** | Silent push notifications | Acceptable for legitimate use |
| `bluetooth-central` | **HIGH** | Bluetooth scanning while background | Document purpose; limit scan duration |
| `bluetooth-peripheral` | **MEDIUM** | Bluetooth advertising in background | Document purpose; limit advertising duration |
| `external-accessory` | **LOW** | MFi accessory communication | Acceptable with user notification |
| `newsstand-download` | **LOW** | Newsstand content download | Acceptable for news apps |

### Common Vulnerable Patterns

#### Pattern 1: Excessive Background Modes

```xml
<!-- VULNERABLE: Too many background modes -->
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
    <string>location</string>
    <string>fetch</string>
    <string>processing</string>
    <string>bluetooth-central</string>
    <string>remote-notification</string>
    <!-- Too many modes may indicate privacy violations -->
</array>

<!-- SECURE: Only necessary modes -->
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
    <!-- Only what the app actually needs -->
</array>
```

#### Pattern 2: Location Tracking Without Clear Purpose

```swift
// VULNERABLE: Continuous location tracking in background
locationManager.startUpdatingLocation()
// Runs indefinitely in background

// SECURE: Significant location changes (privacy-friendly)
locationManager.startMonitoringSignificantLocationChanges()
// Only triggers when user moves 500m or more
```

### Testing

```bash
# Monitor background location updates
# 1. Open app and enable location
# 2. Put app in background (home button)
# 3. Monitor for location updates via Frida
frida -U -f com.example.app -l location-spoofing-ios.js

# Monitor background network activity
# 1. Enable background fetch mode
# 2. Put app in background
# 3. Monitor network traffic with Burp or tcpdump
tcpdump -i any -w capture.pcap 'host api.example.com'
```

### OWASP MASTG Reference

- **MASTG-TEST-0020**: Test for Improper Platform Usage (Background Modes)
- **MASTG-TEST-0038**: Test for Privacy Violations

---

## 6. Privacy Descriptions

### What It Does

Provides user-facing descriptions for why the app needs access to sensitive data (camera, microphone, location, contacts, etc.).

### Security Risk

**Privacy violations**: Missing or vague descriptions can lead to user distrust, regulatory violations (GDPR, CCPA), and potential app store rejection.

### Detection

```bash
# Check all privacy usage descriptions
plutil -p Info.plist | grep "UsageDescription"

# Check specific descriptions
plutil -p Info.plist | grep "NSCameraUsageDescription"
plutil -p Info.plist | grep "NSMicrophoneUsageDescription"
plutil -p Info.plist | grep "NSLocationWhenInUseUsageDescription"
```

### Required Privacy Descriptions

| Key | Risk Level | Description Required | When Needed |
|-----|------------|---------------------|-------------|
| `NSCameraUsageDescription` | **HIGH** | Why camera access is needed | When app uses camera |
| `NSMicrophoneUsageDescription` | **HIGH** | Why microphone access is needed | When app records audio |
| `NSLocationWhenInUseUsageDescription` | **HIGH** | Why location access is needed while app is in use | When app accesses location |
| `NSLocationAlwaysAndWhenInUseUsageDescription` | **CRITICAL** | Why location access is needed even when app is not in use | When app tracks location in background |
| `NSLocationAlwaysUsageDescription` | **CRITICAL** | Deprecated but may be present | Legacy apps |
| `NSContactsUsageDescription` | **HIGH** | Why contacts access is needed | When app reads contacts |
| `NSPhotoLibraryUsageDescription` | **HIGH** | Why photo library access is needed | When app accesses photos |
| `NSPhotoLibraryAddUsageDescription` | **MEDIUM** | Why app needs to save photos | When app saves photos |
| `NSCalendarsUsageDescription` | **MEDIUM** | Why calendar access is needed | When app reads calendar |
| `NSRemindersUsageDescription` | **MEDIUM** | Why reminders access is needed | When app reads reminders |
| `NSFaceIDUsageDescription` | **HIGH** | Why Face ID is needed | When app uses biometric authentication |
| `NSUserTrackingUsageDescription` | **HIGH** | Why app tracks user across other apps | When app uses App Tracking Transparency |
| `NSSiriUsageDescription` | **MEDIUM** | Why Siri integration is needed | When app uses Siri |
| `NSBluetoothAlwaysUsageDescription` | **HIGH** | Why Bluetooth access is needed | When app uses Bluetooth |

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Missing description | **CRITICAL** | Usage key present but no description | Add clear, specific description |
| Vague description | **HIGH** | Generic text like "needed for app functionality" | Provide specific, user-friendly explanation |
| Proportionality violation | **MEDIUM** | Description doesn't match actual use | Ensure description accurately reflects use case |
| Location always without justification | **CRITICAL** | `NSLocationAlwaysAndWhenInUseUsageDescription` without clear need | Use "when in use" unless absolutely necessary |
| Biometric without fallback | **MEDIUM** | Face ID/Touch ID without passcode option | Provide alternative authentication method |

### Common Vulnerable Patterns

#### Pattern 1: Missing Description

```xml
<!-- VULNERABLE: No description -->
<key>NSCameraUsageDescription</key>
<string></string>  <!-- EMPTY: App will crash on iOS 10+ -->

<!-- SECURE: Clear description -->
<key>NSCameraUsageDescription</key>
<string>We need camera access to scan QR codes and take profile photos.</string>
```

#### Pattern 2: Vague Description

```xml
<!-- VULNERABLE: Generic description -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>App needs location access to work properly.</string>

<!-- SECURE: Specific description -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>We need your location to show nearby restaurants and provide directions.</string>
```

### Testing

```bash
# Test permission request flow
# 1. Reinstall app (clear all permissions)
# 2. Launch app
# 3. Trigger permission request
# 4. Verify description is displayed correctly

# Test permission denial behavior
# 1. Deny permission in system settings
# 2. Try to use feature requiring permission
# 3. Verify app handles denial gracefully (no crashes)
```

### OWASP MASTG Reference

- **MASTG-TEST-0038**: Test for Privacy Violations
- **MASTG-TEST-0039**: Test for Permissions and Data Access

---

## 7. File Sharing (UIFileSharingEnabled)

### What It Does

Allows the app's documents directory to be accessed via iTunes file sharing or the Files app.

### Security Risk

**Data leakage**: Enabled file sharing exposes app documents to external access, potentially allowing unauthorized data extraction.

### Detection

```bash
# Check if file sharing is enabled
plutil -p Info.plist | grep "UIFileSharingEnabled"

# Check if in-place document opening is enabled
plutil -p Info.plist | grep "LSSupportsOpeningDocumentsInPlace"
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| `UIFileSharingEnabled = true` | **MEDIUM** | Documents directory accessible via iTunes | Ensure no sensitive data in documents directory |
| `LSSupportsOpeningDocumentsInPlace = true` | **MEDIUM** | Files app can open app documents | Ensure document validation on open |
| Both enabled | **HIGH** | Combined file access risk | Implement document access controls |
| Sensitive files in documents | **HIGH** | Encryption keys, user data, etc. in shared directory | Move sensitive data to app container |

### Common Vulnerable Patterns

#### Pattern 1: Enabled File Sharing with Sensitive Data

```xml
<!-- VULNERABLE: File sharing enabled -->
<key>UIFileSharingEnabled</key>
<true/>

<!-- App stores sensitive data in Documents directory -->
// In code:
let documentsPath = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
let keyPath = documentsPath + "/encryption_key.txt"
try? "secret_key_123".write(toFile: keyPath, atomically: true, encoding: .utf8)

<!-- SECURE: Disable file sharing or use secure storage -->
<key>UIFileSharingEnabled</key>
<false/>

// Use Keychain for sensitive data:
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "encryption_key",
    kSecValueData as String: "secret_key_123".data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

### Testing

```bash
# Test file sharing access
# 1. Enable file sharing in Info.plist
# 2. Install app on device
# 3. Connect to iTunes (macOS 10.14 or earlier) or use Finder
# 4. Navigate to Files → [App Name]
# 5. List and download files

# Test via iFunBox (third-party tool)
ifunbox install target.ipa
ifunbox browse Documents/

# Test on jailbroken device
ssh root@"<device-ip>" "ls -la /var/mobile/Containers/Data/Application/*/Documents/"
```

### OWASP MASTG Reference

- **MASTG-TEST-0035**: Test for Local Data Storage
- **MASTG-TEST-0036**: Test for Data Caching

---

## 8. App Tracking Transparency

### What It Does

Required by iOS 14.5+ for apps that track user activity across other apps and websites. Requires user consent.

### Security Risk

**Privacy violations**: Missing or improper implementation can lead to regulatory violations and app store rejection.

### Detection

```bash
# Check for tracking description
plutil -p Info.plist | grep "NSUserTrackingUsageDescription"

# Check if AppTrackingTransparency framework is used
codesign -d --entitlements - /path/to/app.app/ | grep "com.apple.developer.app-tracking-transparency"
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Missing description when tracking | **CRITICAL** | App uses tracking but no description | Add `NSUserTrackingUsageDescription` |
| Tracking without consent | **CRITICAL** | App tracks before obtaining consent | Implement proper ATT flow |
| Vague description | **HIGH** | Generic "needed for app functionality" | Provide clear explanation of tracking purpose |

### Common Vulnerable Patterns

#### Pattern 1: Tracking Without Consent

```swift
// VULNERABLE: Tracks before obtaining consent
import AppTrackingTransparency

func trackUser() {
    let trackingStatus = ATTrackingManager.trackingAuthorizationStatus
    if trackingStatus == .notDetermined {
        // Still tracks without asking!
        AdvertiserIdManager.shared.fetchAdvertiserId { id in
            print("Advertising ID: \(id)")
        }
    }
}

// SECURE: Request consent first
func requestTrackingAndTrack() {
    ATTrackingManager.requestTrackingAuthorization { status in
        switch status {
        case .authorized:
            AdvertiserIdManager.shared.fetchAdvertiserId { id in
                print("Advertising ID: \(id)")
            }
        default:
            print("Tracking denied")
        }
    }
}
```

### Testing

```bash
# Test ATT flow
# 1. Fresh install app
# 2. Navigate to screen that triggers tracking
# 3. Verify prompt appears: "Allow [App] to track your activity across other companies' apps and websites?"
# 4. Deny permission
# 5. Verify app respects denial (no tracking)

# Test on iOS 14.5+ device
# Before iOS 14.5, ATT not required
# After iOS 14.5, must have description
```

### OWASP MASTG Reference

- **MASTG-TEST-0038**: Test for Privacy Violations
- **MASTG-TEST-0040**: Test for Third-Party Tracking

---

## 9. Biometric Authentication

### What It Does

Provides Face ID or Touch ID authentication for app features. Requires user-facing description.

### Security Risk

**Authentication bypass**: Improper implementation can lead to authentication bypass, privacy violations, or poor user experience.

### Detection

```bash
# Check for biometric description
plutil -p Info.plist | grep "NSFaceIDUsageDescription"

# Check if LocalAuthentication framework is linked
otool -L /path/to/app.app/app | grep LocalAuthentication
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Missing description | **CRITICAL** | Uses Face ID/Touch ID but no description | Add `NSFaceIDUsageDescription` |
| No fallback | **HIGH** | Biometric only, no passcode option | Provide passcode fallback |
| Cached authentication | **MEDIUM** | Biometric auth persists too long | Implement proper timeout |
| No revocation | **MEDIUM** | Authenticated session not revocable | Implement logout/revoke mechanism |

### Common Vulnerable Patterns

#### Pattern 1: Biometric Without Passcode Fallback

```swift
// VULNERABLE: Biometric only
import LocalAuthentication

func authenticate() {
    let context = LAContext()
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Authenticate") { success, error in
        if success {
            // No fallback option
            unlockApp()
        }
    }
}

// SECURE: With passcode fallback
func authenticate() {
    let context = LAContext()
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate") { success, error in
        if success {
            unlockApp()
        }
    }
}
```

#### Pattern 2: No Authentication Revocation

```swift
// VULNERABLE: Authentication never expires
var isAuthenticated = false

func authenticate() {
    let context = LAContext()
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate") { success, error in
        if success {
            self.isAuthenticated = true  // Never expires
        }
    }
}

// SECURE: Implement timeout
var isAuthenticated = false
var authExpirationDate: Date?

func authenticate() {
    let context = LAContext()
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate") { success, error in
        if success {
            self.isAuthenticated = true
            self.authExpirationDate = Date().addingTimeInterval(300)  // 5 minutes
        }
    }
}

func checkAuthentication() -> Bool {
    guard isAuthenticated else { return false }
    guard let expiration = authExpirationDate else { return false }
    return Date() < expiration
}
```

### Testing

```bash
# Test biometric authentication
# 1. Enroll Face ID/Touch ID in device settings
# 2. Launch app
# 3. Trigger biometric prompt
# 4. Test with valid biometric (should succeed)
# 5. Test with invalid biometric (should fail or retry)
# 6. Test passcode fallback (should work)
```

### OWASP MASTG Reference

- **MASTG-TEST-0088**: Test for Local Authentication
- **MASTG-TEST-0089**: Test for Biometric Authentication

---

## 10. Siri Integration

### What It Does

Allows app to respond to Siri voice commands and provide data to Siri.

### Security Risk

**Privacy & data exposure**: Improper Siri integration can expose sensitive data through voice commands without proper user consent.

### Detection

```bash
# Check for Siri description
plutil -p Info.plist | grep "NSSiriUsageDescription"

# Check which SiriKit Intents the app extension declares
# IntentsSupported lives in the EXTENSION's Info.plist, under
# NSExtension -> NSExtensionAttributes (not in the main app's Info.plist)
plutil -p /path/to/app-extension.appex/Info.plist | grep -A 10 "IntentsSupported"

# Check for Siri entitlement
codesign -d --entitlements - /path/to/app.app/ | grep "com.apple.developer.siri"
```

### Security Checks

| Check | Risk Level | What to Look For | Remediation |
|-------|------------|-----------------|-------------|
| Missing description | **MEDIUM** | Uses Siri but no description | Add `NSSiriUsageDescription` |
| Sensitive intents | **HIGH** | Exposes sensitive data via Siri | Limit what Siri can access |
| No authentication | **HIGH** | Siri commands don't require re-auth | Require authentication for sensitive actions |
| Vague description | **MEDIUM** | Generic "Siri integration" | Explain what Siri can do |

### Common Vulnerable Patterns

#### Pattern 1: Exposing Sensitive Data via Siri

```swift
// VULNERABLE: Exposes all data via Siri
import Intents

class IntentHandler: INExtension {
    override func handler(for intent: INIntent) -> Any {
        if intent is INGetAccountDetailsIntent {
            return GetAccountDetailsIntentHandler()  // Returns full account details
        }
    }
}

// SECURE: Limit data exposure
class IntentHandler: INExtension {
    override func handler(for intent: INIntent) -> Any {
        if intent is INGetAccountDetailsIntent {
            // Only return masked data
            return GetAccountDetailsIntentHandler(masked: true)
        }
    }
}
```

### Testing

```bash
# Test Siri integration
# 1. Enable Siri in device settings
# 2. Launch app
# 3. Activate Siri (long press side button)
# 4. Test supported intents (e.g., "Hey Siri, check my balance")
# 5. Verify returned data is appropriate and not overly sensitive
```

### OWASP MASTG Reference

- **MASTG-TEST-0020**: Test for Improper Platform Usage
- **MASTG-TEST-0038**: Test for Privacy Violations

---

## 11. Other Security Keys

### Additional Security-Relevant Keys

| Key | Risk Level | Security Implications | Detection Command |
|-----|------------|---------------------|------------------|
| `ITSAppUsesNonExemptEncryption` | **MEDIUM** | Export compliance | `plutil -p Info.plist \| grep ITSAppUsesNonExemptEncryption` |
| `NSHealthShareUsageDescription` | **HIGH** | Health data access | `plutil -p Info.plist \| grep NSHealthShareUsageDescription` |
| `NSHealthUpdateUsageDescription` | **HIGH** | Health data modification | `plutil -p Info.plist \| grep NSHealthUpdateUsageDescription` |
| `NSHomeKitUsageDescription` | **MEDIUM** | HomeKit access | `plutil -p Info.plist \| grep NSHomeKitUsageDescription` |
| `NSMotionUsageDescription` | **MEDIUM** | Motion data access | `plutil -p Info.plist \| grep NSMotionUsageDescription` |
| `NSSpeechRecognitionUsageDescription` | **MEDIUM** | Speech recognition access | `plutil -p Info.plist \| grep NSSpeechRecognitionUsageDescription` |
| `NSAppleMusicUsageDescription` | **LOW** | Music library access | `plutil -p Info.plist \| grep NSAppleMusicUsageDescription` |
| `NSBluetoothPeripheralUsageDescription` | **MEDIUM** | Bluetooth access | `plutil -p Info.plist \| grep NSBluetoothPeripheralUsageDescription` |
| `NSCalendarsUsageDescription` | **MEDIUM** | Calendar access | `plutil -p Info.plist \| grep NSCalendarsUsageDescription` |
| `NSRemindersUsageDescription` | **MEDIUM** | Reminders access | `plutil -p Info.plist \| grep NSRemindersUsageDescription` |

### Key: `CFBundleIdentifier`

**Risk Level**: Medium
**Security Implications**: Package name can be spoofed or hijacked

```bash
# Check bundle identifier
plutil -p Info.plist | grep "CFBundleIdentifier"

# Check if using default bundle name
# VULNERABLE: com.example.app (generic)
# SECURE: com.company.product.app (unique, reverse-DNS)
```

### Key: `CFBundleVersion` and `CFBundleShortVersionString`

**Risk Level**: Low
**Security Implications**: Version information can be exploited in version-specific attacks

```bash
# Check version
plutil -p Info.plist | grep "CFBundleShortVersionString"
plutil -p Info.plist | grep "CFBundleVersion"

# Ensure versioning is consistent
```

### Key: `MinimumOSVersion`

**Risk Level**: Medium
**Security Implications**: Running on older iOS versions may have known vulnerabilities

```bash
# Check minimum OS version
plutil -p Info.plist | grep "MinimumOSVersion"

# VULNERABLE: iOS 9 or lower (multiple known vulnerabilities)
# SECURE: iOS 12 or higher
```

### Key: `UIRequiredDeviceCapabilities`

**Risk Level**: Low
**Security Implications**: App requirements may expose device capabilities

```bash
# Check required capabilities
plutil -p Info.plist | grep -A 10 "UIRequiredDeviceCapabilities"

# Check for:
# - arm64 (64-bit only)
# - gps (GPS required)
# - camera-flash (flash required)
```

---

## Quick Audit Script

```bash
#!/bin/bash

echo "=== iOS Info.plist Security Audit ==="
echo ""

INFO_PLIST="${1:-Info.plist}"

if [ ! -f "$INFO_PLIST" ]; then
    echo "Error: Info.plist not found"
    exit 1
fi

echo "Checking: $INFO_PLIST"
echo ""

# URL Schemes
echo "1. URL Schemes:"
if plutil -p "$INFO_PLIST" | grep -q "CFBundleURLSchemes"; then
    echo "   [!] URL schemes found:"
    plutil -p "$INFO_PLIST" | grep -A 5 "CFBundleURLSchemes" | grep "string"
else
    echo "   [OK] No URL schemes defined"
fi
echo ""

# ATS
echo "2. App Transport Security:"
if plutil -p "$INFO_PLIST" | grep -q "NSAllowsArbitraryLoads.*true"; then
    echo "   [CRITICAL] NSAllowsArbitraryLoads = true (cleartext HTTP allowed)"
elif plutil -p "$INFO_PLIST" | grep -q "NSAllowsArbitraryLoadsInWebContent.*true"; then
    echo "   [HIGH] NSAllowsArbitraryLoadsInWebContent = true"
elif plutil -p "$INFO_PLIST" | grep -q "NSExceptionDomains"; then
    echo "   [MEDIUM] ATS domain exceptions found"
    plutil -p "$INFO_PLIST" | grep -A 3 "NSExceptionDomains"
else
    echo "   [OK] ATS properly configured (HTTPS enforced)"
fi
echo ""

# File Sharing
echo "3. File Sharing:"
if plutil -p "$INFO_PLIST" | grep -q "UIFileSharingEnabled.*true"; then
    echo "   [HIGH] File sharing enabled"
else
    echo "   [OK] File sharing disabled"
fi
echo ""

# Background Modes
echo "4. Background Modes:"
if plutil -p "$INFO_PLIST" | grep -q "UIBackgroundModes"; then
    echo "   [!] Background modes found:"
    plutil -p "$INFO_PLIST" | grep -A 10 "UIBackgroundModes" | grep "string"
else
    echo "   [OK] No background modes"
fi
echo ""

# Privacy Descriptions
echo "5. Privacy Descriptions:"
privacy_keys=(
    "NSCameraUsageDescription"
    "NSMicrophoneUsageDescription"
    "NSLocationWhenInUseUsageDescription"
    "NSContactsUsageDescription"
    "NSPhotoLibraryUsageDescription"
    "NSFaceIDUsageDescription"
)

missing_count=0
for key in "${privacy_keys[@]}"; do
    if ! plutil -p "$INFO_PLIST" | grep -q "$key"; then
        echo "   [MISSING] $key"
        ((missing_count++))
    fi
done

if [ $missing_count -eq 0 ]; then
    echo "   [OK] All privacy descriptions present"
fi
echo ""

echo "=== Audit Complete ==="
```

Save as `audit-infoplist.sh`, make executable: `chmod +x audit-infoplist.sh`, run: `./audit-infoplist.sh Info.plist`

---

## Reference Links

- **OWASP MASTG**: https://mas.owasp.org/MASTG/
- **Apple Developer Documentation**: https://developer.apple.com/documentation/bundleresources/information_property_list
- **iOS Security Guide**: https://support.apple.com/guide/security/welcome/web
