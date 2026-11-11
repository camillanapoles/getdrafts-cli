# URL Scheme Security Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [URL Scheme Fundamentals](#url-scheme-fundamentals)
3. [URL Scheme Registration](#url-scheme-registration)
4. [Vulnerabilities](#vulnerabilities)
5. [Testing Methodology](#testing-methodology)
6. [Deep Link Fuzzing](#deep-link-fuzzing)
7. [Universal Links](#universal-links)
8. [Attack Scenarios](#attack-scenarios)
9. [Remediation Strategies](#remediation-strategies)
10. [Compliance and Standards](#compliance-and-standards)
11. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

URL schemes allow iOS applications to be launched from other apps, Safari, or even external sources. While useful for inter-app communication, improperly secured URL schemes can lead to serious security vulnerabilities including hijacking, parameter injection, and unauthorized actions.

### Why Test URL Schemes?

- **Inter-app communication**: Test data flow between applications
- **Deep linking**: Verify security of deep link handlers
- **Parameter injection**: Test for unsafe parameter handling
- **Hijacking risks**: Check for scheme hijacking vulnerabilities
- **Authentication bypass**: Identify auth bypass via URL parameters
- **OAuth callback security**: Validate OAuth flow redirects

---

## URL Scheme Fundamentals

### How URL Schemes Work

```
1. User taps link or app triggers URL
2. iOS looks up registered URL scheme
3. Launches target application with URL
4. Application processes URL in:
   - application(_:open:options:) (iOS 13+)
   - application(_:open:sourceApplication:annotation:) (older)
5. Application extracts parameters and performs actions
```

### URL Scheme Format

```
<scheme>://<host>/<path>?<query>#<fragment>

Examples:
- myapp://home
- myapp://profile?user=123
- myapp://payment?amount=100&merchant=456
- myapp://auth?token=abc123&redirect=success
```

### Common iOS URL Schemes

| Scheme | Description | Security Concern |
|--------|-------------|------------------|
| http://, https:// | Web URLs | Universal Links conflict |
| tel:// | Phone calls | Number injection |
| mailto:// | Email | Email injection |
| sms:// | SMS | Message injection |
| facetime:// | FaceTime calls | Call hijacking |
| file:// | File access | Path traversal |

---

## URL Scheme Registration

### Registering URL Schemes (Info.plist)

```xml
<!-- Info.plist URL Scheme Registration -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.example.myapp</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <string>myapp-secure</string>
        </array>
        <key>CFBundleTypeRole</key>
        <string>Editor</string>
    </dict>
</array>
```

### Alternative Registration (Info.plist - Modern)

```xml
<!-- Modern Info.plist format -->
<dict>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeRole</key>
            <string>Editor</string>
            <key>CFBundleURLName</key>
            <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>myapp</string>
                <string>myapp-auth</string>
                <string>myapp-payment</string>
            </array>
        </dict>
    </array>
</dict>
```

### Handling URL Schemes in Code

```swift
// Swift - Handling URL schemes (iOS 13+)
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey : Any] = [:]
    ) -> Bool {
        // Validate scheme
        guard url.scheme == "myapp" else { return false }

        // Handle URL
        handleURL(url)
        return true
    }

    func scene(
        _ scene: UIScene,
        openURLContexts URLContexts: Set<UIOpenURLContext>
    ) {
        // iOS 13+ - Handle URL in SceneDelegate
        guard let url = URLContexts.first?.url else { return }
        handleURL(url)
    }

    func handleURL(_ url: URL) {
        // Extract scheme
        guard let scheme = url.scheme else { return }

        // Extract host/path
        let host = url.host ?? ""
        let path = url.path

        // Extract query parameters
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        let query = components?.queryItems ?? []

        // Process based on scheme
        switch scheme {
        case "myapp":
            processMyAppURL(url: url, host: host, path: path, query: query)
        case "myapp-auth":
            processAuthURL(url: url, query: query)
        case "myapp-payment":
            processPaymentURL(url: url, query: query)
        default:
            print("Unknown scheme: \(scheme)")
        }
    }
}
```

### Finding Registered URL Schemes

```bash
# Method 1: Extract and parse Info.plist
unzip -q Example.ipa -d Extracted
plutil -p Extracted/Payload/Example.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Method 2: Use Frida to find URL schemes
frida -U -l url-scheme-monitor.js -f com.example.app

```

```javascript
// find-url-schemes.js:
if (ObjC.available) {
    var infoDict = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    var urlTypes = infoDict.objectForKey_("CFBundleURLTypes");

    console.log("[*] URL Schemes:");
    for (var i = 0; i < urlTypes.count(); i++) {
        var urlType = urlTypes.objectAtIndex_(i);
        var schemes = urlType.objectForKey_("CFBundleURLSchemes");
        for (var j = 0; j < schemes.count(); j++) {
            console.log("  " + schemes.objectAtIndex_(j));
        }
    }
}
```

---

## Vulnerabilities

### 1. URL Scheme Hijacking

**Description**: A malicious app registers the same URL scheme as the target app. iOS may launch the malicious app instead of the legitimate app.

**Attack Vector**:
```
1. Malicious app registers "myapp://" scheme
2. User clicks "myapp://" link
3. iOS launches malicious app instead of legitimate app
4. Malicious app can steal data or perform actions
```

**Impact**:
- User confusion
- Data theft
- Phishing attacks
- Service disruption

### 2. OAuth Callback Hijacking

**Attack Scenario**

OAuth flow using custom URL scheme as callback URL:

1. User initiates OAuth login in target app
2. OAuth provider redirects to `myapp://callback?code=AUTH_CODE`
3. Attacker app also registers `myapp://` URL scheme
4. iOS may open attacker's app instead (non-deterministic scheme resolution)
5. Attacker captures OAuth authorization code

**Root Cause**: iOS allows multiple apps to register the same custom URL scheme. First installed app doesn't always win — scheme resolution is non-deterministic.

**Attack Vectors**:

| Attack Vector | Technique | Impact |
|---|---|---|
| OAuth callback interception | Register same scheme | Steal authorization codes, tokens |
| Deep link hijacking | Register same scheme | Phishing, data interception |
| Payment callback interception | Register payment scheme | Transaction manipulation |
| Password reset hijacking | Register same scheme | Account takeover via reset tokens |

### 3. Parameter Injection

**Description**: URL parameters are not validated, allowing injection of malicious data.

**Vulnerable Code**:
```swift
func processURL(url: URL) {
    let query = url.query?.components(separatedBy: "&") ?? []

    for param in query {
        let parts = param.components(separatedBy: "=")
        let key = parts[0]
        let value = parts[1]

        // DANGEROUS: No validation
        UserDefaults.standard.set(value, forKey: key)
    }
}
```

**Attack Example**:
```
myapp://?userId=../malicious&token=../../etc/passwd
myapp://?userId=<script>alert('XSS')</script>
myapp://?userId=admin&role=superuser
```

**Impact**:
- SQL injection
- XSS attacks
- Privilege escalation
- Data corruption

### 4. Lack of Validation

**Description**: URL parameters are not validated before being used.

**Vulnerable Code**:
```swift
func handleAuth(url: URL) {
    if let token = url.query?.components(separatedBy: "token=").last {
        // DANGEROUS: No validation
        authenticate(token: token)
    }
}
```

**Impact**:
- Authentication bypass
- Session hijacking
- Unauthorized access

### 5. Sensitive Actions in URL

**Description**: Performing sensitive actions (payments, password changes) via URL without confirmation.

**Attack Example**:
```
myapp://payment?amount=9999.99&recipient=attacker_account
myapp://reset-password?newPassword=hacked123
myapp://transfer?to=attacker&amount=1000
```

**Impact**:
- Unauthorized financial transactions
- Password reset abuse
- Data exfiltration

---

## Testing Methodology

### Step 1: Enumerate URL Schemes

```bash
# Extract IPA
unzip -q Example.ipa -d Extracted

# Parse Info.plist for URL schemes
plutil -p Extracted/Payload/Example.app/Info.plist | grep -A10 "CFBundleURLTypes"

# Use Frida to list schemes
frida -U -l deeplink-security-analyzer.js -f com.example.app
```

### Step 2: Test Basic URL Opening

```bash
# Open URL scheme from Safari
xcrun simctl openurl booted "myapp://"
xcrun simctl openurl booted "myapp://home"
xcrun simctl openurl booted "myapp://profile?user=123"
```

### Step 3: Parameter Injection Testing

```bash
# Test various parameter values
# XSS attempts
xcrun simctl openurl booted "myapp://?param=<script>alert(1)</script>"

# SQL injection attempts
xcrun simctl openurl booted "myapp://?id=1' OR '1'='1"

# Path traversal
xcrun simctl openurl booted "myapp://?file=../../etc/passwd"

# Command injection
xcrun simctl openurl booted "myapp://?cmd=whoami"
```

### Step 4: Sensitive Action Testing

```bash
# Test CSRF vulnerability in deep links
xcrun simctl openurl booted "myapp://payment?amount=9999"
xcrun simctl openurl booted "myapp://transfer?to=attacker&amount=1000"
xcrun simctl openurl booted "myapp://reset-password?new=123456"

# Use Frida script to detect CSRF issues
frida -U -l deeplink-csrf-validator-ios.js -f com.example.app
```

### Step 5: Frida Hooking

```javascript
// Hook URL handling to monitor parameters
if (ObjC.available) {
    var UIApplication = ObjC.classes.UIApplication;

    Interceptor.attach(UIApplication['- openURL:'].implementation, {
        onEnter: function(args) {
            var url = ObjC.Object(args[2]).toString();
            console.log('[DEEPLINK] URL opened: ' + url);
        }
    });
}
```

---

## Deep Link Fuzzing

### Manual Fuzzing

```bash
# Create fuzzing script
cat > fuzz_urls.sh << 'EOF'
#!/bin/bash

APP_SCHEME="myapp"
FUZZ_VECTORS=(
    "<script>alert(1)</script>"
    "1' OR '1'='1"
    "../../../etc/passwd"
    "$(whoami)"
    "%00"
    "%0A"
    "admin"
    "root"
    "../../"
)

for vector in "${FUZZ_VECTORS[@]}"; do
    url="${APP_SCHEME}://?param=${vector}"
    echo "Testing: $url"
    xcrun simctl openurl booted "$url"
    sleep 1
done
EOF

chmod +x fuzz_urls.sh
./fuzz_urls.sh
```

### Automated Fuzzing

Use dedicated Frida scripts for automated deep link fuzzing:

```bash
# Use deep link security analyzer
frida -U -l deeplink-security-analyzer.js -f com.example.app

# Use CSRF validator
frida -U -l deeplink-csrf-validator-ios.js -f com.example.app
```

---

## Universal Links

### Universal Links Overview

```
Universal Links allow:
- Standard HTTP/HTTPS URLs (https://myapp.example.com/path)
- Seamless app opening without user choice
- Better user experience
- More secure than custom schemes

Apple App Site Association (AASA) file required:
- Hosted at: https://myapp.example.com/.well-known/apple-app-site-association
- JSON format
- Signed by Apple
```

### AASA File Format

```json
{
    "applinks": {
        "apps": [],
        "details": [
            {
                "appID": "TEAMID.com.example.myapp",
                "paths": [
                    "/path/*",
                    "/another/*"
                ]
            }
        ]
    }
}
```

### Registering Universal Links

```xml
<!-- Entitlements file -->
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:myapp.example.com</string>
    <string>applinks:api.example.com</string>
</array>
```

### Testing Universal Links

```bash
# Test Universal Link
xcrun simctl openurl booted "https://myapp.example.com/home"

# Test path handling
xcrun simctl openurl booted "https://myapp.example.com/profile?user=123"

# Fetch AASA file
curl https://myapp.example.com/.well-known/apple-app-site-association
```

---

## Attack Scenarios

### Scenario 1: Hijacking Financial Transactions

**Setup**:
- Target app uses URL scheme for payments: `payapp://payment`
- No user confirmation required
- Amount and recipient extracted from URL

**Attack**:
```
1. Attacker creates malicious website with link:
   payapp://payment?amount=9999.99&recipient=attacker_account

2. Victim clicks link on iOS device

3. iOS opens payment app

4. App initiates payment without confirmation

5. Funds transferred to attacker
```

**Mitigation**:
- Require user confirmation
- Validate recipient
- Limit transaction amount
- Add security code/PIN

### Scenario 2: Authentication Bypass

**Setup**:
- App uses URL scheme for authentication: `myapp://auth`
- Token passed in URL parameter
- No validation of token source

**Attack**:
```
1. Attacker steals token from another user's device

2. Attacker creates link:
   myapp://auth?token=stolen_token

3. Victim clicks link

4. App authenticates victim with stolen token

5. Attacker gains access to victim's account
```

**Mitigation**:
- Validate token server-side
- Use secure storage (Keychain)
- Add additional verification
- Implement token expiration

### Scenario 3: XSS via URL Parameters

**Setup**:
- App displays URL parameters in UI without sanitization
- WebView renders HTML from parameters

**Attack**:
```
1. Attacker creates link:
   myapp://display?content=<script>alert(document.cookie)</script>

2. Victim clicks link

3. App displays content in WebView

4. JavaScript executes in app context

5. Steals sensitive data (cookies, tokens, etc.)
```

**Mitigation**:
- Sanitize all input
- Escape HTML entities
- Use Content Security Policy
- Use Frida: `webview-xss-scanner-ios.js`

---

## Remediation Strategies

### 1. Parameter Validation

```swift
func handleURL(url: URL) -> Bool {
    guard let scheme = url.scheme,
          scheme.hasPrefix("myapp") else {
        return false
    }

    // Validate all parameters
    guard let userId = url.queryValue(for: "userId"),
          validateUserId(userId) else {
        return false
    }

    // Sanitize input
    let sanitizedUserId = sanitize(userId)

    // Use sanitized value
    processUser(sanitizedUserId)

    return true
}

func validateUserId(_ userId: String) -> Bool {
    let userIdRegex = "^[0-9]{1,10}$"
    let predicate = NSPredicate(format: "SELF MATCHES %@", userIdRegex)
    return predicate.evaluate(with: userId)
}
```

### 2. Whitelist Allowed Parameters

```swift
let ALLOWED_PARAMS = ["userId", "action", "redirect"]

func handleURL(url: URL) {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
        return
    }

    let queryItems = components.queryItems ?? []

    // Validate each parameter
    for item in queryItems {
        guard ALLOWED_PARAMS.contains(item.name) else {
            print("Unknown parameter: \(item.name)")
            return
        }

        guard validateParameterValue(item.name, value: item.value) else {
            print("Invalid value for \(item.name)")
            return
        }
    }

    processURL(url)
}
```

### 3. Avoid Sensitive Actions in URLs

```swift
// ❌ BAD: Sensitive action via URL
func handlePayment(url: URL) {
    if let amount = url.queryValue(for: "amount"),
       let recipient = url.queryValue(for: "recipient") {
        initiatePayment(amount: amount, recipient: recipient)
    }
}

// ✅ GOOD: URL navigates to payment UI
func handlePayment(url: URL) {
    if let amount = url.queryValue(for: "amount") {
        navigateToPaymentUI(withAmount: amount)
        // User must confirm in UI
    }
}
```

### 4. Use Universal Links Instead

```swift
// Use Universal Links for better security
// URL: https://myapp.example.com/payment?amount=100

func application(
    _ application: UIApplication,
    continue userActivity: NSUserActivity,
    restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void
) -> Bool {
    guard let url = userActivity.webpageURL,
          url.host == "myapp.example.com" else {
        return false
    }

    // Only handle HTTPS links
    guard url.scheme == "https" else {
        return false
    }

    handleUniversalLink(url)
    return true
}
```

### 5. Add CSRF Protection for State-Changing Actions

```swift
// Store expected CSRF tokens
private var expectedCSRFTokens: [String: Date] = [:]

func handleAction(url: URL) -> Bool {
    // Check for CSRF token
    guard let token = url.queryValue(for: "token"),
          validateCSRFToken(token) else {
        print("Missing or invalid CSRF token")
        return false
    }

    // Validate action
    guard let action = url.queryValue(for: "action"),
          allowedActions.contains(action) else {
        return false
    }

    // Process action
    performAction(action)
    return true
}

func validateCSRFToken(_ token: String) -> Bool {
    // Check if token exists and not expired
    guard let issuedDate = expectedCSRFTokens[token],
          Date().timeIntervalSince(issuedDate) < 300 else {
        return false
    }

    // Invalidate single-use token
    expectedCSRFTokens.removeValue(forKey: token)
    return true
}
```

---

## Compliance and Standards

### OWASP MASVS

| MSTG ID | Topic | Requirement |
|--------|-------|-------------|
| MSTG-ARCH-9 | WebViews | Verify deep links are validated before use |
| MSTG-STORAGE-2 | Sensitive Data in URLs | Verify no sensitive data in URLs |
| MSTG-AUTH-2 | Authentication | Verify deep link auth is validated |

### GDPR Compliance

- Document all deep link handling
- Implement privacy controls
- Allow users to opt out
- Provide data access controls

### PCI DSS

- Never include card data in deep links
- Implement proper tokenization
- Comply with PCI DSS requirements

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | URL Scheme Context |
|---------------|-------|-------------------|
| MASTG-TEST-0020 | Input Validation | Parameter validation |
| MASTG-APP-SEC-0015 | Inter-Process Communication | URL schemes |
| MASTG-APP-SEC-0020 | URL Scheme Security | Scheme hijacking |
| MASTG-TEST-0070 | Deep Link Testing | URL scheme testing |
| MASTG-TEST-0131 | Test Deep Links | Deep link testing |
| MASTG-TEST-0146 | Test URL Scheme Handling | URL scheme handling |

---

## Summary

This guide covered:
- URL scheme fundamentals and registration
- Common vulnerabilities (hijacking, injection, OAuth callback hijacking)
- Comprehensive testing methodology
- Deep link fuzzing techniques
- Universal Links security
- Real-world attack scenarios
- Remediation strategies and best practices

URL schemes are a powerful feature for inter-app communication, but they must be implemented with security in mind. Always validate parameters, avoid sensitive actions, and consider using Universal Links for better security.

---

## Related Scripts

- `deeplink-security-analyzer.js` - Analyze deep link security
- `deeplink-csrf-validator-ios.js` - Detect CSRF vulnerabilities in deep links
- `webview-xss-scanner-ios.js` - Detect XSS in WebView content loading
- `url-scheme-monitor.js` - Monitor URL scheme activity

---

**Document Version:** 2.0 (Merged from url-scheme-hijacking.md + url-scheme-security.md)
**Last Updated:** June 2026
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** iOS development knowledge, Xcode, jailbroken device (optional)
