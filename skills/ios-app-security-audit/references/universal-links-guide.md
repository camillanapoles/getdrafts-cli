# Universal Links Guide

## Universal Links Architecture

Universal Links are Apple's deep linking solution introduced in iOS 9. They provide a secure, user-friendly way to link directly to content within your app without requiring custom URL schemes.

### Key Characteristics
- Standard HTTP/HTTPS URLs
- No user confirmation dialog
- App association validated via web server
- Graceful fallback to Safari/website
- No scheme conflicts

### Comparison with URL Schemes

| Feature | Custom URL Schemes | Universal Links |
|---------|-------------------|-----------------|
| URL Format | myapp://path | https://example.com/path |
| User Confirmation | Yes (usually) | No |
| Scheme Conflicts | Possible | No (domain-based) |
| Fallback | Manual | Automatic |
| Security | Validation required | Domain validation |

## AASA File Format

### Apple App Site Association (AASA)

The AASA file is a JSON document hosted on your web server that associates your website with your app.

### File Location
```
https://<domain>/.well-known/apple-app-site-association
```

### Complete AASA Example

```json
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appIDs": ["TEAMID.com.example.myapp"],
        "paths": [
          "/articles/*",
          "NOT /private/*",
          "/settings",
          "/profile/*",
          "/checkout/*"
        ],
        "components": [
          {
            "/": "/articles/*",
            "comment": "Article pages"
          },
          {
            "/": "/profile/*",
            "comment": "User profiles",
            "exclude": ["*/admin"]
          }
        ]
      }
    ]
  },
  "webcredentials": {
    "apps": ["TEAMID.com.example.myapp"]
  },
  "appclips": {
    "apps": ["TEAMID.com.example.myapp.Clip"]
  }
}
```

### AASA File Structure

#### apps Array
```json
"apps": []
```
Always empty (legacy field, reserved for future use).

#### details Array
```json
"details": [
  {
    "appIDs": ["TEAMID.com.example.myapp"],
    "paths": [...],
    "components": [...]
  }
]
```
Contains one or more app configurations.

#### appIDs
```json
"appIDs": ["TEAMID.com.example.myapp"]
```
- Format: `<TeamID>.<BundleIdentifier>`
- Team ID from Apple Developer account
- Bundle identifier from Xcode project

#### paths Array
```json
"paths": [
  "/articles/*",
  "NOT /private/*",
  "/settings"
]
```
Path patterns specifying which URLs should open in your app:
- `*` wildcard matches any characters
- `?` matches single character
- `NOT /path/*` excludes a path
- Paths are case-sensitive
- Wildcards don't match subdirectories

#### components Array (New)
```json
"components": [
  {
    "/": "/articles/*",
    "comment": "Article pages",
    "exclude": ["*/admin"]
  }
]
```
Advanced path matching with:
- Path patterns
- Comments
- Exclude rules

## AASA File Requirements

### 1. File Location
```
MUST be at: https://example.com/.well-known/apple-app-site-association
NOT at: https://example.com/.well-known/apple-app-site-association.json
```

### 2. Content-Type
```
Content-Type: application/json
OR
No Content-Type header (acceptable)
```

### 3. No Redirects
```
❌ BAD: HTTP redirect
https://example.com/.well-known/apple-app-site-association
  → 301 → https://www.example.com/.well-known/apple-app-site-association

✅ GOOD: Direct access
https://example.com/.well-known/apple-app-site-association
```

### 4. Valid JSON
```json
// Must be valid JSON
// No trailing commas
// Proper escaping

❌ BAD: Invalid JSON
{
  "applinks": {
    "details": [
      {
        "appIDs": ["TEAMID.com.example.myapp"],  // Trailing comma
      }
    ]
  }
}

✅ GOOD: Valid JSON
{
  "applinks": {
    "details": [
      {
        "appIDs": ["TEAMID.com.example.myapp"]
      }
    ]
  }
}
```

### 5. CDN Signature (Optional)
```json
// Apple CDN wraps the JSON
{
  "applinks": {
    "details": [...]
  }
}
```

## AASA Validation

### 1. Fetch AASA File

```bash
# Check file accessibility
curl -I https://example.com/.well-known/apple-app-site-association

# Expected:
# HTTP/2 200
# Content-Type: application/json (or no header)
# Content-Length: [size]
```

### 2. Download and Validate

```bash
# Download AASA
curl https://example.com/.well-known/apple-app-site-association -o aasa.json

# Validate JSON
python3 -m json.tool aasa.json

# Check for errors
cat aasa.json | python3 -m json.tool > /dev/null
echo $?
# 0 = valid JSON, non-zero = invalid
```

### 3. Check CDN Signature

```text
# Check if signed
curl https://example.com/.well-known/apple-app-site-association | head -1

# If wrapped:
{"applinks":{"details":[...]}}

# If not wrapped:
{
  "applinks": {
    "details": [...]
  }
}
```

### 4. Verify Path Patterns

```bash
# Extract paths
curl -s https://example.com/.well-known/apple-app-site-association |   python3 -c "import sys, json; data=json.load(sys.stdin); print(data['applinks']['details'][0]['paths'])"

# Expected output:
# ['/articles/*', 'NOT /private/*', '/settings']
```

### 5. Test URL Matching

```bash
# Test if URL would open in app
# Note: Requires device or simulator to test

# Example URLs to test:
# https://example.com/articles/123  → Should open app
# https://example.com/private/data   → Should NOT open app (NOT)
# https://example.com/settings       → Should open app
```

## Associated Domains Entitlement

### 1. Add Entitlement

```xml
<!-- Entitlements.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.associated-domains</key>
    <array>
        <string>applinks:example.com</string>
        <string>applinks:www.example.com</string>
        <string>applinks:*.example.com</string>
    </array>
</dict>
</plist>
```

### 2. Multiple Domains

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:example.com</string>
    <string>applinks:blog.example.com</string>
    <string>applinks:shop.example.com</string>
    <string>applinks:app.example.co.uk</string>
</array>
```

### 3. Wildcard Subdomains

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <!-- Match any subdomain -->
    <string>applinks:*.example.com</string>
</array>
```

### 4. Development vs Production

```xml
<!-- Development: Use development certificate -->
<!-- AASA file must be signed -->
<!-- Paths: /non-wildcard paths only -->

<!-- Production: Use distribution certificate -->
<!-- AASA file can be unsigned -->
<!-- Paths: Wildcards supported -->
```

## Implementation in Swift

### 1. AppDelegate Integration

```swift
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        return true
    }
    
    // Universal Link handler
    func application(_ application: UIApplication,
                     continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        
        // Check if it's a browsing activity
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
              let url = userActivity.webpageURL else {
            return false
        }
        
        // Validate the URL
        guard validateUniversalLink(url) else {
            return false
        }
        
        // Handle the universal link
        handleUniversalLink(url)
        
        return true
    }
    
    private func validateUniversalLink(_ url: URL) -> Bool {
        // Validate domain
        guard let host = url.host else { return false }
        guard ["example.com", "www.example.com"].contains(host) else {
            return false
        }
        
        // Validate path
        guard url.path.isEmpty == false else { return false }
        
        // Validate scheme
        guard url.scheme == "https" else { return false }
        
        return true
    }
    
    private func handleUniversalLink(_ url: URL) {
        // Extract path and parameters
        let path = url.path
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        let queryItems = components?.queryItems
        
        print("Universal Link:")
        print("  URL: \(url.absoluteString)")
        print("  Path: \(path)")
        print("  Query: \(queryItems ?? [])")
        
        // Route to appropriate view controller
        routeToViewController(for: path, parameters: queryItems)
    }
    
    private func routeToViewController(for path: String, parameters: [URLQueryItem]?) {
        // Example routing
        if path.hasPrefix("/articles/") {
            let articleId = path.replacingOccurrences(of: "/articles/", with: "")
            showArticle(articleId)
        } else if path == "/settings" {
            showSettings()
        } else if path.hasPrefix("/profile/") {
            let userId = path.replacingOccurrences(of: "/profile/", with: "")
            showProfile(userId)
        }
    }
}
```

### 2. SceneDelegate Integration (iOS 13+)

```swift
import UIKit

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    
    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        // Handle universal link
        if let url = userActivity.webpageURL {
            handleUniversalLink(url)
        }
    }
    
    private func handleUniversalLink(_ url: URL) {
        // Extract and validate parameters
        let path = url.path
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        
        // Route to appropriate view
        // ...
    }
}
```

### 3. SwiftUI Integration

```swift
import SwiftUI

@main
struct MyAppApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onOpenURL { url in
            handleUniversalLink(url)
        }
    }
    
    func handleUniversalLink(_ url: URL) {
        print("Universal link received: \(url)")
        
        // Parse path and parameters
        let path = url.path
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        let queryItems = components?.queryItems
        
        // Update app state
        // Navigate to appropriate view
    }
}
```

### 4. Universal Link Parser

```swift
struct UniversalLink {
    let url: URL
    let path: String
    let parameters: [String: String]
    
    init(url: URL) {
        self.url = url
        
        // Extract path
        self.path = url.path
        
        // Extract parameters
        var params: [String: String] = [:]
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
           let queryItems = components.queryItems {
            for item in queryItems {
                if let value = item.value {
                    params[item.name] = value
                }
            }
        }
        self.parameters = params
    }
    
    func parameter(named name: String) -> String? {
        return parameters[name]
    }
}

// Usage
let link = UniversalLink(url: url)
let articleId = link.parameter(named: "id")
let source = link.parameter(named: "source")
```

## Security Considerations

### 1. Always Validate Incoming URLs

```swift
// ❌ BAD: Trust all URLs
func handleUniversalLink(_ url: URL) {
    let userId = url.pathComponents.last
    // Direct usage without validation
    showProfile(userId!)
}

// ✅ GOOD: Validate thoroughly
func handleUniversalLink(_ url: URL) -> Bool {
    // Validate domain
    guard let host = url.host,
          allowedDomains.contains(host) else {
        return false
    }
    
    // Validate path pattern
    guard let path = url.path.removingPercentEncoding,
          path.hasPrefix("/profile/") else {
        return false
    }
    
    // Validate path length
    guard path.count <= 256 else {
        return false
    }
    
    // Sanitize path
    guard !path.contains("..") else {
        return false
    }
    
    // Validate parameters
    if let components = URLComponents(url: url, resolvingAgainstBaseURL: true) {
        for item in components.queryItems ?? [] {
            guard validateParameter(name: item.name, value: item.value) else {
                return false
            }
        }
    }
    
    return true
}

func validateParameter(name: String, value: String?) -> Bool {
    // Allow only specific parameters
    guard allowedParameters.contains(name) else {
        return false
    }
    
    // Validate value format
    guard let value = value, value.count <= 256 else {
        return false
    }
    
    // Sanitize value
    guard !value.contains("<") && !value.contains(">") else {
        return false
    }
    
    return true
}
```

### 2. Check Domain Whitelist

```swift
// Define allowed domains
let allowedDomains: Set<String> = [
    "example.com",
    "www.example.com",
    "app.example.co.uk"
]

func isAllowedDomain(_ url: URL) -> Bool {
    guard let host = url.host else { return false }
    return allowedDomains.contains(host)
}
```

### 3. Validate Path Patterns

```swift
// Define allowed path patterns
let allowedPathPatterns: [NSRegularExpression] = [
    try! NSRegularExpression(pattern: "^/articles/[0-9]+", options: []),
    try! NSRegularExpression(pattern: "^/profile/[a-zA-Z0-9_-]+", options: []),
    try! NSRegularExpression(pattern: "^/settings", options: [])
]

func isValidPath(_ path: String) -> Bool {
    for pattern in allowedPathPatterns {
        let range = NSRange(location: 0, length: path.utf16.count)
        if pattern.firstMatch(in: path, options: [], range: range) != nil {
            return true
        }
    }
    return false
}
```

### 4. Sanitize Parameters

```swift
func sanitizeParameter(_ value: String) -> String {
    var sanitized = value
    
    // Remove dangerous characters
    let dangerousChars = CharacterSet(charactersIn: "<>&"'\")
    sanitized = sanitized.components(separatedBy: dangerousChars).joined()
    
    // Remove null bytes
    sanitized = sanitized.replacingOccurrences(of: "\x00", with: "")
    
    // Truncate to max length
    if sanitized.count > 256 {
        sanitized = String(sanitized.prefix(256))
    }
    
    return sanitized
}
```

### 5. Rate Limiting

```swift
class UniversalLinkRateLimiter {
    private var attempts: [String: [Date]] = [:]
    private let maxAttempts = 10
    private let timeWindow: TimeInterval = 60 // seconds
    
    func shouldAllow(_ url: URL) -> Bool {
        let key = url.host ?? "unknown"
        let now = Date()
        
        // Clean old attempts
        attempts[key]?.removeAll(where: { now.timeIntervalSince($0) > timeWindow })
        
        // Check rate limit
        if let currentAttempts = attempts[key] {
            if currentAttempts.count >= maxAttempts {
                return false
            }
            var newAttempts = currentAttempts
            newAttempts.append(now)
            attempts[key] = newAttempts
        } else {
            attempts[key] = [now]
        }
        
        return true
    }
}
```

### 6. Avoid Sensitive Data in URLs

```swift
// ❌ BAD: Sensitive data in URL
https://example.com/auth?token=abc123def456

// ✅ GOOD: Use temporary reference
https://example.com/auth?ref=xyz
// Then exchange ref for token via secure API

// Secure API exchange
POST /api/auth/validate
{
  "reference": "xyz"
}

Response:
{
  "token": "abc123def456"
}
```

## Common Misconfigurations

### 1. Wildcard Paths

```json
// ❌ BAD: Too permissive
"paths": [
  "*"  // Matches ALL paths!
]

// ✅ GOOD: Specific paths
"paths": [
  "/articles/*",
  "/settings",
  "/profile/*",
  "NOT /admin/*"
]
```

### 2. Missing Path Validation

```swift
// ❌ BAD: No validation
func handleUniversalLink(_ url: URL) {
    let userId = url.lastPathComponent
    showProfile(userId!)  // No validation!
}

// ✅ GOOD: Validate everything
func handleUniversalLink(_ url: URL) {
    guard validateUrl(url) else {
        showErrorMessage()
        return
    }
    
    let userId = url.lastPathComponent
    showProfile(userId)
}
```

### 3. Exposed Sensitive Data

```swift
// ❌ BAD: Password in URL
https://example.com/reset-password?token=abc123&newPassword=secret

// ✅ GOOD: Use secure flow
// 1. Email contains link with token only
https://example.com/reset-password?token=abc123

// 2. App shows password reset form
// 3. New password sent via POST, not URL
POST /api/reset-password
{
  "token": "abc123",
  "newPassword": "hashed_password"
}
```

### 4. Broken Fallback

```swift
// ❌ BAD: No fallback handling
func handleUniversalLink(_ url: URL) {
    // If app can't handle, user stuck
    show404()
}

// ✅ GOOD: Proper fallback
func handleUniversalLink(_ url: URL) {
    if canHandle(url) {
        showContent(url)
    } else {
        // Open in Safari
        UIApplication.shared.open(url)
    }
}
```

### 5. CDN Signature Issues

```bash
# Common CDN signature problems

# 1. Expired signature
# AASA file has CDN signature that expired
# Solution: Re-sign and upload

# 2. Wrong domain
# AASA file hosted on wrong subdomain
# ❌ BAD: https://www.example.com/.well-known/apple-app-site-association
# ✅ GOOD: https://example.com/.well-known/apple-app-site-association

# 3. Missing signature
# CDN expects signature but file unsigned
# Solution: Sign with Apple's CDN or use unsigned version
```

### 6. AASA File Not Accessible

```bash
# Common accessibility issues

# 1. Wrong path
# File must be in /.well-known/
# ❌ BAD: https://example.com/apple-app-site-association
# ✅ GOOD: https://example.com/.well-known/apple-app-site-association

# 2. Wrong Content-Type
# ❌ BAD: Content-Type: text/plain
# ✅ GOOD: Content-Type: application/json

# 3. Redirects
# File must not redirect
# ❌ BAD: HTTP → HTTPS redirect
# ✅ GOOD: Direct HTTPS access

# 4. Blocked by CORS
# Ensure file is accessible without CORS headers
```

---

## Breaking Universal Links → URL Scheme Fallback

### Attack Techniques

Attackers can force Universal Links to fail, causing fallback to less-secure URL schemes which may be hijackable.

**1. User long-presses link**
- User long-presses Universal Link in Safari
- Taps "Open in Safari" from context menu
- This disables Universal Link for that domain
- Subsequent opens use Safari only (app won't open)

**2. Redirect chain breaks Universal Links**
```
https://domain-a.com/link
  → HTTP 302 → https://domain-b.com/redirect
  → HTTP 302 → https://target.com/path
```
Universal Links only work on direct links. HTTP redirects break the association.

**3. JavaScript redirect breaks Universal Links**
```html
<script>window.location = "https://target.com/path"</script>
<meta http-equiv="refresh" content="0;url=https://target.com/path">
```
Universal Links require server-side HTTP 302 redirects. Client-side redirects (JavaScript, meta refresh) don't trigger UL.

**4. App not installed**
- Universal Link fails to open app
- Falls back to website
- If website redirects to URL scheme → hijackable if scheme is generic

**5. AASA file missing or invalid**
- Universal Links can't validate app association
- Falls back to Safari
- May then redirect to URL scheme

### Testing

```bash
# 1. Test redirect chain
curl -I "https://target.com/link"  # Check for 302 redirects
curl -I "https://target.com/link" -L  # Follow redirects

# 2. Test JavaScript redirect
# Open link in Safari, observe behavior
# UL should work, JS redirect breaks UL

# 3. Test with app uninstalled
# Remove app from device
# Try Universal Link
# Should show website, not error

# 4. Test long-press behavior
# Long-press UL in Safari
# Select "Open in Safari"
# Try opening UL again
# Should stay in Safari (UL disabled for domain)

# 5. Force clear UL cache
# Delete app and reinstall
# Settings → Safari → Clear History and Website Data
```

### Exploitation Example

```
Attacker flow:
1. Identify Universal Link: https://bank.com/payment?id=123
2. Register URL scheme: bankapp://
3. Create phishing site that redirects:
   https://evil.bank.com → https://bank.com/payment?account=attacker
4. User clicks link from phishing email
5. Redirect breaks UL → falls back to bankapp://
6. Attacker's app (with bankapp:// scheme) opens
7. User enters credentials → attacker harvests them
```

### Remediation

**1. Ensure AASA file is properly configured**
```bash
# Verify AASA accessibility
curl -I https://example.com/.well-known/apple-app-site-association
# Expected: HTTP 2 200, Content-Type: application/json

# Validate JSON
curl https://example.com/.well-known/apple-app-site-association | python3 -m json.tool
```

**2. Use server-side redirects only**
```nginx
# ✅ GOOD: Server-side redirect
location /old-path {
    return 302 https://example.com/new-path;
}

# ❌ BAD: JavaScript redirect
location /old-path {
    default_type text/html;
    return "<script>window.location='https://example.com/new-path'</script>";
}
```

**3. Test with app uninstalled**
- Universal Link should show website gracefully
- No errors, no broken redirects
- Website should have same security as app

**4. Use secure URL scheme as fallback**
- If UL must fall back to scheme, use unique scheme name
- Example: `com.example.bank.app.v2://` instead of `bankapp://`
- Include app identifier in scheme name

**5. Validate fallback behavior**
```swift
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {

    guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
          let url = userActivity.webpageURL else {
        return false
    }

    // UL validation failed
    if !validateUniversalLink(url) {
        // Don't fall back to URL scheme automatically
        // Show user error or redirect to website
        return false
    }

    return handleUniversalLink(url)
}
```

---

## Testing Universal Links

### 1. Test from Simulator

```bash
# Universal Link on Simulator
xcrun simctl openurl booted "https://example.com/articles/123"

# Expected:
# - Opens app if configured correctly
# - Falls back to Safari if not configured
```

### 2. Test on Device

```bash
# Method 1: Using Notes app
# 1. Open Notes app
# 2. Type/paste universal link
# 3. Tap the link
# 4. Observe behavior

# Method 2: Using Safari
# 1. Open Safari
# 2. Navigate to URL
# 3. Check if app opens

# Method 3: Using URL scheme
# This is NOT universal link, but useful for comparison
# myapp://articles/123
```

### 3. Force Fallback to Safari

```bash
# Long-press link in Safari
# This forces opening in Safari even if app can handle it

# Useful for:
# - Testing fallback behavior
# - Debugging universal link issues
```

### 4. Clear Universal Links Cache

```bash
# Method 1: Delete app and reinstall
# This clears all cached associations

# Method 2: Reset Safari data
# Settings → Safari → Clear History and Website Data
# This clears some association data

# Method 3: Restart device
# Sometimes needed to clear stale associations
```

### 5. Verify AASA File

```bash
# Test AASA file accessibility
curl -I https://example.com/.well-known/apple-app-site-association

# Expected output:
# HTTP/2 200
# Content-Type: application/json (or no header)
# Content-Length: [size]

# Download and validate
curl https://example.com/.well-known/apple-app-site-association |   python3 -m json.tool

# Check for errors
curl https://example.com/.well-known/apple-app-site-association |   python3 -c "import sys, json; json.load(sys.stdin)"
echo "Exit code: $?"  # 0 = valid, non-zero = invalid
```

### 6. Test Multiple Domains

```bash
# Test all configured domains
for domain in example.com www.example.com blog.example.com; do
    echo "Testing $domain"
    curl -I "https://$domain/.well-known/apple-app-site-association"
    echo ""
done
```

## Debugging

### 1. Enable Logging

```swift
import os.log

let logger = OSLog(subsystem: "com.example.app", category: "UniversalLinks")

extension AppDelegate {
    func application(_ application: UIApplication,
                     continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
              let url = userActivity.webpageURL else {
            return false
        }
        
        os_log("Universal link received: %{public}@", log: logger, type: .debug, url.absoluteString)
        
        // Log URL components
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: true) {
            os_log("  Scheme: %{public}@", log: logger, type: .debug, components.scheme ?? "none")
            os_log("  Host: %{public}@", log: logger, type: .debug, components.host ?? "none")
            os_log("  Path: %{public}@", log: logger, type: .debug, components.path)
            if let queryItems = components.queryItems {
                os_log("  Query items: %{public}@", log: logger, type: .debug, queryItems)
            }
        }
        
        return handleUniversalLink(url)
    }
}
```

### 2. Check System Log

```bash
# View logs related to your app
log stream --predicate 'subsystem == "com.example.app"' --level debug

# Filter for universal links
log stream --predicate 'eventMessage contains "Universal link"' --level debug
```

### 3. Verify App Installation

```bash
# Check if app is installed
# On device: Settings → Safari → Open Links
# Verify your app is in the list
```

### 4. Test AASA Delivery

```bash
# Test AASA file from multiple locations
# 1. From CDN
curl https://example.com/.well-known/apple-app-site-association

# 2. From subdomain
curl https://www.example.com/.well-known/apple-app-site-association

# 3. From root domain
curl https://example.com/.well-known/apple-app-site-association

# All should return the same content
```

## OWASP MASTG References

- **MASTG-APP-ARCH-005: Universal Links**
  - Universal Links architecture
  - AASA file format

- **MASTG-APP-ANALYSIS-004: Deep Link Testing**
  - Universal Links testing
  - AASA validation

- **MASTG-APP-CODE-002: URL Handling Security**
  - URL validation
  - Input sanitization
