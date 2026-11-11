# WebView Security Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [WebView Fundamentals](#webview-fundamentals)
3. [WKWebView vs UIWebView](#wkwebview-vs-uiwebview)
4. [WKWebView Configuration](#wkwebview-configuration)
5. [JavaScript Bridge](#javascript-bridge)
6. [Content Loading](#content-loading)
7. [Security Testing](#security-testing)
8. [Common Vulnerabilities](#common-vulnerabilities)
9. [Frida WebView Hooks](#frida-webview-hooks)
10. [Secure Configuration Checklist](#secure-configuration-checklist)
11. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

WebViews are used in iOS applications to display web content within native apps. They provide powerful capabilities but also introduce significant security risks if not configured properly. This guide covers WKWebView security, JavaScript bridges, content loading, and testing methodologies.

### Why Test WebView Security?

- **Prevent XSS attacks**: Protect against cross-site scripting
- **Block unauthorized access**: Restrict file system and network access
- **Validate JavaScript bridges**: Ensure secure native-JS communication
- **Test content loading**: Verify safe handling of web content
- **Assess configuration**: Review WebView security settings

---

## WebView Fundamentals

### WebView Architecture

```
┌─────────────────────────────────────────┐
│          iOS Application                │
│  ┌───────────────────────────────────┐ │
│  │         WebView (WKWebView)       │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │    WebKit Engine            │ │ │
│  │  │  - JavaScript Engine        │ │ │
│  │  │  - Rendering Engine        │ │ │
│  │  │  - Network Stack           │ │ │
│  │  └─────────────────────────────┘ │ │
│  │                                  │ │
│  │  JavaScript Bridge               │ │
│  │  <-> iOS Native Code             │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### WebView Capabilities

| Capability | Description | Security Concern |
|------------|-------------|------------------|
| HTML/CSS/JavaScript | Full web technologies | XSS attacks |
| File Access | Load local files | Path traversal |
| Network Access | HTTP/HTTPS requests | CSRF, data exfiltration |
| JavaScript Bridge | Native-JS communication | Code injection |
| Local Storage | Cookies, localStorage | Data persistence |

---

## WKWebView vs UIWebView

### UIWebView (Deprecated)

```swift
// ❌ DO NOT USE - Deprecated in iOS 12
import UIKit

class OldViewController: UIViewController {
    var webView: UIWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        webView = UIWebView(frame: view.bounds)
        webView.loadRequest(URLRequest(url: URL(string: "https://example.com")!))
        view.addSubview(webView)
    }
}
```

**Security Issues**:
- Outdated WebKit engine
- No modern security features
- Deprecated and removed in iOS 13+

---

### WKWebView (Recommended)

```swift
// ✅ RECOMMENDED - Modern WebView
import WebKit

class ModernViewController: UIViewController, WKNavigationDelegate {
    var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        // Configure WebView
        let configuration = WKWebViewConfiguration()
        configuration.allowsInlineMediaPlayback = true
        configuration.preferences.javaScriptEnabled = true

        webView = WKWebView(frame: view.bounds, configuration: configuration)
        webView.navigationDelegate = self
        view.addSubview(webView)

        // Load URL
        if let url = URL(string: "https://example.com") {
            webView.load(URLRequest(url: url))
        }
    }

    // WKNavigationDelegate methods
    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        // Validate URL
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        // Only allow HTTPS
        guard url.scheme == "https" else {
            decisionHandler(.cancel)
            return
        }

        // Allow safe navigation
        decisionHandler(.allow)
    }
}
```

---

## WKWebView Configuration

### Security-Critical Settings

```swift
// Secure WKWebView configuration
func createSecureConfiguration() -> WKWebViewConfiguration {
    let configuration = WKWebViewConfiguration()

    // 1. JavaScript - Enable only if needed
    configuration.preferences.javaScriptEnabled = false

    // 2. File Access - Disable for security
    configuration.preferences.setValue(false, forKey: "allowFileAccessFromFileURLs")
    configuration.preferences.setValue(false, forKey: "allowUniversalAccessFromFileURLs")

    // 3. Content Security Policy
    let contentController = WKUserContentController()
    let cspScript = """
    var meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
    document.head.appendChild(meta);
    """
    let cspUserScript = WKUserScript(
        source: cspScript,
        injectionTime: .atDocumentStart,
        forMainFrameOnly: true
    )
    contentController.addUserScript(cspUserScript)
    configuration.userContentController = contentController

    // 4. Media playback
    configuration.allowsInlineMediaPlayback = false
    configuration.mediaTypesRequiringUserActionForPlayback = .all

    // 5. Data detector
    configuration.dataDetectorTypes = []

    // 6. User agent
    let customUserAgent = "MyApp/1.0"
    configuration.applicationNameForUserAgent = customUserAgent

    return configuration
}
```

### Configuration Settings Reference

| Setting | Description | Secure Value |
|---------|-------------|--------------|
| `javaScriptEnabled` | Enable JavaScript | `false` (if not needed) |
| `allowFileAccessFromFileURLs` | File access from file URLs | `false` |
| `allowUniversalAccessFromFileURLs` | Universal file access | `false` |
| `javaScriptCanOpenWindowsAutomatically` | Auto-open windows | `false` |
| `mediaTypesRequiringUserActionForPlayback` | Autoplay media | `.all` |

---

## JavaScript Bridge

### WKScriptMessageHandler

```swift
// ❌ VULNERABLE - No validation
class WeakViewController: UIViewController, WKScriptMessageHandler {
    var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        let contentController = WKUserContentController()
        contentController.add(self, name: "nativeBridge")

        let configuration = WKWebViewConfiguration()
        configuration.userContentController = contentController

        webView = WKWebView(frame: view.bounds, configuration: configuration)
        view.addSubview(webView)
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        // No validation of message!
        processCommand(message.body as? String)
    }

    func processCommand(_ command: String?) {
        // DANGEROUS: Executing commands from web!
        print("Command: \(command ?? "")")
    }
}

// JavaScript can now call:
// window.webkit.messageHandlers.nativeBridge.postMessage("malicious_command")
```

```swift
// ✅ SECURE - Validated JavaScript bridge
class SecureViewController: UIViewController, WKScriptMessageHandler {
    var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        let contentController = WKUserContentController()
        contentController.add(self, name: "nativeBridge")

        let configuration = WKWebViewConfiguration()
        configuration.userContentController = contentController

        webView = WKWebView(frame: view.bounds, configuration: configuration)
        view.addSubview(webView)
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard let body = message.body as? [String: Any],
              let command = body["command"] as? String else {
            return
        }

        // Validate command
        guard isValidCommand(command) else {
            print("Invalid command: \(command)")
            return
        }

        // Execute validated command
        executeCommand(command, parameters: body["parameters"])
    }

    private func isValidCommand(_ command: String) -> Bool {
        let allowedCommands = ["getUserInfo", "refreshData", "shareContent"]
        return allowedCommands.contains(command)
    }

    private func executeCommand(_ command: String, parameters: Any?) {
        switch command {
        case "getUserInfo":
            // Safe to execute
            break
        case "refreshData":
            // Safe to execute
            break
        case "shareContent":
            // Safe to execute
            break
        default:
            // Unknown command - ignore
            break
        }
    }
}
```

### Calling JavaScript from Native

```swift
// Execute JavaScript in WebView
func executeJavaScript(_ script: String) {
    webView.evaluateJavaScript(script) { (result, error) in
        if let error = error {
            print("JavaScript error: \(error)")
        } else {
            print("JavaScript result: \(result ?? "")")
        }
    }
}

// Usage
executeJavaScript("alert('Hello from native!')")
executeJavaScript("document.title = 'Modified by native'")
```

---

## Content Loading

### Loading Local HTML

```swift
// ❌ VULNERABLE - Loading local HTML without validation
func loadLocalHTML() {
    if let path = Bundle.main.path(forResource: "page", ofType: "html") {
        let url = URL(fileURLWithPath: path)
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }
}

// ✅ SECURE - Validate file path
func loadLocalHTMLSecurely() {
    guard let path = Bundle.main.path(forResource: "page", ofType: "html") else {
        return
    }

    // Ensure file is in app bundle
    let bundleURL = Bundle.main.bundleURL
    let fileURL = URL(fileURLWithPath: path)

    guard fileURL.path.hasPrefix(bundleURL.path) else {
        print("File outside bundle!")
        return
    }

    // Load with limited read access
    webView.loadFileURL(fileURL, allowingReadAccessTo: bundleURL)
}
```

### Loading Remote Content

```swift
// ❌ VULNERABLE - No URL validation
func loadRemoteContent(urlString: String) {
    if let url = URL(string: urlString) {
        webView.load(URLRequest(url: url))
    }
}

// ✅ SECURE - URL validation
func loadRemoteContentSecurely(urlString: String) -> Bool {
    guard let url = URL(string: urlString) else {
        return false
    }

    // Only allow HTTPS
    guard url.scheme == "https" else {
        print("Only HTTPS URLs allowed!")
        return false
    }

    // Validate domain whitelist
    let allowedDomains = ["example.com", "api.example.com"]
    guard let host = url.host,
          allowedDomains.contains(host) else {
        print("Domain not in whitelist!")
        return false
    }

    // Load URL
    webView.load(URLRequest(url: url))
    return true
}
```

### Loading HTML String

```swift
// ❌ VULNERABLE - No sanitization
func loadHTMLString(_ html: String) {
    webView.loadHTMLString(html, baseURL: nil)
}

// ✅ SECURE - Sanitize HTML
func loadHTMLStringSecurely(_ html: String) {
    // Use HTML sanitization library
    let sanitizedHTML = sanitizeHTML(html)

    // Set secure base URL
    let baseURL = URL(string: "https://example.com")

    webView.loadHTMLString(sanitizedHTML, baseURL: baseURL)
}

// Simple HTML sanitization (use proper library in production)
func sanitizeHTML(_ html: String) -> String {
    var sanitized = html

    // Remove script tags
    sanitized = sanitized.replacingOccurrences(
        of: "<script[^>]*>.*?</script>",
        with: "",
        options: .regularExpression
    )

    // Remove on* event handlers
    sanitized = sanitized.replacingOccurrences(
        of: "\\son[a-z]+\\s*=",
        with: "",
        options: .regularExpression
    )

    return sanitized
}
```

---

## Security Testing

### XSS Testing

```text
# Test XSS via URL parameter
# Load: https://example.com/?param=<script>alert(1)</script>

# Test XSS via HTML injection
# Load: "<img src=x onerror=alert(1)>"

# Test XSS via JavaScript bridge
window.webkit.messageHandlers.nativeBridge.postMessage({
    command: "alert(1)"
});

# Test with Frida
frida -U -l webview-xss-scanner-ios.js -f com.example.app
```

### File Access Testing

```bash
# Test file access from web
# JavaScript: fetch("file:///etc/passwd")

# Test with Frida
# NOTE: `webview-file-access.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
frida -U -l webview-file-access.js -f com.example.app
```

### JavaScript Bridge Testing

```javascript
// Test JavaScript bridge functions
// List all message handlers
Object.getOwnPropertyNames(window.webkit.messageHandlers)

// Test each handler
window.webkit.messageHandlers.nativeBridge.postMessage("test")

// Test with malformed data
window.webkit.messageHandlers.nativeBridge.postMessage({"command": "malicious"})
```

---

## Common Vulnerabilities

### 1. XSS via URL Parameter

```swift
// ❌ VULNERABLE
func loadWebPage(urlString: String) {
    let html = """
    <html>
        <body>
            <div id="content"></div>
            <script>
                document.getElementById('content').innerHTML = '\(urlString)';
            </script>
        </body>
    </html>
    """
    webView.loadHTMLString(html, baseURL: nil)
}

// ✅ SECURE
func loadWebPageSecurely(urlString: String) {
    let sanitized = urlString.replacingOccurrences(of: "<", with: "&lt;")
                                   .replacingOccurrences(of: ">", with: "&gt;")
                                   .replacingOccurrences(of: "'", with: "&#39;")
                                   .replacingOccurrences(of: "\"", with: "&quot;")

    let html = """
    <html>
        <body>
            <div id="content"></div>
            <script>
                document.getElementById('content').textContent = '\(sanitized)';
            </script>
        </body>
    </html>
    """
    webView.loadHTMLString(html, baseURL: nil)
}
```

---

### 2. File Path Traversal

```swift
// ❌ VULNERABLE
func loadLocalFile(path: String) {
    let fileURL = URL(fileURLWithPath: path)
    webView.loadFileURL(fileURL, allowingReadAccessTo: fileURL.deletingLastPathComponent())
}

// ✅ SECURE
func loadLocalFileSecurely(path: String) {
    var normalizedPath = (path as NSString).standardizingPath

    // Prevent path traversal
    if normalizedPath.contains("..") {
        print("Path traversal detected!")
        return
    }

    // Ensure file is in app bundle
    let bundlePath = Bundle.main.bundlePath
    if !normalizedPath.hasPrefix(bundlePath) {
        print("File outside bundle!")
        return
    }

    let fileURL = URL(fileURLWithPath: normalizedPath)
    webView.loadFileURL(fileURL, allowingReadAccessTo: Bundle.main.bundleURL)
}
```

---

### 3. JavaScript Bridge Injection

```swift
// ❌ VULNERABLE - No validation
func handleJavaScriptMessage(_ message: [String: Any]) {
    let command = message["command"] as? String ?? ""

    switch command {
    case "deleteUser":
        deleteUser()  // Anyone can delete users!
    case "updateSettings":
        updateSettings(message["settings"] as? [String: Any])
    default:
        break
    }
}

// ✅ SECURE - Strict validation
func handleJavaScriptMessageSecurely(_ message: [String: Any]) {
    guard let command = message["command"] as? String,
          isValidCommand(command) else {
        print("Invalid command")
        return
    }

    // Additional validation for sensitive commands
    if command == "deleteUser" {
        guard hasUserPermission() else {
            print("Permission denied")
            return
        }
    }

    executeCommand(command, parameters: message)
}

private func isValidCommand(_ command: String) -> Bool {
    let allowedCommands = [
        "getUserInfo",
        "updateSettings",
        "deleteUser"  // But requires permission
    ]
    return allowedCommands.contains(command)
}
```

---

## Frida WebView Hooks

### Hooking WKWebView

```javascript
// webview-hook.js - Hook WKWebView
if (ObjC.available) {
    console.log("[*] Hooking WKWebView...");

    var WKWebView = ObjC.classes.WKWebView;

    // Hook loadRequest:
    Interceptor.attach(WKWebView["- loadRequest:"], {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            var url = request.URL();

            console.log("\n[+] WKWebView loading request:");
            console.log("  URL:", url.absoluteURL().toString());
            console.log("  HTTP Method:", request.HTTPMethod());
            console.log("  Headers:", request.allHTTPHeaderFields());
        }
    });

    // Hook loadHTMLString:baseURL:
    Interceptor.attach(WKWebView["- loadHTMLString:baseURL:"], {
        onEnter: function(args) {
            var html = ObjC.Object(args[2]);
            var baseURL = ObjC.Object(args[3]);

            console.log("\n[+] WKWebView loading HTML string:");
            console.log("  Base URL:", baseURL ? baseURL.absoluteURL().toString() : "null");
            console.log("  HTML length:", html.length());
            console.log("  HTML preview:", html.substringToRange_(NSMakeRange(0, 100)));
        }
    });

    // Hook evaluateJavaScript:completionHandler:
    Interceptor.attach(WKWebView["- evaluateJavaScript:completionHandler:"], {
        onEnter: function(args) {
            var script = ObjC.Object(args[2]);

            console.log("\n[+] WKWebView executing JavaScript:");
            console.log("  Script:", script);
        }
    });

    console.log("[*] WKWebView hooks installed");
}
```

### Hooking JavaScript Bridge

```javascript
// jsbridge-hook.js - Hook JavaScript bridge
if (ObjC.available) {
    console.log("[*] Hooking JavaScript bridge...");

    var WKUserContentController = ObjC.classes.WKUserContentController;

    // Hook addScriptMessageHandler:name:
    Interceptor.attach(WKUserContentController["- addScriptMessageHandler:name:"], {
        onEnter: function(args) {
            var handler = ObjC.Object(args[2]);
            var name = ObjC.Object(args[3]);

            console.log("\n[+] Adding script message handler:");
            console.log("  Name:", name);
            console.log("  Handler class:", handler.$className);
        }
    });

    // Hook userContentController:didReceiveScriptMessage:
    // (This is in the delegate class, not WKUserContentController)
    // Find your delegate class and hook the method

    console.log("[*] JavaScript bridge hooks installed");
}
```

---

## Secure Configuration Checklist

### Pre-Launch Checklist

```markdown
## WebView Security Checklist

### Configuration
- [ ] Using WKWebView (not UIWebView)
- [ ] JavaScript enabled only if necessary
- [ ] File access disabled
- [ ] Universal access disabled
- [ ] JavaScript bridge validated
- [ ] Content Security Policy implemented
- [ ] Data detectors disabled (if not needed)
- [ ] Autoplay media requires user action

### Content Loading
- [ ] URL validation for remote content
- [ ] HTTPS only for remote content
- [ ] Domain whitelist implemented
- [ ] Local file path sanitized
- [ ] HTML content sanitized
- [ ] Base URL set appropriately

### JavaScript Bridge
- [ ] Message handler names randomized
- [ ] Commands whitelisted
- [ ] Parameters validated
- [ ] Sensitive operations require authentication
- [ ] Error handling implemented
- [ ] Logging disabled in production

### Testing
- [ ] XSS testing completed
- [ ] File access testing completed
- [ ] JavaScript bridge testing completed
- [ ] Content Security Policy tested
- [ ] Network interception tested
```

### Secure Template

```swift
import WebKit

class SecureWebViewViewController: UIViewController, WKNavigationDelegate, WKScriptMessageHandler {

    private var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()
        setupWebView()
    }

    private func setupWebView() {
        let configuration = createSecureConfiguration()
        webView = WKWebView(frame: view.bounds, configuration: configuration)
        webView.navigationDelegate = self

        view.addSubview(webView)

        // Load initial content
        loadSecureContent()
    }

    private func createSecureConfiguration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()

        // 1. Security settings
        configuration.preferences.javaScriptEnabled = true  // Only if needed
        configuration.preferences.setValue(false, forKey: "allowFileAccessFromFileURLs")
        configuration.preferences.setValue(false, forKey: "allowUniversalAccessFromFileURLs")
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false

        // 2. Content Security Policy
        let contentController = WKUserContentController()
        let cspScript = createCSPScript()
        let cspUserScript = WKUserScript(
            source: cspScript,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        contentController.addUserScript(cspUserScript)

        // 3. JavaScript bridge
        contentController.add(self, name: "secureBridge")

        configuration.userContentController = contentController

        // 4. Media settings
        configuration.allowsInlineMediaPlayback = false
        configuration.mediaTypesRequiringUserActionForPlayback = .all

        return configuration
    }

    private func createCSPScript() -> String {
        return """
        var meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = "default-src 'self'; script-src 'self' 'nonce-random'; style-src 'self' 'nonce-random';";
        document.head.appendChild(meta);
        """
    }

    private func loadSecureContent() {
        // Load from secure source
        guard let url = URL(string: "https://example.com") else {
            return
        }

        webView.load(URLRequest(url: url))
    }

    // MARK: - WKNavigationDelegate

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        // Validate URL
        if isValidURL(url) {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
        }
    }

    private func isValidURL(_ url: URL) -> Bool {
        // 1. Only HTTPS
        guard url.scheme == "https" else {
            return false
        }

        // 2. Whitelist domains
        let allowedDomains = ["example.com", "api.example.com"]
        guard let host = url.host,
              allowedDomains.contains(host) else {
            return false
        }

        // 3. No path traversal
        guard !url.path.contains("..") else {
            return false
        }

        return true
    }

    // MARK: - WKScriptMessageHandler

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard let body = message.body as? [String: Any],
              let command = body["command"] as? String else {
            return
        }

        // Validate command
        guard isValidCommand(command) else {
            print("Invalid command: \(command)")
            return
        }

        // Execute secure command
        executeSecureCommand(command, parameters: body)
    }

    private func isValidCommand(_ command: String) -> Bool {
        let allowedCommands = [
            "getUserInfo",
            "refreshData"
        ]
        return allowedCommands.contains(command)
    }

    private func executeSecureCommand(_ command: String, parameters: [String: Any]?) {
        switch command {
        case "getUserInfo":
            getUserInfo(parameters)
        case "refreshData":
            refreshData(parameters)
        default:
            break
        }
    }

    // MARK: - Commands

    private func getUserInfo(_ parameters: [String: Any]?) {
        // Implement secure user info retrieval
    }

    private func refreshData(_ parameters: [String: Any]?) {
        // Implement secure data refresh
    }
}
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | WebView Context |
|---------------|-------|-----------------|
| MASTG-APP-SEC-0025 | WebView Security | WebView configuration |
| MASTG-TEST-0065 | WebView Testing | XSS, content loading |
| MASTG-APP-SEC-0015 | Inter-Process Communication | JavaScript bridge |
| MASTG-TEST-0080 | JavaScript Bridge Testing | Bridge validation |

---

## Summary

This guide covered:
- WebView fundamentals and architecture
- WKWebView vs UIWebView (WKWebView is mandatory)
- Secure WKWebView configuration
- JavaScript bridge security
- Content loading (local and remote)
- Security testing methodologies
- Common vulnerabilities (XSS, file access, bridge injection)
- Frida hooking for WebView analysis
- Comprehensive security checklist

WebViews are powerful but require careful configuration. Always use WKWebView, implement proper validation, and test thoroughly for XSS and injection vulnerabilities.

---

## References

### Official Documentation
- Apple WKWebView: https://developer.apple.com/documentation/webkit/wkwebview
- Content Security Policy: https://developer.apple.com/documentation/webkit/disabling_content_security_policy
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- iOS Security Guide: https://support.apple.com/guide/security/
- WebKit Security: https://webkit.org/security/
- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** iOS development knowledge, Swift, WebView concepts
