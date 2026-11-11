# iOS IPC (Inter-Process Communication) Security Guide

## Table of Contents

1. [Overview](#overview)
2. [IPC Mechanisms](#ipc-mechanisms)
3. [URL Schemes](#url-schemes)
4. [Universal Links](#universal-links)
5. [Pasteboard](#pasteboard)
6. [App Groups](#app-groups)
7. [XPC Services](#xpc-services)
8. [NSXPCConnection](#nsxpcconnection)
9. [Testing IPC](#testing-ipc)
10. [Common Vulnerabilities](#common-vulnerabilities)
11. [Frida XPC Tracing](#frida-xpc-tracing)
12. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

iOS provides multiple Inter-Process Communication (IPC) mechanisms that allow apps to communicate with each other and with system services. This guide covers URL schemes, Universal Links, pasteboard, App Groups, and XPC services, along with security implications and testing methodologies.

### Why Test IPC Security?

- **Validate data flow**: Ensure secure inter-app communication
- **Test injection attacks**: Check for parameter manipulation
- **Verify access controls**: Confirm proper isolation and restrictions
- **Identify leakage risks**: Find data exposure through IPC
- **Assess implementation**: Review security of IPC mechanisms

---

## IPC Mechanisms

### iOS IPC Comparison

| Mechanism | Security Level | Use Case | Isolation |
|-----------|---------------|----------|-----------|
| URL Schemes | Medium | Deep linking | App-level |
| Universal Links | High | Web-to-app | Domain-validated |
| Pasteboard | Low | Copy/paste | User-controlled |
| App Groups | Medium | Data sharing | Group-restricted |
| XPC Services | High | Service communication | Process-isolated |
| Notifications | Low | Event broadcast | System-wide |

### IPC Architecture

```
┌─────────────────────────────────────────────────┐
│              iOS IPC Layer                     │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐          │
│  │ URL Schemes  │  │Universal Links│          │
│  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐          │
│  │  Pasteboard  │  │ App Groups   │          │
│  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐                             │
│  │ XPC Services │                             │
│  └──────────────┘                             │
├─────────────────────────────────────────────────┤
│           OS Kernel (Darwin)                  │
└─────────────────────────────────────────────────┘
```

---

## URL Schemes

### Fundamentals

```swift
// Registering URL scheme (Info.plist)
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>

// Handling URL scheme
func application(
    _ app: UIApplication,
    open url: URL,
    options: [UIApplication.OpenURLOptionsKey : Any] = [:]
) -> Bool {
    handleURL(url)
    return true
}
```

### Security Issues

#### Issue 1: Parameter Injection

```swift
// ❌ VULNERABLE - No validation
func handleURL(_ url: URL) {
    if let userId = url.queryValue(for: "userId") {
        loadUserProfile(userId)  // No validation!
    }
}

// ✅ SECURE - Validate parameters
func handleURL(_ url: URL) -> Bool {
    guard let userId = url.queryValue(for: "userId"),
          isValidUserId(userId) else {
        return false
    }

    loadUserProfile(userId)
    return true
}

func isValidUserId(_ id: String) -> Bool {
    let regex = "^[0-9]{1,10}$"
    return NSPredicate(format: "SELF MATCHES %@", regex).evaluate(with: id)
}
```

#### Issue 2: Sensitive Actions

```swift
// ❌ VULNERABLE - Payment via URL
func handlePaymentURL(_ url: URL) {
    if let amount = url.queryValue(for: "amount"),
       let recipient = url.queryValue(for: "recipient") {
        initiatePayment(amount: amount, to: recipient)
    }
}

// ✅ SECURE - URL only navigates to UI
func handlePaymentURL(_ url: URL) {
    if let amount = url.queryValue(for: "amount") {
        navigateToPaymentUI(amount: amount)
        // User must confirm in UI
    }
}
```

### Testing URL Schemes

```bash
# Find registered schemes
plutil -p Info.plist | grep -A5 "CFBundleURLSchemes"

# Test basic opening
xcrun simctl openurl booted "myapp://"

# Test with parameters
xcrun simctl openurl booted "myapp://profile?user=123"

# Test injection
xcrun simctl openurl booted "myapp://?param=<script>alert(1)</script>"
xcrun simctl openurl booted "myapp://?param=1' OR '1'='1"

# Test with Frida
frida -U -l url-scheme-monitor.js -f com.example.app
```

---

## Universal Links

### Fundamentals

```swift
// Registering Universal Links (Info.plist)
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:myapp.example.com</string>
</array>

// Hosting AASA file
// https://myapp.example.com/.well-known/apple-app-site-association
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

// Handling Universal Links
func application(
    _ application: UIApplication,
    continue userActivity: NSUserActivity,
    restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void
) -> Bool {
    if let url = userActivity.webpageURL {
        handleUniversalLink(url)
        return true
    }
    return false
}
```

### Security Issues

#### Issue 1: HTTP Fallback

```swift
// ❌ VULNERABLE - Falls back to HTTP
func handleUniversalLink(_ url: URL) {
    if url.scheme == "https" {
        processSecureLink(url)
    } else {
        // Fallback to HTTP - INSECURE!
        processInsecureLink(url)
    }
}

// ✅ SECURE - Only HTTPS
func handleUniversalLink(_ url: URL) -> Bool {
    guard url.scheme == "https",
          url.host == "myapp.example.com" else {
        return false
    }

    processSecureLink(url)
    return true
}
```

#### Issue 2: Path Validation

```swift
// ❌ VULNERABLE - No path validation
func handleUniversalLink(_ url: URL) {
    // Any path is accepted
    let action = url.path
    performAction(action)
}

// ✅ SECURE - Validate paths
func handleUniversalLink(_ url: URL) -> Bool {
    let allowedPaths = ["/home", "/profile", "/settings"]
    guard allowedPaths.contains(url.path) else {
        return false
    }

    let action = url.path
    performAction(action)
    return true
}
```

### Testing Universal Links

```bash
# Fetch AASA file
curl https://myapp.example.com/.well-known/apple-app-site-association

# Test Universal Link
xcrun simctl openurl booted "https://myapp.example.com/home"

# Test path validation
xcrun simctl openurl booted "https://myapp.example.com/../../etc/passwd"

# Test HTTP (should fail)
xcrun simctl openurl booted "http://myapp.example.com/home"

# Test with Frida
frida -U -l url-scheme-monitor.js -f com.example.app
```

---

## Pasteboard

### Fundamentals

```swift
// Reading from pasteboard
let pasteboard = UIPasteboard.general
let text = pasteboard.string

// Writing to pasteboard
UIPasteboard.general.string = "Hello, World!"

// Monitoring pasteboard changes
class PasteboardObserver: NSObject {
    var observer: NSObjectProtocol?

    func startObserving() {
        observer = NotificationCenter.default.addObserver(
            forName: UIPasteboard.changedNotification,
            object: UIPasteboard.general,
            queue: .main
        ) { [weak self] notification in
            self?.handlePasteboardChange()
        }
    }

    func handlePasteboardChange() {
        let text = UIPasteboard.general.string
        print("Pasteboard changed: \(text ?? "")")
    }
}
```

### Security Issues

#### Issue 1: Unauthorized Access

```swift
// ❌ VULNERABLE - Reads pasteboard without user consent
class MyViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

        // Automatically reads pasteboard on load
        if let text = UIPasteboard.general.string {
            processPastedText(text)
        }
    }
}

// ✅ SECURE - Requires user action
class MyViewController: UIViewController {
    @IBAction func pasteButtonTapped(_ sender: UIButton) {
        // Only read when user explicitly requests
        if let text = UIPasteboard.general.string {
            processPastedText(text)
        }
    }
}
```

#### Issue 2: Background Access

```swift
// ❌ VULNERABLE - Reads pasteboard in background
class BackgroundReader: NSObject {
    func readInBackground() {
        // Reading pasteboard when app not in focus
        let text = UIPasteboard.general.string
        exfiltrateData(text)  // Sends to attacker!
    }
}

// ✅ SECURE - Only read when active
class ForegroundReader: NSObject {
    func readInForeground() {
        // Check if app is active
        guard UIApplication.shared.applicationState == .active else {
            return
        }

        let text = UIPasteboard.general.string
        processText(text)
    }
}
```

### Testing Pasteboard

```bash
# Set pasteboard content
echo "test string" | pbcopy

# Monitor pasteboard with Objection
objection -g com.example.app explore
ios pasteboard monitor

# Test pasteboard reading
# 1. Copy text to pasteboard
# 2. Switch to app
# 3. Check if app reads pasteboard immediately

# Test with Frida
frida -U -l pasteboard-monitor.js -f com.example.app
```

### Pasteboard Hooking with Frida

```javascript
// pasteboard-hook.js - Hook pasteboard operations
if (ObjC.available) {
    console.log("[*] Hooking pasteboard...");

    var UIPasteboard = ObjC.classes.UIPasteboard;

    // Hook string getter
    Interceptor.attach(UIPasteboard["- string"], {
        onEnter: function(args) {
            console.log("\n[+] Pasteboard read");
            console.log("  Time:", new Date());
        },
        onLeave: function(retval) {
            var string = ObjC.Object(retval);
            console.log("  Content:", string);
        }
    });

    // Hook string setter
    Interceptor.attach(UIPasteboard["- setString:"], {
        onEnter: function(args) {
            var string = ObjC.Object(args[2]);
            console.log("\n[+] Pasteboard write");
            console.log("  Content:", string);
            console.log("  Time:", new Date());
        }
    });

    console.log("[*] Pasteboard hooks installed");
}
```

---

## App Groups

### Fundamentals

```swift
// Configuring App Groups (Entitlements)
// App 1 Entitlements
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.example.shared</string>
</array>

// App 2 Entitlements
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.example.shared</string>
</array>

// Shared UserDefaults
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
sharedDefaults?.set("shared_value", forKey: "shared_key")

// Shared file container
let sharedContainerURL = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.shared")
let fileURL = sharedContainerURL?.appendingPathComponent("shared_data.txt")

// Writing to shared file
try? "shared data".write(to: fileURL!, atomically: true, encoding: .utf8)

// Reading from shared file
let sharedData = try? String(contentsOf: fileURL!, encoding: .utf8)
```

### Security Issues

#### Issue 1: Sensitive Data in Shared Storage

```swift
// ❌ VULNERABLE - Sensitive data in shared container
func storeSensitiveData() {
    let sharedContainer = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.shared")

    let token = "sensitive_auth_token"
    try? token.write(
        to: sharedContainer!.appendingPathComponent("token.txt"),
        atomically: true,
        encoding: .utf8
    )
}

// ✅ SECURE - Use Keychain for sensitive data
func storeSensitiveData() {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app",
        kSecValueData as String: "sensitive_auth_token".data(using: .utf8)!,
        kSecAttrAccessGroup as String: "TEAMID.com.example.shared"
    ]

    SecItemAdd(query as CFDictionary, nil)
}
```

#### Issue 2: No Access Control

```swift
// ❌ VULNERABLE - No access control in shared defaults
class SharedDataManager {
    let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")

    func setValue(_ value: Any, forKey key: String) {
        // Any app in group can set any key!
        sharedDefaults?.set(value, forKey: key)
    }

    func getValue(forKey key: String) -> Any? {
        // Any app in group can read any key!
        return sharedDefaults?.object(forKey: key)
    }
}

// ✅ SECURE - Implement access control
class SecureSharedDataManager {
    let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
    let appId = "com.example.app1"

    func setValue(_ value: Any, forKey key: String) {
        // Prefix key with app ID
        let fullKey = "\(appId).\(key)"
        sharedDefaults?.set(value, forKey: fullKey)
    }

    func getValue(forKey key: String) -> Any? {
        // Only read keys prefixed with app ID
        let fullKey = "\(appId).\(key)"
        return sharedDefaults?.object(forKey: fullKey)
    }

    func setPublicValue(_ value: Any, forKey key: String) {
        // Mark as public for cross-app access
        sharedDefaults?.set(value, forKey: "public.\(key)")
    }
}
```

### Testing App Groups

```bash
# Find shared containers
ssh root@DEVICE_IP
find /var/mobile/Containers/Shared -name "*.plist"

# Read shared defaults
defaults read /var/mobile/Containers/Shared/AppGroup/...

# Check App Groups entitlements
plutil -p Payload/Example.app/entitlements.plist | grep application-groups

# Test with Frida
frida -U -l app-groups-inspector.js -f com.example.app
```

### App Groups Hooking with Frida

```javascript
// app-groups-hook.js - Hook shared defaults
if (ObjC.available) {
    console.log("[*] Hooking shared defaults...");

    var UserDefaults = ObjC.classes.NSUserDefaults;

    // Hook initializer with suite name
    Interceptor.attach(UserDefaults["- initWithSuiteName:"], {
        onEnter: function(args) {
            var suiteName = ObjC.Object(args[2]);
            console.log("\n[+] Shared defaults initialized");
            console.log("  Suite:", suiteName);
        }
    });

    // Hook setObject:forKey:
    Interceptor.attach(UserDefaults["- setObject:forKey:"], {
        onEnter: function(args) {
            var value = ObjC.Object(args[2]);
            var key = ObjC.Object(args[3]);

            // Check if this is a shared defaults
            var defaults = ObjC.Object(args[0]);
            var suiteName = defaults.suiteName();

            if (suiteName) {
                console.log("\n[+] Shared defaults write");
                console.log("  Suite:", suiteName);
                console.log("  Key:", key);
                console.log("  Value:", value);
            }
        }
    });

    console.log("[*] Shared defaults hooks installed");
}
```

---

## XPC Services

### Fundamentals

```swift
// XPC Service Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.platform.xpc</string>
    <key>NSExtensionPrincipalClass</key>
    <string>MyXPCService</string>
</dict>

// XPC Service Implementation
class MyXPCService: NSObject, XPCServiceProtocol {
    func processRequest(_ request: String, reply: @escaping (String) -> Void) {
        // Process request
        let response = "Processed: " + request
        reply(response)
    }
}

// Client connecting to XPC Service
class XPCClient {
    private var connection: NSXPCConnection?

    func connectToService() {
        let serviceListener = NSXPCListener.service()!
        let endpoint = serviceListener.endpoint

        connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection?.remoteObjectInterface = NSXPCInterface(
            with: XPCServiceProtocol.self
        )

        connection?.resume()
    }

    func sendRequest(_ request: String, completion: @escaping (String) -> Void) {
        let proxy = connection?.remoteObjectProxy as? XPCServiceProtocol
        proxy?.processRequest(request, reply: completion)
    }
}
```

### XPC Protocol Definition

```swift
// XPCServiceProtocol.swift
@objc protocol XPCServiceProtocol {
    func processRequest(_ request: String, reply: @escaping (String) -> Void)
    func authenticate(user: String, password: String, reply: @escaping (Bool) -> Void)
    func getFile(path: String, reply: @escaping (Data?) -> Void)
}
```

### Security Issues

#### Issue 1: No Authentication

```swift
// ❌ VULNERABLE - No authentication in XPC service
class MyXPCService: NSObject, XPCServiceProtocol {
    func getFile(path: String, reply: @escaping (Data?) -> Void) {
        // Any client can request any file!
        let data = try? Data(contentsOf: URL(fileURLWithPath: path))
        reply(data)
    }
}

// ✅ SECURE - Implement authentication
class SecureXPCService: NSObject, XPCServiceProtocol {
    private var authenticatedClients = Set<UUID>()

    func authenticate(user: String, password: String, reply: @escaping (Bool) -> Void) {
        // Validate credentials
        let isValid = validateCredentials(user: user, password: password)

        if isValid {
            let clientId = UUID()
            authenticatedClients.insert(clientId)
            // Return client ID to use for future requests
        }

        reply(isValid)
    }

    func getFile(path: String, reply: @escaping (Data?) -> Void) {
        // Only authenticated clients can access files
        // (Need to pass client ID in real implementation)

        let sanitizedPath = sanitizePath(path)
        let data = try? Data(contentsOf: URL(fileURLWithPath: sanitizedPath))
        reply(data)
    }
}
```

#### Issue 2: Path Traversal

```swift
// ❌ VULNERABLE - Path traversal in XPC service
class FileXPCService: NSObject, XPCServiceProtocol {
    func getFile(path: String, reply: @escaping (Data?) -> Void) {
        // No path validation!
        let data = try? Data(contentsOf: URL(fileURLWithPath: path))
        reply(data)
    }
}

// ✅ SECURE - Path sanitization
class SecureFileXPCService: NSObject, XPCServiceProtocol {
    func getFile(path: String, reply: @escaping (Data?) -> Void) {
        // Sanitize path
        let sanitizedPath = sanitizePath(path)

        // Restrict to allowed directory
        let allowedDir = "/var/mobile/Containers/Data/Application/..."

        guard sanitizedPath.hasPrefix(allowedDir) else {
            reply(nil)
            return
        }

        let data = try? Data(contentsOf: URL(fileURLWithPath: sanitizedPath))
        reply(data)
    }

    private func sanitizePath(_ path: String) -> String {
        // Remove path traversal attempts
        var sanitized = path
        sanitized = sanitized.replacingOccurrences(of: "../", with: "")
        sanitized = sanitized.replacingOccurrences(of: "./", with: "")
        sanitized = sanitized.replacingOccurrences(of: "~", with: "")

        return sanitized
    }
}
```

---

## NSXPCConnection

### Fundamentals

```swift
// Creating NSXPCConnection
let connection = NSXPCConnection(
    machServiceName: "com.example.myservice",
    options: []
)

connection.remoteObjectInterface = NSXPCInterface(
    with: MyProtocol.self
)

connection.invalidationHandler = {
    print("Connection invalidated")
}

connection.resume()

// Using the proxy
let proxy = connection.remoteObjectProxy as? MyProtocol
proxy?.doSomething { result in
    print("Result: \(result)")
}

// Clean up
connection.invalidate()
```

### NSXPCConnection Security

```swift
// Secure XPC connection
class SecureXPCClient {
    private var connection: NSXPCConnection?
    private var authenticationToken: String?

    func connect() {
        let connection = NSXPCConnection(
            machServiceName: "com.example.secure.service",
            options: .privileged
        )

        connection.remoteObjectInterface = NSXPCInterface(
            with: SecureProtocol.self
        )

        // Add security attributes
        connection.remoteObjectInterface?.setInterface(
            SecureProtocol.self,
            for: Optional<MyProtocol>.self,
            argumentIndex: 0,
            ofReply: 0
        )

        self.connection = connection
        connection.resume()

        // Authenticate
        authenticate()
    }

    private func authenticate() {
        let proxy = connection?.remoteObjectProxy as? SecureProtocol
        proxy?.authenticate(token: "secure_token") { success in
            if success {
                print("Authentication successful")
            } else {
                print("Authentication failed")
                self.connection?.invalidate()
            }
        }
    }

    func makeSecureRequest(_ request: String, completion: @escaping (String) -> Void) {
        guard let proxy = connection?.remoteObjectProxy as? SecureProtocol else {
            completion("Connection not established")
            return
        }

        proxy.processRequest(request, reply: completion)
    }
}
```

---

## Testing IPC

### Comprehensive Testing Script

```bash
#!/bin/bash
# ipc-test.sh - Comprehensive IPC testing

APP_BUNDLE_ID="com.example.app"

echo "[*] Starting IPC testing for $APP_BUNDLE_ID"

# 1. Test URL Schemes
echo "\n[+] Testing URL Schemes..."
plutil -p Info.plist | grep -A5 "CFBundleURLSchemes"

# Test each scheme
xcrun simctl openurl booted "myapp://"
xcrun simctl openurl booted "myapp://?param=<script>alert(1)</script>"

# 2. Test Universal Links
echo "\n[+] Testing Universal Links..."
curl https://myapp.example.com/.well-known/apple-app-site-association

xcrun simctl openurl booted "https://myapp.example.com/home"

# 3. Test Pasteboard
echo "\n[+] Testing Pasteboard..."
echo "test content" | pbcopy

# Start pasteboard monitoring
objection -g $APP_BUNDLE_ID explore -s "ios pasteboard monitor" &
sleep 2

# 4. Test App Groups
echo "\n[+] Testing App Groups..."
plutil -p Payload/Example.app/entitlements.plist | grep application-groups

# Find shared containers
find /var/mobile/Containers/Shared -name "*.plist"

# 5. Test XPC Services
echo "\n[+] Testing XPC Services..."
plutil -p Payload/Example.app/Info.plist | grep "com.apple.platform.xpc"

echo "\n[*] IPC testing complete"
```

### Frida IPC Hooking Script

```javascript
// ipc-hook.js - Comprehensive IPC hooking
if (ObjC.available) {
    console.log("[*] Hooking IPC mechanisms...");

    // 1. Hook URL schemes
    var AppDelegate = ObjC.classes.AppDelegate;
    Interceptor.attach(AppDelegate["- application:open:options:"], {
        onEnter: function(args) {
            var url = ObjC.Object(args[2]);
            console.log("\n[+] URL Opened:");
            console.log("  Scheme:", url.scheme());
            console.log("  Host:", url.host());
            console.log("  Path:", url.path());
            console.log("  Query:", url.query());
        }
    });

    // 2. Hook pasteboard
    var UIPasteboard = ObjC.classes.UIPasteboard;
    Interceptor.attach(UIPasteboard["- string"], {
        onEnter: function(args) {
            console.log("\n[+] Pasteboard read");
        },
        onLeave: function(retval) {
            var string = ObjC.Object(retval);
            console.log("  Content:", string);
        }
    });

    // 3. Hook shared defaults
    var UserDefaults = ObjC.classes.NSUserDefaults;
    Interceptor.attach(UserDefaults["- initWithSuiteName:"], {
        onEnter: function(args) {
            var suiteName = ObjC.Object(args[2]);
            console.log("\n[+] Shared defaults initialized");
            console.log("  Suite:", suiteName);
        }
    });

    // 4. Hook XPC connection
    var NSXPCConnection = ObjC.classes.NSXPCConnection;
    Interceptor.attach(NSXPCConnection["- initWithListenerEndpoint:"], {
        onEnter: function(args) {
            console.log("\n[+] XPC connection created");
        }
    });

    console.log("[*] IPC hooks installed");
}
```

---

## Common Vulnerabilities

### 1. Injection Attacks

**URL Schemes**:
```
myapp://?param=<script>alert(1)</script>
myapp://?param=1' OR '1'='1
myapp://?param=../../etc/passwd
```

**Universal Links**:
```
https://myapp.example.com/../../etc/passwd
https://myapp.example.com/..<script>alert(1)</script>
```

**Pasteboard**:
```
JavaScript:alert(document.cookie)
../../etc/passwd
```

---

### 2. Authorization Bypass

```swift
// ❌ VULNERABLE - No authorization check
class MyXPCService: NSObject, MyProtocol {
    func performAdminAction() {
        // Anyone can call this!
        executeAdminTask()
    }
}

// ✅ SECURE - Check authorization
class SecureXPCService: NSObject, MyProtocol {
    func performAdminAction() {
        guard isAuthorized() else {
            return
        }
        executeAdminTask()
    }

    private func isAuthorized() -> Bool {
        // Verify client has admin privileges
        return false
    }
}
```

---

### 3. Data Leakage

```swift
// ❌ VULNERABLE - Leaks data through IPC
func processSensitiveData() {
    let data = "sensitive_token_123"

    // Write to shared container - any app in group can read!
    let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
    sharedDefaults?.set(data, forKey: "sensitive_data")
}

// ✅ SECURE - Use Keychain
func processSensitiveData() {
    let data = "sensitive_token_123"

    // Store in Keychain - access controlled
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecValueData as String: data.data(using: .utf8)!,
        kSecAttrAccessGroup as String: "TEAMID.com.example.shared"
    ]

    SecItemAdd(query as CFDictionary, nil)
}
```

---

## Frida XPC Tracing

### XPC Message Tracing

```javascript
// xpc-trace.js - Trace XPC messages
if (ObjC.available) {
    console.log("[*] Tracing XPC messages...");

    var xpcMod = Process.findModuleByName('libxpc.dylib');
    var xpc_connection_create = xpcMod ? xpcMod.findExportByName('xpc_connection_create') : null;

    Interceptor.attach(xpc_connection_create, {
        onEnter: function(args) {
            var serviceName = args[0].readUtf8String();
            console.log("\n[+] XPC Connection Created");
            console.log("  Service:", serviceName);
        }
    });

    var xpc_connection_send_message = xpcMod ? xpcMod.findExportByName('xpc_connection_send_message') : null;

    Interceptor.attach(xpc_connection_send_message, {
        onEnter: function(args) {
            var connection = args[0];
            var message = args[1];

            console.log("\n[+] XPC Message Sent");
            console.log("  Connection:", connection);
            console.log("  Message:", message);
        }
    });

    console.log("[*] XPC tracing hooks installed");
}
```

### NSXPCConnection Hooking

```javascript
// nsxpc-hook.js - Hook NSXPCConnection
if (ObjC.available) {
    console.log("[*] Hooking NSXPCConnection...");

    var NSXPCConnection = ObjC.classes.NSXPCConnection;

    // Hook init
    Interceptor.attach(NSXPCConnection["- initWithListenerEndpoint:"], {
        onEnter: function(args) {
            console.log("\n[+] NSXPCConnection created");
        }
    });

    // Hook resume
    Interceptor.attach(NSXPCConnection["- resume"], {
        onEnter: function(args) {
            console.log("\n[+] NSXPCConnection resumed");
        }
    });

    // Hook remoteObjectProxy
    Interceptor.access(NSXPCConnection["- remoteObjectProxy"], {
        onEnter: function(args) {
            console.log("\n[+] Remote object proxy accessed");
        },
        onLeave: function(retval) {
            var proxy = ObjC.Object(retval);
            console.log("  Proxy class:", proxy.$className);
        }
    });

    console.log("[*] NSXPCConnection hooks installed");
}
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | IPC Context |
|---------------|-------|-------------|
| MASTG-APP-SEC-0015 | Inter-Process Communication | IPC security |
| MASTG-TEST-0020 | Input Validation | Parameter injection |
| MASTG-APP-SEC-0020 | URL Scheme Security | Scheme hijacking |
| MASTG-TEST-0070 | Deep Link Testing | URL scheme testing |

---

## Summary

This guide covered:
- iOS IPC mechanisms (URL schemes, Universal Links, pasteboard, App Groups, XPC)
- Security issues and vulnerabilities in each IPC method
- Testing methodologies for IPC mechanisms
- Frida hooking for IPC tracing
- Common injection and authorization bypass attacks
- Remediation strategies and secure implementations

iOS IPC provides powerful inter-app communication capabilities, but each mechanism has specific security considerations. Always validate inputs, implement access controls, and test thoroughly.

---

## References

### Official Documentation
- Apple IPC: https://developer.apple.com/documentation/xpc
- URL Schemes: https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content
- App Groups: https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- iOS Security Guide: https://support.apple.com/guide/security/
- XPC Programming Guide: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html
- Universal Links: https://developer.apple.com/documentation/xcode/implementing-deep-links

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** iOS development knowledge, Swift/Objective-C, understanding of process isolation
