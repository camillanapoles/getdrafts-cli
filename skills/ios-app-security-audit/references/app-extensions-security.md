# iOS App Extensions Security

## iOS App Extension Types

### 1. Today Widget (Today Extension)

```swift
// TodayWidget.swift
import WidgetKit
import SwiftUI

struct TodayWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "com.example.widget", provider: Provider()) { entry in
            TodayEntryView(entry: entry)
        }
        .configurationDisplayName("Today Widget")
        .description("Shows today's information")
        .supportedFamilies([.systemSmall])
    }
}

// Info.plist keys
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.widgetkit-extension</string>
</dict>
```

**Security Considerations:**
- Limited execution time
- No user interaction
- Network access restricted
- Memory constraints

### 2. Share Extension

```swift
// ShareViewController.swift
import UIKit
import Social

class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        guard let extensionItem = extensionContext?.inputItems.first as? NSExtensionItem,
              let itemProvider = extensionItem.attachments?.first,
              itemProvider.hasItemConformingToTypeIdentifier("public.url") else {
            return
        }
        
        // Process shared URL
    }
}

// Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.share-services</string>
    <key>NSExtensionAttributes</key>
    <dict>
        <key>NSExtensionActivationRule</key>
        <dict>
            <key>NSExtensionActivationSupportsURLWithMaxCount</key>
            <integer>1</integer>
        </dict>
    </dict>
</dict>
```

**Security Considerations:**
- Can access shared content
- May extract sensitive URLs
- Requires user activation

### 3. Custom Keyboard Extension

```swift
// KeyboardViewController.swift
import UIKit

class KeyboardViewController: UIInputViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Keyboard UI setup
        let button = UIButton(type: .system)
        button.setTitle("Paste", for: .normal)
        button.addTarget(self, action: #selector(pasteText), for: .touchUpInside)
        
        view.addSubview(button)
    }
    
    @objc func pasteText() {
        // Can read clipboard if full access granted
        let text = UIPasteboard.general.string
        textDocumentProxy.insertText(text ?? "")
    }
}

// Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.keyboard-service</string>
    <key>NSExtensionAttributes</key>
    <dict>
        <key>RequestsOpenAccess</key>
        <false/>  <!-- No full access by default -->
    </dict>
</dict>
```

**Security Considerations:**
- Full access allows reading user input
- Can access general pasteboard
- Network access restricted without full access
- Can send typed data to server

### 4. Notification Content Extension

```swift
// NotificationViewController.swift
import UIKit
import UserNotifications
import UserNotificationsUI

class NotificationViewController: UIViewController, UNNotificationContentExtension {
    @IBOutlet var label: UILabel!
    
    func didReceive(_ notification: UNNotification) {
        // Process notification content
        let content = notification.request.content
        label.text = content.body
    }
}

// Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.usernotifications.content-extension</string>
    <key>NSExtensionAttributes</key>
    <dict>
        <key>UNNotificationExtensionCategory</key>
        <string>MY_CATEGORY</string>
        <key>UNNotificationExtensionDefaultContentHidden</key>
        <true/>
    </dict>
</dict>
```

**Security Considerations:**
- Time constraints (max 25 seconds)
- Limited API access
- Can display custom UI for notifications
- May show sensitive content

### 5. Notification Service Extension

```swift
// NotificationService.swift
import UserNotifications

class NotificationService: UNNotificationServiceExtension {
    var contentHandler: ((UNNotificationContent) -> Void)?
    var bestAttemptContent: UNMutableNotificationContent?
    
    override func didReceive(_ request: UNNotificationRequest, 
                          withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)
        
        // Modify notification content
        bestAttemptContent?.title = "Modified: " + (bestAttemptContent?.title ?? "")
    }
    
    override func serviceExtensionTimeWillExpire() {
        // Called before time expires
        if let contentHandler = contentHandler,
           let bestAttemptContent = bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }
}

// Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.usernotifications.service</string>
</dict>
```

**Security Considerations:**
- Silent background execution
- Can download content
- Can modify notification payload
- Limited time (~30 seconds)

### 6. File Provider Extension

```swift
// FileProviderExtension.swift
import FileProvider

class FileProviderExtension: NSFileProviderExtension {
    override func startProvidingItemAt(url: URL, completionHandler: @escaping (Error?) -> Void) {
        // Provide file content
    }
    
    override func item(for identifier: NSFileProviderItemIdentifier, 
                    completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) {
        // Return file metadata
    }
}

// Info.plist
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.fileprovider-service</string>
</dict>
```

**Security Considerations:**
- Can access file system
- Domain-scope restrictions
- Can read/write files
- Sandbox restrictions apply

### 7. Safari Web Extension

```swift
// content.js (JavaScript)
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "getPageData") {
        // Read page data
        const pageData = document.body.innerHTML;
        sendResponse({ data: pageData });
    }
});

// manifest.json
{
    "manifest_version": 2,
    "name": "My Extension",
    "permissions": ["activeTab", "<all_urls>"],
    "content_scripts": [{
        "matches": ["<all_urls>"],
        "js": ["content.js"]
    }]
}
```

**Security Considerations:**
- Can read all web pages
- Can inject scripts
- Can intercept network requests
- Cross-site data access

## Security Implications

### Shared Containers

```text
# App Groups container structure
/var/mobile/Containers/Shared/AppGroup/
├── group.com.example.app1/
├── group.com.example.app2/
└── group.com.example.shared/

# Access from extension
let containerURL = FileManager.default.containerURL(
    forSecurityApplicationGroupIdentifier: "group.com.example.shared"
)
```

#### Data Leakage

```swift
// Vulnerable: Extension can read sensitive data
// Main app stores in shared container
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
sharedDefaults?.set("userPassword", forKey: "password")

// Extension reads
let password = sharedDefaults?.string(forKey: "password")
// Can exfiltrate
```

#### Remediation

```swift
// ✅ Secure: Don't use App Groups for sensitive data
// Use Keychain instead
func storeSecurely(_ password: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "user",
        kSecValueData as String: password.data(using: .utf8)!
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// ✅ Secure: Validate shared data access
func validateSharedAccess() -> Bool {
    // Check caller identity
    // Validate data integrity
    // Implement access controls
}
```

### Data Leakage

#### Keyboard Extension

```swift
// Vulnerable: Keyboard can read all input
class KeyboardViewController: UIInputViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Capture all keystrokes
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(textDidChange),
            name: UITextInputMode.currentInputModeDidChangeNotification,
            object: nil
        )
    }
    
    @objc func textDidChange() {
        let text = textDocumentProxy.documentContextBeforeInput
        // Send to server
        exfiltrate(text)
    }
}
```

#### Remediation

```swift
// ✅ Secure: Request minimal permissions
// Don't request full access unless needed
// Implement privacy controls
// Limit data collection
```

### Sandbox Bypasses

#### Extension Privileges

```swift
// Extensions may have different privileges
// Check extension's sandbox
import os.log

func checkSandbox() {
    let log = OSLog(subsystem: "com.example.app", category: "Sandbox")
    os_log("Extension sandbox: %{public}@", log: log, type: .info, "Checking...")
    
    // Check file access
    // Check network access
    // Check entitlements
}
```

## Analysis Methodology

### 1. Enumerate Extensions

```bash
# List all app extensions
find . -name "*.appex" -type d

# Check extension Info.plist
for ext in *.appex; do
    echo "=== $ext ==="
    plutil -p "$ext/Info.plist"
done
```

### 2. Check Extension Entitlements

```bash
# Get extension entitlements
codesign -d --entitlements :- Payload/MyApp.app/Plugins/Extension.appex

# Check for App Groups
codesign -d --entitlements :- Payload/MyApp.app/Plugins/Extension.appex |   grep "com.apple.security.application-groups"

# Check for network access
codesign -d --entitlements :- Payload/MyApp.app/Plugins/Extension.appex |   grep "com.apple.security.network"
```

### 3. Test Shared Containers

```bash
# Find shared containers
find /var/mobile/Containers/Shared/AppGroup/ -name "group.*"

# Check container contents
ls -la /var/mobile/Containers/Shared/AppGroup/group.com.example.app/

# Test write access from extension
```

### 4. Frida Hooks for Extensions

```javascript
// Hook extension lifecycle
var NSExtension = ObjC.classes.NSExtension;

// Hook extensionContext
if (ObjC.classes.NSExtensionContext) {
    var ExtensionContext = ObjC.classes.NSExtensionContext;
    
    Interceptor.attach(ExtensionContext["- openURL:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[Extension] openURL:");
            console.log("  URL:", ObjC.Object(args[2]).absoluteString().toString());
        }
    });
}

// Hook file provider
if (ObjC.classes.NSFileProviderExtension) {
    var FileProvider = ObjC.classes.NSFileProviderExtension;
    
    Interceptor.attach(FileProvider["- startProvidingItemAtURL:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[FileProvider] startProvidingItemAtURL:");
            console.log("  URL:", ObjC.Object(args[2]).path().toString());
        }
    });
}

// Hook notification service
if (ObjC.classes.UNNotificationServiceExtension) {
    var NotificationService = ObjC.classes.UNNotificationServiceExtension;
    
    Interceptor.attach(NotificationService["- didReceive:withContentHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[NotificationService] didReceive:");
            var request = new ObjC.Object(args[2]);
            console.log("  Content:", request.content().description());
        }
    });
}
```

### 5. Test Extension Communication

```swift
// Test host-app communication
// In extension
class ExtensionCommunicator {
    func communicateWithHost() {
        let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
        sharedDefaults?.set("test", forKey: "message")
        
        // In host app, observe changes
        // Check if extension can write
    }
}
```

## App Groups Data Sharing Risks

### 1. Data Contamination

```swift
// Malicious app in same group
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")

// Overwrite legitimate app's data
sharedDefaults?.set("hacked", forKey: "username")
sharedDefaults?.set("fake@example.com", forKey: "email")
```

### 2. Credential Leakage

```swift
// Read credentials from shared container
let containerURL = FileManager.default.containerURL(
    forSecurityApplicationGroupIdentifier: "group.com.example.shared"
)

let credsFile = containerURL?.appendingPathComponent("credentials.json")
let credentials = try? String(contentsOf: credsFile!)

// Exfiltrate
sendToServer(credentials!)
```

### 3. Privilege Escalation

```swift
// Lower-privileged extension can access
// higher-privileged app's data
// via shared container
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")

let isAdmin = sharedDefaults?.bool(forKey: "isAdmin")
if isAdmin! {
    // Perform admin actions
}
```

### 4. Testing App Groups

```bash
# Check embedded.mobileprovision
security cms -D -i embedded.mobileprovision |   plutil -p | grep -A 10 "application-groups"

# Find all groups on device
ls -la /var/mobile/Containers/Shared/AppGroup/

# Test group access
# Create test app with same group
# Try to read/write data
```

## Testing Checklist

- [ ] Enumerate all app extensions
- [ ] Verify each extension's entitlements
- [ ] Check App Groups usage
- [ ] Test data leakage scenarios
- [ ] Verify sandbox enforcement
- [ ] Test keyboard full access
- [ ] Check file provider scope
- [ ] Verify notification content handling
- [ ] Test shared container access
- [ ] Review extension permissions

## OWASP MASTG References

- **MASTG-APP-ARCH-004: Extension Architecture**
  - Extension types and capabilities
  - Security boundaries

- **MASTG-APP-ANALYSIS-003: Extension Security**
  - Extension testing methodology
  - Privilege assessment

- **MASTG-APP-DATA-001: Data Storage**
  - App Groups security
  - Shared container risks
