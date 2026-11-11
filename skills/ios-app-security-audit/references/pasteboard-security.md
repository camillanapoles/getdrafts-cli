# Pasteboard Security

## UIPasteboard API

### Pasteboard Types
```swift
// General pasteboard - accessible by any app
let generalPasteboard = UIPasteboard.general

// Custom pasteboard
let customPasteboard = UIPasteboard(name: UIPasteboard.Name("com.example.custom"), create: false)

// App-specific pasteboard
let appPasteboard = UIPasteboard.withUniqueName()
```

### Reading/Writing
```swift
// Read string
let stringContent = UIPasteboard.general.string

// Write string
UIPasteboard.general.string = "Hello, World!"
```

## Security Risks

### 1. Any App Can Read General Pasteboard
```swift
// Malicious app can read anytime
let stolenData = UIPasteboard.general.string
```

### 2. No User Notification
```swift
// Apps can silently read clipboard
// Before iOS 14, NO indication
```

### 3. Data Persistence
```swift
// Clipboard persists across app launches
// Until overwritten or timeout
```

### 4. Universal Clipboard
```swift
// Syncs across devices
// Vulnerable to MITM if not secured
```

## Testing

### 1. Monitor Reads
```swift
class PasteboardMonitor {
    private var timer: Timer?
    
    func startMonitoring() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
            let changeCount = UIPasteboard.general.changeCount
            print("Change count: \(changeCount)")
        }
    }
}
```

### 2. Frida Hook
```javascript
// Hook UIPasteboard:string
var Pasteboard = ObjC.classes.UIPasteboard;
Interceptor.attach(Pasteboard["- string"].implementation, {
    onEnter: function(args) {
        console.log("[Pasteboard] Reading string");
    },
    onLeave: function(retval) {
        if (retval.toInt32() !== 0) {
            console.log("Value:", new ObjC.Object(retval).toString());
        }
    }
});

// Hook UIPasteboard:setString:
Interceptor.attach(Pasteboard["- setString:"].implementation, {
    onEnter: function(args) {
        console.log("[Pasteboard] Writing:", new ObjC.Object(args[2]).toString());
    }
});
```

### 3. Continuous Monitoring
```javascript
var lastChangeCount = 0;

setInterval(function() {
    var pasteboard = ObjC.classes.UIPasteboard.general();
    var currentCount = pasteboard.changeCount();
    
    if (currentCount !== lastChangeCount) {
        console.log("Changed! Count:", currentCount);
        var string = pasteboard.string();
        if (string !== null) console.log("String:", string.toString());
        lastChangeCount = currentCount;
    }
}, 500);
```

## Remediation

### 1. Minimize Clipboard Usage
```swift
// Use delegation instead
protocol UserDataDelegate: AnyObject {
    func didSelectUser(_ user: User)
}

class UserListViewController: UIViewController {
    weak var delegate: UserDataDelegate?
    
    func didSelectUser(_ user: User) {
        delegate?.didSelectUser(user)
    }
}
```

### 2. Clear After Use
```swift
func handlePasteboardContent() {
    guard let content = UIPasteboard.general.string else { return }
    processContent(content)
    UIPasteboard.general.string = nil
}
```

### 3. Use App-Specific Pasteboard
```swift
let appPasteboard = UIPasteboard.withUniqueName()
appPasteboard.string = "internal data"
```

### 4. Validate Content
```swift
func validatePasteboardURL() -> URL? {
    guard let url = UIPasteboard.general.url else { return nil }
    guard url.scheme == "https" || url.scheme == "http" else { return nil }
    guard let host = url.host, trustedDomains.contains(host) else { return nil }
    return url
}
```

## OWASP MASTG References
- MASTG-APP-DATA-005: Pasteboard Security
- MASTG-APP-ANALYSIS-010: Clipboard Testing
- MASTG-APP-ARCH-009: Data Transfer Security



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

