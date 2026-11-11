# Notification Security

## APNS Overview

Apple's push notification service delivering notifications to iOS devices.

### APNS Payload Structure
```json
{
  "aps": {
    "alert": {
      "title": "Notification Title",
      "body": "Notification body text"
    },
    "badge": 1,
    "sound": "default"
  },
  "custom_key": "custom_value"
}
```

## didReceiveRemoteNotification Security

### Handling
```swift
func application(_ application: UIApplication,
                 didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                 fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
    
    // ⚠️ SECURITY RISK: userInfo contains untrusted data
    guard let aps = userInfo["aps"] as? [String: Any] else {
        completionHandler(.failed)
        return
    }
    
    guard let type = aps["type"] as? String,
          allowedTypes.contains(type) else {
        completionHandler(.failed)
        return
    }
    
    processNotification(userInfo)
    completionHandler(.newData)
}
```

## Notification Content Security

### Visible Data
```swift
// ❌ BAD - Sensitive data in notification
let content = UNMutableNotificationContent()
content.title = "Welcome"
content.body = "Your password is: secret123"

// ✅ GOOD - Minimal information
let content = UNMutableNotificationContent()
content.title = "Welcome"
content.body = "Login successful"
```

## Testing

### 1. Analyze Payload
```swift
func application(_ application: UIApplication,
                 didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
    print("Notification payload: \(userInfo)")
}
```

### 2. Frida Hooks
```javascript
// Hook application:didReceiveRemoteNotification:fetchCompletionHandler:
var appDel = ObjC.classes.UIApplication.sharedApplication().delegate;
if (appDel) {
    var method = "- application:didReceiveRemoteNotification:fetchCompletionHandler:";
    if (appDel[method]) {
        Interceptor.attach(appDel[method].implementation, {
            onEnter: function(args) {
                var userInfo = new ObjC.Object(args[3]);
                console.log("[Remote Notification]");
                console.log("  Payload:", userInfo.description());
            }
        });
    }
}
```

### 3. Test Fuzzing
```swift
class NotificationFuzzer {
    func testMalformedPayloads() {
        let payloads: [[String: Any]] = [
            [:],
            ["aps": [:]],
            ["aps": ["alert": "test"], "url": "javascript:alert(1)"],
            ["aps": ["alert": "test"], "command": "rm -rf /"]
        ]
        
        for payload in payloads {
            handleNotification(payload)
        }
    }
}
```

## Remediation

### 1. Never Include Sensitive Data
```swift
// ❌ BAD
let payload: [String: Any] = [
    "aps": ["alert": "Your password is: secret123"]
]

// ✅ GOOD
let payload: [String: Any] = [
    "aps": ["alert": "Password changed successfully"]
]
```

### 2. Validate All Inputs
```swift
func validateNotificationPayload(_ userInfo: [AnyHashable: Any]) -> Bool {
    guard let aps = userInfo["aps"] as? [String: Any] else { return false }
    
    if let alert = aps["alert"] as? String {
        guard alert.count <= 200 else { return false }
    }
    
    if let action = userInfo["action"] as? String {
        guard allowedActions.contains(action) else { return false }
    }
    
    return true
}
```

### 3. Use End-to-End Encryption
```swift
import CryptoKit

func encryptNotificationContent(_ content: String) -> Data? {
    guard let data = content.data(using: .utf8) else { return nil }
    let key = SymmetricKey(size: .bits256)
    let sealed = try? AES.GCM.seal(data, using: key)
    return sealed?.combined
}
```

## OWASP MASTG References
- MASTG-APP-ARCH-012: Notification Architecture
- MASTG-APP-ANALYSIS-013: Notification Security Testing
- MASTG-APP-CODE-006: Notification Handling Security



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

