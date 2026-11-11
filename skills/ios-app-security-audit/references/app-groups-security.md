# App Groups Security

## App Groups Mechanism

App Groups allow data sharing between main app, extensions, and other apps.

### Container Structure
```
/var/mobile/Containers/Shared/AppGroup/
├── group.com.example.app1/
├── group.com.example.app2/
└── group.com.example.shared/
```

### Shared UserDefaults
```swift
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
sharedDefaults?.set("value", forKey: "sharedKey")
let value = sharedDefaults?.string(forKey: "sharedKey")
```

## Security Risks

### 1. Data Contamination
```swift
// Malicious app can modify shared data
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
sharedDefaults?.set("hacked", forKey: "userEmail")
```

### 2. Credential Leakage
```swift
// Extension can read credentials from shared container
let containerURL = FileManager.default.containerURL(
    forSecurityApplicationGroupIdentifier: "group.com.example.shared"
)
let credsURL = containerURL?.appendingPathComponent("credentials.json")
let credentials = try? String(contentsOf: credsURL!)
```

## Testing

### 1. Check Entitlements
```bash
codesign -d --entitlements :- Payload/MyApp.app |   grep "application-groups"
```

### 2. Frida Hook
```javascript
// Hook UserDefaults
var UserDefaults = ObjC.classes.NSUserDefaults;
Interceptor.attach(UserDefaults["- objectForKey:"].implementation, {
    onEnter: function(args) {
        var key = new ObjC.Object(args[2]);
        console.log("UserDefaults read:", key.toString());
    }
});
```

## Remediation

### 1. Encrypt Sensitive Data
```swift
import CryptoKit

func encryptData(_ data: Data, key: SymmetricKey) throws -> Data {
    return try AES.GCM.seal(data, using: key).combined
}
```

### 2. Validate Data
```swift
func validateSharedData(_ data: [String: Any]) -> Bool {
    guard data["version"] != nil else { return false }
    // Validate types and integrity
    return true
}
```

## OWASP MASTG References
- MASTG-APP-DATA-002: App Groups Security
- MASTG-APP-ANALYSIS-007: App Group Testing
- MASTG-APP-ARCH-008: Data Sharing Architecture



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

