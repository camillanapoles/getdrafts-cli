# UserDefaults Security

## NSUserDefaults Storage

UserDefaults stores key-value pairs as plist files, NOT encrypted.

### Storage Location
```
~/Library/Preferences/[BundleIdentifier].plist
```

### Typical Sensitive Data
```swift
// ❌ DANGEROUS uses
UserDefaults.standard.set("user123", forKey: "username")
UserDefaults.standard.set("password123", forKey: "password")
UserDefaults.standard.set("abc123def", forKey: "authToken")
```

## Suite-Based UserDefaults (App Groups)

```swift
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
sharedDefaults?.set("shared_value", forKey: "sharedKey")
```

### Storage Location
```
~/Library/Group Containers/[GroupID]/[GroupID].plist
```

## Security Issues

### 1. Plaintext Storage
```bash
# Anyone with device access can read
plutil -p ~/Library/Preferences/com.example.app.plist
```

### 2. No Data Protection
```bash
# Default is FileProtectionType.none
ls -la@ ~/Library/Preferences/com.example.app.plist
```

### 3. App Groups Data Leakage
```swift
// Any app in same group can read
let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
let leakedToken = sharedDefaults?.string(forKey: "authToken")
```

## Testing

### 1. Read Plists
```bash
plutil -p ~/Library/Preferences/com.example.app.plist
plutil -convert json -o - ~/Library/Preferences/com.example.app.plist
```

### 2. Dump with Frida
```javascript
var defaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
var allKeys = defaults.dictionaryRepresentation().allKeys();

for (var i = 0; i < allKeys.count(); i++) {
    var key = allKeys.objectAtIndex_(i).toString();
    var value = defaults.objectForKey_(key);
    console.log(key, ":", value.toString());
}
```

### 3. Check App Groups
```bash
codesign -d --entitlements :- Payload/MyApp.app |   grep "application-groups"
```

## Remediation

### 1. Use Keychain for Sensitive Data
```swift
import Security

func storeInKeychain(key: String, value: String) -> Bool {
    let data = value.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
    ]
    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}
```

### 2. Encrypt UserDefaults Values
```swift
import CryptoKit

class SecureUserDefaults {
    private let defaults: UserDefaults
    private let encryptionKey: SymmetricKey
    
    func set(_ value: String, forKey key: String) throws {
        let data = value.data(using: .utf8)!
        let encrypted = try AES.GCM.seal(data, using: encryptionKey).combined
        defaults.set(encrypted, forKey: key)
    }
}
```

## OWASP MASTG References
- MASTG-APP-DATA-004: UserDefaults Security
- MASTG-APP-STORAGE-002: Keychain Usage
- MASTG-APP-ANALYSIS-009: UserDefaults Testing



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

