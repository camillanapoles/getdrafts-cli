# Data Protection API Guide

## iOS Data Protection API

File-level encryption system using AES-256 with passcode-derived keys.

### Protection Levels

#### NSFileProtectionComplete
```swift
// Encrypted until device unlocked
let attributes: [FileAttributeKey: Any] = [
    .protectionKey: FileProtectionType.complete
]
try? FileManager.default.setAttributes(attributes, ofItemAtPath: url.path)
```

#### NSFileProtectionCompleteUnlessOpen
```swift
// Encrypted unless open
let attributes: [FileAttributeKey: Any] = [
    .protectionKey: FileProtectionType.completeUnlessOpen
]
```

#### NSFileProtectionCompleteUntilFirstUserAuthentication
```swift
// Encrypted until first unlock
let attributes: [FileAttributeKey: Any] = [
    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
]
```

#### NSFileProtectionNone
```swift
// No encryption - PLAINTEXT
let attributes: [FileAttributeKey: Any] = [
    .protectionKey: FileProtectionType.none
]
```

## How It Works

```
User creates file
↓
File written to storage
↓
Key derived from passcode + UID
↓
File encrypted with AES-256
↓
Key stored in Keybag
↓
Locked → Key inaccessible → File unreadable
Unlocked → Key accessible → File readable
```

## Testing

### 1. Verify Protection Level
```bash
ls -la@ secure_file.txt
xattr -l secure_file.txt
```

### 2. Programmatic Check
```swift
extension FileManager {
    func protectionLevel(for file: URL) -> FileProtectionType? {
        guard let attributes = try? attributesOfItem(atPath: file.path),
              let protection = attributes[.protectionKey] as? FileProtectionType else {
            return nil
        }
        return protection
    }
}
```

### 3. Frida Hooks
```javascript
// Hook setAttributes:ofItemAtPath:error:
var FM = ObjC.classes.NSFileManager;
Interceptor.attach(FM["- setAttributes:ofItemAtPath:error:"].implementation, {
    onEnter: function(args) {
        var attributes = new ObjC.Object(args[2]);
        var protection = attributes.objectForKey_("NSFileProtectionKey");
        if (protection) {
            console.log("Protection:", protection.toString());
        }
    }
});
```

## Secure Enclave Integration

```swift
import CryptoKit

func generateSecureEnclaveKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey()
}

func signWithSecureEnclave(data: Data, privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey) throws -> Data {
    let signature = try privateKey.signature(for: data)
    return signature.rawRepresentation
}
```

## Remediation

### 1. Always Set Explicit Protection
```swift
try? "data".write(to: fileURL, atomically: true, encoding: .utf8)
let attributes: [FileAttributeKey: Any] = [
    .protectionKey: FileProtectionType.complete
]
try? FileManager.default.setAttributes(attributes, ofItemAtPath: fileURL.path)
```

### 2. Use Appropriate Level
```swift
enum DataSensitivity {
    case critical        // Complete
    case sensitive       // CompleteUnlessOpen
    case private         // CompleteUntilFirstUserAuthentication
    case public          // None
}
```

## OWASP MASTG References
- MASTG-APP-STORAGE-003: Data Protection API
- MASTG-APP-ANALYSIS-011: File Protection Testing
- MASTG-APP-ARCH-010: Encryption Architecture



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

