# Swift Security Patterns

## Swift Type Safety

### Benefits
- Strict type checking at compile time
- Prevents type mismatches
- Reduces runtime errors

### Optional Handling
```swift
// ❌ BAD - Force unwrapping
let password = userDict["password"]!

// ✅ GOOD - Safe unwrapping
if let password = userDict["password"] as? String {
    // Use safely
}

// ✅ BETTER - Guard
guard let password = userDict["password"] as? String else { return }
```

## Common Anti-Patterns

### 1. String Concatenation for SQL
```swift
// ❌ VULNERABLE - SQL Injection
let query = "SELECT * FROM users WHERE email = '\(userEmail)'"

// ✅ SECURE - Parameterized
let query = "SELECT * FROM users WHERE email = ?"
let result = database.execute(query, parameters: [userEmail])
```

### 2. String Interpolation in URLs
```swift
// ❌ VULNERABLE - URL Injection
let url = URL(string: "https://api.example.com/user/\(userId)")!

// ✅ SECURE - URLComponents
var components = URLComponents(string: "https://api.example.com/user")
components?.path = "/\(userId)"
guard let url = components?.url else { return }
```

### 3. Unsafe Pointer Usage
```swift
// ❌ DANGEROUS - Buffer overflow
let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: 10)
ptr[100] = 42

// ✅ SECURE - Bounds checking
guard index >= 0 && index < capacity else { return }
ptr[index] = 42
```

## CryptoKit Usage

### Secure Random
```swift
// ❌ BAD
let random = Int.random(in: 0..<1000000)

// ✅ SECURE
import CryptoKit
let secureRandom = SystemRandomNumberGenerator().next()
```

### Hashing
```swift
// ❌ BAD - MD5
import CommonCrypto
var md5 = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
CC_MD5(data, CC_LONG(data.count), &md5)

// ✅ SECURE - SHA-256
import CryptoKit
let hash = SHA256.hash(data: data)
```

### Encryption
```swift
// ✅ SECURE - AES-GCM
import CryptoKit

let key = SymmetricKey(size: .bits256)
let plaintext = "Secret message".data(using: .utf8)!
let sealedBox = try AES.GCM.seal(plaintext, using: key)
let encryptedData = sealedBox.combined
```

## Swift Access Control

### Access Levels
```swift
// open - Accessible everywhere, subclassable
open class PublicAPI {
    open func publicMethod() {}
}

// public - Accessible everywhere, not subclassable
public class RestrictedAPI {
    public func restrictedMethod() {}
}

// internal - Accessible within module
internal class InternalAPI {}

// private - Accessible within declaration
private class PrivateAPI {}
```

## SwiftUI State Management

### ❌ BAD - Sensitive data in @State
```swift
struct LoginView: View {
    @State private var password: String = ""
    
    var body: some View {
        SecureField("Password", text: $password)
    }
}
```

### ✅ GOOD - Secure storage
```swift
class AuthenticationManager: ObservableObject {
    @Published var passwordInput: String = ""
    
    func storePassword() {
        KeychainHelper.save(password: passwordInput, key: "user_password")
        passwordInput = ""
    }
}
```

## Concurrency

### Thread Safety
```swift
// ❌ BAD - Data race
class SharedData {
    var data: [String] = []
    func add(_ item: String) { data.append(item) }
}

// ✅ GOOD - Actor
actor SharedData {
    private var data: [String] = []
    func add(_ item: String) async { data.append(item) }
}
```

## Security Checklist

### Type Safety
- [ ] Avoid force unwrapping
- [ ] Use guard let
- [ ] Validate types
- [ ] Use type-safe collections

### Memory Safety
- [ ] Limit UnsafeMutablePointer
- [ ] Add bounds checking
- [ ] Deallocate properly

### Cryptography
- [ ] Use CryptoKit
- [ ] Never implement custom crypto
- [ ] Use secure random
- [ ] Prefer AEAD (AES-GCM)

### Access Control
- [ ] Use private/internal
- [ ] Expose minimal interface
- [ ] Document requirements

### Data Storage
- [ ] Never store sensitive in @State
- [ ] Use Keychain
- [ ] Implement clearing
- [ ] Use Data Protection

### Concurrency
- [ ] Use actors
- [ ] Handle cancellation
- [ ] Minimize exposure
- [ ] Use async/await

## OWASP MASTG References
- MASTG-APP-CODE-008: Swift Security Patterns
- MASTG-APP-ARCH-014: Secure Coding in Swift
- MASTG-APP-ANALYSIS-015: Swift Code Review



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

