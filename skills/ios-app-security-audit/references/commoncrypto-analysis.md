# CommonCrypto Analysis Guide for iOS

## Table of Contents

1. [Overview](#overview)
2. [CommonCrypto API](#commoncrypto-api)
3. [CryptoKit Framework](#cryptokit-framework)
4. [Security Framework](#security-framework)
5. [Weak Algorithms](#weak-algorithms)
6. [Hardcoded Keys](#hardcoded-keys)
7. [Key Derivation](#key-derivation)
8. [Crypto Implementation Analysis](#crypto-implementation-analysis)
9. [Frida Crypto Hooking](#frida-crypto-hooking)
10. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

iOS applications use various cryptographic APIs including CommonCrypto, CryptoKit, and Security framework. This guide covers these APIs, common vulnerabilities, testing methodologies, and Frida hooking for crypto analysis.

### Why Test Crypto Implementation?

- **Verify algorithm strength**: Ensure strong cryptographic algorithms
- **Detect hardcoded keys**: Find embedded encryption keys
- **Assess key derivation**: Evaluate key generation methods
- **Test crypto implementations**: Validate proper usage
- **Identify weak cryptography**: Find vulnerable crypto operations

---

## CommonCrypto API

### CCCrypt - Symmetric Encryption

```swift
import CommonCrypto

// ❌ VULNERABLE - Using weak algorithm
func encryptWeak(plaintext: Data, key: Data) -> Data? {
    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,  // Operation
        kCCAlgorithmDES,  // WEAK ALGORITHM!
        kCCOptionPKCS7Padding,  // Options
        key.bytes,  // Key
        key.count,  // Key length
        nil,  // Initialization vector (none for ECB)
        plaintext.bytes,  // Input
        plaintext.count,  // Input length
        encrypted.mutableBytes,  // Output
        encrypted.count,  // Output buffer size
        &numBytesEncrypted  // Bytes encrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return encrypted
}

// ✅ SECURE - Using AES-256-GCM
func encryptSecure(plaintext: Data, key: Data) -> Data? {
    guard key.count == kCCKeySizeAES256 else {
        return nil
    }

    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key.bytes,
        key.count,
        nil,  // IV (should use proper IV)
        plaintext.bytes,
        plaintext.count,
        encrypted.mutableBytes,
        encrypted.count,
        &numBytesEncrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return encrypted
}
```

### CCDigest - Hash Functions

```swift
import CommonCrypto

// ❌ VULNERABLE - Using weak hash
func hashWeak(data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5(data.bytes, CC_LONG(data.count), &digest)
    return Data(digest)
}

// ✅ SECURE - Using SHA-256
func hashSecure(data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(data.bytes, CC_LONG(data.count), &digest)
    return Data(digest)
}

// ✅ SECURE - Using SHA-512
func hashVerySecure(data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    CC_SHA512(data.bytes, CC_LONG(data.count), &digest)
    return Data(digest)
}
```

### CCHmac - HMAC

```swift
import CommonCrypto

// HMAC implementation
func hmac(key: Data, data: Data, algorithm: CCHmacAlgorithm) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(algorithm.digestLength))

    CCHmac(
        algorithm,
        key.bytes,
        key.count,
        data.bytes,
        data.count,
        &digest
    )

    return Data(digest)
}

extension CCHmacAlgorithm {
    var digestLength: Int {
        switch self {
        case kCCHmacAlgSHA1:
            return Int(CC_SHA1_DIGEST_LENGTH)
        case kCCHmacAlgSHA256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case kCCHmacAlgSHA512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        default:
            return 0
        }
    }
}

// Usage
let key = Data("secret_key".utf8)
let data = Data("message".utf8)

// ❌ WEAK - HMAC-SHA1
let hmacSHA1 = hmac(key: key, data: data, algorithm: kCCHmacAlgSHA1)

// ✅ SECURE - HMAC-SHA256
let hmacSHA256 = hmac(key: key, data: data, algorithm: kCCHmacAlgSHA256)
```

### CCKeyDerivationPBKDF - Key Derivation

```swift
import CommonCrypto

// PBKDF2 key derivation
func deriveKeyPBKDF(
    password: String,
    salt: Data,
    rounds: UInt32,
    keySize: Int
) -> Data? {
    let passwordData = password.data(using: .utf8)!
    var derivedKey = Data(count: keySize)

    let status = CCKeyDerivationPBKDF(
        CCPBKDFAlgorithm(kCCPBKDF2),
        passwordData.bytes,
        passwordData.count,
        salt.bytes,
        salt.count,
        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
        rounds,
        derivedKey.mutableBytes,
        derivedKey.count
    )

    guard status == kCCSuccess else {
        return nil
    }

    return derivedKey
}

// ❌ WEAK - Too few iterations
let weakKey = deriveKeyPBK(
    password: "password",
    salt: Data("salt".utf8),
    rounds: 100,  // TOO WEAK!
    keySize: 32
)

// ✅ SECURE - Sufficient iterations
let strongKey = deriveKeyPBK(
    password: "password",
    salt: Data("salt".utf8),
    rounds: 100000,  // STRONG!
    keySize: 32
)
```

---

## CryptoKit Framework

### SHA-256/384/512

```swift
import CryptoKit

// SHA-256
let data = Data("message".utf8)
let sha256 = SHA256.hash(data: data)
print("SHA-256:", sha256.compactMap { String(format: "%02x", $0) }.joined())

// SHA-384
let sha384 = SHA384.hash(data: data)
print("SHA-384:", sha384.compactMap { String(format: "%02x", $0) }.joined())

// SHA-512
let sha512 = SHA512.hash(data: data)
print("SHA-512:", sha512.compactMap { String(format: "%02x", $0) }.joined())
```

### AES-GCM Encryption

```swift
import CryptoKit

// AES-GCM encryption
func encryptAESGCM(plaintext: Data, key: SymmetricKey) -> (ciphertext: Data, tag: Data)? {
    do {
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        return (sealedBox.ciphertext, sealedBox.tag)
    } catch {
        return nil
    }
}

// AES-GCM decryption
func decryptAESGCM(ciphertext: Data, tag: Data, key: SymmetricKey) -> Data? {
    let sealedBox = try! AES.GCM.SealedBox(nonce: AES.GCM.Nonce(), ciphertext: ciphertext, tag: tag)

    do {
        let decrypted = try AES.GCM.open(sealedBox, using: key)
        return decrypted
    } catch {
        return nil
    }
}

// Usage
let key = SymmetricKey(size: .bits256)
let plaintext = Data("secret message".utf8)

if let (ciphertext, tag) = encryptAESGCM(plaintext: plaintext, key: key) {
    print("Encrypted:", ciphertext)
    print("Tag:", tag)

    if let decrypted = decryptAESGCM(ciphertext: ciphertext, tag: tag, key: key) {
        print("Decrypted:", String(data: decrypted, encoding: .utf8))
    }
}
```

### ChaChaPoly

```swift
import CryptoKit

// ChaChaPoly encryption
func encryptChaChaPoly(plaintext: Data, key: SymmetricKey) -> (ciphertext: Data, tag: Data)? {
    do {
        let sealedBox = try ChaChaPoly.seal(plaintext, using: key)
        return (sealedBox.ciphertext, sealedBox.tag)
    } catch {
        return nil
    }
}

// ChaChaPoly decryption
func decryptChaChaPoly(ciphertext: Data, tag: Data, key: SymmetricKey) -> Data? {
    let sealedBox = try! ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(), ciphertext: ciphertext, tag: tag)

    do {
        let decrypted = try ChaChaPoly.open(sealedBox, using: key)
        return decrypted
    } catch {
        return nil
    }
}
```

### P-256/384/521 Keys

```swift
import CryptoKit

// P-256 key generation
let privateKeyP256 = P256.KeyAgreement.PrivateKey()
let publicKeyP256 = privateKeyP256.publicKey

// P-384 key generation
let privateKeyP384 = P384.KeyAgreement.PrivateKey()
let publicKeyP384 = privateKeyP384.publicKey

// P-521 key generation
let privateKeyP521 = P521.KeyAgreement.PrivateKey()
let publicKeyP521 = privateKeyP521.publicKey

// Key exchange (ECDH)
func performKeyExchange(privateKey: P256.KeyAgreement.PrivateKey,
                     publicKey: P256.KeyAgreement.PublicKey) -> SymmetricKey? {
    do {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
    } catch {
        return nil
    }
}

// Signing with P-256
let signingKey = P256.Signing.PrivateKey()
let signature = try! signingKey.signature(for: Data("message".utf8))

// Verification with P-256
let publicKey = signingKey.publicKey
let isValid = publicKey.isValidSignature(signature, for: Data("message".utf8))
print("Signature valid:", isValid)
```

---

## Security Framework

### SecKey Operations

```swift
import Security

// Generate RSA key pair
func generateRSAKeyPair() -> (privateKey: SecKey, publicKey: SecKey)? {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 2048,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false
        ],
        kSecPublicKeyAttrs as String: [
            kSecAttrIsPermanent as String: false
        ]
    ]

    var error: Unmanaged<CFError>?
    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)

    guard let privateKey = privateKey else {
        return nil
    }

    let publicKey = SecKeyCopyPublicKey(privateKey)

    return (privateKey, publicKey!)
}

// Encrypt with public key
func encryptWithPublicKey(data: Data, publicKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    let encrypted = SecKeyCreateEncryptedData(
        publicKey,
        .rsaEncryptionPKCS1,
        data as CFData,
        &error
    )

    guard let encrypted = encrypted else {
        return nil
    }

    return encrypted as Data
}

// Decrypt with private key
func decryptWithPrivateKey(encryptedData: Data, privateKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    let decrypted = SecKeyCreateDecryptedData(
        privateKey,
        .rsaEncryptionPKCS1,
        encryptedData as CFData,
        &error
    )

    guard let decrypted = decrypted else {
        return nil
    }

    return decrypted as Data
}

// Signing with private key
func signData(data: Data, privateKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    let signature = SecKeyCreateSignature(
        privateKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        &error
    )

    guard let signature = signature else {
        return nil
    }

    return signature as Data
}

// Verification with public key
func verifySignature(data: Data, signature: Data, publicKey: SecKey) -> Bool {
    var error: Unmanaged<CFError>?
    let isValid = SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        signature as CFData,
        &error
    )

    return isValid
}
```

---

## Weak Algorithms

### Weak Algorithm Table

| Algorithm | Type | Security Level | Use Case |
|-----------|------|---------------|----------|
| DES | Symmetric | Weak | ❌ NEVER USE |
| 3DES | Symmetric | Weak | ❌ NEVER USE |
| RC4 | Stream Cipher | Very Weak | ❌ NEVER USE |
| MD5 | Hash | Broken | ❌ NEVER USE |
| SHA-1 | Hash | Weak | ❌ NEVER USE |
| AES-128-ECB | Symmetric | Weak | ❌ NEVER USE |
| AES-128-CBC | Symmetric | Medium | ⚠️ USE AES-GCM |
| AES-256-GCM | Symmetric | Strong | ✅ RECOMMENDED |
| ChaCha20-Poly1305 | Symmetric | Strong | ✅ RECOMMENDED |
| SHA-256 | Hash | Strong | ✅ RECOMMENDED |
| SHA-384 | Hash | Strong | ✅ RECOMMENDED |
| SHA-512 | Hash | Strong | ✅ RECOMMENDED |
| RSA-2048 | Asymmetric | Medium | ⚠️ USE RSA-4096 |
| RSA-4096 | Asymmetric | Strong | ✅ RECOMMENDED |
| P-256 | Asymmetric | Strong | ✅ RECOMMENDED |
| P-384 | Asymmetric | Strong | ✅ RECOMMENDED |
| P-521 | Asymmetric | Strong | ✅ RECOMMENDED |

### Detecting Weak Algorithms

```bash
# Search binary for weak algorithm references
strings Example.app/Example | grep -i "CC_MD5\|CC_SHA1"
strings Example.app/Example | grep -i "kCCAlgorithmDES\|kCCAlgorithmRC4"
strings Example.app/Example | grep -i "kCCAlgorithm3DES"

# Search for ECB mode
strings Example.app/Example | grep -i "ECB\|kCCModeECB"

# Analyze with Frida
frida -U -l crypto-hook-ios.js -f com.example.app
```

---

## Hardcoded Keys

### Finding Hardcoded Keys

```bash
# Method 1: Strings analysis
strings Example.app/Example | grep -i "key\|secret\|token\|password"

# Method 2: Hex pattern search
strings Example.app/Example | grep -E "[0-9a-f]{32,}" | head -20

# Method 3: Base64 pattern search
strings Example.app/Example | grep -E "[A-Za-z0-9+/]{40,}={0,2}" | head -20

# Method 4: Using Frida
frida -U -l memory-dumper-ios.js -f com.example.app
```

### Hardcoded Key Patterns

```swift
// ❌ VULNERABLE - Hardcoded encryption key
class CryptoManager {
    private let encryptionKey = "0123456789ABCDEF0123456789ABCDEF"  // HARDCODED!
    private let iv = "1234567890123456"  // HARDCODED!

    func encrypt(_ data: Data) -> Data? {
        // Use hardcoded key...
    }
}

// ✅ SECURE - Load key from Keychain
class SecureCryptoManager {
    private var encryptionKey: Data?

    init() {
        encryptionKey = loadEncryptionKey()
    }

    private func loadEncryptionKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "encryption.key",
            kSecReturnData as String: true
        ]

        var keyData: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &keyData)

        if keyData == nil {
            return generateEncryptionKey()
        }

        return keyData as? Data
    }

    private func generateEncryptionKey() -> Data? {
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { Data($0) }
    }
}
```

### Hardcoded API Keys

```swift
// ❌ VULNERABLE - Hardcoded API key
class APIClient {
    private let apiKey = "sk_live_EXAMPLE_REDACTED"  // HARDCODED!  [rev-ios vendor patch: literal neutro]

    func makeRequest() {
        // Use hardcoded API key...
    }
}

// ✅ SECURE - Load API key from Keychain
class SecureAPIClient {
    private var apiKey: String?

    init() {
        apiKey = loadAPIKey()
    }

    private func loadAPIKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "api",
            kSecAttrAccount as String: "production",
            kSecReturnData as String: true
        ]

        var data: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &data)

        guard let keyData = data as? Data else {
            return nil
        }

        return String(data: keyData, encoding: .utf8)
    }
}
```

---

## Key Derivation

### PBKDF2

```swift
import CommonCrypto

// ✅ SECURE - PBKDF2 with sufficient iterations
func deriveKeyPBKDF2(
    password: String,
    salt: Data,
    iterations: UInt32,
    keyLength: Int
) -> Data? {
    let passwordData = password.data(using: .utf8)!
    var derivedKey = Data(count: keyLength)

    let status = CCKeyDerivationPBKDF(
        CCPBKDFAlgorithm(kCCPBKDF2),
        passwordData.bytes,
        passwordData.count,
        salt.bytes,
        salt.count,
        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
        iterations,
        derivedKey.mutableBytes,
        derivedKey.count
    )

    guard status == kCCSuccess else {
        return nil
    }

    return derivedKey
}

// Recommended: 100,000+ iterations
let salt = Data("random_salt".utf8)
let password = "secure_password_123"

let derivedKey = deriveKeyPBKDF2(
    password: password,
    salt: salt,
    iterations: 100000,
    keyLength: 32
)
```

### CryptoKit Key Derivation

```swift
import CryptoKit

// HKDF key derivation
func deriveKeyHKDF(
    inputKeyMaterial: SymmetricKey,
    salt: Data,
    info: Data,
    outputByteCount: Int
) -> SymmetricKey {
    return inputKeyMaterial.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: salt,
        sharedInfo: info,
        outputByteCount: outputByteCount
    )
}

// Usage
let ikm = SymmetricKey(size: .bits256)
let salt = Data("salt".utf8)
let info = Data("info".utf8)

let derivedKey = deriveKeyHKDF(
    inputKeyMaterial: ikm,
    salt: salt,
    info: info,
    outputByteCount: 32
)
```

---

## Crypto Implementation Analysis

### Common Crypto Mistakes

#### Mistake 1: Reusing IV

```swift
// ❌ VULNERABLE - Reusing IV
func encryptWithoutIV(plaintext: Data, key: Data) -> Data? {
    var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)  // ALWAYS SAME!

    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key.bytes,
        key.count,
        &iv,
        plaintext.bytes,
        plaintext.count,
        encrypted.mutableBytes,
        encrypted.count,
        &numBytesEncrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return encrypted
}

// ✅ SECURE - Unique IV for each encryption
func encryptWithIV(plaintext: Data, key: Data) -> (ciphertext: Data, iv: Data)? {
    var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
    _ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)

    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key.bytes,
        key.count,
        &iv,
        plaintext.bytes,
        plaintext.count,
        encrypted.mutableBytes,
        encrypted.count,
        &numBytesEncrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return (encrypted, Data(iv))
}
```

#### Mistake 2: ECB Mode

```swift
// ❌ VULNERABLE - ECB mode
func encryptECB(plaintext: Data, key: Data) -> Data? {
    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding | kCCOptionECBMode,  // ECB MODE!
        key.bytes,
        key.count,
        nil,  // No IV in ECB
        plaintext.bytes,
        plaintext.count,
        encrypted.mutableBytes,
        encrypted.count,
        &numBytesEncrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return encrypted
}

// ✅ SECURE - CBC mode with unique IV
func encryptCBC(plaintext: Data, key: Data) -> (ciphertext: Data, iv: Data)? {
    var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
    _ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)

    var encrypted = Data(count: plaintext.count + kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,  // CBC mode (default)
        key.bytes,
        key.count,
        &iv,
        plaintext.bytes,
        plaintext.count,
        encrypted.mutableBytes,
        encrypted.count,
        &numBytesEncrypted
    )

    guard status == kCCSuccess else {
        return nil
    }

    encrypted.count = numBytesEncrypted
    return (encrypted, Data(iv))
}
```

#### Mistake 3: Constant Time Comparison

```swift
// ❌ VULNERABLE - Not constant time
func compareKeys(key1: Data, key2: Data) -> Bool {
    return key1 == key2  // Not constant time!
}

// ✅ SECURE - Constant time comparison
func compareKeysConstantTime(key1: Data, key2: Data) -> Bool {
    guard key1.count == key2.count else {
        return false
    }

    var result = 0
    for i in 0..<key1.count {
        result |= Int(key1[i] ^ key2[i])
    }

    return result == 0
}
```

---

## Frida Crypto Hooking

### Hooking CCCrypt

```javascript
// crypto-hook.js - Hook CommonCrypto functions
if (ObjC.available) {
    console.log("[*] Hooking crypto functions...");

    // CommonCrypto is not a standalone module on iOS: its symbols are exported
    // from libSystem, so a module-scoped lookup cannot be relied on. A global
    // search finds them regardless of how the image is laid out.
    var CCCrypt = Module.findGlobalExportByName('CCCrypt');

    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                var op = args[0].toInt32();  // Operation
                var alg = args[1].toInt32();  // Algorithm
                var options = args[2].toInt32();  // Options
                var keyLen = args[4].toInt32();  // Key length
                var dataLen = args[7].toInt32();  // Data length

                console.log("\n[+] CCCrypt called:");
                console.log("  Operation:", op === 0 ? "Encrypt" : "Decrypt");
                console.log("  Algorithm:", alg);
                console.log("  Options:", options);
                console.log("  Key Length:", keyLen);
                console.log("  Data Length:", dataLen);

                // Check for weak algorithms
                if (alg === 2) {  // kCCAlgorithmDES
                    console.log("  ⚠️ WEAK ALGORITHM: DES!");
                } else if (alg === 3) {  // kCCAlgorithm3DES
                    console.log("  ⚠️ WEAK ALGORITHM: 3DES!");
                } else if (alg === 4) {  // kCCAlgorithmCAST
                    console.log("  ⚠️ WEAK ALGORITHM: CAST!");
                }

                // Check for ECB mode
                if (options & 1) {  // kCCOptionECBMode
                    console.log("  ⚠️ ECB MODE DETECTED!");
                }
            },
            onLeave: function(retval) {
                console.log("  Result:", retval.toInt32());
            }
        });
    }

    var CC_SHA256 = ccMod ? ccMod.findExportByName('CC_SHA256') : null;

    if (CC_SHA256) {
        Interceptor.attach(CC_SHA256, {
            onEnter: function(args) {
                var dataLen = args[1].toInt32();
                console.log("\n[+] CC_SHA256 called:");
                console.log("  Data Length:", dataLen);
            }
        });
    }

    var CC_MD5 = ccMod ? ccMod.findExportByName('CC_MD5') : null;

    if (CC_MD5) {
        Interceptor.attach(CC_MD5, {
            onEnter: function(args) {
                var dataLen = args[1].toInt32();
                console.log("\n[+] ⚠️ CC_MD5 called (WEAK ALGORITHM!):");
                console.log("  Data Length:", dataLen);
            }
        });
    }

    console.log("[*] Crypto hooks installed");
}
```

### Finding Hardcoded Keys with Frida

```javascript
// find-keys.js - Find potential cryptographic keys
if (ObjC.available) {
    console.log("[*] Searching for cryptographic keys...");

    // Search in memory for key-like patterns
    function scanMemoryForKeys() {
        var ranges = Process.enumerateRanges('r--');
        var keyPatterns = [
            /[0-9a-f]{32}/gi,  // 128-bit hex
            /[0-9a-f]{48}/gi,  // 192-bit hex
            /[0-9a-f]{64}/gi,  // 256-bit hex
            /[A-Za-z0-9+/]{32,}={0,2}/g  // Base64
        ];

        console.log("[+] Scanning memory ranges...");
        var count = 0;

        ranges.forEach(function(range) {
            try {
                var data = range.base.readByteArray(range.size);
                var str = hexdump(data, { ansi: false });

                keyPatterns.forEach(function(pattern) {
                    var matches = str.match(pattern);
                    if (matches) {
                        matches.forEach(function(match) {
                            console.log("[+] Possible key at", range.base);
                            console.log("  ", match);
                            count++;
                        });
                    }
                });
            } catch (e) {
                // Ignore
            }
        });

        console.log("[+] Found", count, "potential keys");
    }

    scanMemoryForKeys();
}
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Crypto Context |
|---------------|-------|----------------|
| MASTG-TEST-0050 | Cryptography Testing | Algorithm strength |
| MASTG-APP-SEC-0030 | Cryptographic Verification | Implementation review |
| MASTG-TEST-0055 | Key Management | Key derivation |
| MASTG-APP-SEC-0035 | Cryptographic Storage | Hardcoded keys |

---

## Summary

This guide covered:
- CommonCrypto API (CCCrypt, CCDigest, CCHmac, CCKeyDerivationPBKDF)
- CryptoKit framework (SHA, AES-GCM, ChaChaPoly, P-256/384/521)
- Security framework SecKey operations
- Weak algorithms to avoid (DES, 3DES, RC4, MD5, SHA-1, ECB)
- Hardcoded key detection and prevention
- Secure key derivation methods
- Common crypto implementation mistakes
- Frida hooking for crypto analysis

Proper cryptography is critical for iOS app security. Always use strong algorithms, avoid hardcoded keys, and follow cryptographic best practices.

---

## References

### Official Documentation
- Apple CommonCrypto: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/
- Apple CryptoKit: https://developer.apple.com/documentation/cryptokit
- Apple Security: https://developer.apple.com/documentation/security
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- NIST Cryptographic Standards: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
- Cryptography Best Practices: https://www.cryptopp.com/wiki/Cryptographically_Secure_Random_Number
- CryptoKit Examples: https://developer.apple.com/documentation/cryptokit/creating_a_shared_secret_using_key_agreement

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** Cryptography knowledge, iOS development, Swift/Objective-C
