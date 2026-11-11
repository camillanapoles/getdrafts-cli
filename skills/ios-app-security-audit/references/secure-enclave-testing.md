# Secure Enclave Testing

The Secure Enclave is a coprocessor that provides cryptographic operations and biometric data protection. This guide covers Secure Enclave capabilities, key operations, biometric binding, attestation, limitations, and testing methodologies.

**MASTG References:**
- MASTG-TEST-0047: Testing for Keychain Data
- MASTG-TEST-0048: Testing the Keychain (iOS)
- MASTG-TEST-0056: Testing Code Quality and Code Construction Issues

## 1. Secure Enclave Capabilities

### What Can Be Done in Secure Enclave

| Operation | Secure Enclave | Regular Keychain |
|-----------|----------------|-----------------|
| Key Generation | ✅ | ✅ |
| Encryption/Decryption | ✅ | ✅ |
| Signing | ✅ | ✅ |
| Biometric Binding | ✅ | ❌ |
| Key Storage | ✅ | ✅ |
| Key Export | ❌ | ✅ |

### Supported Algorithms

- **ECC**: P-256, P-384
- **RSA**: 2048-bit and larger (limited)
- **ECDSA**: P-256, P-384
- **Ed25519**: macOS only

## 2. Key Operations

### Creating Secure Enclave Keys

```swift
import CryptoKit
import LocalAuthentication

// Secure key generation
class SecureEnclaveKeyManager {
    static let shared = SecureEnclaveKeyManager()

    private init() {}

    func generateKeyPair(label: String) throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(
            kSecAttrAccessibleWhenUnlocked,
            .userPresence,
            nil
        )!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: label,
                kSecAttrAccessControl as String: access,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: label + ".public"
            ]
        ]

        var publicKey: SecKey?
        var privateKey: SecKey?

        let status = SecKeyGeneratePair(
            attributes as CFDictionary,
            &publicKey,
            &privateKey
        )

        guard status == errSecSuccess,
              let privateKey = privateKey else {
            throw KeyError.generationFailed
        }

        return privateKey
    }

    func getPrivateKey(label: String) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: label,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let key = result as? SecKey else {
            throw KeyError.notFound
        }

        // Verify key is in Secure Enclave
        guard SecKeyIsAlgorithmSupported(
            key,
            .sign,
            .ecdsaSignatureMessageX962SHA256
        ) else {
            throw KeyError.notInSecureEnclave
        }

        return key
    }
}

enum KeyError: LocalizedError {
    case generationFailed
    case notFound
    case notInSecureEnclave

    var errorDescription: String? {
        switch self {
        case .generationFailed:
            return "Failed to generate key"
        case .notFound:
            return "Key not found"
        case .notInSecureEnclave:
            return "Key is not in Secure Enclave"
        }
    }
}
```

### Signing Operations

```swift
// Secure signing
extension SecureEnclaveKeyManager {
    func sign(data: Data, with key: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw KeyOperationError.algorithmNotSupported
        }

        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            key,
            algorithm,
            data as CFData,
            &error
        )

        guard let signatureData = signature as Data? else {
            throw KeyOperationError.signingFailed
        }

        return signatureData
    }

    func verify(signature: Data,
               data: Data,
               with publicKey: SecKey) throws -> Bool {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            algorithm,
            data as CFData,
            signature as CFData,
            &error
        )

        return isValid
    }
}

enum KeyOperationError: LocalizedError {
    case algorithmNotSupported
    case signingFailed
    case verificationFailed

    var errorDescription: String? {
        switch self {
        case .algorithmNotSupported:
            return "Algorithm not supported"
        case .signingFailed:
            return "Signing failed"
        case .verificationFailed:
            return "Verification failed"
        }
    }
}
```

## 3. Biometric Binding

### Biometric-Protected Keys

```swift
// Biometric authentication integration
class BiometricKeyManager {
    static let shared = BiometricKeyManager()

    private init() {}

    func generateKeyWithBiometricProtection(label: String) throws -> SecKey {
        // Require biometric authentication
        let access = SecAccessControlCreateWithFlags(
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.userPresence, .privateKeyUsage],
            nil
        )!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: label,
                kSecAttrAccessControl as String: access,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
        ]

        var publicKey: SecKey?
        var privateKey: SecKey?

        let status = SecKeyGeneratePair(
            attributes as CFDictionary,
            &publicKey,
            &privateKey
        )

        guard status == errSecSuccess,
              let privateKey = privateKey else {
            throw KeyError.generationFailed
        }

        return privateKey
    }

    func signWithBiometric(data: Data,
                          with key: SecKey,
                          reason: String = "Authenticate to sign") throws -> Data {
        let context = LAContext()
        context.localizedReason = reason

        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            key,
            algorithm,
            data as CFData,
            &error,
            context as CFTypeRef
        )

        guard let signatureData = signature as Data? else {
            // Check if error is user cancellation
            if let error = error?.takeRetainedValue() {
                let nsError = error as Error
                if nsError.domain == LAErrorDomain {
                    throw BiometricError.userCancelled
                }
            }
            throw KeyOperationError.signingFailed
        }

        return signatureData
    }
}

enum BiometricError: LocalizedError {
    case userCancelled
    case biometricNotAvailable
    case biometricNotEnrolled

    var errorDescription: String? {
        switch self {
        case .userCancelled:
            return "User cancelled biometric authentication"
        case .biometricNotAvailable:
            return "Biometric authentication is not available"
        case .biometricNotEnrolled:
            return "No biometrics enrolled"
        }
    }
}
```

## 4. Attestation

### Key Attestation

```swift
// Secure Enclave attestation
class SecureEnclaveAttestation {
    static let shared = SecureEnclaveAttestation()

    private init() {}

    func attestKey(label: String) throws -> Data {
        let key = try SecureEnclaveKeyManager.shared.getPrivateKey(label: label)

        // Get public key
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw AttestationError.publicKeyNotFound
        }

        // Generate attestation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var attestationKey: SecKey?
        var attestationPublicKey: SecKey?

        let status = SecKeyGeneratePair(
            attributes as CFDictionary,
            &attestationPublicKey,
            &attestationKey
        )

        guard status == errSecSuccess else {
            throw AttestationError.generationFailed
        }

        // Create attestation
        // Note: Secure Enclave attestation requires Apple's proprietary API

        return Data()
    }

    func verifyAttestation(attestation: Data,
                           publicKey: SecKey) throws -> Bool {
        // Verify attestation chain
        // Check Apple certificates
        // Verify device attestation

        return true
    }
}

enum AttestationError: LocalizedError {
    case generationFailed
    case publicKeyNotFound
    case verificationFailed

    var errorDescription: String? {
        switch self {
        case .generationFailed:
            return "Failed to generate attestation"
        case .publicKeyNotFound:
            return "Public key not found"
        case .verificationFailed:
            return "Attestation verification failed"
        }
    }
}
```

## 5. Limitations

### Secure Enclave Limitations

| Limitation | Description |
|------------|-------------|
| **Key Export** | Keys cannot be exported from Secure Enclave |
| **Key Size** | Limited to specific key sizes |
| **Algorithms** | Limited set of supported algorithms |
| **Device Specific** | Keys cannot be transferred between devices |
| **No Direct Access** | Cannot directly access key material |

## 6. Testing

### Frida Script to Probe Secure Enclave

```javascript
// Probe Secure Enclave usage
if (ObjC.available) {
    try {
        const SecKey = ObjC.classes.SecKey;

        // Hook SecKeyGeneratePair
        const generatePair = Module.findGlobalExportByName('SecKeyGeneratePair');

        if (generatePair) {
            Interceptor.attach(generatePair, {
                onEnter: function(args) {
                    const attributes = new ObjC.Object(args[0]);
                    console.log("[+] SecKeyGeneratePair called");

                    // Check for kSecAttrTokenID
                    const tokenId = attributes.objectForKey_("kSecAttrTokenID");
                    if (tokenId && !tokenId.isNull()) {
                        const tokenIdValue = tokenId.toString();
                        console.log("    Token ID: " + tokenIdValue);

                        if (tokenIdValue.includes("SecureEnclave")) {
                            console.log("    [!] Key will be stored in Secure Enclave");
                        }
                    }

                    // Check for access control
                    const accessControl = attributes.objectForKey_("kSecAttrAccessControl");
                    if (accessControl && !accessControl.isNull()) {
                        console.log("    [!] Access control configured");
                    }
                }
            });
        }

        // Hook SecKeyCreateSignature
        const createSignature = Module.findGlobalExportByName('SecKeyCreateSignature');

        if (createSignature) {
            Interceptor.attach(createSignature, {
                onEnter: function(args) {
                    const key = new ObjC.Object(args[0]);
                    const algorithm = new ObjC.Object(args[1]);

                    console.log("[+] SecKeyCreateSignature called");
                    console.log("    Algorithm: " + algorithm.toString());
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        console.log("    [+] Signature created successfully");
                    }
                }
            });
        }

        console.log("[+] Secure Enclave hooks installed");
    } catch (e) {
        console.log("[-] Error probing Secure Enclave: " + e);
    }
}
```

## Testing Checklist

### Key Operations
- [ ] Verify key generation in Secure Enclave
- [ ] Test signing operations
- [ ] Verify key storage
- [ ] Test key retrieval
- [ ] Check for key export attempts

### Biometric Binding
- [ ] Test biometric authentication
- [ ] Verify biometric fallback
- [ ] Test user cancellation
- [ ] Verify biometric not available handling
- [ ] Test multiple authentication attempts

### Attestation
- [ ] Generate attestation
- [ ] Verify attestation chain
- [ ] Test attestation validation
- [ ] Check certificate validity
- [ ] Verify device binding

### Security
- [ ] Test key extraction attempts
- [ ] Verify key isolation
- [ ] Test secure enclave bypass
- [ ] Check for timing attacks
- [ ] Verify side-channel protection

## OWASP MASTG References

- **MASTG-TEST-0047**: Testing for Keychain Data
- **MASTG-TEST-0048**: Testing the Keychain (iOS)
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **Keychain Access**: Keychain viewer
- **Security Framework**: Apple's security APIs

### Reference Materials
- [Secure Enclave Documentation](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave)
- [CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
