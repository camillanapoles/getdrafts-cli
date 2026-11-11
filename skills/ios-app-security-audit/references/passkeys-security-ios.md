# Passkeys and WebAuthn Security - iOS Testing Guide

## Table of Contents

1. [Overview](#overview)
2. [Understanding Passkeys on iOS](#understanding-passkeys-on-ios)
3. [Authentication Architecture](#authentication-architecture)
4. [Testing Methodology](#testing-methodology)
5. [Security Considerations](#security-considerations)
6. [Frida Detection](#frida-detection)
7. [Common Vulnerabilities](#common-vulnerabilities)
8. [Secure Implementation](#secure-implementation)

---

## Overview

Passkeys (WebAuthn/FIDO2) are the modern passwordless authentication method introduced in iOS 16. This guide covers Passkeys security testing, implementation analysis, and common vulnerabilities.

### Why Passkeys Security Matters

- **Passwordless**: Eliminates password-related attacks
- **Phishing Resistant**: Tied to origin, preventing credential phishing
- **Biometric**: Protected by Secure Enclave biometrics
- **Cross-Platform**: Works across Apple devices via iCloud Keychain
- **Banking Adoption**: Rapid adoption in financial apps

---

## Understanding Passkeys on iOS

### What is a Passkey?

A Passkey is a FIDO2 credential consisting of:

1. **Private Key**: Stored in Secure Enclave, never leaves device
2. **Public Key**: Shared with the relying party (server)
3. **User Handle**: Identifier for the account
4. **Attestation**: Proof of authenticator authenticity

### iOS Implementation Stack

```
┌─────────────────────────────────────┐
│      Application Layer              │
│  (AuthenticationContextProvider)    │
├─────────────────────────────────────┤
│      AuthenticationServices         │
│  (ASAuthorizationController)        │
├─────────────────────────────────────┤
│      LocalAuthentication            │
│  (Biometric PROMPT)                 │
├─────────────────────────────────────┤
│      Secure Enclave                 │
│  (Key Storage + Signing)            │
└─────────────────────────────────────┘
```

### Key APIs

#### ASAuthorizationController

```swift
import AuthenticationServices

// Register a new passkey
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: "example.com"
)

let request = provider.createRegistrationRequest(
    challenge: challenge,
    userHandle: userHandle,
    userName: userName,
    displayName: displayName
)

// Authenticate with existing passkey
let request = provider.createAssertionRequest(
    challenge: challenge
)
```

#### ASAuthorizationAppleIDProvider

```swift
// Sign in with Apple (alternative to passkeys)
let request = ASAuthorizationAppleIDProvider().createRequest()
```

---

## Authentication Architecture

### Registration Flow

```
1. App generates challenge (server-side)
2. App calls ASAuthorizationController with registration request
3. System shows Face ID / Touch ID prompt
4. Secure Enclave generates keypair
5. Private key stored in Secure Enclave
6. Public key + attestation sent to server
7. Server verifies attestation and stores public key
```

### Authentication Flow

```
1. App receives challenge from server
2. App calls ASAuthorizationController with assertion request
3. System shows biometric prompt
4. Secure Enclave signs challenge with private key
5. Signature + clientData sent to server
6. Server verifies signature and authenticates user
```

---

## Testing Methodology

### Static Analysis

#### Pattern Detection

```bash
# Search for Passkey implementation
grep -r "ASAuthorizationPlatformPublicKeyCredentialProvider" . --include="*.swift"
grep -r "ASAuthorizationController" . --include="*.swift"
grep -r "WebAuthn\|FIDO\|Passkey" . --include="*.swift" --include="*.m"

# Check for credential storage
grep -r "Keychain.*Passkey\|Credential.*store" . --include="*.swift"
```

#### Binary Analysis

```bash
# Check for AuthenticationServices linkage
otool -L "<app_binary>" | grep -i "authentication"

# Look for Passkey symbols
nm "<app_binary>" | grep -i "ASAuthorization\|WebAuthn\|FIDO"

# Check for Secure Enclave usage
otool -tV "<app_binary>" | grep -i "SecureEnclave\|kSecAttrTokenID"
```

### Dynamic Analysis

#### Testing Steps

1. **Verify Passkey Registration**
   - Trigger registration flow
   - Verify biometric prompt appears
   - Check for Secure Enclave storage
   - Verify server receives attestation

2. **Test Authentication**
   - Trigger authentication flow
   - Verify challenge is signed correctly
   - Check for proper error handling

3. **Test Edge Cases**
   - Cancel biometric prompt
   - Use wrong biometric
   - Test with no biometric enrolled

4. **Test Phishing Resistance**
   - Attempt to use passkey from different origin
   - Verify origin enforcement

---

## Security Considerations

### Critical Security Properties

| Property | Description | Test Method |
|----------|-------------|-------------|
| Challenge Freshness | Challenge must be single-use | Reuse challenge, verify rejection |
| Origin Binding | Passkey tied to RP ID | Test with different origin |
| Secure Enclave | Private key never leaves | Verify key storage attributes |
| User Presence | Biometric required | Test without biometric |

### Common Vulnerabilities

#### 1. Missing Challenge Verification

```swift
// Vulnerable: No server-side challenge verification
let challenge = Data() // Empty challenge
let request = provider.createAssertionRequest(challenge: challenge)
```

**Impact**: Replay attacks, MITM

**Fix**: Use cryptographically random server-generated challenge

#### 2. Weak RP ID

```swift
// Vulnerable: Overly permissive RP ID
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: ".com" // Allows any subdomain
)
```

**Impact**: Passkey phishing across subdomains

**Fix**: Use exact domain: "app.example.com"

#### 3. Missing User Verification

```swift
// Vulnerable: No user verification requirement
let request = provider.createAssertionRequest(challenge: challenge)
// Default may allow non-biometric authentication
```

**Impact**: Weaker authentication

**Fix**: Explicitly require user verification

#### 4. Insecure Credential Storage

```swift
// Vulnerable: Storing passkey identifier insecurely
UserDefaults.standard.set(credentialID, forKey: "passkey")
```

**Impact**: Credential tracking, privacy issues

**Fix**: Use Keychain with proper access controls

---

## Frida Detection

### Using passkeys-hook-ios.js

```bash
# Monitor Passkey operations
frida -U -f com.example.app -l passkeys-hook-ios.js
```

### Manual Hooking

```javascript
// Hook ASAuthorizationController
var ASAuthController = ObjC.classes.ASAuthorizationController;
if (ASAuthController) {
    var authorize = ASAuthController["- authorizeWithCompletionHandler:"];
    Interceptor.attach(authorize.implementation, {
        onEnter: function(args) {
            console.log("[*] Passkey authorization initiated");
        }
    });
}

// Check for Secure Enclave key storage
var Keychain = ObjC.classes.SecKeychain;
if (Keychain) {
    // Monitor SecItemAdd for passkey storage
    var secMod = Process.findModuleByName('Security');
    var SecItemAdd = secMod ? secMod.findExportByName('SecItemAdd') : null;
    Interceptor.attach(SecItemAdd, {
        onEnter: function(args) {
            var query = ObjC.Object(args[0]);
            console.log("[*] Keychain storage query:", query);
        }
    });
}
```

### Detecting Attestation Data

```javascript
// Hook for challenge generation and signing
var provider = ObjC.classes.ASAuthorizationPlatformPublicKeyCredentialProvider;
if (provider) {
    var createReg = provider["- createRegistrationRequest:challenge:userHandle:userName:displayName:"];
    if (createReg) {
        Interceptor.attach(createReg.implementation, {
            onLeave: function(retval) {
                if (retval && !retval.isNull()) {
                    var request = ObjC.Object(retval);
                    console.log("[+] Passkey registration request created");
                    // Log challenge and user data
                }
            }
        });
    }
}
```

---

## Common Vulnerabilities

### Vulnerability Categories

#### MASTG-TEST-0046: Weak Authentication

| Vulnerability | Impact | Detection |
|---------------|--------|------------|
| No biometric required | Low | Cancel biometric, check if auth proceeds |
| Challenge reuse | High | Reuse challenge from previous request |
| No origin enforcement | Critical | Test passkey from different domain |

#### MASTG-CRYPTO-1: Weak Cryptography

| Vulnerability | Impact | Detection |
|---------------|--------|------------|
| Weak RP ID | Medium | Binary analysis for RP ID string |
| Missing attestation verification | High | Test with fake attestation |
| Insecure key storage | Medium | Keychain analysis |

---

## Secure Implementation

### Best Practices

#### 1. Proper Challenge Generation

```swift
// Secure: Server-generated, cryptographically random challenge
func generateChallenge() -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes)
}
```

#### 2. Correct RP ID

```swift
// Secure: Use exact domain
let rpID = "app.example.com" // NOT ".example.com" or "example.com"

let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: rpID
)
```

#### 3. Require User Verification

```swift
// Secure: Explicit user verification
let request = provider.createAssertionRequest(challenge: challenge)
request.userVerificationPreference = .required
```

#### 4. Secure Credential Storage

```swift
// Secure: Keychain with proper attributes
func saveCredentialID(_ credentialID: Data, forUser userID: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: userID,
        kSecValueData as String: credentialID,
        kSecAttrAccessControl as String: accessControl
    ]

    SecItemAdd(query as CFDictionary, nil)
}
```

#### 5. Verify Attestation

```swift
// Server-side: Verify attestation
func verifyAttestation(attestation: WebAuthnAttestation) -> Bool {
    // 1. Verify attestation signature
    // 2. Verify attestation statement format
    // 3. Verify authenticator data
    // 4. Verify user presence and verification
    return true
}
```

---

## Testing Checklist

### Registration Testing

- [ ] Challenge is cryptographically random
- [ ] Challenge is single-use
- [ ] RP ID matches exact domain
- [ ] Biometric prompt appears
- [ ] Attestation is verified server-side
- [ ] Public key stored securely
- [ ] User handle is unique

### Authentication Testing

- [ ] Challenge is fresh
- [ ] User verification required
- [ ] Origin enforced
- [ ] Signature verified
- [ ] Error handling for cancelled biometric
- [ ] Rate limiting on failed attempts

### Storage Testing

- [ ] Private key in Secure Enclave
- [ ] Credential ID in Keychain
- [ ] No credential leakage to logs
- [ ] iCloud sync enabled (if intended)

---

## CVSS Scoring

For Passkeys vulnerabilities:

| Scenario | Base Score | Vector |
|----------|-------------|--------|
| Challenge bypass | 8.1 (High) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Origin enforcement missing | 9.1 (Critical) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| No biometric required | 7.5 (High) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N |

---

## Quick Reference

### Detection Commands

```bash
# Find Passkey implementation
grep -r "ASAuthorizationPlatformPublicKeyCredentialProvider" . --include="*.swift"

# Check AuthenticationServices linkage
otool -L "<app_binary>" | grep AuthenticationServices

# Runtime hooking
frida -U -f "<bundle_id>" -l passkeys-hook-ios.js
```

### Secure Implementation Template

```swift
import AuthenticationServices

// 1. Register passkey
func registerPasskey() {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: "app.example.com"
    )

    let challenge = generateChallenge() // Server-provided
    let request = provider.createRegistrationRequest(
        challenge: challenge,
        userHandle: userID.data(using: .utf8)!,
        userName: username,
        displayName: displayName
    )

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.performRequests()
}

// 2. Authenticate with passkey
func authenticateWithPasskey() {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: "app.example.com"
    )

    let challenge = generateChallenge() // Server-provided
    let request = provider.createAssertionRequest(challenge: challenge)

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.performRequests()
}
```

---

## Additional Resources

- [Apple Passkeys Documentation](https://developer.apple.com/passkeys/)
- [WebAuthn Specification](https://w3c.github.io/webauthn/)
- [FIDO2 Alliance](https://fidoalliance.org/)
- [MASTG Authentication](https://mas.owasp.org/MASTG/0x04d-Testing-Authentication-and-Session-Management.html)

---

**Next Steps**: See [secure-enclave-probe.js](../assets/frida-scripts/secure-enclave-probe.js) for Secure Enclave runtime analysis and [crypto-hook-ios.js](../assets/frida-scripts/crypto-hook-ios.js) for cryptographic monitoring.
