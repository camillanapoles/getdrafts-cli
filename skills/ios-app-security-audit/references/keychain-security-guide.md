# iOS Keychain Security Guide

## Table of Contents

1. [Overview](#overview)
2. [Keychain Fundamentals](#keychain-fundamentals)
3. [Keychain API](#keychain-api)
4. [Accessibility Levels](#accessibility-levels)
5. [Access Control](#access-control)
6. [Keychain Groups](#keychain-groups)
7. [Secure Enclave](#secure-enclave)
8. [Testing with Frida](#testing-with-frida)
9. [Common Vulnerabilities](#common-vulnerabilities)
10. [Remediation Code](#remediation-code)
11. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

The iOS Keychain provides secure storage for sensitive data such as passwords, encryption keys, and authentication tokens. This guide covers Keychain APIs, security features, testing methodologies, common vulnerabilities, and remediation strategies.

### Why Test Keychain Security?

- **Verify secure storage**: Ensure sensitive data properly protected
- **Test access controls**: Check accessibility settings are appropriate
- **Evaluate encryption**: Verify data encrypted at rest
- **Audit key usage**: Review what apps access Keychain
- **Identify vulnerabilities**: Find weak configurations or misuse

---

## Keychain Fundamentals

### Keychain Architecture

```
┌─────────────────────────────────────────┐
│           iOS Keychain                 │
│  ┌───────────────────────────────────┐ │
│  │   Keychain Database               │ │
│  │   - Encrypted at rest             │ │
│  │   - Access controlled             │ │
│  │   - Backed up to iCloud (optional)│ │
│  └───────────────────────────────────┘ │
│                                         │
│  Access Control:                        │
│  - Accessibility levels                │
│  - SecAccessControl                    │
│  - Keychain access groups              │
│  - App-specific access                 │
└─────────────────────────────────────────┘
```

### Keychain Data Types

| Type | Description | Use Case |
|------|-------------|----------|
| kSecClassGenericPassword | Password string | User passwords, API keys |
| kSecClassInternetPassword | Web password | HTTP authentication |
| kSecClassCertificate | X.509 certificate | SSL/TLS certificates |
| kSecClassKey | Cryptographic key | Encryption keys, signing keys |
| kSecClassIdentity | Certificate + Private Key | Client authentication |

### Keychain Location (iOS)

The iOS keychain is a **system-wide facility** managed by the `securityd` daemon. It is NOT stored inside the app's sandbox container.

```bash
# System-level keychain database
/private/var/Keychains/        # iOS 10 and earlier
/var/db/keychain/              # iOS 11+ (modern)

# Files (system level — not directly accessible to apps):
keychain-2.db
keychain-2.db-shm
keychain-2.db-wal

# Note: iOS apps NEVER have direct filesystem access to the
# keychain database. All access goes through the Security
# framework APIs (SecItemAdd, SecItemCopyMatching, etc.).
# Pentesters can extract keychain items via:
# 1. Jailbroken device (filesystem access to the system db)
# 2. Encrypted iTunes/Finder backup + keychain backup tool
# 3. Runtime dumping via Frida (keychain-dumper.js)
# 4. The app's own logs/memory if it mishandles keychain data
```

---

## Keychain API

### SecItemAdd - Adding Items

```swift
import Security
import Foundation

// Add generic password
func addPassword(service: String, account: String, password: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
    ]

    let status = SecItemAdd(query as CFDictionary, nil)

    if status == errSecDuplicateItem {
        print("Item already exists")
        return false
    } else if status == errSecSuccess {
        print("Password added successfully")
        return true
    } else {
        print("Error adding password: \(status)")
        return false
    }
}

// Add with custom accessibility
func addSecurePassword(service: String, account: String, password: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}
```

### SecItemCopyMatching - Reading Items

```swift
// Read generic password
func readPassword(service: String, account: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        return String(data: data, encoding: .utf8)
    }

    return nil
}

// Read all passwords for service
func readAllPasswords(service: String) -> [[String: String]]? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecReturnAttributes as String: true,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess,
          let items = result as? [[String: Any]] else {
        return nil
    }

    return items.map { item in
        var dict = [String: String]()

        if let account = item[kSecAttrAccount as String] as? String {
            dict["account"] = account
        }

        if let data = item[kSecValueData as String] as? Data {
            dict["password"] = String(data: data, encoding: .utf8)
        }

        return dict
    }
}
```

### SecItemUpdate - Updating Items

```swift
// Update password
func updatePassword(service: String, account: String, newPassword: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]

    let attributes: [String: Any] = [
        kSecValueData as String: newPassword.data(using: .utf8)!
    ]

    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    return status == errSecSuccess
}

// Update accessibility
func updateAccessibility(service: String, account: String, newAccessibility: CFString) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]

    let attributes: [String: Any] = [
        kSecAttrAccessible as String: newAccessibility
    ]

    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    return status == errSecSuccess
}
```

### SecItemDelete - Deleting Items

```swift
// Delete specific item
func deletePassword(service: String, account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]

    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
}

// Delete all items for service
func deleteAllPasswords(service: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service
    ]

    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
}

// Delete all keychain items (BE CAREFUL!)
func deleteAllItems() -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword
    ]

    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
}
```

---

## Accessibility Levels

### Accessibility Constants

| Constant | Description | Security Level |
|----------|-------------|----------------|
| `kSecAttrAccessibleWhenUnlocked` | Available when device unlocked (default) | OK for general use |
| `kSecAttrAccessibleAfterFirstUnlock` | Available after first unlock (until reboot) | Lower |
| `kSecAttrAccessibleAlways` | **DEPRECATED iOS 12** — always available | Never use |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Device passcode required, no iCloud backup | Best for sensitive data |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Device unlocked, no iCloud backup | Better |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | After first unlock, no iCloud backup | OK |

### Accessibility Examples

```swift
// Default (recommended) - Available when unlocked
func storeDefaultData(password: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app",
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
    ]

    SecItemAdd(query as CFDictionary, nil)
}

// Low security - Available after first unlock
func storeLowSecurityData(password: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app",
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
    ]

    SecItemAdd(query as CFDictionary, nil)
}

// High security - Passcode required, no backup
func storeHighSecurityData(password: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app",
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    ]

    SecItemAdd(query as CFDictionary, nil)
}
```

### Accessibility Decision Tree

```
Data Sensitivity → Accessibility Level
│
├─ Highly Sensitive (API keys, encryption keys)
│  └─ kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
│     ✅ Requires passcode
│     ✅ No iCloud backup
│     ✅ Lost device = data lost
│
├─ Sensitive (auth tokens, passwords)
│  └─ kSecAttrAccessibleWhenUnlockedThisDeviceOnly
│     ✅ Device must be unlocked
│     ✅ No iCloud backup
│
├─ Moderately Sensitive (user preferences, settings)
│  └─ kSecAttrAccessibleWhenUnlocked
│     ⚠️ Device must be unlocked
│     ⚠️ Backs up to iCloud
│
└─ Low Sensitivity (cache, temporary data)
   └─ kSecAttrAccessibleAfterFirstUnlock
      ❌ Available even when locked
      ❌ Backs up to iCloud
```

---

## Access Control

### SecAccessControl API

```swift
import LocalAuthentication

// Store password with biometric protection
func storeWithBiometrics(password: String) -> Bool {
    var error: Unmanaged<CFError>?

    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .userPresence,
        &error
    ) else {
        print("Error creating access control: \(error!.takeRetainedValue())")
        return false
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app",
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessControl as String: accessControl
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}

// Read password with biometric prompt
func readWithBiometrics(service: String, account: String, completion: @escaping (String?) -> Void) {
    let context = LAContext()
    context.localizedCancelTitle = "Cancel"

    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        completion(nil)
        return
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecUseOperationPrompt as String: "Authenticate to access password",
        kSecUseAuthenticationContext as String: context
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        completion(String(data: data, encoding: .utf8))
    } else {
        completion(nil)
    }
}

// Access Control Flags
enum AccessControlFlags {
    case userPresence              // Touch ID / Face ID or passcode
    case biometryAny              // Any enrolled biometric
    case biometryCurrentSet       // Currently enrolled biometric only
    case devicePasscode           // Passcode required
    case privateKeyUsage          // For keys only
    case applicationPassword      // Application-specific password
}
```

### SecAccessControl with Keys

```swift
// Generate key with access control
func generateSecureKey() -> SecKey? {
    let accessControlError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .privateKeyUsage,
        &accessControlError
    ) else {
        return nil
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 2048,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.app.key",
            kSecAttrAccessControl as String: accessControl
        ]
    ]

    var error: Unmanaged<CFError>?
    return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
}

// Sign data with biometric protection
func signData(data: Data, completion: @escaping (Data?) -> Void) {
    let context = LAContext()

    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: "com.example.app.key",
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecReturnRef as String: true,
        kSecUseOperationPrompt as String: "Authenticate to sign data",
        kSecUseAuthenticationContext as String: context
    ]

    var keyItem: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &keyItem)

    guard status == errSecSuccess,
          let privateKey = keyItem as? SecKey else {
        completion(nil)
        return
    }

    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        &error
    ) else {
        completion(nil)
        return
    }

    completion(signature as Data)
}
```

---

## Keychain Groups

### Sharing Data Between Apps

```swift
// App 1: Store data in shared Keychain
func storeSharedData(service: String, account: String, password: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: password.data(using: .utf8)!,
        kSecAttrAccessGroup as String: "TEAMID.com.example.shared"
    ]

    SecItemAdd(query as CFDictionary, nil)
}

// App 2: Read shared data
func readSharedData(service: String, account: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecAttrAccessGroup as String: "TEAMID.com.example.shared"
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        return String(data: data, encoding: .utf8)
    }

    return nil
}
```

### Entitlements Configuration

```xml
<!-- App 1 Entitlements -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.app1</string>
        <string>TEAMID.com.example.shared</string>
    </array>
</dict>
</plist>

<!-- App 2 Entitlements -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.app2</string>
        <string>TEAMID.com.example.shared</string>
    </array>
</dict>
</plist>
```

---

## Secure Enclave

### Storing Keys in Secure Enclave

```swift
// Generate key pair in Secure Enclave
func generateSecureEnclaveKey() -> SecKey? {
    let accessControlError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .privateKeyUsage,
        &accessControlError
    ) else {
        return nil
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.app.secure.key",
            kSecAttrAccessControl as String: accessControl,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave  // Secure Enclave
        ]
    ]

    var error: Unmanaged<CFError>?
    let keyPair = SecKeyCreateRandomKey(attributes as CFDictionary, &error)

    return keyPair
}

// Sign with Secure Enclave key
func signWithSecureEnclave(data: Data, completion: @escaping (Data?) -> Void) {
    let context = LAContext()

    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: "com.example.app.secure.key",
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
        kSecUseOperationPrompt as String: "Authenticate to sign",
        kSecUseAuthenticationContext as String: context
    ]

    var keyItem: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &keyItem)

    guard status == errSecSuccess,
          let privateKey = keyItem as? SecKey else {
        completion(nil)
        return
    }

    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        &error
    ) else {
        completion(nil)
        return
    }

    completion(signature as Data)
}
```

### Secure Enclave Benefits

| Feature | Secure Enclave | Software Keychain |
|---------|----------------|-------------------|
| Private Key Storage | Hardware-isolated | Software-isolated |
| Key Extraction | Impossible | Possible |
| Biometric Enforcement | Native | Possible |
| Device Loss Protection | High | Medium |
| Performance | Excellent | Good |

---

## Testing with Frida

### Hooking Keychain Operations

```javascript
// keychain-hook.js - Hook SecItem functions
if (ObjC.available) {
    console.log("[*] Hooking Keychain operations...");

    // Hook SecItemAdd
    var secMod = Process.findModuleByName('Security');
    var SecItemAdd = secMod ? secMod.findExportByName('SecItemAdd') : null;

    Interceptor.attach(SecItemAdd, {
        onEnter: function(args) {
            console.log("\n[+] SecItemAdd called");
            var query = ObjC.Object(args[0]);
            console.log("  Query:", query);

            // Log kSecClass
            var secClass = query.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecClass"));
            if (secClass) {
                console.log("  Class:", secClass);
            }

            // Log service
            var service = query.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecAttrService"));
            if (service) {
                console.log("  Service:", service);
            }

            // Log account
            var account = query.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecAttrAccount"));
            if (account) {
                console.log("  Account:", account);
            }

            // Log accessibility
            var accessible = query.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecAttrAccessible"));
            if (accessible) {
                console.log("  Accessibility:", accessible);
            }
        },
        onLeave: function(retval) {
            console.log("  Result:", retval.toInt32());
        }
    });

    // Hook SecItemCopyMatching
    var SecItemCopyMatching = secMod ? secMod.findExportByName('SecItemCopyMatching') : null;

    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            console.log("\n[+] SecItemCopyMatching called");
            var query = ObjC.Object(args[0]);
            console.log("  Query:", query);
        },
        onLeave: function(retval) {
            console.log("  Result:", retval);
            if (retval.toInt32() === 0) {  // errSecSuccess
                console.log("  Item found!");
                var result = args[1];
                console.log("  Result pointer:", result);
            }
        }
    });

    // Hook SecItemUpdate
    var SecItemUpdate = secMod ? secMod.findExportByName('SecItemUpdate') : null;

    Interceptor.attach(SecItemUpdate, {
        onEnter: function(args) {
            console.log("\n[+] SecItemUpdate called");
            var query = ObjC.Object(args[0]);
            var attributes = ObjC.Object(args[1]);
            console.log("  Query:", query);
            console.log("  Attributes:", attributes);
        },
        onLeave: function(retval) {
            console.log("  Result:", retval.toInt32());
        }
    });

    // Hook SecItemDelete
    var SecItemDelete = secMod ? secMod.findExportByName('SecItemDelete') : null;

    Interceptor.attach(SecItemDelete, {
        onEnter: function(args) {
            console.log("\n[+] SecItemDelete called");
            var query = ObjC.Object(args[0]);
            console.log("  Query:", query);
        },
        onLeave: function(retval) {
            console.log("  Result:", retval.toInt32());
        }
    });

    console.log("[*] Keychain hooks installed");
}

// Run:
```

```bash
frida -U -l keychain-hook.js -f com.example.app
```

### Dumping Keychain with Frida

```javascript
// keychain-dump.js - Dump all Keychain items
if (ObjC.available) {
    function dumpKeychain() {
        console.log("\n[*] Dumping Keychain...");

        var secMod = Process.findModuleByName('Security');
        var SecItemCopyMatching = secMod ? secMod.findExportByName('SecItemCopyMatching') : null;

        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("kSecClassGenericPassword"), ObjC.classes.NSString.stringWithString_("kSecClass"));
        query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("kCFBooleanTrue"), ObjC.classes.NSString.stringWithString_("kSecReturnAttributes"));
        query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("kCFBooleanTrue"), ObjC.classes.NSString.stringWithString_("kSecReturnData"));
        query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("kSecMatchLimitAll"), ObjC.classes.NSString.stringWithString_("kSecMatchLimit"));

        var resultPtr = Memory.alloc(8);
        var status = new NativeFunction(SecItemCopyMatching, 'int', ['pointer', 'pointer'])(query, resultPtr);

        if (status === 0) {  // errSecSuccess
            var result = new ObjC.Object(resultPtr.readPointer());

            console.log("[+] Found " + result.count() + " items");

            for (var i = 0; i < result.count(); i++) {
                var item = result.objectAtIndex_(i);
                console.log("\n  Item " + i + ":");

                var service = item.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecAttrService"));
                var account = item.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecAttrAccount"));
                var data = item.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecValueData"));

                if (service) {
                    console.log("    Service:", service);
                }
                if (account) {
                    console.log("    Account:", account);
                }
                if (data) {
                    var password = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);  // UTF8
                    console.log("    Password:", password);
                }
            }
        } else {
            console.log("[-] Failed to dump Keychain");
        }
    }

    dumpKeychain();
}

// Run:
```

```bash
frida -U -l keychain-dump.js -f com.example.app
```

### Using Objection

```bash
# Start Objection session
objection -g com.example.app explore

# Dump Keychain
ios keychain dump

# Dump to JSON
ios keychain dump --json keychain_dump.json

# Search for specific items
ios keychain dump --filter com.example.app
```

---

## Common Vulnerabilities

### 1. Weak Accessibility

**Problem**: Using `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAfterFirstUnlock` for sensitive data.

```swift
// ❌ VULNERABLE
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: apiKey.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways  // ALWAYS accessible!
]
```

**Impact**: Data accessible even when device locked.

**Fix**:
```swift
// ✅ SECURE
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: apiKey.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
]
```

---

### 2. No Access Control

**Problem**: Not using `SecAccessControl` for sensitive data.

```swift
// ❌ VULNERABLE - No biometric/passcode protection
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: password.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
]
```

**Impact**: Data accessible without authentication.

**Fix**:
```swift
// ✅ SECURE - Requires authentication
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .userPresence,
    nil
)!

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: password.data(using: .utf8)!,
    kSecAttrAccessControl as String: accessControl
]
```

---

### 3. Plaintext Passwords in Keychain

**Problem**: Storing passwords without additional encryption.

```swift
// ❌ VULNERABLE - Password in Keychain (encrypted by iOS but not app-specific)
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: "my_password_123".data(using: .utf8)!
]
```

**Impact**: If Keychain compromised, passwords exposed.

**Fix**:
```swift
// ✅ SECURE - Encrypt password before storing
let password = "my_password_123"
let encryptedPassword = encryptPassword(password)  // App-specific encryption

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: encryptedPassword,
    kSecAttrAccessControl as String: accessControl
]
```

---

### 4. Hardcoded Keys

**Problem**: Encryption keys hardcoded in app.

```swift
// ❌ VULNERABLE
let encryptionKey = "0123456789ABCDEF0123456789ABCDEF"  // Hardcoded!
let encryptedPassword = encrypt(password, key: encryptionKey)
```

**Impact**: Key easily extracted from binary.

**Fix**:
```swift
// ✅ SECURE - Use Keychain for encryption key
func getEncryptionKey() -> Data {
    var key: Data?

    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: "com.example.app.encryption.key",
        kSecReturnData as String: true
    ]

    SecItemCopyMatching(query as CFDictionary, &key)

    if key == nil {
        // Generate new key
        key = generateRandomKey()
        storeEncryptionKey(key!)
    }

    return key!
}
```

---

## Remediation Code

### Secure Keychain Helper

```swift
import Security
import LocalAuthentication
import CryptoKit

class SecureKeychain {

    // MARK: - Constants

    static let accessGroup = "TEAMID.com.example.shared"

    // MARK: - Store Password

    static func storePassword(
        service: String,
        account: String,
        password: String,
        requiresBiometrics: Bool = true
    ) -> Bool {

        var accessControl: SecAccessControl?

        if requiresBiometrics {
            var error: Unmanaged<CFError>?
            accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .userPresence,
                &error
            )
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: password.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            kSecAttrAccessGroup as String: accessGroup
        ]

        if let accessControl = accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        }

        let status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            return updatePassword(service: service, account: account, password: password)
        }

        return status == errSecSuccess
    }

    // MARK: - Read Password

    static func readPassword(
        service: String,
        account: String,
        requiresBiometrics: Bool = false,
        completion: @escaping (String?) -> Void
    ) {

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccessGroup as String: accessGroup
        ]

        if requiresBiometrics {
            let context = LAContext()
            context.localizedCancelTitle = "Cancel"

            var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                completion(nil)
                return
            }

            query[kSecUseOperationPrompt as String] = "Authenticate to access password"
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let data = result as? Data {
            completion(String(data: data, encoding: .utf8))
        } else {
            completion(nil)
        }
    }

    // MARK: - Update Password

    static func updatePassword(
        service: String,
        account: String,
        password: String
    ) -> Bool {

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup
        ]

        let attributes: [String: Any] = [
            kSecValueData as String: password.data(using: .utf8)!
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        return status == errSecSuccess
    }

    // MARK: - Delete Password

    static func deletePassword(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

    // MARK: - Generate Secure Key

    static func generateSecureKey(tag: String) -> SecKey? {
        var error: Unmanaged<CFError>?

        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .privateKeyUsage,
            &error
        )

        guard accessControl != nil else {
            return nil
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl!,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
        ]

        return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    }

    // MARK: - Sign with Secure Key

    static func signWithSecureKey(
        tag: String,
        data: Data,
        completion: @escaping (Data?) -> Void
    ) {

        let context = LAContext()
        context.localizedCancelTitle = "Cancel"

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseOperationPrompt as String: "Authenticate to sign",
            kSecUseAuthenticationContext as String: context
        ]

        var keyItem: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &keyItem)

        guard status == errSecSuccess,
              let privateKey = keyItem as? SecKey else {
            completion(nil)
            return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) else {
            completion(nil)
            return
        }

        completion(signature as Data)
    }
}
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Keychain Context |
|---------------|-------|------------------|
| MASTG-TEST-0040 | Data Storage Security Testing | Keychain testing |
| MASTG-APP-SEC-0030 | Cryptographic Verification | Secure Enclave |
| MASTG-TEST-0045 | Keychain Analysis | Keychain enumeration |
| MASTG-APP-SEC-0040 | Secure Storage | Keychain best practices |

---

## Summary

This guide covered:
- Keychain fundamentals and data types
- Core Keychain APIs (Add, CopyMatching, Update, Delete)
- Accessibility levels and their security implications
- SecAccessControl for biometric/passcode protection
- Keychain groups for data sharing
- Secure Enclave for hardware-isolated key storage
- Testing with Frida and Objection
- Common vulnerabilities and their impacts
- Secure Keychain helper class

The iOS Keychain provides secure storage for sensitive data, but proper configuration is essential. Always use appropriate accessibility levels, implement access control, and consider the Secure Enclave for cryptographic operations.

---

## References

### Official Documentation
- Apple Keychain Services: https://developer.apple.com/documentation/security/keychain_services
- SecAccessControl: https://developer.apple.com/documentation/security/secaccesscontrol
- Secure Enclave: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- iOS Security Guide: https://support.apple.com/guide/security/
- Common Crypto: https://developer.apple.com/documentation/security
- LocalAuthentication: https://developer.apple.com/documentation/localauthentication

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, iOS developers
**Prerequisites:** iOS development knowledge, Swift/Objective-C, Security framework understanding
