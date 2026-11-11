# Insecure Deserialization - iOS Security Testing Guide

## Table of Contents

1. [Overview](#overview)
2. [Understanding iOS Deserialization](#understanding-ios-deserialization)
3. [Critical APIs and Vectors](#critical-apis-and-vectors)
4. [Attack Vectors and Gadget Chains](#attack-vectors-and-gadget-chains)
5. [Testing Methodology](#testing-methodology)
6. [Frida Detection](#frida-detection)
7. [Secure Coding Practices](#secure-coding-practices)
8. [MASTG References](#mastg-references)

---

## Overview

Insecure deserialization is one of the most critical vulnerabilities in iOS applications, potentially leading to Remote Code Execution (RCE) through gadget chains. This guide covers iOS deserialization security, common attack vectors, detection methods, and secure alternatives.

### Why Deserialization Security Matters

- **RCE Potential**: NSKeyedUnarchiver can instantiate arbitrary objects
- **Gadget Chains**: Combination of classes can create exploit chains
- **Data Tampering**: Serialized data can be modified in transit
- **Persistence**: Archives stored in UserDefaults or Keychain
- **MASTG Priority**: TEST-0018 - Insecure Deserialization

---

## Understanding iOS Deserialization

### Serialization in iOS

iOS provides multiple serialization mechanisms:

| Mechanism | Security | Use Case | Risk Level |
|-----------|----------|----------|------------|
| NSKeyedArchiver | Depends | Object graphs | High |
| Codable (Swift) | Better | Swift types | Medium |
| Property Lists | Low | Simple data | Medium |
| JSON | Safe | Interop | Low |

### NSKeyedArchiver/NSKeyedUnarchiver

```objectivec
// Vulnerable: Unsanitized deserialization
NSData *data = [userInput dataUsingEncoding:NSUTF8StringEncoding];
id object = [NSKeyedUnarchiver unarchiveObjectWithData:data];
// Can execute arbitrary code if data contains malicious class chain
```

```swift
// Secure: Using NSSecureCoding
if let data = userInput.data(using: .utf8) {
    NSKeyedUnarchiver.setRequiresSecureCoding(true)
    if let object = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSString.self, from: data) {
        // Safe - class is whitelisted
    }
}
```

---

## Critical APIs and Vectors

### High-Risk APIs

#### NSKeyedUnarchiver

```objectivec
// Dangerous methods
+ (id)unarchiveObjectWithData:(NSData *)data;
+ (id)unarchiveTopLevelObjectWithData:(NSData *)data;
+ (BOOL)unarchiveObjectWithFile:(NSString *)path;
```

#### NSKeyedArchiver

```objectivec
// Monitored methods
+ (NSData *)archivedDataWithRootObject:(id)rootObject;
- (instancetype)initRequiringSecureCoding:(BOOL)requiresSecureCoding;
```

#### NSSecureCoding Protocol

```objectivec
// Check for secure coding support
+ (BOOL)supportsSecureCoding;
- (instancetype)initWithCoder:(NSCoder *)coder;
```

### Common Danger Patterns

1. **UserDefaults with serialized objects**
   ```objectivec
   // Vulnerable
   [[NSUserDefaults standardUserDefaults] setObject:archivedData forKey:@"user"];
   ```

2. **Keychain with archives**
   ```objectivec
   // Vulnerable
   [keychainData setObject:archivedObject forKey:@"session"];
   ```

3. **IPC with untrusted data**
   ```objectivec
   // Vulnerable
   NSData *data = [notification.userInfo objectForKey:@"payload"];
   id object = [NSKeyedUnarchiver unarchiveObjectWithData:data];
   ```

---

## Attack Vectors and Gadget Chains

### Gadget Chain Concept

A gadget chain exploits the deserialization process by:

1. **Trigger**: Vulnerable deserialization point
2. **Gadget**: Class that executes code in `initWithCoder:` or `awakeAfterUsingCoder:`
3. **Chain**: Multiple gadgets combined for RCE

### Common iOS Gadget Classes

| Class | Dangerous Method | Potential Impact |
|-------|------------------|------------------|
| NSTimer | initWithCoder: | Code execution |
| NSURLRequest | initWithCoder: | SSRF |
| UIBezierPath | initWithCoder: | Memory corruption |
| NSValueTransformer | initWithCoder: | Type confusion |

### Example Gadget Chain

```
[Malicious Archive] → NSKeyedUnarchiver → NSTimer (initWithCoder:)
                                          → Selector invocation
                                          → Arbitrary code execution
```

---

## Testing Methodology

### Static Analysis

#### Pattern Detection

```bash
# Search for unsafe deserialization
grep -r "unarchiveObjectWithData" . --include="*.swift" --include="*.m"

# Check for NSSecureCoding
grep -r "supportsSecureCoding" . --include="*.swift" --include="*.m"

# Find UserDefaults archives
grep -r "UserDefaults.*archive" . --include="*.swift" --include="*.m"
```

#### Binary Analysis

```bash
# Check for NSKeyedUnarchiver usage
otool -tV "<app_binary>" | grep -i "unarchiveObjectWithData"

# Look for NSSecureCoding flag
otool -tV "<app_binary>" | grep -i "_setRequiresSecureCoding"
```

### Dynamic Analysis

#### Testing Steps

1. **Identify deserialization points**
   - Search for NSKeyedUnarchiver calls
   - Check IPC endpoints
   - Review UserDefaults/Keychain usage

2. **Craft malicious payloads**
   - Create test archives with dangerous classes
   - Modify serialized data in transit
   - Inject through UI inputs

3. **Monitor execution**
   - Use Frida hooks for detection
   - Watch for gadget chain triggers
   - Monitor for crashes or unexpected behavior

---

## Frida Detection

### Using deserialization-hook-ios.js

```bash
# Basic usage
frida -U -f com.example.app -l deserialization-hook-ios.js

# For specific class monitoring
frida -U -f com.example.app -l deserialization-hook-ios.js -e "console.log('Monitoring')"
```

### Manual Hooking

```javascript
// Hook NSKeyedUnarchiver
var NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
var unarchive = NSKeyedUnarchiver["- unarchiveObjectWithData:"];
Interceptor.attach(unarchive.implementation, {
    onLeave: function(retval) {
        if (retval && !retval.isNull()) {
            var obj = ObjC.Object(retval);
            console.log("Deserialized class:", obj.$className);
            console.log("Stack trace:", Thread.backtrace());
        }
    }
});

// Check secure coding status
var secureCoding = NSKeyedUnarchiver["+ allowsSecureCoding"];
console.log("Secure coding allowed:", secureCoding());
```

### Detecting Gadget Chains

```javascript
// Monitor dangerous classes
var dangerousClasses = ["NSTimer", "NSURLRequest", "UIBezierPath"];

dangerousClasses.forEach(function(clsName) {
    if (ObjC.classes[clsName]) {
        var initWithCoder = ObjC.classes[clsName]["- initWithCoder:"];
        if (initWithCoder) {
            Interceptor.attach(initWithCoder.implementation, {
                onEnter: function(args) {
                    console.log("[!] Gadget chain trigger:", clsName);
                    console.log("Stack trace:", Thread.backtrace());
                }
            });
        }
    }
});
```

---

## Secure Coding Practices

### Use NSSecureCoding

```swift
// 1. Adopt NSSecureCoding protocol
class SecureData: NSObject, NSSecureCoding {
    var sensitive: String = ""

    // 2. Implement required methods
    static var supportsSecureCoding: Bool { true }

    func encode(with coder: NSCoder) {
        coder.encode(sensitive, forKey: "sensitive")
    }

    required init?(coder: NSCoder) {
        guard let s = coder.decodeObject(of: NSString.self, forKey: "sensitive") as? String else {
            return nil
        }
        self.sensitive = s
    }
}

// 3. Require secure coding
NSKeyedUnarchiver.setRequiresSecureCoding(true)
if let decoded = try? NSKeyedUnarchiver.unarchivedObject(ofClass: SecureData.self, from: data) {
    // Safe - class is enforced
}
```

### Use Codable for Swift

```swift
// Prefer Codable over NSKeyedArchiver
struct SafeData: Codable {
    let sensitive: String
}

let decoder = JSONDecoder()
let data = try decoder.decode(SafeData.self, from: jsonData)
```

### Validation Best Practices

1. **Class Whitelisting**
   ```swift
   @objc(class: "SpecificClass") + (BOOL)supportsSecureCoding
   ```

2. **Input Validation**
   ```swift
   func validateSerializedData(_ data: Data) -> Bool {
       // Check size, format, expected classes
       return data.count < 1024 * 1024 // 1MB limit
   }
   ```

3. **Avoid Untrusted Sources**
   - Never deserialize from network without validation
   - Validate all IPC payloads
   - Sanitize UserDefaults/Keychain data

---

## MASTG References

### MASTG-TEST-0018: Insecure Deserialization

#### Testing Requirements

- [ ] Identify deserialization points in application
- [ ] Test for unsafe NSKeyedUnarchiver usage
- [ ] Verify NSSecureCoding is enforced
- [ ] Check for gadget chain vulnerabilities
- [ ] Validate UserDefaults/Keychain serialization
- [ ] Test IPC endpoints for malicious payloads

#### Remediation Checklist

- [ ] Enable NSSecureCoding for all archives
- [ ] Use Codable for new Swift code
- [ ] Implement class whitelisting
- [ ] Validate all serialized data
- [ ] Sign or encrypt sensitive archives

### Additional Resources

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Apple NSSecureCoding Documentation](https://developer.apple.com/documentation/foundation/nscoding)
- [MASTG Data Storage](https://mas.owasp.org/MASTG/0x06d-Testing-Data-Storage.html)

### CVSS Scoring

For insecure deserialization vulnerabilities:

| Scenario | Base Score | Vector |
|----------|-------------|--------|
| RCE via gadget chain | 9.8 (Critical) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Data tampering | 7.5 (High) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N |
| DoS via crash | 7.5 (High) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |

---

## Quick Reference

### Detection Commands

```bash
# Find all deserialization usage in codebase
grep -r "unarchiveObject\|decodeObject\|NSCoding" . --include="*.swift" --include="*.m"

# Binary analysis
class-dump "<app_binary>" | grep -i "NSCoding\|NSSecureCoding"

# Runtime hooking
frida -U -f "<bundle_id>" -l deserialization-hook-ios.js
```

### Secure Coding Template

```swift
// Copy-paste template for secure serialization
class SecureObject: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool = true

    func encode(with coder: NSCoder) {
        coder.encode(property, forKey: "property")
    }

    required init?(coder: NSCoder) {
        guard let value = coder.decodeObject(of: NSString.self, forKey: "property") as? String else {
            return nil
        }
        self.property = value
    }
}

// Usage
NSKeyedUnarchiver.setRequiresSecureCoding(true)
let obj = try? NSKeyedUnarchiver.unarchivedObject(ofClass: SecureObject.self, from: data)
```

---

**Next Steps**: See [frida-ios-guide.md](frida-ios-guide.md) for general Frida usage and [crypto-hook-ios.js](../assets/frida-scripts/crypto-hook-ios.js) for related cryptographic monitoring.
