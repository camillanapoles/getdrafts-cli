# Memory Analysis for iOS Apps

## Overview

Memory analysis is critical for finding secrets that exist in cleartext during runtime, even if they're encrypted on disk or in transit. Sensitive data such as API keys, passwords, tokens, and decrypted content can often be extracted from memory.

**Why memory analysis matters**:
- Decrypted data is cleartext in memory
- Secrets may be hardcoded and only used at runtime
- Session tokens and authentication credentials
- Cached user input (passwords, credit cards)
- Encryption keys and certificates

---

## 1. Memory Dumping Tools

### fridump

fridump is a Python tool that dumps process memory using Frida.

**Installation**:
```bash
pip3 install fridump
```

**Usage (Device)**:
```bash
fridump -U -f com.example.app -o dump/
```

**Usage (Emulator)**:
```bash
fridump -e com.example.app -o dump/
```

**Output**: Directory with memory regions as binary files

---

### objection Heap Dump

objection can dump the Objective-C heap for object analysis.

**Usage**:
```bash
objection -g com.example.app explore
ios heap dump ~/heap_dump/
```

**Output**: JSON file with heap objects and their values

---

### Frida Memory APIs

Direct memory reading and scanning using Frida scripts.

**Read memory**:
```javascript
// Read specific address
var data = ptr("0x100000000").readByteArray(1024);
console.log(hexdump(data));
```

**Scan memory**:
```javascript
// Scan for pattern
Memory.scanSync(ptr("0x100000000"), 1024 * 1024, "48 65 6c 6c 6f", {
  onMatch: function(address, size) {
    console.log("Found at: " + address);
  },
  onComplete: function() {
    console.log("Scan complete");
  }
});
```

---

## 2. Analysis Workflow

### Step 1: Trigger Sensitive Operations

Before dumping memory, trigger the operations that load secrets:
- Login with credentials
- Make API calls
- Decrypt data
- Access protected features

### Step 2: Dump Memory

**Immediately after triggering**, dump memory:

```bash
# With fridump
fridump -U com.example.app -o dump/

# Or with custom Frida script
frida -U com.example.app -l assets/frida-scripts/memory-dumper-ios.js
```

### Step 3: Search for Patterns

```bash
# Convert to strings
strings dump/* | tee strings.txt

# Search for common secret patterns
strings.txt | rg -i "password\|token\|key\|secret\|api"

# Search for specific patterns
strings.txt | rg "sk-[a-z0-9]{32}"        # Stripe keys
strings.txt | rg "AKIA[0-9A-Z]{16}"       # AWS keys
strings.txt | rg "ghp_[a-zA-Z0-9]{36}"    # GitHub tokens
strings.txt | rg "ey[A-Za-z0-9_-]+\."     # JWT tokens
```

---

## 3. Common Secret Patterns

### API Keys and Tokens

| Service | Pattern | Example |
|---------|---------|---------|
| **Stripe** | `sk-[a-z0-9]{32}` | `sk_test_51abc...` |
| **AWS** | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| **GitHub** | `ghp_[a-zA-Z0-9]{36}` | `ghp_1234567890abcdef...` |
| **JWT** | `ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.` | `eyJhbGciOi...` |
| **Generic API Key** | `api[_-]?key.*["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{20,}` | Various |

### Credentials

```bash
# Search for credential pairs
strings.txt | rg -i "username.*password\|user.*pass\|email.*pass"

# Search for common auth headers
strings.txt | rg -i "authorization.*bearer\|x-api-key\|authentication"
```

### Encryption Keys

```bash
# Look for hex strings (potential AES keys)
strings.txt | rg "0x[0-9a-fA-F]{32}"     # 128-bit key
strings.txt | rg "0x[0-9a-fA-F]{64}"     # 256-bit key

# Look for base64-encoded data
strings.txt | rg "[A-Za-z0-9+/]{32,}={0,2}"
```

---

## 4. Advanced Memory Analysis

### Finding Objects in ObjC/Swift

```javascript
// Find all NSString objects
if (ObjC.available) {
    var NSString = ObjC.classes.NSString;
    ObjC.choose(NSString, {
        onMatch: function(instance) {
            var str = instance.toString();
            if (str.includes("password") || str.includes("key")) {
                console.log("Found: " + str);
            }
        },
        onComplete: function() {}
    });
}
```

### Finding HTTP Responses

```javascript
// Find NSURLResponse objects with data
if (ObjC.available) {
    ObjC.choose(ObjC.classes.NSURLResponse, {
        onMatch: function(instance) {
            console.log("Response: " + instance.toString());
        },
        onComplete: function() {}
    });
}
```

### Monitoring Memory Allocation

```javascript
// Hook NSData allocation to capture sensitive data
var NSData = ObjC.classes.NSData;
Interceptor.attach(NSDATA["-initWithBytes:length:"].implementation, {
    onEnter: function(args) {
        var data = args[2].readUtf8String(100);
        if (data.includes("password") || data.includes("token")) {
            console.log("NSData with sensitive data: " + data);
        }
    }
});
```

---

## 5. Frida Memory Dumper Script

For a complete memory dumper implementation, see `assets/frida-scripts/memory-dumper-ios.js`.

**Key features**:
- Scans all readable memory regions
- Searches for common secret patterns
- Outputs JSON with secrets + memory addresses
- Works on simulator and device

**Usage**:
```bash
frida -U -f com.example.app -l assets/frida-scripts/memory-dumper-ios.js
```

---

## 6. Static Analysis for Memory Issues

### Hardcoded Secrets

```bash
# Search for hardcoded secrets in source
rg "(password|token|key|secret)\s*=\s*['\"]" . --exclude-dir=Frameworks/

# Search for base64-encoded secrets
rg "[A-Za-z0-9+/]{32,}={0,2}" . --exclude-dir=Frameworks/ | head -20
```

### Insecure Memory Handling

```bash
# Look for sensitive data in mutable containers
rg -A 5 "NSMutableString\|NSMutableData" . --exclude-dir=Frameworks/ | rg -i "password\|secret\|key"

# Check for proper cleanup
rg "memset.*0\|secureZero" . --exclude-dir=Frameworks/
```

---

## 7. Memory Disclosure Vulnerabilities

### What to Look For

1. **Hardcoded credentials in memory**
   - Credentials hardcoded in source
   - Visible in static analysis but confirmed in memory

2. **Decrypted data**
   - Database content after decryption
   - API responses with sensitive data
   - User input before secure storage

3. **Session tokens**
   - Authentication tokens
   - Session cookies
   - OAuth tokens

4. **Encryption keys**
   - Symmetric keys for data encryption
   - Private keys for signing
   - Key derivation outputs

### Testing Steps

```bash
# 1. Start the app
frida -U -f com.example.app

# 2. Trigger sensitive operation
#    - Login
#    - Load protected data
#    - Make API call

# 3. Dump memory
fridump -U com.example.app -o dump/

# 4. Search for secrets
strings dump/* | rg -i "password|token|key"
```

---

## 8. Prevention Guidance

### For Developers

**DO**:
- Use secure storage (Keychain) for secrets
- Clear sensitive data from memory after use
- Use immutable containers for sensitive data
- Implement proper memory zeroization

**DON'T**:
- Hardcode secrets in source code
- Store secrets in UserDefaults
- Log sensitive data
- Keep decrypted data in memory longer than necessary

### Memory Zeroization (Swift)

```swift
// Proper zeroization of sensitive data
func secureZero(_ data: inout Data) {
    data.withUnsafeMutableBytes { bytes in
        memset(bytes.baseAddress, 0, data.count)
    }
}

// For strings
func securelyClear(_ string: inout String) {
    string = ""
    string.reserveCapacity(0)
}
```

---

## 9. Generalized Testing Checklist

- [ ] Dump memory after login (check for credentials)
- [ ] Dump memory after API call (check for tokens)
- [ ] Search for hardcoded secrets (static analysis)
- [ ] Verify no sensitive data in NSString objects
- [ ] Check for decrypted database content
- [ ] Verify session tokens are properly protected
- [ ] Test memory zeroization for sensitive data

---

## 10. Example: Finding Hardcoded Credentials in Memory

Many apps contain hardcoded credentials that remain in cleartext during runtime. This example demonstrates how to find them.

**Sample vulnerable code**:
```swift
// In SensitiveDataStorageViewController
let username = "testuser"
let password = "TestPass123!"
```

**How to find**:
```bash
# 1. Trigger the sensitive feature
#    - Navigate to screen that uses credentials
#    - Login or access protected data

# 2. Dump memory immediately
fridump -U -f com.example.app -o dump/

# 3. Search for credentials
strings dump/* | rg "testuser|TestPass"

# Expected: Found in memory as cleartext
```

**What to look for**:
- Username/password pairs
- API keys and tokens
- Session identifiers
- Decrypted database content

---

## References

- [SKILL.md](../SKILL.md) - Complete iOS pentesting methodology
- [side-channel-analysis-ios.md](side-channel-analysis-ios.md) - Side channel data leakage
- [commoncrypto-analysis.md](commoncrypto-analysis.md) - Cryptography analysis

**For Frida scripts**, see [assets/frida-scripts/](../assets/frida-scripts/).

**For tool installation**, see [tool-installation-ios.md](tool-installation-ios.md).

---

**For troubleshooting**, see [troubleshooting-ios.md](troubleshooting-ios.md).
