# Mach-O Binary Analysis Guide

**Complete guide to analyzing iOS Mach-O binaries for security vulnerabilities.**

## Table of Contents

1. [Overview](#1-overview)
2. [Mach-O Format Overview](#2-mach-o-format-overview)
3. [Fat Binary / Universal Binary](#3-fat-binary--universal-binary)
4. [Key Analysis Commands](#4-key-analysis-commands)
5. [Segment Analysis](#5-segment-analysis)
6. [Security Features](#6-security-features)
7. [Framework Analysis](#7-framework-analysis)
8. [Symbol Analysis](#8-symbol-analysis)
9. [String Analysis](#9-string-analysis)
10. [Encrypted Binary Detection](#10-encrypted-binary-detection)
11. [Class Extraction](#11-class-extraction)
12. [Disassembler Usage](#12-disassembler-usage)

---

## 1. Overview

### What is Mach-O?

Mach-O (Mach Object) is the file format for executables, object code, shared libraries, and core dumps on macOS and iOS. It's the native binary format for Apple platforms.

### Why Analyze Mach-O Binaries?

- **Reverse engineering**: Understand app functionality and business logic
- **Vulnerability detection**: Find hardcoded secrets, weak crypto, and security flaws
- **Security assessment**: Verify security features (PIE, ARC, stack protection)
- **Hardcoding checks**: Detect embedded credentials, API keys, and sensitive data
- **Framework analysis**: Identify third-party libraries and their security implications

### Mach-O Structure

```
Mach-O File
├── Mach Header (32 or 64-bit)
├── Load Commands
│   ├── Segment Command (code, data, linkedit, etc.)
│   ├── Dylib Command (dynamic library dependencies)
│   ├── Dylinker Command (dynamic linker path)
│   ├── UUID Command (unique identifier)
│   ├── Code Signature Command
│   └── Encryption Info Command
├── Segments
│   ├── __TEXT (code, strings, constants)
│   ├── __DATA (initialized data, exports, imports)
│   └── __LINKEDIT (symbol tables, relocations, code signatures)
└── Section Headers
```

---

## 2. Mach-O Format Overview

### Mach Header

```bash
# Display Mach header
otool -h /path/to/binary

# Example output for arm64:
magic   cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    21     2408   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

**Key Fields**:
- `magic`: Magic number identifying Mach-O format
- `cputype`: CPU architecture (ARM64, x86_64, etc.)
- `filetype`: File type (EXECUTE, DYLIB, etc.)
- `flags`: File flags (PIE, TWOLEVEL, NOUNDEFS, etc.)

### Load Commands

Load commands describe the structure of the binary and tell the kernel/dyld how to load it.

```bash
# Display all load commands
otool -l /path/to/binary

# Display specific load command type
otool -l /path/to/binary | grep -A 20 "LC_SEGMENT_64"
```

**Important Load Commands**:

| Command | Description | Security Relevance |
|----------|-------------|---------------------|
| `LC_SEGMENT_64` | Segment definition | Code and data layout |
| `LC_LOAD_DYLIB` | Dynamic library dependency | Third-party libraries |
| `LC_LOAD_WEAK_DYLIB` | Weak dylib dependency | Optional dependencies |
| `LC_RPATH` | Runtime search path | Library loading |
| `LC_UUID` | Unique identifier | Crash reporting, debugging |
| `LC_CODE_SIGNATURE` | Code signature | Integrity verification |
| `LC_ENCRYPTION_INFO` | Encryption information | FairPlay encryption |
| `LC_MAIN` | Entry point | Application startup |

---

## 3. Fat Binary / Universal Binary

### What is Fat Binary?

A fat binary (universal binary) contains multiple architectures in a single file. This allows the app to run on different device types (iPhone, iPad, Apple Silicon Mac, Intel Mac).

### Detect Fat Binary

```bash
# Check if binary is fat
file /path/to/binary

# Fat binary output:
# Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]

# Single architecture output:
# Mach-O 64-bit executable arm64e
```

### List Architectures

```bash
# Display all architectures
lipo -info /path/to/binary

# Example output:
# Architectures in the fat file: target are: x86_64 arm64e
```

### Extract Specific Architecture

```bash
# Extract arm64 architecture
lipo -thin arm64 -output binary_arm64 /path/to/binary

# Extract x86_64 architecture
lipo -thin x86_64 -output binary_x86_64 /path/to/binary

# Verify extracted architecture
file binary_arm64
# Output: Mach-O 64-bit executable arm64e
```

### Create Universal Binary

```bash
# Create universal binary from multiple architectures
lipo -create arm64_binary x86_64_binary -output universal_binary

# Add architecture to existing universal binary
lipo universal_binary -add armv7_binary -output new_universal_binary
```

### Split Universal Binary

```bash
# Split universal binary into separate architectures
lipo -split universal_binary output_dir/

# Result:
# output_dir/arm64_binary
# output_dir/x86_64_binary
```

---

## 4. Key Analysis Commands

### otool - Display Load Commands

```bash
# Display all load commands
otool -l /path/to/binary

# Display in verbose mode
otool -l -v /path/to/binary

# Display only segment commands
otool -l /path/to/binary | grep -A 15 "LC_SEGMENT_64"
```

### otool - Display Dependencies

```bash
# Display dynamic library dependencies
otool -L /path/to/binary

# Display with arch
otool -L -arch all /path/to/binary

# Example output:
# /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
# /System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 1856.1.0)
# @rpath/AFNetworking.framework/AFNetworking (compatibility version 1.0.0, current version 1.0.0)
```

**Key Patterns**:
- `@executable_path/`: Relative to executable
- `@loader_path/`: Relative to loader
- `@rpath/`: Runtime search path
- Framework paths: `/System/Library/Frameworks/`, `/usr/lib/`

### otool - Display Objective-C Metadata

```bash
# Display Objective-C class list
otool -oV /path/to/binary

# Display class information (non-verbose)
otool -o /path/to/binary

# Display specific class
otool -oV /path/to/binary | grep -A 30 "MyClass"
```

**Output Structure**:
```
@interface MyClass : NSObject {
    NSString *_name;
    NSInteger _age;
}
- (void)method1;
- (void)method2:(NSString *)param;
@end
```

### nm - Display Symbols

```bash
# Display all symbols
nm /path/to/binary

# Display only external (undefined) symbols
nm -u /path/to/binary

# Display only defined symbols
nm -g /path/to/binary

# Display in BSD format (no addresses)
nm -gU /path/to/binary

# Display in POSIX format
nm -P /path/to/binary

# Sort by address
nm -n /path/to/binary

# Display only Objective-C methods
nm /path/to/binary | grep -i "\[-\|\]"
```

**Symbol Types**:
- `T` or `t`: Text section (code)
- `D` or `d`: Data section (initialized data)
- `B` or `b`: BSS section (uninitialized data)
- `U`: Undefined symbol (imported)
- `_`: External symbol

### strings - Extract Strings

```bash
# Extract all strings
strings /path/to/binary

# Extract strings of minimum length
strings -n 8 /path/to/binary

# Extract from specific section
strings -a /path/to/binary

# Search for specific pattern
strings /path/to/binary | grep -i "password\|api_key\|secret\|token"

# Extract URLs
strings /path/to/binary | grep -E "https?://"

# Extract file paths
strings /path/to/binary | grep -E "^/"

# Count occurrences
strings /path/to/binary | grep -c "http"
```

### jtool2 - Enhanced Analysis

```bash
# Display Mach header
jtool2 -h /path/to/binary

# Display load commands
jtool2 -l /path/to/binary

# Disassemble function
jtool2 -d _main /path/to/binary

# Find strings
jtool2 -s "password" /path/to/binary

# Display symbols
jtool2 -t /path/to/binary

# Display sections
jtool2 -S /path/to/binary
```

---

## 5. Segment Analysis

### __TEXT Segment

Contains code, constants, and Objective-C method strings.

```bash
# Display __TEXT section
otool -s __TEXT __text /path/to/binary

# Display __TEXT segment contents
otool -s __TEXT __stubs /path/to/binary
otool -s __TEXT __objc_methname /path/to/binary
otool -s __TEXT __cstring /path/to/binary
```

**Key Sections**:
- `__text`: Main executable code
- `__stubs`: Function stubs for lazy binding
- `__objc_methname`: Objective-C method names
- `__cstring`: C strings (including hardcoded secrets)
- `__objc_classname`: Objective-C class names

### __DATA Segment

Contains initialized data, imports, exports, and Objective-C class references.

```bash
# Display __DATA segment
otool -s __DATA __data /path/to/binary

# Display __objc_ivar section (instance variables)
otool -s __DATA __objc_ivar /path/to/binary

# Display __objc_classlist section (class list)
otool -s __DATA __objc_classlist /path/to/binary

# Display __nl_symbol_ptr section (non-lazy symbol pointers)
otool -s __DATA __nl_symbol_ptr /path/to/binary

# Display __la_symbol_ptr section (lazy symbol pointers)
otool -s __DATA __la_symbol_ptr /path/to/binary
```

**Key Sections**:
- `__data`: Initialized data
- `__objc_ivar`: Instance variables
- `__objc_classlist`: Class list for Objective-C runtime
- `__objc_protolist`: Protocol list
- `__objc_selrefs`: Selector references
- `__bss`: Uninitialized data (zero-initialized)

### __LINKEDIT Segment

Contains symbol tables, relocation entries, and code signatures.

```bash
# Display symbol table
otool -s __LINKEDIT __symtab /path/to/binary

# Display string table
otool -s __LINKEDIT __stringtab /path/to/binary

# Display indirect symbol table
otool -s __LINKEDIT __ind_symtab /path/to/binary
```

**Key Sections**:
- `__symtab`: Symbol table
- `__stringtab`: String table
- `__ind_symtab`: Indirect symbol table
- `__code_signature`: Code signature data

---

## 6. Security Features

### PIE (Position Independent Executable)

PIE makes the binary's base address randomized at load time, making exploit techniques like ROP (Return Oriented Programming) more difficult.

```bash
# Check if PIE is enabled
otool -h /path/to/binary | grep PIE

# Alternative check
codesign -d -vvv /path/to/binary | grep -i pie

# PIE flag in output: flags=0x00000100 (PIE)
```

**Detection**:
- `flags contain PIE` or `0x00000100`: PIE enabled (secure)
- No PIE flag: PIE disabled (vulnerable)

**Remediation**:
- Enable PIE in Xcode build settings: `ENABLE_BITCODE = YES` or add linker flag `-fPIE -pie`

---

### ARC (Automatic Reference Counting)

ARC automatically manages memory for Objective-C objects, reducing memory-related vulnerabilities.

```bash
# Check for ARC (indirect check)
# ARC is detected by absence of manual memory management calls

# Search for retain/release/autorelease
nm /path/to/binary | grep -i "retain\|release\|autorelease"

# If many references to these functions: Manual memory management (more vulnerable)
# If few/no references: Likely ARC enabled
```

**Detection**:
- Manual memory management: `retain`, `release`, `autorelease` symbols present
- ARC enabled: Minimal manual memory management calls

**Remediation**:
- Enable ARC in Xcode: Add `-fobjc-arc` compiler flag

---

### Stack Protection

Stack canaries protect against stack buffer overflows.

```bash
# Check for stack protection
# This is usually enabled by default in Xcode

# Look for stack protection functions
nm /path/to/binary | grep -i "__stack_chk_fail\|__stack_chk_guard"

# If present: Stack protection enabled
```

---

### Code Signing

Code signatures verify binary integrity and authenticity.

```bash
# Verify code signature
codesign -v /path/to/binary

# Display signature information
codesign -d -vvv /path/to/binary

# Check for entitlements
codesign -d --entitlements - /path/to/binary
```

**Signature Status**:
- `valid on disk`: Valid signature
- `code object is not signed at all`: Not signed
- `invalid entitlements`: Entitlement mismatch

---

## 7. Framework Analysis

### Identify Framework Dependencies

```bash
# List all frameworks and dylibs
otool -L /path/to/binary

# Filter for system frameworks
otool -L /path/to/binary | grep "/System/Library/Frameworks/"

# Filter for third-party frameworks
otool -L /path/to/binary | grep -v "/System/Library/" | grep -v "/usr/lib/"

# Identify framework versions
otool -L /path/to/binary | grep -E "AFNetworking|Alamofire|SDWebImage"
```

### Analyze Third-Party Frameworks

```bash
# Extract framework from IPA
unzip -q target.ipa "Payload/*.app/Frameworks/*"

# Analyze framework binary
otool -l Payload/*.app/Frameworks/AFNetworking.framework/AFNetworking

# Check framework version
plutil -p Payload/*.app/Frameworks/AFNetworking.framework/Info.plist | grep CFBundleShortVersionString

# Check framework for vulnerabilities
# Research framework version for known CVEs
```

### Embedded Frameworks Check

```bash
# Find all embedded frameworks
find /path/to/app.app/Frameworks -name "*.framework" -type d

# Check if frameworks are bitcode-enabled (iOS 14+)
otool -arch all -l /path/to/app.app/Frameworks/MyFramework.framework/MyFramework | grep -i bitcode

# Check framework code signing
codesign -dvvv /path/to/app.app/Frameworks/MyFramework.framework/MyFramework
```

**Security Implications**:
- **Vulnerable frameworks**: Check for known CVEs in framework versions
- **Excessive permissions**: Frameworks may request additional entitlements
- **Code injection**: Vulnerable frameworks can be exploited

---

## 8. Symbol Analysis

### Exported Symbols

```bash
# Display exported symbols
nm -gU /path/to/binary

# Display exported functions only
nm -gU /path/to/binary | grep " T "

# Display exported data symbols only
nm -gU /path/to/binary | grep " D "
```

**Importance**:
- Exported symbols define the binary's public API
- May reveal sensitive functionality
- Can be used for hooking with Frida

### Imported Symbols

```bash
# Display imported symbols
nm -u /path/to/binary

# Display imported functions only
nm -u /path/to/binary | grep " U "

# Display imported data symbols only
nm -u /path/to/binary | grep " U " | grep -v " ("
```

**Importance**:
- Imported symbols show what the binary uses
- May reveal external API calls
- Can indicate network/crypto libraries used

### Objective-C Methods

```bash
# Extract all Objective-C method names
otool -oV /path/to/binary | grep -A 1 "class methods" | grep "^- "

# Extract instance methods
otool -oV /path/to/binary | grep "^- "

# Extract class methods
otool -oV /path/to/binary | grep "^+ "

# Search for specific method pattern
otool -oV /path/to/binary | grep -i "login\|auth\|password\|encrypt"
```

### Swift Symbols

```bash
# Extract Swift method names
nm /path/to/binary | grep "T _\$s" | swift-demangle

# Extract Swift type metadata
nm /path/to/binary | grep "T _\$s" | grep -i "Type"

# Search for specific Swift class
nm /path/to/binary | grep "T _\$s.*MyClass"
```

---

## 9. String Analysis

### Hardcoded Secrets

```bash
# Search for API keys
strings /path/to/binary | grep -iE "api[_-]?key|apikey"

# Search for passwords
strings /path/to/binary | grep -iE "password|passwd|pwd|secret"

# Search for tokens
strings /path/to/binary | grep -iE "token|bearer|oauth"

# Search for private keys
strings /path/to/binary | grep -iE "private[_-]?key|rsa|ecdsa"
```

### URLs and Endpoints

```bash
# Extract HTTP/HTTPS URLs
strings /path/to/binary | grep -E "https?://"

# Extract API endpoints
strings /path/to/binary | grep -E "https?://.*/api/"

# Extract CDN URLs
strings /path/to/binary | grep -E "cloudfront|akamai|cdn"

# Extract internal URLs
strings /path/to/binary | grep -E "http://192\.168\.|http://10\.|http://172\."
```

### Configuration Data

```bash
# Extract JSON data
strings /path/to/binary | grep -E "^{|^\""

# Extract XML data
strings /path/to/binary | grep -E "<|>"

# Extract file paths
strings /path/to/binary | grep -E "^/.*\.(txt|json|xml|plist)"

# Extract UUIDs
strings /path/to/binary | grep -E "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
```

### String Patterns for Vulnerability Detection

| Pattern | Regex | Vulnerability | Severity |
|---------|--------|--------------|----------|
| Hardcoded API Key | `(AIza|AKIA|sk_|pk_live|pk_test).{20,}` | Credential Exposure | High |
| Hardcoded Password | `password\s*=\s*['"].+['"]` | Credential Exposure | Critical |
| Debug Flags | `DEBUG\s*=\s*true` | Debug Code | Medium |
| Test Endpoints | `http://test\.|http://dev\.|http://staging\.` | Information Disclosure | Low |
| Crypto Algorithms | `DES|RC4|MD5` | Weak Crypto | High |
| Unsafe Deserialization | `NSSecureCoding.*false` | RCE | Critical |

---

## 10. Encrypted Binary Detection

### FairPlay Encryption

iOS apps downloaded from App Store are encrypted with FairPlay DRM.

```bash
# Check encryption info
otool -l /path/to/binary | grep -A 5 "LC_ENCRYPTION_INFO"

# Example output (encrypted):
# cryptid 1
# cryptoff 16384
# cryptsize 1024000

# cryptid = 1: Encrypted
# cryptid = 0: Not encrypted

# Example output (not encrypted):
# cryptid 0
# cryptoff 0
# cryptsize 0
```

### Decryption Options

#### Option 1: Clutch (Jailbroken Device)

```bash
# Install Clutch on device (via Cydia)
ssh root@"<device-ip>" "apt-get install clutch"

# Decrypt app
ssh root@"<device-ip>" "clutch -b com.example.app"

# Decrypted IPA will be in /var/mobile/Documents/
# Copy to Mac:
scp root@"<device-ip>":/var/mobile/Documents/*.ipas ./
```

#### Option 2: Frida Decryption

```javascript
// decrypt.js - Frida script to decrypt app
// This is a simplified example

function dump_encrypted() {
    console.log("Attempting to decrypt...");

    // Find encrypted modules
    Process.enumerateModules().forEach(function(module) {
        console.log("Module:", module.name, "Base:", module.base);

        // Dump each module
        try {
            const data = module.base.readByteArray(module.size);
            const filename = module.name.replace(/\//g, "_") + ".bin";
            const file = new File(filename, "wb");
            file.write(data);
            file.close();
            console.log("Dumped:", filename);
        } catch (e) {
            console.log("Failed to dump", module.name, e);
        }
    });
}

dump_encrypted();
```

```bash
# Use Frida to decrypt
frida -U -f com.example.app -l dump-ios.js
```

#### Option 3: CrackerXI (Jailbroken Device)

```bash
# Install CrackerXI on device (via Cydia)
ssh root@"<device-ip>" "apt-get install crackerxi"

# Decrypt app
# Open CrackerXI app on device
# Select app and decrypt

# Decrypted IPA will be in CrackerXI documents folder
```

### Post-Decryption Verification

```bash
# Verify encryption is removed
otool -l decrypted.app.app/decrypted.app | grep "LC_ENCRYPTION_INFO"

# Should show cryptid = 0 (not encrypted)

# Verify binary is still valid
codesign -v decrypted.app.app/

# If codesign fails, re-sign:
codesign --force --sign - decrypted.app.app/
```

---

## 11. Class Extraction

### Using class-dump

```bash
# Dump all Objective-C classes
class-dump /path/to/binary

# Output to file
class-dump /path/to/binary > class_dump.txt

# Dump specific class
class-dump /path/to/binary --arch arm64 -A -H -C MyClass

# Dump headers to directory
class-dump -H -o headers/ /path/to/binary
```

### Using dsdump

```bash
# Dump all classes
dsdump -o output.txt /path/to/binary

# Dump specific class
dsdump -o output.txt -c MyClass /path/to/binary

# Quick overview
dsdump -s /path/to/binary/
```

### Using class-dump-swift

```bash
# Dump Swift classes
class-dump-swift /path/to/binary

# Output to file
class-dump-swift /path/to/binary > swift_classes.txt

# Dump specific class
class-dump-swift -C MySwiftClass /path/to/binary
```

### Extracting Method Implementations

```bash
# Extract method addresses
otool -oV /path/to/binary | grep -A 2 "method name"

# Disassemble method at address
otool -tV /path/to/binary --arch arm64 -s "<address>"

# Use Frida to hook and extract method implementation
frida -U -f com.example.app -l objc-method-observer.js
```

---

## 12. Disassembler Usage

### Hopper Disassembler

```bash
# Launch Hopper
hopper /path/to/binary

# CLI usage
hopper -o output_file /path/to/binary

# Common Hopper features:
# - Disassembly view: See assembly code
# - Pseudocode: Generate C-like pseudocode
# - Strings view: Extract all strings
# - Symbols view: View exported/imported symbols
# - CFG view: Control flow graph
# - Patching: Modify binary (careful!)
```

### Hopper Analysis Workflow

1. **Load Binary**: Open binary in Hopper
2. **Analyze Strings**: Use `⌘ + Shift + S` to view strings
3. **Search Functions**: Use `⌘ + F` to search for functions
4. **Disassemble**: Select function → `Space` for disassembly
5. **Pseudocode**: Select function → `⌘ + Enter` for pseudocode
6. **Cross-Reference**: Right-click → References to see usage
7. **Export**: File → Export → Assembly or C file

### Ghidra

```bash
# Launch Ghidra
ghidraRun

# Import binary:
# File → Import File → Select binary → OK

# Analyze:
# Analysis → Auto Analyze

# Navigation:
# Symbol Tree: Browse functions, classes, data
# Listing: Assembly code view
# Decompiler: C pseudocode (Press Tab)
# Strings: String list
```

### Ghidra Analysis Workflow

1. **Import Binary**: File → Import File
2. **Auto-Analyze**: Analysis → Auto Analyze → OK
3. **Browse Symbols**: Symbol Tree (left panel)
4. **Disassemble**: Click function → Listing view
5. **Decompile**: Click function → Press Tab
6. **Search Strings**: Window → Defined Strings
7. **Search Functions**: Search → For Functions
8. **Cross-Reference**: Right-click → References

---

## Quick Analysis Script

```bash
#!/bin/bash

BINARY="${1:-target.app/target}"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found"
    exit 1
fi

echo "=== Mach-O Binary Analysis ==="
echo ""
echo "Analyzing: $BINARY"
echo ""

# Check if binary is encrypted
echo "1. Encryption Status:"
ENCRYPTION=$(otool -l "$BINARY" | grep -A 5 "LC_ENCRYPTION_INFO" | grep "cryptid" | awk '{print $2}')

if [ "$ENCRYPTION" = "1" ]; then
    echo "   [INFO] Binary is encrypted (FairPlay DRM)"
    echo "   [ACTION] Decrypt using Clutch or Frida before full analysis"
else
    echo "   [OK] Binary is not encrypted"
fi
echo ""

# Check architecture
echo "2. Architecture:"
lipo -info "$BINARY"
echo ""

# Check PIE
echo "3. PIE (Position Independent Executable):"
if otool -h "$BINARY" | grep -q "PIE"; then
    echo "   [OK] PIE enabled"
else
    echo "   [HIGH] PIE disabled (vulnerable to ROP)"
fi
echo ""

# Check ARC
echo "4. ARC (Automatic Reference Counting):"
ARC_CHECK=$(nm "$BINARY" | grep -i "retain\|release\|autorelease" | wc -l)
if [ "$ARC_CHECK" -lt 5 ]; then
    echo "   [OK] ARC likely enabled"
else
    echo "   [MEDIUM] Manual memory management detected"
fi
echo ""

# Check frameworks
echo "5. Framework Dependencies:"
otool -L "$BINARY" | grep -E "AFNetworking|Alamofire|SDWebImage|Kingfisher"
echo ""

# Check for hardcoded secrets
echo "6. Hardcoded Secrets Check:"
SECRET_COUNT=0

if strings "$BINARY" | grep -qiE "api[_-]?key|apikey|api_key"; then
    echo "   [CRITICAL] Possible API keys found"
    ((SECRET_COUNT++))
fi

if strings "$BINARY" | grep -qiE "password|passwd|pwd|secret"; then
    echo "   [HIGH] Possible passwords found"
    ((SECRET_COUNT++))
fi

if strings "$BINARY" | grep -qiE "token|bearer|oauth"; then
    echo "   [MEDIUM] Possible tokens found"
    ((SECRET_COUNT++))
fi

if [ $SECRET_COUNT -eq 0 ]; then
    echo "   [OK] No obvious secrets found"
fi
echo ""

# Check for weak crypto
echo "7. Cryptography Check:"
if strings "$BINARY" | grep -qiE "DES|RC4|MD5"; then
    echo "   [HIGH] Weak cryptography algorithms found"
else
    echo "   [OK] No obvious weak crypto found"
fi
echo ""

# Check code signing
echo "8. Code Signing:"
codesign -v "$BINARY" 2>&1
echo ""

# Check get-task-allow
echo "9. Debugging (get-task-allow):"
if codesign -d --entitlements - "$BINARY" 2>/dev/null | grep -q "get-task-allow.*true"; then
    echo "   [CRITICAL] get-task-allow = true (production build should not have this)"
else
    echo "   [OK] get-task-allow not present or false"
fi
echo ""

# Check Objective-C classes
echo "10. Objective-C Classes:"
CLASS_COUNT=$(otool -o "$BINARY" | grep "^class " | wc -l)
echo "   Found $CLASS_COUNT Objective-C classes"
echo ""

# Extract sample methods
echo "11. Sample Methods (first 10):"
otool -o "$BINARY" | grep "^- " | head -10
echo ""

echo "=== Analysis Complete ==="
```

Save as `analyze-macho.sh`, make executable: `chmod +x analyze-macho.sh`, run: `./analyze-macho.sh target.app/target`

---

## Reference Links

- **OWASP MASTG**: https://mas.owasp.org/MASTG/
- **Apple Developer Documentation**: https://developer.apple.com/documentation/xcode/writing-code-for-code-signing
- **Mach-O Format**: https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachORuntime/
- **Hopper Disassembler**: https://www.hopperapp.com/
- **Ghidra**: https://ghidra-sre.org/
