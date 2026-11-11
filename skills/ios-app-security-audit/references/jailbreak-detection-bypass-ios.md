# iOS Jailbreak Detection Bypass

> **Purpose**: Comprehensive guide for bypassing jailbreak detection in iOS apps during security testing
> **Scope**: All detection techniques (file checks, URL schemes, write tests, method calls) with verified Frida bypasses
> **Reference**: Industry-standard jailbreak detection techniques applicable to any iOS app

---

## Table of Contents

1. [Detection Technique Categories](#detection-technique-categories)
2. [Common Jailbreak Indicators](#common-jailbreak-indicators)
3. [Bypass Strategy Overview](#bypass-strategy-overview)
4. [Bypass Scripts](#bypass-scripts)
5. [Category-Specific Bypasses](#category-specific-bypasses)
6. [Detection Technique Examples](#detection-technique-examples)
7. [Testing Methodology](#testing-methodology)
8. [Advanced Detection Evasion](#advanced-detection-evasion)

---

## Detection Technique Categories

iOS apps implement jailbreak detection through five primary techniques:

### 1. File Existence Checks

**Method**: `NSFileManager` APIs to detect jailbreak artifacts

```objc
// Common detection patterns
[[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]
[[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"]
[[NSFileManager defaultManager] isReadableFileAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"]
```

**What apps check**:
- Cydia.app installation directory
- MobileSubstrate dylib
- Shell binaries (/bin/bash, /bin/sh)
- SSH daemon (/usr/sbin/sshd)
- APT package manager (/etc/apt)
- Jailbreak indicator files (/private/jailbreak.txt)

---

### 2. URL Scheme Checks

**Method**: `UIApplication canOpenURL:` to detect jailbreak apps

```objc
// Check for Cydia URL scheme
[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]

// Check for Sileo (modern package manager)
[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"sileo://"]]
```

**What apps check**:
- `cydia://` - Cydia package manager
- `sileo://` - Sileo package manager
- `activator://` - Activator tweak
- `bigbossjonboss://` - BigBoss repo

---

### 3. Write Tests

**Method**: Attempt to write to protected filesystem locations

```objc
// Try writing to /private/ (only writable on jailbroken devices)
NSString *testPath = @"/private/jailbreak_test.txt";
BOOL success = [[NSFileManager defaultManager] createFileAtPath:testPath
                                                    contents:nil
                                                  attributes:nil];

// Clean up if successful
if (success) {
    [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
}
```

**What apps check**:
- Write access to `/private/`
- Write access to `/var/root/`
- Write access to system directories

---

### 4. Method Calls

**Method**: Direct calls to jailbreak detection methods

```objc
// Common method signatures
+ (BOOL)isJailbroken;
+ (BOOL)isJailBroken;  // Alternate spelling
+ (BOOL)isDeviceJailbroken;
- (BOOL)jailbreakTest;

// Usage in production apps
if ([[JailbreakDetector sharedInstance] isJailbroken]) {
    // Block sensitive functionality
}
```

**What apps check**:
- Custom detector classes
- Third-party SDKs (anti-fraud, security libraries)
- Obfuscated method names

---

### 5. Process and DYLIB Checks

**Method**: Check for jailbreak-related processes or loaded libraries

```objc
// Check for Frida server (common in pentesting)
if (getpid("frida-server") || getpid("frida-helper")) {
    // Debugger detected
}

// Check for suspicious DYLIBs
if (dlopen("/usr/lib/frida/frida-agent.dylib", RTLD_NOLOAD)) {
    // Frida detected
}
```

**What apps check**:
- `frida-server`, `cydia`, `substrate` processes
- Loaded dynamic libraries
- Symbol presence in memory

---

## Common Jailbreak Indicators

### Filesystem Paths (Most Common)

| Path | Purpose | Detection Type |
|------|---------|----------------|
| `/Applications/Cydia.app` | Cydia installer | File existence |
| `/Library/MobileSubstrate/MobileSubstrate.dylib` | Tweak injection | File readability |
| `/bin/bash` | Unix shell | File existence |
| `/bin/sh` | Unix shell | File existence |
| `/usr/sbin/sshd` | SSH daemon | File existence |
| `/etc/apt` | Package manager | File existence |
| `/private/jailbreak.txt` | Jailbreak marker | File existence |
| `/var/cache/apt` | Package cache | File existence |
| `/var/lib/cydia` | Cydia data | File existence |
| `/var/log/syslog` | System logs | File existence |
| `/usr/bin/sshd` | SSH daemon | File existence |
| `/usr/libexec/sftp-server` | SFTP server | File existence |
| `/usr/libexec/ssh-keysign` | SSH key signing | File existence |

### URL Schemes

| Scheme | Purpose |
|--------|---------|
| `cydia://` | Cydia package manager |
| `sileo://` | Sileo package manager |
| `activator://` | Activator gesture system |
| `bigbossjonboss://` | BigBoss repository |

### Processes and Libraries

| Indicator | Purpose |
|-----------|---------|
| `frida-server` | Frida instrumentation |
| `cydia` | Cydia background process |
| `substrate` | MobileSubstrate tweak injection |
| `frida-agent.dylib` | Frida client library |
| `libfrida.dylib` | Frida core library |

---

## Bypass Strategy Overview

### Strategy: Hook-Based Interception

The most reliable bypass method is intercepting detection API calls at runtime using Frida:

```
App calls detection API → Frida intercepts → Returns fake result → App believes device is clean
```

**Advantages**:
- Universal across apps (same script works for most targets)
- No filesystem modifications required
- Real-time bypass with logging
- Can block multiple detection types simultaneously

**When to use each bypass script**:
- **Comprehensive script** (`jailbreak-detection-bypass.js`): Production testing, full coverage (all 5 categories + C-level syscalls)
- **Lightweight script** (`jailbreak-bypass-ios.js`): Quick, low-noise testing; method-only detection, or when C-level hooks destabilize the app

---

## Bypass Scripts

### Comprehensive Jailbreak Bypass (Recommended)

**File**: `assets/frida-scripts/jailbreak-detection-bypass.js`

**Coverage**: All 5 detection categories with real-time blocking, plus C-level syscalls (stat/fopen/fork/posix_spawn) and anti-frida dlopen

**Usage**:
```bash
# Spawn app with bypass
frida -U -f com.example.app -l jailbreak-detection-bypass.js

# Attach to running app
frida -U com.example.app -l jailbreak-detection-bypass.js

# With simulator
frida -e com.example.app -l jailbreak-detection-bypass.js
```

**What it blocks**:
- ✅ File existence checks (14+ jailbreak paths)
- ✅ File readability checks
- ✅ URL scheme checks (4+ schemes)
- ✅ Write tests (blocks /private/ writes)
- ✅ Method calls (auto-discovers isJailbroken patterns)

**Console output**:
```
[*] ================================================
[*] JAILBREAK DETECTION BYPASS - iOS STARTED
[*] ================================================
[+] NSFileManager.fileExistsAtPath: hooked successfully
[+] NSFileManager.isReadableFileAtPath: hooked successfully
[+] UIApplication.canOpenURL: hooked successfully
[+] NSFileManager.createFileAtPath:contents:attributes: hooked successfully
[+] stat() hooked successfully
[+] fopen() hooked successfully
[+] fork() hooked successfully
[+] posix_spawn() hooked successfully
[+] dlopen() hooked successfully
[+] Hooked <CustomDetector> + isJailbroken
[*] ================================================
[*] Total hooks applied: 11
[*] Jailbreak Detection Bypass Complete
[*] ================================================
```

---

### Lightweight Jailbreak Bypass

**File**: `assets/frida-scripts/jailbreak-bypass-ios.js`

**Coverage**: Method call detection only (Category 4)

**Usage**:
```bash
# Quick method-only bypass
frida -U -p "<PID>" -l jailbreak-bypass-ios.js
```

**What it blocks**:
- ✅ `+isJailbroken` methods (all classes)
- ✅ `-isJailbroken` methods (all classes)
- ✅ `+isJailBroken` methods (alternate spelling)
- ✅ `+isDeviceJailbroken` methods
- ✅ Custom `jailbreakTest` methods

**When to use**:
- App only uses method-based detection
- Minimal overhead required
- Quick verification before comprehensive testing

---

## Category-Specific Bypasses

### Bypass 1: File Existence Checks

**Frida hook**:
```javascript
// Hook fileExistsAtPath:
var NSFileManager = ObjC.classes.NSFileManager;
var fileExistsMethod = NSFileManager["- fileExistsAtPath:"];

Interceptor.attach(fileExistsMethod.implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();

        // Block known jailbreak paths
        if (isJailbreakPath(path)) {
            console.log("[BLOCKED] fileExistsAtPath: " + path);
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(0x0); // Return FALSE
        }
    }
});

function isJailbreakPath(path) {
    var jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd"
    ];

    return jailbreakPaths.includes(path) ||
           path.indexOf("Cydia") !== -1 ||
           path.indexOf("MobileSubstrate") !== -1;
}
```

**Expected result**: App believes no jailbreak files exist

---

### Bypass 2: URL Scheme Checks

**Frida hook**:
```javascript
// Hook canOpenURL:
var UIApplication = ObjC.classes.UIApplication;
var canOpenURLMethod = UIApplication["- canOpenURL:"];

Interceptor.attach(canOpenURLMethod.implementation, {
    onEnter: function(args) {
        var url = ObjC.Object(args[2]);
        var urlString = url.absoluteString().toString();

        // Block jailbreak schemes
        if (urlString.startsWith("cydia://") ||
            urlString.startsWith("sileo://")) {
            console.log("[BLOCKED] canOpenURL: " + urlString);
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(0x0); // Return FALSE
        }
    }
});
```

**Expected result**: App believes jailbreak apps cannot be opened

---

### Bypass 3: Write Tests

**Frida hook**:
```javascript
// Hook createFileAtPath:contents:attributes:
var NSFileManager = ObjC.classes.NSFileManager;
var createFileMethod = NSFileManager["- createFileAtPath:contents:attributes:"];

Interceptor.attach(createFileMethod.implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();

        // Block writes to protected paths
        if (path.startsWith("/private/") ||
            path.startsWith("/var/root/")) {
            console.log("[BLOCKED] createFileAtPath: " + path);
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(0x0); // Return FALSE (write failed)
        }
    }
});
```

**Expected result**: Write tests fail as expected on non-jailbroken device

---

### Bypass 4: Method Calls

**Frida hook**:
```javascript
// Auto-discovery and hook
for (var className in ObjC.classes) {
    var clazz = ObjC.classes[className];

    // Hook +isJailbroken
    if (clazz["+ isJailbroken"]) {
        Interceptor.attach(clazz["+ isJailbroken"].implementation, {
            onLeave: function(retval) {
                console.log("[BLOCKED] " + className + " +isJailbroken");
                retval.replace(0x0); // Return FALSE
            }
        });
    }

    // Hook -isJailbroken
    if (clazz["- isJailbroken"]) {
        Interceptor.attach(clazz["- isJailbroken"].implementation, {
            onLeave: function(retval) {
                retval.replace(0x0); // Return FALSE
            }
        });
    }
}
```

**Expected result**: All `isJailbroken` methods return `FALSE`

---

### Bypass 5: Process and DYLIB Checks

**Advanced bypass** (requires comprehensive script):
```javascript
// Hook getpid to hide Frida processes
var getpidPtr = Module.findGlobalExportByName("getpid");
if (getpidPtr) {
    Interceptor.attach(getpidPtr, {
        onEnter: function(args) {
            this.processName = null;
        },
        onLeave: function(retval) {
            // Return fake PID or filter output
        }
    });
}

// Hook dlopen to hide Frida libraries
var dlopenPtr = Module.findGlobalExportByName("dlopen");
if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path.indexOf("frida") !== -1) {
                console.log("[BLOCKED] dlopen: " + path);
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        }
    });
}
```

**Note**: Process/DYLIB checks are less common in production apps. Most apps rely on Categories 1-4.

---

## Detection Technique Examples

The bypass script handles all common detection patterns found in production iOS apps:

| Detection Category | Example Implementation | Script Component | Result |
|-------------------|------------------------|------------------|--------|
| **File existence** | Checks for `/Applications/Cydia.app` | `fileExistsAtPath` hook | ✅ Pass |
| **File + URL** | Combines file checks with `cydia://` scheme | `fileExistsAtPath` + `canOpenURL` hooks | ✅ Pass |
| **Write test** | Attempts write to `/private/` to test root access | `createFileAtPath` hook | ✅ Pass |
| **Direct method** | Calls custom `+isJailbroken` method | Method discovery hook | ✅ Pass |

**Testing methodology**:
```bash
# 1. Identify target app bundle ID
# 2. Launch with comprehensive bypass
frida -U -f com.example.app -l jailbreak-detection-bypass.js

# 3. Navigate to jailbreak detection check in app
# 4. Trigger detection (login, sensitive feature, etc.)
# 5. Expected: App should proceed (believes device is clean)
```

**Expected console output during testing**:
```
[BLOCKED] fileExistsAtPath: /Applications/Cydia.app
         → Modified return: FALSE

[BLOCKED] canOpenURL: cydia://
         → Modified return: FALSE

[BLOCKED] createFileAtPath: /private/jailbreak_test.txt
         → Modified return: FALSE (write failed)

[BLOCKED] CustomJailbreakDetector +isJailbroken
         → Modified return: FALSE
```

---

## Testing Methodology

### Step 1: Detection Discovery

```bash
# Static analysis - find detection code
rg "isJailbroken\|jailBreak\|cydia" app/ --exclude-dir=Frameworks/

# Check for NSFileManager usage
rg "fileExistsAtPath\|isReadableFileAtPath\|createFileAtPath" app/

# Check for URL scheme checks
rg "canOpenURL" app/

# Check for common jailbreak paths
rg "/Applications/Cydia\|/bin/bash\|/etc/apt" app/
```

### Step 2: Dynamic Verification

```bash
# Run with bypass script
frida -U -f com.example.app -l jailbreak-detection-bypass.js

# Trigger jailbreak detection in app
# (e.g., navigate to sensitive feature)

# Watch console output for blocked checks
# Each BLOCKED line indicates detection attempt
```

### Step 3: Validation

```bash
# Without bypass: App should block functionality
# With bypass: App should allow functionality

# Example: Banking app
# Without bypass: "Device rooted. Access denied."
# With bypass: "Welcome to your account"
```

### Step 4: Documentation

Document findings in security report:
```
Jailbreak Detection: WEAK

Findings:
- App implements 4 detection techniques
- All detections bypassed using Frida instrumentation
- Sensitive functionality accessible without jailbreak protection

Risk: MEDIUM
- App relies on client-side jailbreak detection
- No server-side validation for sensitive operations
- Bypass trivial with Frida

Recommendation:
- Implement server-side device attestation
- Do not rely solely on client-side detection
- See OWASP MASTG-APP-SEC-0010
```

---

## Advanced Detection Evasion

### Anti-Frida Detection

Some apps detect Frida instrumentation. Countermeasures:

#### 1. Hide Frida Ports

```javascript
// Hook frida-server port detection
var connectPtr = Module.findGlobalExportByName("connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sockaddr = args[1].readByteArray(16);
        // Check if connecting to Frida port 27042
        // Block or redirect connection
    }
});
```

#### 2. Rename Frida Server

```bash
# On device
mv /var/jb/usr/bin/frida-server /var/jb/usr/bin/.syslogd

# Run with custom name
/var/jb/usr/bin/.syslogd &
```

#### 3. Use Objection (Built-in Evasion)

```bash
# Objection has built-in anti-detection bypass
objection -g com.example.app explore

# Inside objection
ios jailbreak disable

# This uses optimized hooks that evade detection
```

---

### Obfuscated Detection

Some apps use custom or obfuscated detection:

```objective-c
// Common obfuscation patterns
// Pattern 1: String concatenation
var path = "/Appl" + "ication" + "s/Cy" + "dia.app";

// Pattern 2: Base64 encoding
var path = [@"L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA=" base64Decoded];

// Pattern 3: Custom hash/checksum
if (customHashCheck("/Applications/Cydia.app") == JAILBREAK_HASH) {
    // Device is jailbroken
}
```

**Countermeasure**: Use comprehensive hooks instead of path matching:

```javascript
// Hook ALL fileExistsAtPath calls (not just specific paths)
Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();

        // Log ALL file checks
        console.log("[FILE CHECK] " + path);

        // Block suspicious patterns
        if (path.match(/^(\/private|\/var\/root|\/Applications\/Cydia|\/etc\/apt)/)) {
            this.shouldBlock = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldBlock) {
            retval.replace(0x0);
        }
    }
});
```

---

## References

### OWASP MASTG

- **MASTG-APP-SEC-0010**: Runtime Manipulation Prevention
- **MASTG-TEST-0011**: Testing Jailbreak Detection
- **MASTG-TECH-0013**: iOS File System

### Related Guides

- [jailbreak-setup-guide.md](jailbreak-setup-guide.md) - Setting up jailbroken devices
- [frida-ios-simulator-workflow.md](frida-ios-simulator-workflow.md) - Frida basics and simulator usage

### Frida Scripts

- `jailbreak-detection-bypass.js` - Comprehensive bypass for all detection categories (recommended)
- `jailbreak-bypass-ios.js` - Lightweight, method-only bypass (pure ObjC)

### Community Resources

- [Frida Instrumentation Documentation](https://frida.re/docs/)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-app-security-testing-guide/)

---

## Summary

Jailbreak detection bypass is fundamental to iOS app security testing. This guide covers:

- ✅ Five detection technique categories (files, URLs, writes, methods, processes)
- ✅ 14+ common jailbreak indicators (paths, schemes, processes)
- ✅ Complete Frida bypass script with real-time blocking
- ✅ Category-specific bypass hooks for targeted testing
- ✅ Detection technique examples and verification
- ✅ Advanced evasion techniques (anti-Frida detection, obfuscated methods)
- ✅ Testing methodology for production apps

**Best Practice**:
1. Use the comprehensive bypass script (`jailbreak-detection-bypass.js`) for comprehensive testing
2. Document all blocked detections in security reports
3. Recommend server-side validation as proper remediation
4. Test on both jailbroken devices and simulators

---

**Document Version**: 1.0
**Last Updated**: June 2026
**Target Audience**: Mobile security professionals, iOS penetration testers
**Prerequisites**: Basic Frida knowledge, jailbroken device or simulator (see frida-ios-simulator-workflow.md)
