# Frida Dynamic Analysis Techniques

> **Purpose**: Verified techniques for iOS app dynamic analysis using Frida. All techniques apply to ANY iOS app.

---

## 1. Simulator Attachment

### Verified: Frida Connection Syntax

**For iOS Simulator** (Apple Silicon):
```bash
# 1. Launch app (returns PID)
xcrun simctl launch booted com.example.app
# Output: com.example.app: 12345

# 2. Attach to PID
frida -p 12345 -l script.js
```

**What does NOT work**:
```bash
frida -U -f com.app        # -U is for USB device only
frida -N com.app           # Can be ambiguous with multiple matches
```

**Why**:
- Simulator apps run in "Local System" context
- `frida -p <PID>` attaches unambiguously to specific process
- No need for device flags when targeting local simulator

### Common Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| "unable to find process with pid X" | App process terminated | `xcrun simctl launch booted com.app` (get new PID) |
| "ambiguous identifier" | Multiple bundle ID matches | Use `-p <PID>` instead of `-N <bundle>` |
| "Objective-C runtime NOT available" | Target not an iOS app | Verify app is running: `frida-ps \| grep appname` |

---

## 2. Method Enumeration (Frida 17.11.0+)

### Verified: $ownMethods Property

**Correct approach**:
```javascript
if (ObjC.available) {
    var clazz = ObjC.classes.SomeClass;
    var methods = clazz.$ownMethods;

    methods.forEach(function(method) {
        console.log(method);  // "- methodName:", "+ methodName:"
    });
}
```

**Verification before use**:
```javascript
if (!ObjC.available) {
    console.log("[-] Objective-C runtime not available");
    return;
}
```

---

## 3. Data Extraction

### Verified: UserDefaults Filtering

**Problem**: `standardUserDefaults.dictionaryRepresentation()` returns 500+ keys, mostly system-level.

**Solution** (verified on real app):
```javascript
var systemPrefixes = ["WebKit", "Apple", "NS", "PK", "AI", "_"];

function isSystemKey(key) {
    for (var i = 0; i < systemPrefixes.length; i++) {
        if (key.indexOf(systemPrefixes[i]) === 0) return true;
    }
    return false;
}

var standardUserDefaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
var dictionary = standardUserDefaults.dictionaryRepresentation();
var keys = dictionary.allKeys();
var count = keys.count();

for (var i = 0; i < count; i++) {
    var key = keys.objectAtIndex_(i).toString();
    if (!isSystemKey(key)) {
        var value = dictionary.objectForKey_(key);
        console.log("Key: " + key + ", Value: " + value);
    }
}
```

**Verified result**: 546 total keys → 7 app-specific keys (98.7% reduction)

---

## 4. Security Method Auto-Discovery

### Verified: Jailbreak Detection Pattern

**Working pattern** (tested on real app):
```javascript
var methodNames = ["isJailbroken", "isJailBroken", "isDeviceJailbroken"];
var hookedCount = 0;

for (var className in ObjC.classes) {
    var clazz = ObjC.classes[className];

    methodNames.forEach(function(methodName) {
        // Check class methods (+)
        if (clazz["+ " + methodName]) {
            Interceptor.attach(clazz["+ " + methodName].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x0);  // Return FALSE
                }
            });
            hookedCount++;
        }
        // Check instance methods (-)
        if (clazz["- " + methodName]) {
            Interceptor.attach(clazz["- " + methodName].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x0);  // Return FALSE
                }
            });
            hookedCount++;
        }
    });
}

console.log("[*] Hooked " + hookedCount + " jailbreak detection methods");
```

**Verified result**: 9 methods hooked across 3 classes (JailbreakDetection, PFDevice, UIKeyboardCandidateViewState)

---

## 5. Script Design

### Verified: Configurable Filter Pattern

**Anti-pattern** (don't use):
```javascript
// App-specific - breaks on other apps
if (ObjC.classes.SpecificAppName) { ... }
```

**Correct pattern**:
```javascript
// Configurable at top of script
var classNameFilter = "";  // User edits this line

for (var className in ObjC.classes) {
    if (classNameFilter === "" ||
        className.toLowerCase().includes(classNameFilter.toLowerCase())) {
        // Process matching classes
    }
}
```

**Usage**:
```bash
# First run: show all classes
frida -p "<PID>" -l class-explorer-ios.js

# Edit script: var classNameFilter = "Jailbreak";

# Second run: show only matching classes
frida -p "<PID>" -l class-explorer-ios.js
```

---

## Summary of Verified Techniques

| Technique | Status | Key Detail |
|-----------|--------|------------|
| Simulator attach with `-p <PID>` | ✅ Verified | `xcrun simctl launch` returns PID |
| `$ownMethods` for enumeration | ✅ Verified | Works in Frida 17.11.0+ |
| UserDefaults filtering | ✅ Verified | 546 → 7 keys (98.7% reduction) |
| Jailbreak method auto-discovery | ✅ Verified | 9 methods found and hooked |
| `ObjC.available` check | ✅ Verified | Standard verification |
| Configurable filter pattern | ✅ Verified | Works on any app |

---

## Device vs Simulator

| Feature | Simulator | Device |
|---------|-----------|--------|
| List processes | `frida-ps` | `frida-ps -U` |
| Attach to PID | `frida -p <PID>` | `frida -p <PID>` |
| Attach by bundle | `frida -N <bundle>` (may be ambiguous) | `frida -U <bundle>` |
| Spawn with script | Not typical | `frida -U -f com.app -l script.js` |

---

## 6. Jailbreak Detection Bypass - Complete

### Detection Technique Categories

Production apps use multiple detection vectors. A complete bypass requires hooking ALL categories:

| Category | Methods | What it checks |
|----------|---------|----------------|
| **File existence** | `fileExistsAtPath:`, `isReadableFileAtPath:` | Presence of jailbreak artifacts |
| **URL schemes** | `canOpenURL:` | Cydia://, sileo:// handlers |
| **Write tests** | `createFileAtPath:contents:attributes:` | Can write to `/private/` (root) |
| **Direct methods** | `+ isJailbroken`, `- isJailbroken` | Explicit detection methods |

**Critical**: Hooking only `isJailbroken` is insufficient. Production apps implement multiple detection techniques - a single hook bypasses only one category.

### Required Hooks for Complete Bypass

For comprehensive bypass coverage across all detection categories:

```javascript
// File existence checks
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onLeave: function(retval) { retval.replace(0x0); }
});

// URL scheme checks
Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onLeave: function(retval) { retval.replace(0x0); }
});

// Write tests
Interceptor.attach(ObjC.classes.NSFileManager['- createFileAtPath:contents:attributes:'].implementation, {
    onLeave: function(retval) { retval.replace(0x0); }
});

// Direct detection methods
var methodNames = ["isJailbroken", "isJailBroken", "isDeviceJailbroken"];
for (var className in ObjC.classes) {
    var clazz = ObjC.classes[className];
    methodNames.forEach(function(methodName) {
        if (clazz["+ " + methodName]) {
            Interceptor.attach(clazz["+ " + methodName].implementation, {
                onLeave: function(retval) { retval.replace(0x0); }
            });
        }
        if (clazz["- " + methodName]) {
            Interceptor.attach(clazz["- " + methodName].implementation, {
                onLeave: function(retval) { retval.replace(0x0); }
            });
        }
    });
}
```

### Common Jailbreak Paths

Industry-standard paths checked by jailbreak detection implementations:

**Applications**:
- `/Applications/Cydia.app`
- `/Applications/Sileo.app`
- `/Applications/FakeCarrier.app`
- `/Applications/Icy.app`
- `/Applications/IntelliScreen.app`
- `/Applications/MxTube.app`
- `/Applications/RockApp.app`
- `/Applications/SBSettings.app`
- `/Applications/WinterBoard.app`

**Libraries & Binaries**:
- `/Library/MobileSubstrate/MobileSubstrate.dylib`
- `/usr/libexec/ssh-keysign`
- `/bin/bash`
- `/usr/sbin/sshd`
- `/etc/apt`
- `/private/jailbreak.txt`
- `/private/var/lib/apt/`
- `/var/cache/apt/`
- `/var/lib/apt/`
- `/var/tmp/cydia.log`

**Symbolic Links** (indicate jailbreak):
- `/Applications` → `/var/stash/Applications`
- `/Library/Ringtones` → `/var/stash/Library/Ringtones`
- `/Library/Wallpaper` → `/var/stash/Library/Wallpaper`
- `/usr/include` → `/var/stash/usr/include`
- `/usr/libexec` → `/var/stash/usr/libexec`
- `/usr/share` → `/var/stash/usr/share`
- `/var/db/stash`

### Obfuscation vs Dynamic Analysis

**Key finding from production app analysis**: String obfuscation does NOT bypass Frida instrumentation.

- **Static obfuscation**: Hides strings in binary (e.g., `/Appl\137cation\163/Cydia.app`)
- **Dynamic instrumentation**: Frida hooks runtime methods AFTER deobfuscation
- **Result**: Even obfuscated paths are plain strings at runtime - hooks work normally

**Best practice**: Use method-level hooks (shown above) rather than string search. Methods deobfuscate internally before calling file APIs - hooking the API catches all variants.

### Comprehensive Script

`assets/frida-scripts/jailbreak-detection-bypass.js` - Production-ready bypass covering all detection categories (ObjC checks + C-level syscalls + direct method discovery).

---

## References

- [Frida Simulator Workflow](frida-ios-simulator-workflow.md) — Step-by-step simulator guide
- [Frida Scripts Index](frida-scripts-index.md) — All available scripts
- [SKILL.md](../SKILL.md) — Complete methodology
