# Side Channel Data Leakage Analysis in iOS Apps

## Overview

Side channel data leakage occurs when sensitive information is exposed through unintended channels outside the primary communication path. These leaks are often overlooked in security reviews but can expose sensitive data to other apps or attackers with device access.

**Common side channels in iOS**:
- SplashBoard snapshots (app switcher screenshots)
- Pasteboard contents
- Cookies in memory/disk
- Temporary files
- Device logs
- Keyboard cache

---

## 1. SplashBoard Snapshots

### What Are They?

When an iOS app backgrounds, the system automatically captures a screenshot for the app switcher. These screenshots are stored in the app's SplashBoard directory and persist until the app is terminated.

### Risk

If sensitive data is visible when the app backgrounds, it's exposed in:
- App switcher (visible to anyone looking at the device)
- SplashBoard directory (accessible with filesystem access)
- Backup data (if not excluded from backup)

### Location

**Simulator**:
```bash
~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Data/Application/*/Library/Caches/Snapshots/
```

**Device**:
```bash
/var/mobile/Containers/Data/Application/*/Library/Caches/Snapshots/
```

### Extraction

**From Simulator**:
```bash
# Find all snapshots
find ~/Library/Developer/CoreSimulator/Devices -name "*.png" -path "*/Snapshots/*"

# Copy snapshots from specific app
xcrun simctl get_app_container booted com.example.app data
cp -R ~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Data/Application/*/Library/Caches/Snapshots/ ./snapshots/
```

**From Device** (requires filesystem access):
```bash
# Via SSH (jailbroken)
ssh mobile@device
find /var/mobile/Containers/Data/Application -name "Snapshots" -type d
cp -r /var/mobile/Containers/Data/Application/*/Library/Caches/Snapshots/ /tmp/
scp -r mobile@device:/tmp/Snapshots/ ./
```

**With objection**:
```bash
objection -g com.example.app explore
ios ls /Library/Caches/Snapshots
ios download /Library/Caches/Snapshots/* ./snapshots/
```

### Detection Patterns (Static Analysis)

```bash
# Check if app implements background handling
rg "applicationDidEnterBackground\|sceneDidBecomeInactive" . --exclude-dir=Frameworks/

# Look for screen obfuscation code
rg "blur\|obfuscate\|hide.*sensitive\|snapshot.*ignore" . --exclude-dir=Frameworks/
```

### Mitigation

**Swift**:
```swift
func applicationDidEnterBackground(_ application: UIApplication) {
    // Blur or hide sensitive UI
    // iOS 13+ handles this automatically with appropriate configuration
}

// Or use iOS 13+ automatic snapshotting
let imageView = UIImageView(image: UIImage(named: "placeholder"))
self.view.addSubview(imageView)
```

---

## 2. Pasteboard Leakage

### What Is It?

Apps that copy sensitive data to the system pasteboard expose it to:
- Other apps that read the pasteboard
- Background pasteboard monitoring
- Pasteboard history in some keyboards

### Risk

Any data copied to the pasteboard is accessible to all apps with pasteboard read access until:
- The app copies something else
- The app terminates
- User copies new data

### Detection

**Static Analysis**:
```bash
# Look for pasteboard usage
rg "UIPasteboard\|generalPasteboard\|pasteboard.*string" . --exclude-dir=Frameworks/

# Check for sensitive data being copied
rg -A 3 "UIPasteboard.general" . --exclude-dir=Frameworks/ | rg "password\|token\|key\|secret"
```

**Dynamic Analysis (Frida)**:
```javascript
// Monitor pasteboard operations
if (ObjC.available) {
    var UIPasteboard = ObjC.classes.UIPasteboard;
    var generalPasteboard = UIPasteboard.generalPasteboard();

    Interceptor.attach(generalPasteboard["-string"].implementation, {
        onLeave: function(retval) {
            console.log("[Pasteboard Read] " + retval);
        }
    });

    Interceptor.attach(generalPasteboard["-setString:"].implementation, {
        onEnter: function(args) {
            var str = ObjC.Object(args[2]);
            console.log("[Pasteboard Write] " + str.toString());
        }
    });
}
```

### Extraction

**From Frida**:
```bash
frida -U -f com.example.app -l assets/frida-scripts/pasteboard-monitor.js
```

**Manual Check**:
```bash
# On jailbroken device
ssh mobile@device
uiutil --pboard
```

### Mitigation

- Don't copy sensitive data to pasteboard
- If necessary, clear it immediately after use
- Use secure pasteboard APIs when available (iOS 14+)
- Detect pasteboard monitoring attempts

---

## 3. Cookies in Memory and Disk

### What Are They?

Cookies used for authentication can leak through:
- HTTPCookieStorage (memory)
- Cookie storage files (disk)
- Cookie cache

### Location

**Disk (Simulator)**:
```bash
~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Data/Application/*/Library/Cookies/*.binarycookies
```

**Disk (Device)**:
```bash
/var/mobile/Containers/Data/Application/*/Library/Cookies/*.binarycookies
```

**Memory**: In NSHTTPCookieStorage objects

### Extraction

**From Disk**:
```bash
# Copy binarycookies file
cp /path/to/Library/Cookies/*.binarycookies ./cookies.binarycookies

# Parse with binarycookies-parser
python3 binarycookies_parser.py cookies.binarycookies
```

**From Memory (Frida)**:
```javascript
// Extract cookies from NSHTTPCookieStorage
if (ObjC.available) {
    var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
    var cookies = NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();

    // enumerateObjectsUsingBlock: takes an Objective-C block, not a plain
    // JavaScript function: passing a JS function makes the call fail. The
    // block wrapper is built with new ObjC.Block({...}), and the cookie has
    // to be wrapped too, because inside the block it arrives as a raw
    // pointer.
    var cookieBlock = new ObjC.Block({
        retType: 'void',
        argTypes: ['id'],
        implementation: function(cookiePtr) {
            var cookie = new ObjC.Object(cookiePtr);
            console.log(JSON.stringify({
                domain: cookie.domain().toString(),
                name: cookie.name().toString(),
                value: cookie.value().toString(),
                path: cookie.path().toString(),
                secure: cookie.isSecure(),
                httpOnly: cookie.isHTTPOnly(),
                isSecure: cookie.isSecure()
            }));
        }
    });

    cookies.enumerateObjectsUsingBlock_(cookieBlock);
}
```

### Detection Patterns

```bash
# Check for cookie handling
rg "HTTPCookieStorage\|setCookie\|cookie.*value" . --exclude-dir=Frameworks/

# Check for sensitive data in cookies
rg -B 2 -A 2 "HTTPCookie" . --exclude-dir=Frameworks/ | rg -i "session\|token\|auth"
```

### Mitigation

- Use `HttpOnly` flag
- Set `Secure` flag for HTTPS-only
- Set appropriate `SameSite` attribute
- Don't store sensitive data in cookies
- Use short expiration times
- Consider token-based auth instead

---

## 4. Temporary Files

### What Are They?

Apps may write sensitive data to temporary directories that persist:
- In `/tmp/` (simulator)
- In `NSTemporaryDirectory()` (device)
- In cache directories

### Location

**Simulator**:
```bash
~/Library/Developer/CoreSimulator/Devices/*/data/tmp/
```

**Device**:
```bash
/var/mobile/Containers/Data/Application/*/tmp/
```

### Extraction

```bash
# Simulator
find ~/Library/Developer/CoreSimulator/Devices/*/data/tmp -type f -exec file {} \;

# Device (via objection)
objection -g com.example.app explore
ios ls tmp
ios download tmp/* ./tmp_dump/
```

### Detection Patterns

```bash
# Look for temp file usage
rg "NSTemporaryDirectory\|tmp.*file\|writeTo.*tmp" . --exclude-dir=Frameworks/

# Check for sensitive data in temp operations
rg -A 3 "NSTemporaryDirectory" . --exclude-dir=Frameworks/
```

### Mitigation

- Avoid writing sensitive data to temp directories
- Securely delete temp files immediately after use
- Use encrypted storage for sensitive temp data
- Exclude temp directories from backups

---

## 5. Device Logs

### What Are They?

Apps may log sensitive information to:
- Console (visible in Console.app)
- System logs (accessible on device)
- Crash logs

### Detection

```bash
# Check for NSLog/os_log usage with sensitive data
rg "NSLog.*password\|os_log.*token\|print.*secret" . --exclude-dir=Frameworks/

# Look for log statements with sensitive patterns
rg -i "NSLog.*\(.*\)" . --exclude-dir=Frameworks/ | rg -i "password\|token\|key\|secret\|auth"
```

### Extraction

**From Simulator**:
```bash
# Monitor logs in real-time
log stream --predicate 'subsystem == "com.example.app"' --level debug

# Filter for sensitive keywords
log stream | grep -i "password\|token\|key\|secret"
```

**From Device**:
```bash
# With idevicesyslog (libimobiledevice)
idevicesyslog | grep com.example.app
```

### Mitigation

- Never log sensitive data
- Use logging frameworks that strip sensitive data
- Disable debug logging in production
- Use os_log with appropriate privacy levels

---

## 6. Keyboard Cache

### What Is It?

iOS caches text input for autocomplete, potentially exposing:
- Passwords (if in password fields)
- Usernames
- Other sensitive input

### Detection

```bash
# Check for text fields without secureTextEntry
rg "UITextField\|isSecureTextEntry.*false" . --exclude-dir=Frameworks/

# Look for autocorrect enabled on sensitive fields
rg -A 2 "UITextField.*password\|UITextField.*secret" . --exclude-dir=Frameworks/ | rg "autocorrectionType"
```

### Mitigation

**Swift**:
```swift
// For sensitive fields
textField.isSecureTextEntry = true
textField.autocorrectionType = .no
textField.autocapitalizationType = .none
```

---

## Generalized Analysis Workflow

### Step 1: Static Analysis

```bash
# Check for side channel patterns
rg "applicationDidEnterBackground\|UIPasteboard\|NSLog" . --exclude-dir=Frameworks/

# Check for sensitive data handling
rg -i "password\|token\|secret\|key" . --exclude-dir=Frameworks/ | rg -i "copy\|log\|paste"
```

### Step 2: Dynamic Analysis

```bash
# Monitor pasteboard
frida -U -f com.example.app -l assets/frida-scripts/pasteboard-monitor.js

# Trigger app backgrounding and extract snapshots
# (Use automated script or manual extraction)
```

### Step 3: Filesystem Analysis

```bash
# Check temp directories
objection -g com.example.app explore
ios ls tmp
ios ls Library/Caches

# Download suspicious files
ios download tmp/* ./
ios download Library/Caches/* ./
```

---

## Testing Checklist

- [ ] App screenshots don't show sensitive data in app switcher
- [ ] Sensitive data not copied to pasteboard
- [ ] Cookies use HttpOnly and Secure flags
- [ ] No sensitive data in temporary files
- [ ] No sensitive data in logs
- [ ] Sensitive text fields disable autocorrect
- [ ] Memory dumps don't reveal sensitive data (see memory-analysis-ios.md)

---

## References

- [SKILL.md](../SKILL.md) - Complete iOS pentesting methodology
- [memory-analysis-ios.md](memory-analysis-ios.md) - Memory analysis techniques
- [phishing-attacks-ios.md](phishing-attacks-ios.md) - Phishing and UI spoofing

---

**For tool installation**, see [tool-installation-ios.md](tool-installation-ios.md).

**For troubleshooting**, see [troubleshooting-ios.md](troubleshooting-ios.md).
