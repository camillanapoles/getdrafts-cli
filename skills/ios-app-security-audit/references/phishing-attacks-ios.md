# Phishing Attack Vectors in iOS Apps

## Overview

Phishing in mobile apps involves deceptive techniques to trick users into providing sensitive information. Unlike traditional web phishing, mobile app phishing can exploit platform-specific features like deep links, WebViews, and system-like UI elements.

**Common mobile phishing vectors**:
- Fake system dialogs mimicking iOS UI
- WebView spoofing to display fake login screens
- Deep link hijacking
- UI confusion attacks
- Notification spoofing

---

## 1. Fake System Dialogs

### What Are They?

Apps can create alerts that look identical to iOS system dialogs:
- Apple ID sign-in prompts
- iTunes Store authentication
- Face ID/Touch ID prompts
- Network connection alerts

### Risk

Users cannot distinguish between real system dialogs and fake ones, leading to:
- Credential theft
- Authentication bypass
- Social engineering attacks

### Detection (Static Analysis)

```bash
# Look for UIAlertController creation
rg "UIAlertController" . --exclude-dir=Frameworks/

# Check for system-like titles
rg -A 3 "UIAlertController" . --exclude-dir=Frameworks/ | rg -i "apple.*id\|itunes\|sign.*in\|password"

# Check for secure text fields in alerts
rg -A 5 "UIAlertController" . --exclude-dir=Frameworks/ | rg "isSecureTextEntry\|password"
```

### Detection (Dynamic Analysis)

```bash
# Look for alerts while using the app
# Any unexpected password prompt is suspicious
```

### Common Patterns

Malicious apps often create system-like dialogs in view controllers dedicated to social engineering:

**Fake Sign-In Dialogs**:
```swift
let alert = UIAlertController(title: "Sign In to iTunes Store",
    message: "To continue, enter the password for \"user@example.com\"",
    preferredStyle: UIAlertController.Style.alert)
alert.addTextField { textField in
    textField.placeholder = "Password"
    textField.isSecureTextEntry = true
}
```

**Fake Account Verification**:
```swift
let alert = UIAlertController(title: "Sign-In Required",
    message: "Sign In to manage your account.",
    preferredStyle: UIAlertController.Style.alert)
alert.addTextField { textField in
    textField.placeholder = "Apple ID"
    textField.keyboardType = .emailAddress
}
alert.addTextField { textField in
    textField.placeholder = "Password"
    textField.isSecureTextEntry = true
}
```

**Key indicators**:
- System-like titles ("iTunes Store", "Apple ID", "Sign In")
- Password fields in alerts (`isSecureTextEntry = true`)
- Urgency language in message text
- No clear app branding or identity

### Mitigation

**For Users**:
- Verify the app requesting credentials
- Check URL/domain in WebViews
- Use device-level biometrics when possible

**For Developers**:
- Don't replicate system UI elements
- Use official authentication frameworks (AuthenticationServices)
- Show app identity clearly

---

## 2. WebView Spoofing

### What Is It?

Apps using WebViews can be tricked into displaying:
- Fake login screens
- Phishing pages from external URLs
- Content spoofing attacks

### Risk

Attackers can:
- Inject malicious JavaScript
- Display fake payment pages
- Capture credentials through fake forms
- Bypass same-origin policies

### Detection (Static Analysis)

```bash
# Look for WebView usage
rg "WKWebView\|UIWebView" . --exclude-dir=Frameworks/

# Check for arbitrary URL loading
rg -A 3 "WKWebView.*load" . --exclude-dir=Frameworks/ | rg -i "http\|url.*string\|request"

# Look for URL validation
rg -B 2 -A 2 "loadRequest\|loadURL" . --exclude-dir=Frameworks/ | rg "validate\|whitelist\|allowlist"
```

### Detection (Dynamic Analysis)

**Frida script to monitor WebView loads**:
```javascript
if (ObjC.available) {
    var WKWebView = ObjC.classes.WKWebView;

    Interceptor.attach(WKWebView["-loadRequest:"].implementation, {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            var url = request.URL().absoluteString();
            console.log("[WebView Load] " + url);
        }
    });
}
```

### Testing

```bash
# 1. Find WebView screens in the app
# 2. Try loading external URLs (if input可控)
# 3. Check if domain is displayed to user
# 4. Verify SSL certificate validation
```

### Mitigation

**Swift**:
```swift
// Validate URLs before loading
func loadURL(_ url: URL) {
    guard allowedHosts.contains(url.host ?? "") else {
        showError("Invalid URL")
        return
    }

    let request = URLRequest(url: url)
    webView.load(request)
}

// Show domain to user
func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    domainLabel.text = webView.url?.host
}
```

---

## 3. Deep Link Abuse

### What Are It?

Deep links (URL schemes) allow apps to be launched from other sources:
- `myapp://path/to/page`
- `https://myapp.com/path`

Attackers can:
- Register same scheme in malicious app
- Intercept deep links
- Launch attacks when link is clicked

### Risk

- Credential capture through fake deep link handlers
- Data leakage through exposed parameters
- Attack surface expansion

### Detection (Static Analysis)

```bash
# Find registered URL schemes
plutil -p YourApp.app/Info.plist | rg -A 10 "CFBundleURLTypes"

# Check for deep link handling
rg "openURL\|handleOpen\|continueUserActivity" . --exclude-dir=Frameworks/

# Look for parameter extraction
rg -A 5 "openURL" . --exclude-dir=Frameworks/ | rg -i "token\|password\|key\|user"
```

### Detection (Dynamic Analysis)

```bash
# Test deep link handling
xcrun simctl openurl booted "myapp://auth?token=test"

# Monitor app response
# Check if sensitive parameters are exposed
```

### Testing Examples

**Extract URL schemes from any app**:
```bash
# Check registered schemes in Info.plist
plutil -p /path/to/YourApp.app/Info.plist | rg -A 10 "CFBundleURLTypes"

# Output example:
# CFBundleURLTypes = [
#   {
#     CFBundleURLSchemes = [
#       "myapp",
#       "myapp-auth"
#     ];
#   }
# ]
```

**Test deep link handling**:
```bash
# Test authentication flow
xcrun simctl openurl booted "myapp://auth?token=abc123"

# Test parameter manipulation
xcrun simctl openurl booted "myapp://reset?email=admin@evil.com&token=stolen"
```

### Mitigation

**Universal Links** (recommended):
- Use `https://` URLs instead of custom schemes
- Validate `apple-app-site-association` file
- Verify domain ownership

**For Custom Schemes**:
```swift
// Validate deep link parameters
func handleDeepLink(_ url: URL) {
    // Validate signature if from external source
    // Sanitize all parameters
    // Don't auto-execute sensitive actions
}
```

---

## 4. UI Confusion Attacks

### What Are They?

Attackers manipulate UI elements to confuse users:
- Overlay attacks (fake views over real ones)
- Button hijacking
- Layout manipulation

### Detection

```bash
# Look for view overlays
rg "addSubview\|present\|overlay" . --exclude-dir=Frameworks/

# Check for button manipulation
rg -A 3 "addTarget" . --exclude-dir=Frameworks/ | rg -i "sensitive\|action.*important"
```

### Testing

```bash
# 1. Look for unexpected overlays
# 2. Check if buttons can be covered
# 3. Verify tap areas are appropriate
```

---

## 5. Notification Spoofing

### What Are It?

Fake local notifications that:
- Mimic system notifications
- Request sensitive actions
- Direct users to fake screens

### Detection

```bash
# Look for notification creation
rg "UNUserNotification\|UILocalNotification" . --exclude-dir=Frameworks/

# Check for sensitive content in notifications
rg -A 5 "Notification" . --exclude-dir=Frameworks/ | rg -i "password\|verify\|urgent"
```

### Mitigation

- Don't request sensitive info via notifications
- Verify notification content
- Show clear app identity

---

## 6. Testing Checklist

### Static Analysis

- [ ] Identify all URL schemes registered
- [ ] Check for fake system dialogs
- [ ] Verify WebView URL validation
- [ ] Check deep link parameter handling
- [ ] Look for UI overlay possibilities

### Dynamic Analysis

- [ ] Test each deep link with malicious parameters
- [ ] Try loading arbitrary URLs in WebViews
- [ ] Verify all password prompts are legitimate
- [ ] Check if domain is visible in WebViews
- [ ] Test notification handling

---

## 7. Remediation Guidance

### Best Practices

**For Deep Links**:
- Use Universal Links instead of custom schemes
- Validate all parameters
- Don't auto-execute sensitive actions

**For WebViews**:
- Whitelist allowed domains
- Show current domain to user
- Disable JavaScript if not needed
- Use WKWebView (not deprecated UIWebView)

**For Authentication**:
- Use AuthenticationServices framework
- Implement Sign in with Apple
- Show clear app identity

**For UI Elements**:
- Don't replicate system dialogs
- Make fake dialogs distinguishable
- Use platform-standard authentication UI

---

## 8. Detection Script (Frida)

```javascript
/**
 * Phishing Detection - Monitor for fake dialogs and WebView loads
 */

if (ObjC.available) {
    console.log("[*] Phishing Detection Script Started");

    // Monitor UIAlertController creation
    var UIAlertController = ObjC.classes.UIAlertController;

    var alertInit = UIAlertController["-initWithTitle:message:preferredStyle:"];
    Interceptor.attach(alertInit.implementation, {
        onEnter: function(args) {
            var title = ObjC.Object(args[2]).toString();
            var message = ObjC.Object(args[3]).toString();

            // Check for suspicious patterns
            if (title.includes("iTunes") ||
                title.includes("Apple ID") ||
                title.includes("Sign In")) {
                console.log("[!] Suspicious dialog: " + title);
                console.log("    Message: " + message);
            }
        }
    });

    // Monitor WebView loads
    try {
        var WKWebView = ObjC.classes.WKWebView;
        var loadRequest = WKWebView["-loadRequest:"];

        Interceptor.attach(loadRequest.implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                if (url.startsWith("http://")) {
                    console.log("[!] Insecure WebView load: " + url);
                }
            }
        });
    } catch(e) {
        console.log("[-] WKWebView not found in this app");
    }

    console.log("[*] Monitoring active...");
}
```

**Usage**:
```bash
frida -U -f com.example.app -l phishing_detection.js
```

---

## References

- [SKILL.md](../SKILL.md) - Complete iOS pentesting methodology
- [side-channel-analysis-ios.md](side-channel-analysis-ios.md) - Side channel data leakage
- [url-scheme-security-guide.md](url-scheme-security-guide.md) - Deep link analysis

**For tool installation**, see [tool-installation-ios.md](tool-installation-ios.md).

**For troubleshooting**, see [troubleshooting-ios.md](troubleshooting-ios.md).
