# Frida Scripts for iOS App Security Audit

> **Note**: Our Frida scripts are built upon the work of the amazing security community. See [Sources & Credits](#sources--credits) for attribution. If you find better scripts, contributions are welcome!

Ready-to-use Frida scripts for common iOS security testing tasks.

## Quick Start

```bash
# Basic usage - spawn app with script
frida -U -f com.example.app -l script.js

# Attach to running app
frida -U com.example.app -l script.js

# With objection
objection -g com.example.app explore
# Then use built-in commands or paste script content
```

## Best Practices for iOS Frida

### 1. Objective-C Runtime Check

Always verify ObjC runtime is available before hooking Objective-C classes:

```javascript
// REQUIRED: Check Objective-C runtime
if (!ObjC.available) {
    console.log("[-] Objective-C runtime not available. Exiting.");
    return;
}
```

### 2. Main Queue Scheduling

For UI-related hooks or operations that must run on the main thread:

```javascript
// PATTERN: Use ObjC.schedule for main queue operations
ObjC.schedule(ObjC.mainQueue, function() {
    console.log("[+] Running on main queue");
    // Access UI-related APIs safely
});
```

### 3. Saved References Pattern

Always cache Objective-C class/method references to avoid repeated lookups:

```javascript
// AVOID: Repeated class lookups (slow)
Interceptor.attach(ObjC.classes.UIWindow['- initWithFrame:'].implementation, { ... });

// PREFER: Cache references once
var UIWINDOW_INIT = ObjC.classes.UIWindow['- initWithFrame:'].implementation;
Interceptor.attach(UIWINDOW_INIT, { ... });
```

### 4. Memory Management

Always cache strings allocated with `Memory.allocUtf8String()` to avoid memory churn:

```javascript
// AVOID: Allocates on every call (memory churn)
Interceptor.attach(targetFunc, {
    onLeave: function(retval) {
        var p = Memory.allocUtf8String("target_string"); // BAD
        Memory.copy(this.buf, p, len);
    }
});

// PREFER: Cache strings once
var CACHED_STRINGS = {
    "target_string": Memory.allocUtf8String("target_string")
};

Interceptor.attach(targetFunc, {
    onLeave: function(retval) {
        if (CACHED_STRINGS[this.key]) {
            Memory.copy(this.buf, CACHED_STRINGS[this.key], len); // GOOD
        }
    }
});
```

### 5. Pointer Validation

Always validate pointers before reading memory:

```javascript
// AVOID: Crash if pointer is null
var str = args[0].readUtf8String();

// PREFER: Defensive validation
if (!args[0] || args[0].isNull()) {
    console.log("[-] Invalid pointer");
    return;
}
var str = args[0].readUtf8String();
```

### 6. Try-Catch Per Hook

Always wrap Objective-C method hooks in try-catch to prevent crashes:

```javascript
// PATTERN: Safe hooking with error handling
try {
    var method = ObjC.classes.TargetClass['- methodName:'];
    Interceptor.attach(method.implementation, {
        onEnter: function(args) {
            var self = new ObjC.Object(args[0]);
            var selector = ObjC.selectorAsString(args[1]);
            console.log("[*] " + self.$className + " called: " + selector);
        },
        onLeave: function(retval) {
            try {
                var obj = new ObjC.Object(retval);
                console.log("[+] Return: " + obj.toString());
            } catch(e) {
                console.log("[+] Return: " + retval);
            }
        }
    });
} catch(e) {
    console.log("[-] Failed to hook TargetClass -methodName: " + e);
}
```

## Available Scripts

| Script | Category | Purpose | OWASP Ref |
|--------|----------|---------|-----------|
| `ssl-pinning-bypass-ios.js` | Network | Universal SSL/TLS pinning bypass — native BoringSSL `SSL_(CTX_)set_custom_verify` (SSL Kill Switch 2), NSURLSession, AFNetworking, Alamofire, TrustKit, App Transport Security overrides | M5 |
| `jailbreak-detection-bypass.js` | Auth | Comprehensive jailbreak bypass — ObjC file/readable/write-test + canOpenURL, stat/fopen/fork/posix_spawn/dlopen syscalls, UIDevice, and direct isJailbroken/jailbreakTest method discovery | M8 |
| `biometric-bypass-ios.js` | Auth | Universal biometric auth bypass — TouchID, FaceID, LocalAuthentication, EvaluatePolicy | M3 |
| `keychain-dumper.js` | Storage | Dump Keychain items with access control and metadata (generic passwords, certificates, identities, keys) | M6 |
| `url-scheme-monitor.js` | IPC | Monitor URL scheme handlers and deep link invocations with parameter extraction | M9 |
| `uiwebview-interceptor.js` | Network | Monitor UIWebView and WKWebView URL loading, JavaScript interfaces, and SSL errors | M1 |
| `nsuserdefaults-dumper.js` | Storage | Comprehensive UserDefaults dumper with sensitive data detection, system key filtering, read/write monitoring hooks, App Groups support, and summary statistics | M6 |
| `network-interceptor-ios.js` | Network | HTTP/HTTPS traffic interception — NSURLSession, NSURLConnection, CFNetwork, WebSocket monitoring | M5 |
| `pasteboard-monitor.js` | Storage | Monitor clipboard (pasteboard) access for sensitive data exfiltration | M9 |
| `app-transport-security.js` | Network | Monitor and bypass App Transport Security (ATS) configuration and exceptions | M5 |
| `objc-method-tracer.js` | Utility | Trace Objective-C method calls with arguments, return values, and call stack | General |
| `binary-class-dump.js` | Utility | Dump Objective-C class information and method signatures from running binary | General |
| `coredata-interceptor.js` | Storage | Intercept CoreData operations (NSManagedObjectContext, NSFetchRequest, NSManagedObject) | M6 |
| `crypto-hook-ios.js` | Crypto | Hook CommonCrypto operations (CCCrypt, CCHmac, CC_MD5, CC_SHA1, CC_SHA256) | M4 |
| `xpc-tracer.js` | IPC | Trace XPC (Cross-Process Communication) messages and service connections | M9 |
| `clipboard-exfiltration.js` | Storage | Monitor and log clipboard read/write operations for data leak detection | M9 |
| `data-protection-check.js` | Storage | Check NSDataProtection levels for files in app container (NSFileProtectionComplete, etc.) | M6 |
| `secure-enclave-probe.js` | Crypto | Probe Secure Enclave operations and key storage (kSecAttrTokenIDSecureEnclave) | M4 |
| `background-fetch-monitor.js` | Utility | Monitor background fetch and app refresh tasks | General |
| `keylogger-basic.js` | Utility | Basic keylogger for UITextField and UITextView input capture | M9 |
| `notification-interceptor.js` | IPC | Intercept local and remote notifications (UNUserNotificationCenter) | M9 |
| `deep-link-fuzzer.js` | IPC | Fuzz deep link handlers and URL scheme endpoints | M9 |
| `deeplink-security-analyzer.js` | IPC | Deep link security analyzer - detect token exposure, OAuth interception, and authentication bypass | M9 |
| `app-groups-inspector.js` | Storage | Inspect app group shared container contents and access patterns | M6 |
| `flutter-ios-hook.js` | Utility | Hook Flutter iOS platform channels and message passing | M5 |
| `react-native-ios-hook.js` | Utility | Hook React Native iOS bridge and native modules | M5 |
| `dump-ios.js` | Utility | Dump decrypted iOS app binaries and dynamic libraries from memory | M7 |
| `ios-static-analysis.js` | Utility | Comprehensive static security analysis of iOS applications (classes, methods, URL schemes, ATS, crypto) | General |
| `ios-utilities.js` | Utility | Collection of useful iOS pentesting utilities (memory, modules, classes, methods, file system) | General |
| `objc-method-observer.js` | Utility | Observe and log Objective-C method calls in real-time with filtering | General |
| `flutter-ssl-pinning-ios.js` | Network | Bypass SSL pinning in Flutter iOS apps — hooks Flutter's native BoringSSL (dart:io `HttpClient`, `SSL_(CTX_)set_custom_verify`) plus SecTrust/plugin fallbacks | M5 |
| `file-protection-enumerator.js` | Storage | Enumerate and analyze iOS file protection attributes and identify insecure sensitive files | M6 |
| `enterprise-cert-bypass.js` | Auth | Bypass enterprise certificate validation checks (NSURLSession delegate, SecTrustEvaluate hooks) | M8 |
| `mdm-bypass.js` | Auth | Detect and bypass MDM (Mobile Device Management) restrictions and managed app configuration | M8 |
| `mobsf-api-integration.js` | Utility | Push live findings to MobSF REST API for correlation with static scan results | General |
| `objc-api-explorer.js` | Utility | Explore Objective-C runtime: list classes, methods, protocols, properties, and Ivar layouts at runtime | General |
| `sdk-tracer.js` | Supply Chain | Runtime SDK detection and analysis - identifies analytics, advertising, authentication, payment, and other third-party SDKs with method tracing | M2 |
| `memory-dumper-ios.js` | Storage | Scan process memory for API keys, tokens, passwords, and other secrets using pattern matching | M6 |
| `cookie-dumper-ios.js` | Network | Extract cookies from NSHTTPCookieStorage with domain, value, and security flags | M5 |
| `jailbreak-bypass-ios.js` | Auth | Lightweight jailbreak bypass — pure ObjC, auto-discovers and hooks isJailbroken methods only (class + instance); use when the comprehensive script's C-level hooks destabilize the app | M8 |
| `class-explorer-ios.js` | Utility | List all Objective-C classes and methods with filtering support | General |
| `simple-test-ios.js` | Utility | Verify Frida connection to iOS app in simulator (test Objective-C runtime availability) | General |
| `tls-keylogger-ios.js` | Network | Extract TLS session secrets from BoringSSL in NSS key-log format (SSLKEYLOGFILE) — decrypt traffic in Wireshark without MITM or pinning bypass (TLS 1.2 + 1.3) | M5 |
| `proxy-detection-bypass-ios.js` | Network | Hide active proxy/VPN config from the app (CFNetworkCopySystemProxySettings, CFNetworkCopyProxiesForURL, connectionProxyDictionary) | M5 |
| `webview-inspector-enable-ios.js` | Network | Force-enable Safari Web Inspector on WKWebView in production builds (isInspectable + legacy _developerExtrasEnabled) | M4 |
| `rasp-bypass-ios.js` | Auth | Bypass commercial/OSS RASP — IOSSecuritySuite, FreeRASP/Talsec, JailMonkey, IBM Trusteer, IOSSecuritySlayer — flips jailbreak/debugger/emulator/proxy/RE getters to safe | M7 |
| `anti-debugging-bypass-ios.js` | Auth | Defeat native anti-debugging — ptrace(PT_DENY_ATTACH), syscall(SYS_ptrace), sysctl(KERN_PROC) P_TRACED scrub, getppid | M7 |
| `jailbreak-detection-tracer-ios.js` | Auth | Non-destructive recon — traces which paths/APIs the app checks for jailbreak (fileExistsAtPath/canOpenURL/stat/access/fopen) without bypassing | M7 |
| `prevent-app-termination-ios.js` | Auth | Prevent app self-termination during instrumentation (exit/_exit/abort, self-directed kill, terminateWithSuccess) | M7 |
| `sqlite-query-logger-ios.js` | Storage | Log every SQL statement in real time before execution (sqlite3_prepare_v2/v3/prepare + UTF-16 variants) | M9 |
| `keychain-editor-ios.js` | Storage | Intercept Keychain reads and inject alternative values (SecItemCopyMatching) for auth bypass/testing | M6 |
| `keyboard-security-check-ios.js` | Storage | Audit keyboard security — third-party keyboard policy + secureTextEntry/autocorrect on sensitive fields | M9 |
| `snapshot-overlay-check.js` | Storage | Verify app-switcher snapshot protection (overlay/hide on backgrounding lifecycle) | M9 |
| `managed-app-inspector.js` | Storage | Dump MDM managed app configuration (com.apple.configuration.managed) for enterprise/MDM audits | M8 |
| `pkcs12-extractor-ios.js` | Crypto | Capture client certificates and passphrases via SecPKCS12Import (dumps .p12 blob + passphrase) | M1 |
| `location-spoofing-ios.js` | Utility | Spoof GPS coordinates in CLLocationManager (location getter + delegate callbacks, configurable lat/long) | M4 |
| `anti-frida-bypass-advanced-ios.js` | Anti-Detection | Advanced anti-Frida detection bypass — thread name hiding, /proc/self/maps spoofing, port scanning block, dlopen path hiding | M7 |
| `stalker-coverage-ios.js` | Utility | Code coverage collection using Frida Stalker — track executed blocks, functions, and modules for fuzzing/reverse engineering | General |
| `biometric-deeplink-bypass-ios.js` | Auth | Detect deep links that reach protected views without biometric re-authentication — correlates LAContext.evaluatePolicy timing against deep-link navigation (H1-637194 Shopify pattern) | M3 |
| `deeplink-csrf-validator-ios.js` | IPC | Flag state-changing deep link actions (follow/pay/delete/transfer) that lack a CSRF/state/nonce token (H1-805073 Periscope forced-follow pattern) | M9 |
| `mobile-rate-limit-detector-ios.js` | Auth | Detect auth endpoints (/login, /oauth, /pin, ...) with no rate limiting by counting attempts against lockout/critical thresholds (H1-160109 Instacart pattern) | M3 |
| `ssl-validation-checker-ios.js` | Network | Detect apps that skip SSL/TLS certificate validation (no SecTrustEvaluate / NSURLSession challenge handler) — MITM-exposed (H1-168538 Twitter pattern) | M5 |
| `webview-xss-scanner-ios.js` | Network | Scan WebView HTML loads (loadHTMLString / evaluateJavaScript) for unsanitized user input and XSS payloads (H1 Brave/Nextcloud patterns) | M4 |
| `cryptokit-hook-ios.js` | Crypto | Hook Apple CryptoKit operations (AES-GCM/ChaChaPoly seal/open, HMAC, SHA, key agreement) to inspect keys, plaintext, and ciphertext | M4 |
| `deserialization-hook-ios.js` | Storage | Trace unsafe deserialization — NSKeyedUnarchiver/NSCoding, JSONDecoder, PropertyListDecoder — flagging insecure unarchiving without class allow-lists | M4 |
| `nwconnection-hook-ios.js` | Network | Inspect Network.framework (`NWConnection`) sends/receives — payloads, endpoints, and TLS parameters for modern Swift networking | M5 |
| `passkeys-hook-ios.js` | Auth | Trace passkey / WebAuthn flows (ASAuthorizationController, AuthenticationServices) — credential creation/assertion and relying-party data | M3 |
| `rasp-bypass-ios-full.js` | Auth | Multi-layer RASP bypass — combined exit/abort/ptrace/sysctl/uname/file-check neutralization for hardened apps | M7 |
| `rasp-bypass-ios-ultra.js` | Auth | Ultra-aggressive RASP bypass for simulator detection — hooks exit/abort/pthread_kill, sysctl, uname, ptrace, getppid | M7 |
| `rasp-terminology-trace-ios.js` | Auth | Non-destructive recon — traces RASP/anti-tamper terminology and class/method usage (e.g. NuDetect) without bypassing, with heartbeat monitoring | M7 |
| `react-native-rasp-bypass-ios.js` | Auth | Bypass RASP in React Native iOS apps — targets the RN bridge / native security modules (e.g. RNNuDetect) | M7 |
| `swift-concurrency-monitor-ios.js` | Utility | Monitor Swift concurrency primitives (async/await, Task, actors, MainActor) for race/ordering issues during analysis | General |
| `white-screen-diagnose-ios.js` | Utility | Diagnose blank/white-screen launches — inspect view hierarchy, root view controller, and window state to triage UI failures | General |

**Legend:**
- **STABLE**: Production-ready, well-tested (maturity is noted per script in the Detailed Usage sections below)
- **BETA**: Functional but may need refinement

## Detailed Usage

### SSL Pinning Bypass (STABLE)

```bash
frida -U -f com.example.app -l ssl-pinning-bypass-ios.js

# Hooks: NSURLSession delegate methods, AFNetworking, Alamofire, TrustKit,
#         ServerTrustPolicy, SecTrustEvaluate, SecPolicyCreateSSL
# MASTG Ref: MASTG-TEST-0011
```

### Jailbreak Detection Bypass — Comprehensive (STABLE)

```bash
frida -U -f com.example.app -l jailbreak-detection-bypass.js

# Use for: production/banking apps with layered detection.
# Hooks: NSFileManager fileExistsAtPath / fileExistsAtPath:isDirectory: / isReadableFileAtPath
#         / createFileAtPath (write test); UIApplication canOpenURL (cydia://, sileo://, ...);
#         stat, fopen, fork, posix_spawn, dlopen syscalls (anti-frida);
#         UIDevice.isJailbroken; direct +/-isJailbroken & *jailbreakTest* method discovery
# MASTG Ref: MASTG-TEST-0015
```

### Jailbreak Bypass - Lightweight (STABLE)

```bash
frida -U -f com.example.app -l jailbreak-bypass-ios.js

# Use for: Quick, low-noise testing when isJailbroken hooks are sufficient
#          (simple apps, CTFs), or when the comprehensive script's C-level hooks
#          (stat/fopen/fork/posix_spawn) destabilize the target.
# Hooks: Auto-discovers and hooks isJailbroken, isJailBroken, isDeviceJailbroken,
#        jailbreakTest methods in all classes (class + instance). Pure ObjC — no
#        Interceptor.replace on C functions.
# MASTG Ref: MASTG-TEST-0015

# When to use which:
# - Lightweight (this script): simple apps, quick POC, method-call-only detection,
#                              or when C-level hooks crash the app.
# - Comprehensive (jailbreak-detection-bypass.js): production/banking apps with layered
#                              detection — adds file checks, URL schemes, write tests,
#                              stat/fopen/fork/posix_spawn/dlopen syscalls, and UIDevice.
```

### Biometric Bypass (STABLE)

```bash
frida -U -f com.example.app -l biometric-bypass-ios.js

# Hooks: LAContext.evaluatePolicy, LAContext.canEvaluatePolicy,
#         TouchID/FaceID callbacks, LAContext
# MASTG Ref: MASTG-TEST-0018
```

### Keychain Dumper (STABLE)

```bash
frida -U -f com.example.app -l keychain-dumper.js

# Outputs: Item class, account, service, access group, creation date,
#           accessibility attribute (kSecAttrAccessible)
# MASTG Ref: MASTG-STORAGE-0012
```

### URL Scheme Monitor (STABLE)

```bash
frida -U -f com.example.app -l url-scheme-monitor.js

# Hooks: UIApplication openURL, canOpenURL,
#         URL scheme parameter extraction, deep link logging
# MASTG Ref: MASTG-TEST-0049
```

### UIWebView Interceptor (STABLE)

```bash
frida -U -f com.example.app -l uiwebview-interceptor.js

# Hooks: UIWebView.loadRequest, loadHTMLString, stringByEvaluatingJavaScriptFromString,
#         WKWebView.loadRequest, loadHTMLString, evaluateJavaScript,
#         WKNavigationDelegate callbacks
# MASTG Ref: MASTG-TEST-0045
```

### NSUserDefaults Dumper (STABLE)

```bash
frida -U -f com.example.app -l nsuserdefaults-dumper.js

# Outputs: All domain values (app domain, global domain),
#           Type information (String, Number, Bool, Array, Dictionary),
#           Sensitive data detection (API keys, tokens)
# MASTG Ref: MASTG-STORAGE-0011
```

### Network Interceptor (STABLE)

```bash
frida -U -f com.example.app -l network-interceptor-ios.js

# Hooks: NSURLSession dataTask, NSURLSessionDelegate methods,
#         NSURLConnection, CFURLConnection, WebSocket connections
# Logs: URL, method, headers, body (first 500 chars), status code
# MASTG Ref: MASTG-NETWORK-0001
```

### Pasteboard Monitor (STABLE)

```bash
frida -U -f com.example.app -l pasteboard-monitor.js

# Hooks: UIPasteboard.string, UIPasteboard.items,
#         Read and write operations with content logging
# MASTG Ref: MASTG-STORAGE-0013
```

### App Transport Security (STABLE)

```bash
frida -U -f com.example.app -l app-transport-security.js

# Monitors: NSAllowsArbitraryLoads, NSExceptionDomains,
#           SSL/TLS configuration, ATS policy violations
# Outputs: Configuration warnings and bypass opportunities
# MASTG Ref: MASTG-NETWORK-0011
```

### ObjC Method Tracer (STABLE)

```bash
# Edit CONFIG.targetClasses at top of script before running
frida -U -f com.example.app -l objc-method-tracer.js

# Configurable: Target classes, method filter, include class methods,
#               verbose output with arguments and return values
```

### Binary Class Dump (STABLE)

```bash
frida -U -f com.example.app -l binary-class-dump.js

# Outputs: All Objective-C classes, instance methods, class methods,
#           Properties, protocols, superclasses
```

### CoreData Interceptor (BETA)

```bash
frida -U -f com.example.app -l coredata-interceptor.js

# Hooks: NSManagedObjectContext.executeFetchRequest,
#         NSManagedObject managedObjectContext, setValue:forKey:
# Logs: Entity names, predicates, fetch results, data modifications
# MASTG Ref: MASTG-STORAGE-0014
```

### Crypto Hook (BETA)

```bash
frida -U -f com.example.app -l crypto-hook-ios.js

# Hooks: CCCrypt, CCCryptorCreate, CCHmac,
#         CC_MD5, CC_SHA1, CC_SHA256, CC_SHA512
# Logs: Operation type, algorithm, key length, input/output data
# MASTG Ref: MASTG-CRYPTO-0001
```

### XPC Tracer (BETA)

```bash
frida -U -f com.example.app -l xpc-tracer.js

# Hooks: xpc_connection_create, xpc_connection_send_message,
#         xpc_connection_set_event_handler
# Logs: Service name, message dictionary, handler callbacks
# MASTG Ref: MASTG-TEST-0048
```

### Clipboard Exfiltration (BETA)

```bash
frida -U -f com.example.app -l clipboard-exfiltration.js

# Hooks: UIPasteboard read/write with content type detection
# Detects: Potential data exfiltration via clipboard
# MASTG Ref: MASTG-STORAGE-0013
```

### Data Protection Check (BETA)

```bash
frida -U -f com.example.app -l data-protection-check.js

# Analyzes: NSFileProtectionComplete, NSFileProtectionCompleteUnlessOpen,
#            NSFileProtectionCompleteUntilFirstUserAuthentication,
#            NSFileProtectionNone
# Scans: App container files and reports protection levels
# MASTG Ref: MASTG-STORAGE-0012
```

### Secure Enclave Probe (BETA)

```bash
frida -U -f com.example.app -l secure-enclave-probe.js

# Hooks: SecItemAdd, SecItemCopyMatching with kSecAttrTokenIDSecureEnclave
# Detects: Secure Enclave key storage usage, access control flags
# MASTG Ref: MASTG-CRYPTO-0002
```

### Background Fetch Monitor (BETA)

```bash
frida -U -f com.example.app -l background-fetch-monitor.js

# Hooks: BGTaskScheduler.submit, beginBackgroundTaskWithExpirationHandler,
#         application:performFetchWithCompletionHandler
# Logs: Task scheduling, execution, and background time limits
```

### Keylogger Basic (BETA)

```bash
frida -U -f com.example.app -l keylogger-basic.js

# Hooks: UITextField textFieldShouldReturn, UITextFieldDelegate,
#         UITextViewDelegate text change methods
# Logs: Field identifiers, input content, timestamps
# MASTG Ref: MASTG-TEST-0061
```

### Notification Interceptor (BETA)

```bash
frida -U -f com.example.app -l notification-interceptor.js

# Hooks: UNUserNotificationCenter.addNotificationRequest,
#         userNotificationCenter:didReceiveNotificationResponse,
#         delegate callbacks
# Logs: Notification title, body, payload data, trigger type
# MASTG Ref: MASTG-TEST-0065
```

### Deep Link Fuzzer (BETA)

```bash
frida -U -f com.example.app -l deep-link-fuzzer.js

# Hooks: UIApplication openURL with fuzzing patterns
# Tests: SQL injection, XSS, command injection in URL parameters
# MASTG Ref: MASTG-TEST-0049
```

### Deep Link Security Analyzer (STABLE)

```bash
frida -U -f com.example.app -l deeplink-security-analyzer.js

# Hooks: UIApplication openURL, application:openURL:options:, application:continueUserActivity:restorationHandler:
# Detects: Token/secret exposure, OAuth code interception, authentication bypass, CSRF via deep links
# Logs: URL components, query parameters, severity levels (CRITICAL, HIGH, MEDIUM, LOW), CVSS 4.0 scores
# MASTG Ref: MASTG-TEST-0151, MASTG-TEST-0152, MASTG-APP-003, MASTG-AUTH-002, MASTG-STORAGE-0013

# Detection Patterns:
# - Token exposure: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CRITICAL)
# - OAuth code interception: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (HIGH)
# - Authentication bypass: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CRITICAL)
# - CSRF via deep link: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N (HIGH)
```

### App Groups Inspector (BETA)

```bash
frida -U -f com.example.app -l app-groups-inspector.js

# Inspects: App group container directories, shared file paths
# Detects: Data sharing patterns between app extensions
# MASTG Ref: MASTG-STORAGE-0011
```

### Flutter iOS Hook (BETA)

```bash
frida -U -f com.example.app -l flutter-ios-hook.js

# Hooks: FlutterMethodChannel.invokeMethod, FlutterBinaryMessenger,
#         Platform message passing
# Logs: Method name, arguments, response data
# MASTG Ref: MASTG-TEST-0050
```

### React Native iOS Hook (BETA)

```bash
frida -U -f com.example.app -l react-native-ios-hook.js

# Hooks: RCTBridge enqueueJSCall, RCTNativeModule methods,
#         Native module invocations
# Logs: Module name, method name, arguments, return values
# MASTG Ref: MASTG-TEST-0050
```

### SDK Tracer (STABLE)

```bash
frida -U -f com.example.app -l sdk-tracer.js

# Hooks: Mixpanel, Amplitude, Segment, Flurry, Firebase, Facebook, Google Ads,
#         Adjust, AppsFlyer, Branch, Stripe, Braintree, AWS, Amplify
# Logs: SDK initialization, method calls, PII detection, network requests
# Categories: Analytics, Advertising, Attribution, Authentication, Payment, Cloud
```

**Tracked SDK Categories:**

- **Analytics**: Mixpanel, Amplitude, Segment, Flurry, Crashlytics, Firebase Analytics
- **Advertising**: Facebook SDK, Google AdMob, UnityAds, AdColony
- **Attribution**: Adjust, AppsFlyer, Branch
- **Authentication**: Firebase Auth, Auth0, Okta
- **Payment**: Stripe, Braintree, PayPal
- **Cloud**: AWS SDK, Amplify, Firebase
- **Push**: Firebase Messaging, OneSignal
- **Social**: Facebook, Google Sign-In, Twitter
- **Privacy**: App Tracking Transparency

**Features:**

```text
// Automatic SDK detection by class prefix
[+] Mixpanel (analytics)
[+] FBSDK (advertising) [SENSITIVE]
[+] Stripe (payment) [SENSITIVE]

// Method call tracking with PII detection
[SDK] Mixpanel track
     Args: "user_action", {"type":"button_click"}
[!] PII DETECTED: Email in Stripe.createTokenWithCard

// Network request monitoring
[Network] SDK Request: https://analytics.mixpanel.com/track
[Analytics] Analytics call: https://analytics.mixpanel.com/track
```

**Supply Chain Analysis:**

```bash
# Generate runtime SDK inventory
frida -U -f com.example.app -l sdk-tracer.js

# Combine with SBOM for complete supply chain view
python3 scripts/sbom_generator.py --input app.ipa
python3 scripts/dependency_scanner.py --sbom app-sbom.json
```

### TLS Keylogger (STABLE)

```bash
frida -U -f com.example.app -l tls-keylogger-ios.js | tee keylog.txt

# Extracts BoringSSL session secrets in NSS key-log format (TLS 1.2 + 1.3).
# Prefers SSL_CTX_set_keylog_callback (version independent); falls back to
# CLIENT_RANDOM master-key extraction. Load keylog.txt in Wireshark:
#   Preferences > Protocols > TLS > (Pre)-Master-Secret log filename
# No MITM proxy and no pinning bypass required.
# MASTG Ref: MASTG-TEST-0011
```

> **tls-keylogger-ios.js vs ssl-pinning-bypass-ios.js** — pick by goal:
> - **ssl-pinning-bypass-ios.js**: you need to *see and modify* traffic live through Burp/mitmproxy (request tampering, replay, fuzzing). Requires a proxy in the path.
> - **tls-keylogger-ios.js**: the proxy route is blocked — pinning you can't defeat, a custom/non-NSURLSession TLS stack, or cert-transparency checks — and you only need to *read* traffic. Gives Wireshark offline decryption with no proxy. They compose: keylog for visibility, pinning-bypass for active interception.

### Proxy / VPN Detection Bypass (STABLE)

```bash
frida -U -f com.example.app -l proxy-detection-bypass-ios.js

# Returns an empty (no-proxy) settings dict so the app runs while a proxy is set.
# Hooks: CFNetworkCopySystemProxySettings, CFNetworkCopyProxiesForURL,
#         -[NSURLSessionConfiguration connectionProxyDictionary]
# Pair with ssl-pinning-bypass-ios.js. MASTG Ref: MASTG-TEST-0011
```

### WKWebView Web Inspector Enabler (STABLE)

```bash
frida -U -f com.example.app -l webview-inspector-enable-ios.js

# Forces WKWebView.isInspectable = YES (iOS 16.4+) and toggles the legacy
# _developerExtrasEnabled preference for older builds. Inspect via
# Safari (macOS) > Develop > [device] > [web view]. MASTG Ref: MASTG-TEST-0045
```

### RASP Bypass (BETA)

```bash
frida -U -f com.example.app -l rasp-bypass-ios.js

# Neutralizes IOSSecuritySuite, FreeRASP/Talsec, JailMonkey, IBM Trusteer,
# and IOSSecuritySlayer by flipping their detection getters
# (jailbreak/debugger/emulator/proxy/reverse/tamper -> false; isSecure -> true).
# ObjC paths are version independent; Swift paths match IOSSecuritySuite symbol
# names. Combine with anti-debugging-bypass-ios.js + jailbreak-detection-bypass.js.
# MASTG Ref: MASTG-TEST-0015
```

### Anti-Debugging Bypass (STABLE)

```bash
frida -U -f com.example.app -l anti-debugging-bypass-ios.js

# Hooks: ptrace(PT_DENY_ATTACH) + syscall(SYS_ptrace) -> success no-op,
#         sysctl(KERN_PROC, KERN_PROC_PID) -> clears P_TRACED in kinfo_proc,
#         getppid -> 1 (launchd). Spawn with -f so hooks land before checks run.
# MASTG Ref: MASTG-TEST-0016
```

### Jailbreak Detection Tracer (STABLE)

```bash
frida -U -f com.example.app -l jailbreak-detection-tracer-ios.js

# Read-only recon — never bypasses. Traces fileExistsAtPath:/canOpenURL: and
# stat/lstat/access/fopen/open, marking [JB?] when a path/URL matches a known
# jailbreak indicator. Run BEFORE jailbreak-detection-bypass.js to map the
# detection surface. MASTG Ref: MASTG-TEST-0015
```

### Prevent App Termination (STABLE)

```bash
frida -U -f com.example.app -l prevent-app-termination-ios.js

# Blocks self-termination so anti-tamper can't quit during analysis.
# Hooks: exit/_exit/_Exit/abort -> no-op; kill(self, SIGKILL/SIGTERM/...) ->
#         swallowed; -[UIApplication terminateWithSuccess] -> no-op (IMP replaced).
# Does NOT stop OS watchdog kills. Load first (spawn with -f).
```

### SQLite Query Logger (STABLE)

```bash
frida -U -f com.example.app -l sqlite-query-logger-ios.js

# Logs raw SQL before execution via sqlite3_prepare_v2/v3/prepare and the
# UTF-16 variants. Flags write/DDL and sensitive-looking columns.
# MASTG Ref: MASTG-TEST-0006
```

### Keychain Editor (BETA)

```bash
frida -U -f com.example.app -l keychain-editor-ios.js

# Logs every SecItemCopyMatching lookup (class/service/account) and, when
# CONFIG.overrides match, injects a replacement value and returns errSecSuccess.
# Also logs SecItemAdd / SecItemUpdate / SecItemDelete so you see exactly what
# the app writes, updates, or clears. Passive logger when no overrides are set.
# MASTG Ref: MASTG-TEST-0013
```

> **keychain-dumper.js vs keychain-editor-ios.js** — pick by goal:
> - **keychain-dumper.js**: one-shot *recon* — enumerate and dump all stored items with their accessibility / access-control metadata.
> - **keychain-editor-ios.js**: *active* testing — watch reads/writes/updates/deletes in real time and inject forged values (e.g. force a session token or `isPremium=true`) to test auth and tamper-resistance.

### Keyboard Security Auditor (STABLE)

```bash
frida -U -f com.example.app -l keyboard-security-check-ios.js

# (a) Reports the third-party keyboard policy via
#     application:shouldAllowExtensionPointIdentifier: (allowed by default if
#     unimplemented). (b) Snapshots live UITextField/UITextView and flags
#     sensitive fields missing secureTextEntry or with autocorrect enabled.
# Call auditTextFields() from the REPL after navigating. MASTG Ref: MASTG-TEST-0054
```

### Snapshot Protection Check (STABLE)

```bash
frida -U -f com.example.app -l snapshot-overlay-check.js

# Observes applicationWillResignActive:/applicationDidEnterBackground: and
# reports whether a privacy overlay/hide was applied before iOS snapshots the
# UI for the app switcher. Background the app to get the verdict.
# MASTG Ref: MASTG-TEST-0021
```

### Managed App Configuration Inspector (STABLE)

```bash
frida -U -f com.example.app -l managed-app-inspector.js

# Dumps MDM-delivered config from com.apple.configuration.managed (and the
# feedback channel + bundle ".managed" suite), flagging tokens/passwords/URLs.
# Requires an MDM-enrolled device. MASTG Ref: MASTG-TEST-0002
```

### PKCS#12 Extractor (STABLE)

```bash
frida -U -f com.example.app -l pkcs12-extractor-ios.js

# Hooks SecPKCS12Import to capture the imported .p12/.pfx blob and its
# passphrase (kSecImportExportPassphrase). Saves the blob to the app tmp dir
# and prints base64. Re-use for mutual-TLS interception:
#   openssl pkcs12 -in extracted_1.p12 -info -nodes
# MASTG Ref: MASTG-TEST-0012
```

### Location Spoofing (STABLE)

```bash
# Edit CONFIG.latitude / CONFIG.longitude at top of script first
frida -U -f com.example.app -l location-spoofing-ios.js

# Replaces CLLocation objects from -[CLLocationManager location] and the
# delegate callbacks (didUpdateLocations: / didUpdateToLocation:fromLocation:).
# MASTG Ref: MASTG-TEST-0073
```

## Combining Scripts

```bash
# Complete network + storage audit
frida -U -f com.example.app \
  -l ssl-pinning-bypass-ios.js \
  -l jailbreak-detection-bypass.js \
  -l network-interceptor-ios.js \
  -l keychain-dumper.js \
  -l nsuserdefaults-dumper.js

# IPC + Deep Link testing
frida -U -f com.example.app \
  -l jailbreak-detection-bypass.js \
  -l url-scheme-monitor.js \
  -l xpc-tracer.js \
  -l notification-interceptor.js

# Crypto + Auth assessment
frida -U -f com.example.app \
  -l jailbreak-detection-bypass.js \
  -l biometric-bypass-ios.js \
  -l crypto-hook-ios.js \
  -l secure-enclave-probe.js

# Full hybrid app analysis (Flutter/React Native)
# Use -l flutter-ios-hook.js OR -l react-native-ios-hook.js, not both.
frida -U -f com.example.app \
  -l ssl-pinning-bypass-ios.js \
  -l uiwebview-interceptor.js \
  -l network-interceptor-ios.js \
  -l flutter-ios-hook.js
```

## Using with Objection

```bash
objection -g com.example.app explore

# iOS-specific commands
ios jailbreak disable
ios jailbreak simulate
ios hooking list classes
ios hooking list class_methods TargetClass
ios hooking watch class_method "-[TargetClass method:]"
ios keychain dump
ios nsuserdefaults get
ios pasteboard monitor
ios biometrics bypass
ios sslpinning disable

# WebView analysis
ios webview get_cookies
ios webview execute_js "document.body.innerHTML"

# Heap analysis
ios heap dump_instances com.target.ModelClass
ios heap search_instances "password"
ios heap print_instance 0x12345678
```

## Sources & Credits

### SSL Pinning Bypass
- **Frida CodeShare** — https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/ — Multiple pinning bypass
- **FriList** — https://github.com/rsenet/FriList — iOS SSL unpinning scripts
- **OWASP MASTG** — https://github.com/OWASP/OWASP-MSTG — Mobile Security Testing Guide

### Jailbreak Detection Bypass
- **FridaBypassKit** (okankurtuluss) — https://github.com/okankurtuluss/FridaBypassKit — All-in-one bypass
- **nabla-c0d3** — https://github.com/nabla-c0d3/sslyze — SSL/TLS analysis

### Biometric Bypass
- **dki** — https://github.com/dki/frida-scripts — Biometric bypass scripts
- **WithSecureLABS** — https://github.com/WithSecureLABS/ios-mas — iOS Mobile Assessment Scripts

### Keychain Dumper
- **Frida CodeShare** — https://codeshare.frida.re/@martinborse/ios-keychain-dumper/
- **Frida-iOS-Dump** — https://github.com/ChiChou/Frida-iOS-Dump

### Network Interceptor
- **Custom Implementation** — Frida-based iOS network monitoring
- Covers: NSURLSession, NSURLConnection, CFNetwork, WebSocket
- OWASP Reference: MASTG-NETWORK-0001

### Objective-C Runtime Utilities
- **FRIDA-ObjC-Trace** — https://github.com/interference-security/frida-scripts — ObjC method tracing
- **Frida-trace** — https://codeshare.frida.re/@oleavr/frida-trace/ — Trace instrumentation

### TLS Keylogger (BoringSSL)
- **andydavies** — https://github.com/andydavies/ios-tls-keylogger — iOS TLS key extraction
- **Frida CodeShare** — https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
- Consolidates the universalkeylogger / ios13 / ios-15 / newoffset variants into one symbol-first script
- OWASP Reference: MASTG-TEST-0011

### RASP / Anti-Tamper Bypass
- **IOSSecuritySuite** (securing) — https://github.com/securing/IOSSecuritySuite
- **Free-RASP iOS** (Talsec) — https://github.com/talsec/Free-RASP-iOS
- **JailMonkey** (GantMan) — https://github.com/GantMan/jail-monkey
- **fridantiroot** (dzonerzy) — https://codeshare.frida.re/@dzonerzy/fridantiroot/ — pattern inspiration
- OWASP Reference: MASTG-TEST-0015, MASTG-TEST-0016

### Collections & Toolkits
- **FriList** — https://github.com/rsenet/FriList — 184 stars, iOS Frida scripts collection
- **Objection** (SensePost) — https://github.com/sensepost/objection — Runtime mobile exploration toolkit
- **Frida CodeShare** — https://codeshare.frida.re/ — Community script repository
- **interference-security** — https://github.com/interference-security/frida-scripts — Comprehensive script collection

### iOS-Specific Resources
- **OWASP MASTG** — https://mas.owasp.org/MASSTG/ — Mobile App Security Testing Guide
- **Frida iOS Tutorials** — https://codeshare.frida.re/browse/ios/
- **iOS Reverse Engineering** — https://github.com/interference-security/tools
