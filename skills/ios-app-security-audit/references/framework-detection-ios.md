# Framework Detection for iOS

## Detection Methodology

### React Native Detection

#### File-Based Detection

```bash
# Check for main.jsbundle
find . -name "main.jsbundle"

# Check for React Native framework
find . -path "*/Frameworks/*" -name "*React*"

# Check for Hermes
find . -name "hermes"
find . -name "libhermes.dylib" -o -name "libhermes.a"

# Check for React Native version file
find . -name "RNVersion.h"

# Check for package.json in bundle
find . -name "package.json"
```

#### Binary Analysis

```bash
# Check for React symbols
otool -tV MyApp | grep -i react

# Search for React Native strings
strings MyApp | grep -i reactnative

# Check for Hermes
strings MyApp | grep -i hermes

# Check for React Native bridges
otool -oV MyApp | grep -i "RCTBridge"
```

#### Code Indicators

```swift
// React Native bridge initialization
// Objective-C code in binary
- (RCTBridge *)createBridgeWithDelegate:(id<RCTBridgeDelegate>)delegate
                     launchOptions:(NSDictionary *)launchOptions {
  RCTBridge *bridge = [[RCTBridge alloc] initWithDelegate:delegate
                                              launchOptions:launchOptions];
  return bridge;
}
```

### Flutter Detection

#### File-Based Detection

```bash
# Check for Flutter.framework
find . -path "*/Frameworks/Flutter.framework"

# Check for flutter_assets directory
find . -type d -name "flutter_assets"

# Check for kernel_blob.bin
find . -name "kernel_blob.bin"

# Check for app.flx
find . -name "app.flx"

# Check for FlutterVersion.h
find . -name "FlutterVersion.h"
```

#### Binary Analysis

```bash
# Check for Flutter symbols
otool -L MyApp | grep Flutter

# Check for Flutter engine
strings MyApp | grep -i "flutter.*engine"

# Check for Dart VM
strings MyApp | grep -i "dart.*vm"

# Check for Flutter runtime
otool -oV MyApp | grep "FlutterEngine"
```

### Cordova/Ionic Detection

#### File-Based Detection

```bash
# Check for cordova.js
find . -name "cordova.js"

# Check for cordova_plugins.js
find . -name "cordova_plugins.js"

# Check for config.xml
find . -name "config.xml"

# Check for CDVWebViewEngine
find . -name "*WebViewEngine*"
```

#### Binary Analysis

```bash
# Check for Cordova symbols
strings MyApp | grep -i cordova

# Check for WebView plugins
strings MyApp | grep -i "CDVPlugin"

# Check for plugin loading
otool -oV MyApp | grep -i "loadCordovaPlugin"
```

### Xamarin Detection

#### File-Based Detection

```bash
# Check for Xamarin runtime
find . -name "libmonotouch.dylib" -o -name "libxamarin.dylib"

# Check for .dll files
find . -name "*.dll"

# Check for Mono VM
find . -path "*/Mono/*"

# Check for Xamarin assemblies
find . -name "Xamarin.*.dll"
```

#### Binary Analysis

```bash
# Check for Mono symbols
strings MyApp | grep -i mono

# Check for Xamarin runtime
otool -L MyApp | grep -i xamarin

# Check for .NET metadata
strings MyApp | grep -i "mscorlib"
```

### Unity Detection

#### File-Based Detection

```bash
# Check for UnityFramework
find . -path "*/Frameworks/UnityFramework.framework"

# Check for Data directory
find . -path "*/Data/*"

# Check for UnityEngine.dll
find . -name "UnityEngine.dll"

# Check for il2cpp
find . -name "libil2cpp.dylib" -o -name "GameAssembly.dylib"
```

#### Binary Analysis

```bash
# Check for Unity symbols
strings MyApp | grep -i unity

# Check for Unity Engine
otool -L MyApp | grep -i "UnityEngine"

# Check for IL2CPP
strings MyApp | grep -i il2cpp
```

### Swift Detection

#### Mach-O Section Analysis

```bash
# Check for Swift sections
otool -l MyApp | grep __swift5_types
otool -l MyApp | grep __swift5_protos
otool -l MyApp | grep __swift5_reflstr

# Check Swift version
otool -l MyApp | grep __swift5_capture

# List all Swift sections
otool -l MyApp | grep "sect name __TEXT" | grep swift
```

#### Binary Analysis

```bash
# Check for Swift runtime
otool -L MyApp | grep -i swift

# Check for Swift stdlib
otool -L MyApp | grep -i "libswift"

# Check for Swift metadata
otool -ov MyApp | grep -i "Swift.*Metadata"
```

### Objective-C Detection

#### Mach-O Section Analysis

```bash
# Check for Objective-C sections
otool -l MyApp | grep __objc_classlist
otool -l MyApp | grep __objc_protolist
otool -l MyApp | grep __objc_imageinfo

# Check for Objective-C protocols
otool -l MyApp | grep __objc_protorefs
```

#### Binary Analysis

```bash
# Get all Objective-C classes
otool -oV MyApp | grep "^_OBJC_CLASS"

# Get all protocols
otool -oV MyApp | grep "_OBJC_PROTOCOL"

# Get all categories
otool -oV MyApp | grep "_OBJC_CATEGORY"

# Check Foundation linkage
otool -L MyApp | grep Foundation
```

## Detection Commands

### React Native

```bash
# Find React Native bundle
find . -name "main.jsbundle"

# Search for React Native code
otool -tV MyApp | grep -i "ReactNativeBridge"

# Check for Hermes engine
strings MyApp | grep -i "Hermes.*Runtime"

# List React Native frameworks
ls -la Payload/MyApp.app/Frameworks/ | grep -i react
```

### Flutter

```bash
# Find Flutter framework
otool -L MyApp | grep Flutter

# Check for Dart AOT
find . -name "kernel_blob.bin"

# List Flutter assets
find ./Payload/MyApp.app/flutter_assets -type f

# Check Flutter version
strings MyApp | grep "Flutter.*Engine"
```

### Cordova/Ionic

```bash
# Find Cordova files
find . -name "cordova.js" -o -name "cordova_plugins.js"

# Check config.xml
plutil -p config.xml | grep -i cordova

# List plugins
cat cordova_plugins.js | grep "pluginId"
```

### Xamarin

```bash
# Find Xamarin runtime
otool -L MyApp | grep -i xamarin

# Check for .dll files
find . -name "*.dll"

# List Mono assemblies
ls -la Payload/MyApp.app/Managed/ | head -20
```

### Unity

```bash
# Find Unity framework
otool -L MyApp | grep -i unity

# Check Unity data directory
ls -la Payload/MyApp.app/Data/

# Check IL2CPP
strings MyApp | grep -i il2cpp
```

### Swift

```bash
# Check Swift sections
otool -l MyApp | grep __swift5_types

# List Swift libraries
otool -L MyApp | grep libswift

# Check Swift version
strings MyApp | grep -i "Swift.*version"
```

### Objective-C

```bash
# Get all classes
otool -oV MyApp | grep "^_OBJC_CLASS" | wc -l

# Get class methods
otool -oV MyApp | grep "_OBJC_CLASS_\$_"

# Check Foundation
otool -L MyApp | grep Foundation
```

## Framework-Specific Security Issues

### React Native

#### Bridge Vulnerabilities

```objc
// Vulnerable: Exposed native module (Objective-C)
@interface ExposedModule : NSObject <RCTBridgeModule>
@end

@implementation ExposedModule
RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(executeCommand:(NSString *)command) {
    // Direct execution without validation
    system([command UTF8String]); // ❌ Shell injection on iOS
}
@end

// Attack: JavaScript can call arbitrary exposed methods
// Note: system() is restricted in App Store binaries; iOS apps
// cannot spawn processes, so focus shifts to:
// - File I/O abuse
// - Native API abuse (keychain, network, etc.)
// - WKWebView evaluateJavaScript
```

#### NativeModule Exposure

```javascript
// Vulnerable: Exposed sensitive API
const NativeModule = NativeModules.SecureModule;

// Can access from JavaScript anywhere
NativeModule.getPassword();
NativeModule.getAuthToken();

// Risk: Any JavaScript code can access
```

#### Remediation

```objc
// ✅ Secure: Validate all inputs (Objective-C)
@interface SecureModule : NSObject <RCTBridgeModule>
@end

@implementation SecureModule
RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(executeCommand:(NSString *)command) {
    NSArray *allowedCommands = @[@"status", @"version"];
    if (![allowedCommands containsObject:command]) {
        // Reject unknown commands
        return;
    }
    // Execute only allowed command
}
@end

// ✅ Secure: Use bridge only for necessary operations
// Minimize native module surface
// Validate all inputs
// Implement authentication checks
// See: react-native-ios-security.md for full coverage
```

### Flutter

#### MethodChannel Risks

```dart
// Vulnerable: Exposed method channel
const platform = MethodChannel('com.example.app/secure');

// Call sensitive method from anywhere
platform.invokeMethod('getPassword');

// Attack: Malicious plugin or code can access
```

#### Dart Code Injection

```dart
// Vulnerable: Dynamic code evaluation
final code = userSuppliedCode; // From deep link
eval(code); // DANGEROUS!

// Attack: myapp://execute?code=import'dart:io';
```

#### Remediation

```dart
// ✅ Secure: Validate method calls
class SecureHandler {
  static const _channel = MethodChannel('com.example.app/secure');
  static final _allowedMethods = {'init', 'update'};
  
  static void handleMethod(MethodCall call, Result result) {
    if (!_allowedMethods.contains(call.method)) {
      result.error('INVALID_METHOD', 'Method not allowed', null);
      return;
    }
    // Handle method
  }
}

// ✅ Secure: Avoid eval()
// Use only allowed method channels
// Validate all parameters
// Implement authentication
```

### Cordova/Ionic

#### Plugin Permissions

```xml
<!-- Vulnerable: Excessive permissions -->
<plugin name="cordova-plugin-contacts" />
<plugin name="cordova-plugin-camera" />
<plugin name="cordova-plugin-geolocation" />

<!-- Many apps request more permissions than needed -->
```

#### JavaScript Bridge

```javascript
// Vulnerable: Exposed native APIs
cordova.exec(success, error, "SecurePlugin", "getPassword", []);

// Accessible from any loaded JavaScript
// Including injected JavaScript from deep links
```

#### Remediation

```xml
<!-- ✅ Secure: Minimal permissions -->
<!-- Only request what's absolutely needed -->

<!-- ✅ Secure: Whitelist allowed URLs -->
<allow-navigation href="https://trusted.com/*" />
```

### Xamarin

#### Reflection Usage

```csharp
// Vulnerable: Unrestricted reflection
var type = Type.GetType(userSuppliedType);
var method = type.GetMethod(userSuppliedMethod);
method.Invoke(null, null);

// Attack: Can call any method
```

#### Serialization Risks

```csharp
// Vulnerable: Insecure deserialization
var data = Deserialize(userInput);
// Can execute arbitrary code
```

#### Remediation

```csharp
// ✅ Secure: Restrict reflection
private static readonly Type[] ALLOWED_TYPES = {
    typeof(string),
    typeof(int)
};

// ✅ Secure: Safe deserialization
// Use known, safe types
// Validate all inputs
```

### Unity

#### PlayerPrefs Risks

```csharp
// Vulnerable: Plaintext storage
PlayerPrefs.SetString("password", userPassword);
// Stored in plaintext plist file
```

#### Dll Injection

```csharp
// Vulnerable: Load external DLLs
Assembly.Load(userSuppliedDllPath);
// Can execute arbitrary code
```

#### Remediation

```csharp
// ✅ Secure: Use Keychain equivalent
// For iOS: Use KeychainItem
// Encrypt sensitive data

// ✅ Secure: Don't load external DLLs
// Bundle all required code
// Validate all inputs
```

### Swift

#### Type Confusion

```swift
// Vulnerable: Unsafe type casting
let obj: Any = userSuppliedValue
let sensitive = obj as! SecureData  // Crash if wrong type

// Better: Optional binding
if let secure = obj as? SecureData {
    // Use safely
}
```

#### Memory Safety

```swift
// Vulnerable: Unsafe pointer usage
let ptr = UnsafeMutablePointer<Int>.allocate(capacity: 10)
ptr[100] = 42  // Out of bounds!

// Secure: Bounds checking
guard index >= 0 && index < capacity else { return }
ptr[index] = 42
```

#### Remediation

```swift
// ✅ Secure: Use Swift type safety
guard let value = obj as? ExpectedType else { return }

// ✅ Secure: Avoid force unwrapping
// Always use optional binding

// ✅ Secure: Minimize unsafe code
// Use Swift's safe abstractions
```

### Objective-C

#### Message Forwarding

```objc
// Vulnerable: Uncontrolled message forwarding
- (NSMethodSignature *)methodSignatureForSelector:(SEL)sel {
    return [super methodSignatureForSelector:sel];
}

// Attack: Can send arbitrary messages
```

#### KVO Abuse

```objc
// Vulnerable: Observable sensitive properties
@property (nonatomic, strong) NSString *password;

// Attack: Can observe changes
```

#### Remediation

```objc
// ✅ Secure: Control message forwarding
- (id)forwardingTargetForSelector:(SEL)sel {
    if ([self respondsToSelector:sel]) {
        return self;
    }
    return nil;  // Don't forward arbitrary messages
}

// ✅ Secure: Don't expose sensitive properties
// Use internal properties with proper access control
```

## Frida Hooks per Framework

### React Native

```javascript
// Hook React Native bridge
if (ObjC.classes.RCTBridge) {
    var bridge = ObjC.classes.RCTBridge;
    
    // Hook enqueueJSCall
    Interceptor.attach(bridge["- enqueueJSCall:"].implementation, {
        onEnter: function(args) {
            console.log("[RCTBridge] enqueueJSCall:");
            console.log("  Call:", ObjC.Object(args[2]).toString());
        }
    });
    
    // Hook executeJSCall
    Interceptor.attach(bridge["- executeJSCall:"].implementation, {
        onEnter: function(args) {
            console.log("[RCTBridge] executeJSCall:");
            console.log("  Method:", ObjC.Object(args[2]).toString());
        }
    });
}

// Trace all React Native modules
function traceReactNativeModules() {
    if (!ObjC.classes.RCTBridge) return;
    
    var modules = ObjC.classes.RCTBridge.currentBridge().modules.allKeys();
    console.log("React Native Modules:", modules);
    
    modules.forEach(function(moduleName) {
        var moduleClass = ObjC.classes[moduleName];
        if (!moduleClass) return;
        
        console.log("  Module:", moduleName);
        var methods = moduleClass.$methods;
        methods.forEach(function(method) {
            if (method.startsWith(" ") && !method.includes(":")) {
                console.log("    Method:", method.trim());
            }
        });
    });
}
```

### Flutter

```javascript
// Hook Flutter engine
var FlutterEngine = ObjC.classes.FlutterEngine;
if (FlutterEngine) {
    Interceptor.attach(FlutterEngine["- initWithName:project:allowHeadlessExecution:"].implementation, {
        onEnter: function(args) {
            console.log("[FlutterEngine] init");
            console.log("  Name:", ObjC.Object(args[2]).toString());
        }
    });
}

// Hook method channel calls
function traceFlutterMethodChannels() {
    var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
    if (!FlutterMethodChannel) return;
    
    Interceptor.attach(FlutterMethodChannel["- setMethodCallHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[FlutterMethodChannel] setMethodCallHandler");
            var handler = new ObjC.Object(args[2]);
            console.log("  Handler:", handler.className);
        }
    });
}

// Hook Flutter plugin registry
var FlutterPluginRegistry = ObjC.classes.FlutterPluginRegistry;
if (FlutterPluginRegistry) {
    Interceptor.attach(FlutterPluginRegistry["- registerPlugin:withRegistrar:"].implementation, {
        onEnter: function(args) {
            console.log("[FlutterPluginRegistry] registerPlugin");
            console.log("  Plugin:", ObjC.Object(args[2]).toString());
        }
    });
}
```

### Cordova

```javascript
// Hook CDVCommandDelegate
var CDVCommandDelegate = ObjC.classes.CDVCommandDelegate;
if (CDVCommandDelegate) {
    Interceptor.attach(CDVCommandDelegate["- evalJs:completion:"].implementation, {
        onEnter: function(args) {
            console.log("[CDVCommandDelegate] evalJs");
            console.log("  JS:", ObjC.Object(args[2]).toString());
        }
    });
}

// Trace Cordova plugins
function traceCordovaPlugins() {
    var CDVPlugin = ObjC.classes.CDVPlugin;
    if (!CDVPlugin) return;
    
    console.log("Cordova Plugins:");
    var plugins = ObjC.classes.CDVPluginManager.availablePlugins();
    if (plugins) {
        for (var i = 0; i < plugins.count(); i++) {
            var plugin = plugins.objectAtIndex_(i);
            console.log("  Plugin:", plugin.toString());
        }
    }
}
```

### Xamarin

```javascript
// Hook Mono runtime
var Mono = Module.findBaseAddress("libmonotouch.dylib");
if (Mono) {
    console.log("Mono runtime loaded at:", Mono);
    
    // Find mono_jit_exec function
    var monoMod = Process.findModuleByName("libmonotouch.dylib");
    var mono_jit_exec = monoMod ? monoMod.findExportByName("mono_jit_exec") : null;
    if (mono_jit_exec) {
        Interceptor.attach(mono_jit_exec, {
            onEnter: function(args) {
                console.log("[Mono] JIT exec");
            }
        });
    }
}

// Trace .NET assemblies
function traceXamarinAssemblies() {
    var Assembly = ObjC.classes.Assembly;
    if (!Assembly) return;
    
    // Hook GetExecutingAssembly
    Interceptor.attach(Assembly["+ GetExecutingAssembly"].implementation, {
        onLeave: function(retval) {
            console.log("[Assembly] GetExecutingAssembly");
            console.log("  Assembly:", new ObjC.Object(retval).toString());
        }
    });
}
```

### Unity

```javascript
// Hook Unity engine
var UnityFramework = Module.findBaseAddress("UnityFramework");
if (UnityFramework) {
    console.log("UnityFramework loaded at:", UnityFramework);
}

// Trace PlayerPrefs
function tracePlayerPrefs() {
    var PlayerPrefs = ObjC.classes.PlayerPrefs;
    if (!PlayerPrefs) return;
    
    // Hook GetString
    Interceptor.attach(PlayerPrefs["+ GetString:default:"].implementation, {
        onEnter: function(args) {
            console.log("[PlayerPrefs] GetString");
            console.log("  Key:", ObjC.Object(args[2]).toString());
        }
    });
    
    // Hook SetString
    Interceptor.attach(PlayerPrefs["+ SetString:forKey:"].implementation, {
        onEnter: function(args) {
            console.log("[PlayerPrefs] SetString");
            console.log("  Key:", ObjC.Object(args[3]).toString());
            console.log("  Value:", ObjC.Object(args[2]).toString());
        }
    });
}
```

### Swift

```javascript
// Hook Swift runtime
var SwiftMetadata = Module.findGlobalExportByName("$s10Foundation8NSObjectCSo6CMdmc");
if (SwiftMetadata) {
    console.log("Swift metadata found");
}

// Trace Swift classes
function traceSwiftClasses() {
    var count = 0;
    for (var className in ObjC.classes) {
        if (className.startsWith("_TtC")) {
            // Swift class names start with _TtC
            count++;
        }
    }
    console.log("Swift classes:", count);
}
```

### Objective-C

```javascript
// Hook all Objective-C class initializers
function traceObjCClassCreation() {
    for (var className in ObjC.classes) {
        var clazz = ObjC.classes[className];
        try {
            var initMethods = [
                "- init",
                "- initWithCoder:",
                "- initWithFrame:"
            ];
            
            initMethods.forEach(function(method) {
                if (clazz[method]) {
                    Interceptor.attach(clazz[method].implementation, {
                        onEnter: function(args) {
                            console.log("[ObjC] " + className + " " + method);
                        }
                    });
                }
            });
        } catch(e) {}
    }
}
```

## OWASP MASTG References

- **MASTG-APP-ARCH-002: Framework Analysis**
  - Framework identification
  - Technology stack assessment

- **MASTG-APP-ANALYSIS-002: Framework Security**
  - Framework-specific vulnerabilities
  - Native bridge security

- **MASTG-APP-CODE-001: Code Review**
  - Binary analysis
  - Runtime inspection
