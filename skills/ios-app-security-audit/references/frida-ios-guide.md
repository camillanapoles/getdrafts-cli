# Frida Guide for iOS Security Testing

## Table of Contents

1. [Overview](#overview)
2. [Frida Fundamentals](#frida-fundamentals)
3. [Frida 17 Migration Guide](#frida-17-migration-guide)
4. [Objective-C Runtime Access](#objective-c-runtime-access)
5. [Hooking Objective-C Methods](#hooking-objective-c-methods)
6. [Swift Method Hooking](#swift-method-hooking)
7. [Reading and Modifying Properties](#reading-and-modifying-properties)
8. [Working with Objective-C Data Types](#working-with-objective-c-data-types)
9. [Native Code Hooking](#native-code-hooking)
10. [Memory Manipulation](#memory-manipulation)
11. [iOS-Specific Features](#ios-specific-features)
12. [Spawn vs Attach](#spawn-vs-attach)
13. [Practical Examples](#practical-examples)
14. [Advanced Techniques](#advanced-techniques)
15. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

Frida provides powerful runtime manipulation capabilities for iOS applications through dynamic instrumentation. This guide covers Frida fundamentals, Objective-C runtime access, hooking techniques, memory manipulation, and iOS-specific features for comprehensive security testing.

### Why Frida for iOS Security?

- **Dynamic analysis**: Inspect and modify app behavior at runtime
- **Runtime hooking**: Intercept and alter method implementations
- **Memory inspection**: Access and modify application memory
- **Network monitoring**: Intercept API calls and data transmission
- **Bypass protections**: SSL pinning, root detection, debugger detection
- **Automated testing**: Scriptable for comprehensive coverage

---

## Frida Fundamentals

### Basic Frida Commands

> **Frida 17+ spawn behavior**: Apps resume automatically on spawn (no flag needed). The old `--no-pause` flag is **removed** in Frida 17. Use `--pause` to pause the app at spawn instead. Omit both flags for the default (resume) behavior.

```bash
# List processes on connected device
frida-ps -U

# List installed + running apps with bundle IDs (confirms jailbreak + frida-server)
frida-ps -Uai

# Attach to running process
frida -U "Safari"

# Spawn new process (from bundle ID, Frida 17+)
frida -U -f com.apple.mobilesafari

# Spawn and pause (was --no-pause in Frida 16.x; replaced by --pause in 17+)
frida -U -f com.apple.mobilesafari --pause

# Load script from file
frida -U -l script.js -f com.apple.mobilesafari

# Create REPL (Read-Eval-Print Loop)
frida -U -f com.example.app

# Exit REPL
%exit
```

> **Device vs simulator**: `-U` targets the USB-attached physical device (jailbroken, with frida-server running). For the iOS Simulator, use `-D <SIMULATOR_UDID>` instead — see [frida-ios-simulator-workflow.md](frida-ios-simulator-workflow.md) for the simulator-specific syntax, `.implementation` pattern, and known limitations.

### Frida REPL Commands

```javascript
// Inside Frida REPL

// Evaluate JavaScript expression
ObjC.available
// Returns: true

// List Objective-C classes
Object.keys(ObjC.classes).slice(0, 10)

// Get specific class
var NSURL = ObjC.classes.NSURL

// Get method names
NSURL.$ownMethods

// List all methods in class
ObjC.classes.NSURL.$ownMethods.join('\n')
```

### Basic Script Structure

```javascript
// script.js - Basic Frida script structure

// Wait for ObjC runtime to be loaded
setTimeout(function() {
    if (ObjC.available) {
        console.log("Objective-C runtime available");

        // Your code here
        var NSString = ObjC.classes.NSString;
        console.log("NSString class:", NSString);

    } else {
        console.log("Objective-C runtime not available");
    }
}, 100);
```

---

## Frida 17 Migration Guide

> **Important**: If you are migrating scripts from Frida 16.x to 17.x, this section covers the key API changes that require code updates.

### Overview of Breaking Changes

Frida 17 introduced several API changes that improve consistency and performance. The most significant changes affect:

1. **Memory access APIs** - now pointer-based
2. **Module/Process APIs** - consolidated and streamlined
3. **Enumeration APIs** - now return arrays directly instead of callbacks

### Memory Access API Changes

#### OLD (Frida 16.x)

```javascript
// ❌ Deprecated - Do not use in Frida 17+
var value = Memory.readU32(ptr('0x12345678'));
var value = Memory.readU8(ptr('0x12345678'));
var str = Memory.readUtf8String(ptr('0x12345678'));
```

#### NEW (Frida 17+)

```javascript
// ✅ Correct - Pointer-based read methods
var value = ptr('0x12345678').readU32();
var value = ptr('0x12345678').readU8();
var str = ptr('0x12345678').readUtf8String();

// For variables already a pointer
var address = ptr(0x12345678);
var value = address.readU32();
```

**Why**: The new pattern is more consistent with JavaScript object-oriented design and reduces API surface.

### Module/Process API Changes

#### Module.getExportByName() Changes

#### OLD (Frida 16.x)

```javascript
// ❌ Deprecated global helper
var openPtr = Module.getExportByName(null, "open");
var CC_MD5 = Module.getExportByName("CommonCrypto", "CC_MD5");
```

#### NEW (Frida 17+)

```javascript
// ✅ Correct - module access lives on the Process object
var mainModule = Process.enumerateModules()[0];
var openPtr = mainModule.getExportByName("open");

// For a specific module, prefer findModuleByName(): it returns null instead
// of throwing when the module is not loaded.
var cryptoModule = Process.findModuleByName("libcommonCrypto.dylib");
var CC_MD5 = cryptoModule ? cryptoModule.getExportByName("CC_MD5") : null;

// Global lookup - searches every loaded module
var openPtr = Module.findGlobalExportByName("open");
```

**Why**: Consolidates module access under Process object for better organization.

### Export Resolution (Frida 17)

The static two-argument `findExportByName(module, symbol)` form on the `Module` object was **removed in Frida 17** — calling it now throws a `TypeError` because the method no longer exists. Use the global or module-scoped APIs instead:

```javascript
// Global lookup - searches every loaded module (null if absent)
var openPtr = Module.findGlobalExportByName("open");

// Module-scoped lookup
var secMod = Process.findModuleByName("Security");
var SecTrustEvaluate = secMod ? secMod.findExportByName("SecTrustEvaluate") : null;
```

`Process.getModuleByName(name)` **throws** when the module is not loaded; `Process.findModuleByName(name)` returns `null` instead, so prefer the `find` variant in scripts that must not abort. `Module.getGlobalExportByName(name)` is the throwing counterpart of `Module.findGlobalExportByName(name)`.

### The ObjC Bridge and the Host

> **Official note (Frida 17)**: "As of Frida 17, this runtime bridge is no longer baked into Frida's GumJS runtime, and can be fetched by running: `npm install frida-objc-bridge`. Import it into your agent like this: `import ObjC from 'frida-objc-bridge';` For now this is not needed in scripts loaded by the Frida REPL, as well as frida-trace."

The `ObjC` global is **not part of the Frida core**: it is a bridge that the *host* provides to the script. The `frida` CLI ships it (`frida-tools/bridges/objc.js`) and injects it automatically, so `ObjC.classes`, `ObjC.selector(...)` and `ObjC.available` work out of the box when you run:

```bash
frida -U -f com.example.app -l assets/frida-scripts/ssl-pinning-bypass-ios.js
```

The bridge is also injected when FridaGadget runs in `"listen"` mode and the CLI connects to it, and by `frida-trace`.

**It is not provided** when FridaGadget runs in `"type": "script"` mode, or with any other custom host. In that case the script fails immediately with `ReferenceError: ObjC is not defined` — the failure looks like a broken script but is really a missing bridge.

If you must run a bundled script through a script-mode host, either:

- keep the Gadget in `"listen"` mode and drive it with the CLI (what this skill's documented flow does), or
- build the agent with the official bridge: `npm install frida-objc-bridge` and `import ObjC from 'frida-objc-bridge';`

The 69 bundled scripts that use `ObjC` were verified to load under a simulated Frida API (`scripts/frida_harness.js`); the CI runs that harness on every push, so a script that would abort on load cannot reach the repository unnoticed.

### Enumeration API Changes

#### Process.enumerateModules() Changes

#### OLD (Frida 16.x)

```javascript
// ❌ Deprecated - Callback-based
Process.enumerateModules({
    onMatch: function(module) {
        console.log("Module:", module.name);
    },
    onComplete: function() {
        console.log("Done");
    }
});
```

#### NEW (Frida 17+)

```javascript
// ✅ Correct - Returns array directly
for (const module of Process.enumerateModules()) {
    console.log("Module:", module.name);
}

// Or with array methods
Process.enumerateModules().forEach(function(module) {
    console.log("Module:", module.name);
});

// Filter and map
const interesting = Process.enumerateModules().filter(function(m) {
    return m.name.includes("Crypto");
});
```

**Why**: Modern JavaScript prefers direct array returns over callbacks for better composition.

### Module.enumerateImports/Exports Changes

Similar pattern applies to imports/exports enumeration:

```javascript
// ✅ Frida 17+ - Returns array
const imports = module.enumerateImportsSync();
imports.forEach(function(imp) {
    console.log("Import:", imp.name, "from", imp.module);
});

// For async version (still callback-based)
module.enumerateImports({
    onMatch: function(imp) {
        console.log("Import:", imp.name);
    },
    onComplete: function() {
        console.log("Done");
    }
});
```

### Migration Checklist

Use this checklist when updating scripts from Frida 16.x to 17+:

- [ ] Replace `Memory.read*()` with `ptr().read*()`
- [ ] Replace `Memory.write*()` with `ptr().write*()`
- [ ] Update `Module.getExportByName()` to use module object
- [ ] Replace the static two-argument `findExportByName(module, symbol)` form with `Module.findGlobalExportByName(symbol)` or `module.findExportByName(symbol)`
- [ ] Convert `Process.enumerateModules()` callbacks to array iteration
- [ ] Update enumeration APIs to use direct array returns where applicable

### Example: Before and After

#### Before (Frida 16.x)

```javascript
// Old pattern
Process.enumerateModules({
    onMatch: function(module) {
        if (module.name === "CommonCrypto") {
            var func = Module.getExportByName("CommonCrypto", "CC_MD5");
            Interceptor.attach(func, {
                onEnter: function(args) {
                    var data = Memory.readByteArray(args[0], 32);
                    console.log("CC_MD5 input:", hexdump(data));
                }
            });
        }
    },
    onComplete: function() {}
});
```

#### After (Frida 17+)

```javascript
// New pattern
const modules = Process.enumerateModules();
const cryptoModule = modules.find(function(m) {
    return m.name === "CommonCrypto";
});

if (cryptoModule) {
    const CC_MD5 = cryptoModule.getExportByName("CC_MD5");
    Interceptor.attach(CC_MD5, {
        onEnter: function(args) {
            const data = args[0].readByteArray(32);
            console.log("CC_MD5 input:", hexdump(data));
        }
    });
}
```

### Compatibility Notes

- **Frida 16.x scripts** may work in Frida 17+ with deprecation warnings, but removed APIs (such as the static `findExportByName` form) throw a `TypeError` instead of warning
- **Frida 17+ scripts** will NOT work in Frida 16.x
- **Recommended**: Update all scripts to Frida 17+ APIs for future compatibility

---

## Objective-C Runtime Access

### Accessing Classes

```javascript
// Method 1: Direct class access
var NSString = ObjC.classes.NSString;
console.log("NSString:", NSString);

// Method 2: Dynamic class lookup
var className = "NSString";
var TheClass = ObjC.classes[className];
console.log("Dynamically found:", TheClass);

// Method 3: Check if class exists
if (ObjC.classes.MyCustomClass) {
    console.log("Custom class found!");
}

// List all classes
var allClasses = Object.keys(ObjC.classes);
console.log("Total classes:", allClasses.length);
console.log("First 10 classes:", allClasses.slice(0, 10));

// Filter classes by name prefix
var uikitClasses = Object.keys(ObjC.classes).filter(function(name) {
    return name.startsWith("UI");
});
console.log("UIKit classes:", uikitClasses.length);
```

### Accessing Methods

```javascript
// Get class
var NSURLSession = ObjC.classes.NSURLSession;

// Get all methods (including inherited)
var allMethods = NSURLSession.$methods;
console.log("All methods:", allMethods.slice(0, 5));

// Get own methods (defined in this class only)
var ownMethods = NSURLSession.$ownMethods;
console.log("Own methods:", ownMethods.slice(0, 5));

// Get method implementation
var methodImplementation = NSURLSession["- dataTaskWithURL:completionHandler:"];
console.log("Method implementation:", methodImplementation);

// List methods in readable format
console.log(NSURLSession.$ownMethods.join('\n'));
```

### Finding Classes by Pattern

```javascript
// Helper function to find classes matching pattern
function findClasses(pattern) {
    var regex = new RegExp(pattern, "i");
    return Object.keys(ObjC.classes).filter(function(name) {
        return regex.test(name);
    });
}

// Find all URL-related classes
var urlClasses = findClasses("URL");
console.log("URL classes:", urlClasses.slice(0, 10));

// Find all manager classes
var managers = findClasses("Manager");
console.log("Managers:", managers.slice(0, 10));

// Find all crypto-related classes
var crypto = findClasses("Crypt|Encrypt|Hash|Key");
console.log("Crypto classes:", crypto.slice(0, 10));
```

---

## Hooking Objective-C Methods

### Basic Method Hooking

```javascript
// Hook a simple method
var NSString = ObjC.classes.NSString;
var oldImpl = NSString["- length"];

Interceptor.attach(oldImpl, {
    onEnter: function(args) {
        console.log("NSString:length called");
    },
    onLeave: function(retval) {
        console.log("String length:", retval);
    }
});
```

### Accessing Method Arguments

```javascript
// Hook method with arguments
var NSURLSession = ObjC.classes.NSURLSession;
var dataTaskMethod = NSURLSession["- dataTaskWithURL:completionHandler:"];

Interceptor.attach(dataTaskMethod, {
    onEnter: function(args) {
        // args[0]: self
        // args[1]: _cmd (selector)
        // args[2]: first argument (URL)
        // args[3]: second argument (completion handler)

        var self = ObjC.Object(args[0]);
        var url = ObjC.Object(args[2]);

        console.log("self:", self);
        console.log("URL:", url);
        console.log("URL string:", url.absoluteURL().toString());
    },
    onLeave: function(retval) {
        var task = ObjC.Object(retval);
        console.log("Returned task:", task);
    }
});
```

### Modifying Return Values

```javascript
// Hook and modify return value
var NSBundle = ObjC.classes.NSBundle;
var mainBundle = NSBundle["- mainBundle"];

Interceptor.attach(mainBundle, {
    onLeave: function(retval) {
        var bundle = ObjC.Object(retval);

        // Log bundle info
        console.log("Bundle ID:", bundle.bundleIdentifier());
        console.log("Bundle path:", bundle.bundlePath());

        // Optionally modify return value
        // retval.replace(ptr(0x12345678));  // Replace with different pointer
    }
});
```

### Hooking Class Methods (+)

```javascript
// Hook class method (starts with +)
var NSFileManager = ObjC.classes.NSFileManager;
var defaultManager = NSFileManager["+ defaultManager"];

Interceptor.attach(defaultManager, {
    onEnter: function(args) {
        console.log("[NSFileManager defaultManager] called");
    },
    onLeave: function(retval) {
        var manager = ObjC.Object(retval);
        console.log("Default manager:", manager);
    }
});
```

---

## Swift Method Hooking

### Understanding Swift Method Names

```javascript
// Swift method names are mangled
// Format: _TtC{Module Length}{Module Name}{Class Length}{Class Name}{Method}

// Example:
// _TtC12MyApp6MyClassC8myMethodySS_F  // MyApp.MyClass.myMethod(_:)
// _TtC12MyApp6MyClassC8myMethodySSF    // MyApp.MyClass.myMethod()

// Hooking Swift methods
var SwiftClass = ObjC.classes.MyApp_MyClass;

// Find Swift methods
console.log("Swift methods:", SwiftClass.$ownMethods.filter(function(m) {
    return m.startsWith("_TtC") || m.startsWith("$__");
}));
```

### Hooking Swift Instance Methods

```javascript
// Hook Swift instance method
// Original Swift: func myMethod(text: String) -> String

var SwiftClass = ObjC.classes.MyApp_MyClass;

// Find the mangled method name
var swiftMethods = SwiftClass.$ownMethods;
console.log("Methods:", swiftMethods);

// Hook the method (example mangled name)
var mangledName = "$__myMethod_text___";  // Actual name will differ

Interceptor.attach(SwiftClass[mangledName], {
    onEnter: function(args) {
        var self = ObjC.Object(args[0]);

        // Swift arguments are passed differently
        // You may need to inspect the actual arguments

        console.log("Swift myMethod called");
        console.log("self:", self);
    },
    onLeave: function(retval) {
        console.log("Return value:", retval);
    }
});
```

### Using SwiftDemangle

```javascript
// Helper to demangle Swift method names
function demangleSwift(name) {
    // Simple demangling (may not cover all cases)
    if (name.startsWith("_TtC")) {
        return "Swift method: " + name;
    }
    return name;
}

// List and demangle all methods
var SwiftClass = ObjC.classes.MyApp_MyClass;
SwiftClass.$ownMethods.forEach(function(method) {
    console.log("Method:", method, "->", demangleSwift(method));
});
```

### Swift Property Access

```javascript
// Swift properties often have getter methods
// Format: property() or getProperty()

var SwiftClass = ObjC.classes.MyApp_MyClass;

// Find property getter methods
var propertyGetters = SwiftClass.$ownMethods.filter(function(method) {
    return method.includes("property") || method.includes("Property");
});

console.log("Property methods:", propertyGetters);

// Hook property getter
var propertyGetter = SwiftClass["- myProperty"];
if (propertyGetter) {
    Interceptor.attach(propertyGetter, {
        onLeave: function(retval) {
            console.log("Property value:", retval);
        }
    });
}
```

### Swift Symbol Search by Mangled Name

For Swift apps, methods are often exposed as mangled symbols. These can be hooked directly by symbol name:

```javascript
// Get the main module
const mainModule = Process.enumerateModules()[0];

// Search for Swift symbols by pattern
// Swift mangled names start with _$s
const swiftSymbols = mainModule.enumerateSymbols().filter(function(sym) {
    return sym.name.startsWith("_$s");
});

console.log("Found", swiftSymbols.length, "Swift symbols");

// Example: Hook a specific Swift method by mangled name
// Pattern: _$s{ModuleLength}{ModuleName}{ClassLength}{ClassName}{MethodSignature}
// Example: _$s9TargetApp14GameControllerC10checkCheatyyF
//         TargetApp.GameController.checkCheat()

const targetSymbol = mainModule.findSymbolByName("_$s9TargetApp14GameControllerC10checkCheatyyF");
if (targetSymbol) {
    console.log("Found target symbol:", targetSymbol.name);
    Interceptor.attach(targetSymbol, {
        onEnter: function(args) {
            console.log("[Swift] checkCheat called!");
        },
        onLeave: function(retval) {
            console.log("[Swift] Return value:", retval);
            // Bypass the check
            retval.replace(ptr(0));
        }
    });
}

// Search for specific patterns
function findSwiftSymbols(pattern) {
    const regex = new RegExp(pattern);
    return mainModule.enumerateSymbols().filter(function(sym) {
        return regex.test(sym.name);
    });
}

// Find all methods in a specific class
const gameControllerMethods = findSwiftSymbols("_$s.*GameController.*");
console.log("GameController methods:", gameControllerMethods.map(function(s) {
    return s.name;
}));
```

### Demangling Swift Symbols

Frida provides a built-in demangler for Swift symbols:

```javascript
// Use Frida's demangler
const symbolName = "_$s9TargetApp14GameControllerC10checkCheatyyF";
try {
    const demangled = DebugSymbol.fromAddress(ptr(symbolName)).name;
    console.log("Demangled:", demangled);
} catch (e) {
    console.log("Could not demangle:", symbolName);
}

// Manual demangling pattern reference:
// _$s - Swift symbol prefix
// 9TargetApp - Module name (9 = length)
// 14GameController - Class name (14 = length)
// C - Class marker
// 10checkCheat - Method name (10 = length)
// yyF - Signature (void return, no parameters)
```

### Swift Method Signature Patterns

Common Swift method signatures in mangled names:

| Pattern | Meaning |
|---------|---------|
| `yyF` | `() -> Void` - no parameters, void return |
| `ySdF` | `(Double) -> Void` - one Double parameter, void return |
| `ySS_F` | `(String) -> Void` - one String parameter, void return |
| `SbyF` | `() -> Bool` - no parameters, Bool return |
| `ySSSgF` | `(String?) -> Void` - optional String parameter |

Example breakdown:
```
_$s9TargetApp14GameController10validateUserySSSgF
│  │          │            │           │         └─> returns String?
│  │          │            │           └───────────> validateUser
│  │          │            └───────────────────────> GameController (no C because it's a method)
│  │          └────────────────────────────────────> TargetApp
│  └────────────────────────────────────────────────> Swift symbol prefix
└──────────────────────────────────────────────────> _$s (Swift prefix)
```

---

## Reading and Modifying Properties

### Reading Objective-C Properties

```javascript
// Get class
var Person = ObjC.classes.Person;

// Create instance (if init method exists)
var person = Person.alloc().init();

// Read property value
var name = person.name();
console.log("Name:", name);

// Alternative: Use valueForKey_
var name2 = person.valueForKey_("name");
console.log("Name (via valueForKey):", name2);
```

### Setting Property Values

```javascript
// Get class
var Person = ObjC.classes.Person;

// Create instance
var person = Person.alloc().init();

// Set property value
person.setName_("John Doe");

// Alternative: Use setValue_forKey_
person.setValue_forKey_("Jane Doe", "name");

// Verify
console.log("New name:", person.name());
```

### Hooking Property Access

```javascript
// Hook property getter
var Person = ObjC.classes.Person;
var nameGetter = Person["- name"];

Interceptor.attach(nameGetter, {
    onEnter: function(args) {
        console.log("Getting name property");
    },
    onLeave: function(retval) {
        var name = ObjC.Object(retval);
        console.log("Name value:", name.toString());
    }
});

// Hook property setter
var nameSetter = Person["- setName:"];

Interceptor.attach(nameSetter, {
    onEnter: function(args) {
        var self = ObjC.Object(args[0]);
        var name = ObjC.Object(args[2]);

        console.log("Setting name to:", name.toString());
    }
});
```

### Dynamic Property Inspection

```javascript
// Helper to list all properties of a class
function listProperties(className) {
    var theClass = ObjC.classes[className];
    if (!theClass) {
        console.log("Class not found:", className);
        return;
    }

    console.log("Properties for", className, ":");

    // Get all methods
    var methods = theClass.$ownMethods;

    // Filter for property-related methods
    var getters = methods.filter(function(m) {
        return m.startsWith("- ") && !m.includes(":");
    });

    getters.forEach(function(getter) {
        var propName = getter.substring(2);  // Remove "- "
        console.log("  -", propName);

        // Try to find setter
        var setter = "- set" +
                     propName.charAt(0).toUpperCase() +
                     propName.slice(1) + ":";
        if (methods.indexOf(setter) !== -1) {
            console.log("    Setter:", setter);
        }
    });
}

// Usage
listProperties("Person");
listProperties("NSBundle");
```

---

## Working with Objective-C Data Types

### NSString

```javascript
// Create NSString
var NSString = ObjC.classes.NSString;

var str1 = NSString.stringWithString_("Hello");
var str2 = "World";

var str3 = str1.stringByAppendingString_(str2);
console.log("Concatenated:", str3.toString());

// Hook NSString methods
Interceptor.attach(NSString["- length"], {
    onLeave: function(retval) {
        console.log("String length:", retval.toInt32());
    }
});

Interceptor.attach(NSString["- stringByAppendingString:"], {
    onEnter: function(args) {
        var self = ObjC.Object(args[0]);
        var other = ObjC.Object(args[2]);
        console.log("Appending:", self.toString(), " + ", other.toString());
    }
});
```

### NSArray

```javascript
// Create NSArray
var NSArray = ObjC.classes.NSArray;
var arr = NSArray.arrayWithObjects_("one", "two", "three", null);

console.log("Array:", arr);
console.log("Count:", arr.count());
console.log("First object:", arr.objectAtIndex_(0));

// Iterate array
for (var i = 0; i < arr.count(); i++) {
    console.log("Item", i, ":", arr.objectAtIndex_(i).toString());
}

// Hook NSArray
Interceptor.attach(NSArray["- objectAtIndex:"], {
    onEnter: function(args) {
        console.log("Accessing index:", args[2].toInt32());
    }
});
```

### NSDictionary

```javascript
// Create NSDictionary
var NSDictionary = ObjC.classes.NSDictionary;

var dict = NSDictionary.dictionaryWithObjects_forKeys_(
    "value1", "key1",
    "value2", "key2",
    null
);

console.log("Dictionary:", dict);
console.log("Value for key1:", dict.objectForKey_("key1"));

// Iterate dictionary
var keys = dict.allKeys();
for (var i = 0; i < keys.count(); i++) {
    var key = keys.objectAtIndex_(i);
    var value = dict.objectForKey_(key);
    console.log(key.toString(), ":", value.toString());
}

// Hook NSDictionary
Interceptor.attach(NSDictionary["- objectForKey:"], {
    onEnter: function(args) {
        var key = ObjC.Object(args[2]);
        console.log("Looking up key:", key.toString());
    }
});
```

### NSData

```javascript
// Create NSData
var NSData = ObjC.classes.NSData;
var NSString = ObjC.classes.NSString;

var str = NSString.stringWithString_("Hello, World!");
var data = str.dataUsingEncoding_(4);  // NSUTF8StringEncoding

console.log("Data:", data);
console.log("Length:", data.length());
console.log("Description:", data.description());

// Convert to hex
var bytes = data.bytes();
var length = data.length();
var hex = "";
for (var i = 0; i < length; i++) {
    var byte = bytes.add(i).readU8();
    hex += byte.toString(16).padStart(2, "0") + " ";
}
console.log("Hex:", hex);

// Hook NSData
Interceptor.attach(NSData["- length"], {
    onLeave: function(retval) {
        console.log("Data length:", retval.toInt32());
    }
});
```

### NSNumber

```javascript
// Create NSNumber
var NSNumber = ObjC.classes.NSNumber;

var num1 = NSNumber.numberWithInt_(42);
var num2 = NSNumber.numberWithFloat_(3.14);
var num3 = NSNumber.numberWithBool_(1);

console.log("Int:", num1.intValue());
console.log("Float:", num2.floatValue());
console.log("Bool:", num3.boolValue());
```

---

## Native Code Hooking

### Hooking Native Functions

```javascript
// Hook standard C function
var openPtr = Module.findGlobalExportByName("open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        console.log("Opening file:", path);
    },
    onLeave: function(retval) {
        console.log("File descriptor:", retval.toInt32());
    }
});

// Hook system function
var systemPtr = Module.findGlobalExportByName("system");
Interceptor.attach(systemPtr, {
    onEnter: function(args) {
        var command = args[0].readUtf8String();
        console.log("Executing command:", command);
    }
});
```

### Hooking Framework Functions

```javascript
// Hook Security framework functions
var secMod = Process.findModuleByName("Security");
var SecItemCopyMatchingPtr = secMod ? secMod.findExportByName("SecItemCopyMatching") : null;
Interceptor.attach(SecItemCopyMatchingPtr, {
    onEnter: function(args) {
        console.log("SecItemCopyMatching called");

        // Read query dictionary
        var query = ObjC.Object(args[0]);
        console.log("Query:", query);

        // Log query keys
        var keys = query.allKeys();
        for (var i = 0; i < keys.count(); i++) {
            console.log("  Key:", keys.objectAtIndex_(i));
        }
    },
    onLeave: function(retval) {
        console.log("Result:", retval);
    }
});
```

### Hooking Specific Module Functions

```javascript
// Get module by name
var moduleName = "CommonCrypto";
var module = Process.findModuleByName(moduleName);

if (module) {
    console.log("Module:", module.name);
    console.log("Base address:", module.base);
    console.log("Size:", module.size);

    // Enumerate exports
    module.enumerateExports().forEach(function(exp) {
        console.log("Export:", exp.name, exp.address);
    });

    // Hook CC_MD5
    var CC_MD5 = module ? module.findExportByName("CC_MD5") : null;
    if (CC_MD5) {
        Interceptor.attach(CC_MD5, {
            onEnter: function(args) {
                var data = args[0];
                var len = args[1].toInt32();
                var md = args[2];

                console.log("CC_MD5 called with", len, "bytes");
            }
        });
    }
}
```

---

## Memory Manipulation

### Reading Memory

```javascript
// Read from address
var address = ptr(0x12345678);
var value = address.readU8();
console.log("Byte at address:", value);

// Read string
var strPtr = ptr(0x12345678);
var str = strPtr.readUtf8String();
console.log("String:", str);

// Read array of bytes
var bytes = address.readByteArray(16);
console.log(hexdump(bytes, {
    offset: 0,
    length: 16,
    header: true,
    ansi: true
}));

// Read from ObjC object
var obj = ObjC.Object(ptr(0x12345678));
var ivar = obj.valueForKey_("myIvar");
console.log("Instance variable:", ivar);
```

### Writing Memory

```javascript
// Write to address
var address = ptr(0x12345678);
address.writeU8(0xFF);

// Write string
var strPtr = Memory.allocUtf8String("Hello");
Memory.protect(strPtr, 6, "rw-");

// Write bytes
var bytes = Memory.allocByteArray([0x48, 0x65, 0x6C, 0x6C, 0x6F]);
console.log("Written bytes:", bytes);

// Modify return value
Interceptor.attach(targetFunction, {
    onLeave: function(retval) {
        // Change return value to 0
        retval.replace(ptr(0));
    }
});
```

### Memory Allocation

```javascript
// Allocate memory for string
var str = Memory.allocUtf8String("Test string");
console.log("Allocated string at:", str);

// Allocate memory for structure
var structSize = 32;
var structPtr = Memory.alloc(structSize);
console.log("Allocated struct at:", structPtr);

// Write to struct
structPtr.writeU8(1);
structPtr.add(4).writeU32(42);

// Read from struct
console.log("Field 0:", structPtr.readU8());
console.log("Field 4:", structPtr.add(4).readU32());
```

### Memory Scanning

```javascript
// Pattern scanning
var pattern = "48 65 6C 6C 6F";  // "Hello" in hex
Memory.scan(Process.enumerateModules()[0].base, 1024, pattern, {
    onMatch: function(address, size) {
        console.log("Found pattern at:", address);
    },
    onComplete: function() {
        console.log("Scan complete");
    }
});

// Search for strings
Memory.scan(Process.enumerateModules()[0].base, 1024, "48 65 6C 6C 6F", {
    onMatch: function(address, size) {
        var str = address.readUtf8String();
        console.log("String at", address, ":", str);
    }
});
```

---

## iOS-Specific Features

### Main Thread Operations

```javascript
// Execute code on main thread
ObjC.schedule(ObjC.mainQueue, function() {
    console.log("Running on main thread");
    var alert = ObjC.classes.UIAlertController.alloc().initWithTitle_message_preferredStyle_(
        "Test", "Frida Alert", 1
    );
    var alertWindow = ObjC.classes.UIWindow.alloc().initWithFrame_(ObjC.classes.UIScreen.mainScreen().bounds());
    alertWindow.setRootViewController_(ObjC.classes.UIViewController.alloc().init());
    alertWindow.makeKeyAndVisible();
});
```

### Accessing UIApplication

```javascript
// Get sharedApplication
var UIApplication = ObjC.classes.UIApplication;
var app = UIApplication.sharedApplication();
console.log("App:", app);

// Get key window
var window = app.keyWindow();
console.log("Window:", window);

// Get root view controller
var rootVC = window.rootViewController();
console.log("Root VC:", rootVC);
```

### Accessing Keychain

```javascript
// Hook SecItemCopyMatching
var secMod = Process.findModuleByName("Security");
var SecItemCopyMatching = secMod ? secMod.findExportByName("SecItemCopyMatching") : null;

Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
        console.log("[Keychain] SecItemCopyMatching called");

        // Read query dictionary
        var query = ObjC.Object(args[0]);
        console.log("Query:", query);

        // Read kSecClass
        var secClass = query.objectForKey_(ObjC.classes.NSString.stringWithString_("kSecClass"));
        console.log("kSecClass:", secClass);
    },
    onLeave: function(retval) {
        console.log("[Keychain] Result:", retval);
    }
});
```

### Accessing Pasteboard

```javascript
// Hook UIPasteboard
var UIPasteboard = ObjC.classes.UIPasteboard;

// Hook generalPasteboard
Interceptor.attach(UIPasteboard["+ generalPasteboard"], {
    onLeave: function(retval) {
        var pb = ObjC.Object(retval);
        console.log("Pasteboard:", pb);
        console.log("String:", pb.string());
    }
});

// Hook setString_
Interceptor.attach(UIPasteboard["- setString:"], {
    onEnter: function(args) {
        var str = ObjC.Object(args[2]);
        console.log("Setting pasteboard string:", str.toString());
    }
});
```

---

## Spawn vs Attach

### Spawn Mode

```bash
# Spawn app (start from beginning; Frida 17+ resumes by default)
frida -U -f com.example.app

# Benefits:
# - Can hook methods before they execute
# - Can intercept initialization
# - Can modify behavior from startup

# Drawbacks:
# - App starts fresh (no state)
# - Slower startup
```

### Attach Mode

```bash
# Attach to running app
frida -U "Example App"

# Benefits:
# - Fast connection
# - App retains state
# - Good for interactive testing

# Drawbacks:
# - Misses early initialization
# - Cannot hook methods already executed
```

### Choosing Between Spawn and Attach

```javascript
// Use spawn when:
// 1. You need to hook initialization methods
// 2. You want to intercept app startup
// 3. You need to modify early behavior

// Example: Hooking didFinishLaunchingWithOptions
var appDelegate = ObjC.classes.AppDelegate;
Interceptor.attach(appDelegate["- application:didFinishLaunchingWithOptions:"], {
    onEnter: function(args) {
        console.log("App launching");
        var options = ObjC.Object(args[3]);
        console.log("Launch options:", options);
    }
});

// Use attach when:
// 1. Testing specific features interactively
// 2. App is already running
// 3. Quick testing of existing behavior

// Example: Hooking a button tap
var button = ObjC.classes.UIButton;
Interceptor.attach(button["- sendAction:to:forEvent:"], {
    onEnter: function(args) {
        console.log("Button tapped");
        var action = ObjC.Object(args[2]);
        var target = ObjC.Object(args[3]);
        console.log("Action:", action);
        console.log("Target:", target);
    }
});
```

---

## Practical Examples

### Example 1: Log All Network Requests

```javascript
// Hook NSURLSession data task
var NSURLSession = ObjC.classes.NSURLSession;
var dataTaskMethod = NSURLSession["- dataTaskWithURL:completionHandler:"];

Interceptor.attach(dataTaskMethod, {
    onEnter: function(args) {
        var url = ObjC.Object(args[2]);
        console.log("\n[Network] Request to:", url.absoluteURL().toString());
    }
});

// Hook completion handler
// Note: This is simplified; real implementation needs more work
```

### Example 2: Bypass Simple Root Check

```javascript
// Hook common root check methods

// Check for existence of Cydia app
var fileManager = ObjC.classes.NSFileManager;
var fileExistsMethod = fileManager["- fileExistsAtPath:"];

Interceptor.attach(fileExistsMethod, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]);
        var pathStr = path.toString();

        // Return false for common jailbreak paths
        if (pathStr.indexOf("Applications/Cydia.app") !== -1 ||
            pathStr.indexOf("/bin/bash") !== -1) {
            console.log("[Root Check] Bypassing check for:", pathStr);
        }
    },
    onLeave: function(retval) {
        var path = ObjC.Object(this.args[2]);
        var pathStr = path.toString();

        if (pathStr.indexOf("Applications/Cydia.app") !== -1) {
            // Return false (file doesn't exist)
            retval.replace(ptr(0));
        }
    }
});
```

### Example 3: Intercept HTTP Cookies

```javascript
// Hook NSHTTPCookieStorage
var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
var sharedStorage = NSHTTPCookieStorage["- sharedHTTPCookieStorage"];

Interceptor.attach(sharedStorage, {
    onLeave: function(retval) {
        var storage = ObjC.Object(retval);
        var cookies = storage.cookies();

        console.log("\n[Cookies] Total:", cookies.count());

        for (var i = 0; i < cookies.count(); i++) {
            var cookie = cookies.objectAtIndex_(i);
            console.log("  - Name:", cookie.name());
            console.log("    Value:", cookie.value());
            console.log("    Domain:", cookie.domain());
        }
    }
});
```

---

## Advanced Techniques

### Method Tracing

```javascript
// Trace all methods in a class
function traceClass(className) {
    var theClass = ObjC.classes[className];
    if (!theClass) {
        console.log("Class not found:", className);
        return;
    }

    console.log("Tracing", className, "...");

    var methods = theClass.$ownMethods;
    methods.forEach(function(methodName) {
        var method = theClass[methodName];
        if (!method) return;

        console.log("  Hooking:", methodName);

        Interceptor.attach(method, {
            onEnter: function(args) {
                console.log("  [" + className + "] " + methodName);
            }
        });
    });
}

// Usage
traceClass("NSURLSession");
```

### Stack Trace

```javascript
// Helper to get stack trace
function getStackTrace() {
    return Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)  // Limit to 10 frames
        .join("\n");
}

// Use in hooks
Interceptor.attach(targetMethod, {
    onEnter: function(args) {
        console.log("\n[Stack Trace]");
        console.log(getStackTrace());
    }
});
```

### Class Dumping

```javascript
// Dump class information
function dumpClass(className) {
    var theClass = ObjC.classes[className];
    if (!theClass) {
        console.log("Class not found:", className);
        return;
    }

    console.log("\n=== Class:", className, "===");

    // Superclass
    console.log("Superclass:", theClass.superclass);

    // Protocols
    console.log("Protocols:", theClass.$protocols.join(", "));

    // Properties
    console.log("\nProperties:");
    // (Property inspection requires more work)

    // Methods
    console.log("\nMethods:");
    theClass.$ownMethods.forEach(function(method) {
        console.log("  " + method);
    });
}

// Usage
dumpClass("NSURLSession");
```

### CModule for Native Performance

Frida's CModule allows you to write native C code that runs with zero overhead. This is particularly useful for:

- Anti-cheat contexts where performance matters
- Hot functions that execute frequently
- Complex logic that's easier in C than JavaScript

#### Basic CModule Usage

```javascript
// Create a C module with C code
const cm = new CModule(`
#include <gum/gum.h>

// Pointer to original function
static void (*original_malloc)(size_t size);

// Replacement function
void replacement_malloc(size_t size) {
    // Log allocation
    gum_debug_log("Malloc called with size: %zu\\n", size);

    // Call original
    return original_malloc(size);
}

// Initialize - called when CModule is loaded
void init(GumInterceptor *interceptor) {
    gum_debug_log("CModule initialized\\n");
}
`, {
    // Pass symbol dependencies
    original_malloc: Module.findGlobalExportByName("malloc")
});

// Replace malloc with C implementation
const mallocPtr = Module.findGlobalExportByName("malloc");
Interceptor.replace(mallocPtr, new NativeCallback(cm.replacement_malloc, 'void', ['size_t']));
```

#### PLT/GOT Hooking with CModule

```javascript
// Hook functions via PLT/GOT for anti-cheat bypass
const pltHook = new CModule(`
#include <gum/gum.h>

// Original function pointers
static void (*original_open)(const char *path, int oflag);
static int (*original_openat)(int fd, const char *path, int oflag);

// Replacement: open()
void replacement_open(const char *path, int oflag) {
    // Log file open
    if (strstr(path, "suspicious") != NULL) {
        gum_debug_log("[CModule] Blocked access to: %s\\n", path);
        errno = EACCES;
        return -1;
    }
    return original_open(path, oflag);
}

// Replacement: openat()
int replacement_openat(int fd, const char *path, int oflag) {
    if (strstr(path, "protected") != NULL) {
        gum_debug_log("[CModule] Blocked openat to: %s\\n", path);
        errno = EACCES;
        return -1;
    }
    return original_openat(fd, path, oflag);
}
`, {
    original_open: Module.findGlobalExportByName("open"),
    original_openat: Module.findGlobalExportByName("openat"),
});

// Apply hooks
Interceptor.replace(
    Module.findGlobalExportByName("open"),
    new NativeCallback(pltHook.replacement_open, 'void', ['pointer', 'int'])
);
```

#### Memory Scanning with CModule

```javascript
// Fast memory scanning using native C code
const memScanner = new CModule(`
#include <gum/gum.h>
#include <string.h>

// Scan for byte pattern
int scan_pattern(const guint8 *haystack, size_t haystack_len,
                 const guint8 *needle, size_t needle_len) {
    if (needle_len > haystack_len) return 0;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;  // Found
        }
    }
    return 0;  // Not found
}
`);

// Use in JavaScript
const pattern = [0x48, 0x65, 0x6C, 0x6C, 0x6F];  // "Hello"
const haystack = ptr(0x1000).readByteArray(0x100);

if (memScanner.scan_pattern(haystack, 0x100, pattern, 5)) {
    console.log("Pattern found!");
}
```

### When to Use CModule vs JavaScript

| Scenario | Use | Reason |
|----------|-----|--------|
| Simple hooks | JavaScript | Easier to write and debug |
| Hot functions | CModule | Zero overhead, faster execution |
| String manipulation | JavaScript | Better string handling in JS |
| Memory scanning | CModule | Native performance for large scans |
| Anti-cheat bypass | CModule | Harder to detect than JS hooks |

---

## Advanced iOS Techniques

### ObjC API Patterns

#### Understanding args[] in Objective-C

When hooking Objective-C methods, the `args[]` array works differently:

```javascript
// args[0] = self (the object instance)
// args[1] = selector (method name)
// args[2] = first argument
// args[3] = second argument (if multiple args)

// Example: -[NSURL initWithString:]
Interceptor.attach(targetAddress, {
    onEnter(args) {
        const urlString = new ObjC.Object(args[2]);
        console.log("URL:", urlString.toString());
    }
});
```

#### ApiResolver for ObjC Methods

```javascript
const resolver = new ApiResolver('objc');
const matches = resolver.enumerateMatchesSync('-[NSFileManager fileExists*]');
// Returns array of {name, address}

const address = ptr(matches[0].address);
Interceptor.attach(address, {
    onEnter(args) {
        const filePath = new ObjC.Object(args[2]);
        console.log("File access:", filePath.toString());
    }
});
```

#### $ownMethods vs $methods

```javascript
// $ownMethods - Only methods defined by this class
ObjC.classes.NSFileManager.$ownMethods

// $methods - Methods including inherited ones
ObjC.classes.NSFileManager.$methods

// $moduleName - Framework the class belongs to
ObjC.classes.NSString.$moduleName
```

### CFDataRef Pattern

```javascript
// Reading CFDataRef bytes
const cfData = new ObjC.Object(args[0]);
const bytes = cfData.bytes();
const string = bytes.readUtf8String();
console.log("CFData:", string);
```

### CryptoKit Hooking Pattern

```javascript
// Hook AES.GCM.seal to get data before encryption
// Symbol pattern:
// static_CryptoKit.AES.GCM.seal_A_where_A:_Foundation.DataProtocol_

const sealFunctions = Module.enumerateImportsSync(binaryName);
// Find AES.GCM.seal import
// Hook to extract:
// - Data to encrypt
// - SymmetricKey
// - IV/Nonce
```

### Swift.String Pattern

```javascript
// Swift strings have different internal representation
// Use appropriate methods to read Swift data
```

### Security Finding Classification

When instrumenting iOS applications with Frida, classify findings using severity levels:

```javascript
// CRITICAL - Immediate security risk
console.log("🔴 CRITICAL: Token detected in URL!");
console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");

// HIGH - Important security issue
console.log("🟠 HIGH: Credentials detected in URL!");
console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");

// MEDIUM - Moderate security concern
console.log("🟡 MEDIUM: Potential keychain access");
console.log("  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N");

// LOW - Minor security issue
console.log("🟢 LOW: Debug logging detected");
console.log("  CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Frida Application |
|---------------|-------|-------------------|
| MASTG-TEST-0011 | Runtime Manipulation | Frida hooking |
| MASTG-TECH-0016 | Runtime Instrumentation | Frida capabilities |
| MASTG-APP-SEC-0010 | Runtime Manipulation Prevention | Detecting hooks |
| MASTG-APP-SEC-0011 | Debugging Protection | Bypassing detection |
| MASTG-TEST-0030 | Input Validation | Hooking input methods |
| MASTG-TEST-0071 | Method Analysis | ObjC API exploration |
| MASTG-TEST-0051 | Runtime Analysis | Dynamic instrumentation |
| MASTG-STORAGE-002 | File System Access | NSFileManager hooking |
| MASTG-CRYPTO-001 | Cryptographic Implementation | CryptoKit monitoring |
| MASTG-NETWORK-1 | Communication Security | NSURL monitoring |

---

## Summary

This guide covered:
- Frida fundamentals and basic commands
- Objective-C runtime access (classes, methods, properties)
- Hooking Objective-C methods with argument inspection
- Swift method hooking techniques
- Reading and modifying property values
- Working with common Objective-C data types
- Native code hooking for C functions
- Memory manipulation and scanning
- iOS-specific features (main thread, UIApplication, Keychain)
- Spawn vs attach modes
- Practical security testing examples
- Advanced techniques (tracing, stack traces)

Frida is a powerful tool for dynamic iOS security testing. Mastering these techniques enables comprehensive analysis of application behavior at runtime.

---

## References

### Official Documentation
- Frida Documentation: https://frida.re/docs/
- Objective-C Runtime: https://developer.apple.com/documentation/objectivec
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Community Resources
- Frida CodeShare: https://codeshare.frida.re/
- Frida Examples: https://github.com/frida/frida-examples
- iOS Reverse Engineering: https://github.com/iosre/iOSAppReverseEngineering

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, security researchers
**Prerequisites:** iOS development knowledge, JavaScript, jailbroken device with Frida server

## Simulator-Specific Notes

When working against an iOS Simulator with Frida 17+, the patterns in this guide may not apply directly. The correct hook pattern, attach strategy, and lifecycle management are documented in `references/frida-ios-simulator-workflow.md`.

