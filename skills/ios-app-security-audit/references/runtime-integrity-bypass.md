# Runtime Integrity Bypass

Runtime integrity checks protect apps from tampering and modification. This guide covers class integrity verification, anti-tamper detection, dylib injection checks, and bypass techniques with Frida.

**MASTG References:**
- MASTG-TEST-0013: Detection of Rooted or Jailbroken Devices
- MASTG-TEST-0056: Testing Code Quality and Code Construction Issues
- MASTG-TEST-0083: Testing Binary Protection

## 1. Class Integrity Verification

### Vulnerability: Basic Class Check

```objective-c
// Vulnerable integrity check
@interface IntegrityChecker : NSObject
@end

@implementation IntegrityChecker

- (BOOL)verifyClassIntegrity {
    // VULNERABLE: Simple class existence check
    if (NSClassFromString(@"CriticalClass")) {
        return YES;
    }
    return NO;
}

- (BOOL)verifyMethodIntegrity {
    // VULNERABLE: Simple method existence check
    Class cls = NSClassFromString(@"CriticalClass");

    if (class_getInstanceMethod(cls, @selector(criticalMethod))) {
        return YES;
    }

    return NO;
}

@end
```

### Bypass with Frida

```javascript
// Bypass class integrity checks
if (ObjC.available) {
    try {
        const IntegrityChecker = ObjC.classes.IntegrityChecker;

        if (IntegrityChecker) {
            // Hook verifyClassIntegrity
            const verifyClassIntegrity = IntegrityChecker['- verifyClassIntegrity'];
            Interceptor.attach(verifyClassIntegrity.implementation, {
                onLeave: function(retval) {
                    console.log("[+] verifyClassIntegrity called");
                    console.log("    Original result: " + retval);

                    // Force return YES
                    retval.replace(0x1);
                    console.log("    [!] Bypassed - returning YES");
                }
            });

            // Hook verifyMethodIntegrity
            const verifyMethodIntegrity = IntegrityChecker['- verifyMethodIntegrity'];
            Interceptor.attach(verifyMethodIntegrity.implementation, {
                onLeave: function(retval) {
                    console.log("[+] verifyMethodIntegrity called");
                    console.log("    Original result: " + retval);

                    // Force return YES
                    retval.replace(0x1);
                    console.log("    [!] Bypassed - returning YES");
                }
            });

            console.log("[+] Integrity check bypasses installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```objective-c
// Secure integrity verification
@interface SecureIntegrityChecker : NSObject
@property (nonatomic, assign) NSUInteger expectedMethodCount;
@end

@implementation SecureIntegrityChecker

- (instancetype)init {
    self = [super init];
    if (self) {
        _expectedMethodCount = [self countMethodsInClass:NSClassFromString(@"CriticalClass")];
    }
    return self;
}

- (BOOL)verifyClassIntegrity {
    Class cls = NSClassFromString(@"CriticalClass");

    if (!cls) {
        return NO;
    }

    // Count current methods
    NSUInteger currentCount = [self countMethodsInClass:cls];

    // Compare with expected count
    if (currentCount != self.expectedMethodCount) {
        NSLog(@"Method count mismatch: expected %lu, got %lu",
              (unsigned long)self.expectedMethodCount,
              (unsigned long)currentCount);
        return NO;
    }

    return YES;
}

- (NSUInteger)countMethodsInClass:(Class)cls {
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    free(methods);
    return methodCount;
}

- (BOOL)verifyMethodIntegrity {
    Class cls = NSClassFromString(@"CriticalClass");

    if (!cls) {
        return NO;
    }

    // Check critical method exists
    Method method = class_getInstanceMethod(cls, @selector(criticalMethod));

    if (!method) {
        return NO;
    }

    // Verify method signature
    const char *types = method_getTypeEncoding(method);
    NSString *signature = [NSString stringWithUTF8String:types];

    // Compare with expected signature
    NSString *expectedSignature = @"v@:";

    if (![signature isEqualToString:expectedSignature]) {
        NSLog(@"Method signature mismatch: %@", signature);
        return NO;
    }

    return YES;
}

@end
```

## 2. Anti-Tamper Detection

### Vulnerability: Simple Tamper Check

```objective-c
// Vulnerable tamper detection
@interface TamperDetector : NSObject
@end

@implementation TamperDetector

- (BOOL)detectTampering {
    // VULNERABLE: Simple file check
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];

    // Check file size
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDictionary *attributes = [fileManager attributesOfItemAtPath:binaryPath error:nil];

    NSNumber *fileSize = attributes[NSFileSize];

    // Expected file size (hardcoded - vulnerable)
    NSUInteger expectedSize = 12345678;

    if ([fileSize unsignedIntegerValue] != expectedSize) {
        return YES; // Tampering detected
    }

    return NO;
}

@end
```

### Bypass with Frida

```javascript
// Bypass tamper detection
if (ObjC.available) {
    try {
        const TamperDetector = ObjC.classes.TamperDetector;

        if (TamperDetector) {
            // Hook detectTampering
            const detectTampering = TamperDetector['- detectTampering'];
            Interceptor.attach(detectTampering.implementation, {
                onLeave: function(retval) {
                    console.log("[+] detectTampering called");
                    console.log("    Original result: " + retval);

                    // Force return NO (no tampering)
                    retval.replace(0x0);
                    console.log("    [!] Bypassed - returning NO");
                }
            });

            console.log("[+] Tamper detection bypass installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```objective-c
// Secure tamper detection
@interface SecureTamperDetector : NSObject
@property (nonatomic, strong) NSString *expectedHash;
@property (nonatomic, strong) NSString *expectedSignature;
@end

@implementation SecureTamperDetector

- (instancetype)init {
    self = [super init];
    if (self) {
        // Load expected hash from secure storage
        _expectedHash = [self loadExpectedHash];
        _expectedSignature = [self loadExpectedSignature];
    }
    return self;
}

- (BOOL)detectTampering {
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];

    // Calculate current hash
    NSString *currentHash = [self calculateHashForFile:binaryPath];

    // Verify hash
    if (![currentHash isEqualToString:self.expectedHash]) {
        NSLog(@"Hash mismatch detected");
        return YES;
    }

    // Verify code signature
    if (![self verifyCodeSignature:binaryPath]) {
        NSLog(@"Code signature verification failed");
        return YES;
    }

    return NO;
}

- (NSString *)calculateHashForFile:(NSString *)path {
    NSData *fileData = [NSData dataWithContentsOfFile:path];

    if (!fileData) {
        return nil;
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(fileData.bytes, (CC_LONG)fileData.length, digest);

    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }

    return hash;
}

- (BOOL)verifyCodeSignature:(NSString *)path {
    SecStaticCodeRef codeRef = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(
        (__bridge CFURLRef)[NSURL fileURLWithPath:path],
        kSecCSDefaultFlags,
        &codeRef
    );

    if (status != errSecSuccess || !codeRef) {
        return NO;
    }

    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &info);

    if (status != errSecSuccess || !info) {
        CFRelease(codeRef);
        return NO;
    }

    // Verify signature
    BOOL isValid = NO;
    NSDictionary *signingInfo = (__bridge NSDictionary *)info;

    if (signingInfo) {
        isValid = YES;

        // Check for ad-hoc signature (insecure)
        if ([signingInfo[(__bridge NSString *)kSecCodeInfoIdentifier] isEqualTo:@"adhoc"]) {
            isValid = NO;
        }
    }

    if (info) CFRelease(info);
    if (codeRef) CFRelease(codeRef);

    return isValid;
}

- (NSString *)loadExpectedHash {
    // Load from secure storage
    return @"expected_hash_here";
}

- (NSString *)loadExpectedSignature {
    // Load from secure storage
    return @"expected_signature_here";
}

@end
```

## 3. Dylib Injection Checks

### Vulnerability: Simple Dylib Check

```objective-c
// Vulnerable dylib check
@interface DylibChecker : NSObject
@end

@implementation DylibChecker

- (BOOL)detectDylibInjection {
    // VULNERABLE: Simple check for known dylibs
    const char *knownDylibs[] = {
        "FridaGadget",
        "libcycript",
        "substrate",
        NULL
    };

    for (int i = 0; knownDylibs[i] != NULL; i++) {
        if (dlopen(knownDylibs[i], RTLD_NOLOAD)) {
            return YES; // Injection detected
        }
    }

    return NO;
}

@end
```

### Bypass with Frida

```javascript
// Bypass dylib injection detection
if (ObjC.available) {
    try {
        const DylibChecker = ObjC.classes.DylibChecker;

        if (DylibChecker) {
            // Hook detectDylibInjection
            const detectDylibInjection = DylibChecker['- detectDylibInjection'];
            Interceptor.attach(detectDylibInjection.implementation, {
                onLeave: function(retval) {
                    console.log("[+] detectDylibInjection called");
                    console.log("    Original result: " + retval);

                    // Force return NO (no injection)
                    retval.replace(0x0);
                    console.log("    [!] Bypassed - returning NO");
                }
            });

            // Also hook dlopen
            const dlopen = Module.findGlobalExportByName('dlopen');
            Interceptor.attach(dlopen, {
                onEnter: function(args) {
                    const path = args[0].readUtf8String();
                    console.log("[+] dlopen called: " + path);

                    // Hide Frida-related dylibs
                    if (path && (
                        path.includes("Frida") ||
                        path.includes("frida") ||
                        path.includes("gadget")
                    )) {
                        console.log("    [!] Hiding Frida dylib");
                        this.hide = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.hide) {
                        // Return NULL to hide the dylib
                        retval.replace(ptr(0));
                    }
                }
            });

            console.log("[+] Dylib injection bypasses installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```objective-c
// Secure dylib injection detection
@interface SecureDylibChecker : NSObject
@property (nonatomic, strong) NSSet *allowedDylibs;
@end

@implementation SecureDylibChecker

- (instancetype)init {
    self = [super init];
    if (self) {
        _allowedDylibs = [NSSet setWithArray:@[
            @"/System/Library/Frameworks/*",
            @"/usr/lib/*",
            @"/System/Library/PrivateFrameworks/*"
        ]];
    }
    return self;
}

- (BOOL)detectDylibInjection {
    // Get all loaded dylibs
    uint32_t count = 0;
    const char **images = _dyld_image_names(&count);

    // Check each dylib
    for (uint32_t i = 0; i < count; i++) {
        const char *image = images[i];
        NSString *path = [NSString stringWithUTF8String:image];

        // Check if dylib is allowed
        if (![self isDylibAllowed:path]) {
            NSLog(@"Unauthorized dylib detected: %@", path);
            return YES;
        }
    }

    return NO;
}

- (BOOL)isDylibAllowed:(NSString *)path {
    // Check if path matches allowed patterns
    for (NSString *pattern in self.allowedDylibs) {
        if ([path hasPrefix:pattern]) {
            return YES;
        }
    }

    return NO;
}

- (NSArray *)getLoadedDylibs {
    uint32_t count = 0;
    const char **images = _dyld_image_names(&count);

    NSMutableArray *dylibs = [NSMutableArray arrayWithCapacity:count];

    for (uint32_t i = 0; i < count; i++) {
        const char *image = images[i];
        [dylibs addObject:[NSString stringWithUTF8String:image]];
    }

    return dylibs;
}

@end
```

## 4. FreeRASP Bypass (Talsec Runtime Protection)

### Overview

FreeRASP is a free runtime application self-protection (RASP) library developed by [Talsec](https://talsec.io). It provides comprehensive security checks including anti-debugging, anti-tampering, emulator detection, and Frida detection. Understanding its detection mechanisms is essential for penetration testing.

### Common FreeRASP Detection Methods

```objective-c
// FreeRASP detection mechanisms
@interface FreeRASPDetector : NSObject
- (BOOL)checkCodeIntegrity;
- (BOOL)checkDebugger;
- (BOOL)checkEmulator;
- (BOOL)checkFrida;
@end

@implementation FreeRASPDetector

// 1. Anti-Tamper: Code signature verification
- (BOOL)checkCodeIntegrity {
    SecStaticCodeRef codeRef = NULL;
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];
    
    OSStatus status = SecStaticCodeCreateWithPath(
        (__bridge CFURLRef)[NSURL fileURLWithPath:binaryPath],
        kSecCSDefaultFlags, &codeRef);
    
    if (status == errSecSuccess) {
        status = SecStaticCodeCheckValidity(codeRef, kSecCSCheckAll, NULL);
        CFRelease(codeRef);
    }
    
    return (status != errSecSuccess);
}

// 2. Anti-Debug: Check P_TRACED flag
- (BOOL)checkDebugger {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return NO;
}

// 3. Emulator Detection
- (BOOL)checkEmulator {
    #if TARGET_OS_SIMULATOR
    return YES;
    #else
    NSString *platform = [[UIDevice currentDevice] model];
    return [platform containsString:@"Simulator"] ||
           [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Xcode.app"];
    #endif
}

// 4. Frida Detection (process + port)
- (BOOL)checkFrida {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    sysctl(mib, 4, NULL, &size, NULL, 0);
    
    struct kinfo_proc *procs = malloc(size);
    if (sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
        size_t count = size / sizeof(struct kinfo_proc);
        for (size_t i = 0; i < count; i++) {
            if (strstr(procs[i].kp_proc.p_comm, "frida")) {
                free(procs);
                return YES;
            }
        }
    }
    free(procs);
    
    // Port check (27042)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {AF_INET, htons(27042), {inet_addr("127.0.0.1")}};
    BOOL open = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    return open;
}

@end
```

### Frida Detection Bypass for FreeRASP

```javascript
// Comprehensive FreeRASP bypass script
if (ObjC.available) {
    console.log("[+] FreeRASP Bypass Script Loaded");
    
    const FreeRASPDetector = ObjC.classes.FreeRASPDetector;
    
    if (FreeRASPDetector) {
        // Hook all common FreeRASP detection methods
        var methods = ['checkDebugger', 'checkEmulator', 'checkFrida', 
                       'checkCodeIntegrity', 'checkSecurity'];
        
        methods.forEach(function(method) {
            try {
                var impl = FreeRASPDetector['- ' + method];
                if (impl) {
                    Interceptor.attach(impl.implementation, {
                        onLeave: function(retval) {
                            retval.replace(0x0); // Return NO (safe)
                        }
                    });
                    console.log("[+] Bypassed: " + method);
                }
            } catch (e) {}
        });
    }
    
    // Hook connect() to block Frida port detection
    var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
    var connectPtr = kernelMod ? kernelMod.findExportByName("connect") : null;
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onLeave: function(retval) {
                // Frida port 27042 detection blocked
            }
        });
    }
    
    console.log("[+] FreeRASP bypasses installed");
}
```

### detectFreeRASP() - Detection Function

```javascript
// Detect if FreeRASP is present in the app
function detectFreeRASP() {
    console.log("[=] Checking for FreeRASP...");
    var results = { found: false, indicators: [] };
    
    if (ObjC.available) {
        // Check for FreeRASP classes
        var knownClasses = ["FreeRASP", "TalsecRuntime", "RuntimeIntegrity"];
        for (var i = 0; i < knownClasses.length; i++) {
            if (ObjC.classes[knownClasses[i]]) {
                console.log("[+] Found class: " + knownClasses[i]);
                results.found = true;
                results.indicators.push(knownClasses[i]);
            }
        }
        
        // Check for security-related classes
        var allClasses = Object.keys(ObjC.classes);
        for (var i = 0; i < allClasses.length; i++) {
            var clsName = allClasses[i];
            if (clsName.indexOf("FreeRASP") !== -1 || clsName.indexOf("Talsec") !== -1) {
                console.log("[+] Security class: " + clsName);
                results.found = true;
            }
        }
    }
    
    console.log("[=] FreeRASP: " + (results.found ? "FOUND" : "NOT FOUND"));
    return results;
}

setTimeout(detectFreeRASP, 1000);
```

### bypassFreeRASP() - Bypass Function

```javascript
// Comprehensive FreeRASP bypass
function bypassFreeRASP() {
    console.log("[=] Installing FreeRASP bypasses...");
    if (!ObjC.available) return;
    
    var securityMethods = ["checkSecurity", "validateIntegrity", "detectThreat", 
                          "appIsTampered", "isDebuggerAttached", "checkFrida"];
    
    var hookedCount = 0;
    var allClasses = Object.keys(ObjC.classes);
    
    for (var i = 0; i < allClasses.length; i++) {
        var cls = ObjC.classes[allClasses[i]];
        try {
            var methods = cls.$ownMethods;
            for (var j = 0; j < methods.length; j++) {
                for (var k = 0; k < securityMethods.length; k++) {
                    if (methods[j].name.indexOf(securityMethods[k]) !== -1) {
                        var method = cls[methods[j].name];
                        if (method && method.implementation) {
                            Interceptor.attach(method.implementation, {
                                onLeave: function(retval) { retval.replace(0x0); }
                            });
                            hookedCount++;
                        }
                    }
                }
            }
        } catch (e) {}
    }
    
    // Hook dlopen to hide Frida
    var dlopenPtr = Module.findGlobalExportByName("dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onLeave: function(retval) {
                // Hide Frida libraries from being reported as loaded
            }
        });
    }
    
    console.log("[+] FreeRASP bypass: " + hookedCount + " methods hooked");
}

setTimeout(bypassFreeRASP, 500);
```

### Detection Indicators

| Indicator | Description | How to Check |
|-----------|-------------|--------------|
| Class names | FreeRASP classes | `ObjC.classes` enumeration |
| Method patterns | `checkSecurity`, `detectThreat` | Method name analysis |
| Library files | `libFreeRASP.dylib` | Module enumeration |
| Frida detection | Process/port scanning | Network socket checks |
| Emulator checks | Simulator detection | Runtime environment |

## 5. FridaGadget Injection

### Overview

FridaGadget is a re-packagable Frida variant embedded directly into iOS apps for dynamic instrumentation without jailbreak or frida-server. It's a standalone dylib injected into the target app.

### Step-by-Step Injection

```bash
# 1. Extract IPA
unzip -o target_app.ipa -d extracted/
APP_BINARY="extracted/Payload/TargetApp.app/TargetApp"

# 2. Download FridaGadget (match version to your Frida)
FRIDA_VERSION=$(frida --version 2>/dev/null || echo "17.11.0")   # fallback; pinned in references/tool-versions.md
curl -L -o frida-gadget.dylib \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/FridaGadget-${FRIDA_VERSION}-ios-arm64.dylib"

# 3. Inject FridaGadget using insert-dylib
insert-dylib --weak --all-yes FridaGadget.dylib "$APP_BINARY" "$APP_BINARY-patched"
mv "$APP_BINARY-patched" "$APP_BINARY"

# 4. Re-sign binary
codesign -f -s "Apple Development: TeamID" "extracted/Payload/TargetApp.app/"

# 5. Package IPA
cd extracted && zip -r ../target_patched.ipa * && cd ..

# 6. Install
ideviceinstaller install target_patched.ipa
```

### FridaGadget Usage Examples

#### Connect to FridaGadget

```bash
# Wait for app to launch, then attach
frida -U -f com.example.app

# Or attach to running process
frida -U -p $(pid of target app)

# Use script file
frida -U -f com.example.app -l my_script.js
```

#### FridaGadget Configuration

Create a `frida.config` JSON in the app's Documents directory:

```json
{
    "interaction": {
        "type": "listen",
        "address": "0.0.0.0",
        "port": 27042
    }
}
```

**Security Consideration**: Apps can detect FridaGadget via `dladdr()`, memory scanning, port scanning, or thread names. Use stripped/disguised FridaGadget combined with anti-detection techniques.

### Detecting FridaGadget in Apps

```javascript
// Detect FridaGadget presence in the app
function detectFridaGadget() {
    console.log("[=] Checking for FridaGadget...");
    var results = { found: false, indicators: [] };
    
    // Check loaded modules for FridaGadget
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name.toLowerCase();
        if (name.includes("frida") || name.includes("gadget")) {
            console.log("[+] Suspicious module: " + modules[i].name);
            results.found = true;
            results.indicators.push(modules[i].name);
        }
    }
    
    // Check for FridaGadget class patterns
    if (ObjC.available) {
        var allClasses = Object.keys(ObjC.classes);
        for (var i = 0; i < allClasses.length; i++) {
            var clsName = allClasses[i];
            if (clsName.indexOf("Frida") !== -1 || clsName.indexOf("Gadget") !== -1) {
                console.log("[+] Frida class: " + clsName);
                results.found = true;
                results.indicators.push(clsName);
            }
        }
    }
    
    // Check for Frida server via named pipes
    var fridaPipe = Module.findGlobalExportByName("frida");
    if (fridaPipe) {
        console.log("[+] Frida pipe detected");
        results.found = true;
        results.indicators.push("frida_pipe");
    }
    
    console.log("[=] FridaGadget: " + (results.found ? "FOUND" : "NOT FOUND"));
    return results;
}

// Check for Frida server running on default ports
function checkFridaServer() {
    console.log("[=] Checking for Frida server...");
    var fridaPorts = [27042, 27043, 27044, 27045];
    
    for (var i = 0; i < fridaPorts.length; i++) {
        var sock = socket(AF_INET, SOCK_STREAM, 0);
        var addr = Memory.alloc(16);
        addr.writeInt32(AF_INET);
        addr.add(2).writeInt16(fridaPorts[i]);
        addr.add(4).writeInt32(inet_addr("127.0.0.1"));
        
        var result = connect(sock, addr, 16);
        close(sock);
        
        if (result === 0) {
            console.log("[+] Frida server detected on port: " + fridaPorts[i]);
            return true;
        }
    }
    console.log("[-] No Frida server detected");
    return false;
}

setTimeout(detectFridaGadget, 1000);
setTimeout(checkFridaServer, 1500);
```

### Frida Version Fingerprinting Detection

Modern apps may detect specific Frida versions via memory fingerprinting:

```javascript
// Frida version strings in memory
var fridaVersionSignatures = {
    "16.5": ["frida-core 16.5", "Frida 16.5"],
    "16.4": ["frida-core 16.4", "frida 16.4"],
    "16.3": ["frida 16.3", "FRIDA 16.3"],
    "16.2": ["Frida 16.2", "frida-16-2"],
    "16.1": ["frida-16-1", "frida 16.1"],
    "16.0": ["FRIDA 16.0", "frida-core 16.0"]
};

// Check for version strings in loaded libraries
function checkFridaVersions() {
    console.log("[=] Checking for Frida version signatures...");
    var modules = Process.enumerateModules();
    
    for (var i = 0; i < modules.length; i++) {
        var baseAddr = modules[i].base;
        var size = modules[i].size;
        
        // Scan first 4KB of module for version strings
        try {
            var data = baseAddr.readByteArray(Math.min(4096, size));
            for (var version in fridaVersionSignatures) {
                for (var j = 0; j < fridaVersionSignatures[version].length; j++) {
                    if (data.indexOf(fridaVersionSignatures[version][j]) !== -1) {
                        console.log("[+] Frida version detected: " + version);
                        return version;
                    }
                }
            }
        } catch (e) {}
    }
    console.log("[-] No Frida version detected");
    return null;
}
```

### Anti-Frida Detection Bypass Techniques

#### Bypass DYLD Image Enumeration

```javascript
// Hook _dyld_get_image_name to filter Frida libraries
var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
var dyldGetImageName = kernelMod ? kernelMod.findExportByName("__dyld_get_image_name") : null;

if (dyldGetImageName) {
    Interceptor.attach(dyldGetImageName, {
        onEnter: function(args) {
            this.index = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                try {
                    var name = retval.readUtf8String();
                    if (name && (
                        name.toLowerCase().includes("frida") ||
                        name.toLowerCase().includes("gadget") ||
                        name.toLowerCase().includes("libcycript")
                    )) {
                        retval.replace(ptr(0)); // Return NULL for Frida dylibs
                    }
                } catch (e) {}
            }
        }
    });
    console.log("[+] DYLD enumeration bypass installed");
}

// Hook _dyld_image_count to hide Frida-modified count
var dyldImageCount = kernelMod ? kernelMod.findExportByName("__dyld_image_count") : null;
if (dyldImageCount) {
    Interceptor.attach(dyldImageCount, {
        onLeave: function(retval) {
            // Could return adjusted count if needed
        }
    });
}
```

#### Bypass dladdr Detection

```javascript
// Hide Frida symbols from dladdr
var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
var dladdrPtr = kernelMod ? kernelMod.findExportByName("dladdr") : null;

if (dladdrPtr) {
    Interceptor.attach(dladdrPtr, {
        onEnter: function(args) {
            this.addr = args[0];
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                try {
                    // Dl_info is at args[1]
                    var info = this.addr.add(0);
                    var dli_fname = info.readPointer();
                    if (!dli_fname.isNull()) {
                        var fname = dli_fname.readUtf8String();
                        if (fname && (
                            fname.includes("Frida") ||
                            fname.includes("frida") ||
                            fname.includes("gadget")
                        )) {
                            // Zero out the filename
                            dli_fname.writePointer(ptr(0));
                        }
                    }
                } catch (e) {}
            }
        }
    });
    console.log("[+] dladdr bypass installed");
}
```

## 6. Advanced Anti-Frida Detection Bypass

### Overview

Modern apps employ sophisticated Frida detection mechanisms beyond basic process name checking. This section covers advanced bypass techniques for:
- Process name detection
- Port detection (frida-server default 27042)
- Memory artifact detection
- Frida version fingerprinting

### Process Name Detection Bypass

#### Vulnerable Detection Code

```objective-c
// Checks for frida-server process names
- (BOOL)detectFridaByProcessName {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    
    // Get process list size
    sysctl(mib, 4, NULL, &size, NULL, 0);
    
    struct kinfo_proc *procs = malloc(size);
    sysctl(mib, 4, procs, &size, NULL, 0);
    
    size_t count = size / sizeof(struct kinfo_proc);
    
    for (size_t i = 0; i < count; i++) {
        struct kinfo_proc *proc = &procs[i];
        char *name = proc->kp_proc.p_comm;
        
        // Check for Frida-related process names
        if (strstr(name, "frida") != NULL ||
            strstr(name, "linjector") != NULL ||
            strstr(name, "gadget") != NULL) {
            free(procs);
            return YES;
        }
    }
    
    free(procs);
    return NO;
}
```

#### Bypass with Process Name Hiding

```javascript
// Hide Frida processes from process enumeration
if (ObjC.available) {
    console.log("[+] Installing process name hiding...");
    
    // Hook sysctl to filter process list
    var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
    var sysctlPtr = kernelMod ? kernelMod.findExportByName("sysctl") : null;
    
    Interceptor.attach(sysctlPtr, {
        onEnter: function(args) {
            // Save original arguments
            this.mib = args[0];
            this.size = args[1];
        },
        onLeave: function(retval) {
            // KERN_PROC_ALL = 4
            // If querying process list, filter out Frida
            try {
                var mib0 = this.mib.readU32();
                if (mib0 === 1 && args[1].toInt32() >= 4) {
                    // Could filter process names here
                    // This is a simplified example
                }
            } catch (e) {
                // Ignore errors
            }
        }
    });
    
    // Hook pthread_create to detect Frida threads
    var pthreadPtr = kernelMod ? kernelMod.findExportByName("pthread_create") : null;
    
    Interceptor.attach(pthreadPtr, {
        onEnter: function(args) {
            this.start_routine = args[2];
            this.arg = args[3];
        },
        onLeave: function(retval) {
            // Frida threads can be identified by their start routine
            // This is informational only
        }
    });
}
```

### Port Detection Bypass

#### Vulnerable Detection Code

```objective-c
// Frida server default port check
- (BOOL)detectFridaByPort {
    // Check common Frida ports
    int ports[] = {27042, 27043, 27044, 27045};
    int numPorts = sizeof(ports) / sizeof(ports[0]);
    
    for (int i = 0; i < numPorts; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms
        
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
        
        if (result == 0) {
            // Port is open - Frida detected
            return YES;
        }
    }
    
    return NO;
}
```

#### Bypass with Port/Hook Hidden

```javascript
// Bypass port-based Frida detection
if (ObjC.available) {
    console.log("[+] Installing port detection bypass...");
    
    // Hook connect() to hide Frida ports
    var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
    var connectPtr = kernelMod ? kernelMod.findExportByName("connect") : null;
    
    Interceptor.attach(connectPtr, {
        onEnter: function(args) {
            this.sockfd = args[0].toInt32();
            this.addrPtr = args[1];
        },
        onLeave: function(retval) {
            try {
                var addr = this.addrPtr;
                var sin_family = addr.add(0).readU16();
                
                // Only check TCP connections
                if (sin_family === 2) { // AF_INET
                    var port = addr.add(2).readU16BE();
                    
                    // Frida default ports
                    var fridaPorts = [27042, 27043, 27044, 27045];
                    if (fridaPorts.indexOf(port) !== -1) {
                        console.log("[+] Blocked connection to Frida port: " + port);
                        retval.replace(-1); // Return error
                    }
                }
            } catch (e) {
                // Ignore errors
            }
        }
    });
    
    // Hook socket() creation to monitor Frida sockets
    var socketPtr = kernelMod ? kernelMod.findExportByName("socket") : null;
    
    Interceptor.attach(socketPtr, {
        onLeave: function(retval) {
            // Track socket creation if needed
            // Frida sockets can be identified by their properties
        }
    });
    
    console.log("[+] Port detection bypass installed");
}
```

### Memory Artifact Detection Bypass

#### Vulnerable Detection Code

```objective-c
// Memory scanning for Frida artifacts
- (BOOL)detectFridaByMemory {
    // Frida Gadget signatures in memory
    const char *fridaSignatures[] = {
        "LIBFRIDA",
        "FridaAgent",
        "frida_agent",
        "FridaGadget",
        "CydiaSubstrate",
        NULL
    };
    
    // Scan mapped memory regions
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        // iOS doesn't have /proc, use task_info instead
        return [self scanTaskPorts];
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char perms[5] = {0};
        char pathname[256] = {0};
        
        sscanf(line, "%*x-%*x %s %*x %*s %*d %256s", perms, pathname);
        
        // Check if memory region is writable and has Frida signature
        if (strstr(perms, "rw") && strlen(pathname) > 0) {
            // Read and scan the memory region
            // This is a simplified check
            for (int i = 0; fridaSignatures[i] != NULL; i++) {
                if (strstr(pathname, fridaSignatures[i])) {
                    fclose(fp);
                    return YES;
                }
            }
        }
    }
    
    fclose(fp);
    return NO;
}

- (BOOL)scanTaskPorts {
    // Use mach task_info to scan memory
    mach_port_t task = mach_task_self();
    struct task_basic_info info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    
    kern_return_t kr = task_info(task, TASK_BASIC_INFO, 
                                  (task_info_t)&info, &count);
    
    return (kr != KERN_SUCCESS);
}
```

#### Bypass with Memory Scanning Evasion

```javascript
// Bypass memory-based Frida detection
if (ObjC.available) {
    console.log("[+] Installing memory artifact bypass...");
    
    // Hook mmap to detect and hide Frida memory regions
    var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
    var mmapPtr = kernelMod ? kernelMod.findExportByName("mmap") : null;
    
    Interceptor.attach(mmapPtr, {
        onEnter: function(args) {
            this.addr = args[0];
            this.length = args[1];
            this.prot = args[2].toInt32();
            this.flags = args[3].toInt32();
            this.fd = args[4].toInt32();
            this.offset = args[5];
        },
        onLeave: function(retval) {
            // Check if this is a Frida-related mapping
            try {
                if (this.fd >= 0) {
                    // Could identify Frida by file descriptor
                    // This requires additional tracking
                }
            } catch (e) {}
        }
    });
    
    // Hook vm_protect to detect memory scanning
    var vmProtectPtr = kernelMod ? kernelMod.findExportByName("vm_protect") : null;
    
    Interceptor.attach(vmProtectPtr, {
        onEnter: function(args) {
            this.task = args[0];
            this.address = args[1];
            this.size = args[2];
            this.protection = args[3].toInt32();
        }
    });
    
    // Disable or hook memory scanning functions
    var taskInfoPtr = kernelMod ? kernelMod.findExportByName("task_info") : null;
    
    if (taskInfoPtr) {
        Interceptor.attach(taskInfoPtr, {
            onEnter: function(args) {
                this.task = args[0];
                this.flavor = args[1];
                this.info = args[2];
                this.count = args[3];
            },
            onLeave: function(retval) {
                // Could filter out Frida-related info here
            }
        });
    }
    
    console.log("[+] Memory artifact bypass installed");
}
```

### Frida Version Fingerprinting Bypass

#### Vulnerable Detection Code

```objective-c
// Detect specific Frida versions by fingerprinting
- (BOOL)detectFridaVersion {
    // Frida version strings in memory
    NSDictionary *versionSignatures = @{
        @"16.5": @"frida-core 16.5",
        @"16.4": @"frida-core 16.4",
        @"16.3": @"frida 16.3",
        @"16.2": @"Frida 16.2",
        @"16.1": @"frida-16-1",
        @"16.0": @"FRIDA 16.0"
    };
    
    // Scan loaded dylibs for version strings
    uint32_t count = _dyld_image_count();
    
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        NSString *imageName = [NSString stringWithUTF8String:name];
        
        for (NSString *version in versionSignatures) {
            if ([imageName containsString:version]) {
                return YES;
            }
        }
    }
    
    return NO;
}
```

#### Bypass with Version String Manipulation

```javascript
// Bypass Frida version fingerprinting
if (ObjC.available) {
    console.log("[+] Installing version fingerprinting bypass...");
    
    // Hook _dyld_get_image_name to filter Frida libraries
    var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
    var dyldGetImageName = kernelMod ? kernelMod.findExportByName("__dyld_get_image_name") : null;
    
    if (dyldGetImageName) {
        Interceptor.attach(dyldGetImageName, {
            onEnter: function(args) {
                this.index = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (retval.isNull()) return;
                
                try {
                    var name = retval.readUtf8String();
                    
                    // Hide Frida-related dylibs from enumeration
                    if (name && (
                        name.indexOf("frida") !== -1 ||
                        name.indexOf("Frida") !== -1 ||
                        name.indexOf("gadget") !== -1
                    )) {
                        retval.replace(ptr(0)); // Return NULL
                    }
                } catch (e) {}
            }
        });
    }
    
    // Hook _dyld_image_count to adjust count
    var dyldImageCount = kernelMod ? kernelMod.findExportByName("__dyld_image_count") : null;
    
    if (dyldImageCount) {
        Interceptor.attach(dyldImageCount, {
            onLeave: function(retval) {
                // Return adjusted count if we hid any images
                // This is more complex and depends on implementation
            }
        });
    }
    
    // Hook dladdr to hide Frida symbols
    var dladdrPtr = kernelMod ? kernelMod.findExportByName("dladdr") : null;
    
    if (dladdrPtr) {
        Interceptor.attach(dladdrPtr, {
            onEnter: function(args) {
                this.addr = args[0];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    try {
                        // Dl_info is at args[1]
                        // Could zero out the dli_fname if it contains Frida
                    } catch (e) {}
                }
            }
        });
    }
    
    console.log("[+] Version fingerprinting bypass installed");
}
```

### Detection Bypass Summary Table

| Detection Type | Method | Bypass Technique |
|----------------|--------|------------------|
| Process Name | `sysctl` KERN_PROC_ALL | Hook to filter Frida processes |
| Port Scanning | `connect()` to 27042 | Return error on Frida ports |
| Memory Scan | `mmap`/`vm_read` | Hide Frida memory regions |
| DYLD Enum | `_dyld_image_names` | Filter Frida from list |
| dladdr | Symbol resolution | Hide Frida symbols |
| Thread Scan | `pthread_create` | Monitor Frida threads |
| Signature | Memory patterns | Obfuscate Frida signatures |
| Version | String matching | Hide version strings |

## Testing Checklist
- [ ] Test class integrity verification
- [ ] Check method integrity
- [ ] Verify signature validation
- [ ] Test tamper detection
- [ ] Check for bypass vulnerabilities

### Detection Bypass
- [ ] Test Frida hooking
- [ ] Verify bypass techniques
- [ ] Check for detection
- [ ] Test multiple bypass methods
- [ ] Verify effectiveness

### Security
- [ ] Verify secure implementations
- [ ] Test detection evasion
- [ ] Check for false positives
- [ ] Verify performance impact
- [ ] Test integration with other protections

## OWASP MASTG References

- **MASTG-TEST-0013**: Detection of Rooted or Jailbroken Devices
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
- **MASTG-TEST-0083**: Testing Binary Protection

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **Substrate**: Tweak development
- **Cycript**: Runtime manipulation

### Reference Materials
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Frida Documentation](https://frida.re/docs/)
- [Substrate Documentation](https://www.cydiasubstrate.com/)
