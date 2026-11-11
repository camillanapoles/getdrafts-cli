# iOS Framework Stub Guide - Objective-C Symbol Export

## Overview

Guía para crear stubs de frameworks que funcionen correctamente en iOS Simulator cuando el framework original solo está disponible para device.

## Problem Statement

Cuando ejecutas una app arm64 en iOS Simulator (Apple Silicon), puedes encontrar:

```
dyld: Symbol not found: _OBJC_CLASS_$_FrameworkSDK
  Referenced from: <binary>
  Expected in: <framework_path>
```

**Root Cause**: El framework original contiene código ARM64 device-only con referencias a hardware/simulator detection. El app intenta cargar estas clases pero el framework no existe en simulator.

## Solution Pattern

### Option 1: Empty Objective-C Classes (Recommended)

**Why this works**: El runtime Objective-C necesita las clases exportadas, no la implementación. Clases vacías satisfacen el linker sin funcionalidad de detección.

#### Template

```objc
// framework_stub.m
#import <Foundation/Foundation.h>

// Copiar nombres de clases del framework original
// Si no conoces las clases, usa strings del binario:
// strings Framework.framework/FrameworkName | grep "^_OBJC_CLASS"

@interface FrameworkSDK : NSObject
@end

@interface FrameworkListener : NSObject
@end

@interface FrameworkDelegate : NSObject
@end

// Implementaciones vacías - exportan símbolos correctamente
@implementation FrameworkSDK
@end

@implementation FrameworkListener
@end

@implementation FrameworkDelegate
@end
```

#### Compilation

```bash
clang -framework Foundation -dynamiclib \
    -o framework_stub.dylib framework_stub.m \
    -arch arm64 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    -fobjc-arc
```

#### Verification

```bash
# Verificar que clases se exportan
nm -gU framework_stub.dylib | grep _OBJC_CLASS
# Output debería mostrar:
# 000000000010000 _OBJC_CLASS_$_FrameworkSDK
# 000000000010000 _OBJC_METACLASS_$_FrameworkSDK
# ...
```

### Option 2: Minimal Implementation with Methods

Si el app llama métodos específicos del framework, implementarlos vacíos:

```objc
#import <Foundation/Foundation.h>

@interface FrameworkSDK : NSObject
+ (instancetype)sharedInstance;
- (void)startMonitoring;
- (void)stopMonitoring;
- (void)initializeSDK;
@end

@implementation FrameworkSDK

+ (instancetype)sharedInstance {
    static FrameworkSDK *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (void)startMonitoring {
    // Empty - do nothing
}

- (void)stopMonitoring {
    // Empty - do nothing
}

- (void)initializeSDK {
    // Empty - do nothing
}

@end
```

**Use Option 2 when**:
- El app llama métodos específicos (crashes con "unrecognized selector")
- Need `sharedInstance` pattern
- Callback delegates son requeridos

## Complete Workflow

### Step 1: Identify Required Classes

```bash
# Extraer símbolos del framework original (si tienes acceso)
strings Framework.framework/FrameworkName | grep "^_OBJC_CLASS"

# O buscar en binario principal
strings App.app/Executable | grep "FrameworkName"

# En binario principal, buscar referencias
otool -t App.app/Executable | grep FrameworkName
```

### Step 2: Create Stub File

Usa Option 1 (clases vacías) u Option 2 (con métodos) según necesites.

### Step 3: Compile for Device Architecture

```bash
# IMPORTANTE: arm64 para simulator (Apple Silicon)
clang -framework Foundation -dynamiclib \
    -o framework_stub.dylib framework_stub.m \
    -arch arm64 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    -fobjc-arc
```

### Step 4: Replace Original Framework

```bash
# Backup del original (OPCIONAL)
cp -R Framework.framework Framework.framework.backup

# Reemplazar binario
cp framework_stub.dylib \
   App.app/Frameworks/FrameworkName.framework/FrameworkName
```

### Step 5: Convert for Simulator

```bash
# Usar SimForge para parchear LC_BUILD_VERSION
simforge convert \
    App.app/Frameworks/FrameworkName.framework/FrameworkName
```

### Step 6: Re-sign

```bash
# Firmar framework
codesign --force --sign - \
    App.app/Frameworks/FrameworkName.framework/FrameworkName

# Firmar app bundle
codesign --force --sign - App.app
```

### Step 7: Install and Test

```bash
# Reinstalar app
UDID=$(xcrun simctl list devices booted | grep -oE "[A-F0-9-]{36}" | head -1)
xcrun simctl uninstall $UDID com.bundle.id
xcrun simctl install $UDID App.app

# Lanzar y verificar
xcrun simctl launch booted com.bundle.id
```

## Troubleshooting

### Issue: "Code signature invalid"

```
dyld: Code signature invalid
```

**Fix**: Re-signar todo el app bundle:

```bash
codesign --remove-signature App.app
codesign --force --sign - App.app
```

### Issue: "Incompatible platform (have 'iOS', need 'iOS-sim')"

**Fix**: Convertir framework:

```bash
simforge convert \
    App.app/Frameworks/FrameworkName.framework/FrameworkName
```

### Issue: App crashes with "unrecognized selector"

**Cause**: Stub no tiene métodos que el app llama.

**Fix**: Usar Option 2 e implementar métodos específicos que el app llama. Para encontrar qué métodos:

```javascript
// Frida script para descubrir métodos llamados
if (ObjC.available) {
    var targetClass = ObjC.classes.FrameworkSDK;
    if (targetClass) {
        // Hook -forwardInvocation para ver qué se llama
        var forwardInv = ObjC.classes.NSObject['- forwardInvocation:'];
        if (forwardInv) {
            Interceptor.attach(forwardInv.implementation, {
                onEnter: function(args) {
                    var selector = ObjC.Object(args[2]);
                    console.log("[*] FrameworkSDK called: " + selector);
                }
            });
        }
    }
}
```

### Issue: Still crashes even with stub

**Possible causes**:
1. Framework tiene dependencias en otros frameworks
2. Framework usa Swift ABI incompatible
3. Framework tiene código arm64-only no parcheable

**Fix**: Revisar `references/simforge-compatibility.md` para limitaciones conocidas.

## Quick Templates

### Template 1: Simple RASP Framework Stub

```objc
#import <Foundation/Foundation.h>

@interface RASPFramework : NSObject
+ (instancetype)sharedInstance;
- (void)startMonitoring;
- (void)stopMonitoring;
- (BOOL)isDeviceCompromised;
- (void)registerDelegate:(id)delegate;
@end

@implementation RASPFramework

+ (instancetype)sharedInstance {
    static id instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (void)startMonitoring {}
- (void)stopMonitoring {}
- (BOOL)isDeviceCompromised { return NO; }
- (void)registerDelegate:(id)delegate {}

@end
```

### Template 2: React Native RAP Framework

```objc
#import <Foundation/Foundation.h>

@interface RNAppFramework : NSObject
+ (void)configure;
- (void)startMonitoring;
- (void)triggerAlert;
@end

@implementation RNAppFramework

+ (void)configure {}
- (void)startMonitoring {}
- (void)triggerAlert {}

@end
```

### Template 3: Generic Empty Stub

```objc
#import <Foundation/Foundation.h>

// Agrega clases según lo que necesites
@interface GenericFrameworkClass1 : NSObject
@end

@interface GenericFrameworkClass2 : NSObject
@end

@implementation GenericFrameworkClass1
@end

@implementation GenericFrameworkClass2
@end
```

## Integration with RASP Patterns

Este stub guide complementa `references/rasp-patterns-ios.md`:

1. **Use Pattern 2 (SimForge)** primero para preparar el app
2. **Usa este guide** para crear stubs de frameworks RASP
3. **Apply Pattern 1 (Dylib RASP)** para mantener el app corriendo
4. **Use Pattern 5 (White Screen)** si la UI no renderiza

## Common Framework Stubs

Based on common RASP frameworks found in the wild:

### IOSSecuritySuite

```objc
@interface IOSSecuritySuite : NSObject
+ (BOOL)isJailbroken;
+ (BOOL)isDebuggerAttached;
+ (BOOL)isSimulator;
+ (BOOL)isDeviceMotion.available;
+ (BOOL)isEncrypted;
@end
```

### FreeRASP

```objc
@interface FreeRASPManager : NSObject
+ (void)enableProtection;
+ (BOOL)isDeviceSafe;
@end
```

## Automation Script

```bash
#!/bin/bash
# create_framework_stub.sh "<framework_name>" "<output_dir>"

FRAMEWORK_NAME="$1"
OUTPUT_DIR="$2"

cat > "$OUTPUT_DIR/${FRAMEWORK_NAME}_stub.m" <<'EOF'
#import <Foundation/Foundation.h>

@interface ${FRAMEWORK_NAME} : NSObject
@end

@implementation ${FRAMEWORK_NAME}
@end
EOF

clang -framework Foundation -dynamiclib \
    -o "$OUTPUT_DIR/${FRAMEWORK_NAME}_stub.dylib" \
    "$OUTPUT_DIR/${FRAMEWORK_NAME}_stub.m" \
    -arch arm64 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    -fobjc-arc

echo "Stub creado: $OUTPUT_DIR/${FRAMEWORK_NAME}_stub.dylib"
```

## Verification

### Command Line Check

```bash
# 1. Verificar clases exportadas
nm -gU framework_stub.dylib | grep _OBJC_CLASS

# 2. Verificar arquitectura
file framework_stub.dylib
# Expected: Mach-O 64-bit dynamically linked shared library arm64

# 3. Verificar dependencias
otool -L framework_stub.dylib
# Expected: /System/Library/Frameworks/Foundation.framework, ...
```

### Frida Verification

```javascript
// Verificar que stub se carga
if (ObjC.available) {
    if (ObjC.classes.YourFramework) {
        console.log("[+] Stub cargado correctamente");
    } else {
        console.log("[-] Stub NO encontrado - check export");
    }
}
```

## References

- `references/rasp-patterns-ios.md` - RASP bypass patterns
- `references/simforge-ios-testing.md` - SimForge workflow
- `assets/frida-scripts/white-screen-diagnose-ios.js` - Diagnostic tool
