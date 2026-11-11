# RASP Bypass Patterns - iOS Runtime Application Self-Protection

## Overview

Patrones reutilizables para bypass RASP (Runtime Application Self-Protection) en apps iOS. Estos patrones son genéricos y aplicables a cualquier app, no solo a un caso específico.

## Prerequisites

- **SimForge**: Para ejecutar apps arm64 en iOS Simulator (Apple Silicon)
- **Xcode Command Line Tools**: `clang`, `codesign`, `otool`
- **Frida 17+**: Para instrumentación dinámica

## Pattern 1: Dylib RASP Bypass (C/Objective-C)

### Use Case

App cierra inmediatamente o en segundos (2-8s) cuando detecta simulator/jailbreak. Necesitas mantener el app corriendo para análisis.

### Core Pattern

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Override de funciones de terminación - CRITICAL: infinite loop
void exit(int status) {
    // NO return - el linker no continúa ejecución
    while(1) {
        sleep(1000);
    }
}

void abort(void) {
    while(1) { sleep(1000); }
}

void _exit(int status) {
    while(1) { sleep(1000); }
}

// Constructor - bloquéo de señales
__attribute__((constructor))
static void constructor(void) {
    // Ignorar todas las señales de terminación
    for (int sig = 1; sig < 32; sig++) {
        signal(sig, SIG_IGN);
    }
}
```

### Why This Works

1. **Override directo**: Sobrescribe las funciones en el linker antes de que libc se cargue
2. **Infinite loop**: `while(1)` evita que el linker continúe la cadena de terminación
3. **Signal blocking**: `SIG_IGN` ignora señales que el RASP usa para matar el app

### Compilation

```bash
clang -framework Foundation -dynamiclib -o rasp_bypass.dylib \
    rasp_bypass.m -arch arm64 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path)
```

### Deployment

```bash
# Inyectar dylib al lanzar
simforge launch --bundleid com.target.app --dylib rasp_bypass.dylib
```

### Variations

#### Selective Signal Blocking (preserva UI)

Si la UI se congela o muestra pantalla blanca, intenta bloquear solo señales de terminación:

```c
__attribute__((constructor))
static void constructor(void) {
    // Solo bloquear señales de terminación, NO UI signals
    signal(SIGTERM, SIG_IGN);  // 15
    signal(SIGINT, SIG_IGN);   // 2
    signal(SIGQUIT, SIG_IGN);  // 3
    signal(SIGHUP, SIG_IGN);   // 1
    // Permitir: SIGPIPE(13), SIGUSR1(10), SIGUSR2(12), SIGALRM(14)
}
```

### Techniques to AVOID

❌ **DYLD_INTERPOSE de funciones libc de proceso/señales (para RASP)**: Demasiado agresivo, causa crash 0x6000000
```c
// NO usar para bypass RASP - causará crash
DYLD_INTERPOSE(_exit, my_exit);
```

> **Matiz (no es una prohibición absoluta de `DYLD_INTERPOSE`)**: interponer funciones de
> ciclo de vida del proceso/señales (`exit`, `abort`, `kill`, syscalls) para bypass RASP es
> lo problemático. En cambio, interponer una **función C de fábrica/arranque** para
> bootstrapear un swizzle Obj-C cuando la clase objetivo aún no está registrada **sí es
> estable**. Ejemplo verificado: interponer `MTLCreateSystemDefaultDevice()` para instalar
> un swizzle de `-[MTLSimDevice newHeapWithDescriptor:]` y correr juegos Unity en el
> simulador (ver `references/unity-ios-security.md` y `assets/dylibs/metalheapfix.m`). La
> diferencia: la fábrica se llama una vez en init, devuelves el objeto real y el proceso
> continúa con normalidad.

❌ **dlsym(RTLD_NEXT)**: No funciona en simulator (funciones ya enlazadas)
```c
// NO usar en simulator
original_exit = dlsym(RTLD_NEXT, "exit");
```

## Pattern 2: SimForge Complete App Conversion

### Use Case

Ejecutar app arm64 en iOS Simulator (Apple Silicon). El app se instala pero crashea inmediatamente.

### Problem

SimForge solo parchea frameworks automáticamente, NO el binario principal. Además, TODOS los frameworks necesitan conversión.

### Complete Pattern

```bash
#!/bin/bash
APP_PATH="$1"
APP_NAME=$(basename "$APP_PATH" .app)

# 1. Convertir binario principal
echo "[1/4] Converting main binary..."
simforge convert "$APP_PATH/$APP_NAME"

# 2. Convertir TODOS los frameworks
echo "[2/4] Converting all frameworks..."
for fw in "$APP_PATH/Frameworks"/*.framework; do
    if [ -d "$fw" ]; then
        fw_name=$(basename "$fw" .framework)
        binary="$fw/$fw_name"
        if [ -f "$binary" ]; then
            echo "  - $fw_name"
            simforge convert "$binary" 2>&1 | grep -v "^$"
            codesign --force --sign - "$binary" 2>&1 | grep -v "^$"
        fi
    fi
done

# 3. Re-firmar app bundle
echo "[3/4] Re-signing app bundle..."
codesign --force --sign - "$APP_PATH"

# 4. Verificar
echo "[4/4] Verifying..."
codesign -vvv "$APP_PATH" 2>&1 | tail -2
```

### Why Each Step Matters

1. **Main binary**: SimForge no lo parchea automáticamente
2. **All frameworks**: Cada framework independiente necesita LC_BUILD_VERSION parcheado
3. **Re-sign**: SimForge rompe firma, step 2 rompe más firmas
4. **Verify**: Codesign estricto detecta problemas que -v ignora

### Alternative: vtool for Legacy Frameworks

Si un framework tiene `LC_VERSION_MIN_IPHONEOS` (Xcode antiguo):

```bash
vtool -arch arm64 -set-build-version 7 17.0 17.0 "$binary"
vtool -arch arm64 -set-version-min ios 17.0 17.0 "$binary"
```

**Note**: `ios` NO `iphonesimulator` - ese es un error común.

## Pattern 3: Objective-C Framework Stub

### Use Case

App requiere un framework de RASP (ej: IOSSecuritySuite, FreeRASP, Guardsquare) que solo existe en device, no en simulator. App crashea con "Symbol not found: _OBJC_CLASS_$_FrameworkName".

### Problem

Stub simple (assembly) NO exporta clases Objective-C correctamente. Runtime no encuentra `_OBJC_CLASS_$_`.

### Solution

Usar Objective-C real con clases vacías:

```objc
// framework_stub.m
#import <Foundation/Foundation.h>

// Forward declarations
@interface FrameworkSDK : NSObject
@end

@interface FrameworkListener : NSObject
@end

// Empty implementations - classes exist but do nothing
@implementation FrameworkSDK
@end

@implementation FrameworkListener
@end
```

### Complete Workflow

```bash
# 1. Compilar stub
clang -framework Foundation -dynamiclib \
    -o framework_stub.dylib framework_stub.m \
    -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    -fobjc-arc

# 2. Reemplazar framework original
cp framework_stub.dylib \
   App.app/Frameworks/FrameworkSDK.framework/FrameworkSDK

# 3. Convertir para simulator
simforge convert \
   App.app/Frameworks/FrameworkSDK.framework/FrameworkSDK

# 4. Re-firmar
codesign --force --sign - \
   App.app/Frameworks/FrameworkSDK.framework/FrameworkSDK
codesign --force --sign - App.app
```

### Why This Works

- `@interface` + `@implementation` exporta correctamente `_OBJC_CLASS_$_FrameworkSDK`
- Clases vacías satisfacen el linker sin funcionalidad que detecte
- `-fobjc-arc` asegura compatibilidad con ARC

### Alternative: Inject Stub Functions Only

Si solo necesitas exportar funciones específicas (no clases):

```c
// Exportar símbolos específicos
__attribute__((visibility("default")))
void framework_specific_function(void) {
    // Empty implementation
}
```

## Pattern 4: Frida 17+ Simulator Pattern

### Use Case

Instrumentar app con Frida en iOS Simulator (Apple Silicon, arm64). Scripts que funcionaban en device fallan en simulator.

### Core Pattern Change

Frida 17+ requiere `.implementation` pattern para Objective-C en simulator arm64:

```javascript
// CORRECTO para simulator arm64
if (ObjC.available) {
    var targetClass = ObjC.classes.TargetClass;
    if (targetClass) {
        var method = targetClass['- detectEnvironment'];
        if (method) {
            Interceptor.attach(method.implementation, {
                onEnter: function(args) {
                    console.log("[*] detectEnvironment called");
                },
                onLeave: function(retval) {
                    console.log("[*] Returning: safe");
                    retval.replace(NSFileProtectionComplete);
                }
            });
        }
    }
}
```

### Why dlsym Fails in Simulator

```javascript
// INCORRECTO en simulator - funciones ya enlazadas
var exitPtr = Module.findGlobalExportByName("exit");
if (exitPtr) {
    Interceptor.attach(exitPtr, {...});  // Nunca se llama
}

// CORRECTO - usar .implementation
var exitImpl = ObjC.classes.NSProcessInfo['- exit'];
if (exitImpl) {
    Interceptor.attach(exitImpl.implementation, {...});
}
```

### Simulator-Specific Gotchas

1. **No syscall hooks**: `stat()`, `fopen()`, `fork()` pueden fallar
2. **Use .implementation**: ObjC methods require `.implementation` property
3. **PID attachment**: Usa `-p <PID>` no `-f <bundle>` si el app ya corrió

### Working Template

```javascript
if (ObjC.available) {
    console.log("[*] ObjC runtime available");

    // Patrón 1: Escanear clases RASP
    var raspPatterns = [
        "DetectSDK", "SecuritySDK", "IntegritySDK",
        "FraudSDK", "RiskSDK"
    ];

    for (var className in ObjC.classes) {
        var cls = ObjC.classes[className];
        var classNameLower = className.toLowerCase();

        for (var i = 0; i < raspPatterns.length; i++) {
            if (classNameLower.indexOf(raspPatterns[i].toLowerCase()) !== -1) {
                console.log("[+] Found RASP class: " + className);

                // Hook todos los métodos
                var methods = ObjC.class_getMethodList(cls);
                for (var j = 0; j < methods.length; j++) {
                    var method = cls[methods[j]];
                    if (method && method.implementation) {
                        Interceptor.attach(method.implementation, {
                            onEnter: function(args) {
                                console.log("[-] " + className + " -> " + methods[j]);
                            }
                        });
                    }
                }
                break;
            }
        }
    }
}
```

## Pattern 5: White Screen Diagnosis

### Use Case

App corre estable pero muestra pantalla blanca. Necesitas diagnosticar si es:
- RASP bloqueando UI
- ViewController no seteado
- React Native/Flutter bridge issue
- App en background

### Diagnostic Pattern

Ver en `assets/frida-scripts/white-screen-diagnose-ios.js` para el script completo.

### Key Checks

```javascript
// 1. UIApplication exists
var app = ObjC.classes.UIApplication.sharedApplication();
if (!app) {
    console.log("[-] NO UIApplication - app not initialized");
    return;
}

// 2. Key window exists
var keyWindow = app.keyWindow();
if (!keyWindow) {
    console.log("[-] NO Key Window - app in background or crashed");
    return;
}

// 3. RootViewController seteado
var rootVC = keyWindow.rootViewController();
if (!rootVC) {
    console.log("[-] NO RootViewController - WHITE SCREEN EXPECTED");
    console.log("    Fix: Check if RASP blocks UI initialization");
} else {
    console.log("[+] RootViewController: " + rootVC.$className);

    // 4. View loaded
    var view = rootVC.view();
    if (view) {
        console.log("[+] View exists, frame: " + view.frame());
        console.log("    Hidden: " + view.isHidden() + ", Alpha: " + view.alpha());
    }
}

// 5. Detect framework
if (ObjC.classes.RCTBridge) {
    console.log("[*] React Native detected - check bridge initialization");
}
```

### Common Causes

| Symptom | Likely Cause | Fix |
|----------|--------------|-----|
| NO Key Window | App en background | Check applicationState |
| NO RootViewController | UI initialization blocked | Hook UI initialization |
| View exists but hidden | RASP hiding UI | Hook setHidden:/setAlpha: |
| React Native detected | Bridge not initialized | Hook RCTBridge initialization |

## Decision Tree: Choosing a Pattern

```
┌─────────────────────────────────────────┐
│ App cierra inmediatamente (0-8s)        │
└──────────────────┬──────────────────────┘
                   │
         ¿Falla en simulator pero OK en device?
                   │
         ┌─────────┴─────────┐
         │YES                   │NO
         │                     │
    [Pattern 2]          [Pattern 1]
    SimForge              Dylib RASP
    + Framework Stub     Bypass
         │                     │
         └─────────┬─────────┘
                   │
    ¿App corre pero muestra pantalla blanca?
                   │
         ┌─────────┴─────────┐
         │YES                   │NO
         │                     │
    [Pattern 5]           ¡HECHO!
    White Screen            DONE
    Diagnosis
```

## Quick Reference

| Pattern | Use When | Command |
|---------|----------|---------|
| Dylib RASP Bypass | App cierra rápido | `simforge launch --dylib rasp_bypass.dylib` |
| SimForge Complete | Simulator crash | `bash convert_all.sh App.app` |
| Framework Stub | Symbol not found | `clang -framework Foundation -dynamiclib stub.m` |
| Frida 17+ | Instrumentación falla | Use `.implementation` pattern |
| White Screen | UI no renderiza | `frida -l white-screen-diagnose-ios.js` |

## Testing Checklist

- [ ] Dylib compila sin warnings
- [ ] SimForge convierte todos los frameworks
- [ ] Codesign verification pasa
- [ ] Frida script no tiene errores
- [ ] App corre >10 minutos en simulator
- [ ] UI se renderiza correctamente (no pantalla blanca)

## References

- `references/rasp-framework-stub-guide.md` - Detailed stub creation guide
- `references/simforge-ios-testing.md` - SimForge workflow
- `assets/frida-scripts/white-screen-diagnose-ios.js` - Diagnostic script
- `references/frida-ios-simulator-workflow.md` - Frida 17+ simulator patterns
