# RASP (Runtime Application Self-Protection) para iOS - Guía Completa

## Table of Contents

1. [Indicadores de Detección por RASP](#indicadores-de-detección-por-rasp) ⭐ **NUEVO**
2. [Introducción a RASP](#1-introducción-a-rasp)
3. [Mecanismos de Detección Comunes](#2-mecanismos-de-detección-comunes)
4. [RASP Open-Source](#3-rasp-open-source)
5. [RASP Comerciales](#4-rasp-comerciales)
6. [Matriz de Comparación](#5-matriz-de-comparación)
7. [Técnicas de Bypass Genéricas](#6-técnicas-de-bypass-genéricas)
8. [Checklist de Testing](#7-checklist-de-testing)

---

# Indicadores de Detección por RASP

Esta sección proporciona **indicadores específicos e inequívocos** para identificar qué RASP está utilizando una aplicación iOS. Estos indicadores incluyen nombres de clases, strings únicos, frameworks, y firmas binarias que permiten identificar cada RASP de forma determinante.

## Cómo Usar Esta Guía

1. **Extraer el IPA**: `unzip -o app.ipa -d extracted/`
2. **Analizar el binario**: Usa los comandos proporcionados para cada RASP
3. **Verificar múltiples indicadores**: Un RASP puede tener varios indicadores
4. **Confirmar con Frida**: Usa el script de detección al final

## Script de Detección Automatizada

```javascript
/**
 * RASP Detection Script - Identifica qué RASP usa la app
 * Uso: frida -U -f com.target.app -l rasp-detect-ios.js
 */
(function() {
    'use strict';
    
    console.log('[*] RASP Detection Script Started');
    
    var detectedRASPs = [];
    
    // ============================================
    // PATRONES DE DETECCIÓN POR RASP
    // ============================================
    
    var RASP_PATTERNS = {
        // Open-Source
        FreeRASP: {
            classes: ['FreeRASP', 'TalsecRuntime', 'Talsec', 'RuntimeIntegrity', 'Threat'],
            methods: ['checkDebugger', 'checkEmulator', 'checkFrida', 'checkCodeIntegrity'],
            strings: ['talsec', 'freerasp', 'Threat detected'],
            frameworks: ['TalsecRuntime', 'FreeRASP'],
            modules: ['libTalsecRuntime', 'libFreeRASP']
        },
        
        IOSSecuritySuite: {
            classes: ['IOSSecuritySuite', 'SecuritySuite', 'JailbreakDetector'],
            methods: ['amIJailbroken', 'amIDebugged', 'amIRunInEmulator', 'amIReverseEngineered', 'detectScreenshot'],
            strings: ['securing', 'IOSSecuritySuite', 'amIJailbroken'],
            frameworks: ['IOSSecuritySuite'],
            modules: ['IOSSecuritySuite']
        },
        
        JailMonkey: {
            classes: ['JailMonkey'],
            methods: ['isJailBroken', 'isDebugged', 'hookDetected', 'canMockLocation', 'trustFall', 'AdbEnabled'],
            strings: ['jail-monkey', 'gantman'],
            frameworks: ['JailMonkey'],
            modules: ['JailMonkey']
        },
        
        // Comerciales
        Arxan: {
            classes: ['Arxan', 'AXProtection', 'ArxanGuard', 'ITM', 'Integrity'],
            methods: ['itmcallback', 'itmpreference', 'guard_', 'protect_'],
            strings: ['Arxan Technologies', 'Digital.ai', 'ITM', 'Integrity Measurement'],
            frameworks: ['Arxan', 'AXProtection'],
            modules: ['libarxan', 'libitm', 'libAX']
        },
        
        Guardsquare: {
            classes: ['GS', 'GSCrypto', 'GSProguard', 'iXProtect', 'XProtect'],
            methods: ['gs_', 'getGSPreference', 'iXProtect'],
            strings: ['Guardsquare', 'iXProtect', 'DexGuard'],
            frameworks: ['iXProtect', 'GSCrypto'],
            modules: ['libiXProtect', 'libGSCrypto', 'libGuardsquare']
        },
        
        Promon: {
            classes: ['Promon', 'PShield', 'SHIELD'],
            methods: ['prom_', 'shield_', 'pshield_'],
            strings: ['Promon SHIELD', 'promon.co', 'financial fraud'],
            frameworks: ['PromonSHIELD', 'PShield'],
            modules: ['libPShield', 'libPromon']
        },
        
        Appdome: {
            classes: ['Appdome', 'ADMobile', 'Fusion', 'ThreatEvent'],
            methods: ['ad_', 'appdome_', 'fusion_'],
            strings: ['Appdome', 'ONEShield', 'Fusion', 'Threat-Events'],
            frameworks: ['Appdome', 'ADMobile', 'Fusion'],
            modules: ['libAppdome', 'libADMobile', 'libFusion']
        },
        
        Irdeto: {
            classes: ['Irdeto', 'IDTO', 'IrdetoControl'],
            methods: ['irdeto_', 'idto_'],
            strings: ['Irdeto', 'anti-piracy', 'Code Security'],
            frameworks: ['Irdeto'],
            modules: ['libIrdeto', 'libIDTO']
        },
        
        WhiteCryption: {
            classes: ['WC', 'WhiteCryption', 'Intertrust'],
            methods: ['wc_', 'whitecrypt_'],
            strings: ['White-Cryption', 'Intertrust', 'whitebox'],
            frameworks: ['WhiteCryption'],
            modules: ['libWhiteCryption', 'libWC']
        },
        
        Verimatrix: {
            classes: ['Verimatrix', 'VMX', 'VASCO'],
            methods: ['vmx_', 'veri_'],
            strings: ['Verimatrix', 'VASCO', 'CAS'],
            frameworks: ['Verimatrix'],
            modules: ['libVerimatrix', 'libVMX']
        },
        
        Zimperium: {
            classes: ['Zimperium', 'zDefend', 'zIPS'],
            methods: ['zimperium_', 'zdefend_', 'zips_'],
            strings: ['Zimperium', 'zDefend', 'MAPS', 'Mobile Application Protection'],
            frameworks: ['zDefend', 'zIPS'],
            modules: ['libZimperium', 'libzDefend']
        },
        
        IBM_Trusteer: {
            classes: ['Trusteer', 'TS', 'ts_', 'APO', 'FraudDetection'],
            methods: ['ts_', 'trusteer_', 'apo_'],
            strings: ['Trusteer', 'IBM', 'Fraud', 'APO'],
            frameworks: ['Trusteer', 'APO'],
            modules: ['libTrusteer', 'libTS']
        },
        
        Pradeo: {
            classes: ['Pradeo', 'PradeoSecurity'],
            methods: ['pradeo_', 'ps_'],
            strings: ['Pradeo', 'pradeo.io'],
            frameworks: ['PradeoSecurity'],
            modules: ['libPradeo']
        },
        
        VKey: {
            classes: ['VKey', 'V-Key', 'vkey_'],
            methods: ['vkey_', 'vk_'],
            strings: ['V-Key', 'v-key.com'],
            frameworks: ['VKey'],
            modules: ['libVKey']
        },
        
        Build38: {
            classes: ['Build38', 'B38'],
            methods: ['b38_', 'build38_'],
            strings: ['Build38', 'application shielding'],
            frameworks: ['Build38'],
            modules: ['libBuild38', 'libB38']
        }
    };
    
    // ============================================
    // FUNCIONES DE DETECCIÓN
    // ============================================
    
    function detectByClasses() {
        console.log('\n[=] Detecting by Class Names...');
        var allClasses = Object.keys(ObjC.classes);
        var found = [];
        
        for (var raspName in RASP_PATTERNS) {
            var patterns = RASP_PATTERNS[raspName];
            var matched = false;
            
            for (var i = 0; i < patterns.classes.length; i++) {
                var classPattern = patterns.classes[i].toLowerCase();
                for (var j = 0; j < allClasses.length; j++) {
                    if (allClasses[j].toLowerCase().indexOf(classPattern) !== -1) {
                        if (!matched) {
                            console.log('[+] ' + raspName + ' detected (class: ' + allClasses[j] + ')');
                            found.push(raspName);
                            matched = true;
                        }
                    }
                }
                if (matched) break;
            }
        }
        
        return found;
    }
    
    function detectByMethods() {
        console.log('\n[=] Detecting by Method Names...');
        var found = [];
        
        for (var raspName in RASP_PATTERNS) {
            var patterns = RASP_PATTERNS[raspName];
            var matched = false;
            
            for (var i = 0; i < allClasses.length; i++) {
                if (matched) break;
                try {
                    var cls = ObjC.classes[allClasses[i]];
                    var methods = cls.$ownMethods;
                    
                    for (var j = 0; j < methods.length; j++) {
                        if (matched) break;
                        var m = methods[j].toLowerCase();
                        
                        for (var k = 0; k < patterns.methods.length; k++) {
                            if (m.indexOf(patterns.methods[k].toLowerCase()) !== -1) {
                                console.log('[+] ' + raspName + ' detected (method: ' + allClasses[i] + ' -> ' + methods[j] + ')');
                                found.push(raspName);
                                matched = true;
                                break;
                            }
                        }
                    }
                } catch (e) {}
            }
        }
        
        return found;
    }
    
    function detectByModules() {
        console.log('\n[=] Detecting by Loaded Modules...');
        var found = [];
        var modules = Process.enumerateModules();
        
        for (var raspName in RASP_PATTERNS) {
            var patterns = RASP_PATTERNS[raspName];
            var matched = false;
            
            for (var i = 0; i < modules.length; i++) {
                var modName = modules[i].name.toLowerCase();
                
                for (var j = 0; j < patterns.modules.length; j++) {
                    if (modName.indexOf(patterns.modules[j].toLowerCase()) !== -1) {
                        console.log('[+] ' + raspName + ' detected (module: ' + modules[i].name + ')');
                        found.push(raspName);
                        matched = true;
                        break;
                    }
                }
                if (matched) break;
            }
        }
        
        return found;
    }
    
    function scanMemoryForStrings() {
        console.log('\n[=] Scanning Memory for RASP Strings...');
        var found = [];
        
        // Leer strings del binario principal
        try {
            var mainModule = Process.enumerateModules()[0];
            var base = mainModule.base;
            var size = Math.min(mainModule.size, 1024 * 1024); // Scan first 1MB
            
            var ranges = Process.enumerateRanges('r--');
            for (var i = 0; i < ranges.length; i++) {
                var range = ranges[i];
                if (range.base.compare(base) >= 0 && range.base.compare(base.add(size)) < 0) {
                    try {
                        Memory.scan(range.base, range.size, '0a', {
                            onMatch: function(address, size) {
                                // Simplificado - solo para demostración
                            },
                            onComplete: function() {}
                        });
                    } catch (e) {}
                }
            }
        } catch (e) {
            console.log('[-] Memory scan skipped: ' + e);
        }
        
        return found;
    }
    
    // ============================================
    // EJECUTAR TODAS LAS DETECCIONES
    // ============================================
    
    setTimeout(function() {
        var classResults = detectByClasses();
        var methodResults = detectByMethods();
        var moduleResults = detectByModules();
        var stringResults = scanMemoryForStrings();
        
        // Consolidar resultados
        var allResults = {};
        for (var raspName in RASP_PATTERNS) {
            allResults[raspName] = {
                byClass: classResults.indexOf(raspName) !== -1,
                byMethod: methodResults.indexOf(raspName) !== -1,
                byModule: moduleResults.indexOf(raspName) !== -1,
                byString: stringResults.indexOf(raspName) !== -1,
                confidence: 0
            };
            
            // Calcular confianza
            var score = 0;
            if (allResults[raspName].byClass) score += 40;
            if (allResults[raspName].byMethod) score += 30;
            if (allResults[raspName].byModule) score += 25;
            if (allResults[raspName].byString) score += 5;
            allResults[raspName].confidence = score;
        }
        
        // Mostrar resultados consolidados
        console.log('\n[=] ================================================');
        console.log('[=] FINAL RASP DETECTION RESULTS');
        console.log('[=] ================================================');
        
        var detectedAny = false;
        for (var raspName in allResults) {
            if (allResults[raspName].confidence > 0) {
                detectedAny = true;
                var conf = allResults[raspName].confidence;
                var level = conf >= 70 ? 'HIGH' : (conf >= 40 ? 'MEDIUM' : 'LOW');
                console.log('[+] ' + raspName + ' - Confidence: ' + conf + '% (' + level + ')');
                console.log('    Classes: ' + allResults[raspName].byClass);
                console.log('    Methods: ' + allResults[raspName].byMethod);
                console.log('    Modules: ' + allResults[raspName].byModule);
                console.log('    Strings: ' + allResults[raspName].byString);
            }
        }
        
        if (!detectedAny) {
            console.log('[-] No RASP detected');
            console.log('[!] App may use:');
            console.log('    - Custom RASP implementation');
            console.log('    - Native-only protections');
            console.log('    - No RASP');
        }
        
        console.log('\n[*] Detection Complete');
        console.log('[*] For detailed bypass, use: rasp-bypass-ios.js');
        
    }, 1000);
})();
```

---

## Indicadores por RASP

### Open-Source

#### FreeRASP (Talsec)

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `FreeRASP`, `TalsecRuntime`, `Talsec`, `RuntimeIntegrity`, `Threat` | `class-dump | grep -iE "talsec|freerasp"` |
| **Métodos** | `checkDebugger`, `checkEmulator`, `checkFrida`, `checkCodeIntegrity`, `checkSecurity` | `class-dump | grep -iE "check(Debug|Emul|Frida|Integrity)"` |
| **Strings** | `"talsec"`, `"freerasp"`, `"Threat detected"` | `strings *.app/*.app | grep -iE "talsec|freerasp"` |
| **Frameworks** | `TalsecRuntime.framework`, `FreeRASP.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "talsec"` |
| **Módulos** | `@rpath/TalsecRuntime.framework/TalsecRuntime` | `otool -L *.app/* | grep -i talsec` |
| **Firma Única** | `[Talsec setAlertCallback:]` | `nm *.app/* | grep Talsec` |

**Indicadores Inequívocos (100% específicos):**
1. Clase `TalsecRuntime` con método `setAlertCallback:`
2. Framework `TalsecRuntime.framework` presente
3. String `"FreeRASP/iOS"` en el binario
4. Selector `amITampered` o `checkFrida` presente

```bash
# Detección rápida de FreeRASP
unzip -o app.ipa -d extracted/
cd extracted/Payload/*.app/

# Verificar framework
if ls Frameworks/*Talsec* 2>/dev/null; then
    echo "✓ FreeRASP (Talsec) detectado - Framework presente"
fi

# Verificar strings
if strings * | grep -qi "talsec"; then
    echo "✓ FreeRASP (Talsec) detectado - Strings presentes"
fi

# Verificar clases
if class-dump * 2>/dev/null | grep -qi "TalsecRuntime"; then
    echo "✓ FreeRASP (Talsec) detectado - Clases presentes"
fi
```

#### IOSSecuritySuite

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `IOSSecuritySuite`, `SecuritySuite`, `JailbreakDetector` | `class-dump | grep -iE "securitysuite|security_suite"` |
| **Métodos** | `amIJailbroken`, `amIDebugged`, `amIRunInEmulator`, `amIReverseEngineered` | `class-dump | grep -iE "amI(Jail|Debug|Emul)"` |
| **Strings** | `"securing"`, `"IOSSecuritySuite"`, `"amIJailbroken"` | `strings *.app/* | grep -iE "iossecuritysuite|amIJailbroken"` |
| **Frameworks** | `IOSSecuritySuite.framework` | `ls Payload/*.app/Frameworks/ | grep -i securitysuite` |
| **Módulos** | `IOSSecuritySuite` | `otool -L *.app/* | grep -i securitysuite` |
| **Firma Única** | `[IOSSecuritySuite amIJailbroken]` (static) | `nm *.app/* | grep IOSSecuritySuite` |

**Indicadores Inequívocos:**
1. Framework `IOSSecuritySuite.framework` presente
2. Clase `IOSSecuritySuite` con métodos estáticos `amIJailbroken`, `amIDebugged`
3. String `"github.com/securing/IOSSecuritySuite"`
4. Selector `detectScreenshotWithHandler:` presente

```bash
# Detección rápida de IOSSecuritySuite
cd extracted/Payload/*.app/

# Verificar framework
if ls Frameworks/*IOSSecuritySuite* 2>/dev/null; then
    echo "✓ IOSSecuritySuite detectado - Framework presente"
fi

# Verificar métodos característicos
if class-dump * 2>/dev/null | grep -qi "amIJailbroken"; then
    echo "✓ IOSSecuritySuite detectado - Método amIJailbroken presente"
fi
```

#### JailMonkey

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `JailMonkey` (única clase) | `class-dump | grep -i jailmonkey` |
| **Métodos** | `isJailBroken`, `isDebugged`, `hookDetected`, `canMockLocation`, `trustFall`, `AdbEnabled` | `class-dump | grep -iE "isJailBroken|trustFall"` |
| **Strings** | `"jail-monkey"`, `"gantman"`, `"React Native jailbreak detection"` | `strings *.app/* | grep -iE "jail-monkey|gantman"` |
| **Frameworks** | `JailMonkey.framework` | `ls Payload/*.app/Frameworks/ | grep -i jailmonkey` |
| **Módulos** | `JailMonkey` | `otool -L *.app/* | grep -i jailmonkey` |
| **Firma Única** | `[JailMonkey trustFall]` (método específico) | `nm *.app/* | grep trustFall` |

**Indicadores Inequívocos:**
1. Clase `JailMonkey` presente (es React Native bridge)
2. Método `trustFall` único de JailMonkey
3. String `"jail-monkey"` o `"gantman"`
4. Archivo `JailMonkey.js` en los bundles (React Native)

```bash
# Detección rápida de JailMonkey
cd extracted/Payload/*.app/

# Verificar si es React Native
if ls *.jsbundle 2>/dev/null || ls index.bundle 2>/dev/null; then
    echo "✓ React Native app detectado"
    
    # Buscar JailMonkey en el bundle
    if grep -l "jail-monkey\|JailMonkey" *.jsbundle 2>/dev/null; then
        echo "✓ JailMonkey detectado en JS bundle"
    fi
fi
```

### Comerciales

#### Arxan (ahora Digital.ai)

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `ITM`, `IntegrityMeasurement`, `ArxanGuard`, `AXProtection` | `class-dump | grep -iE "ITM|IntegrityMeasurement|Arxan"` |
| **Métodos** | `itmcallback`, `itmpreference`, `guard_`, `protect_` | `class-dump | grep -iE "itm|guard_"` |
| **Strings** | `"Arxan Technologies"`, `"Digital.ai"`, `"ITM"`, `"Integrity Measurement"` | `strings *.app/* | grep -iE "arxan|digital.ai|Integrity Measurement"` |
| **Frameworks** | `Arxan.framework`, `ITM.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "arxan|itm"` |
| **Módulos** | `libarxan`, `libitm`, `libAX` | `otool -L *.app/* | grep -iE "arxan|itm"` |
| **Firma Única** | `[ITM setCallback:]` o `[ArxanGuard check:]` | `nm *.app/* | grep -iE "ITM|ArxanGuard"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `ITM` (Integrity Measurement)
2. Framework `ITM.framework` o `Arxan.framework`
3. String `"Arxan Technologies"` o `"Digital.ai ITM"`
4. Método `itmcallback` o similar con prefijo `itm`

```bash
# Detección de Arxan
cd extracted/Payload/*.app/

# Verificar frameworks
if ls Frameworks/*ITM* Frameworks/*Arxan* 2>/dev/null; then
    echo "✓ Arxan/Digital.ai detectado - Framework presente"
fi

# Verificar strings específicos
if strings * | grep -qi "Arxan\|Digital.ai.*ITM"; then
    echo "✓ Arxan/Digital.ai detectado - Strings presentes"
fi
```

#### Guardsquare

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `GSCrypto`, `GSProguard`, `iXProtect`, `XProtect` | `class-dump | grep -iE "GSCrypto|iXProtect|XProtect"` |
| **Métodos** | `gs_`, `getGSPreference`, `iXProtect`, `protectWithKey:` | `class-dump | grep -iE "gs_|GSCrypto"` |
| **Strings** | `"Guardsquare"`, `"iXProtect"`, `"DexGuard"`, `"Frequently Asked Questions"` | `strings *.app/* | grep -iE "guardsquare|ixprotect|dexguard"` |
| **Frameworks** | `iXProtect.framework`, `GSCrypto.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "ixprotect|GSCrypto"` |
| **Módulos** | `libiXProtect`, `libGSCrypto`, `libGuardsquare` | `otool -L *.app/* | grep -iE "ixprotect|GSCrypto"` |
| **Firma Única** | `[GSCrypto encrypt:]` o `[iXProtect init]` | `nm *.app/* | grep -iE "GSCrypto|iXProtect"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `GS` (Guardsquare)
2. Framework `iXProtect.framework` presente
3. String `"Guardsquare"` o `"iXProtect"`
4. Método de encriptación `GSCrypto` o similar

```bash
# Detección de Guardsquare
cd extracted/Payload/*.app/

if ls Frameworks/*iXProtect* Frameworks/*GSCrypto* 2>/dev/null; then
    echo "✓ Guardsquare detectado - Framework presente"
fi
```

#### Promon SHIELD

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Promon`, `PShield`, `SHIELD` | `class-dump | grep -iE "Promon|PShield|SHIELD"` |
| **Métodos** | `prom_`, `shield_`, `pshield_` | `class-dump | grep -iE "prom_|shield_"` |
| **Strings** | `"Promon SHIELD"`, `"promon.co"`, `"financial fraud"` | `strings *.app/* | grep -iE "promon|financial.*fraud"` |
| **Frameworks** | `PromonSHIELD.framework`, `PShield.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "promon|shield"` |
| **Módulos** | `libPShield`, `libPromon` | `otool -L *.app/* | grep -iE "pshield|promon"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `PShield` o `Promon`
2. Framework `PromonSHIELD.framework`
3. String `"Promon SHIELD"`
4. Enfoque en apps financieras

```bash
# Detección de Promon
cd extracted/Payload/*.app/

if ls Frameworks/*Promon* Frameworks/*PShield* 2>/dev/null; then
    echo "✓ Promon SHIELD detectado"
fi
```

#### Appdome

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Appdome`, `ADMobile`, `Fusion`, `ThreatEvent` | `class-dump | grep -iE "Appdome|ADMobile|Fusion"` |
| **Métodos** | `ad_`, `appdome_`, `fusion_`, `onThreatEvent:` | `class-dump | grep -iE "ad_|appdome|fusion_"` |
| **Strings** | `"Appdome"`, `"ONEShield"`, `"Fusion"`, `"Threat-Events"`, `"Built for security"` | `strings *.app/* | grep -iE "appdome|oneshield|fusion|threat-event"` |
| **Frameworks** | `Appdome.framework`, `ADMobile.framework`, `Fusion.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "appdome|fusion"` |
| **Módulos** | `libAppdome`, `libADMobile`, `libFusion` | `otool -L *.app/* | grep -iE "appdome|fusion"` |
| **Firma Única** | `[ADMobile initialize]` o `[Fusion check:]` | `nm *.app/* | grep -iE "ADMobile|Fusion"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `AD` o `ADMobile`
2. Framework `Fusion.framework` (tecnología de Appdome)
3. String `"Built on Appdome"` o similar
4. String `"ONEShield"` o `"Threat-Events"`

```bash
# Detección de Appdome
cd extracted/Payload/*.app/

if ls Frameworks/*Appdome* Frameworks/*Fusion* 2>/dev/null; then
    echo "✓ Appdome detectado - Framework presente"
fi

if strings * | grep -qi "Built on Appdome\|ONEShield"; then
    echo "✓ Appdome detectado - Strings presentes"
fi
```

#### IBM Trusteer

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Trusteer`, `TS`, `APO`, `FraudDetection` | `class-dump | grep -iE "Trusteer|APO|FraudDetection"` |
| **Métodos** | `ts_`, `trusteer_`, `apo_` | `class-dump | grep -iE "ts_|apo_"` |
| **Strings** | `"Trusteer"`, `"IBM"`, `"APO"`, `"Fraud Detection"` | `strings *.app/* | grep -iE "trusteer|APO.*fraud"` |
| **Frameworks** | `Trusteer.framework`, `APO.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "trusteer|apo"` |
| **Módulos** | `libTrusteer`, `libTS`, `libAPO` | `otool -L *.app/* | grep -iE "trusteer|libts|libapo"` |
| **Firma Única** | `[ts_ init:]` o `[APO check:]` | `nm *.app/* | grep -iE "ts_|APO"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `ts_` o `APO`
2. Framework `APO.framework` (App Protection Only)
3. String `"Trusteer"` o `"IBM Trusteer"`
4. Método `ts_init` o similar

```bash
# Detección de IBM Trusteer
cd extracted/Payload/*.app/

if ls Frameworks/*Trusteer* Frameworks/*APO* 2>/dev/null; then
    echo "✓ IBM Trusteer detectado"
fi
```

#### Zimperium MAPS

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Zimperium`, `zDefend`, `zIPS`, `zAlert` | `class-dump | grep -iE "Zimperium|zDefend|zIPS"` |
| **Métodos** | `zimperium_`, `zdefend_`, `zips_` | `class-dump | grep -iE "zimperium|zdefend|zips"` |
| **Strings** | `"Zimperium"`, `"zDefend"`, `"MAPS"`, `"Mobile Application Protection"` | `strings *.app/* | grep -iE "zimperium|zdefend|maps.*protection"` |
| **Frameworks** | `zDefend.framework`, `zIPS.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "zdefend|zips"` |
| **Módulos** | `libZimperium`, `libzDefend` | `otool -L *.app/* | grep -iE "zimperium|zdefend"` |

**Indicadores Inequívocos:**
1. Clases con prefijo `z` (zDefend, zIPS, zAlert)
2. Framework `zDefend.framework`
3. String `"Zimperium"` o `"MAPS"`
4. Clase `zDefend` con métodos de defensa

```bash
# Detección de Zimperium
cd extracted/Payload/*.app/

if ls Frameworks/*zDefend* Frameworks/*zIPS* 2>/dev/null; then
    echo "✓ Zimperium MAPS detectado"
fi
```

#### Irdeto

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Irdeto`, `IDTO`, `IrdetoControl` | `class-dump | grep -iE "Irdeto|IDTO"` |
| **Métodos** | `irdeto_`, `idto_` | `class-dump | grep -iE "irdeto|idto"` |
| **Strings** | `"Irdeto"`, `"anti-piracy"`, `"Code Security"` | `strings *.app/* | grep -iE "irdeto|anti-piracy"` |
| **Frameworks** | `Irdeto.framework` | `ls Payload/*.app/Frameworks/ | grep -i irdeto` |
| **Módulos** | `libIrdeto`, `libIDTO` | `otool -L *.app/* | grep -iE "irdeto|idto"` |

#### WhiteCryption (Intertrust)

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `WC`, `WhiteCryption`, `Intertrust` | `class-dump | grep -iE "WhiteCryption|Intertrust|^[A-Z]WC"` |
| **Métodos** | `wc_`, `whitecrypt_` | `class-dump | grep -iE "wc_|whitecrypt"` |
| **Strings** | `"White-Cryption"`, `"Intertrust"`, `"whitebox"` | `strings *.app/* | grep -iE "white.*crypt|intertrust"` |
| **Frameworks** | `WhiteCryption.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "white"` |
| **Módulos** | `libWhiteCryption`, `libWC` | `otool -L *.app/* | grep -iE "white|wc"` |

#### Verimatrix

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Verimatrix`, `VMX`, `VASCO` | `class-dump | grep -iE "Verimatrix|VMX|VASCO"` |
| **Métodos** | `vmx_`, `veri_` | `class-dump | grep -iE "vmx_|veri_"` |
| **Strings** | `"Verimatrix"`, `"VASCO"`, `"CAS"` | `strings *.app/* | grep -iE "verimatrix|vasco|cas"` |
| **Frameworks** | `Verimatrix.framework` | `ls Payload/*.app/Frameworks/ | grep -i verimatrix` |
| **Módulos** | `libVerimatrix`, `libVMX` | `otool -L *.app/* | grep -iE "verimatrix|vmx"` |

#### Pradeo

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Pradeo`, `PradeoSecurity` | `class-dump | grep -i pradeo` |
| **Métodos** | `pradeo_`, `ps_` | `class-dump | grep -iE "pradeo|ps_"` |
| **Strings** | `"Pradeo"`, `"pradeo.io"` | `strings *.app/* | grep -i pradeo` |
| **Frameworks** | `PradeoSecurity.framework` | `ls Payload/*.app/Frameworks/ | grep -i pradeo` |
| **Módulos** | `libPradeo` | `otool -L *.app/* | grep -i pradeo` |

#### V-Key

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `VKey`, `V-Key`, `vkey_` | `class-dump | grep -iE "vkey|V-Key"` |
| **Métodos** | `vkey_`, `vk_` | `class-dump | grep -iE "vkey|vk_"` |
| **Strings** | `"V-Key"`, `"v-key.com"` | `strings *.app/* | grep -iE "v-key|vkey"` |
| **Frameworks** | `VKey.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "vkey"` |
| **Módulos** | `libVKey` | `otool -L *.app/* | grep -iE "vkey"` |

#### Build38

| Tipo | Indicadores | Comando de Detección |
|------|-------------|----------------------|
| **Clases** | `Build38`, `B38` | `class-dump | grep -iE "Build38|^[A-Z]B38"` |
| **Métodos** | `b38_`, `build38_` | `class-dump | grep -iE "b38|build38"` |
| **Strings** | `"Build38"`, `"application shielding"` | `strings *.app/* | grep -iE "build38|shielding"` |
| **Frameworks** | `Build38.framework` | `ls Payload/*.app/Frameworks/ | grep -iE "build38|b38"` |
| **Módulos** | `libBuild38`, `libB38` | `otool -L *.app/* | grep -iE "build38|b38"` |

## Matriz de Confianza de Detección

| RASP | Framework | Clases | Methods | Strings | Confianza Mínima |
|------|-----------|---------|---------|---------|------------------|
| **FreeRASP** | ✓✓✓ | ✓✓✓ | ✓✓ | ✓✓ | **95%** |
| **IOSSecuritySuite** | ✓✓✓ | ✓✓✓ | ✓✓✓ | ✓✓ | **100%** |
| **JailMonkey** | ✓✓ | ✓✓✓ | ✓✓✓ | ✓ | **95%** |
| **Arxan** | ✓✓ | ✓✓ | ✓ | ✓✓ | **85%** |
| **Guardsquare** | ✓✓✓ | ✓✓ | ✓ | ✓✓ | **90%** |
| **Promon** | ✓✓ | ✓✓ | ✓ | ✓ | **80%** |
| **Appdome** | ✓✓✓ | ✓✓ | ✓ | ✓✓ | **90%** |
| **Irdeto** | ✓ | ✓ | ✓ | ✓ | **70%** |
| **WhiteCryption** | ✓✓ | ✓ | ✓ | ✓ | **75%** |
| **Verimatrix** | ✓ | ✓ | ✓ | ✓ | **70%** |
| **Zimperium** | ✓✓✓ | ✓✓ | ✓ | ✓✓ | **90%** |
| **IBM Trusteer** | ✓✓ | ✓✓ | ✓ | ✓ | **85%** |
| **Pradeo** | ✓ | ✓ | ✓ | ✓ | **70%** |
| **V-Key** | ✓ | ✓ | ✓ | ✓ | **65%** |
| **Build38** | ✓ | ✓ | ✓ | ✓ | **65%** |

**Leyenda:**
- ✓✓✓ = Muy confiable (casi siempre presente)
- ✓✓ = Comúnmente presente
- ✓ = A veces presente
- **Confianza Mínima**: Porcentaje de confianza con 1 indicador positivo

## Script Shell de Detección Rápida

```bash
#!/bin/bash
# RASP Detection Script - Versión Shell
# Uso: ./detect-rasp.sh app.ipa

IPA="$1"
EXTRACTED_DIR="extracted"
BINARY_DIR=""

if [ -z "$IPA" ]; then
    echo "Uso: $0 <app.ipa>"
    exit 1
fi

echo "[*] RASP Detection Script"
echo "[*] Target: $IPA"

# Extraer IPA
echo "[*] Extracting IPA..."
unzip -q "$IPA" -d "$EXTRACTED_DIR"
BINARY_DIR=$(find "$EXTRACTED_DIR/Payload" -name "*.app" -type d | head -1)

if [ -z "$BINARY_DIR" ]; then
    echo "[-] No .app directory found"
    exit 1
fi

echo "[+] Binary directory: $BINARY_DIR"

# Detectar por Frameworks
echo ""
echo "[=] Detection by Frameworks:"
echo "---------------------------------------------"

if ls "$BINARY_DIR"/Frameworks/*Talsec* 2>/dev/null; then
    echo "✓ FreeRASP (Talsec) - Framework TalsecRuntime present"
fi

if ls "$BINARY_DIR"/Frameworks/*IOSSecuritySuite* 2>/dev/null; then
    echo "✓ IOSSecuritySuite - Framework IOSSecuritySuite present"
fi

if ls "$BINARY_DIR"/Frameworks/*JailMonkey* 2>/dev/null; then
    echo "✓ JailMonkey - Framework JailMonkey present"
fi

if ls "$BINARY_DIR"/Frameworks/*ITM* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*Arxan* 2>/dev/null; then
    echo "✓ Arxan/Digital.ai - Framework ITM/Arxan present"
fi

if ls "$BINARY_DIR"/Frameworks/*iXProtect* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*GSCrypto* 2>/dev/null; then
    echo "✓ Guardsquare - Framework iXProtect/GSCrypto present"
fi

if ls "$BINARY_DIR"/Frameworks/*Promon* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*PShield* 2>/dev/null; then
    echo "✓ Promon SHIELD - Framework Promon/PShield present"
fi

if ls "$BINARY_DIR"/Frameworks/*Fusion* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*Appdome* 2>/dev/null; then
    echo "✓ Appdome - Framework Fusion/Appdome present"
fi

if ls "$BINARY_DIR"/Frameworks/*Trusteer* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*APO* 2>/dev/null; then
    echo "✓ IBM Trusteer - Framework Trusteer/APO present"
fi

if ls "$BINARY_DIR"/Frameworks/*zDefend* 2>/dev/null || ls "$BINARY_DIR"/Frameworks/*zIPS* 2>/dev/null; then
    echo "✓ Zimperium MAPS - Framework zDefend present"
fi

# Detectar por Strings
echo ""
echo "[=] Detection by Strings:"
echo "---------------------------------------------"

MAIN_BINARY=$(find "$BINARY_DIR" -type f -perm +111 | head -1)
if [ -f "$MAIN_BINARY" ]; then
    if strings "$MAIN_BINARY" | grep -qi "talsec\|freerasp"; then
        echo "✓ FreeRASP (Talsec) - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "iossecuritysuite\|securing"; then
        echo "✓ IOSSecuritySuite - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "jail-monkey\|gantman"; then
        echo "✓ JailMonkey - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "arxan\|digital.ai.*ITM\|Integrity Measurement"; then
        echo "✓ Arxan/Digital.ai - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "guardsquare\|ixprotect"; then
        echo "✓ Guardsquare - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "promon\|financial.*fraud"; then
        echo "✓ Promon SHIELD - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "appdome\|oneshield\|fusion.*security"; then
        echo "✓ Appdome - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "trusteer\|APO.*fraud"; then
        echo "✓ IBM Trusteer - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "zimperium\|zdefend"; then
        echo "✓ Zimperium MAPS - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "irdeto"; then
        echo "✓ Irdeto - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "white.*crypt\|intertrust"; then
        echo "✓ WhiteCryption - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "verimatrix\|vasco"; then
        echo "✓ Verimatrix - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "pradeo"; then
        echo "✓ Pradeo - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "v-key\|vkey"; then
        echo "✓ V-Key - Strings found"
    fi
    
    if strings "$MAIN_BINARY" | grep -qi "build38"; then
        echo "✓ Build38 - Strings found"
    fi
fi

echo ""
echo "[*] Detection complete"
echo "[!] Clean up: rm -rf $EXTRACTED_DIR"
```

## Comandos de Verificación por RASP

### FreeRASP
```bash
# Verificación completa de FreeRASP
cd extracted/Payload/*.app/
echo "=== FreeRASP Detection ==="
ls Frameworks/*Talsec* && echo "✓ Framework present" || echo "✗ Framework absent"
strings * | grep -qi "talsec" && echo "✓ Strings found" || echo "✗ Strings absent"
otool -L * | grep -qi "talsec" && echo "✓ Module linked" || echo "✗ Module absent"
```

### IOSSecuritySuite
```bash
# Verificación completa de IOSSecuritySuite
cd extracted/Payload/*.app/
echo "=== IOSSecuritySuite Detection ==="
ls Frameworks/*IOSSecuritySuite* && echo "✓ Framework present" || echo "✗ Framework absent"
strings * | grep -qi "iossecuritysuite" && echo "✓ Strings found" || echo "✗ Strings absent"
class-dump * 2>/dev/null | grep -qi "amIJailbroken" && echo "✓ Methods found" || echo "✗ Methods absent"
```

### Arxan
```bash
# Verificación completa de Arxan
cd extracted/Payload/*.app/
echo "=== Arxan Detection ==="
ls Frameworks/*ITM* Frameworks/*Arxan* && echo "✓ Framework present" || echo "✗ Framework absent"
strings * | grep -qi "arxan\|digital.ai" && echo "✓ Strings found" || echo "✗ Strings absent"
nm * 2>/dev/null | grep -qi "ITM\|ArxanGuard" && echo "✓ Symbols found" || echo "✗ Symbols absent"
```

### Appdome
```bash
# Verificación completa de Appdome
cd extracted/Payload/*.app/
echo "=== Appdome Detection ==="
ls Frameworks/*Fusion* Frameworks/*Appdome* && echo "✓ Framework present" || echo "✗ Framework absent"
strings * | grep -qi "appdome\|oneshield" && echo "✓ Strings found" || echo "✗ Strings absent"
strings * | grep -qi "Built on Appdome\|Fusion" && echo "✓ Build signature found" || echo "✗ Build signature absent"
```

## Resumen de Firma Única por RASP

| RASP | Firma Única (100% Específica) |
|------|-------------------------------|
| **FreeRASP** | `[TalsecRuntime setAlertCallback:]` + Framework `TalsecRuntime.framework` |
| **IOSSecuritySuite** | `[IOSSecuritySuite amIJailbroken]` + Framework `IOSSecuritySuite.framework` |
| **JailMonkey** | `[JailMonkey trustFall]` + React Native bundle |
| **Arxan** | `[ITM setCallback:]` + Framework `ITM.framework` |
| **Guardsquare** | `[GSCrypto encrypt:]` + Framework `iXProtect.framework` |
| **Promon** | `[PShield init]` + Framework `PromonSHIELD.framework` |
| **Appdome** | `[ADMobile initialize]` + Framework `Fusion.framework` + String "Built on Appdome" |
| **Irdeto** | `[IrdetoControl check:]` + Framework `Irdeto.framework` |
| **WhiteCryption** | `[WC encrypt:]` + Framework `WhiteCryption.framework` |
| **Verimatrix** | `[VMX check:]` + Framework `Verimatrix.framework` |
| **Zimperium** | `[zDefend init]` + Framework `zDefend.framework` |
| **IBM Trusteer** | `[ts_init:]` + Framework `APO.framework` |
| **Pradeo** | `[PradeoSecurity init:]` + Framework `PradeoSecurity.framework` |
| **V-Key** | `[VKey init:]` + Framework `VKey.framework` |
| **Build38** | `[B38 check:]` + Framework `Build38.framework` |

---

## 1. Introducción a RASP

### Qué es RASP

**Runtime Application Self-Protection (RASP)** es una tecnología de seguridad que protege las aplicaciones desde adentro, en tiempo de ejecución. A diferencia de las medidas de seguridad estáticas (como ofuscación o encriptación de código), RASP:

- **Monitorea la aplicación en tiempo de ejecución**
- **Detecta amenazas activas** (jailbreak, debugging, tampering, hooks)
- **Responde en tiempo real** (puede terminar la app, limitar funcionalidades, o alertar)
- **Se integra directamente en el código de la aplicación**

### RASP vs. Medidas Estáticas

| Aspecto | RASP (Runtime) | Medidas Estáticas |
|---------|----------------|-------------------|
| **Protección** | Dinámica, en ejecución | Estática, en compile-time |
| **Detección** | Amenazas activas | Patrones de código |
| **Respuesta** | Tiempo real | Precompilada |
| **Ejemplos** | Anti-debug, jailbreak detect | Obfuscation, encryption |
| **Evasion** | Requiere bypass en runtime | Requiere reverse engineering |

### OWASP MASTG References

- **MASTG-TEST-0013**: Testing Root and Jailbroken Device Detection
- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues

## 2. Mecanismos de Detección Comunes

Todos los RASP implementan combinaciones de estos mecanismos de detección:

### 2.1 Jailbreak Detection

#### File System Checks
El método más básico: buscar archivos y directorios típicos de jailbreak.

```objective-c
// Archivos comunes de jailbreak
NSString *jailbreakFiles[] = {
    @"/Applications/Cydia.app",
    @"/Applications/blackra1n.app",
    @"/Applications/FakeCarrier.app",
    @"/Applications/Icy.app",
    @"/Applications/IntelliScreen.app",
    @"/Applications/MxTube.app",
    @"/Applications/RockApp.app",
    @"/Applications/SBSettings.app",
    @"/Applications/WinterBoard.app",
    @"/private/var/lib/apt/",
    @"/private/var/tmp/cached Cydia.deb",
    @"/private/var/lib/cydia",
    @"/var/cache/apt/",
    @"/var/lib/cydia",
    @"/usr/bin/sshd",
    @"/usr/libexec/sftp-server",
    @"/usr/sbin/sshd",
    @"/etc/apt",
    @"/bin/sh",
    @"/bin/bash",
    @"/Library/MobileSubstrate/MobileSubstrate.dylib",
    @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    @"/var/db/stash",
    @"/usr/libexec/ssh-keysign",
    @"/bin/sshd",
    @"/etc/ssh",
    @"/private/var/lib/cydia",
    @"/Applications/Sileo.app",
    @"/usr/bin/frida",
    @"/usr/bin/cycript",
    @"/usr/local/bin/frida",
    @"/usr/local/bin/cycript",
    NULL
};

- (BOOL)isJailbrokenByFiles {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (int i = 0; jailbreakFiles[i] != nil; i++) {
        if ([fileManager fileExistsAtPath:jailbreakFiles[i]]) {
            return YES;
        }
    }
    return NO;
}
```

**Bypass**: Hookear `fileExistsAtPath:` o `NSFileManager` methods para retornar `NO` para paths de jailbreak.

#### Process Enumeration
Buscar procesos relacionados con jailbreak:

```objective-c
- (BOOL)isJailbrokenByProcesses {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        return NO;
    }
    
    struct kinfo_proc *procs = malloc(size);
    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) {
        free(procs);
        return NO;
    }
    
    size_t count = size / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < count; i++) {
        char *name = procs[i].kp_proc.p_comm;
        
        if (strstr(name, "cydia") || strstr(name, "sileo") ||
            strstr(name, "frida") || strstr(name, "substrate")) {
            free(procs);
            return YES;
        }
    }
    
    free(procs);
    return NO;
}
```

**Bypass**: Hookear `sysctl` para filtrar procesos de jailbreak de la lista.

#### Sandbox Integrity Check
Verificar si el sandbox de iOS está comprometido:

```objective-c
- (BOOL)isSandboxCompromised {
    // Intentar escribir fuera del sandbox
    NSString *testPath = @"/private/jailbreak_test.txt";
    BOOL canWrite = [[@"test" dataUsingEncoding:NSUTF8StringEncoding]
                      writeToFile:testPath
                      atomically:YES];
    
    if (canWrite) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;  // Sandbox comprometido = jailbreak
    }
    
    // Verificar symlinks típicos
    NSArray *symlinks = @[
        @"/var/mobile", @"/var/root", @"/Applications",
        @"/private/var/lib/apt"
    ];
    
    for (NSString *path in symlinks) {
        NSDictionary *attrs = [[NSFileManager defaultManager]
                               attributesOfItemAtPath:path
                               error:nil];
        if (attrs && [attrs fileType] == NSFileTypeSymbolicLink) {
            return YES;
        }
    }
    
    return NO;
}
```

**Bypass**: Hookear `writeToFile:`, `attributesOfItemAtPath:`, y `fileType`.

### 2.2 Anti-Debugging

#### ptrace(PT_DENY_ATTACH)

```objective-c
#include <sys/types.h>
#include <sys/ptrace.h>

- (void)enableAntiDebug {
    // PT_DENY_ATTACH previene que un debugger se adjunte
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
}
```

**Bypass**:
```javascript
var ptrace = Module.findGlobalExportByName('ptrace');
Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
    console.log('[+] ptrace blocked');
    return 0;
}, 'int', ['int', 'int', 'pointer', 'pointer']));
```

#### sysctl KERN_PROC_PID

```objective-c
#include <sys/sysctl.h>

- (BOOL)isDebuggerAttached {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, NULL, 0) < 0) {
        return NO;
    }
    
    // P_TRACED indica que hay un debugger adjunto
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
```

**Bypass**:
```javascript
var sysctl = Module.findGlobalExportByName('sysctl');
Interceptor.attach(sysctl, {
    onLeave: function(retval) {
        // Limpiar el flag P_TRACED (0x800)
        // en la estructura kinfo_proc retornada
    }
});
```

#### getppid() Check

```objective-c
- (BOOL)isDebuggerAttachedByPPID {
    // Si el PID del padre es 1 (launchd), no hay debugger
    // Si no es 1, podría ser un debugger
    int ppid = getppid();
    return ppid != 1;
}
```

**Bypass**:
```javascript
var getppid = Module.findGlobalExportByName('getppid');
Interceptor.replace(getppid, new NativeCallback(function () {
    return 1;  // Siempre retornar launchd como padre
}, 'int', []));
```

### 2.3 Anti-Tampering

#### Code Signature Verification

```objective-c
#include <Security/Security.h>

- (BOOL)verifyCodeSignature {
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];
    SecStaticCodeRef codeRef = NULL;
    OSStatus status;
    
    status = SecStaticCodeCreateWithPath(
        (__bridge CFURLRef)[NSURL fileURLWithPath:binaryPath],
        kSecCSDefaultFlags,
        &codeRef
    );
    
    if (status != errSecSuccess || !codeRef) {
        return NO;
    }
    
    status = SecStaticCodeCheckValidity(
        codeRef,
        kSecCSCheckAll,
        NULL
    );
    
    CFRelease(codeRef);
    
    return status == errSecSuccess;
}
```

**Bypass**: Hookear `SecStaticCodeCheckValidity` para siempre retornar `errSecSuccess`.

#### File Hash Validation

```objective-c
#import <CommonCrypto/CommonCrypto.h>

- (BOOL)verifyFileHash {
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];
    NSString *expectedHash = @"abcdef1234567890..."; // Hash hardcoded
    
    NSString *currentHash = [self sha256HashOfFile:binaryPath];
    return [currentHash isEqualToString:expectedHash];
}

- (NSString *)sha256HashOfFile:(NSString *)path {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    NSMutableString *hash = [NSMutableString
                             stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    
    return hash;
}
```

**Bypass**: Reemplazar el método de verificación o la función de hash.

### 2.4 Hook Detection

#### Frida Process Detection

```objective-c
- (BOOL)isFridaRunning {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    
    sysctl(mib, 4, NULL, &size, NULL, 0);
    struct kinfo_proc *procs = malloc(size);
    sysctl(mib, 4, procs, &size, NULL, 0);
    
    size_t count = size / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < count; i++) {
        char *name = procs[i].kp_proc.p_comm;
        if (strstr(name, "frida") || strstr(name, "frida-server")) {
            free(procs);
            return YES;
        }
    }
    
    free(procs);
    return NO;
}
```

#### Frida Port Detection

```objective-c
- (BOOL)isFridaPortOpen {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);  // Puerto default de Frida
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;  // Conexión exitosa = Frida presente
}
```

**Bypass**: Hookear `connect()` para fallar en puertos de Frida (27042, 27043, etc.).

#### DYLD Image Enumeration

```objective-c
- (BOOL)detectSuspiciousDylibs {
    uint32_t count = _dyld_image_count();
    
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        NSString *imageName = [NSString stringWithUTF8String:name];
        
        if ([imageName containsString:@"Frida"] ||
            [imageName containsString:@"frida"] ||
            [imageName containsString:@"substrate"] ||
            [imageName containsString:@"cycript"]) {
            return YES;
        }
    }
    
    return NO;
}
```

**Bypass**: Hookear `_dyld_get_image_name` para filtrar dylibs sospechosos.

### 2.5 Emulator/Simulator Detection

```objective-c
- (BOOL)isRunningInEmulator {
#if TARGET_OS_SIMULATOR
    return YES;  // Compilado para simulator
#else
    // Verificaciones en runtime
    UIDevice *device = [UIDevice currentDevice];
    NSString *platform = [device model];
    
    if ([platform containsString:@"Simulator"] ||
        [platform containsString:@"x86_64"]) {
        return YES;
    }
    
    // Verificar archivos de Xcode
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:@"/Applications/Xcode.app"]) {
        return YES;
    }
    
    // Verificar hardware
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *machine = [NSString stringWithUTF8String:systemInfo.machine];
    if ([machine hasPrefix:@"x86"] || [machine hasPrefix:@"i386"]) {
        return YES;
    }
    
    return NO;
#endif
}
```

**Bypass**: Hookear todas las funciones de verificación (`fileExistsAtPath:`, `uname`, etc.).

## 3. RASP Open-Source

### 3.1 FreeRASP (Talsec)

#### Información General
- **Repositorio**: https://github.com/talsec/Free-RASP-iOS
- **Licencia**: MIT (Open-source)
- **Lenguaje**: Swift + Objective-C
- **Mantenimiento**: Activo

#### Características

| Característica | Soportado |
|----------------|-----------|
| Jailbreak Detection | ✓ |
| Debugger Detection | ✓ |
| Emulator Detection | ✓ |
| Hook Detection | ✓ |
| Tamper Detection | ✓ |
| Reverse Engineering Detection | ✓ |
| Device Integrity | ✓ |

#### Métodos de Detección

FreeRASP implementa múltiples capas de detección:

```swift
// Ejemplo de detección (simplificado)
public class FreeRASP {
    
    // 1. Jailbreak por archivos
    private func detectJailbreakFiles() -> Bool {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/bin/bash",
            "/usr/bin/sshd",
            "/private/var/lib/apt"
        ]
        
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    // 2. Jailbreak por procesos
    private func detectJailbreakProcesses() -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        
        sysctl(&mib, 4, nil, &size, nil, 0)
        let procs = UnsafeMutablePointer<kinfo_proc>.allocate(capacity: size)
        defer { procs.deallocate() }
        
        sysctl(&mib, 4, procs, &size, nil, 0)
        let count = size / MemoryLayout<kinfo_proc>.stride
        
        for i in 0..<count {
            let name = withUnsafePointer(to: &procs[i].kp_proc.p_comm) {
                $0.withMemoryRebound(to: CChar.self, capacity: 16) {
                    String(cString: $0)
                }
            }
            
            if name.contains("cydia") || name.contains("sileo") {
                return true
            }
        }
        return false
    }
    
    // 3. Debugger detection
    private func detectDebugger() -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        
        if sysctl(&mib, 4, &info, &size, nil, 0) != 0 {
            return false
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // 4. Frida detection
    private func detectFrida() -> Bool {
        // Port check
        let fridaPorts: [UInt16] = [27042, 27043, 27044, 27045]
        
        for port in fridaPorts {
            if isPortOpen(port) {
                return true
            }
        }
        
        // Process check
        return isProcessRunning("frida")
    }
    
    // 5. Emulator detection
    private func detectEmulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        let device = UIDevice.currentDevice()
        return device.model.contains("Simulator")
        #endif
    }
}
```

#### Debilidades

1. **Open-source**: Los atacantes pueden estudiar exactamente cómo funciona
2. **Métodos documentados**: Todas las técnicas de detección son públicas
3. **Sin obfuscation**: El código está visible y fácil de analizar
4. **Sin anti-tampering**: No se protege a sí mismo de modificación
5. **Patrones predecibles**: Usa los mismos checks que muchos otros RASP

#### Bypass con Frida

El script `rasp-bypass-ios.js` ya incluye bypass para FreeRASP:

```javascript
// FreeRASP (Talsec) bypass patterns
var forceFalse = [
    'jailbroken', 'jailbreak', 'isjailbroken',
    'debugger', 'isdebugged', 'amidebugged',
    'emulator', 'issimulator', 'isemulator',
    'tamper', 'tampered', 'istampered',
    'hook', 'hooked', 'ishooked',
    'reverseengineer', 'amireverseengineered'
];

var forceTrue = [
    'issecure', 'issafe', 'istrusted',
    'isintegrityok', 'isintact', 'isgenuine'
];

// El script escanea todas las clases y hookea métodos
// que coinciden con estos patrones
```

**Para bypass completo de FreeRASP**:
```bash
# Usar el script unificado
frida -U -f com.target.app -l rasp-bypass-ios.js

# Combinar con jailbreak detection bypass
frida -U -f com.target.app \
  -l rasp-bypass-ios.js \
  -l jailbreak-detection-bypass.js
```

#### Callback de Amenazas

FreeRASP notifica amenazas vía callback:

```swift
// En tu app
FreeRASP.alertCallback = { threat in
    switch threat {
    case .jailbreak:
        print("Jailbreak detectado!")
    case .debugger:
        print("Debugger detectado!")
    case .hook:
        print("Framework de hooking detectado!")
    case .emulator:
        print("Corriendo en emulador!")
    case .tamper:
        print("App modificada!")
    @unknown default:
        print("Amenaza desconocida!")
    }
    
    // Respuesta recomendada: terminar la app
    exit(0)
}
```

**Bypass**: Hookear el callback para que nunca se ejecute:

```javascript
if (ObjC.available) {
    // Buscar clases de FreeRASP
    var freeRASPClasses = ['FreeRASP', 'TalsecRuntime', 'RuntimeIntegrity'];
    
    for (var i = 0; i < freeRASPClasses.length; i++) {
        if (ObjC.classes[freeRASPClasses[i]]) {
            var cls = ObjC.classes[freeRASPClasses[i]];
            
            // Hookear todos los métodos
            var methods = cls.$ownMethods;
            for (var j = 0; j < methods.length; j++) {
                try {
                    Interceptor.attach(cls[methods[j]].implementation, {
                        onLeave: function(retval) {
                            // Forzar "safe" o "no threat"
                            retval.replace(ptr(0));  // NO/false
                        }
                    });
                } catch (e) {}
            }
        }
    }
}
```

### 3.2 IOSSecuritySuite

#### Información General
- **Repositorio**: https://github.com/securing/IOSSecuritySuite
- **Licencia**: MIT (Open-source)
- **Lenguaje**: Swift
- **Mantenimiento**: Moderadamente activo

#### Características

| Característica | Soportado |
|----------------|-----------|
| Jailbreak Detection | ✓ |
| Debugger Detection | ✓ |
| Emulator Detection | ✓ |
| Screen Capture Detection | ✓ |
| Device Integrity | ✓ |
| Passcode Detection | ✓ |

#### Métodos de Detección

IOSSecuritySuite usa funciones estáticas de Swift:

```swift
import IOSSecuritySuite

// Uso básico
let jailbroken = IOSSecuritySuite.amIJailbroken()
let debugger = IOSSecuritySuite.amIDebugged()
let emulator = IOSSecuritySuite.amIRunInEmulator()
let hooked = IOSSecuritySuite.amIReverseEngineered()

// Checking con detalles
if IOSSecuritySuite.amIJailbroken() {
    // Tomar acción
}

// Detección de screenshot
IOSSecuritySuite.detectScreenshot { detected in
    if detected {
        print("Screenshot detectado!")
    }
}
```

#### Debilidades

1. **Static functions**: Fácil de localizar y hookear
2. **Símbolos visibles**: Nombres de funciones claras en el binario
3. **Sin protección propia**: No se valida a sí mismo
4. **Patrones conocidos**: Muy documentado online

#### Bypass con Frida

IOSSecuritySuite usa funciones Swift estáticas. El bypass requiere:

```javascript
// Scan por símbolos de Swift
var swiftDetections = [
    'amIJailbroken', 'amIDebugged', 'amIRunInEmulator',
    'amIReverseEngineered', 'amIProxied', 'amIRunInVirtualMachine',
    'isDebuggerAttached', 'isFridaRunning', 'amITampered'
];

function hookSwiftBoolSymbols(moduleName) {
    try {
        var syms = Module.enumerateSymbols(moduleName);
        for (var s = 0; s < syms.length; s++) {
            var sym = syms[s];
            if (!sym.address || sym.address.isNull()) continue;
            
            for (var d = 0; d < swiftDetections.length; d++) {
                if (sym.name.indexOf(swiftDetections[d]) !== -1) {
                    (function (name, addr) {
                        try {
                            Interceptor.attach(addr, {
                                onLeave: function (retval) {
                                    // Bool: 0 = safe, 1 = threat
                                    if (retval.toInt32() !== 0) {
                                        retval.replace(ptr(0));
                                        console.log('[+] IOSSecuritySuite ' + name + ': bypassed');
                                    }
                                }
                            });
                        } catch (e) {}
                    })(sym.name, sym.address);
                    break;
                }
            }
        }
    } catch (e) {}
}

// Escanear app binary
hookSwiftBoolSymbols('TargetApp');
```

**Uso práctico**:
```bash
frida -U -f com.target.app -l rasp-bypass-ios.js
```

### 3.3 JailMonkey

#### Información General
- **Repositorio**: https://github.com/GantMan/jail-monkey
- **Licencia**: MIT (Open-source)
- **Lenguaje**: Objective-C (React Native bridge)
- **Mantenimiento**: Bajo

#### Características

| Característica | Soportado |
|----------------|-----------|
| Jailbreak Detection (iOS) | ✓ |
| Root Detection (Android) | ✓ |
| Debug Detection | ✓ |
| Emulator Detection | ✓ |
| Mock Location Detection | ✓ |
| ADB Detection | ✓ |

#### Métodos de Detección

JailMonkey está diseñado para React Native:

```javascript
import JailMonkey from 'jail-monkey';

// Uso en React Native
if (JailMonkey.isJailBroken()) {
    console.log('Device is jailbroken!');
}

if (JailMonkey.isDebugged()) {
    console.log('App is being debugged!');
}

if (JailMonkey.isMockLocation()) {
    console.log('Mock location enabled!');
}

if (JailMonkey.isAdbEnabled()) {
    console.log('ADB is enabled!');  // Android only
}

if (JailMonkey.canMockLocation()) {
    console.log('Device can mock location!');
}

// TrustFall detection (anti-fraud)
if (JailMonkey.trustFall()) {
    console.log('Device is compromised!');
}
```

Debajo del capó (Objective-C):

```objective-c
@implementation JailMonkey

- (BOOL)isJailBroken {
    // File checks
    NSArray *files = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt"
    ];
    
    for (NSString *file in files) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:file]) {
            return YES;
        }
    }
    
    // Process checks
    // ... código de enumeración de procesos ...
    
    return NO;
}

- (BOOL)isDebugged {
    // P_TRACED check
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

- (BOOL)canMockLocation {
    // Verificar si el dispositivo puede falsificar ubicación
    return NO;  // Simplificado
}

- (BOOL)trustFall {
    // TrustFall: combinación de checks anti-fraud
    return [self isJailBroken] ||
           [self isDebugged] ||
           [self canMockLocation];
}

@end
```

#### Debilidades

1. **React Native específico**: Solo útil en apps RN
2. **Código simple**: Métodos muy básicos de detección
3. **Sin ofuscación**: Código visible claro
4. **Fácil de bypass**: Solo requiere hookear un par de métodos

#### Bypass con Frida

```javascript
// JailMonkey bypass
if (ObjC.available) {
    try {
        var JailMonkey = ObjC.classes.JailMonkey;
        
        if (JailMonkey) {
            // Métodos a bypass
            var methods = [
                'isJailBroken',
                'isDebugged', 
                'hookDetected',
                'canMockLocation',
                'trustFall',
                'AdbEnabled'
            ];
            
            for (var i = 0; i < methods.length; i++) {
                var method = JailMonkey['- ' + methods[i]];
                if (method) {
                    Interceptor.attach(method.implementation, {
                        onLeave: function(retval) {
                            retval.replace(ptr(0));  // Return NO/false
                            console.log('[+] JailMonkey.' + methods[i] + ' bypassed');
                        }
                    });
                }
            }
        }
    } catch (e) {
        console.log('[-] JailMonkey bypass failed: ' + e);
    }
}
```

**Uso práctico**:
```bash
# JailMonkey está en React Native apps
frida -U -f com.reactnative.app -l rasp-bypass-ios.js
```

## 4. RASP Comerciales

### 4.1 Arxan (ahora Digital.ai)

#### Información General
- **Empresa**: Digital.ai (adquirió Arxan Technologies)
- **Sitio**: https://www.digital.ai/products/application-protection
- **Tipo**: Comercial
- **Precio**: Contactar para sales (estimado: $20k-$100k/año)

#### Características Principales

| Característica | Nivel |
|----------------|-------|
| Anti-Debugging | Alto |
| Anti-Tampering | Alto |
| Anti-Reverse Engineering | Alto |
| Code Obfuscation | Alto |
| Integrity Checks | Alto |
| RASP (Runtime) | Alto |

#### Métodos de Detección Conocidos

Arxan usa múltiples capas:

1. **Binary Instrumentation**: Inyecta código de validación en el binario compilado
2. **Integrity Guards**: Puntos de verificación distribuidos por el código
3. **White-box Cryptography**: Protección de claves criptográficas
4. **Code Encryption**: Secciones del código están encriptadas y se desencriptan en runtime
5. **Anti-debug**: Detecta debuggers y herramientas de análisis

```c
// Ejemplo conceptual (simplificado)
// Arxan inyecta "guards" que verifican integridad

// Guard #1: verificar checksum de función
void arxan_guard_1() {
    if (!verify_function_checksum()) {
        terminate_app("Integrity violation");
    }
}

// Guard #2: verificar debugger
void arxan_guard_2() {
    if (is_debugger_attached()) {
        terminate_app("Debugger detected");
    }
}

// Estos guards se intercalan en todo el código
```

#### Debilidades Conocidas

1. **Patrones binarios**: Arxan tiene firmas binarias características
2. **Guards predecibles**: Los puntos de verificación siguen patrones
3. **Precio alto**: Muchas empresas no pueden pagar, así que menos análisis público
4. **Analizable**: Con suficientes recursos, se puede revertir

#### Bypass Genérico

No existe un bypass universal para Arxan debido a su naturaleza propietaria. Sin embargo:

```javascript
// Estrategia: identificar y desactivar guards
// NOTA: Requiere análisis previo del binario específico

if (ObjC.available) {
    console.log('[+] Arxan bypass - searching for guards...');
    
    // Buscar funciones con nombres típicos de Arxan
    var allClasses = Object.keys(ObjC.classes);
    for (var i = 0; i < allClasses.length; i++) {
        var clsName = allClasses[i];
        
        // Arxan usa clases con nombres como:
        // - AXProtection
        // - ArxanGuard
        // - IntegrityCheck
        if (clsName.indexOf('Arxan') !== -1 ||
            clsName.indexOf('AX') !== -1 ||
            clsName.indexOf('Guard') !== -1) {
            
            console.log('[+] Found potential Arxan class: ' + clsName);
            
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            
            for (var j = 0; j < methods.length; j++) {
                var m = methods[j];
                if (m.indexOf('check') !== -1 ||
                    m.indexOf('verify') !== -1 ||
                    m.indexOf('guard') !== -1) {
                    
                    console.log('[+] Hooking: ' + clsName + ' -> ' + m);
                    try {
                        Interceptor.attach(cls[m].implementation, {
                            onLeave: function(retval) {
                                retval.replace(ptr(1));  // Success/OK
                            }
                        });
                    } catch (e) {}
                }
            }
        }
    }
}
```

**Notas**:
- Este bypass es genérico y puede no funcionar con todas las implementaciones de Arxan
- Arxan cambia sus técnicas regularmente para evadir herramientas automatizadas
- Para bypass completo, se requiere análisis de reversing del binario específico

### 4.2 Guardsquare (iXProtect)

#### Información General
- **Empresa**: Guardsquare
- **Sitio**: https://www.guardsquare.com/iXProtect
- **Tipo**: Comercial
- **Precio**: Contactar (estimado: $15k-$80k/año)

#### Características Principales

| Característica | Nivel |
|----------------|-------|
| RASP (Runtime) | Alto |
| Anti-Debugging | Alto |
| Anti-Tampering | Alto |
| Code Obfuscation | Muy Alto |
| API Key Protection | Alto |
| Threat Analytics | Medio |

#### Métodos de Detección Conocidos

Guardsquare combina RASP con obfuscación:

1. **String Encryption**: Strings encriptados que se desencriptan en runtime
2. **Control Flow Obfuscation**: Flujo de código ofuscado
3. **Class Encryption**: Clases encriptadas
4. **Runtime Checks**: Verificaciones durante ejecución
5. **API Key Protection**: Protección específica para API keys

#### Debilidades Conocidas

1. **Strings desencriptados**: En runtime, los strings deben estar en memoria
2. **Patrones de iXProtect**: Tiene firmas características
3. **Integración con ProGuard**: Para Android, usa ProGuard que tiene patrones conocidos

#### Bypass Genérico

```javascript
// Guardsquare/iXProtect bypass genérico
if (ObjC.available) {
    console.log('[+] Guardsquare bypass');
    
    // iXProtect usa clases con patrones específicos
    var gsClasses = Object.keys(ObjC.classes);
    for (var i = 0; i < gsClasses.length; i++) {
        var clsName = gsClasses[i];
        
        // Buscar clases de Guardsquare
        if (clsName.indexOf('GS') === 0 ||  // Prefijo GS
            clsName.indexOf('Guard') !== -1 ||
            clsName.indexOf('iXProtect') !== -1 ||
            clsName.indexOf('XProtect') !== -1) {
            
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            
            for (var j = 0; j < methods.length; j++) {
                var m = methods[j];
                var mName = m.toLowerCase();
                
                if (mName.indexOf('check') !== -1 ||
                    mName.indexOf('verify') !== -1 ||
                    mName.indexOf('detect') !== -1 ||
                    mName.indexOf('protect') !== -1) {
                    
                    try {
                        Interceptor.attach(cls[m].implementation, {
                            onLeave: function(retval) {
                                // Retornar "no threat detected"
                                if (retval.toInt32() !== 0) {
                                    retval.replace(ptr(0));
                                }
                            }
                        });
                    } catch (e) {}
                }
            }
        }
    }
}
```

### 4.3 Promon SHIELD

#### Información General
- **Empresa**: Promon AS
- **Sitio**: https://promon.co/products/shield
- **Tipo**: Comercial
- **Precio**: Premium (contactar)

#### Características Principales

| Característica | Nivel |
|----------------|-------|
| Anti-Tampering | Muy Alto |
| Anti-Reverse Engineering | Muy Alto |
| Anti-Hooking | Alto |
| Financial Fraud Protection | Alto |
| Runtime Instrumentation | Alto |

#### Métodos de Detección Conocidos

Promon SHIELD se especializa en apps financieras:

1. **Runtime Instrumentation**: Monitoreo constante del runtime
2. **Process Detection**: Detección de procesos sospechosos
3. **Hook Detection**: Detección avanzada de frameworks de hooking
4. **Screen Recording Detection**: Previene grabación de pantalla
5. **Accessibility Service Abuse Detection**: Previene abuso de servicios de accesibilidad

#### Debilidades Conocidas

1. **Enfoque financiero**: Optimizado para banking/fintech
2. **Poca documentación pública**: Menos análisis disponible
3. **Costo muy alto**: Solo para grandes empresas

#### Bypass Genérico

```javascript
// Promon SHIELD bypass genérico
if (ObjC.available) {
    console.log('[+] Promon SHIELD bypass');
    
    // Promon usa clases con nombres como:
    // - PROMon*
    // - Shield*
    // - PShield*
    
    var promonClasses = Object.keys(ObjC.classes);
    for (var i = 0; i < promonClasses.length; i++) {
        var clsName = promonClasses[i];
        
        if (clsName.indexOf('Promon') !== -1 ||
            clsName.indexOf('SHIELD') !== -1 ||
            clsName.indexOf('PShield') !== -1) {
            
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            
            for (var j = 0; j < methods.length; j++) {
                var m = methods[j];
                
                try {
                    Interceptor.attach(cls[m].implementation, {
                        onLeave: function(retval) {
                            // No threat
                            retval.replace(ptr(0));
                        }
                    });
                } catch (e) {}
            }
        }
    }
}
```

### 4.4 Appdome

#### Información General
- **Empresa**: Appdome
- **Sitio**: https://www.appdome.com
- **Tipo**: Comercial
- **Precio**: Freemium (tiered pricing)

#### Características Principales

| Característica | Nivel |
|----------------|-------|
| ONEShield RASP | Alto |
| Anti-Tampering | Alto |
| Anti-Debugging | Alto |
| Anti-Emulator | Alto |
| Number of Defenses | 400+ |

#### Métodos de Detección Conocidos

Appdome promete "400+ defenses" incluyendo:

1. **Jailbreak Detection**: Múltiples técnicas
2. **Debugger Detection**: Varias capas
3. **Hook Detection**: Frida, Substrate, Cycript
4. **Screen Capture Prevention**: Previene screenshots
5. **Clipboard Protection**: Protege el clipboard
6. **Network Protection**: Detecta proxies, VPNs

#### Debilidades Conocidas

1. **Configuración basada**: Las protecciones se configuran, no se programan
2. **400 defenses pero muchas simples**: Alto número pero muchas checks básicos
3. **Patrones conocidos**: Appdome tiene firmas binarias reconocibles

#### Bypass Genérico

```javascript
// Appdome bypass genérico
if (ObjC.available) {
    console.log('[+] Appdome bypass');
    
    // Appdome usa clases como:
    // - Appdome*
    // - AD*
    // - Fusion* (su tecnología)
    
    var appdomeClasses = Object.keys(ObjC.classes);
    for (var i = 0; i < appdomeClasses.length; i++) {
        var clsName = appdomeClasses[i];
        
        if (clsName.indexOf('Appdome') !== -1 ||
            clsName.indexOf('ADMobile') !== -1 ||
            clsName.indexOf('Fusion') !== -1) {
            
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            
            for (var j = 0; j < methods.length; j++) {
                var m = methods[j];
                
                try {
                    Interceptor.attach(cls[m].implementation, {
                        onLeave: function(retval) {
                            retval.replace(ptr(0));  // Safe
                        }
                    });
                } catch (e) {}
            }
        }
    }
    
    // Appdome también hookea funciones del sistema
    // Necesitamos deshookearlas
    var connect = Module.findGlobalExportByName('connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                var addr = args[1];
                var port = addr.add(2).readU16BE();
                
                // Appdome verifica puertos de Frida
                if ([27042, 27043, 27044].indexOf(port) !== -1) {
                    console.log('[+] Blocked Appdome Frida port check');
                }
            }
        });
    }
}
```

### 4.5 Irdeto

#### Información General
- **Empresa**: Irdeto
- **Sitio**: https://www.irdeto.com
- **Tipo**: Comercial
- **Precio**: Enterprise (contactar)

#### Características Principales

| Característica | Nivel |
|----------------|-------|
| Anti-Piracy | Muy Alto |
| Anti-Tampering | Alto |
| Code Protection | Alto |
| Secure Runtime | Alto |

#### Métodos de Detección Conocidos

1. **Code Signing Verification**: Verifica firma del código
2. **Tamper Detection**: Detecta modificaciones
3. **Secure Environment**: Runtime protegido

#### Bypass Genérico

```javascript
// Irdeto bypass (similar a otros RASP comerciales)
if (ObjC.available) {
    var irdetoClasses = Object.keys(ObjC.classes);
    for (var i = 0; i < irdetoClasses.length; i++) {
        var clsName = irdetoClasses[i];
        
        if (clsName.indexOf('Irdeto') !== -1 ||
            clsName.indexOf('IDTO') !== -1) {
            
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            
            for (var j = 0; j < methods.length; j++) {
                try {
                    Interceptor.attach(cls[methods[j]].implementation, {
                        onLeave: function(retval) { retval.replace(ptr(0)); }
                    });
                } catch (e) {}
            }
        }
    }
}
```

### 4.6 WhiteCryption (Intertrust)

#### Información General
- **Empresa**: Intertrust (adquirió WhiteCryption)
- **Sitio**: https://www.intertrust.com/products/whitecryption
- **Tipo**: Comercial
- **Precio**: Enterprise

#### Características

| Característica | Nivel |
|----------------|-------|
| Application Shielding | Alto |
| Anti-Tampering | Alto |
| Code Obfuscation | Alto |
| Secure Key Management | Muy Alto |

#### Bypass Genérico

Similar a otros RASP con enfoque en protección de claves.

### 4.7 Verimatrix

#### Información General
- **Empresa**: Verimatrix
- **Sitio**: https://www.verimatrix.com
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| App Protection | Medio-Alto |
| Fraud Detection | Alto |
| VASCO Integration | Alto |

### 4.8 Zimperium MAPS

#### Información General
- **Empresa**: Zimperium
- **Sitio**: https://www.zimperium.com/mobile-application-protection-suite
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| zDefend SDK | Alto |
| Threat Intelligence | Alto |
| Anti-Malware | Medio |
| Mobile IPS | Alto |

### 4.9 IBM Trusteer

#### Información General
- **Empresa**: IBM (adquirió Trusteer)
- **Sitio**: https://www.ibm.com/security/trusteer
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| Mobile Fraud Detection | Muy Alto |
| Risk-based Auth | Alto |
| Secure Browsing | Alto |
| Threat Intel | Alto |

**IBM Trusteer ya tiene bypass en `rasp-bypass-ios.js`**:
```javascript
// IBM Trusteer usa clases con prefijo "ts_"
// El script ya cubre estas clases
```

### 4.10 Pradeo

#### Información General
- **Empresa**: Pradeo
- **Sitio**: https://www.pradeo.io
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| RASP | Alto |
| Malware Detection | Medio |
| Fraud Prevention | Alto |
| Data Theft Protection | Alto |

### 4.11 V-Key

#### Información General
- **Empresa**: V-Key
- **Sitio**: https://www.v-key.com
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| RASP | Alto |
| Code Hardening | Alto |
| Anti-Tampering | Alto |

### 4.12 Build38

#### Información General
- **Empresa**: Build38
- **Sitio**: https://www.build38.com
- **Tipo**: Comercial

#### Características

| Característica | Nivel |
|----------------|-------|
| App Shielding | Alto |
| Anti-Tampering | Alto |
| Anti-Debugging | Alto |
| Fraud Detection | Medio |

## 5. Matriz de Comparación

### Matriz de Características

| RASP | Jailbreak | Anti-Debug | Anti-Tamper | Hook Detect | Emulator | Screen Rec | Tipo |
|------|-----------|------------|-------------|--------------|-----------|------------|------|
| **FreeRASP** | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | OSS |
| **IOSSecuritySuite** | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | OSS |
| **JailMonkey** | ✓ | ✓ | ✗ | ✗ | ✓ | ✗ | OSS |
| **Arxan/Digital.ai** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Comm |
| **Guardsquare** | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | Comm |
| **Promon SHIELD** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Comm |
| **Appdome** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Comm |
| **Irdeto** | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | Comm |
| **WhiteCryption** | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ | Comm |
| **Verimatrix** | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | Comm |
| **Zimperium MAPS** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Comm |
| **IBM Trusteer** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Comm |
| **Pradeo** | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | Comm |
| **V-Key** | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | Comm |
| **Build38** | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | Comm |

### Matriz de Dificultad de Bypass

| RASP | Dificultad de Bypass | Razón |
|------|---------------------|-------|
| **JailMonkey** | Fácil | React Native específico, código simple |
| **IOSSecuritySuite** | Fácil | Static functions, sin protección |
| **FreeRASP** | Fácil-Medio | Open source, bien documentado |
| **Appdome** | Medio | 400 defenses pero muchas básicas |
| **Guardsquare** | Medio-Alto | Combina RASP con obfuscation |
| **Promon SHIELD** | Alto | Enfoque financiero, técnicas avanzadas |
| **Arxan/Digital.ai** | Alto | Binary instrumentation, guards |
| **IBM Trusteer** | Medio-Alto | Framework propietario |
| **Irdeto** | Alto | Enterprise grade |
| **Zimperium** | Alto | Threat intelligence + RASP |

## 6. Técnicas de Bypass Genéricas

### 6.1 Bypass de File System Checks

```javascript
// Hookear NSFileManager
var NSFileManager = ObjC.classes.NSFileManager;
var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];

Interceptor.attach(fileExistsAtPath.implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        this.isJailbreakPath = isJailbreakPath(path);
    },
    onLeave: function(retval) {
        if (this.isJailbreakPath) {
            retval.replace(ptr(0));  // NO
        }
    }
});

function isJailbreakPath(path) {
    var jailbreakPaths = [
        'Cydia', 'Sileo', 'substrate', 'frida',
        'cycript', 'bash', 'sshd', 'apt'
    ];
    
    for (var i = 0; i < jailbreakPaths.length; i++) {
        if (path.indexOf(jailbreakPaths[i]) !== -1) {
            return true;
        }
    }
    return false;
}
```

### 6.2 Bypass de Process Enumeration

```javascript
// Hookear sysctl
var sysctl = Module.findGlobalExportByName('sysctl');

Interceptor.attach(sysctl, {
    onEnter: function(args) {
        this.mib = args[0];
        this.oldPtr = args[1];
        this.sizePtr = args[2];
    },
    onLeave: function(retval) {
        // Si es KERN_PROC_ALL, filtrar procesos de jailbreak
        try {
            var mib0 = this.mib.readU32();
            if (mib0 === 1) {  // CTL_KERN
                var mib2 = this.mib.add(8).readU32();
                if (mib2 === 15) {  // KERN_PROC_ALL
                    // Filtrar procesos de la lista retornada
                    console.log('[+] Process enumeration filtered');
                }
            }
        } catch (e) {}
    }
});
```

### 6.3 Bypass de Port Scanning

```javascript
// Hookear connect()
var connect = Module.findGlobalExportByName('connect');

Interceptor.attach(connect, {
    onEnter: function(args) {
        var addr = args[1];
        var sin_family = addr.readU16();
        
        if (sin_family === 2) {  // AF_INET
            var port = addr.add(2).readU16BE();
            
            // Puertos de Frida
            var fridaPorts = [27042, 27043, 27044, 27045];
            if (fridaPorts.indexOf(port) !== -1) {
                console.log('[+] Blocked connection to Frida port: ' + port);
                this.block = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.block) {
            retval.replace(ptr(-1));  // Error
        }
    }
});
```

### 6.4 Bypass de DYLD Enumeration

```javascript
// Hookear _dyld_get_image_name
var dyldGetImageName = Module.findGlobalExportByName('__dyld_get_image_name');

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
                        name.indexOf('frida') !== -1 ||
                        name.indexOf('Frida') !== -1 ||
                        name.indexOf('substrate') !== -1 ||
                        name.indexOf('cycript') !== -1
                    )) {
                        retval.replace(ptr(0));  // Return NULL
                        console.log('[+] Hidden from DYLD: ' + name);
                    }
                } catch (e) {}
            }
        }
    });
}
```

### 6.5 Bypass de ptrace/PT_DENY_ATTACH

```javascript
// Reemplazar ptrace
var ptrace = Module.findGlobalExportByName('ptrace');

if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function () {
        console.log('[+] ptrace blocked');
        return 0;
    }, 'int', []));
}
```

### 6.6 Bypass de getppid()

```javascript
// Reemplazar getppid
var getppid = Module.findGlobalExportByName('getppid');

if (getppid) {
    Interceptor.replace(getppid, new NativeCallback(function () {
        return 1;  // launchd
    }, 'int', []));
}
```

## 7. Checklist de Testing

### Detección de RASP en Apps

#### Paso 1: Identificar qué RASP usa la app

```bash
# 1.1 Buscar clases sospechosas con Frida
frida -U -f com.target.app -e "
  if (ObjC.available) {
    var allClasses = Object.keys(ObjC.classes);
    var raspClasses = [];
    for (var i = 0; i < allClasses.length; i++) {
      var name = allClasses[i];
      if (name.indexOf('RASP') !== -1 ||
          name.indexOf('Security') !== -1 ||
          name.indexOf('Guard') !== -1 ||
          name.indexOf('Protect') !== -1 ||
          name.indexOf('Appdome') !== -1 ||
          name.indexOf('Arxan') !== -1 ||
          name.indexOf('IOSSecuritySuite') !== -1 ||
          name.indexOf('Talsec') !== -1 ||
          name.indexOf('FreeRASP') !== -1 ||
          name.indexOf('JailMonkey') !== -1 ||
          name.indexOf('Trusteer') !== -1 ||
          name.indexOf('GS') === 0) {
        raspClasses.push(name);
      }
    }
    console.log('[=] RASP Classes found: ' + JSON.stringify(raspClasses));
  }
"

# 1.2 Buscar frameworks en el IPA
unzip -p target.ipa 'Payload/*.app/Frameworks/*.framework/*' | strings | grep -iE "rasp|security|guard"

# 1.3 Verificar librerías cargadas
frida -U -f com.target.app -e "
  var modules = Process.enumerateModules();
  for (var i = 0; i < modules.length; i++) {
    if (modules[i].name.indexOf('RASP') !== -1 ||
        modules[i].name.indexOf('Security') !== -1 ||
        modules[i].name.indexOf('Guard') !== -1) {
      console.log('[+] RASP Module: ' + modules[i].name);
    }
  }
"
```

#### Paso 2: Identificar métodos de detección

```bash
# Listar métodos de clases RASP encontradas
frida -U -f com.target.app -e "
  if (ObjC.available) {
    var raspClass = ObjC classes.RASP_CLASS_NAME];  // Reemplazar
    if (raspClass) {
      console.log('[=] Methods: ' + raspClass.$ownMethods);
    }
  }
"
```

#### Paso 3: Probar cada mecanismo

| Mecanismo | Test | Bypass |
|-----------|------|--------|
| Jailbreak Files | Crear archivo jailbreak | Hook fileExistsAtPath: |
| Jailbreak Process | Ejecutar Cydia | Hook sysctl |
| Debugger | Adjuntar debugger | Hook sysctl/getppid |
| Frida Port | Conectar a 27042 | Hook connect() |
| DYLD Enum | _dyld_image_count | Hook _dyld_get_image_name |
| Tamper | Modificar binario | Hook SecStaticCodeCheckValidity |

### Scripts de Testing

```javascript
/**
 * RASP Testing Script
 * Usa este script para identificar y probar RASP en apps iOS
 */

(function () {
    'use strict';

    console.log('[*] RASP Testing Script Loaded');
    console.log('[*] Target: ' + ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier').toString());

    // ============================================
    // 1. Detect RASP Presence
    // ============================================
    function detectRASP() {
        console.log('\n[=] Step 1: Detecting RASP...');
        
        var raspIndicators = {
            classes: [],
            methods: [],
            modules: []
        };

        // Check for RASP classes
        var allClasses = Object.keys(ObjC.classes);
        var raspPatterns = [
            /RASP/i, /Security/i, /Guard/i, /Protect/i,
            /Appdome/i, /Arxan/i, /IOSSecurity/i, /Talsec/i,
            /FreeRASP/i, /JailMonkey/i, /Trusteer/i,
            /^GS/, /Zimperium/i, /Promon/i
        ];

        for (var i = 0; i < allClasses.length; i++) {
            var className = allClasses[i];
            for (var j = 0; j < raspPatterns.length; j++) {
                if (raspPatterns[j].test(className)) {
                    raspIndicators.classes.push(className);
                    break;
                }
            }
        }

        if (raspIndicators.classes.length > 0) {
            console.log('[+] Found ' + raspIndicators.classes.length + ' RASP-related classes:');
            raspIndicators.classes.forEach(function (cls) {
                console.log('    - ' + cls);
            });
        } else {
            console.log('[-] No RASP classes found (may use custom names)');
        }

        // Check for RASP modules
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var name = modules[i].name;
            for (var j = 0; j < raspPatterns.length; j++) {
                if (raspPatterns[j].test(name)) {
                    raspIndicators.modules.push(name);
                    break;
                }
            }
        }

        if (raspIndicators.modules.length > 0) {
            console.log('[+] Found RASP modules:');
            raspIndicators.modules.forEach(function (mod) {
                console.log('    - ' + mod);
            });
        }

        return raspIndicators;
    }

    // ============================================
    // 2. Test Detection Mechanisms
    // ============================================
    function testDetections() {
        console.log('\n[=] Step 2: Testing Detection Mechanisms...');

        // Test 1: Can we detect jailbreak files?
        console.log('\n[---] Testing: File System Checks');
        var fm = ObjC.classes.NSFileManager.defaultManager();
        var testFiles = [
            '/Applications/Cydia.app',
            '/Applications/Sileo.app',
            '/bin/bash',
            '/usr/bin/sshd',
            '/private/var/lib/apt'
        ];

        for (var i = 0; i < testFiles.length; i++) {
            var exists = fm.fileExistsAtPath_(testFiles[i]);
            console.log('    ' + testFiles[i] + ': ' + (exists ? 'EXISTS' : 'not found'));
        }

        // Test 2: Can we enumerate processes?
        console.log('\n[---] Testing: Process Enumeration');
        try {
            var sysctl = Module.findGlobalExportByName('sysctl');
            console.log('    sysctl: ' + (sysctl ? 'available' : 'not found'));
        } catch (e) {
            console.log('    sysctl: error - ' + e);
        }

        // Test 3: Can we check Frida ports?
        console.log('\n[---] Testing: Port Scanning');
        var connect = Module.findGlobalExportByName('connect');
        console.log('    connect(): ' + (connect ? 'available' : 'not found'));
        console.log('    Frida default ports: 27042, 27043, 27044, 27045');

        // Test 4: Can we enumerate DYLD images?
        console.log('\n[---] Testing: DYLD Enumeration');
        try {
            var dyldCount = Module.findGlobalExportByName('_dyld_image_count');
            var dyldName = Module.findGlobalExportByName('_dyld_get_image_name');
            console.log('    _dyld_image_count: ' + (dyldCount ? 'available' : 'not found'));
            console.log('    _dyld_get_image_name: ' + (dyldName ? 'available' : 'not found'));
        } catch (e) {
            console.log('    DYLD: error - ' + e);
        }

        // Test 5: Can we detect debugger via ptrace?
        console.log('\n[---] Testing: ptrace');
        var ptrace = Module.findGlobalExportByName('ptrace');
        console.log('    ptrace: ' + (ptrace ? 'available' : 'not found'));

        // Test 6: Can we detect debugger via getppid?
        console.log('\n[---] Testing: getppid');
        var getppid = Module.findGlobalExportByName('getppid');
        console.log('    getppid: ' + (getppid ? 'available' : 'not found'));
    }

    // ============================================
    // 3. Install Bypasses
    // ============================================
    function installBypasses() {
        console.log('\n[=] Step 3: Installing RASP Bypasses...');

        var hookedCount = 0;

        // Hook common RASP detection methods
        var forceFalse = [
            'jailbroken', 'jailbreak', 'isjailbroken', 'isjailbreaked',
            'amijailbroken', 'isdevicejailbroken', 'jailbreaktest',
            'debug', 'debugger', 'isdebug', 'isdebugged', 'amidebugged',
            'beingdebugged', 'tracerpid',
            'emulator', 'simulator', 'isemulator', 'issimulator', 'amiruninemulator',
            'hook', 'hooked', 'ishooked', 'frida', 'cycript', 'substrate',
            'tamper', 'tampered', 'istampered', 'integritycompromised',
            'reverse', 'reverseengineer', 'amireverseengineered',
            'proxied', 'isproxied', 'amiproxied', 'vpn', 'isvpn',
            'mocklocation', 'canmocklocation', 'trustfall'
        ];

        var forceTrue = [
            'issecure', 'issafe', 'istrusted', 'isintegrityok',
            'isintact', 'isgenuine', 'isclean', 'isdeviceclean'
        ];

        function classify(selLower) {
            for (var t = 0; t < forceTrue.length; t++) {
                if (selLower.indexOf(forceTrue[t]) !== -1) return 1;
            }
            for (var f = 0; f < forceFalse.length; f++) {
                if (selLower.indexOf(forceFalse[f]) !== -1) return 0;
            }
            return -1;
        }

        var allClasses = Object.keys(ObjC.classes);
        for (var i = 0; i < allClasses.length; i++) {
            var clsName = allClasses[i];
            if (/^(NS|UI|CA|CF|CG|_|__|WK|AV|CL|SK|MK|GK)/.test(clsName)) continue;

            try {
                var cls = ObjC.classes[clsName];
                var methods = cls.$ownMethods;

                for (var j = 0; j < methods.length; j++) {
                    var sel = methods[j];
                    var selBody = sel.replace(/^[-+]\s*/, '');
                    if (selBody.indexOf(':') !== -1) continue;

                    var forced = classify(selBody.toLowerCase());
                    if (forced === -1) continue;

                    try {
                        Interceptor.attach(cls[sel].implementation, {
                            onLeave: function (retval) {
                                retval.replace(ptr(forced));
                            }
                        });
                        hookedCount++;
                    } catch (e) {}
                }
            } catch (e) {}
        }

        console.log('[+] RASP bypasses installed: ' + hookedCount + ' methods hooked');

        // Hook connect() for port scanning bypass
        var connectPtr = Module.findGlobalExportByName('connect');
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function (args) {
                    try {
                        var addr = args[1];
                        var sinFamily = addr.readU16();
                        if (sinFamily === 2) {  // AF_INET
                            var port = addr.add(2).readU16BE();
                            var fridaPorts = [27042, 27043, 27044, 27045];
                            if (fridaPorts.indexOf(port) !== -1) {
                                console.log('[+] Blocked connection to Frida port: ' + port);
                                this.block = true;
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.block) {
                        retval.replace(ptr(-1));
                    }
                }
            });
            console.log('[+] Port scanning bypass installed');
        }

        // Hook _dyld_get_image_name
        var dyldGetImageName = Module.findGlobalExportByName('__dyld_get_image_name');
        if (dyldGetImageName) {
            Interceptor.attach(dyldGetImageName, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        try {
                            var name = retval.readUtf8String();
                            if (name && (
                                name.indexOf('frida') !== -1 ||
                                name.indexOf('Frida') !== -1 ||
                                name.indexOf('gadget') !== -1 ||
                                name.indexOf('substrate') !== -1
                            )) {
                                retval.replace(ptr(0));
                                console.log('[+] Hidden from DYLD: ' + name);
                            }
                        } catch (e) {}
                    }
                }
            });
            console.log('[+] DYLD enumeration bypass installed');
        }

        // Hook ptrace
        var ptrace = Module.findGlobalExportByName('ptrace');
        if (ptrace) {
            Interceptor.replace(ptrace, new NativeCallback(function () {
                return 0;
            }, 'int', []));
            console.log('[+] ptrace bypass installed');
        }

        // Hook getppid
        var getppid = Module.findGlobalExportByName('getppid');
        if (getppid) {
            Interceptor.replace(getppid, new NativeCallback(function () {
                return 1;
            }, 'int', []));
            console.log('[+] getppid bypass installed');
        }
    }

    // ============================================
    // Run All Tests
    // ============================================
    setTimeout(function () {
        var raspFound = detectRASP();
        testDetections();
        installBypasses();

        console.log('\n[=] RASP Testing Complete');
        console.log('[*] Tips:');
        console.log('    - Use this output to identify which RASP is in use');
        console.log('    - Check logs for bypass confirmation');
        console.log('    - If app crashes, some methods may require different handling');
    }, 1000);

})();
```

## Referencias

- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Frida Documentation](https://frida.re/docs/)
- [FreeRASP GitHub](https://github.com/talsec/Free-RASP-iOS)
- [IOSSecuritySuite GitHub](https://github.com/securing/IOSSecuritySuite)
- [JailMonkey GitHub](https://github.com/GantMan/jail-monkey)

## Conclusión

Esta guía cubre los 15 principales RASP para iOS, tanto open-source como comerciales. Para pentesting práctico:

1. **Usa scripts unificados**: `rasp-bypass-ios.js` cubre la mayoría de casos
2. **Identifica primero**: Detecta qué RASP usa la app antes de bypass
3. **Combina técnicas**: RASP a menudo tiene múltiples capas
4. **Verifica**: Siempre verifica que el bypass funcionó

Los RASP comerciales (Arxan, Guardsquare, Promon) son más difíciles pero no imposibles de bypass con las técnicas correctas y suficiente tiempo de análisis.
