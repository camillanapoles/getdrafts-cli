# Skill de Auditoría de Seguridad de Apps iOS

[![Skill Android](https://img.shields.io/badge/Android-Pentesting%20Skill-3DDC84.svg)](https://github.com/DragonJAR/Android-Pentesting-Skill)
[![Licencia](https://img.shields.io/badge/licencia-Apache%202.0-blue.svg)](LICENSE)
[![Versión](https://img.shields.io/badge/versi%C3%B3n-1.0.0-green.svg)](https://github.com/DragonJAR/iOS-Pentesting-Skill/blob/main/SKILL.md)
[![Autor](https://img.shields.io/badge/autor-DragonJAR%20SAS-orange.svg)](https://www.DragonJAR.org)
[![Inglés](https://img.shields.io/badge/read%20in-English-blue.svg)](README.md)

> Skill completo de auditoría de seguridad de apps iOS para agentes de IA. Realiza análisis estático, instrumentación dinámica, rastreo source-to-sink y genera reportes CVSS 4.0.

## 🎯 Qué Hace Esta Skill

Esta skill transforma un agente de IA en un **auditor de seguridad iOS** capaz de:

- **Descompilar y analizar IPAs** — Análisis Mach-O, dsdump, class-dump, extracción de IPA
- **Detectar vulnerabilidades** — 20 categorías de patrones / 97 bloques grep, alineado con OWASP Mobile Top 10
- **Probar esquemas de URL e IPC** — Inyección de esquemas de URL personalizados, abuso de universal links, XPC, App Groups
- **Rastrear flujos de datos** — Metodología source-to-sink con niveles de confianza
- **Evitar protecciones** — SSL pinning, detección de jailbreak, RASP, verificaciones nativas, encriptación
- **Modificar IPAs** — Parcheo de binarios, edición de recursos, re-firmado, re-empaquetado
- **Generar reportes** — Puntuación CVSS 4.0, mapeo MASTG, plantillas profesionales

## 📦 Instalación

### Opción 1: Clonar en el Directorio de Skills del Agente

```bash
# Para Claude Code / OpenCode agents
cd ~/.agents/skills/
git clone https://github.com/DragonJAR/iOS-Pentesting-Skill ios-app-security-audit

# Para otros agentes, colocar en el directorio de skills
```

### Opción 2: Instalar Globalmente

```bash
# Clonar en cualquier ubicación
git clone https://github.com/DragonJAR/iOS-Pentesting-Skill.git

# Agregar a la configuración de ruta de skills del agente
```

## ⚙️ Requisitos Previos

La skill funciona en **macOS** y **Linux**. macOS es recomendado para funcionalidad completa; Linux tiene alternativas para la mayoría de herramientas (~90% de compatibilidad).

| Herramienta | Versión | Propósito |
|-------------|----------|------------|
| Frida | ver [tool-versions.md](references/tool-versions.md) | Instrumentación dinámica — `frida-server` en el dispositivo debe coincidir exactamente con la versión del core `frida` del host |
| Objection | 1.12.4+ | Exploración móvil (modo mantenimiento) |
| dsdump | 0.13+ | Volcado de clases Swift |
| class-dump | - | Volcado de clases Objective-C (opcional) |
| plutil | sistema (macOS) / plistutil (Linux) | Manipulación de plist |
| codesign | sistema (macOS) / ldid (Linux) | Firmado de código |
| security | sistema (macOS) | Acceso a keychain |
| lipo | sistema (macOS) / llvm-lipo (Linux) | Manipulación de binarios fat |
| otool | sistema (macOS) / llvm-objdump (Linux) | Análisis Mach-O |
| Python | 3.10+ | Ejecución de scripts |

**Matriz de Soporte de Plataformas:** Vea [tool-installation-ios.md](references/tool-installation-ios.md) para las alternativas completas macOS/Linux.

### Verificación

Ejecute la verificación preflight para verificar todas las dependencias:

```bash
./scripts/preflight-check.sh
```

O use la versión Python para compatibilidad multiplataforma:

```bash
python3 scripts/preflight_check.py
```

Variante PowerShell para entornos Windows:

```powershell
./scripts/preflight-check.ps1
```

---

## 🚀 Configuración Rápida (5 minutos)

Prepara tu entorno para auditoría iOS con estos pasos:

### Paso 1: Verificar Herramientas Actuales

```bash
./scripts/preflight-check.sh
```

### Paso 2: Instalar Herramientas Faltantes

**macOS:**
```bash
# Instalar Python y herramientas core
brew install python@3.11 git wget jq tree ripgrep ipatool libimobiledevice ideviceinstaller

# Instalar Frida, Objection, dsdump
pip3 install frida-tools objection dsdump swift-demangle
```

**Linux (Debian/Ubuntu):**
```bash
# Paquetes del sistema
sudo apt update
sudo apt install python3 python3-pip python3-dev clang git wget jq tree ripgrep build-essential libimobiledevice-utils ideviceinstaller

# Paquetes Python
pip3 install frida-tools objection dsdump swift-demangle
```

**O usa el script de configuración automatizada:**
```bash
./scripts/setup-environment.sh
```

### Paso 3: Verificar de Nuevo

```bash
./scripts/preflight-check.sh
```

### Paso 4: Instalar Frida en el Dispositivo (Opcional)

Para análisis dinámico en un dispositivo con jailbreak, ver [references/frida-server-ios-install.md](references/frida-server-ios-install.md)

**¡Ahora estás listo para auditar IPAs!** Ver [Ejemplos de Uso](#-ejemplos-de-uso) abajo.

## 🚀 Ejemplos de Uso

### Ejemplo 1: Auditoría Básica de IPA

**Prompt del usuario:**
```
Audita este IPA: /ruta/a/app.ipa
```

**Respuesta del agente:**
```
Voy a analizar el IPA buscando vulnerabilidades de seguridad.

[Fase 0] Extrayendo IPA y detectando framework...
[Fase 1] Analizando Info.plist y entitlements...
[Fase 2] Ejecutando patrones de seguridad específicos...
[Fase 3] Rastreando flujos de datos...
[Fase 5] Generando reporte de hallazgos...

Encontré 3 problemas:
1. [ALTO] Manejo Inseguro de Esquema de URL (M8: Mala Configuración de Seguridad)
2. [MEDIO] API Key Hardcodeado en Info.plist (M1: Uso Incorrecto de Credenciales)
3. [BAJO] Logging de Debug Habilitado (M8: Mala Configuración de Seguridad)
```

### Ejemplo 2: Bypass de SSL Pinning

**Prompt del usuario:**
```
La app tiene SSL pinning. Evítalo con Frida e intercepta el tráfico.
```

**Respuesta del agente:**
```
Voy a usar el script de bypass de SSL pinning para interceptar tráfico HTTPS.

[1] Identificando implementación de SSL pinning...
    Encontrado: NSURLSession con validación personalizada de certificados
[2] Cargando script de Frida: ssl-pinning-bypass-ios.js
[3] Hookeando métodos de NSURLSessionDelegate
[4] SSL pinning evitado. Tráfico ahora desencriptado.

Request interceptado:
POST /api/login
{"email": "usuario@ejemplo.com", "password": "secreto123"}
```

### Ejemplo 3: Análisis de React Native

**Prompt del usuario:**
```
Analiza esta app iOS de React Native buscando secretos hardcodeados en el bundle de JavaScript.
```

**Respuesta del agente:**
```
[Fase 0] Detectado framework React Native (libReactNative.a encontrado)
[Fase 0] Extrayendo bundle de JavaScript desde Payload/YourApp.app/index.ios.bundle
[Fase 2] Escaneando secretos en bundle de JavaScript...

Encontré 2 secretos hardcodeados:
- API_KEY = "sk_live_abc123..." en index.ios.bundle:4521 (M1: Uso Incorrecto de Credenciales)
- AWS_SECRET = "wJalrXUtnFEMI/K7MDENG..." en index.ios.bundle:8912 (M1: Uso Incorrecto de Credenciales)
```

### Ejemplo 4: Modificación de IPA

**Prompt del usuario:**
```
Deshabilita la detección de jailbreak en este IPA y re-empaquétalo.
```

**Respuesta del agente:**
```
[1] Extrayendo IPA...
[2] Localizando código de detección de jailbreak...
    Encontrado: JailbreakDetector.checkJailbreak() en YourApp
[3] Parcheando binario para retornar false...
    NOP-eando instrucción de comparación
[4] Re-firmando con code signing...
[5] Re-empaquetando IPA...
[6] Verificando firma...

IPA modificado listo: app_patched.ipa
SHA-256: abc123def456...
```

### Ejemplo 5: Análisis de Flutter

**Prompt del usuario:**
```
Analiza esta app iOS de Flutter. Necesito interceptar tráfico HTTPS.
```

**Respuesta del agente:**
```
[Fase 0] Detectado framework Flutter (Flutter.framework encontrado)
[Fase 0] Flutter usa BoringSSL nativamente - los hooks SSL de ObjC/Swift no funcionarán
[Fase 0] Usando Blutter para extraer código Dart: python3 blutter.py Frameworks/App.framework/App
[Fase 4] Cargando script de Frida: flutter-ios-hook.js (objetivos BoringSSL)
[Fase 4] Hookeando SSL_CTX_set_custom_verify() para bypass de certificados
[Fase 4] Hookeando SSL_read/SSL_write() para intercepción de tráfico

Tráfico Flutter ahora interceptado y desencriptado.
```

### Ejemplo 6: Pruebas de Unity IL2CPP en el Simulador

**Prompt del usuario:**
```
Tengo un IPA de un juego Unity IL2CPP. Necesito ejecutarlo en el Simulador de iOS para hacer pruebas — no hay dispositivo físico disponible.
```

**Respuesta del agente:**
```
[Phase 0] Detected Unity 2021.3.56f2 IL2CPP (arm64)
[Phase 0] Converting for simulator with SimForge...
[SimForge] Patched LC_BUILD_VERSION for simulator ABI
[SimForge] Ad-hoc signed bundle
[Launch] App crashes: MTLHeap MTLReportFailure — Metal driver incompatibility
[Fix] Compiling metalheapfix.dylib (MTLSimDevice heap swizzle)
[Fix] Injecting via SIMCTL_CHILD_DYLD_INSERT_LIBRARIES
[Launch] App running on iOS 18.6 simulator!

Optional: Embedding dylib permanently with LC_LOAD_DYLIB...
[Patch] Added @executable_path/Frameworks/metalheapfix.dylib to main binary
[Sign] Re-signed bundle
[Launch] App launches by tapping the icon — no env vars needed

Tested with: Idle Planet Miner v3.0.8 (Unity 2021.3.56f2 IL2CPP arm64) on iOS 18.6 simulator
```

## 📖 Capacidades de la Skill

### Análisis Estático (Fases 0-3)

| Capacidad | Descripción |
|-----------|-------------|
| Extracción de IPA | Unzip IPA, acceso a Payload/YourApp.app/ |
| Análisis Mach-O | otool, lipo, nm para estructura de binario |
| Detección de Framework | React Native, Flutter, Cordova, Xamarin, Native |
| Análisis de Ofuscación | Ofuscación Swift, LLVM, patrones personalizados |
| Análisis de Info.plist | Verificaciones de seguridad para esquemas URL, entitlements, permisos (checklist de 47 claves) |
| Abuso de Esquema URL / IPC | Esquemas personalizados, universal links, XPC, App Groups, pasteboard |
| Detección de Secretos | API keys, contraseñas, tokens en código y plists |
| Rastreo de Flujos de Datos | Metodología source-to-sink con niveles de confianza |
| Cadena de Suministro (SBOM) | Generación CycloneDX/SPDX, escaneo de CVE + licencias de dependencias, revisión de SDKs de terceros |
| Enterprise / MDM | Perfiles de configuración, managed app config, prueba de confianza de certificados enterprise |

### Análisis Dinámico (Fase 4)

| Capacidad | Descripción |
|------------|-------------|
| Scripts de Frida | 73 scripts para hooking, bypass, intercepción y triaje nativo |
| Bypass de SSL Pinning | NSURLSession, AFNetworking, Alamofire, TrustKit, BoringSSL (SSL Kill Switch), React Native, Flutter |
| Bypass de Detección de Jailbreak | 22 indicadores de jailbreak, hooks nativos (fopen, access, stat), probe nativo de jailbreak |
| Bypass de RASP | Detección de debugger, anti-frida, detección de simulador |
| Intercepción de Crypto | Monitoreo de SecKey, SecKeyDecrypt, operaciones CommonCrypto |
| Bypass Biométrico | LAContext, prompt biométrico, fallback a PIN |
| Inspección de Keychain | Listar entradas, extraer metadatos, verificar accesibilidad |
| Intercepción de Red | URLSession, AFNetworking, Alamofire, monitoreo WebSocket |
| Hooking Nativo | Runtime de Objective-C, bridging Swift, hooks por offset |

### Modificación de IPA

| Capacidad | Descripción |
|------------|-------------|
| Parcheo de Binario | otool, jtool2, editor hex para modificación directa de binario |
| Edición de Recursos | Modificar Info.plist, plists embebidos, strings |
| Bypass de ATS | Sobreescribir NSAppTransportSecurity, habilitar tráfico en texto plano |
| Re-firmado | codesign con provisioning profile, entitlements |
| Re-empaquetado | Reconstruir IPA, mantener estructura |

### Reporteo (Fase 5)

| Capacidad | Descripción |
|------------|-------------|
| Puntuación CVSS 4.0 | Severidades compatibles con FIRST.org |
| Mapeo OWASP MASTG | IDs de prueba y categorías MASVS |
| Plantillas Profesionales | Resumen ejecutivo, hallazgos, remediación |

## 🔧 Estructura de la Skill

```
iOS-Pentesting-Skill/
├── SKILL.md                              # Definición de skill (Fases 0-5)
├── requirements.txt                      # Dependencias Python de scripts/
├── ruff.toml                             # Rule set de lint declarado
├── references/                           # 94 documentos de referencia
│   ├── Empieza aquí
│   │   ├── ios-pentesting-decision-tree.md              # Qué comprobación ejecutar según el hallazgo
│   │   ├── troubleshooting-ios.md                       # Fallos comunes y soluciones
│   │   └── getting-started-ios.md                     # Guía de orientación de 15 minutos
│   ├── Fase 0 (extracción y framework)
│   │   ├── environment-setup-ios.md      # Toolchain macOS
│   │   ├── tool-installation-ios.md      # Instalación por herramienta
│   │   ├── static-analysis-patterns-ios.md  # Patrones de grep por categoría
│   │   ├── macho-binary-analysis.md      # Estructura y flags Mach-O
│   │   ├── framework-detection-ios.md    # RN/Flutter/Cordova/Xamarin/Unity
│   │   ├── ipa-extraction-guide.md       # Estructura IPA y desencriptado
│   │   ├── advanced-tools-ios.md         # Corellium, Hopper, Ghidra, lldb
│   │   ├── bitcode-analysis.md           # Binarios con bitcode
│   │   ├── mobsf-integration-guide.md    # Setup opcional MobSF
│   │   ├── libimobiledevice-guide.md                    # Toolchain libimobiledevice
│   │   ├── linux-ios-analysis-workarounds.md            # Linux sin macOS
│   │   └── tool-versions.md                             # Versiones requeridas (fuente de verdad)
│   ├── Fase 1 (superficie de ataque)
│   │   ├── info-plist-checklist.md       # Checklist de claves de Info.plist (47 claves)
│   │   ├── entitlements-security-guide.md
│   │   ├── ios-version-security-changes.md  # iOS 15 → 18
│   │   ├── app-extensions-security.md    # WidgetKit / Share / Keyboard
│   │   ├── url-scheme-security-guide.md  # Secuestro de scheme, callback OAuth, inyección de parámetros
│   │   ├── universal-links-guide.md      # apple-app-site-association
│   │   ├── ats-configuration-guide.md    # NSAppTransportSecurity
│   │   ├── privacy-manifest-ios.md       # PrivacyInfo.xcprivacy (iOS 17+)
│   │   ├── app-groups-security.md        # Abuso de contenedores compartidos
│   │   ├── cloudkit-security-ios.md                     # CloudKit / sync iCloud
│   │   ├── insecure-deserialization-ios.md              # NSKeyedUnarchiver / deserialización
│   │   ├── passkeys-security-ios.md                     # Passkeys / WebAuthn (iOS 16+)
│   │   └── swift-concurrency-security.md                # async/await, actors, carreras de datos
│   ├── Fase 2 (almacenamiento y cripto)
│   │   ├── commoncrypto-analysis.md
│   │   ├── keychain-security-guide.md
│   │   ├── userdefaults-security.md
│   │   ├── coredata-security.md
│   │   ├── pasteboard-security.md
│   │   ├── data-protection-api-guide.md
│   │   ├── objc-security-patterns.md     # swizzling, KVO, nil dispatch
│   │   ├── swift-security-patterns.md    # type safety, generics
│   │   ├── memory-analysis-ios.md                       # Búsqueda de secretos en memoria
│   │   └── side-channel-analysis-ios.md                 # Canales laterales de temporización / caché
│   ├── Fase 3 (data flow)
│   │   ├── deep-link-exploitation-ios.md
│   │   ├── xpc-services-security.md
│   │   ├── ipc-xpc-guide.md
│   │   ├── webview-security-ios.md
│   │   ├── notification-security.md
│   │   ├── phishing-attacks-ios.md                      # Phishing vía deep links / OAuth
│   │   └── deep-link-security-checklist.md                        # Checklist de deep links, testing y remediación
│   ├── Fase 4 (dinámico / Frida)
│   │   ├── jailbreak-setup-guide.md
│   │   ├── frida-server-ios-install.md
│   │   ├── frida-ios-guide.md
│   │   ├── objection-ios-guide.md
│   │   ├── ssl-pinning-bypass-ios.md
│   │   ├── dynamic-analysis-setup-ios.md
│   │   ├── debugger-detection-bypass.md
│   │   ├── runtime-integrity-bypass.md
│   │   ├── secure-enclave-testing.md
│   │   ├── icloud-private-relay-testing.md
│   │   ├── frida-scripts-index.md        # Catálogo canónico de scripts
│   │   ├── frida-dynamic-analysis-ios.md                # Análisis dinámico con Frida en dispositivo
│   │   ├── frida-ios-simulator-workflow.md              # Frida en el simulador de iOS
│   │   ├── jailbreak-detection-bypass-ios.md            # Bypass de detección de jailbreak
│   │   ├── rasp-guide-ios.md                            # Detección y bypass de RASP
│   │   ├── rasp-patterns-ios.md                         # Patrones de RASP y mitigaciones
│   │   ├── rasp-framework-stub-guide.md                 # Stubbing de frameworks RASP
│   │   ├── simforge-emulation-flow.md                   # Flujo canónico SimForge de 10 pasos
│   │   ├── simforge-ios-testing.md                      # Testing en simulador con SimForge
│   │   ├── simforge-crash-triage.md                     # Análisis de crashes .ips
│   │   ├── simforge-compatibility.md                    # Matriz de compatibilidad de SimForge
│   │   ├── simforge-scripts-index.md                    # Índice de uso de scripts SimForge
│   │   ├── simforge-legacy-loadcmd-cleanup.md           # Limpieza de comandos LC heredados
│   │   └── simulator-mitm-setup.md                      # Configuración MITM en el simulador
│   ├── Fase 5 (reporte)
│   │   ├── cvss-scoring-ios.md           # Metodología CVSS 4.0
│   │   ├── cvss-examples-ios.md          # 10 ejemplos trabajados
│   │   ├── reporting-templates-ios.md
│   │   ├── owasp-mastg-ios-checklist.md
│   │   ├── ios-privacy-testing.md
│   │   └── runtime-hardening-checks-ios.md  # 12 chequeos frecuentemente olvidados
│   ├── Mod (reempaquetado)
│   │   ├── repackaging-ios-guide.md
│   │   └── obfuscation-detection-ios.md
│   ├── Frameworks
│   │   ├── react-native-ios-security.md
│   │   ├── flutter-ios-security.md
│   │   ├── cordova-ios-security.md
│   │   ├── xamarin-ios-security.md
│   │   ├── unity-ios-security.md
│   │   ├── swiftui-security-deep-dive.md
│   │   ├── core-ml-security.md
│   │   └── core-ml-security-expanded.md
│   ├── Tools / CI / SC / Ent
│   │   ├── automation-scripts-ios.md
│   │   ├── ci-cd-integration-ios.md
│   │   ├── github-actions-ios-security.md
│   │   ├── fastlane-security.md
│   │   ├── sbom-supply-chain-guide.md
│   │   ├── third-party-sdk-analysis.md
│   │   ├── enterprise-app-testing.md
│   │   ├── mdm-security-testing.md
│   │   └── configuration-profile-abuse.md
├── assets/frida-scripts/                 # 73 scripts de Frida
│   ├── ssl-pinning-bypass-ios.js         # Bypass SSL pinning (STABLE)
│   ├── jailbreak-detection-bypass.js     # Bypass jailbreak detection (STABLE)
│   ├── biometric-bypass-ios.js           # Bypass LAContext (STABLE)
│   ├── objc-method-tracer.js             # Trazador ObjC/Swift genérico (STABLE)
│   ├── network-interceptor-ios.js        # Captura NSURLSession (STABLE)
│   ├── crypto-hook-ios.js                # Hooks CommonCrypto
│   ├── keychain-dumper.js                # Extracción de Keychain
│   ├── url-scheme-monitor.js             # openURL / Universal Links
│   ├── pasteboard-monitor.js             # Lectura/escritura UIPasteboard
│   ├── file-protection-enumerator.js     # Auditoría NSFileProtection
│   ├── data-protection-check.js          # Protección a nivel de archivo
│   ├── sdk-tracer.js                     # Comportamiento de SDKs terceros
│   ├── mdm-bypass.js                     # Bypass de restricciones MDM
│   ├── enterprise-cert-bypass.js         # Bypass cert empresarial
│   ├── react-native-ios-hook.js          # Hooks de módulos RCTBridge
│   ├── flutter-ios-hook.js               # Hooks FlutterMethodChannel
│   ├── flutter-ssl-pinning-ios.js        # Bypass pinning Flutter
│   ├── tls-keylogger-ios.js              # Extracción de llaves TLS BoringSSL (sin MITM)
│   ├── rasp-bypass-ios.js                # Bypass RASP (IOSSecuritySuite/FreeRASP/JailMonkey)
│   ├── anti-debugging-bypass-ios.js      # Bypass anti-debug ptrace/sysctl/getppid
│   └── ... (53 más)
├── assets/dylibs/                        # Dylibs interposer compilados
│   ├── metalheapfix.m                    # Fix del crash de heap Metal en Unity IL2CPP (fuente)
│   └── README.md                         # Instrucciones de compilación y uso
├── scripts/                              # Utilidades, validación y reporte
│   ├── preflight-check.sh                # Verificación de dependencias Bash
│   ├── preflight_check.py                # Verificación multiplataforma
│   ├── preflight-check.ps1               # Verificación PowerShell
│   ├── auto-audit-static-ios.sh          # Driver estático (Fases 0-3)
│   ├── generate-report.py                # Generador de reporte HTML / Markdown
│   ├── test-findings.json                # Muestra de input
│   ├── sbom_generator.py                 # SBOM CycloneDX / SPDX desde IPA
│   ├── dependency_scanner.py             # OSV.dev CVE + licencias
│   ├── _scripts_path.py                  # Helper interno sys.path (no ejecutar)
│   ├── check_docs_consistency.py                  # Verificador de coherencia docs / código / tooling
│   ├── selftest.py                       # Autotest funcional (sin dispositivo ni red)
│   ├── frida_harness.js                  # Carga cada script Frida bajo un API simulado
│   ├── simforge_binaries.py                        # Inventario interno de binarios Mach-O (no ejecutar)
│   ├── setup_mobsf.py                    # Instalador MobSF (opcional)
│   ├── mobsf_config.py                   # Config URL + API key MobSF
│   ├── mobsf_detect.py                   # Auto-detección MobSF en ejecución
│   ├── mobsf_upload.py                   # Subir IPA + esperar scan
│   ├── mobsf_export.py                   # Exportar hallazgos (json / html)
│   ├── mobsf_client.py                   # Cliente REST MobSF
│   ├── mobsf_findings_correlator.py      # Merge manual + MobSF
│   ├── install-mobsf-docker.sh
│   ├── install-mobsf-local.sh
│   ├── run-mobsf-local.sh
│   ├── simforge_preflight.py             # SimForge: preflight de compatibilidad con simulador
│   ├── simforge_apply.py                 # SimForge: parchear IPA para el Simulador iOS
│   ├── simforge_install_launch.sh        # SimForge: instalar + lanzar en simulador activo
│   ├── simforge_triage.py                # SimForge: triaje de crashes de arranque en simulador
│   ├── simforge_iterate.sh               # SimForge: iterar parcheo → instalar → lanzar
│   ├── simforge_cleanup.py               # SimForge: eliminar load commands incompatibles
│   ├── binpatch_util.py                  # Parcheador de strings Mach-O que preserva longitud
│   ├── patch_is_simulator.py             # Desactivar string de detección 'isSimulator'
│   ├── patch_jailbreak_strings.py        # Neutralizar strings de detección de jailbreak
│   ├── patch_nudetect.py                 # Desactivar referencias al SDK NuDetect
│   ├── patch_termination_calls.py        # Neutralizar strings de error de terminación
│   ├── quick-static-analysis.sh          # Driver de triaje estático rápido
│   ├── screenshot-extractor.sh           # Capturar pantallas de la app (device / simulador)
│   ├── unity_sim_metalfix.sh             # Fix de heap Metal en Unity IL2CPP (compilar + inyectar)
│   └── setup-environment.sh              # Configuración automatizada del entorno
```

> **Para el catálogo canónico de scripts de Frida** (targets de cada
> hook, nivel de madurez e invocación de ejemplo), consultá
> `references/frida-scripts-index.md` — el índice de referencias en
> SKILL.md tiene una tabla condensada que mapea cada script a su fase
> del flujo de trabajo.

## 🎓 Frases de Activación

La skill se activa cuando el usuario dice:

- "audita este IPA"
- "analiza app iOS"
- "pentest iOS"
- "seguridad de app"
- "descompila IPA"
- "evaluación de vulnerabilidades iOS"
- "ingeniería inversa iOS"
- "modificar IPA"
- "bypass SSL pinning"
- "bypass detección de jailbreak"
- "abuso de esquema URL"

## ⚠️ Limitaciones

1. **Requisitos de plataforma** — macOS recomendado para funcionalidad completa; Linux tiene ~90% de compatibilidad con alternativas (ver [tool-installation-ios.md](references/tool-installation-ios.md))
2. **El análisis dinámico requiere un dispositivo con jailbreak** — Frida necesita acceso completo (a menos que use el simulador en macOS o Corellium)
3. **Binarios encriptados** — Los binarios de App Store están encriptados; hay que desencriptar con Clutch o frida-ios-dump
4. **Emparejamiento de versiones de Frida** — frida-server en el dispositivo debe coincidir exactamente con frida-tools en el host
5. **Flutter usa BoringSSL nativamente** — Los hooks SSL de ObjC/Swift no funcionan, se necesitan hooks nativos

## 📚 Alineación con Estándares

Esta skill está alineada con:

- **OWASP MASTG** — Guía de Pruebas de Seguridad de Apps Móviles (sección iOS)
- **OWASP MASVS** — Estándar de Verificación de Seguridad de Apps Móviles
- **OWASP Mobile Top 10 2024** — Top 10 riesgos móviles
- **CVSS 4.0** — Sistema de Puntuación de Vulnerabilidades Común

## 🔐 OWASP Mobile Top 10 (2024)

| ID | Categoría |
|----|-----------|
| M1 | Uso Incorrecto de Credenciales |
| M2 | Cadena de Suministro Inadecuada |
| M3 | Autenticación/Autorización Insegura |
| M4 | Validación Insuficiente de Entrada/Salida |
| M5 | Comunicación Insegura |
| M6 | Controles de Privacidad Inadecuados |
| M7 | Protecciones Binarias Insuficientes |
| M8 | Mala Configuración de Seguridad |
| M9 | Almacenamiento de Datos Inseguro |
| M10 | Criptografía Insuficiente |

## 📚 ¿Por Dónde Empezar?

Según tu situación, elige la guía adecuada:

| Tu Situación | Lee Esto |
|--------------|----------|
| **Nuevo en pentesting iOS** | [getting-started-ios.md](references/getting-started-ios.md) - Guía de 15 minutos |
| **Configurando un Mac nuevo** | [environment-setup-ios.md](references/environment-setup-ios.md) - Setup completo de 14 secciones |
| **Falta una herramienta específica** | [tool-installation-ios.md](references/tool-installation-ios.md) - Guía por herramienta |
| **Necesitas referencia de versiones** | [tool-versions.md](references/tool-versions.md) - Fuente única de verdad |
| **Listo para auditar IPAs** | [SKILL.md](SKILL.md) - Metodología completa de 6 fases |
| **Quieres dominar Frida** | [frida-ios-guide.md](references/frida-ios-guide.md) + [frida-scripts-index.md](references/frida-scripts-index.md) |
| **Pruebas en Simulador** | [simforge-ios-testing.md](references/simforge-ios-testing.md) - Sin jailbreak |

---

## 🤝 Contribuyendo

¡Las contribuciones son bienvenidas! Por favor vea el directorio [references/](references/) para áreas que necesitan expansión.

## 📄 Licencia

Apache License 2.0 — Vea [LICENSE](LICENSE) para detalles.

## 👨‍💻 Autor

**DragonJAR SAS** — [https://www.DragonJAR.org](https://www.DragonJAR.org)

[Expertos en servicios de seguridad informática, validación proactiva y seguridad ofensiva.](https://www.dragonjar.org/servicios-de-seguridad-informatica)

---

**⚠️ Descargo de responsabilidad:** Esta skill está diseñada para **pruebas de seguridad autorizadas solamente**. Los usuarios deben obtener autorización adecuada antes de realizar cualquier evaluación de seguridad. Los autores no son responsables del uso indebido de esta herramienta.
