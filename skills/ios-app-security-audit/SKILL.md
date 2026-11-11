---
name: iOS-Pentesting-Skill
description: >
  Comprehensive iOS app security audit with static analysis, dynamic instrumentation, source-to-sink tracing, IPC/component abuse analysis, and CVSS 4.0 reporting. Covers decompilation, Info.plist analysis, URL schemes and universal links, secrets detection, crypto analysis, Frida/Objection integration, and IPA modification. Use when user says "audit IPA", "analyze iOS app", "iOS pentest", "app security", "decompile IPA", "iOS vulnerability assessment", "reverse engineer iOS", "modify IPA", "URL scheme abuse", "bypass SSL pinning", "bypass jailbreak detection", "download IPA from App Store", or provides an IPA for security review, decompiled iOS sources, or decoded resources.
  Do NOT use for Android apps (use Android-specific skill), web application testing, or general programming help.
license: Apache-2.0
compatibility: >
  macOS 11+ with Apple Silicon recommended (full functionality). Linux has ~90% compatibility with tool alternatives (see tool-installation-ios.md). Some features require jailbroken iOS device.
  Requires Frida, Objection, dsdump, and standard macOS toolchain (plutil, otool, codesign, security, lipo).
allowed-tools: "Bash(frida:*) Bash(objection:*) Bash(dsdump:*) Bash(class-dump:*) Bash(codesign:*) Bash(security:*) Bash(lipo:*) Bash(nm:*) Bash(strings:*) Bash(otool:*) Bash(jtool2:*) Bash(plutil:*) Bash(python3:*) Bash(ipa:*) Bash(unzip:*) Bash(zip:*) Bash(find:*) Bash(file:*) Bash(rg:*) Bash(xcrun:*) Bash(ideviceinstaller:*) Bash(idevicesyslog:*) Bash(ideviceinfo:*) Bash(idevicepair:*) Bash(ideviceimagemounter:*) Bash(afcclient:*) Bash(idevicecrashreport:*) Bash(ideviceprovision:*) Bash(swift-demangle:*) Bash(log:*) Bash(ipatool:*) Bash(plistutil:*) Bash(llvm-objdump:*) Bash(llvm-lipo:*) Bash(ldid:*) Read Write Edit Glob Grep"
metadata:
  author: DragonJAR SAS
  version: "1.0.0"
  category: mobile-security
  tags:
    - ios
    - ipa-audit
    - static-analysis
    - dynamic-analysis
    - frida
    - objection
    - security-pentest
    - cvss-scoring
    - reverse-engineering
    - ipatool
---

# iOS App Security Audit

## Overview

> **Language Rule (CRITICAL)**: Match the user's language in your responses.
> - If user speaks Spanish → reply in Spanish
> - If user speaks English → reply in English
> - If user speaks another language → reply in that language
> - Default to English only when the user's language is unclear
>
> **This rule applies to ALL interactions**: questions, explanations, findings, everything.

Deterministic 6-phase static analysis + optional dynamic confirmation workflow. Remove noise early, keep the bundle scope tight. Only report vulnerabilities where source, propagation, and sink are understood or clearly marked as needing dynamic confirmation.

## When to Use
- User provides an IPA file for security review
- User asks to analyze decompiled iOS source code
- User needs to modify or repackage an IPA for testing
- User wants iOS mobile security testing or vulnerability assessment
- User needs help testing URL schemes, universal links, or IPC mechanisms
- User mentions iOS reverse engineering or app analysis
- User wants to acquire an IPA from the App Store (via ipatool — see [references/ipa-extraction-guide.md](references/ipa-extraction-guide.md) §5)

> **New to iOS pentesting?** Start with [references/getting-started-ios.md](references/getting-started-ios.md) for a 15-minute quick start guide.
> **Stuck on an issue?** See [references/troubleshooting-ios.md](references/troubleshooting-ios.md) for centralized troubleshooting.
> **Quick workflow reference?** See [references/ios-pentesting-decision-tree.md](references/ios-pentesting-decision-tree.md) for a visual decision tree of the complete testing workflow with environment options (jailbroken device, iOS Simulator, non-jailbreak).

## Critical Rules
1. NEVER report bare grep hits without traced context
2. ALWAYS constrain searches to the app namespace (avoid framework noise)
3. STOP and report immediately if decoding fails
4. ALWAYS use imperative language in findings
5. NEVER skip validation — if unsure, mark as "Needs Dynamic Confirmation"
6. ALWAYS provide concrete PoC (frida script, objection command, or URL scheme payload)
7. NEVER duplicate findings for the same root cause

> **Quality Note**: Take your time to analyze thoroughly. Quality is more important than speed. Do not skip validation steps — a false positive is worse than a missed finding.

> **Reference**: Before diving into specific analysis phases, consult `references/` for detailed methodology on Mach-O analysis, crypto patterns, IPC abuse, and troubleshooting.

## Interactive Decision Points

**ALWAYS ask these questions BEFORE proceeding with the corresponding action.**

### Session Context (Remember for Entire Session)

**The FIRST question establishes session context — remember the answer and reuse it.**

When the user first provides an IPA or requests any action, establish:

1. **Target Environment** — iOS Simulator OR Physical Device
2. **If Physical:** Jailbreak status (jailbroken / non-jailbroken)
3. **If Simulator:** iOS version/runtime

**Store this context and reuse it for ALL subsequent actions in the session.**

> **Rule**: Only ask "Simulator or Physical Device?" ONCE per session. After the first answer, use that context for all install/hook/modify decisions without re-asking.
>
> **SimForge Requirement (Apple Silicon only)**: When Simulator is chosen, ALWAYS use SimForge to patch arm64 binaries for simulator compatibility. See `references/simforge-ios-testing.md`.
>
> **Example Flow:**
> - User: "Install this IPA"
> - Agent: "Simulator or physical device?"
> - User: "Simulator"
> - Agent: [Uses SimForge to patch, then installs to simulator]
> - ... later ...
> - User: "Bypass SSL pinning"
> - Agent: [Uses simulator commands directly, NO re-ask]

### When Installing an IPA
User request: "Install this IPA", "Install the app", "Deploy the IPA"

**Required questions:**
1. **Target environment?** — iOS Simulator OR Physical Device (jailbroken/non-jailbroken)
2. **If Physical Device:** Is it jailbroken? (determines if Frida server is available)
3. **If Simulator:** Which iOS version/runtime? (xcrun simctl list)

**Commands based on answer:**
- **Simulator**: Use SimForge to patch arm64 binary → `xcrun simctl install <UDID> <app-path>`
  > See `references/simforge-ios-testing.md` for complete SimForge workflow
- **Physical (jailbroken)**: `ideviceinstaller install <ipa>`
- **Physical (non-jailbroken)**: Needs re-signing with provisioning profile first

### When Dynamic Analysis is Requested
User request: "Hook this app", "Bypass SSL pinning", "Intercept traffic", "Runtime analysis"

**Required questions:**
1. ~~**Target environment?**~~ — Use session context (established above)
2. **Is Frida server running?** — Verify with `frida-ps -U` (device) or `frida-ps -D` (simulator)
3. **App bundle ID or process name?** — Need exact identifier for attachment

### When Modifying/Repackaging an IPA
User request: "Modify this IPA", "Patch the app", "Re-sign", "Repackage"

**Required questions:**
1. **What modification?** — Bypass protection, patch code, change resources, etc.
2. ~~**Target device type?**~~ — Use session context (jailbroken vs stock)
3. **Provisioning profile available?** — Required if stock device

### When URL Scheme Testing
User request: "Test URL schemes", "Test deep links", "IPC testing"

**Required questions:**
1. **Test target?** — Static analysis (plist grep) OR Runtime (use session context)
2. **Specific schemes to test?** — Or test all found in Info.plist
3. **Payload injection needed?** — Yes for XSS/parameter testing, No for enumeration only

### When Crypto/Keychain Testing
User request: "Test encryption", "Keychain analysis", "Crypto review"

**Required questions:**
1. **Analysis type?** — Static (code patterns) OR Runtime (Frida hooks)
2. **Target algorithms?** — CommonCrypto, CryptoKit, third-party, or all
3. **Key extraction needed?** — Yes (requires Frida) or No (pattern analysis only)

> **Rule**: NEVER assume the target environment. ALWAYS ask before executing install/hook/modify commands.

## Execution Model
Tools to use: bash, write, edit, read, glob, grep for core workflow.

## Toolchain Requirements
Before starting, verify these tools are installed:
- **Frida** (`frida --version`) — pinned version in [references/tool-versions.md](references/tool-versions.md); ⚠️ `frida-server` on device must match the host `frida` core version (`frida --version`) exactly
- **Objection** 1.12.4 (`objection --version`) — Note: Objection is in maintenance mode
- **dsdump** 0.13+ (`dsdump --version`) — Swift class dump for modern iOS binaries
- **class-dump** (optional) — Objective-C class dump for legacy apps
- **plutil** (system) — plist manipulation (preinstalled on macOS)
- **codesign** (system) — code signing (preinstalled on macOS)
- **security** (system) — keychain access (preinstalled on macOS)
- **lipo** (system) — fat binary manipulation (preinstalled on macOS)
- **nm** (system) — symbol extraction (preinstalled on macOS)
- **strings** (system) — string extraction (preinstalled on macOS)
- **otool** (system) — Mach-O analysis (preinstalled on macOS)
- **jtool2** (optional) — Advanced Mach-O analysis
- **SimForge** (REQUIRED for arm64 apps on Simulator, Apple Silicon only) — `simforge` — Patches Mach-O `LC_BUILD_VERSION` to run arm64 iOS apps in the simulator with dylib injection (no jailbroken device required). See `references/simforge-ios-testing.md`.
- **ipatool** (optional) — `ipatool --version` — Download IPAs from the App Store. Output is FairPlay-encrypted. See [references/ipa-extraction-guide.md](references/ipa-extraction-guide.md) §5.
- **Python** 3.10+ (`python3 --version`)

Run `scripts/preflight-check.sh` (bash), `scripts/preflight_check.py` (universal, JSON output), or `scripts/preflight-check.ps1` (PowerShell) to verify all tools. See `references/environment-setup-ios.md` for installation instructions. See `references/tool-versions.md` for version requirements — the preflight check reads that file directly and warns when an installed version does not match the required one.

---

## Phase 0 — Extract and Detect Framework

### Extract IPA
```bash
# Extract IPA (IPA is a zip file)
unzip app.ipa -d extracted/
cd extracted/Payload/YourApp.app/
```

### Mach-O Analysis
```bash
# Analyze binary structure
otool -l YourApp | rg -A 10 "LC_ENCRYPTION_INFO(_64)?"   # Check encryption (covers arm64)
lipo -info YourApp                                 # Architectures (arm64, armv7, etc.)
file YourApp                                       # Verify Mach-O type
dsdump YourApp > classdump-swift.txt               # Dump Swift classes (if Swift)
class-dump YourApp > classdump-objc.txt              # Dump ObjC classes (if available)
```

> **Reference**: `references/macho-binary-analysis.md` for the complete Mach-O analysis methodology (LC_ENCRYPTION_INFO, LC_CODE_SIGNATURE, segment layout, symbol tables, strip/binary thinning).
> **Reference**: `references/advanced-tools-ios.md` for the deep-dive tool set (Corellium, Hopper, Ghidra, frida-trace, lldb).
> **Reference**: `references/bitcode-analysis.md` when the binary is bitcode-enabled (older App Store builds).
> **Reference**: `references/tool-installation-ios.md` for tool install and troubleshooting.
> **Reference**: `references/libimobiledevice-guide.md` for device pairing, syslog, backup, and filesystem access via the libimobiledevice toolchain.
> **Encrypted binary recovery**: if `cryptid == 1` after `otool -l`, use the bundled `assets/frida-scripts/dump-ios.js` to dump the decrypted binary from memory.

### Framework Detection
Identify the app's architecture early to tailor analysis.

| Framework | Detection Method | Key Artifacts |
|-----------|----------------|---------------|
| **React Native** | `rg "RCTBridgeModule"` · Check for `libReactNative.a` | `index.ios.bundle`, `libReactNative.a` |
| **Flutter** | Check `Frameworks/` for `Flutter.framework` and `App.framework` · Check for `FLT*` keys in Info.plist (`FLTEnableImpeller`, `FLTEnableSurfaceControl`) | `App.framework`, `Flutter.framework`, `flutter_assets/` |
| **Cordova/Ionic** | `rg "cordova"` in Info.plist · Check `www/` directory | `cordova.js`, `config.xml` |
| **Xamarin** | `rg "xamarin"` · Check for `Mono` runtime | `libmonosgen-2.0.dylib` |
| **Unity** | `rg "UnityEngine"` · Check for `UnityFramework.framework` | `Data/Managed/`, `UnityFramework.framework` |
| **Swift Native** | Check for Swift symbols · `dsdump` output shows Swift classes | Swift-only codebase |
| **Objective-C** | Check for ObjC runtime · `class-dump` shows ObjC classes | ObjC-only codebase |

> **Reference**: `references/framework-detection-ios.md` for complete detection scripts, Frida detection hooks, and framework-specific security considerations.
> **Framework-specific deep dives** (load the relevant one when you detect the framework):
> - `references/react-native-ios-security.md`
> - `references/flutter-ios-security.md`
> - `references/cordova-ios-security.md`
> - `references/xamarin-ios-security.md`
> - `references/unity-ios-security.md` (also covers running Unity IL2CPP games in the simulator — Metal heap fix — and IL2CPP reverse engineering with Il2CppDumper on macOS)
> - `references/swiftui-security-deep-dive.md` (even for native SwiftUI apps)
> - `references/core-ml-security.md` and `references/core-ml-security-expanded.md` (apps with on-device ML)

### Obfuscation Detection
- **Swift Obfuscation**: Generic class names (`a.b.c`, `x_1`, `internal_`), mangled symbols
- **LLVM Obfuscator**: Mixed naming, string encryption
- **Custom Obfuscation**: Unusual patterns, mixed naming schemes
- **Third-Party Packers**: iMAS, Arxan, GuardSquare (iXGuard), DexGuard iOS

> **Reference**: `references/static-analysis-patterns-ios.md` for detailed detection patterns.
> **Reference**: `references/obfuscation-detection-ios.md` for SwiftShield, IOSSecuritySuite, Arxan, and Irdeto detection methodology.

### OPTIONAL: MobSF Integration
> **Reference**: `references/mobsf-integration-guide.md` for complete MobSF setup and API usage.

The iOS-Pentesting-Skill offers **optional** Mobile Security Framework (MobSF) integration for automated static and dynamic analysis.

**Key Points**:
- ✅ **OPTIONAL**: User choice, no hard dependency
- ✅ **NON-BLOCKING**: Works perfectly without MobSF
- ✅ **ENHANCEMENT**: MobSF results complement manual analysis
- ✅ **CORRELATION**: Findings merged with manual analysis

**Interactive Setup** (automatically prompts):
```bash
# Run MobSF detection and setup
python3 scripts/setup_mobsf.py
```

This script will:
1. Check if MobSF is already installed
2. Offer installation options if not found
3. Configure API access
4. Test connectivity
5. Save configuration for future sessions

**Quick Start (Docker)**:
```bash
# Install MobSF via Docker
./scripts/install-mobsf-docker.sh

# Configure API
python3 scripts/mobsf_config.py set-url http://127.0.0.1:8000
python3 scripts/mobsf_config.py set-key generate

# Verify configuration
python3 scripts/mobsf_config.py status
```

**Using MobSF in Analysis**:
```bash
# Upload IPA to MobSF
python3 scripts/mobsf_upload.py app.ipa

# Get scan results
python3 scripts/mobsf_export.py --scan-id "<SCAN_ID>"

# Export findings for correlation
python3 scripts/mobsf_export.py --scan-id "<SCAN_ID>" --format json
```

**Alternative: Local Install (no Docker)**:
```bash
# Detect an existing MobSF install or a running server
python3 scripts/mobsf_detect.py

# Install MobSF locally (clones repo + sets up a virtualenv)
./scripts/install-mobsf-local.sh

# Start the local MobSF server
./scripts/run-mobsf-local.sh
```

**Correlation**: merge MobSF's automated detections with your manual source-to-sink findings to deduplicate and enrich evidence using `scripts/mobsf_findings_correlator.py`.

> **NOTE**: MobSF integration is OPTIONAL. The skill works perfectly without it.

---

## Phase 1 — Attack Surface Mapping

### Analyze Info.plist
```bash
plutil -p Info.plist    # Pretty print plist
# Extract specific keys (only works on top-level keys)
plutil -extract CFBundleURLTypes xml1 -o - Info.plist   # CFBundleURLSchemes is nested inside this array
plutil -extract NSAppTransportSecurity xml1 -o - Info.plist
# For nested keys, use PlistBuddy:
/usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes:0:CFBundleURLSchemes" Info.plist
```

### URL Schemes (Deep Links)
Extract and document all custom URL schemes:

| Key | What It Controls | Security Impact |
|-----|----------------|-----------------|
| **CFBundleURLSchemes** | Custom schemes (e.g., `myapp://`) | URL scheme injection via malicious URLs |
| **CFBundleURLTypes** | Scheme declarations | Attack surface enumeration |
| **NSAppTransportSecurity** | TLS/ATS settings | Cleartext traffic, insecure connections |

### Info.plist Security Keys

| Key | What It Controls | Security Checks |
|-----|----------------|-----------------|
| **UIBackgroundModes** | Background capabilities | Unintended background data collection |
| **NSPhotoLibraryUsageDescription** | Photo access | Permission request clarity, photo library scope |
| **NSCameraUsageDescription** | Camera access | Permission request clarity |
| **NSMicrophoneUsageDescription** | Microphone access | Permission request clarity |
| **NSLocationWhenInUseUsageDescription** | Location access | Permission request clarity |
| **NSLocationAlwaysAndWhenInUseUsageDescription** | Background location | Justification for always-on tracking |
| **NSFaceIDUsageDescription** | Face ID biometric | Required since iOS 11; fallback policy |
| **NSContactsUsageDescription** | Contacts access | PII extraction scope |
| **NSHealthShareUsageDescription** | HealthKit read | PII / health data scope |
| **NSHealthUpdateUsageDescription** | HealthKit write | Health data write justification |
| **NSRemindersUsageDescription** | Reminders access | PII scope |
| **NSBluetoothPeripheralUsageDescription** | Bluetooth (legacy) | Legacy key, replaced in iOS 13 |
| **NSBluetoothAlwaysUsageDescription** | Bluetooth (modern) | iOS 13+ required for always-on BLE |
| **NSSpeechRecognitionUsageDescription** | Speech recognition | Audio data exfiltration scope |
| **NSUserTrackingUsageDescription** | App Tracking Transparency | Required for IDFA access since iOS 14.5 |
| **NSAppTransportSecurity** | ATS exceptions | See `references/ats-configuration-guide.md` |
| **LSApplicationQueriesSchemes** | `canOpenURL` whitelist | Enumerates installed apps; surface for fingerprinting |
| **ITSAppUsesNonExemptEncryption** | Export compliance | Triggers App Store export compliance prompt |
| **UIFileSharingEnabled** | iTunes file sharing | Data exposure via iTunes / Files app |
| **UISupportedExternalAccessoryProtocols** | External accessories | Attack surface expansion |
| **UIRequiresPersistentWiFi** | WiFi requirement | Network behavior predictability |
| **NSAppClipboardUsageDescription** | Pasteboard read (UIPasteboard) | macOS Catalyst only; iOS doesn't require usage description — audit clipboard usage via static analysis |

### Entitlements Analysis
```bash
# Extract entitlements from binary
codesign -d --entitlements - YourApp.app/YourApp
```

| Entitlement | Purpose | Security Impact |
|-------------|---------|----------------|
| **keychain-access-groups** | Shared keychain access | Cross-app data sharing |
| **get-task-allow** | Debugger attachment | Debug mode in production — must be `false` in release |
| **application-groups** | App group containers | Shared data between apps / extensions |
| **com.apple.developer.applesignin** | "Sign in with Apple" capability | Required when offering third-party SSO |
| **com.apple.developer.in-app-payments** | Apple Pay capability | Payment flow integrity |
| **com.apple.developer.icloud-container-identifiers** | iCloud document storage | Data exfiltration via iCloud sync |
| **com.apple.developer.icloud-services** | iCloud (CloudKit, Key-Value) | CloudKit data scope |
| **com.apple.developer.ubiquity-container-identifiers** | iCloud ubiquity (Documents) | Document sync scope |
| **com.apple.developer.associated-domains** | Universal Links / Handoff | Deep link / Universal Link routing |
| **com.apple.developer.default-data-protection** | Default `NSFileProtection` class | Determines at-rest encryption for new files |
| **com.apple.developer.pass-type-identifiers** | Wallet pass type | Pass authentication scope |
| **com.apple.developer.healthkit** | HealthKit access | Health data scope |
| **com.apple.developer.homekit** | HomeKit access | Smart home device control scope |
| **aps-environment** (production / development) | Push notifications | APNs token handling, dev vs prod routing |
| **com.apple.developer.networking.wifi-info** | WiFi network info (iOS 13+) | SSID/BSSID exposure; opt-in |
| **com.apple.security.application-groups** | App group containers (App Sandbox — **macOS only**) | N/A on iOS; do not expect in IPA entitlements |
| **com.apple.security.network.client** | Outbound network (App Sandbox — **macOS only**) | N/A on iOS; the iOS sandbox always allows outbound |
| **com.apple.security.network.server** | Inbound network (App Sandbox — **macOS only**) | N/A on iOS; iOS apps cannot bind listening TCP/UDP sockets on cellular or WiFi (sandbox restriction) |

### App Extensions Detection
```bash
# List all app extensions
find . -name "*.appex" -type d
```

Common extensions:
- **Today Widget**: `TodayExtension.appex`
- **Share Extension**: `ShareExtension.appex`
- **Action Extension**: `ActionExtension.appex`
- **Notification Content**: `NotificationContentExtension.appex`

> **Reference**: `references/info-plist-checklist.md` — complete Info.plist key checklist (47 keys).
> **IPC / URL scheme abuse**: see `references/url-scheme-security-guide.md` and `references/universal-links-guide.md`.
> **App extensions** (Today / Share / WidgetKit / Notification Content / Keyboard): `references/app-extensions-security.md`.
> **Privacy manifest** (PrivacyInfo.xcprivacy, App Tracking Transparency): `references/privacy-manifest-ios.md` and `references/ios-privacy-testing.md`.
> **iOS version diffs** (iOS 15 → 18 changes that affect attacks): `references/ios-version-security-changes.md`.

### Enterprise & MDM Apps
In-house / VPP / DEP apps and MDM-managed devices expand the attack surface via configuration profiles, managed app config, and enterprise distribution certificates.
- **Configuration profiles** (`.mobileconfig`): inspect for over-broad payloads, injected trusted CAs, and VPN/proxy settings.
- **Managed app config**: read the `NSUserDefaults` key `com.apple.configuration.managed`.
- **Enterprise certs**: validate the signing identity and provisioning scope (`codesign -dvv`).

> **Reference**: `references/enterprise-app-testing.md`, `references/mdm-security-testing.md`, and `references/configuration-profile-abuse.md`.
> **Dynamic (Phase 4)**: `assets/frida-scripts/mdm-bypass.js` (MDM restriction bypass) and `assets/frida-scripts/enterprise-cert-bypass.js` (enterprise cert trust bypass).
> **Automation**: `references/automation-scripts-ios.md` and `scripts/auto-audit-static-ios.sh` (one-shot static analysis driver for Phases 0–3).

### Data Storage Locations (Quick Reference)

When analyzing data storage, check these locations for sensitive data exposure:

| Location | Path Pattern | What to Check | Tool |
|-----------|-------------|---------------|------|
| **NSUserDefaults** | `Library/Preferences/*.plist` | Tokens, user data, feature flags, config | `plutil -p` |
| **Core Data** | `Library/Application Support/*.sqlite` | Cached API responses, user records, local DB | `sqlite3` |
| **Keychain** | System keychain database | Credentials, encryption keys, certificates | `keychain-dumper`, Frida |
| **Cookies** | `Library/Cookies/*.binarycookies` | Session cookies, authentication tokens | Binary parsing |
| **Cache** | `Library/Caches/` | Cached API responses, images with PII | `find`, `strings` |
| **Snapshots** | `Library/SplashBoard/Snapshots/` | App state screenshots (may contain PII) | Image review |
| **Keyboard** | `Library/Keyboard/` | Autocomplete entries with sensitive input | `strings` |
| **Pasteboard** | System pasteboard | Copied passwords, tokens, sensitive data | Frida hook |
| **WebView Storage** | `Library/WebKit/WebsiteData/` | LocalStorage, IndexedDB, cookies | `sqlite3` |
| **Tmp** | `tmp/` | Temporary files, may contain sensitive data | `find`, `strings` |

> **Full reference**: `references/data-protection-api-guide.md`
> **Testing**: Use `assets/frida-scripts/pasteboard-monitor.js`, `assets/frida-scripts/keylogger-basic.js`

---

## Phase 2 — Targeted Triage

### Scoped Grep Patterns
ALWAYS grep within the app namespace only. Use patterns from `references/static-analysis-patterns-ios.md`:

| Category | Example Patterns (ObjC/Swift) | What to Look For |
|----------|--------------------------------|------------------|
| **WebView sinks** | `loadRequest`, `loadHTMLString`, `evaluateJavaScript` | Loading untrusted URLs |
| **IPC sources** | `openURL(_:)`, `application(_:open:)`, `continue(_:)` | Unsanitized data entry from URL schemes |
| **Keychain** | `SecItemAdd`, `SecItemCopyMatching`, `kSecAttrAccessible` | Insecure storage, weak accessibility |
| **UserDefaults** | `UserDefaults`, `standardUserDefaults`, `set` | Cleartext storage of sensitive data |
| **Pasteboard** | `UIPasteboard.general`, `string`, `setItems` | Data exposure via clipboard |
| **Hardcoded secrets** | `password.*=`, `api[_-]?key`, `"sk_live_`, `secret` | Credentials in code |
| **Crypto** | `kCCAlgorithmAES`, `kCCOptionECBMode`, `MD5`, `SHA1` | Weak algorithms, insecure modes |
| **TLS/ATS** | `NSAllowsArbitraryLoads`, `NSExceptionDomains` | Disabled certificate validation |
| **Logging** | `NSLog`, `print`, `os_log` | Sensitive data in logs |
| **File I/O** | `writeToFile`, `FileManager`, `createFile` | Path traversal, insecure file ops |
| **Background** | `beginBackgroundTask`, `BGTaskScheduler` | Unintended background data collection |
| **Biometric** | `LocalAuthentication`, `evaluatePolicy` | Biometric bypass, fallback to PIN |
| **SQLite** | `sqlite3_exec`, `sqlite3_prepare_v2` | SQL injection |
| **CoreData** | `NSPersistentContainer`, `execute` | Data query injection |

### Binary Analysis Commands
```bash
# Extract strings from binary
strings YourApp | rg -i "(password|key|secret|token|api)"

# List exported symbols (ObjC) — -gU filters out undefined system symbols
nm -gU YourApp | rg " T "

# List dynamic libraries
otool -L YourApp

# Dump Objective-C class methods
class-dump YourApp

# Dump Swift classes (modern)
dsdump YourApp

# Check for specific symbols (e.g., crypto usage) — -gU to skip system library noise
nm -gU YourApp | rg -i "(AES|DES|MD5|SHA)"
```

### Resource File Analysis
Check `Info.plist` and embedded plists for secrets:
```bash
rg -i "(key|token|secret|password|api)" Info.plist
rg -i "(key|token|secret|password|api)" -g "*.plist"
```

> **Reference**: `references/static-analysis-patterns-ios.md` for grep patterns organized by vulnerability type.
> **Reference**: `references/objc-security-patterns.md` and `references/swift-security-patterns.md` for language-specific pitfalls (swizzling, KVO, type-safety, generics).
> **Reference**: `references/runtime-hardening-checks-ios.md` for the runtime hardening controls that are routinely missed: background snapshot obfuscation, custom keyboard risk, AutoFill, screen recording detection, URLSession audit, WKWebView cache cleanup, file protection classes, biometric replay protection, `nscurl` ATS testing, Universal Links validation, and app group containers.

### Phase 2 — Per-area reference files

Use these when a category from the table above lights up:

- **Crypto / CommonCrypto** → `references/commoncrypto-analysis.md`
- **CryptoKit (Swift crypto)** → `references/commoncrypto-analysis.md` § CryptoKit Framework (runtime script: `assets/frida-scripts/cryptokit-hook-ios.js`)
- **Keychain** → `references/keychain-security-guide.md`
- **UserDefaults** → `references/userdefaults-security.md`
- **CoreData** → `references/coredata-security.md`
- **UIPasteboard** → `references/pasteboard-security.md`
- **File protection / NSFileProtection*** → `references/data-protection-api-guide.md`
- **Deserialization security** → `references/insecure-deserialization-ios.md`
- **Passkeys / WebAuthn** → `references/passkeys-security-ios.md`
- **Swift Concurrency** → `references/swift-concurrency-security.md`
- **CloudKit / iCloud sync** → `references/cloudkit-security-ios.md`

### Phase 2 — Runtime Frida scripts

Map the script to the finding category:
- Cryptography → `crypto-hook-ios.js`
- CryptoKit (Swift crypto) → `cryptokit-hook-ios.js`
- Keychain / Secure Enclave → `keychain-dumper.js`, `secure-enclave-probe.js`
- UserDefaults → `nsuserdefaults-dumper.js`
- CoreData → `coredata-interceptor.js`
- Pasteboard → `pasteboard-monitor.js`, `clipboard-exfiltration.js`
- File protection → `data-protection-check.js`, `file-protection-enumerator.js`
- ATS / cleartext → `app-transport-security.js`
- Network → `network-interceptor-ios.js`
- Network.framework (iOS 13+) → `nwconnection-hook-ios.js`
- Deserialization → `deserialization-hook-ios.js`
- Passkeys/WebAuthn (iOS 16+) → `passkeys-hook-ios.js`
- Swift Concurrency → `swift-concurrency-monitor-ios.js`

### SBOM & Supply Chain (OWASP M2)
Enumerate embedded frameworks, third-party SDKs, and their known CVEs:
```bash
# Generate a Software Bill of Materials from the IPA (CycloneDX / SPDX / JSON)
python3 scripts/sbom_generator.py --input app.ipa --format all --output sbom/

# Scan the SBOM for vulnerable or risky dependencies
python3 scripts/dependency_scanner.py --sbom sbom/sbom.json --check-cves --check-licenses --output dep-scan.json
```

> **Reference**: `references/sbom-supply-chain-guide.md` for SBOM formats (CycloneDX/SPDX) and supply-chain risk methodology; `references/third-party-sdk-analysis.md` for per-SDK review (trackers, network behavior, ATS exemptions).
> **Runtime SDK behavior**: `assets/frida-scripts/sdk-tracer.js` enumerates loaded third-party SDKs and hooks their methods for actual network/credential behavior (often more accurate than the static SDK inventory).
> **MobSF correlation** (optional): `scripts/mobsf_findings_correlator.py` merges your manual findings with MobSF's automated ones, deduplicating overlapping detections.

---

## Phase 3 — Data Flow Tracing

### Source-to-Sink Methodology
Map data flow from untrusted sources to dangerous sinks:

#### Common Sources (iOS)

| Source | Method | Example |
|--------|--------|---------|
| **URL Schemes** | `application(_:open:)` | Malicious scheme URLs |
| **Universal Links** | `application(_:continueUserActivity:)` | Universal link abuse |
| **Pasteboard** | `UIPasteboard.general.string` | Data from clipboard |
| **App Groups** | Shared container `NSFileManager` | Inter-app data |
| **XPC** | `NSXPCConnection` | Inter-process communication |
| **Keychain** | `SecItemCopyMatching` | Stored credentials |
| **Notifications** | `UNUserNotificationCenter` | Notification payloads |
| **WebView JS Bridge** | `WKScriptMessageHandler` | Untrusted JS calls |

#### Common Sinks (iOS)

> **iOS scope**: iOS apps run in a sandbox and cannot spawn child processes (no `NSTask`, no `Process`, no `popen`). Realistic "execution" paths on iOS go through WebView JS bridges, XPC, URL schemes, or app group data exfiltration — not OS command execution.

| Sink | Method | Impact |
|------|--------|--------|
| **WebView Load** | `WKWebView.load(_:)`, `loadHTMLString(_:baseURL:)`, `evaluateJavaScript(_:completionHandler:)` | XSS, Phishing, JS bridge abuse |
| **WebView JS Bridge** | `WKScriptMessageHandler` callbacks, `WKScriptMessageHandlerWithReply`, `window.webkit.messageHandlers.*` | Native code execution via injected JS |
| **File Operations** | `Data.write(to:)`, `String.write(toFile:atomically:encoding:)`, `FileManager.createFile(atPath:contents:attributes:)` | Path traversal, sandbox escape, LFI |
| **XPC (ObjC)** | `NSXPCConnection.remoteObjectProxy` method invocations, `NSXPCListenerEndpoint` | IPC injection, privilege escalation |
| **XPC (C-level)** | `xpc_connection_send_message`, `xpc_connection_send_barrier` | XPC message injection, low-level IPC abuse |
| **openURL** | `UIApplication.open(_:options:completionHandler:)` | URL scheme/Universal Link injection, app-to-app attack |
| **canOpenURL** | `UIApplication.canOpenURL(_:)` (requires `LSApplicationQueriesSchemes`) | Installed app enumeration |
| **Keychain Write** | `SecItemAdd`, `SecItemUpdate`, `SecItemDelete` | Credential poisoning, keychain clearing |
| **Pasteboard Write** | `UIPasteboard.general.setItems(_:options:)` | Clipboard exfiltration, data leakage to other apps |
| **SQLite** | `sqlite3_exec`, `sqlite3_prepare_v2` + binding, `FMDB.executeQuery` | SQL injection |
| **CoreData** | `NSFetchRequest` with attacker-influenced `NSPredicate` | Predicate injection, data exfiltration |
| **UserDefaults Write (Swift)** | `UserDefaults.standard.set(_:forKey:)`, `UserDefaults.standard.set(_:forKey:)` variants | Config tampering, sensitive data persistence |
| **UserDefaults Write (ObjC)** | `[[NSUserDefaults standardUserDefaults] setObject:forKey:]`, `setBool:forKey:`, `setInteger:forKey:` | Config tampering, sensitive data persistence |
| **Logging** | `NSLog`, `os_log`, `print` | Sensitive data in logs, log injection |
| **Notifications** | `UNUserNotificationCenter.add(_:withCompletionHandler:)`, `UNMutableNotificationContent` | Notification payload abuse, action hijacking |
| **Biometric** | `LAContext.evaluatePolicy(_:localizedReason:reply:)` | Biometric bypass, fallback to device passcode |

### Decision Rules

| Rule | Condition | Action |
|------|-----------|--------|
| 1 | Direct flow source → sink | Report as **Likely** |
| 2 | Indirect flow via static analysis | Report as **Likely** if path clear |
| 3 | Dynamic/reflective call | Mark as **Needs Dynamic Confirmation** |
| 4 | Native boundary | Mark as **Needs Dynamic Confirmation** |
| 5 | Library code | Verify if app wraps securely |
| 6 | No sanitization | Escalate severity |

### Manual Checks Grep Misses

| Check | Why grep misses | How to verify |
|-------|----------------|---------------|
| **Runtime permissions** | `requestAuthorization()` calls | Trace completion handlers |
| **Custom entitlement protections** | Entitlement checks in code | Look for permission checks |
| **URL scheme handling** | `openURL(_:)` hides parameter extraction | Follow URL parsing and validation |
| **Shared containers** | App groups + shared paths | Map `containerURL(forSecurityApplicationGroupIdentifier:)` |
| **XPC communication** | Interface definitions + dynamic calls | Trace XPC connection setup |
| **WebView JS Bridge** | `WKScriptMessageHandler` + JS code | Map message handlers to JS injection points |

> **Reference**: `references/deep-link-exploitation-ios.md` for modern attack vectors: URL scheme injection, universal link abuse, WebView XSS, pasteboard attacks, XPC injection, app group data leakage, notification abuse.
> **Reference**: `references/url-scheme-security-guide.md` for a complete scheme-by-scheme audit checklist (registration, parsing, validation, origin checks).
> **Reference**: `references/ipc-xpc-guide.md` and `references/xpc-services-security.md` for the XPC connection lifecycle and audit patterns.
> **Reference**: `references/webview-security-ios.md` for WKWebView and UIWebView attack surface (`uiwebview-interceptor.js` runtime hook).
> **Reference**: `references/notification-security.md` for APNS token handling and notification payload abuse.
> **Reference**: `references/app-groups-security.md` for shared container attack surface and `app-groups-inspector.js` runtime hook.

### Phase 3 — Runtime Frida scripts

- URL scheme / openURL → `url-scheme-monitor.js`, `deeplink-security-analyzer.js`, `deep-link-fuzzer.js`
- XPC → `xpc-tracer.js`
- WebView → `uiwebview-interceptor.js`
- Push notifications → `notification-interceptor.js`
- App groups → `app-groups-inspector.js`
- BGTask / background URLSession → `background-fetch-monitor.js`
- Clipboard as exfiltration channel → `keylogger-basic.js` (only when relevant)

---

## Phase 4 — Dynamic Analysis (Optional)

Use when static analysis hits a wall: obfuscation, reflection, native code, runtime protections.

### Simulator-Based Testing (Apple Silicon, no jailbreak required)

When no jailbroken device is available, **SimForge** lets you run a decrypted arm64 iOS app in the iOS simulator and inject dylibs (e.g., Frida Gadget) without `frida-server`. Use it as a fast first iteration before escalating to a physical device.

```bash
# 1. Convert the decrypted .app bundle to simulator platform (patches LC_BUILD_VERSION)
simforge convert /path/to/Payload/YourApp.app

# 2. Ad-hoc re-sign (convert breaks codesig)
codesign -f -s - /path/to/Payload/YourApp.app/Frameworks/*
codesign -f -s - /path/to/Payload/YourApp.app

# 3. Boot a simulator and install
xcrun simctl boot "iPhone 15"
xcrun simctl install booted /path/to/Payload/YourApp.app

# 4. Launch with dylib injection (Frida Gadget, tweak, etc.)
simforge launch --bundleid com.example.app --dylib /path/to/frida-gadget.dylib

# 5. Connect Frida to the Gadget's default port (27042)
frida -H 127.0.0.1:27042 -n Gadget -l assets/frida-scripts/ssl-pinning-bypass-ios.js
```

> **Prerequisite for HTTP(S) interception in the simulator**: install your proxy's CA cert into the simulator's trust store before launching the app. On the simulator this is a single command (no Settings UI, no trust toggle), and the proxy host is `127.0.0.1` — the simulator shares the host's loopback. See `references/simulator-mitm-setup.md` for the full flow (works for Burp Suite, Charles, mitmproxy, Proxyman, OWASP ZAP).

> **Frida on iOS Simulator (Frida 17+)**: Use the `.implementation` hook pattern and attach by PID. All simulator-specific gotchas, CLI syntax changes, and verified recipes are in `references/frida-ios-simulator-workflow.md`.
>
> **Simulator visibility**: By default, the simulator launches in **visible** mode. Only use headless mode when explicitly requested by the user.
>
> **Simulator or physical device?**
> - Simulator (Frida 17+): `references/frida-ios-simulator-workflow.md`
> - Physical device (jailbroken): `references/frida-ios-guide.md`

> **Reference**: `references/simforge-ios-testing.md` for the complete workflow, internal architecture (LC_BUILD_VERSION patching, `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES` injection, tmpfs overlays), use cases (Frida Gadget, Theos tweaks, URL scheme testing, SpringBoard patching), limitations, and troubleshooting. For deep dives, see `references/simforge-emulation-flow.md` (the canonical 10-step procedure with pre-flight checks), `references/simforge-crash-triage.md` (diagnostic methodology with decision tree by `termination.namespace`+`indicator`), and `references/simforge-compatibility.md` (FairPlay / Swift ABI / hardware capability matrix).
> **Unity games in the simulator (Metal heap crash)**: if a converted Unity (IL2CPP) game aborts at graphics init with `MTLStorageModePrivate is required for heaps`, inject the interposer dylib `assets/dylibs/metalheapfix.m` (one-command driver: `scripts/unity_sim_metalfix.sh <UDID> <bundle-id>`). Full methodology + IL2CPP reversing (Il2CppDumper on macOS) in `references/unity-ios-security.md`; triage entry in `references/simforge-crash-triage.md`.

### Troubleshooting: Mixed Load Commands

If the app crashes immediately after `simforge convert` with **dyld assertion** or **SIGSEGV**:

```bash
# Detect the problem: frameworks with BOTH load commands
otool -l Payload/YourApp.app/Frameworks/Suspect.framework/Suspect | grep -A3 "LC_VERSION_MIN\|LC_BUILD"
# Bad output shows BOTH:
#   cmd LC_VERSION_MIN_IPHONEOS
#  version 10.0
#   cmd LC_BUILD_VERSION
#  platform 7

# Clean up using the provided script
python3 scripts/simforge_cleanup.py Payload/YourApp.app

# Re-sign
codesign -f -s - --all-architectures Payload/YourApp.app

# Relaunch
xcrun simctl launch booted com.example.app
```

**Why this happens**: SimForge adds `LC_BUILD_VERSION` for simulator but doesn't remove the legacy `LC_VERSION_MIN_IPHONEOS`. Modern dyld rejects binaries with mixed version commands. See [`references/simforge-legacy-loadcmd-cleanup.md`](references/simforge-legacy-loadcmd-cleanup.md) for detailed methodology.

### Unity IL2CPP Simulator Fix (metalheapfix)

> **Critical**: Unity 2021.x IL2CPP apps crash on the iOS Simulator due to `MTLHeap` using `MTLStorageModeShared` (valid on device, rejected by simulator's `MTLSimDriver`). This is NOT a code signing or packaging issue — it's a Metal driver incompatibility.

**Symptom**: App launches, immediately crashes with:
```
abort → __assert_rtn → Metal MTLReportFailure
MTLSimDriver   -[MTLSimDevice newHeapWithDescriptor:]
UnityFramework MetalHeap::CreateHeap(MTLHeapDescriptor*)
```

**Fix**: A dylib that intercepts `MTLCreateSystemDefaultDevice()` via `DYLD_INTERPOSE` and swizzles `-[MTLSimDevice newHeapWithDescriptor:]` to return `nil`. This forces Unity to fall back to direct buffer allocation (`device.newBufferWithLength:options:`) which the simulator supports.

> **⚠️ WRONG APPROACH (don't repeat)**: Forcing `descriptor.storageMode = MTLStorageModePrivate` passes the heap assertion but crashes at buffer creation (`MTLSimHeap newBufferWithLength:` → XPC error) because Unity's scratch buffers need CPU write access and Private heaps are GPU-only. The correct fix is returning `nil`, not forcing Private.

**Source** (`metalheapfix.m`):
```objc
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>

static id<MTLDevice> (*orig_MTLCreaterSystemDefaultDevice)(void);
static dispatch_once_t onceToken;

static id swizzled_newHeapWithDescriptor(id self, SEL _cmd, MTLHeapDescriptor *descriptor) {
    NSLog(@"[metalheapfix] newHeapWithDescriptor: -> returning nil (force non-heap path)");
    return nil;
}

static void installSwizzle(id<MTLDevice> device) {
    dispatch_once(&onceToken, ^{
        Class cls = object_getClass(device);
        Method original = class_getInstanceMethod(cls, @selector(newHeapWithDescriptor:));
        if (original) {
            method_setImplementation(original, (IMP)swizzled_newHeapWithDescriptor);
            NSLog(@"[metalheapfix] installed heap swizzle on %s", class_getName(cls));
        }
    });
}

__attribute__((used))
static const struct { const char* name; void* replacement; void* original; } interpose_MTLCreaterSystemDefaultDevice
__attribute__((section("__DATA,__interpose"))) = {
    "MTLCreateSystemDefaultDevice",
    (void*)new_MTLCreaterSystemDefaultDevice,
    (void*)&orig_MTLCreaterSystemDefaultDevice
};
```

**Compile on TARGET machine** (do NOT copy dylib from another machine):
```bash
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -dynamiclib -fobjc-arc -Wno-incompatible-function-pointer-types \
  -isysroot "$SDK" -target arm64-apple-ios15.0-simulator \
  -framework Foundation -framework Metal \
  -o metalheapfix.dylib metalheapfix.m
codesign -f -s - metalheapfix.dylib
```

**Complete Unity Simulator Workflow**:
```bash
# 1. SimForge convert (after extraction)
simforge convert /path/to/Payload/YourApp.app

# 2. Ad-hoc sign (simforge breaks codesig)
codesign -f -s - YourApp.app/Frameworks/*
codesign -f -s - YourApp.app

# 3. Verify signature
codesign -v --strict YourApp.app

# 4. Install on SIMULATOR (NOT --console-pty, it kills the app)
UDID="<your iOS 18+ simulator UDID>"
xcrun simctl install $UDID YourApp.app

# 5. Launch with dylib injected (decoupled — stays alive)
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="/path/to/metalheapfix.dylib" \
  xcrun simctl launch $UDID com.example.app

# 6. Verify
xcrun simctl spawn $UDID launchctl list | grep -i appname
xcrun simctl io $UDID screenshot screenshot.png
```

> **⚠️ Runtime version matters**: Test on the SAME iOS runtime that was verified. iOS 18.6 works. iOS 17.5 may NOT work — the `MTLSimDriver` behavior differs between runtimes and the swizzle may not prevent heap creation on older runtimes. ALWAYS check `xcrun simctl list devices` and match the runtime explicitly.

> **Combine with Frida**: You can inject multiple dylibs by colon-separating: `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="/path/to/metalheapfix.dylib:/path/to/frida-gadget.dylib"`

#### Making it Permanent: Embedding the Dylib in the Bundle

The `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES` approach only works per-launch via command line. To make the fix permanent (app launches by tapping the icon), embed the dylib inside the bundle:

**Concept**: Add an `LC_LOAD_DYLIB` load command to the Mach-O binary so dyld loads the dylib automatically at startup. This is the same technique used for Frida Gadget injection, bypass tweaks, and any permanent code modification.

```
┌─────────────────────────────────────┐
│  App.app/                           │
│  ├── Binary (main executable)       │  ← Add LC_LOAD_DYLIB here
│  ├── Frameworks/                    │
│  │   ├── UnityFramework.framework/  │
│  │   ├── metalheapfix.dylib         │  ← Copy dylib here
│  │   └── ...                        │
│  └── Info.plist                     │
└─────────────────────────────────────┘
```

**Step-by-step**:

```bash
# 1. Copy dylib into Frameworks/
cp metalheapfix.dylib App.app/Frameworks/

# 2. Set the install name (dylib's internal identity)
install_name_tool -id "@executable_path/Frameworks/metalheapfix.dylib" \
  App.app/Frameworks/metalheapfix.dylib

# 3. Add LC_LOAD_DYLIB to the main binary
#    install_name_tool CANNOT add new load commands — use one of these:

# Option A: LIEF (Python, most reliable, cross-platform)
pip install lief
python3 -c "
import lief
binary = lief.MachO.parse('App.app/YourBinary')
for b in binary.builders:
    b.add(lief.MachO.DylibCommand.from_path('@executable_path/Frameworks/metalheapfix.dylib'))
    b.write('App.app/YourBinary')
    break
"

# Option B: insert_dylib (third-party)
insert_dylib --strip-codesig --all-yes \
  @executable_path/Frameworks/metalheapfix.dylib App.app/YourBinary

# Option C: optool
optool install -c load -p @executable_path/Frameworks/metalheapfix.dylib \
  -t App.app/YourBinary

# 4. Re-sign everything (order matters — dylib first, bundle last)
codesign -f -s - App.app/Frameworks/metalheapfix.dylib
codesign -f -s - App.app/Frameworks/*
codesign -f -s - App.app
codesign -v --strict App.app

# 5. Install and launch — NO DYLD_INSERT_LIBRARIES needed
xcrun simctl install $UDID App.app
xcrun simctl launch $UDID com.example.app  # just works!
```

> **Unity note**: The main binary is a thin stub (~85KB). Adding `LC_LOAD_DYLIB` to the stub is sufficient — dyld processes `DYLD_INTERPOSE` globally regardless of which binary triggered the load. If it doesn't work, also add the load command to `UnityFramework.framework/UnityFramework`.

> **This technique applies to ANY dylib injection**: Frida Gadget, SSL pinning bypass, jailbreak detection bypass, custom tweaks — the process is identical.

### Frida iOS Integration

> **Frida Installation on macOS (Python 3.14+)**: macOS with Homebrew Python 3.14+ has PEP 668 enabled, which blocks global pip installs. See `references/tool-installation-ios.md` for complete troubleshooting.

```bash
# Recommended: Use pipx (isolated installation)
brew install pipx
pipx install frida-tools
export PATH="$HOME/.local/bin:$PATH"

# Alternative 1: --break-system-packages (dev/testing)
python3 -m pip install --break-system-packages frida frida-tools

# Alternative 2: User directory
python3 -m pip install --user frida frida-tools
export PATH="$HOME/Library/Python/3.14/bin:$PATH"

# Verify installation
frida --version  # Should show 17.x
```

#### Simulator Workflow (Frida 17+)

```bash
# Step-by-step for iOS Simulator:
# 1. Get simulator UDID
UDID=$(xcrun simctl list devices booted | grep -oE "[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}")

# 2. Launch app
xcrun simctl launch booted com.example.app
sleep 2

# 3. Get PID (alternative method if simctl spawn fails)
PID=$(xcrun simctl spawn booted launchctl list 2>/dev/null | rg "com.example.app" | awk '{print $1}' || ps aux | rg "com.example.app" | awk '{print $2}')

# 4. Attach Frida (CRITICAL: Use -D for simulator, not -U)
frida -D $UDID -p $PID -l script.js
```

> **Syscall Hook Limitations**: On simulator, C-level syscall hooks (`stat()`, `fopen()`, `fork()`, `posix_spawn()`) may fail. Use ObjC method hooks via `.implementation` pattern instead. See `references/frida-ios-simulator-workflow.md` for complete patterns and limitations.

#### Device Workflow (Jailbroken)

> `-U` = USB device (jailbroken physical device with frida-server running). For simulator, use `-D <SIMULATOR_UDID>` instead — see [Simulator Workflow](#simulator-workflow-frida-17) below.
>
> **Gotcha**: `frida-ps -U` works without jailbreak (uses lockdownd API), but `frida -U -p` / `frida -U -f` require jailbreak or Frida Gadget. If attach fails with "need Gadget to attach on jailed iOS", the device is not jailbroken — see [references/troubleshooting-ios.md](references/troubleshooting-ios.md#frida-ps--u-works-but-frida--u--p-fails-need-gadget-to-attach-on-jailed-ios) for solutions (SimForge, Gadget injection).

```bash
# Spawn app with hook
frida -U -f com.example.app -l script.js

# Attach to running process
frida -U com.example.app -l script.js
```

#### Frida for iOS
```javascript
// Check if Frida can attach
if (ObjC.available) {
    console.log("Objective-C runtime available");
    // List all loaded classes
    console.log(ObjC.classes);
} else {
    console.log("Objective-C runtime not available");
}
```

> **Reference**: bundled Frida scripts in `assets/frida-scripts/`. See `references/frida-scripts-index.md` for the canonical catalog.
> **Focused runtime triage**: use `pasteboard-monitor.js` for clipboard visibility, `xpc-tracer.js` for XPC/native boundary discovery, and `url-scheme-monitor.js` for URL scheme logging.

> **Script Maturity Levels**:
> - **STABLE**: Production-ready (`ssl-pinning-bypass-ios.js`, `jailbreak-detection-bypass.js`, `biometric-bypass-ios.js`, `network-interceptor-ios.js`, etc.)
> - **BETA**: Functional but incomplete — use with caution

### Objection iOS Commands

```bash
objection -g com.example.app explore

# Enumerate components
ios hooking list classes

# Bypass protections
ios jailbreak disable
ios sslpinning disable
ios keychain dump
ios biometrics bypass
ios pasteboard monitor
ios userdefaults get
```

### iOS Runtime Testing

```bash
# Test URL scheme
xcrun simctl openurl booted "scheme://host/path?param=value"

# Monitor logs (device)
idevicesyslog | rg com.example.app

# Monitor logs (simulator)
log stream --predicate 'process == "YourApp"' | rg com.example.app
```

#### Test URL Scheme Payload
```text
# Example: malicious URL scheme payload
myapp://deeplink?param=<script>alert(1)</script>
```

> **SSL Pinning bypass**: `references/ssl-pinning-bypass-ios.md` + `assets/frida-scripts/ssl-pinning-bypass-ios.js`
> **Anti-tamper bypass**: `references/runtime-integrity-bypass.md` + `assets/frida-scripts/jailbreak-detection-bypass.js` (comprehensive: ObjC file/URL/write-test checks + `stat`/`fopen`/`fork`/`posix_spawn`/`dlopen` syscalls + direct `isJailbroken`/`jailbreakTest` method discovery) for anti-debug, anti-frida, and jailbreak detection bypass. For a quick, low-noise pass on apps that only call `isJailbroken`-style methods (or when the C-level hooks destabilize the target), use the lightweight `assets/frida-scripts/jailbreak-bypass-ios.js` instead. For simulator work, prefer `jailbreak-bypass-ios.js` — it uses the `.implementation` pattern required by Frida 17+ on the simulator (see `references/frida-ios-simulator-workflow.md`).
> **RASP bypass**:
> - Comprehensive guide: `references/rasp-guide-ios.md` + `assets/frida-scripts/rasp-bypass-ios.js` — 15 RASP solutions (FreeRASP, IOSSecuritySuite, JailMonkey, plus 12 commercial: Arxan/Digital.ai, Guardsquare, Promon SHIELD, Appdome, Irdeto, WhiteCryption, Verimatrix, Zimperium, IBM Trusteer, Pradeo, V-Key, Build38). Includes detection methods, weaknesses, and bypass techniques for each.
> - Reusable patterns: `references/rasp-patterns-ios.md` — Generic RASP bypass patterns (dylib injection, SimForge complete conversion, framework stub creation, Frida 17+ simulator patterns, white screen diagnosis). Applicable to any iOS app.
> - Framework stub guide: `references/rasp-framework-stub-guide.md` — How to create Objective-C framework stubs for simulator compatibility (NuDetectSDK, IOSSecuritySuite, FreeRASP templates included)
> **Debugger detection**: `references/debugger-detection-bypass.md` for `sysctl P_TRACED`, `ptrace PT_DENY_ATTACH`, `getppid()` checks and Frida Interceptor bypasses.
> **Secure Enclave probing**: `references/secure-enclave-testing.md` + `assets/frida-scripts/secure-enclave-probe.js`.
> **iCloud Private Relay testing**: `references/icloud-private-relay-testing.md` for relay-aware network captures.
> **Enterprise / MDM bypass**: `assets/frida-scripts/mdm-bypass.js` and `assets/frida-scripts/enterprise-cert-bypass.js` for managed-device restrictions and enterprise certificate trust.
> **Jailbreak setup**: `references/jailbreak-setup-guide.md` for the supported iOS versions and current checkra1n / palera1n / Dopamine coverage.
> **Frida server installation**: `references/frida-server-ios-install.md` for step-by-step Frida server setup on jailbroken devices.
> **Frida on iOS (full guide)**: `references/frida-ios-guide.md` for installation, gadget mode, spawn vs attach.
> **Objection (full guide)**: `references/objection-ios-guide.md` for non-Frida interactive exploration.
> **Reference**: `references/libimobiledevice-guide.md` for device pairing, syslog, backup, screenshot, and IPA installation commands.

---

## Phase 5 — Classification and Reporting

### Confidence Levels

| Level | Definition | Example Evidence |
|-------|-----------|------------------|
| **Confirmed** | Full source-to-sink trace validated | Direct call chain from URL scheme source to `WKWebView.evaluateJavaScript()` with no sanitization |
| **Likely** | Strong evidence, minor gaps | Static trace clear but reflection obscures final sink |
| **Needs Dynamic Confirmation** | Static analysis inconclusive | Obfuscated code or native boundary requiring runtime verification |

### Severity
Use CVSS 4.0. See `references/cvss-scoring-ios.md` for complete methodology, iOS-specific examples, and severity mapping. See `references/cvss-examples-ios.md` for 10 worked examples (ATS bypass, keychain exposure, URL scheme hijack, jailbreak bypass, biometric bypass, etc.).

### Finding Template

````markdown
## [ID] - [Title]

**Confidence**: [Confirmed/Likely/Needs Dynamic Confirmation]
**Severity**: [Critical/High/Medium/Low] (CVSS: [X.X])
**CWE**: [CWE-ID]
**OWASP**: [OWASP Category]

### Description
[1-2 sentences explaining what the vulnerability is]

### Affected Components
- **File**: `path/to/file.m` or `path/to/ViewController.swift`
- **Method**: `methodName` or `@objc func methodName()`
- **Component**: `[ViewController/Service/Extension]` (if applicable)

### Attack Scenario
1. Attacker [action, e.g., crafts malicious URL scheme with payload]
2. App [processing step, e.g., extracts parameter without validation]
3. Data propagates through [call chain]
4. Reaches sink [dangerous operation]
5. Results in [impact, e.g., arbitrary JavaScript execution in WebView context, data exfiltration, or credential theft]

### Proof of Concept
```bash
# Example: URL scheme path traversal
xcrun simctl openurl booted "myapp://deeplink?path=../../../../etc/passwd"
```

Or provide Frida hook script for dynamic verification:
```javascript
// Hook vulnerable method
const targetClass = ObjC.classes.MyViewController;
if (targetClass) {
    const method = targetClass['- processURL:'];
    if (method) {
        Interceptor.attach(method.implementation, {
            onEnter: function(args) {
                console.log("URL processed: " + ObjC.Object(args[2]));
            }
        });
    }
}
```

### Impact
- **Confidentiality**: [High/Medium/Low/None] — [explanation]
- **Integrity**: [High/Medium/Low/None] — [explanation]
- **Availability**: [High/Medium/Low/None] — [explanation]

### Remediation
```swift
// Provide secure code example
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // Parse URL query parameters safely using URLComponents
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let queryItems = components.queryItems,
          let input = queryItems.first(where: { $0.name == "path" })?.value,
          isValidPath(input) else {
        os_log("Invalid path detected")
        return false
    }
    loadContent(at: input)
    return true
}

private func isValidPath(_ path: String) -> Bool {
    // Prevent path traversal and validate format
    return !path.contains("..") && path.range(of: "^/safe/[a-zA-Z0-9_]+\\.html$", options: .regularExpression) != nil
}
```

Or Objective-C:
```objc
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {
    // NSURL has no -queryParameterValue: method. Use NSURLComponents + NSURLQueryItem.
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!components) return NO;  // Invalid URL
    NSArray<NSURLQueryItem *> *queryItems = components.queryItems;

    NSString *input = nil;
    for (NSURLQueryItem *item in queryItems) {
        if ([item.name isEqualToString:@"path"]) {
            input = item.value;
            break;
        }
    }

    if ([self isValidPath:input]) {
        [self loadContentAtPath:input];
    } else {
        NSLog(@"Invalid path detected");
        return NO;
    }
    return YES;
}
```

### CVSS 4.0 Calculation
[Show vector string and score breakdown]
````

### Coverage Statement
End your report with:

```
Coverage Analysis:
- Static Analysis: Complete (all decompiled sources analyzed)
- Dynamic Analysis: [Complete/Partial/Not Performed] (reason if partial)
- Scope: [com.example.app.* bundle only]
- Framework: [React Native/Flutter/Native/Standard]
- Obfuscation: [Swift Obfuscator/Custom/None]

Limitations:
- [List any limitations, e.g., "Native code analysis requires additional tools"]
- [Any components that could not be analyzed]
- [Any findings requiring additional verification]

Total Findings: X (Critical: Y, High: Z, Medium: A, Low: B)
```

> **Reference**: `references/reporting-templates-ios.md` for executive summary format, remediation priority matrix, and presentation templates.

### Automated Report Generation

Use the `generate-report.py` script to generate professional HTML or Markdown reports from findings JSON:

```bash
# Generate HTML report
python3 scripts/generate-report.py \
  --input findings.json \
  --output report.html \
  --app-name "My App" \
  --bundle-id "com.example.app"

# Generate Markdown report
python3 scripts/generate-report.py \
  --input findings.json \
  --output report.md \
  --app-name "My App" \
  --bundle-id "com.example.app"
```

The script supports both JSON array format and JSONL (one finding per line) and automatically:
- Sorts findings by severity (Critical first)
- Calculates CVSS 4.0 severity scores
- Generates executive summary with risk rating
- Maps OWASP MASTG categories
- Provides formatted proof of concept and remediation sections

See `scripts/test-findings.json` for the expected JSON structure.

> **Reference**: `references/reporting-templates-ios.md` for the full executive-summary format, remediation priority matrix, and presentation slide templates.
> **Reference**: `references/owasp-mastg-ios-checklist.md` for the full MASTG test catalog (use it to make sure every applicable test has been run before signing off the report).
> **Reference**: `references/ios-privacy-testing.md` for the privacy/ATT/Privacy Manifest section of the report.

---

## IPA Modification Workflow

### 0. Optional: Convert for simulator testing (Apple Silicon)

Before any modification, if you intend to test the app in the iOS simulator instead of a physical device, run `simforge convert` to patch the Mach-O `LC_BUILD_VERSION` to `PLATFORM_IOSSIMULATOR`. This breaks the original code signature, so re-sign (step 3) becomes mandatory.

```bash
simforge convert /path/to/Payload/YourApp.app
# Re-signing in step 3 below will also cover this case
```

> **Reference**: `references/simforge-ios-testing.md` for the full simulator-based modification + dylib injection flow.

### 1. Extract
```bash
unzip app.ipa -d app-extracted/
cd app-extracted/Payload/YourApp.app/
```

### 2. Modify

#### Binary Patching
Use tools like `otool`, `jtool2`, or hex editor to patch binary:
```bash
# Example: NOP out jailbreak detection
jtool2 -d YourApp > disassembly.txt
# Or specify architecture: ARCH=arm64 jtool2 -d YourApp > disassembly.txt
# Edit binary with hex editor or jtool2
```

#### Resource Modification
Edit `Info.plist` or embedded resources:
```xml
<!-- Example: disable ATS -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### 3. Re-sign
```bash
# Remove existing signature
codesign --remove-signature YourApp.app

# Embed the provisioning profile INSIDE the .app bundle (codesign has no --provisioning-profile flag;
# the standard workflow is to place the .mobileprovision as embedded.mobileprovision inside the bundle)
cp YourProfile.mobileprovision YourApp.app/embedded.mobileprovision

# Sign with new identity and embedded entitlements
codesign -f -s "iPhone Distribution: Your Team" \
  --entitlements entitlements.plist \
  YourApp.app

# Verify signature
codesign -dvv YourApp.app
```

### 4. Re-package
```bash
# Repackage IPA
cd ../../
zip -r app-modified.ipa Payload/
```

### 5. Install and Verify
```bash
# Install on device
ideviceinstaller install app-modified.ipa

# Install on simulator.
# Step 4 left the shell in app-extracted/ (the IPA was zipped from there),
# so the bundle is at ./Payload/YourApp.app relative to the current directory.
cd Payload && xcrun simctl install booted YourApp.app
# OR use an absolute path:
# xcrun simctl install booted /full/path/to/app-extracted/Payload/YourApp.app
```

> **Reference**: `references/dynamic-analysis-setup-ios.md` for advanced repackaging, code signing, and installation. See `references/repackaging-ios-guide.md` for binary patching edge cases and troubleshooting.

---

## Examples

### Example 1: Quick IPA Assessment

**User says**: "Audit this IPA com.example.app.ipa"

**Actions**:
1. Extract IPA: `unzip app.ipa -d extracted/`
2. Detect framework: `otool -l YourApp | rg "LC_ENCRYPTION_INFO"`
3. Analyze Info.plist: `plutil -p Info.plist`
4. Search for secrets: `strings YourApp | rg -i "password|key|secret"`
5. Generate CVSS report using methodology in Phase 5

**Result**: Complete security assessment with vulnerability findings

### Example 2: SSL Pinning Bypass

**User says**: "Bypass SSL pinning in target.app"

**Actions**:
1. Attach Frida: `frida -U -f com.example.app -l ssl-pinning-bypass-ios.js`
2. If fails, consult `references/ssl-pinning-bypass-ios.md`
3. Verify network traffic is unencrypted

**Result**: App accepts all certificates, enabling MITM testing

### Example 3: IPA Modification and Testing

**User says**: "Modify this IPA to disable jailbreak detection"

**Actions**:
1. Extract IPA: `unzip app.ipa -d extracted/`
2. Patch binary using `jtool2` or hex editor
3. Re-sign: `codesign -f -s - YourApp.app`
4. Re-package: `zip -r app-modified.ipa Payload/`
5. Install: `ideviceinstaller install app-modified.ipa`

**Result**: Modified IPA that bypasses jailbreak detection

### Example 4: URL Scheme Abuse Testing

**User says**: "Test URL schemes in myapp.ipa for vulnerabilities"

**Actions**:
1. Extract schemes from Info.plist: `plutil -p Info.plist | grep CFBundleURLSchemes`
2. Analyze handlers: Check `application(_:open:options:)` implementation
3. Test with Frida: `frida -D $UDID -p $PID -l url-scheme-monitor.js`
4. Fuzz schemes: `xcrun simctl openurl booted "myapp://payload"`

**Result**: List of vulnerable URL schemes with PoC payloads

### Example 5: Jailbreak Detection Bypass (Simulator)

**User says**: "Run this app in simulator and bypass jailbreak detection"

**Actions**:
1. Get simulator UDID: `UDID=$(xcrun simctl list devices booted | grep -oE "[A-F0-9-]{36}" | head -1)`
2. Launch app: `xcrun simctl launch booted com.example.app`
3. Get PID: `PID=$(xcrun simctl spawn booted launchctl list | rg "com.example.app" | awk '{print $1}')`
4. Attach with bypass: `frida -D $UDID -p $PID -l jailbreak-bypass-ios.js`

**Result**: App runs in simulator without jailbreak restrictions

---

## Real-World Vulnerability Patterns

Patterns discovered from disclosed vulnerability reports (HackerOne) that are NOT covered by standard testing methodologies. These represent gaps where mobile apps deviate from web security assumptions.

### Pattern 1: Rate Limiting Bypass on Mobile Endpoints

**Vulnerability**: Authentication endpoints on mobile often lack rate limiting, even when web equivalents enforce lockouts.

**Real Case**: H1-160109 (Instacart iOS) - Web locked after 15 attempts, mobile allowed 50+ password guesses without restrictions. H1-2245437 (Files iOS) - PIN code with unlimited attempts.

**Detection with this skill**:

```bash
# 1. Identify auth endpoints
rg "oauth|login|token|pin" -g "*.m" -g "*.swift"

# 2. Monitor with rate limit detector
frida -U -f com.example.app -l assets/frida-scripts/mobile-rate-limit-detector-ios.js

# 3. Simulate brute force (Burp Intruder or Frida loop)
# Send 20+ login attempts with different passwords
```

**Expected Finding**:
```
[VULN] 50 attempts to /oauth/token
       NO rate limiting detected after 50 requests
       Reference: H1-160109 (Instacart iOS), H1-2245437 (Files iOS)
       Impact: Brute force possible, account takeover risk HIGH
```

**PoC**:
```javascript
// In Frida, simulate brute force:
for (let i = 0; i < 50; i++) {
    // Send POST /oauth/token with password + i
}
// If all return 401 except one, no rate limiting
```

**Remediation**:
```swift
// Enforce consistent rate limiting across platforms
private let maxAttempts = 5
private let lockoutTime: TimeInterval = 300

func attemptLogin() {
    guard attemptCount < maxAttempts else {
        // Lock account
        return
    }
    attemptCount += 1
}
```

**Related Script**: `assets/frida-scripts/mobile-rate-limit-detector-ios.js`

---

### Pattern 2: WebView XSS via Unsanitized HTML

**Vulnerability**: WebViews loading HTML content without sanitization, especially when HTML contains user input or template literals.

**Real Cases**: H1-575562 (Nextcloud iOS) - Blind XSS via unsanitized file content; H1-991713, 993670, 1436558, 1438028 (Brave iOS) - Multiple XSS vectors through WebView HTML injection.

**Detection with this skill**:

```bash
# 1. Monitor WebView HTML loading
frida -U -f com.example.app -l assets/frida-scripts/webview-xss-scanner-ios.js

# 2. Trigger HTML loading with user input
# Enter XSS payloads in user-controllable fields
```

**Expected Finding**:
```
[VULN] Unsanitized HTML loading detected in WebView
       Pattern: {{username}}
       Type: template
       Impact: XSS possible if attacker controls HTML source
       Reference: H1-575562 (Nextcloud WebView XSS)
```

**PoC**:
```javascript
// Test payloads:
// Template injection: {{7*7}} → 49
// XSS: <script>alert(document.domain)</script>
// If executed, XSS confirmed
```

**Remediation**:
```swift
// Sanitize HTML before loading in WebView
func loadSafeHTML(_ html: String, baseURL: URL) {
    let sanitized = html
        .replacingOccurrences(of: "<script", with: "&lt;script")
        .replacingOccurrences(of: "{{", with: "")
        .replacingOccurrences(of: "${", with: "")
    webView.loadHTMLString(sanitized, baseURL: baseURL)
}
```

**Related Script**: `assets/frida-scripts/webview-xss-scanner-ios.js`

---

### Pattern 3: Deep Link CSRF (Missing Token Validation)

**Vulnerability**: State-changing deep links lack CSRF tokens, allowing attackers to trigger actions on behalf of users.

**Real Case**: H1-805073 (Periscope iOS) - `pscp://user/<id>/follow` could be triggered from any context without CSRF token, allowing forced follows and account takeover.

**Detection with this skill**:

```bash
# 1. Monitor deep link processing
frida -U -f com.example.app -l assets/frida-scripts/deeplink-csrf-validator-ios.js

# 2. Trigger deep link with sensitive action
xcrun simctl openurl booted "myapp://follow?user=victim"
```

**Expected Finding**:
```
[VULN] Sensitive action via deep link WITHOUT CSRF token
       URL: myapp://follow?user=victim
       Action: follow
       Impact: CSRF possible - forced action without user consent
       Reference: H1-805073 (Periscope deep link CSRF)
```

**PoC**:
```html
<!-- Attacker's website -->
<a href="myapp://follow?user=attacker">Click for prize!</a>
<!-- If victim clicks and gets forced to follow attacker, CSRF confirmed -->
```

**Remediation**:
```swift
// Validate CSRF token before processing deep link actions
func processDeepLink(_ url: URL) {
    guard let token = url.queryParameters?["token"],
          validateCSRFToken(token) else {
        // Reject deep link without valid token
        return
    }
    // Process action
}
```

**Related Script**: `assets/frida-scripts/deeplink-csrf-validator-ios.js`

---

### Pattern 4: Missing SSL Certificate Validation

**Vulnerability**: Apps that don't validate SSL/TLS certificates are vulnerable to MITM attacks without any bypass needed.

**Real Case**: H1-168538 (Twitter iOS 6.62-6.62.1) - Did not validate SSL certificates. A transparent proxy was sufficient to intercept traffic and extract OAuth tokens without installing a trusted CA certificate.

**Detection with this skill**:

```bash
# 1. Run SSL validation checker
frida -U -f com.example.app -l assets/frida-scripts/ssl-validation-checker-ios.js

# 2. Wait 5 seconds for analysis verdict
```

**Expected Finding**:
```
[!] CRITICAL VULNERABILITY
[!] App does NOT validate SSL certificates!
[!] MITM attacks possible WITHOUT any bypass needed
[!] Reference: H1-168538 (Twitter iOS cert validation bypass)
```

**PoC**:
```bash
# Set up proxy WITHOUT installing CA certificate
# If app traffic visible, validation is missing
mitmproxy --listen-port 8080
# Configure device proxy, open app - if traffic visible → VULNERABLE
```

**Remediation**:
```swift
// Implement proper NSURLSessionDelegate
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    let serverTrust = challenge.protectionSpace.serverTrust!
    let credential = URLCredential(trust: serverTrust)
    completionHandler(.useCredential, credential)
}
```

**Related Script**: `assets/frida-scripts/ssl-validation-checker-ios.js`

---

### Pattern 5: Biometric Deeplink Bypass

**Vulnerability**: Deep links navigate to protected features without requiring biometric re-authentication when app is already unlocked.

**Real Case**: H1-637194 (Shopify Mobile) - When app was open, deep links could bypass fingerprint authentication and directly access protected features like settings/payment.

**Detection with this skill**:

```bash
# 1. Monitor biometric and navigation events
frida -U -f com.example.app -l assets/frida-scripts/biometric-deeplink-bypass-ios.js

# 2. Authenticate with biometric
# 3. Wait 10+ seconds (past re-auth timeout)
# 4. Trigger deep link to protected feature
xcrun simctl openurl booted "myapp://settings"
```

**Expected Finding**:
```
[VULN] Protected view accessed WITHOUT recent biometric
       View: SettingsViewController
       Biometric was 15000ms ago
       Deep link was 2000ms ago
       Reference: H1-637194 (Shopify deeplink bypass)
```

**PoC**:
```bash
# 1. Authenticate with fingerprint
# 2. Wait >5 seconds
# 3. Trigger: myapp://payment
# 4. If payment screen opens WITHOUT fingerprint → VULNERABLE
```

**Remediation**:
```swift
// Require biometric re-auth for protected features
var lastBiometricAuth: Date?

func navigateToProtectedFeature() {
    let timeout: TimeInterval = 5.0
    if let lastAuth = lastBiometricAuth,
       Date().timeIntervalSince(lastAuth) < timeout {
        // Recent auth, allow
        showProtectedFeature()
    } else {
        // Require re-auth
        requestBiometric { success in
            if success { showProtectedFeature() }
        }
    }
}
```

**Related Script**: `assets/frida-scripts/biometric-deeplink-bypass-ios.js`

---

## Troubleshooting

### Encrypted Binary (FairPlay)
**Error**: `LC_ENCRYPTION_INFO cryptid 1` - binary cannot be analyzed
**Cause**: App Store FairPlay encryption
**Solution**: Decrypt with `frida-ios-dump`, `Clutch`, or `bagbak` on a jailbroken device. See `references/macho-binary-analysis.md` §Encryption.

### Frida Cannot Attach
**Error**: "Failed to attach", "Process not found", or immediate disconnect
**Cause**: Ptrace protection, anti-debug, or app crashed
**Solution**:
```bash
# Check if app is ptrace-protected
otool -l YourApp | rg LC_CODE_SIGNATURE
# Check entitlements
codesign -d --entitlements - YourApp.app/YourApp
# Disable debugger detection with jailbreak bypass
frida -U -f com.example.app -l assets/frida-scripts/jailbreak-detection-bypass.js
```

### Obfuscated Swift Code Unreadable
**Error**: dsdump shows unreadable or mangled symbols
**Cause**: Swift obfuscation
**Solution**:
```bash
# Identify obfuscation first
dsdump YourApp | head -50
# Use swift-demangle
swift-demangle "<mangled_symbol>"
# See references/static-analysis-patterns-ios.md → "Obfuscation Patterns"
# Switch to Phase 4 (dynamic analysis) for runtime behavior
```

### When to Escalate to Dynamic Analysis
**Error**: Static analysis produces no conclusive result
**Cause**: Obfuscation unclear, reflection, native code boundary, anti-debug/jailbreak detection, or SSL pinning hides the real behavior
**Solution**: Proceed to Phase 4 using `references/dynamic-analysis-setup-ios.md`.

### Info.plist Cannot Parse
**Error**: "Cannot parse plist" or plutil fails
**Cause**: Corrupted or binary plist format
**Solution**:
```bash
# Convert to XML for inspection
plutil -convert xml1 Info.plist -o -
# Re-encode if needed
plutil -convert binary1 Info.plist -o
```

### Class Dump Fails
**Error**: dsdump or class-dump produces no output
**Cause**: Binary stripped, protected, or not Mach-O
**Solution**:
```bash
# Verify architecture
lipo -info YourApp
# For Swift-only apps, use dsdump
# For ObjC, use class-dump
# Check for hardening: otool -l YourApp | rg -A 5 LC_CODE_SIGNATURE
```

### Quick Device Verification Checklist
```bash
# 1. Check if device is connected via USB
idevice_id -l

# 2. Get device identity (model, iOS version, arch)
ideviceinfo | grep -E "^(DeviceName|ProductVersion|ProductType|ModelNumber|CPUArchitecture|SerialNumber)"

# 3. Check pairing status
idevicepair validate

# 4. List installed apps
ideviceinstaller list          # user apps
ideviceinstaller list --all    # all apps (system + user)

# 5. Verify Frida + jailbreak (physical device only)
#    frida-ps -U listing processes = jailbreak detected + frida-server running
frida-ps -U | head -5          # any output confirms Frida is ready
frida-ps -Uai | head -15       # installed + running apps with bundle IDs
#    For simulator, use: frida-ps -D "<SIMULATOR_UDID>"
#    NOTE: frida-ps works via lockdownd (no jailbreak). If frida-ps -U works
#    but frida -U -p fails, the device is NOT jailbroken — see troubleshooting-ios.md.
```

### Device Not Found
**Error**: "No device found" or idevice commands fail
**Cause**: Device not connected, usbmuxd not running, or driver issue
**Solution**:
```bash
# Check device connection
idevice_id -l
# Restart usbmuxd (macOS)
sudo launchctl stop com.apple.usbmuxd && sudo launchctl start com.apple.usbmuxd
# On Linux: sudo systemctl restart usbmuxd
```

### Simulator App Crashes Immediately
**Error**: App launches but crashes before main()
**Cause**: FairPlay encrypted, code signature invalid, or incompatible platform
**Solution**: See `simforge-crash-triage.md` for decision tree. Verify:
```bash
# Check encryption
otool -l YourApp | rg -A 4 LC_ENCRYPTION
# Check signature
codesign -v --strict YourApp
# Check platform
otool -l YourApp | rg -A 4 LC_BUILD_VERSION
```

### Jailbreak Detection Persists
**Error**: App still detects jailbreak after bypass attempts
**Cause**: Multiple detection points, custom checks, or server-side validation
**Solution**: Use comprehensive bypass in `assets/frida-scripts/jailbreak-detection-bypass.js`. See `references/jailbreak-detection-bypass-ios.md` for full methodology.

> **For comprehensive troubleshooting**, see `references/troubleshooting-ios.md` for detailed diagnosis of toolchain issues, environment problems, and common failure patterns.

---

## CI/CD and DevSecOps Integration

When integrating iOS security testing into CI/CD pipelines or automating security checks in development workflows, consider these tools and practices:

### CI/CD Platform Security
- **GitHub Actions**: See `references/github-actions-ios-security.md` for secure workflow patterns, secrets management, and artifact handling in iOS projects.
- **Fastlane**: See `references/fastlane-security.md` for secure automation, lane hardening, and credential protection in iOS build/deploy pipelines.
- **General CI/CD**: See `references/ci-cd-integration-ios.md` for integrating automated security testing into any CI/CD platform (Jenkins, GitLab CI, CircleCI, etc.).

### Automation Scripts
The `scripts/` directory includes automation-friendly tools:
- `scripts/auto-audit-static-ios.sh` — One-shot static analysis driver for Phases 0–3
- `scripts/sbom_generator.py` — Generate SBOMs for supply chain security
- `scripts/dependency_scanner.py` — Scan dependencies for CVEs and license compliance
- `scripts/generate-report.py` — Generate reports from findings JSON
- `scripts/check_docs_consistency.py` — Validate that the documentation matches the code
- `scripts/selftest.py` — Functional self-test: runs the scripts with real inputs and asserts on their behaviour (exit code and output), not just on their syntax. No device, no simulator and no network required
- `scripts/frida_harness.js` — Loads every bundled Frida script under a simulated Frida API: a script that parses but aborts on load (`process.on(...)`, `Java.perform`, a removed API) is caught before it reaches a device. Run by `selftest.py` and by CI

See `references/automation-scripts-ios.md` for complete automation workflow integration.

---

## References Index

| Phase | Files |
|-------|-------|
| Start | `getting-started-ios`, `troubleshooting-ios`, `tool-versions`, `frida-dynamic-analysis-ios`, `ios-pentesting-decision-tree` |
| 0 | `environment-setup-ios`, `tool-installation-ios`, `static-analysis-patterns-ios`, `macho-binary-analysis`, `framework-detection-ios`, `ipa-extraction-guide`, `mobsf-integration-guide`, `advanced-tools-ios`, `bitcode-analysis`, `libimobiledevice-guide` |
| 1 | `info-plist-checklist`, `entitlements-security-guide`, `ios-version-security-changes`, `app-extensions-security`, `url-scheme-security-guide`, `universal-links-guide`, `ats-configuration-guide`, `privacy-manifest-ios`, `app-groups-security`, `insecure-deserialization-ios`, `passkeys-security-ios`, `swift-concurrency-security`, `cloudkit-security-ios` |
| 2 | `commoncrypto-analysis`, `keychain-security-guide`, `userdefaults-security`, `coredata-security`, `pasteboard-security`, `data-protection-api-guide`, `objc-security-patterns`, `swift-security-patterns`, `side-channel-analysis-ios`, `memory-analysis-ios` |
| 3 | `url-scheme-security-guide`, `deep-link-exploitation-ios`, `deep-link-security-checklist`, `app-groups-security`, `xpc-services-security`, `ipc-xpc-guide`, `webview-security-ios`, `notification-security`, `phishing-attacks-ios` |
| 4 | `jailbreak-setup-guide`, `jailbreak-detection-bypass-ios`, `frida-server-ios-install`, `frida-ios-guide`, `frida-ios-simulator-workflow`, `objection-ios-guide`, `ssl-pinning-bypass-ios`, `dynamic-analysis-setup-ios`, `debugger-detection-bypass`, `runtime-integrity-bypass`, `secure-enclave-testing`, `icloud-private-relay-testing`, `libimobiledevice-guide`, `simforge-ios-testing`, `simforge-emulation-flow`, `simforge-crash-triage`, `simforge-compatibility`, `simforge-scripts-index`, `simforge-legacy-loadcmd-cleanup`, `simulator-mitm-setup`, `rasp-guide-ios`, `rasp-patterns-ios`, `rasp-framework-stub-guide` |
| 5 | `cvss-scoring-ios`, `reporting-templates-ios`, `owasp-mastg-ios-checklist`, `ios-privacy-testing`, `cvss-examples-ios`, `frida-scripts-index`, `runtime-hardening-checks-ios` |
| Mod | `repackaging-ios-guide`, `obfuscation-detection-ios`, `bitcode-analysis` |
| FW | `react-native-ios-security`, `flutter-ios-security`, `cordova-ios-security`, `xamarin-ios-security`, `unity-ios-security`, `swiftui-security-deep-dive`, `core-ml-security`, `core-ml-security-expanded` |
| Tools | `advanced-tools-ios`, `environment-setup-ios`, `tool-installation-ios`, `tool-versions`, `linux-ios-analysis-workarounds` |
| CI | `automation-scripts-ios`, `ci-cd-integration-ios`, `github-actions-ios-security`, `fastlane-security` |
| Cross | `ios-version-security-changes`, `objc-security-patterns`, `swift-security-patterns` |
| SC | `sbom-supply-chain-guide`, `third-party-sdk-analysis` |
| Ent | `enterprise-app-testing`, `mdm-security-testing`, `configuration-profile-abuse` |

**Scripts**: `preflight-check.sh`, `preflight_check.py`, `preflight-check.ps1`, `auto-audit-static-ios.sh`, `quick-static-analysis.sh`, `generate-report.py`, `test-findings.json`, `sbom_generator.py`, `dependency_scanner.py`, `_scripts_path.py` (internal sys.path helper, do not invoke directly), `screenshot-extractor.sh`, `screenshot_extractor_sim.py`, `screenshot_extractor_device.py`.

**SimForge scripts** (8 in `scripts/`, for iOS app → iOS simulator emulation):
- `simforge_preflight.py` — 5-check pre-flight (arm64, FairPlay, CFBundleSupportedPlatforms, legacy LC, Swift ABI). Run BEFORE patching.
- `simforge_apply.py` — applies the canonical 5-step patch flow (simforge + vtool + Info.plist + 4-sub-step re-signing).
- `simforge_cleanup.py` — removes the legacy `LC_VERSION_MIN_IPHONEOS` command after conversion (backs the binary up before rewriting it).
- `simforge_binaries.py` — internal helper (do not invoke directly): single source of truth for the Mach-O binaries inside a bundle, shared by `simforge_preflight.py` and `simforge_apply.py`.
- `simforge_install_launch.sh` — boots simulator, installs, launches, reports crash location.
- `simforge_triage.py` — parses `.ips` untruncated + applies decision tree by `termination.namespace`+`indicator`.
- `simforge_iterate.sh` — framework-by-framework iteration loop (launch → triage → fix → relaunch).
- `unity_sim_metalfix.sh` — compiles + injects the metalheapfix interposer dylib so Unity (Metal) games run in the simulator (fixes the `MTLStorageModePrivate is required for heaps` crash). Usage: `unity_sim_metalfix.sh <UDID> <bundle-id>`.
- See `references/simforge-scripts-index.md` for end-to-end usage.

**Repo consistency**: `check_docs_consistency.py` — validates that the documentation matches the code (script references, Frida catalog, declared counts, the reference index, the README file trees and the CLI signature of every documented command). Run it after changing a script, adding a Frida script or editing a reference; it is the gate that stops the documentation from drifting again. It also runs in CI (`.github/workflows/ci.yml`).

**MobSF (optional)**: `setup_mobsf.py`, `mobsf_config.py`, `mobsf_detect.py`, `mobsf_upload.py`, `mobsf_export.py`, `mobsf_client.py`, `mobsf_findings_correlator.py`, `install-mobsf-docker.sh`, `install-mobsf-local.sh`, `run-mobsf-local.sh`.

**Assets — native interposer dylibs** (`assets/dylibs/`, NOT Frida JS — compiled-at-use `.m` sources injected via `DYLD_INSERT_LIBRARIES`; see `assets/dylibs/README.md`):
- `metalheapfix.m` — Phase 4 — runs Unity (Metal) games in the iOS Simulator by forcing Unity's non-heap allocation path. Driver script: `scripts/unity_sim_metalfix.sh`.

**Assets — Frida scripts** (73 in `assets/frida-scripts/`, all listed in `references/frida-scripts-index.md`):

> **Note**: For simulator work with Frida 17+, prefer scripts using the `.implementation` pattern (see `references/frida-ios-simulator-workflow.md`).

| Script | Mapped to SKILL.md phase |
|---|---|
| `binary-class-dump.js` | Phase 0 — runtime class enumeration |
| `dump-ios.js` | Phase 0 — encrypted binary decryption |
| `ios-static-analysis.js` | Phase 0/2 — runtime static analysis |
| `objc-api-explorer.js` | Phase 0 — runtime API surface exploration |
| `objc-method-observer.js` | Phase 2 — non-invasive method observation |
| `objc-method-tracer.js` | Phase 2 — generic method tracer |
| `ios-utilities.js` | Phase 0/2 — shared helpers used by other scripts |
| `keychain-dumper.js` | Phase 2 — keychain item extraction (jailbroken) |
| `nsuserdefaults-dumper.js` | Phase 2 — UserDefaults enumeration |
| `pasteboard-monitor.js` | Phase 2 — clipboard read/write logging |
| `data-protection-check.js` | Phase 2 — NSFileProtection audit |
| `file-protection-enumerator.js` | Phase 2 — file-level protection enum |
| `secure-enclave-probe.js` | Phase 2 — SecAccessControl / Secure Enclave usage |
| `crypto-hook-ios.js` | Phase 2 — CommonCrypto operation hooks |
| `cryptokit-hook-ios.js` | Phase 2 — CryptoKit (Swift crypto) operation hooks |
| `deserialization-hook-ios.js` | Phase 2 — NSKeyedUnarchiver / deserialization hooks (MASTG-TEST-0018) |
| `app-transport-security.js` | Phase 2 — ATS / cleartext-traffic monitoring |
| `network-interceptor-ios.js` | Phase 2 — NSURLSession traffic capture |
| `nwconnection-hook-ios.js` | Phase 2 — Network.framework (NWConnection) hooks (iOS 13+) |
| `passkeys-hook-ios.js` | Phase 2 — Passkeys/WebAuthn hooks (iOS 16+) |
| `swift-concurrency-monitor-ios.js` | Phase 2 — Swift async/await/Task monitoring (iOS 15+) |
| `coredata-interceptor.js` | Phase 2 — CoreData stack hooks |
| `notification-interceptor.js` | Phase 3 — push notification payloads |
| `url-scheme-monitor.js` | Phase 3 — URL scheme / openURL logging |
| `deeplink-security-analyzer.js` | Phase 3 — token / OAuth exposure in deep links |
| `deep-link-fuzzer.js` | Phase 3 — URL scheme fuzzer |
| `app-groups-inspector.js` | Phase 3 — shared container inspection |
| `xpc-tracer.js` | Phase 3 — NSXPCConnection / native XPC messages |
| `uiwebview-interceptor.js` | Phase 3 — WKWebView / UIWebView hooks |
| `keylogger-basic.js` | Phase 3 — UITextField/UITextView input capture |
| `clipboard-exfiltration.js` | Phase 3 — clipboard exfiltration detection |
| `background-fetch-monitor.js` | Phase 3 — BGTask / NSURLSession background |
| `ssl-pinning-bypass-ios.js` | Phase 4 — SSL pinning bypass (STABLE) |
| `anti-frida-bypass-advanced-ios.js` | Phase 4 — advanced anti-Frida detection bypass (IOSSecuritySuite/FreeRASP/JailMonkey/Trusteer/Slayer RASP) |
| `jailbreak-detection-bypass.js` | Phase 4 — comprehensive jailbreak bypass (use on physical devices): ObjC + C syscalls + write-test + method discovery (STABLE) |
| `biometric-bypass-ios.js` | Phase 4 — LAContext bypass (STABLE) |
| `flutter-ssl-pinning-ios.js` | Phase 4 — Flutter pinning bypass (STABLE) |
| `flutter-ios-hook.js` | Phase 4 — FlutterMethodChannel hooks |
| `react-native-ios-hook.js` | Phase 4 — RCTBridge module hooks |
| `sdk-tracer.js` | Phase 4/SC — third-party SDK behavior |
| `mobsf-api-integration.js` | Phase 4 — MobSF output correlation |
| `mdm-bypass.js` | Phase 4/Ent — MDM restriction bypass (Ent/MDM) |
| `enterprise-cert-bypass.js` | Phase 4/Ent — enterprise certificate trust bypass |
| `memory-dumper-ios.js` | Phase 2 — memory secret scanning (STABLE) |
| `cookie-dumper-ios.js` | Phase 2 — NSHTTPCookieStorage extraction |
| `class-explorer-ios.js` | Phase 0 — ObjC class/method listing with filtering |
| `jailbreak-bypass-ios.js` | Phase 4 — lightweight jailbreak bypass (use on simulator): `isJailbroken` methods only, pure ObjC. On physical devices prefer `jailbreak-detection-bypass.js` |
| `simple-test-ios.js` | Phase 4 — Frida connection smoke test (simulator/device) |
| `stalker-coverage-ios.js` | Phase 4 — code coverage analysis using Frida Stalker for tracing execution paths |
| `tls-keylogger-ios.js` | Phase 2 — BoringSSL TLS key extraction (SSLKEYLOGFILE) for Wireshark decryption, no MITM |
| `proxy-detection-bypass-ios.js` | Phase 4 — proxy/VPN detection bypass (CFNetworkCopySystemProxySettings) |
| `webview-inspector-enable-ios.js` | Phase 3 — force-enable WKWebView Web Inspector in production |
| `rasp-bypass-ios.js` | Phase 4 — RASP bypass (IOSSecuritySuite/FreeRASP/JailMonkey/Trusteer/Slayer) |
| `rasp-bypass-ios-full.js` | Phase 4 — multi-layer RASP bypass (combined exit/abort/ptrace/sysctl/uname/file-check neutralization for hardened apps) |
| `rasp-bypass-ios-ultra.js` | Phase 4 — ultra-aggressive RASP bypass for simulator detection (exit/abort/pthread_kill/sysctl/uname/ptrace/getppid) |
| `rasp-terminology-trace-ios.js` | Phase 4 — non-destructive RASP/anti-tamper recon (traces which classes/methods the app checks; run before a bypass) |
| `react-native-rasp-bypass-ios.js` | Phase 4 — RASP bypass in React Native apps (targets the RN bridge / native security modules) |
| `anti-debugging-bypass-ios.js` | Phase 4 — native anti-debugging bypass (ptrace/syscall/sysctl/getppid) |
| `jailbreak-detection-tracer-ios.js` | Phase 4 — non-destructive jailbreak detection recon (run before bypass) |
| `prevent-app-termination-ios.js` | Phase 4 — prevent self-termination during instrumentation |
| `sqlite-query-logger-ios.js` | Phase 2 — real-time SQLite query logging (sqlite3_prepare family) |
| `keychain-editor-ios.js` | Phase 2 — Keychain read interception + value injection (SecItemCopyMatching) |
| `keyboard-security-check-ios.js` | Phase 2 — keyboard security audit (3rd-party keyboards + secureTextEntry) |
| `snapshot-overlay-check.js` | Phase 2 — app-switcher snapshot protection check |
| `pkcs12-extractor-ios.js` | Phase 2 — client cert + passphrase extraction (SecPKCS12Import) |
| `location-spoofing-ios.js` | Phase 3 — GPS location spoofing (CLLocationManager) |
| `managed-app-inspector.js` | Phase 3/Ent — MDM managed app config dump (com.apple.configuration.managed) |
| `mobile-rate-limit-detector-ios.js` | Phase 2 — rate limiting detection on auth endpoints (H1-160109, H1-2245437) |
| `webview-xss-scanner-ios.js` | Phase 3 — WebView XSS detection via unsanitized HTML (H1-575562, 991713+) |
| `deeplink-csrf-validator-ios.js` | Phase 3 — deep link CSRF detection (H1-805073 Periscope) |
| `ssl-validation-checker-ios.js` | Phase 2 — SSL/TLS certificate validation checker (H1-168538 Twitter) |
| `biometric-deeplink-bypass-ios.js` | Phase 4 — biometric deeplink bypass detector (H1-637194 Shopify) |
| `white-screen-diagnose-ios.js` | Phase 4 — blank/white-screen launch diagnosis (view hierarchy, root VC, window state) |

> **Loading Strategy**: Load reference files only when encountering a specific technical challenge they cover. Do NOT load all references at once.

---

## Platform-Specific Notes

> See `references/environment-setup-ios.md` for detailed macOS setup. Most iOS analysis tools require macOS. `rg` (ripgrep) is recommended over `grep -P` — BSD grep does not support PCRE.
