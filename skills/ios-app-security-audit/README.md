# iOS App Security Audit Skill

[![Android Skill](https://img.shields.io/badge/Android-Pentesting%20Skill-3DDC84.svg)](https://github.com/DragonJAR/Android-Pentesting-Skill)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/DragonJAR/iOS-Pentesting-Skill/blob/main/SKILL.md)
[![Author](https://img.shields.io/badge/author-DragonJAR%20SAS-orange.svg)](https://www.DragonJAR.org)
[![Español](https://img.shields.io/badge/read%20in-Espa%C3%B1ol-blue.svg)](README.es.md)

> Comprehensive iOS app security audit skill for AI agents. Performs static analysis, dynamic instrumentation, source-to-sink tracing, and generates CVSS 4.0 reports.

## 🎯 What This Skill Does

This skill transforms an AI agent into an **iOS security auditor** capable of:

- **Decompiling and analyzing IPAs** — Mach-O analysis, dsdump, class-dump, IPA extraction
- **Detecting vulnerabilities** — 20 pattern categories / 97 grep blocks, OWASP Mobile Top 10 aligned
- **Testing URL schemes and IPC** — Custom URL scheme injection, universal link abuse, XPC, App Groups
- **Tracing data flows** — Source-to-sink methodology with confidence levels
- **Bypassing protections** — SSL pinning, jailbreak detection, RASP, native checks, encryption
- **Modifying IPAs** — Binary patching, resource editing, re-signing, re-packaging
- **Unity IL2CPP on Simulator** — Complete workflow for running Unity 2021+ IL2CPP apps on iOS Simulator (Metal heap fix, dylib embedding, no device needed)
- **Generating reports** — CVSS 4.0 scoring, MASTG mapping, professional templates

## 📦 Installation

### Option 1: Clone into Agent Skills Directory

```bash
# For Claude Code / OpenCode agents
cd ~/.agents/skills/
git clone https://github.com/DragonJAR/iOS-Pentesting-Skill ios-app-security-audit

# For other agents, place in your skills directory
```

### Option 2: Install Globally

```bash
# Clone to any location
git clone https://github.com/DragonJAR/iOS-Pentesting-Skill.git

# Add to your agent's skill path configuration
```

## ⚙️ Prerequisites

The skill works on **macOS** and **Linux**. macOS is recommended for full functionality; Linux has alternatives for most tools (~90% compatibility).

| Tool | Version | Purpose |
|------|---------|---------|
| Frida | see [tool-versions.md](references/tool-versions.md) | Dynamic instrumentation — `frida-server` on device must match the host `frida` core version exactly |
| Objection | 1.12.4+ | Mobile exploration (maintenance mode) |
| dsdump | 0.13+ | Swift class dump |
| class-dump | - | Objective-C class dump (optional) |
| plutil | system (macOS) / plistutil (Linux) | plist manipulation |
| codesign | system (macOS) / ldid (Linux) | Code signing |
| security | system (macOS) | Keychain access |
| lipo | system (macOS) / llvm-lipo (Linux) | Fat binary manipulation |
| otool | system (macOS) / llvm-objdump (Linux) | Mach-O analysis |
| Python | 3.10+ | Script execution |

**Platform Support Matrix:** See [tool-installation-ios.md](references/tool-installation-ios.md) for complete macOS/Linux alternatives.

### Verification

Run the preflight check to verify all dependencies:

```bash
./scripts/preflight-check.sh
```

Or use the Python version for cross-platform compatibility:

```bash
python3 scripts/preflight_check.py
```

PowerShell variant for Windows environments:

```powershell
./scripts/preflight-check.ps1
```

---

## 🚀 Quick Setup (5 minutes)

Get your environment ready for iOS auditing with these steps:

### Step 1: Verify Current Tools

```bash
./scripts/preflight-check.sh
```

### Step 2: Install Missing Tools

**macOS:**
```bash
# Install Python and core tools
brew install python@3.11 git wget jq tree ripgrep ipatool libimobiledevice ideviceinstaller

# Install Frida, Objection, dsdump
pip3 install frida-tools objection dsdump swift-demangle
```

**Linux (Debian/Ubuntu):**
```bash
# System packages
sudo apt update
sudo apt install python3 python3-pip python3-dev clang git wget jq tree ripgrep build-essential libimobiledevice-utils ideviceinstaller

# Python packages
pip3 install frida-tools objection dsdump swift-demangle
```

**Or use the automated setup script:**
```bash
./scripts/setup-environment.sh
```

### Step 3: Verify Again

```bash
./scripts/preflight-check.sh
```

### Step 4: Install Frida on Device (Optional)

For dynamic analysis on a jailbroken device, see [references/frida-server-ios-install.md](references/frida-server-ios-install.md)

**Now you're ready to audit IPAs!** See [Usage Examples](#-usage-examples) below.

## 🚀 Usage Examples

### Example 1: Basic IPA Audit

**User prompt:**
```
Audit this IPA: /path/to/app.ipa
```

**Agent response:**
```
I'll analyze the IPA for security vulnerabilities.

[Phase 0] Extracting IPA and detecting framework...
[Phase 1] Analyzing Info.plist and entitlements...
[Phase 2] Running targeted security patterns...
[Phase 3] Tracing data flows...
[Phase 5] Generating findings report...

Found 3 issues:
1. [HIGH] Insecure URL Scheme Handling (M8: Security Misconfiguration)
2. [MEDIUM] Hardcoded API Key in Info.plist (M1: Improper Credential Usage)
3. [LOW] Debug Logging Enabled (M8: Security Misconfiguration)
```

### Example 2: SSL Pinning Bypass

**User prompt:**
```
The app has SSL pinning. Bypass it with Frida and intercept traffic.
```

**Agent response:**
```
I'll use the SSL pinning bypass script to intercept HTTPS traffic.

[1] Identifying SSL pinning implementation...
    Found: NSURLSession with custom certificate validation
[2] Loading Frida script: ssl-pinning-bypass-ios.js
[3] Hooking NSURLSessionDelegate methods
[4] SSL pinning bypassed. Traffic now decrypted.

Intercepted request:
POST /api/login
{"email": "user@example.com", "password": "secret123"}
```

### Example 3: React Native Analysis

**User prompt:**
```
Analyze this React Native iOS app for hardcoded secrets in the JavaScript bundle.
```

**Agent response:**
```
[Phase 0] Detected React Native framework (libReactNative.a found)
[Phase 0] Extracting JavaScript bundle from Payload/YourApp.app/index.ios.bundle
[Phase 2] Scanning for secrets in JavaScript bundle...

Found 2 hardcoded secrets:
- API_KEY = "sk_live_abc123..." at index.ios.bundle:4521 (M1: Improper Credential Usage)
- AWS_SECRET = "wJalrXUtnFEMI/K7MDENG..." at index.ios.bundle:8912 (M1: Improper Credential Usage)
```

### Example 4: IPA Modification

**User prompt:**
```
Disable jailbreak detection in this IPA and repackage it.
```

**Agent response:**
```
[1] Extracting IPA...
[2] Locating jailbreak detection code...
    Found: JailbreakDetector.checkJailbreak() in YourApp
[3] Patching binary to return false...
    NOP-ing comparison instruction
[4] Re-signing with code signing...
[5] Re-packaging IPA...
[6] Verifying signature...

Modified IPA ready: app_patched.ipa
SHA-256: abc123def456...
```

### Example 5: Flutter Analysis

**User prompt:**
```
Analyze this Flutter iOS app. I need to intercept HTTPS traffic.
```

**Agent response:**
```
[Phase 0] Detected Flutter framework (Flutter.framework found)
[Phase 0] Flutter uses BoringSSL natively - ObjC/Swift SSL hooks won't work
[Phase 0] Using Blutter to extract Dart code: python3 blutter.py Frameworks/App.framework/App
[Phase 4] Loading Frida script: flutter-ios-hook.js (BoringSSL targets)
[Phase 4] Hooking SSL_CTX_set_custom_verify() for certificate bypass
[Phase 4] Hooking SSL_read/SSL_write() for traffic interception

Flutter traffic now intercepted and decrypted.
```

### Example 6: Unity IL2CPP Simulator Testing

**User prompt:**
```
I have a Unity IL2CPP game IPA. I need to run it on the iOS Simulator for testing — no physical device available.
```

**Agent response:**
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

## 📖 Skill Capabilities

### Static Analysis (Phases 0-3)

| Capability | Description |
|------------|-------------|
| IPA Extraction | Unzip IPA, access Payload/YourApp.app/ |
| Mach-O Analysis | otool, lipo, nm for binary structure |
| Framework Detection | React Native, Flutter, Cordova, Xamarin, Native |
| Obfuscation Analysis | Swift obfuscation, LLVM, custom patterns |
| Info.plist Analysis | Security checks for URL schemes, entitlements, permissions (47-key checklist) |
| URL Scheme / IPC Abuse | Custom schemes, universal links, XPC, App Groups, pasteboard |
| Secrets Detection | API keys, passwords, tokens in code and plists |
| Data Flow Tracing | Source-to-sink methodology with confidence levels |
| Supply Chain (SBOM) | CycloneDX/SPDX generation, dependency CVE + license scan, third-party SDK review |
| Enterprise / MDM | Configuration profiles, managed app config, enterprise cert trust testing |

### Dynamic Analysis (Phase 4)

| Capability | Description |
|------------|-------------|
| Frida Scripts | 73 scripts for hooking, bypass, interception, and native triage |
| SSL Pinning Bypass | NSURLSession, AFNetworking, Alamofire, TrustKit, BoringSSL (SSL Kill Switch), React Native, Flutter |
| Jailbreak Detection Bypass | 22 jailbreak indicators, native hooks (fopen, access, stat), native jailbreak probe |
| RASP Bypass | Debugger detection, anti-frida, simulator detection |
| Crypto Interception | Monitor SecKey, SecKeyDecrypt, CommonCrypto operations |
| Biometric Bypass | LAContext, biometric prompt, fallback to PIN |
| Keychain Inspection | List entries, extract metadata, check accessibility |
| Network Interception | URLSession, AFNetworking, Alamofire, WebSocket monitoring |
| Native Hooking | Objective-C runtime, Swift bridging, by-offset hooks |

### IPA Modification

| Capability | Description |
|------------|-------------|
| Binary Patching | otool, jtool2, hex editor for direct binary modification |
| Resource Editing | Modify Info.plist, embedded plists, strings |
| ATS Bypass | Override NSAppTransportSecurity, enable cleartext traffic |
| Re-signing | codesign with provisioning profile, entitlements |
| Re-packaging | Rebuild IPA, maintain structure |

### Reporting (Phase 5)

| Capability | Description |
|------------|-------------|
| CVSS 4.0 Scoring | FIRST.org compliant severity ratings |
| OWASP MASTG Mapping | Test IDs and MASVS categories |
| Professional Templates | Executive summary, findings, remediation |

## 🔧 Skill Structure

```
iOS-Pentesting-Skill/
├── SKILL.md                              # Skill definition (Phases 0-5)
├── requirements.txt                      # Python dependencies of scripts/
├── ruff.toml                             # Declared lint rule set
├── references/                           # 94 reference documents
│   ├── Start here
│   │   ├── ios-pentesting-decision-tree.md              # Which check to run for which finding
│   │   ├── troubleshooting-ios.md                       # Common failures and fixes
│   │   └── getting-started-ios.md                     # 15-minute orientation guide
│   ├── Phase 0 (extraction & framework)
│   │   ├── environment-setup-ios.md      # macOS toolchain install
│   │   ├── tool-installation-ios.md      # Per-tool install + troubleshooting
│   │   ├── static-analysis-patterns-ios.md  # Grep patterns by category
│   │   ├── macho-binary-analysis.md      # Mach-O structure & flags
│   │   ├── framework-detection-ios.md    # RN/Flutter/Cordova/Xamarin/Unity
│   │   ├── ipa-extraction-guide.md       # IPA structure & decryption
│   │   ├── advanced-tools-ios.md         # Corellium, Hopper, Ghidra, lldb
│   │   ├── bitcode-analysis.md           # Bitcode-enabled binaries
│   │   ├── mobsf-integration-guide.md    # Optional MobSF setup
│   │   ├── libimobiledevice-guide.md                    # libimobiledevice toolchain
│   │   ├── linux-ios-analysis-workarounds.md            # Linux without macOS
│   │   └── tool-versions.md                             # Tool version requirements (source of truth)
│   ├── Phase 1 (attack surface)
│   │   ├── info-plist-checklist.md       # Info.plist key checklist (47 keys)
│   │   ├── entitlements-security-guide.md
│   │   ├── ios-version-security-changes.md  # iOS 15 → 18
│   │   ├── app-extensions-security.md    # WidgetKit / Share / Keyboard
│   │   ├── url-scheme-security-guide.md   # Scheme hijacking, OAuth callback, parameter injection
│   │   ├── universal-links-guide.md       # apple-app-site-association
│   │   ├── ats-configuration-guide.md    # NSAppTransportSecurity
│   │   ├── privacy-manifest-ios.md       # PrivacyInfo.xcprivacy (iOS 17+)
│   │   ├── app-groups-security.md        # Shared container abuse
│   │   ├── cloudkit-security-ios.md                     # CloudKit / iCloud sync
│   │   ├── insecure-deserialization-ios.md              # NSKeyedUnarchiver / deserialization
│   │   ├── passkeys-security-ios.md                     # Passkeys / WebAuthn (iOS 16+)
│   │   └── swift-concurrency-security.md                # async/await, actors, data races
│   ├── Phase 2 (storage & crypto)
│   │   ├── commoncrypto-analysis.md
│   │   ├── keychain-security-guide.md
│   │   ├── userdefaults-security.md
│   │   ├── coredata-security.md
│   │   ├── pasteboard-security.md
│   │   ├── data-protection-api-guide.md
│   │   ├── objc-security-patterns.md     # swizzling, KVO, nil dispatch
│   │   ├── swift-security-patterns.md    # type safety, generics
│   │   ├── memory-analysis-ios.md                       # In-memory secret scanning
│   │   └── side-channel-analysis-ios.md                 # Timing / cache side channels
│   ├── Phase 3 (data flow)
│   │   ├── deep-link-exploitation-ios.md
│   │   ├── xpc-services-security.md
│   │   ├── ipc-xpc-guide.md
│   │   ├── webview-security-ios.md
│   │   ├── notification-security.md
│   │   ├── phishing-attacks-ios.md                      # Phishing via deep links / OAuth
│   │   └── deep-link-security-checklist.md                        # Deep link security checklist, testing and remediation
│   ├── Phase 4 (dynamic / Frida)
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
│   │   ├── frida-scripts-index.md        # Canonical bundled script catalog
│   │   ├── frida-dynamic-analysis-ios.md                # Frida dynamic analysis on device
│   │   ├── frida-ios-simulator-workflow.md              # Frida on iOS Simulator
│   │   ├── jailbreak-detection-bypass-ios.md            # Jailbreak detection bypass
│   │   ├── rasp-guide-ios.md                            # RASP detection and bypass
│   │   ├── rasp-patterns-ios.md                         # RASP patterns and mitigations
│   │   ├── rasp-framework-stub-guide.md                 # Stubbing RASP frameworks
│   │   ├── simforge-emulation-flow.md                   # Canonical 10-step SimForge flow
│   │   ├── simforge-ios-testing.md                      # SimForge simulator testing
│   │   ├── simforge-crash-triage.md                     # Parsing .ips crash reports
│   │   ├── simforge-compatibility.md                    # SimForge compatibility matrix
│   │   ├── simforge-scripts-index.md                    # SimForge script usage index
│   │   ├── simforge-legacy-loadcmd-cleanup.md           # Legacy LC command cleanup
│   │   └── simulator-mitm-setup.md                      # MITM setup on the simulator
│   ├── Phase 5 (reporting)
│   │   ├── cvss-scoring-ios.md           # CVSS 4.0 methodology
│   │   ├── cvss-examples-ios.md          # 10 worked examples
│   │   ├── reporting-templates-ios.md
│   │   ├── owasp-mastg-ios-checklist.md
│   │   ├── ios-privacy-testing.md
│   │   └── runtime-hardening-checks-ios.md  # 12 frequently-missed checks
│   ├── Mod (repackaging)
│   │   ├── repackaging-ios-guide.md
│   │   └── obfuscation-detection-ios.md
│   ├── Framework deep-dives
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
├── assets/frida-scripts/                 # 73 Frida scripts
│   ├── ssl-pinning-bypass-ios.js         # SSL pinning bypass (STABLE)
│   ├── jailbreak-detection-bypass.js     # Jailbreak detection bypass (STABLE)
│   ├── biometric-bypass-ios.js           # LAContext bypass (STABLE)
│   ├── objc-method-tracer.js             # Generic ObjC/Swift tracer (STABLE)
│   ├── network-interceptor-ios.js        # NSURLSession capture (STABLE)
│   ├── crypto-hook-ios.js                # CommonCrypto hooks
│   ├── keychain-dumper.js                # Keychain extraction
│   ├── url-scheme-monitor.js             # openURL / Universal Links
│   ├── pasteboard-monitor.js             # UIPasteboard read/write
│   ├── file-protection-enumerator.js     # NSFileProtection audit
│   ├── data-protection-check.js          # File-level protection
│   ├── sdk-tracer.js                     # Third-party SDK behavior
│   ├── mdm-bypass.js                     # MDM restriction bypass
│   ├── enterprise-cert-bypass.js         # Enterprise cert trust bypass
│   ├── react-native-ios-hook.js          # RCTBridge module hooks
│   ├── flutter-ios-hook.js               # FlutterMethodChannel hooks
│   ├── flutter-ssl-pinning-ios.js        # Flutter pinning bypass
│   ├── tls-keylogger-ios.js              # BoringSSL TLS key extraction (no MITM)
│   ├── rasp-bypass-ios.js                # RASP bypass (IOSSecuritySuite/FreeRASP/JailMonkey)
│   ├── anti-debugging-bypass-ios.js      # ptrace/sysctl/getppid anti-debug bypass
│   └── ... (53 more)
├── assets/dylibs/                        # Compiled interposer dylibs
│   ├── metalheapfix.m                    # Unity IL2CPP Metal heap crash fix (source)
│   └── README.md                         # Build & usage instructions
├── scripts/                              # Utility, validation & reporting
│   ├── preflight-check.sh                # Bash dependency verification
│   ├── preflight_check.py                # Cross-platform dependency verification
│   ├── preflight-check.ps1               # PowerShell dependency verification
│   ├── auto-audit-static-ios.sh          # Static audit driver (Phases 0-3)
│   ├── generate-report.py                # HTML / Markdown report generator
│   ├── test-findings.json                # Sample report input
│   ├── sbom_generator.py                 # CycloneDX / SPDX SBOM from IPA
│   ├── dependency_scanner.py             # OSV.dev CVE + license scan
│   ├── _scripts_path.py                  # Internal sys.path helper (do not run)
│   ├── check_docs_consistency.py                  # Docs / code / tooling consistency gate
│   ├── selftest.py                       # Functional self-test (no device, no network)
│   ├── frida_harness.js                  # Load every Frida script under a mocked API
│   ├── simforge_binaries.py                        # Internal Mach-O binary inventory (do not run)
│   ├── setup_mobsf.py                    # Optional MobSF installer
│   ├── mobsf_config.py                   # MobSF URL + API key config
│   ├── mobsf_detect.py                   # Auto-detect running MobSF
│   ├── mobsf_upload.py                   # Upload IPA + wait for scan
│   ├── mobsf_export.py                   # Export findings (json / html)
│   ├── mobsf_client.py                   # MobSF REST API client
│   ├── mobsf_findings_correlator.py      # Merge manual + MobSF findings
│   ├── install-mobsf-docker.sh
│   ├── install-mobsf-local.sh
│   ├── run-mobsf-local.sh
│   ├── simforge_preflight.py             # SimForge: simulator compatibility preflight
│   ├── simforge_apply.py                 # SimForge: patch IPA for the iOS Simulator
│   ├── simforge_install_launch.sh        # SimForge: install + launch on booted simulator
│   ├── simforge_triage.py                # SimForge: triage simulator launch crashes
│   ├── simforge_iterate.sh               # SimForge: iterate patch → install → launch
│   ├── simforge_cleanup.py               # SimForge: strip incompatible load commands
│   ├── binpatch_util.py                  # Shared length-preserving Mach-O string patcher
│   ├── patch_is_simulator.py             # Disable 'isSimulator' detection string
│   ├── patch_jailbreak_strings.py        # Neutralize jailbreak-detection strings
│   ├── patch_nudetect.py                 # Disable NuDetect SDK references
│   ├── patch_termination_calls.py        # Neutralize termination error strings
│   ├── quick-static-analysis.sh          # Fast static triage driver
│   ├── screenshot-extractor.sh           # Capture app screenshots (device / simulator)
│   ├── unity_sim_metalfix.sh             # Unity IL2CPP Metal heap fix (compile + inject)
│   └── setup-environment.sh              # Automated environment setup
```

> **For the canonical Frida script catalog** (each script's hook targets,
> maturity level, and example invocation), see
> `references/frida-scripts-index.md` — the SKILL.md References Index
> has a condensed table that maps every script to its workflow phase.

## 🎓 Trigger Phrases

The skill activates when the user says:

- "audit this IPA"
- "analyze iOS app"
- "iOS pentest"
- "app security"
- "decompile IPA"
- "iOS vulnerability assessment"
- "reverse engineer iOS"
- "modify IPA"
- "bypass SSL pinning"
- "bypass jailbreak detection"
- "URL scheme abuse"

## ⚠️ Limitations

1. **Platform requirements** — macOS recommended for full functionality; Linux has ~90% compatibility with alternatives (see [tool-installation-ios.md](references/tool-installation-ios.md))
2. **Dynamic analysis requires a jailbroken device** — Frida needs full access (unless using simulator on macOS or Corellium). Unity IL2CPP apps can run on simulator with the [Metal heap fix](SKILL.md) workaround.
3. **Encrypted binaries** — App Store binaries are encrypted; need to decrypt with Clutch or frida-ios-dump
4. **Frida version matching** — frida-server on device must match frida-tools on host exactly
5. **Flutter uses BoringSSL natively** — ObjC/Swift SSL hooks don't work, need native hooks
6. **Unity IL2CPP on older simulators** — The Metal heap swizzle is tested on iOS 18.6; older runtimes (17.x) may have different MTLSimDriver behavior

## 📚 Standards Alignment

This skill is aligned with:

- **OWASP MASTG** — Mobile Application Security Testing Guide (iOS section)
- **OWASP MASVS** — Mobile Application Security Verification Standard
- **OWASP Mobile Top 10 2024** — Top 10 mobile risks
- **CVSS 4.0** — Common Vulnerability Scoring System

## 🔐 OWASP Mobile Top 10 (2024)

| ID | Category |
|----|----------|
| M1 | Improper Credential Usage |
| M2 | Inadequate Supply Chain Security |
| M3 | Insecure Authentication/Authorization |
| M4 | Insufficient Input/Output Validation |
| M5 | Insecure Communication |
| M6 | Inadequate Privacy Controls |
| M7 | Insufficient Binary Protections |
| M8 | Security Misconfiguration |
| M9 | Insecure Data Storage |
| M10 | Insufficient Cryptography |

## 📚 Where to Start?

Depending on your situation, choose the right guide:

| Your Situation | Read This |
|----------------|-----------|
| **New to iOS pentesting** | [getting-started-ios.md](references/getting-started-ios.md) - 15-minute guide |
| **Setting up a new Mac** | [environment-setup-ios.md](references/environment-setup-ios.md) - Complete 14-section setup |
| **Missing a specific tool** | [tool-installation-ios.md](references/tool-installation-ios.md) - Per-tool guide |
| **Need tool version reference** | [tool-versions.md](references/tool-versions.md) - Single source of truth |
| **Ready to audit IPAs** | [SKILL.md](SKILL.md) - Full 6-phase methodology |
| **Want to master Frida** | [frida-ios-guide.md](references/frida-ios-guide.md) + [frida-scripts-index.md](references/frida-scripts-index.md) |
| **Testing in Simulator** | [simforge-ios-testing.md](references/simforge-ios-testing.md) - No jailbreak needed |

---

## 🤝 Contributing

Contributions are welcome! Please see the [references/](references/) directory for areas that need expansion.

## 📄 License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**DragonJAR SAS** — [https://www.DragonJAR.org](https://www.DragonJAR.org)

[Experts in IT security services, proactive validation, and offensive security.](https://www.dragonjar.org/servicios-de-seguridad-informatica)

---

**⚠️ Disclaimer:** This skill is intended for **authorized security testing only**. Users must obtain proper authorization before conducting any security assessment. The authors are not responsible for misuse of this tool.
