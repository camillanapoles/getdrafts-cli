# Getting Started: iOS App Security Audit

## Quick Start

This guide gets you from zero to your first iOS security audit in 15 minutes. For complete methodology, see `SKILL.md`.

## Prerequisites

1. **macOS** (recommended) or Linux
2. **Python 3.10+**
3. **An IPA file** to audit

### Verify Tools (1 minute)

```bash
# Run preflight check
python3 scripts/preflight_check.py

# Or use bash version
./scripts/preflight-check.sh
```

Missing tools? See `references/tool-installation-ios.md` for setup.

---

## Testing Capabilities by Environment

Your testing capabilities depend on whether you have access to a jailbroken device, simulator, or only a non-jailbroken physical device.

| Capability | Jailbroken Device | iOS Simulator (SimForge) | Non-Jailbreak Device |
|---|---|---|---|
| **SSL pinning bypass** | Frida, SSL Kill Switch 2, Objection | Frida, Objection (with Gadget) | MITM proxy (limited), Frida (sideloaded) |
| **Keychain dump** | keychain-dumper, Frida ios keychain dump | Frida ios keychain dump | Backup extraction only (limited) |
| **Filesystem access** | Full sandbox access via SSH | Full simulator filesystem | Backup extraction only |
| **Runtime manipulation** | Frida, Objection, LLDB attach | Frida (with Gadget injection) | Frida (requires re-signed app + Gadget) |
| **Binary analysis** | On-device class-dump, Hopper | Offline after decryption | Offline after decryption |
| **Method hooking** | Full Frida/Cycript capability | Full Frida capability (with Gadget) | Limited (requires sideload) |
| **Network interception** | Full (Frida + proxy) | Full (Frida + proxy) | Limited (proxy only, may require Frida) |
| **Screenshot/Screen recording** | Full | Full | Full (system feature) |

### Non-Jailbreak Options

**iOS Simulator with SimForge** (recommended for fast iteration):
- Run arm64 iOS apps in simulator without jailbroken device
- Inject Frida Gadget for runtime hooking
- Full filesystem access in simulator sandbox
- See `references/simforge-ios-testing.md`

**Sideloaded with Frida Gadget**:
- Extract IPA, insert FridaGadget.dylib
- Re-sign with provisioning profile
- Install via ios-deploy or Xcode
- Runtime hooking via Frida
- See `references/frida-ios-guide.md` (Gadget mode)

**Backup Extraction**:
- Extract encrypted backup via libimobiledevice
- Parse keychain, preferences, shared files
- Limited access (some data encrypted)
- See `references/libimobiledevice-guide.md`

---

## 5-Minute Audit Workflow

### Step 1: Extract IPA (30 seconds)

```bash
# Extract the IPA (it's a zip file)
unzip app.ipa -d extracted/
cd extracted/Payload/YourApp.app/
```

### Step 2: Framework Detection (1 minute)

```bash
# Detect app framework
rg "RCTBridgeModule" .          # React Native?
rg "Flutter" .                  # Flutter?
rg "cordova" Info.plist        # Cordova/Ionic?
rg "UnityEngine" .             # Unity?
```

Framework detected? See `SKILL.md` Phase 0 → Framework-specific guides.

### Step 3: Attack Surface Check (2 minutes)

```bash
# Check Info.plist for sensitive configurations
plutil -p Info.plist | rg -i "URLScheme|ATS|Background|Privacy"

# Extract entitlements
codesign -d --entitlements - YourApp

# Check for hardcoded secrets
strings YourApp | rg -i "(password|key|secret|token|api)"
```

### Step 4: Static Analysis (1 minute)

```bash
# Use grep patterns for common vulnerabilities
rg -i "NSUserDefaults.*set" .           # Cleartext storage?
rg -i "SecItemAdd.*kSecAttrAccessible" . # Keychain weak access?
rg -i "loadHTMLString|evaluateJavaScript" . # XSS risk?
```

See `references/static-analysis-patterns-ios.md` for 97 grep pattern blocks across 20 categories.

### Step 5: Report (30 seconds)

```bash
# Generate findings JSON (your manual analysis)
cat > findings.json <<EOF
[
  {
    "id": "1",
    "title": "Hardcoded API Key",
    "severity": "High",
    "description": "API key found in binary",
    "affected_file": "YourApp",
    "remediation": "Use secure storage (Keychain)"
  }
]
EOF

# Generate HTML report
python3 scripts/generate-report.py \
  --input findings.json \
  --output report.html \
  --app-name "My App" \
  --bundle-id "com.example.app"
```

---

## Optional: Dynamic Analysis

Need to verify findings runtime? Two options:

### Option A: Simulator (Apple Silicon, no jailbreak)

```bash
# 1. Convert app for simulator
python3 scripts/simforge_preflight.py extracted/Payload/YourApp.app
python3 scripts/simforge_apply.py extracted/Payload/YourApp.app

# 2. Boot simulator and install
./scripts/simforge_install_launch.sh extracted/Payload/YourApp.app com.example.app

# 3. Monitor logs
log stream --predicate 'process == "YourApp"'
```

See `references/simforge-ios-testing.md` for complete flow.

### Option B: Physical Device (jailbreak required)

```bash
# 1. Install Frida server on device
# See references/frida-server-ios-install.md

# 2. Spawn app with hook
frida -U -f com.example.app -l assets/frida-scripts/ssl-pinning-bypass-ios.js

# 3. Monitor URL schemes
frida -U com.example.app -l assets/frida-scripts/url-scheme-monitor.js
```

See `references/frida-ios-guide.md` for complete Frida setup.

---

## Optional: MobSF Automation

Want automated static analysis?

```bash
# 1. Install MobSF (Docker)
./scripts/install-mobsf-docker.sh

# 2. Upload IPA
python3 scripts/mobsf_upload.py app.ipa

# 3. Export results
python3 scripts/mobsf_export.py --scan-id "<SCAN_ID>" --format json

# 4. Correlate with manual findings
python3 scripts/mobsf_findings_correlator.py \
  --mobsf mobsf_results.json \
  --manual findings.json \
  --output correlated.json
```

See `references/mobsf-integration-guide.md` for complete setup.

---

## Common First-Time Issues

| Issue | Solution |
|-------|----------|
| **Encrypted binary** | `cryptid == 1`? Use `assets/frida-scripts/dump-ios.js` to decrypt |
| **Obfuscated code** | Switch to dynamic analysis (Phase 4) |
| **Frida can't attach** | Check jailbreak detection bypass scripts |
| **Simulator crash** | Run `python3 scripts/simforge_triage.py crash.ips` |

For complete troubleshooting, see `references/troubleshooting-ios.md`.

---

## Next Steps

1. **Read the full methodology**: `SKILL.md` (6-phase deterministic workflow)
2. **Deep dive into your framework**: See `SKILL.md` → Framework-specific guides
3. **Master Frida**: See `references/frida-ios-guide.md` and `references/frida-scripts-index.md`
4. **Learn SimForge**: See `references/simforge-ios-testing.md` for no-jailbreak dynamic analysis
5. **Understand CVSS scoring**: See `references/cvss-scoring-ios.md` for severity assessment

---

## Reference Quick Links

| Topic | Reference |
|-------|-----------|
| **Tool installation** | `references/tool-installation-ios.md` |
| **Environment setup** | `references/environment-setup-ios.md` |
| **Static analysis patterns** | `references/static-analysis-patterns-ios.md` |
| **Frida scripts** | `references/frida-scripts-index.md` |
| **Simulator testing** | `references/simforge-ios-testing.md` |
| **Troubleshooting** | `references/troubleshooting-ios.md` |
| **Reporting templates** | `references/reporting-templates-ios.md` |

---

**Time to first audit**: 15 minutes (static) or 30 minutes (with dynamic verification)

**For complete iOS pentesting methodology**, see `SKILL.md`.
