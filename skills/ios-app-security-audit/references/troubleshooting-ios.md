# Troubleshooting Guide: iOS Security Audit

Centralized troubleshooting for common issues in iOS app security auditing. For complete methodology, see `SKILL.md`.

---

## Quick Diagnosis

| Symptom | See Section |
|---------|-------------|
| **Tool not found** | Tool Setup Issues |
| **Encrypted binary** | Binary Extraction |
| **Frida can't attach** | Frida Issues |
| **Simulator crash** | SimForge Issues |
| **MobSF connection failed** | MobSF Issues |
| **Command fails** | Platform-Specific Issues |

---

## Tool Setup Issues

### frida: command not found

**Cause**: Frida not installed or not in PATH

**Solution**:
```bash
# Install frida-tools
pip install frida-tools

# Verify installation
frida --version  # Should match the pinned version in references/tool-versions.md
```

**Reference**: `references/tool-installation-ios.md`

### objection: command not found

**Cause**: Objection not installed

**Solution**:
```bash
pip install objection

# Verify
objection --version
```

### dsdump: command not found

**Cause**: dsdump not installed (Swift class dumper)

**Solution**:
```bash
# Install via Homebrew (macOS)
brew tap dstmath/fr dwarf-dwarf
brew install dstmath/fr/dsdump

# Or build from source
# See references/tool-installation-ios.md
```

### plutil: command not found

**Cause**: Not on macOS (plutil is macOS-only)

**Solution**: Use `libimobiledevice` tools or switch to macOS

**Reference**: `references/libimobiledevice-guide.md`

### rg: command not found

**Cause**: ripgrep not installed

**Solution**:
```bash
# macOS
brew install ripgrep

# Linux
sudo apt install ripgrep  # Debian/Ubuntu
sudo pacman -S ripgrep     # Arch
```

---

## Binary Extraction Issues

### IPA extraction fails

**Symptom**: `unzip` cannot extract IPA

**Cause**: Corrupted IPA or not an IPA file

**Solution**:
```bash
# Verify file type
file app.ipa  # Should show "Zip data"

# Re-download from App Store using ipatool
ipatool download --bundle-id com.example.app --output app.ipa
```

**Reference**: `references/ipa-extraction-guide.md`

### Encrypted binary (cryptid == 1)

**Symptom**: Cannot analyze binary, strings show garbled text

**Diagnosis**:
```bash
otool -l YourApp | rg -A 10 "LC_ENCRYPTION_INFO(_64)?"
# Look for cryptid 1
```

**Solution** (jailbroken device):
```bash
# Use frida-ios-dump
git clone https://github.com/Alibaba-Cloud/frida-ios-dump
cd frida-ios-dump
python3 dump.py com.example.app

# Or use bundled script
frida -U -f com.example.app -l assets/frida-scripts/dump-ios.js
```

**Solution** (SimForge on Apple Silicon):
```bash
# SimForge works with FairPlay-encrypted IPAs
python3 scripts/simforge_preflight.py extracted/Payload/YourApp.app
```

**Reference**: `references/macho-binary-analysis.md`, `references/simforge-compatibility.md`

### Framework not detected

**Symptom**: Cannot identify app framework (React Native, Flutter, etc.)

**Solution**:
```bash
# Comprehensive detection
rg "RCTBridgeModule" .          # React Native
rg "Flutter" .                  # Flutter
rg "cordova" Info.plist        # Cordova
rg "UnityEngine" .             # Unity
rg "xamarin" .                 # Xamarin
```

**Reference**: `references/framework-detection-ios.md`

---

## Static Analysis Issues

### grep patterns produce too many results

**Symptom**: grep returns thousands of matches, mostly in frameworks

**Cause**: Not constraining search to app namespace

**Solution**:
```bash
# ALWAYS search only in app code
rg "pattern" Your.app/ --exclude-dir=Frameworks/

# Or use app namespace prefix
rg "com\.exampleapp\." .  # Your app's bundle ID prefix
```

**Reference**: `SKILL.md` → Critical Rules (rule #2)

### Obfuscated code unreadable

**Symptom**: Class names are `a.b.c`, methods are mangled

**Diagnosis**:
```bash
dsdump YourApp | head -50
# Look for generic class names
```

**Solution**:
```bash
# Demangle Swift symbols
swift-demangle _TtC5App11ViewController

# Switch to runtime analysis (Phase 4)
frida -U com.example.app -l assets/frida-scripts/objc-api-explorer.js
```

**Reference**: `references/obfuscation-detection-ios.md`

### Info.plist cannot be parsed

**Symptom**: `plutil -p Info.plist` fails

**Cause**: Binary or corrupted plist

**Solution**:
```bash
# Convert to XML if binary
plutil -convert xml1 Info.plist

# If corrupted, extract from IPA again
unzip app.ipa -d fresh/
```

---

## Frida Issues

### Frida cannot attach to process

**Symptom**: `frida -U com.example.app` fails with "unable to find process"

**Causes**:
1. App not running
2. Bundle ID incorrect
3. Device not connected

**Solution**:
```bash
# List running apps
frida-ps -U

# Verify bundle ID
ideviceinstaller list | rg com.example

# Check device connection
frida-ps -U  # Should list processes
```

### Frida fails with "process not allowed"

**Symptom**: "Failed to attach: unable to access process"

**Cause**: Anti-debug or jailbreak detection

**Solution**:
```bash
# Bypass jailbreak detection
frida -U -f com.example.app -l assets/frida-scripts/jailbreak-detection-bypass.js

# Or bypass with objection
objection -g com.example.app explore
ios jailbreak disable
```

**Reference**: `references/jailbreak-detection-bypass-ios.md`, `references/debugger-detection-bypass.md`

### frida-ps -U works but frida -U -p fails ("need Gadget to attach on jailed iOS")

**Symptom**: `frida-ps -U` lists processes fine, but `frida -U -p <PID>` or `frida -U -f com.example.app` returns `Failed to spawn: need Gadget to attach on jailed iOS` (or `unable to attach`).

**Root cause**: `-U` flag behaves differently depending on what operation you run:

| Command | Mechanism | Jailbreak required? |
|---------|-----------|---------------------|
| `frida-ps -U` | Reads process list via lockdownd API (developer mode) | **No** — works on iOS 16+ with Developer Mode enabled |
| `frida -U -p <PID>` (attach) | Injects agent into running process | **Yes** — needs frida-server on jailbroken device |
| `frida -U -f <bundle>` (spawn) | Injects agent at process start | **Yes** — needs frida-server or Frida Gadget in the IPA |

**Why the confusion**: `frida-ps -U` succeeding does **NOT** mean the device is jailbroken or that frida-server is running. It only confirms USB connectivity and Developer Mode.

**Solution** (pick one based on context):

```bash
# Option A: Confirm jailbreak is actually present
# On a jailbroken device, /Applications/Cydia.app or /var/jb/ should exist
ssh -p 2222 root@localhost 'ls /var/jb/' 2>/dev/null
# If "Connection refused" or "ssh: connect to host" → no SSH = no jailbreak

# Option B: Use the iOS Simulator (no jailbreak needed)
# See references/simforge-ios-testing.md for full workflow
# Inject Frida Gadget via simforge launch --dylib frida-gadget.dylib

# Option C: Inject Frida Gadget into the app's IPA (no jailbreak needed)
# See references/runtime-integrity-bypass.md §5 "FridaGadget Injection"
# 1. Download IPA with ipatool
# 2. Insert Frida Gadget dylib with insert-dylib
# 3. Re-sign (needs Apple Dev account or ad-hoc)
# 4. Install and launch → Frida attaches via Gadget's local port
```

**Reference**: `references/runtime-integrity-bypass.md` §5 (Gadget injection), `references/simforge-ios-testing.md` (simulator workflow), `SKILL.md` Phase 4 (dynamic analysis decision tree).

### SSL pinning bypass not working

**Symptom**: Network traffic still shows certificate errors after hooking

**Causes**:
1. Wrong SSL library (not NSURLSession)
2. Custom pinning implementation
3. Flutter/React Native bridge

**Solution**:
```bash
# Try different scripts
frida -U com.example.app -l assets/frida-scripts/ssl-pinning-bypass-ios.js

# For Flutter apps
frida -U com.example.app -l assets/frida-scripts/flutter-ssl-pinning-ios.js

# For React Native
frida -U com.example.app -l assets/frida-scripts/react-native-ios-hook.js
```

**Reference**: `references/ssl-pinning-bypass-ios.md`

### Frida version mismatch

**Symptom**: "Failed to load script: protocol mismatch"

**Cause**: frida-tools version doesn't match frida-server on device

**Solution**:
```bash
# Check versions
frida --version        # On host
# Check frida-server version on device

# Reinstall matching versions (pulls frida core — pinned in references/tool-versions.md)
pip uninstall frida-tools frida
pip3 install "frida-tools==14.9.0"

# Reinstall frida-server on device (same version)
# See references/frida-server-ios-install.md
```

---

## SimForge Issues

### SimForge preflight check fails

**Symptom**: `simforge_preflight.py` reports incompatibility

**Common failures**:
1. **Not ARM64**: SimForge only supports arm64 binaries
2. **FairPlay encrypted**: Some FairPlay builds incompatible
3. **Swift ABI mismatch**: iOS 26.x stricter than 17.x

**Solution**:
```bash
# Run detailed preflight
python3 scripts/simforge_preflight.py YourApp.app

# Check compatibility matrix
# See references/simforge-compatibility.md

# Try iOS 17.x SimRuntime (most permissive)
xcrun simctl list runtimes | rg "iOS 17"
```

**Reference**: `references/simforge-compatibility.md`

### Simulator crash on launch

**Symptom**: App crashes immediately in simulator

**Diagnosis**:
```bash
# Find crash report
find ~/Library/Logs/DiagnosticReports -name "*.ips" -mtime -1

# Parse crash report
python3 scripts/simforge_triage.py crash.ips
```

**Common causes**:
1. **Missing dylib**: Framework not patched
2. **Signature issue**: Re-signing incomplete
3. **Swift ABI mismatch**: Runtime too new

**Solution**:
```bash
# Iterative fix
./scripts/simforge_iterate.sh YourApp.app com.example.app

# Or manually fix each failing framework
# See simforge_triage.py output
```

**Reference**: `references/simforge-crash-triage.md`

### SimForge convert breaks signature

**Symptom**: "code signature invalid" after simforge convert

**Cause**: LC_BUILD_VERSION patching invalidates signature

**Solution**:
```bash
# Re-sign is mandatory after convert
codesign --remove-signature YourApp.app
codesign -f -s - YourApp.app/Frameworks/*
codesign -f -s - YourApp.app

# Or use the integrated script
python3 scripts/simforge_apply.py YourApp.app
```

---

## MobSF Issues

### MobSF Docker container fails to start

**Symptom**: `docker run` fails or container exits immediately

**Common causes**:
1. **Port 8000 in use**: Another service using port 8000
2. **Memory insufficient**: Docker needs 4GB+ RAM

**Solution**:
```bash
# Check port usage
lsof -i :8000

# Kill process or use different port
docker run -p 8001:8000 opensecurity/mobile-security-framework-mobsf

# Check Docker memory
docker system df
```

### MobSF API connection fails

**Symptom**: `mobsf_upload.py` fails with "Connection refused"

**Diagnosis**:
```bash
# Check if MobSF is running
curl http://127.0.0.1:8000/api/docs

# Check configuration
python3 scripts/mobsf_config.py status
```

**Solution**:
```bash
# Reconfigure
python3 scripts/mobsf_config.py set-url http://127.0.0.1:8000
python3 scripts/mobsf_config.py set-key generate

# Verify connectivity
python3 scripts/mobsf_detect.py
```

**Reference**: `references/mobsf-integration-guide.md`

### MobSF scan fails with "corrupted IPA"

**Symptom**: MobSF cannot upload or scan IPA

**Cause**: IPA encryption or corruption

**Solution**:
```bash
# Verify IPA locally
unzip -t app.ipa

# If FairPlay encrypted, decrypt first
# Use frida-ios-dump or acquire decrypted IPA

# Or extract and upload directory
unzip app.ipa -d app/
# MobSF can scan extracted .app bundles
```

---

## Platform-Specific Issues

### Linux: missing macOS tools (plutil, codesign, otool)

**Symptom**: Commands not found on Linux

**Cause**: Some tools are macOS-only

**Workarounds**:
```bash
# Use alternative tools
# plutil → libimobiledevice/libplist
# codesign → ldid (Linux)
# otool → objdump or jtool2 (cross-platform)

# For full analysis, use macOS or:
# - SimForge (Apple Silicon)
# - Corellium (cloud iOS VMs)
# - Checkra1n jailbroken device
```

**Reference**: `references/linux-ios-analysis-workarounds.md`

### Windows: Script execution fails

**Symptom**: `.sh` scripts don't run

**Solution**:
```bash
# Use WSL (Windows Subsystem for Linux)
wsl bash ./scripts/preflight-check.sh

# Or use PowerShell versions
.\scripts\preflight-check.ps1
```

---

## General Issues

### Out of memory during analysis

**Symptom**: Analysis script killed or system freezes

**Cause**: Large IPA or many dependencies

**Solution**:
```bash
# Analyze frameworks separately
# Exclude large frameworks from static analysis
rg "pattern" . --exclude-dir=Frameworks/

# Use targeted analysis instead of full scan
# See SKILL.md → Scoped Grep Patterns
```

### Report generation fails

**Symptom**: `generate-report.py` fails with JSON error

**Cause**: Invalid findings JSON format

**Solution**:
```bash
# Validate JSON
cat findings.json | jq .

# Check format matches test-findings.json
cat scripts/test-findings.json

# Use correct structure
[
  {
    "id": "1",
    "title": "Finding title",
    "severity": "High",
    "description": "Description",
    "affected_file": "path/to/file",
    "remediation": "Fix description"
  }
]
```

**Reference**: `references/reporting-templates-ios.md`

---

## Still Stuck?

1. **Check the full methodology**: `SKILL.md`
2. **Verify tool versions**: `python3 scripts/preflight_check.py`
3. **Search issue history**: Check if similar issue documented
4. **Platform-specific guides**:
   - `references/environment-setup-ios.md` (macOS)
   - `references/jailbreak-setup-guide.md` (jailbreak)
   - `references/simforge-ios-testing.md` (SimForge)

---

## Quick Reference Commands

| Need | Command |
|------|---------|
| **Verify tools** | `python3 scripts/preflight_check.py` |
| **List SimRuntimes** | `xcrun simctl list runtimes` |
| **Check device connection** | `frida-ps -U` or `idevice_id -l` |
| **Find crash reports** | `find ~/Library/Logs/DiagnosticReports -name "*.ips" -mtime -1` |
| **Verify IPA** | `file app.ipa` and `unzip -t app.ipa` |
| **Check encryption** | `otool -l YourApp \| rg -A 10 LC_ENCRYPTION` |
| **List Frida processes** | `frida-ps -U` |
| **Test MobSF** | `curl http://127.0.0.1:8000/api/docs` |

---

**For complete iOS pentesting methodology**, see `SKILL.md`.
