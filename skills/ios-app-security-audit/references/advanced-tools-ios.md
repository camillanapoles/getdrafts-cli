# Advanced Tools for iOS Security Testing

This document provides comprehensive reference material for advanced iOS penetration testing tools beyond the standard toolkit. These tools enable deep binary analysis, cloud-based testing, and cross-platform framework assessment.

---

## 1. Corellium — Cloud-Based Virtual iOS Devices

### Overview

Corellium provides cloud-hosted virtual iOS devices that run genuine ARM64 iOS kernels (not emulators). Unlike Xcode simulators that run x86_64 code, Corellium devices execute actual ARM64 binaries, making them essential for testing compiled native code, kernel exploits, and hardware-dependent vulnerabilities.

### Key Features

- **Genuine ARM64 iOS kernels** — Native execution on virtualized Apple Silicon
- **Instant provisioning** — Launch devices in seconds, no hardware procurement
- **Snapshot/restore** — Save device states for repeatable testing
- **Jailbreak support** — Pre-jailbroken images available for full filesystem access
- **USB forwarding** — Physical USB connectivity for device testing
- **API access** — Programmatic device control for automation

### Pricing and Access

Corellium operates on a subscription model with plans starting at approximately $99/month for limited hours. Enterprise plans offer unlimited usage and team features. Academic discounts are available. Access requires approved registration at corellium.com.

### Setup and Authentication

```bash
# Install Corellium CLI tool
npm install -g @corellium/cli

# Authenticate with API token (generate from dashboard)
corellium login --endpoint https://api.corellium.com

# Verify authentication
corellium devices list
```

### Integration with Frida

Corellium devices support full Frida instrumentation:

```bash
# Connect Frida to Corellium device
frida -H "<device-ip>":27042 -p "<process-pid>"

# Or attach to running app
frida -H "<device-ip>":27042 "AppName"

# Spawn and attach for new process
frida -H "<device-ip>":27042 -f com.example.app -o output.log
```

### Integration with Objection

```bash
# Connect objection to Corellium device via USB
objection --host "<device-ip>" --port 27042 attach --pid "<pid>"

# Or spawn a new process
objection --host "<device-ip>" --port 27042 explore -f com.example.app

# Run introspection commands
objection -h "<device-ip>" -p 27042 ios sslpinning disable
```

### Practical Use Cases

| Use Case | Workflow |
|----------|----------|
| Remote testing without physical devices | Provision device, connect via Frida |
| Kernel exploit development | Use snapshot/restore for state management |
| Team collaboration | Share device snapshots across team |
| CI/CD integration | API-driven automated testing pipelines |

---

## 2. Blutter — Flutter iOS Analysis

### Overview

Blutter is a specialized tool for analyzing Flutter applications on iOS. Flutter apps embed a compiled Dart VM and Dart snapshots, which standard iOS analysis tools cannot inspect. Blutter extracts and analyzes these components.

### What Blutter Extracts

- **Dart AOT snapshots** — Compiled Dart code in ARM64
- **Dart IR snapshots** — Intermediate representation
- **App resources** — Assets, fonts, configuration
- **Flutter engine libraries** — Native Flutter framework components
- **Isolate configuration** — Multi-isolate app architecture

### Installation

```bash
# From source (requires Go 1.21+)
git clone https://github.com/ ليلة/Blutter.git
cd Blutter
go build -o blutter ./cmd/blutter

# Verify installation
./blutter --version

# For macOS, ensure LLVM is installed
brew install llvm
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
```

### Dart Snapshot Extraction

```bash
# Basic snapshot extraction from IPA
./blutter extract --input app.ipa --output ./extracted/

# Extract with verbose output
./blutter extract --input app.ipa --output ./extracted/ --verbose

# List contents without extracting
./blutter list --input app.ipa

# Extract specific resource
./blutter extract --input app.ipa --output ./extracted/ --resource assets/data.json
```

### Analysis Workflow

```bash
# Extract and analyze Dart snapshots
./blutter analyze --input app.ipa --output ./analysis/

# Generate function call graph
./blutter analyze --input app.ipa --call-graph

# Search for specific patterns in Dart code
./blutter search --input extracted/ --pattern "api_key|secret|password"

# Export symbols for further analysis
./blutter symbols --input app.ipa --format json --output symbols.json
```

### Interpreting Results

Blutter outputs include:
- **Symbol tables** — Mapped Dart function names
- **String references** — Hardcoded secrets, API endpoints
- **Type information** — Dart class hierarchy reconstruction
- **Call relationships** — Cross-function references

### Limitations

- Cannot decompile Dart AOT to source — only analysis of compiled output
- Flutter 3.13+ uses different snapshot format (WIP support)
- Large apps produce massive output — filter carefully

---

## 3. Binary Ninja — iOS Processor Support

### Overview

Binary Ninja is a polished reverse engineering platform with first-class iOS support. Its ARM64 v8A processor module handles iOS binaries natively, and the plugin ecosystem extends functionality for Mach-O analysis, Frida integration, and automated vulnerability detection.

### Mach-O Analysis Features

- **Native ARM64 disassembly** — Full iOS binary decompilation
- **Mach-O parsing** — Automatic load command interpretation
- **Objective-C/Swift recovery** — Symbol demangling and class recovery
- **PLT/GOT analysis** — Dynamic symbol resolution
- **Control flow reconstruction** — CFG generation for complex functions

### Installation

```bash
# Download Binary Ninja from https://binary.ninja
# Install the application
sudo cp -r Binary\ Ninja /Applications/

# Install Homebrew package
brew install --cask binaryninja

# Launch and activate with license
open -a "Binary Ninja"
```

### Essential iOS Plugins

```bash
# Install plugin manager first
git clone https://github.com/PS4Binja/PS4Binja.git
# Copy to ~/Library/Application\ Support/Binary\ Ninja/

# Mach-O Analyzer plugin
git clone https://github.com/maddiestone/objcDecrypt.git
# Install via Binary Ninja Plugin Manager (View -> Plugin Manager)

# Frida integration
git clone https://github.com/alphaLiam/Binja-Frida.git

# iOS Tweak Analysis plugin
git clone https://github.com/tekflash/Binja-iOS-Analysis.git
```

### Core Analysis Workflow

```python
# Binary Ninja Python API for iOS analysis
from binaryninja import *

# Open Mach-O binary
bv = BinaryViewType.get_view_of_file("target.app/Framework")

# Show ARM64 function
func = bv.get_function_at(0x1000)
print(func.disasasm)

# Search for Objective-C selectors
for sym in bv.symbols:
    if sym.type == SymbolType.ImportedFunction and b"objc_msgSend" in sym.name:
        print(f"Found: {sym.name} at {hex(sym.address)}")

# Find sensitive functions
for func in bv.functions:
    if "keychain" in func.name.lower() or "crypto" in func.name.lower():
        print(f"Sensitive: {func.name} at {hex(func.start)}")
```

### Plugin Ecosystem Highlights

| Plugin | Purpose |
|--------|---------|
| `objcDecrypt` | Decrypt App Store binaries |
| `MachOViewer` | Enhanced Mach-O structure viewer |
| `FridaBind` | Live instrumentation via Frida |
| `ClassDump` | Objective-C header reconstruction |
| `SwiftDemangle` | Demangle Swift symbols |

### Learning Curve

Binary Ninja prioritizes usability. Key advantages:
- Clean IL design makes scripting accessible
- Rich Python/Low Level IL documentation
- Active Discord community for support
- Commercial license includes all plugins

---

## 4. Ghidra — iOS Module and Mach-O Loader

### Overview

Ghidra is NSA's open-source reverse engineering framework with growing iOS support. While originally designed for native binary formats, the community has developed extensions for Mach-O parsing, ARM64 analysis, and iOS-specific functionality.

### Official iOS Support

Ghidra 10+ includes basic iOS support:
- **Mach-O loader** — Community edition handles Mach-O binaries
- **ARM64 processor** — Full instruction decode and analysis
- **Objective-C decompiler** — Function name recovery
- **Swift support** — Symbol demangling for Swift binaries

### Installation

```bash
# Download Ghidra from https://ghidra-sre.org
unzip Ghidra_*_*.zip -d /opt/
cd /opt/ghidra/support
./ghidraRun

# For headless analysis
export GHIDRA_INSTALL_DIR=/opt/ghidra
```

### iOS-Specific Extensions

```bash
# Install Mach-O support extension
git clone https://github.com/nowsecure/ghidra_iOS.git
# Copy to "<ghidra>/Extensions/"

# Alternative: GhidraXS - Enhanced iOS support
git clone https://github.com/0x36/GhidraXS.git
cp -r GhidraXS/* "<ghidra>/Extensions/"

# Restart Ghidra to load extensions
```

### Mach-O Analysis Workflow

```java
// Ghidra Script - Find encrypted regions in Mach-O
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;

public class FindEncryption extends GhidraScript {
    public void run() throws Exception {
        MachHeader header = (MachHeader) currentProgram.getMemory()
            .getAllFileBytes()[0];
        
        // Walk load commands
        for (LoadCommand cmd : header.getLoadCommands()) {
            if (cmd instanceof EncryptionInfoCommand) {
                EncryptionInfoCommand enc = (EncryptionInfoCommand) cmd;
                println("Encrypted region: " + enc.getCryptoff() + 
                        " size: " + enc.getCryptsize());
            }
        }
    }
}
```

### ARM64 Analysis Features

- **Instruction decoding** — Full ARMv8 A64 instruction set
- **IL generation** — PCode intermediate language
- **Decompiler** — C-style output with type recovery
- **Function hashing** — For binary similarity analysis
- **Scripting** — Java, Python (via Ghidrathon)

### Scripting with Python

```python
# Ghidra Python script for iOS analysis
from ghidra.program.model.symbol import *
from ghidra.app.cmd.function import *

# Find all Objective-C methods
listing = currentProgram.getListing()
symbolTable = currentProgram.getSymbolTable()

for symbol in symbolTable.getAllSymbols(True):
    if "objc" in str(symbol.getName()).lower():
        addr = symbol.getAddress()
        func = getFunctionContaining(addr)
        if func:
            decomp = getDecompiler().decompileFunction(func, 5, monitor)
            print(f"{symbol.getName()}: {decomp.getCString()[:100]}...")
```

### Comparison with Binary Ninja

| Aspect | Ghidra | Binary Ninja |
|--------|--------|--------------|
| Cost | Free, open-source | Commercial |
| ARM64 IL | PCode | Lift IR |
| Scripting | Java, Python | Python |
| Learning curve | Steeper | Gentler |
| iOS specificity | Community extensions | Built-in focus |

---

## 5. Tool Comparison Matrix

### Comprehensive Comparison

| Tool | Primary Use Case | Cost | Learning Curve | iOS Specificity | Automation |
|------|------------------|------|----------------|-----------------|------------|
| **Corellium** | Cloud device testing | $$ | Low | High | Excellent API |
| **Blutter** | Flutter analysis | Free | Low | Specialized | CLI only |
| **Binary Ninja** | General RE | $$ | Medium | High | Python API |
| **Ghidra** | General RE | Free | High | Medium | Java/Python |
| **Frida** | Dynamic analysis | Free | Medium | High | JS scripting |
| **Objection** | Dynamic analysis | Free | Low | High | CLI |
| **Radare2** | General RE | Free | Very High | Medium | CLI/scripting |

### Use Case Recommendations

| Scenario | Primary Tool | Secondary Tools |
|----------|--------------|-----------------|
| Remote team testing | Corellium | Frida, Objection |
| Flutter app analysis | Blutter | Frida, Binary Ninja |
| Binary reverse engineering | Binary Ninja | Ghidra, Radare2 |
| Kernel exploit research | Corellium | Ghidra, Binary Ninja |
| App Store binary audit | Binary Ninja | Ghidra, objection |
| CI/CD security scanning | Ghidra (headless) | Blutter |
| Real-time instrumentation | Frida | Objection |

### Cost Analysis

```
Budget-Conscious (Free Tier)
├── Ghidra (primary RE)
├── Radare2 (CLI RE)
├── Frida + Objection (dynamic)
└── Blutter (Flutter only)

Professional ($100-500/month)
├── Binary Ninja (primary RE)
├── Corellium team plan
└── Existing free tools

Enterprise (Custom)
├── Full Corellium enterprise
├── Binary Ninja team licenses
├── Custom Ghidra extensions
└── Integrated CI/CD pipelines
```

---

## 6. OWASP MASTG References

### Tool Selection Guidance

The OWASP Mobile Application Security Testing Guide (MASTG) provides structured methodology for tool selection:

### Static Analysis Tools (Chapter 5)

| Category | Recommended Tools | MASTG Reference |
|----------|-------------------|------------------|
| Disassembly | IDA Pro, Ghidra, Binary Ninja | MASTG-TOOL-0001 |
| Decompilation | Ghidra, Hopper, Frida | MASTG-TOOL-0002 |
| Mach-O parsing | otool, class-dump, Ghidra | MASTG-TOOL-0003 |
| String analysis | strings, radare2, Binary Ninja | MASTG-TOOL-0004 |
| Frida scripts | frida-trace, custom scripts | MASTG-TOOL-0005 |

### Dynamic Analysis Tools (Chapter 6)

| Category | Recommended Tools | MASTG Reference |
|----------|-------------------|------------------|
| Device control | Corellium, USB forwarding | MASTG-TOOL-0010 |
| Runtime analysis | Frida, Objection, substrate | MASTG-TOOL-0011 |
| Network interception | Burp Suite, Proxyman | MASTG-TOOL-0012 |
| Tracing | frida-trace, lldb, syscall-trace | MASTG-TOOL-0013 |
| Memory analysis | frida-ps, debugserver | MASTG-TOOL-0014 |

### Tool Maturity Levels (MASTG Classification)

```
MATURE - Production-ready
├── Frida (dynamic instrumentation)
├── Burp Suite (proxying)
├── Ghidra (RE framework)
└── Objection (runtime mobile)

BETA - Functional but evolving
├── Corellium (cloud devices)
├── Binary Ninja (RE platform)
└── Blutter (Flutter analysis)

EXPERIMENTAL - Limited production use
├── Custom Ghidra iOS extensions
└── Radare2 iOS plugins
```

### Choosing Based on Engagement Type

| Engagement | Recommended Stack |
|------------|------------------|
| **Quick assessment** | Objection + Frida + Burp |
| **Deep dive RE** | Binary Ninja + Ghidra |
| **Remote/distributed** | Corellium + Frida |
| **Flutter apps** | Blutter + Frida + Binary Ninja |
| **Full security audit** | All tools combined |

---

## 7. Practical Workflows

### Workflow 1: Comprehensive Binary Audit

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Initial Reconnaissance                                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Extract IPA from App Store (or provided)                     │
│ 2. Use class-dump to extract Objective-C headers                │
│ 3. Run strings and grep for sensitive patterns                  │
│ 4. Identify encryption/anti-tamper indicators                   │
│                                                                  │
│ Commands:                                                        │
│ $ class-dump -H decrypted_app -o headers/                        │
│ $ strings decrypted_app | grep -i "api.key\|password\|secret"   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Static Analysis with Binary Ninja                       │
├─────────────────────────────────────────────────────────────────┤
│ 1. Open binary in Binary Ninja                                   │
│ 2. Analyze control flow for sensitive functions                │
│ 3. Map Objective-C selectors to implementations                │
│ 4. Document encryption/custom crypto usage                      │
│ 5. Export findings for report                                    │
│                                                                  │
│ Script: objcDecrypt for encrypted binaries                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Dynamic Analysis with Frida/Objection                    │
├─────────────────────────────────────────────────────────────────┤
│ 1. Spawn app with Frida gadget or device attachment            │
│ 2. Disable SSL pinning if present                               │
│ 3. Hook sensitive functions identified in Step 2                │
│ 4. Monitor network traffic with proxy                           │
│ 5. Capture runtime parameters and return values                  │
│                                                                  │
│ Commands:                                                        │
│ $ objection explore -f com.example.app                          │
│ $ frida -H device:27042 -l ssl-pinning-bypass-ios.js                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Verification and Documentation                            │
├─────────────────────────────────────────────────────────────────┤
│ 1. Reproduce findings with evidence                              │
│ 2. Calculate CVSS scores for vulnerabilities                    │
│ 3. Document remediation recommendations                          │
│ 4. Compile final report                                          │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow 2: Flutter App Deep Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: Standard iOS Analysis                                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Extract IPA and analyze as standard iOS app                   │
│ 2. Identify Flutter framework indicators                         │
│ 3. Locate embedded Dart snapshots                                 │
│                                                                  │
│ $ unzip target.ipa -d extracted/                                 │
│ $ find extracted/ -name "*.snapshot" -o -name "dart_*"          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 2: Blutter Dart Analysis                                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Extract Dart snapshots with Blutter                          │
│ 2. Analyze extracted symbols and strings                         │
│ 3. Search for hardcoded secrets                                  │
│ 4. Map Flutter widget references                                  │
│                                                                  │
│ $ blutter extract --input target.ipa --output flutter_out/      │
│ $ blutter search --input flutter_out/ --pattern "api.key"       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 3: Combined Dynamic Analysis                               │
├─────────────────────────────────────────────────────────────────┤
│ 1. Attach Frida to Flutter engine                                │
│ 2. Hook Dart VM functions                                        │
│ 3. Monitor method channel communications                         │
│ 4. Intercept platform channel calls                              │
│                                                                  │
│ $ frida -f com.example.app -l flutter-ios-hook.js                    │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow 3: Cloud-Based Distributed Testing

```
┌─────────────────────────────────────────────────────────────────┐
│ Setup: Corellium Device Provisioning                             │
├─────────────────────────────────────────────────────────────────┤
│ 1. Provision iOS device via Corellium dashboard                 │
│ 2. Install target app via USB forwarding                         │
│ 3. Configure proxy for traffic interception                      │
│                                                                  │
│ $ corellium device create --os 16.5 --iphone14                 │
│ $ corellium usb forward <device-id>                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Analysis: Parallel Tool Execution                                │
├─────────────────────────────────────────────────────────────────┤
│ Terminal 1: Frida instrumentation                                │
│ $ frida -H <corellium-ip>:27042 -f com.example.app              │
│                                                                  │
│ Terminal 2: Objection runtime exploration                        │
│ $ objection --host <corellium-ip> explore -f com.example.app    │
│                                                                  │
│ Terminal 3: Burp Suite proxy                                    │
│ Configure upstream proxy to Corellium device                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Capture: Evidence Collection                                     │
├─────────────────────────────────────────────────────────────────┤
│ 1. Screenshot sensitive UI states                               │
│ 2. Record Frida/Objection output logs                            │
│ 3. Export captured network traffic                               │
│ 4. Save snapshot of device state                                 │
│                                                                  │
│ $ corellium device snapshot <device-id> --name "post-test"     │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow 4: CI/CD Integration

```bash
#!/bin/bash
# iOS Security CI/CD Pipeline

set -e

IPA_PATH=$1
OUTPUT_DIR=$2

echo "=== iOS Security Scan Pipeline ==="

# Step 1: Static Analysis with Ghidra (headless)
echo "[1/4] Running Ghidra static analysis..."
ghidraRun -analysis -project /tmp/ghidra_project \
  -import "$IPA_PATH" -scriptPath ./scripts/ \
  -postScript IOSecurityCheck.java

# Step 2: Flutter Analysis if applicable
if [[ "$IPA_PATH" == *"flutter"* ]]; then
  echo "[2/4] Running Blutter Flutter analysis..."
  ./blutter analyze --input "$IPA_PATH" --output "$OUTPUT_DIR/flutter/"
fi

# Step 3: Dynamic Analysis with Frida
echo "[3/4] Running Frida dynamic analysis..."
frida -f "$IPA_PATH" -l assets/frida-scripts/sdk-tracer.js \
  -o "$OUTPUT_DIR/frida_output.log"

# Step 4: Generate Report
# generate-report.py compiles a findings JSON (the schema produced by
# scripts/dependency_scanner.py and scripts/mobsf_export.py) into the audit
# report. It does not read the Ghidra/Blutter/Frida output directories:
# assemble their findings into $OUTPUT_DIR/findings.json first.
echo "[4/4] Compiling security report..."
python3 ./scripts/generate-report.py \
  --input "$OUTPUT_DIR/findings.json" \
  --output "$OUTPUT_DIR/security-report.md"

echo "=== Scan Complete ==="
```

---

## Quick Reference Commands

### Essential Tool Installation

```bash
# Core tools
brew install frida objection radare2 class-dump
npm install -g @corellium/cli

# Binary analysis
# Binary Ninja: Download from binary.ninja
# Ghidra: Download from ghidra-sre.org

# Flutter analysis
git clone https://github.com/ ليلة/Blutter.git && cd Blutter && go build

# OWASP tools
brew install owasp-zap mobsf
```

### Daily Usage Commands

```bash
# Frida
frida -f com.example.app -U --hooks-libssl    # SSL bypass
frida-trace -i "*crypto*" -f com.example.app  # Trace crypto calls
objection explore -f com.example.app          # Interactive exploration

# Binary Analysis
strings app | grep -i "secret"               # String extraction
class-dump -H app -o headers/                # Headers extraction
otool -L app                                 # Dynamic libraries

# Corellium
corellium devices list                       # List devices
corellium usb forward "<id>"                   # USB forwarding
```

---

## Additional Resources

### Official Documentation

- **Frida**: https://frida.re/docs
- **Ghidra**: https://ghidra-sre.org/documentation
- **Binary Ninja**: https://docs.binary.ninja
- **Corellium**: https://corellium.com/docs
- **OWASP MASTG**: https://mas.owasp.org

### Community Resources

- **iOS RE Discord**: Reverse engineering community
- **r/ReverseEngineering**: Reddit community
- **OWASP Mobile**: Mobile security resources
- **Mobile Security Wiki**: crowdsourced documentation

### Training Materials

- **OWASP Mobile Security Testing Guide**: Comprehensive methodology
- **Corellium Academy**: Virtual device training
- **Ghidra Crash Course**: Official tutorials
- **Frida Academy**: Dynamic instrumentation courses

---

*Last Updated: 2026-04-04*
*Maintainer: DragonJAR Security Team*
