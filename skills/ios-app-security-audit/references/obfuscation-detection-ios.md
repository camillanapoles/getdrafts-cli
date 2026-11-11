# iOS Obfuscation Detection

iOS obfuscation techniques protect apps from reverse engineering. This guide covers Swift name mangling, SwiftShield, commercial protectors (IOSSecuritySuite, Arxan, Irdeto), and detection methodology.

**MASTG References:**
- MASTG-TEST-0083: Testing Binary Protection
- MASTG-TEST-0084: Testing the Binary (iOS)

## 1. Swift Name Mangling

### Swift Name Mangling Detection

```bash
# Check for Swift name mangling
nm MyApp | grep "_Tt" | head -20

# Count mangled symbols
nm MyApp | grep -c "_Tt"

# Check for unmangled symbols
nm MyApp | grep "\[.*\] " | head -10
```

### Frida Detection

```javascript
// Detect Swift name mangling
if (ObjC.available) {
    console.log("[*] Checking for Swift name mangling");

    const modules = Process.enumerateModules();

    for (const module of modules) {
        const exports = module.enumerateExports();

        // Count mangled symbols
        const mangledSymbols = exports.filter(e =>
            e.name.startsWith('_Tt') ||
            e.name.includes('$S') ||
            e.name.includes('$s')
        );

        if (mangledSymbols.length > 0) {
            console.log(`[+] ${module.name}: ${mangledSymbols.length} mangled symbols`);

            // Show examples
            mangledSymbols.slice(0, 10).forEach(s => {
                console.log(`    ${s.name}`);
            });
        }
    }
}
```

## 2. SwiftShield

### SwiftShield Detection

```bash
# Check for SwiftShield signatures
strings MyApp | grep -i "swiftshield\|encrypted" | head -10

# Check for encrypted strings
strings MyApp | grep -E "[A-Za-z0-9]{50,}" | head -10

# Check for deobfuscation table
strings MyApp | grep -i "deobfuscation\|obfuscation" | head -10
```

## 3. Commercial Protectors

### IOSSecuritySuite Detection

```bash
# Check for IOSSecuritySuite signatures
strings MyApp | grep -i "iossecuritysuite\|jailbreak\|debug" | head -20

# Check for anti-debug symbols
nm MyApp | grep -i "jailbreak\|debugger\|frida" | head -20
```

### Arxan Detection

```bash
# Check for Arxan signatures
strings MyApp | grep -i "arxan\|guardit\|anti-tamper" | head -20

# Check for integrity checks
strings MyApp | grep -i "integrity\|tamper\|checksum" | head -20
```

### Irdeto Detection

```bash
# Check for Irdeto signatures
strings MyApp | grep -i "irdeto\|cipher\|whitebox" | head -20

# Check for whitebox crypto
strings MyApp | grep -i "whitebox\|dwhite" | head -20
```

## 4. Detection Methodology

### Automated Detection Script

```bash
#!/bin/bash
# detect_obfuscation.sh

BINARY=$1
OUTPUT=${2:-obfuscation_report.txt}

if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary> [output]"
    exit 1
fi

echo "[*] Detecting obfuscation in: $BINARY"

# 1. Check for Swift name mangling
echo "1. Swift Name Mangling:" > "$OUTPUT"
MANGLED_COUNT=$(nm "$BINARY" | grep -c "_Tt" || echo "0")
echo "   Mangled symbols: $MANGLED_COUNT" >> "$OUTPUT"

if [ "$MANGLED_COUNT" -gt 0 ]; then
    echo "   Status: ENABLED" >> "$OUTPUT"
else
    echo "   Status: DISABLED" >> "$OUTPUT"
fi

# 2. Check for string encryption
echo "" >> "$OUTPUT"
echo "2. String Encryption:" >> "$OUTPUT"
ENCRYPTED_STRINGS=$(strings "$BINARY" | grep -c "[A-Za-z0-9]{50,}" || echo "0")
echo "   Long strings (>50 chars): $ENCRYPTED_STRINGS" >> "$OUTPUT"

if [ "$ENCRYPTED_STRINGS" -gt 10 ]; then
    echo "   Status: LIKELY ENCRYPTED" >> "$OUTPUT"
else
    echo "   Status: NOT ENCRYPTED" >> "$OUTPUT"
fi

# 3. Check for commercial protectors
echo "" >> "$OUTPUT"
echo "3. Commercial Protectors:" >> "$OUTPUT"

if strings "$BINARY" | grep -qi "iossecuritysuite"; then
    echo "   IOSSecuritySuite: DETECTED" >> "$OUTPUT"
else
    echo "   IOSSecuritySuite: NOT DETECTED" >> "$OUTPUT"
fi

if strings "$BINARY" | grep -qi "arxan\|guardit"; then
    echo "   Arxan: DETECTED" >> "$OUTPUT"
else
    echo "   Arxan: NOT DETECTED" >> "$OUTPUT"
fi

if strings "$BINARY" | grep -qi "irdeto"; then
    echo "   Irdeto: DETECTED" >> "$OUTPUT"
else
    echo "   Irdeto: NOT DETECTED" >> "$OUTPUT"
fi

# 4. Check for anti-debug
echo "" >> "$OUTPUT"
echo "4. Anti-Debug:" >> "$OUTPUT"

if nm "$BINARY" | grep -qi "ptrace\|sysctl"; then
    echo "   Anti-debug: DETECTED" >> "$OUTPUT"
else
    echo "   Anti-debug: NOT DETECTED" >> "$OUTPUT"
fi

# 5. Overall assessment
echo "" >> "$OUTPUT"
echo "5. Overall Assessment:" >> "$OUTPUT"

if [ "$MANGLED_COUNT" -gt 0 ] && [ "$ENCRYPTED_STRINGS" -gt 10 ]; then
    echo "   Obfuscation Level: HIGH" >> "$OUTPUT"
elif [ "$MANGLED_COUNT" -gt 0 ] || [ "$ENCRYPTED_STRINGS" -gt 10 ]; then
    echo "   Obfuscation Level: MEDIUM" >> "$OUTPUT"
else
    echo "   Obfuscation Level: LOW" >> "$OUTPUT"
fi

echo "[+] Report saved to: $OUTPUT"
```

## Testing Checklist

### Swift Obfuscation
- [ ] Detect Swift name mangling
- [ ] Check for string encryption
- [ ] Verify obfuscation techniques
- [ ] Test deobfuscation attempts
- [ ] Check for SwiftShield

### Commercial Protectors
- [ ] Detect IOSSecuritySuite
- [ ] Check for Arxan signatures
- [ ] Verify Irdeto presence
- [ ] Test bypass techniques
- [ ] Check for other protectors

### Analysis
- [ ] Verify obfuscation level
- [ ] Test reverse engineering resistance
- [ ] Check for deobfuscation tools
- [ ] Verify runtime behavior
- [ ] Test dynamic analysis

## OWASP MASTG References

- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0084**: Testing the Binary (iOS)
