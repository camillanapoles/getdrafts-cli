# Unity iOS Security

Unity enables building iOS games and apps using C#. The Unity framework and IL2CPP compilation introduce unique security considerations for iOS deployments.

## Architecture Overview

### Unity iOS Compilation Pipeline

```
C# Scripts (Unity)
        ↓
    IL2CPP AOT
        ↓
    C++ Code
        ↓
    LLVM Compiler
        ↓
    ARM64 Native Code
        ↓
    Unity Framework
```

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0083: Testing Binary Protection

## 1. UnityFramework.framework

### Detection

```bash
# Check for Unity framework
find Payload/*.app -name "*.framework" | grep -i unity

# Look for Unity-specific strings
strings Payload/*.app/* | grep -i "unity"

# Check for Unity version
strings Payload/*.app/* | grep "Unity " | head -5

# Check for IL2CPP
strings Payload/*.app/* | grep -i "il2cpp"
```

### Frida Detection

```javascript
// Detect Unity iOS app
if (ObjC.available) {
    try {
        const UnityAppController = ObjC.classes.UnityAppController;

        if (UnityAppController) {
            console.log("[+] Unity iOS App Detected");

            // Try to get Unity version
            try {
                const version = UnityAppController['- application:didFinishLaunchingWithOptions:'];
                if (version) {
                    console.log("    [+] UnityAppController found");
                }
            } catch (e) {}

            // Check for IL2CPP
            const modules = Process.enumerateModules();
            const unityModule = modules.find(m => m.name.includes('Unity') || m.name.includes('il2cpp'));

            if (unityModule) {
                console.log(`    [+] Unity Module: ${unityModule.name}`);
                console.log(`        Base: 0x${unityModule.base.toString(16)}`);
                console.log(`        Size: ${unityModule.size}`);

                // Check for IL2CPP symbols
                const exports = unityModule.enumerateExports();
                const il2cppExports = exports.filter(e => e.name.includes('il2cpp'));

                if (il2cppExports.length > 0) {
                    console.log(`    [+] IL2CPP: Detected (${il2cppExports.length} exports)`);
                    il2cppExports.slice(0, 10).forEach(e => {
                        console.log(`        ${e.name}`);
                    });
                }
            }
        } else {
            console.log("[-] Not a Unity app");
        }
    } catch (e) {
        console.log("[-] Error detecting Unity: " + e);
    }
}
```

### Unity Framework Analysis

```bash
#!/bin/bash
# analyze_unity_framework.sh

APP_PATH=$1

if [ -z "$APP_PATH" ]; then
    echo "Usage: $0 <app_path>"
    exit 1
fi

echo "[*] Analyzing Unity Framework..."

# Find UnityFramework.framework
UNITY_FRAMEWORK=$(find "$APP_PATH" -name "UnityFramework.framework" -type d)

if [ -n "$UNITY_FRAMEWORK" ]; then
    echo "[+] Found UnityFramework.framework"

    UNITY_BINARY="$UNITY_FRAMEWORK/UnityFramework"

    if [ -f "$UNITY_BINARY" ]; then
        echo "[+] Found UnityFramework binary"

        # Get Unity version
        echo "[*] Unity Version:"
        strings "$UNITY_BINARY" | grep -E "^Unity [0-9]+\.[0-9]+\.[0-9]+" | head -1

        # Check for IL2CPP
        echo "[*] IL2CPP Check:"
        if strings "$UNITY_BINARY" | grep -qi "il2cpp"; then
            echo "    [+] IL2CPP: Enabled"
        else
            echo "    [-] IL2CPP: Disabled (Mono backend)"
        fi

        # Check for globalgamemanagers
        echo "[*] GlobalGameManager Check:"
        if strings "$UNITY_BINARY" | grep -qi "globalgamemanagers"; then
            echo "    [+] globalgamemanagers found"
        fi

        # List main exports
        echo "[*] Main Exports:"
        nm "$UNITY_BINARY" | grep "T _Unity" | head -20
    fi
else
    echo "[-] UnityFramework.framework not found"
fi

# Check for Data directory
DATA_DIR=$(find "$APP_PATH" -name "Data" -type d | head -1)

if [ -n "$DATA_DIR" ]; then
    echo "[+] Found Data directory"

    echo "[*] Data directory contents:"
    ls -la "$DATA_DIR"

    # Check for globalgamemanagers
    if [ -f "$DATA_DIR/globalgamemanagers" ]; then
        echo "[+] Found globalgamemanagers file"
        file "$DATA_DIR/globalgamemanagers"
    fi

    # Check for level files
    echo "[*] Level files:"
    find "$DATA_DIR" -name "level*" -o -name "unity default resources" | head -10
fi
```

## 2. IL2CPP on ARM64

### IL2CPP Detection

```javascript
// Comprehensive IL2CPP detection
setTimeout(() => {
    console.log("[*] IL2CPP Analysis");

    const modules = Process.enumerateModules();

    // Find IL2CPP module
    const il2cppModule = modules.find(m =>
        m.name.toLowerCase().includes('il2cpp') ||
        m.name.toLowerCase().includes('unity')
    );

    if (il2cppModule) {
        console.log(`[+] IL2CPP Module: ${il2cppModule.name}`);
        console.log(`    Base: 0x${il2cppModule.base.toString(16)}`);
        console.log(`    Size: ${il2cppModule.size}`);

        const exports = il2cppModule.enumerateExports();

        // IL2CPP Runtime Functions
        const runtimeFunctions = [
            'il2cpp_init',
            'il2cpp_domain_load',
            'il2cpp_thread_attach',
            'il2cpp_thread_detach',
            'il2cpp_get_corlib',
            'il2cpp_get_assembly',
            'il2cpp_get_class',
            'il2cpp_get_method',
            'il2cpp_invoke',
            'il2cpp_runtime_invoke',
            'il2cpp_string_new',
            'il2cpp_value_box',
            'il2cpp_object_new',
            'il2cpp_array_new',
            'il2cpp_array_length',
            'il2cpp_gchandle_new',
            'il2cpp_gchandle_free'
        ];

        console.log("[*] IL2CPP Runtime Functions:");
        runtimeFunctions.forEach(func => {
            const found = exports.find(e => e.name === func);
            if (found) {
                console.log(`    [+] ${func} @ 0x${found.address.toString(16)}`);
            }
        });

        // IL2CPP Metadata Functions
        const metadataFunctions = [
            'il2cpp_get_type_name',
            'il2cpp_type_get_name',
            'il2cpp_class_get_name',
            'il2cpp_class_get_namespace',
            'il2cpp_class_get_parent',
            'il2cpp_class_get_methods',
            'il2cpp_method_get_name',
            'il2cpp_method_get_param_count',
            'il2cpp_assembly_get_image'
        ];

        console.log("[*] IL2CPP Metadata Functions:");
        metadataFunctions.forEach(func => {
            const found = exports.find(e => e.name === func);
            if (found) {
                console.log(`    [+] ${func} @ 0x${found.address.toString(16)}`);
            }
        });

        // Try to initialize IL2CPP
        try {
            const il2cpp_init = Module.findGlobalExportByName('il2cpp_init');
            if (il2cpp_init) {
                console.log("[*] Attempting to initialize IL2CPP...");

                // Note: IL2CPP may already be initialized
                // This is just for demonstration
                console.log("[!] IL2CPP runtime is available for hooking");
            }
        } catch (e) {
            console.log("[-] Could not initialize IL2CPP: " + e);
        }
    } else {
        console.log("[-] IL2CPP module not found");
    }

    console.log("");
}, 2000);
```

### IL2CPP Hooking Example

```javascript
// Hook IL2CPP method invocation
setTimeout(() => {
    try {
        const il2cpp_invoke = Module.findGlobalExportByName('il2cpp_invoke');

        if (il2cpp_invoke) {
            console.log("[*] Hooking il2cpp_invoke...");

            Interceptor.attach(il2cpp_invoke, {
                onEnter: function(args) {
                    const method = args[1];
                    const obj = args[2];
                    const params = args[3];

                    // Try to get method name
                    try {
                        const il2cpp_method_get_name = Module.findGlobalExportByName('il2cpp_method_get_name');
                        if (il2cpp_method_get_name) {
                            const getName = new NativeFunction(il2cpp_method_get_name, 'pointer', ['pointer']);
                            const namePtr = getName(method);

                            if (namePtr && !namePtr.isNull()) {
                                const name = namePtr.readUtf8String();
                                console.log(`[+] IL2CPP Method Called: ${name}`);
                            }
                        }
                    } catch (e) {}
                }
            });

            console.log("[+] il2cpp_invoke hook installed");
        }
    } catch (e) {
        console.log("[-] Error hooking il2cpp_invoke: " + e);
    }
}, 3000);
```

## 3. Data/ Directory Structure

### Typical Unity iOS Data Directory

```
Data/
├── globalgamemanagers       # Global game configuration
├── level0                   # First level data
├── level1                   # Additional levels
├── managed/                 # IL2CPP metadata (if present)
│   └── Metadata.dat
├── Resources/               # Game resources
├── StreamingAssets/         # Streaming assets
│   ├── config.json
│   ├── assets/
│   └── bundles/
└── unity default resources  # Default resources
```

### Extracting StreamingAssets

```bash
#!/bin/bash
# extract_unity_data.sh

APP_PATH=$1
EXTRACT_DIR=$2

if [ -z "$APP_PATH" ] || [ -z "$EXTRACT_DIR" ]; then
    echo "Usage: $0 <app_path> <extract_dir>"
    exit 1
fi

mkdir -p "$EXTRACT_DIR"

echo "[*] Extracting Unity Data..."

# Find Data directory
DATA_DIR=$(find "$APP_PATH" -name "Data" -type d | head -1)

if [ -z "$DATA_DIR" ]; then
    echo "[-] Data directory not found"
    exit 1
fi

echo "[+] Found Data directory: $DATA_DIR"

# Copy Data directory
cp -r "$DATA_DIR" "$EXTRACT_DIR/"

# Analyze globalgamemanagers
if [ -f "$EXTRACT_DIR/Data/globalgamemanagers" ]; then
    echo "[*] Analyzing globalgamemanagers..."

    # Check file type
    file "$EXTRACT_DIR/Data/globalgamemanagers"

    # Extract strings
    strings "$EXTRACT_DIR/Data/globalgamemanagers" > "$EXTRACT_DIR/globalgamemanagers_strings.txt"

    echo "[*] Searching for URLs..."
    grep -oE "https?://[a-zA-Z0-9./?=_-]+" "$EXTRACT_DIR/Data/globalgamemanagers_strings.txt" | sort -u > "$EXTRACT_DIR/urls.txt"

    URL_COUNT=$(wc -l < "$EXTRACT_DIR/urls.txt")
    echo "[+] Found $URL_COUNT unique URLs"

    echo "[*] Searching for secrets..."
    grep -iE "api[_-]?key|password|secret|token|credential" "$EXTRACT_DIR/Data/globalgamemanagers_strings.txt" > "$EXTRACT_DIR/secrets.txt"

    if [ -s "$EXTRACT_DIR/secrets.txt" ]; then
        echo "[!] Found potential secrets:"
        head -20 "$EXTRACT_DIR/secrets.txt"
    fi
fi

# Extract StreamingAssets
if [ -d "$EXTRACT_DIR/Data/StreamingAssets" ]; then
    echo "[+] Found StreamingAssets directory"

    echo "[*] StreamingAssets contents:"
    ls -lh "$EXTRACT_DIR/Data/StreamingAssets"

    # Copy StreamingAssets
    cp -r "$EXTRACT_DIR/Data/StreamingAssets" "$EXTRACT_DIR/streaming_assets"

    # Analyze JSON files
    echo "[*] Analyzing JSON files..."
    find "$EXTRACT_DIR/Data/StreamingAssets" -name "*.json" | while read json_file; do
        echo "  Analyzing: $(basename "$json_file")"

        # Extract URLs
        grep -oE "https?://[a-zA-Z0-9./?=_-]+" "$json_file" >> "$EXTRACT_DIR/urls.txt"

        # Extract secrets
        grep -iE "api[_-]?key|password|secret|token|credential" "$json_file" >> "$EXTRACT_DIR/secrets.txt"
    done

    # Sort and deduplicate
    sort -u "$EXTRACT_DIR/urls.txt" -o "$EXTRACT_DIR/urls.txt"
    sort -u "$EXTRACT_DIR/secrets.txt" -o "$EXTRACT_DIR/secrets.txt"
fi

# Check for managed metadata
if [ -d "$EXTRACT_DIR/Data/managed" ]; then
    echo "[+] Found managed directory (IL2CPP metadata)"

    if [ -f "$EXTRACT_DIR/Data/managed/Metadata.dat" ]; then
        echo "[+] Found Metadata.dat"
        file "$EXTRACT_DIR/Data/managed/Metadata.dat"

        # Metadata.dat contains type information for IL2CPP
        # Use tools like Il2CppDumper to analyze
    fi
fi

echo "[+] Analysis complete: $EXTRACT_DIR"
```

## 4. Asset Bundle Extraction

### Asset Bundle Analysis

```bash
#!/bin/bash
# extract_asset_bundles.sh

DATA_DIR=$1

if [ -z "$DATA_DIR" ]; then
    echo "Usage: $0 <data_dir>"
    exit 1
fi

echo "[*] Searching for asset bundles..."

# Find all asset bundles
ASSET_BUNDLES=$(find "$DATA_DIR" -name "*.unity3d" -o -name "*.asset" -o -name "*.bundle")

if [ -n "$ASSET_BUNDLES" ]; then
    echo "[+] Found asset bundles:"
    echo "$ASSET_BUNDLES"

    # Analyze each bundle
    echo "[*] Analyzing asset bundles..."

    for bundle in $ASSET_BUNDLES; do
        echo "  Analyzing: $(basename "$bundle")"

        # Check file type
        file "$bundle"

        # Extract strings
        strings "$bundle" > "${bundle}.strings.txt"

        # Extract URLs
        grep -oE "https?://[a-zA-Z0-9./?=_-]+" "${bundle}.strings.txt" | sort -u >> asset_bundles_urls.txt

        # Extract secrets
        grep -iE "api[_-]?key|password|secret|token|credential" "${bundle}.strings.txt" >> asset_bundles_secrets.txt

        # Check for textures
        if strings "$bundle" | grep -qi "texture"; then
            echo "    Contains textures"
        fi

        # Check for audio
        if strings "$bundle" | grep -qi "audio\|sound\|music"; then
            echo "    Contains audio"
        fi

        # Check for models
        if strings "$bundle" | grep -qi "mesh\|model\|3d"; then
            echo "    Contains 3D models"
        fi

        # Check for scripts
        if strings "$bundle" | grep -qi "script\|mono"; then
            echo "    Contains scripts (may expose logic)"
        fi
    done

    if [ -f "asset_bundles_urls.txt" ]; then
        URL_COUNT=$(wc -l < "asset_bundles_urls.txt")
        echo "[+] Found $URL_COUNT unique URLs in asset bundles"
    fi

    if [ -s "asset_bundles_secrets.txt" ]; then
        echo "[!] Found potential secrets in asset bundles:"
        head -20 "asset_bundles_secrets.txt"
    fi
else
    echo "[-] No asset bundles found"
fi
```

### AssetBundleLoader Security

```csharp
// Vulnerable AssetBundleLoader
using UnityEngine;
using UnityEngine.Networking;
using System.Collections;

public class VulnerableAssetLoader : MonoBehaviour {
    // VULNERABLE: Downloads from untrusted sources
    public string assetBundleUrl = "http://untrusted.com/assets/bundle.unity3d";

    void Start() {
        StartCoroutine(LoadAssetBundle());
    }

    IEnumerator LoadAssetBundle() {
        // VULNERABLE: No SSL pinning
        // VULNERABLE: No integrity check
        // VULNERABLE: No validation

        using (UnityWebRequest www = UnityWebRequestAssetBundle.GetAssetBundle(assetBundleUrl)) {
            yield return www.SendWebRequest();

            if (www.result == UnityWebRequest.Result.Success) {
                AssetBundle bundle = DownloadHandlerAssetBundle.GetContent(www);

                // Load asset without validation
                GameObject prefab = bundle.LoadAsset<GameObject>("Prefab");

                // Instantiate directly - could be malicious
                Instantiate(prefab);
            }
        }
    }
}
```

```csharp
// Secure AssetBundleLoader
using UnityEngine;
using UnityEngine.Networking;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

public class SecureAssetLoader : MonoBehaviour {
    // Secure: HTTPS only
    public string assetBundleUrl = "https://cdn.example.com/assets/bundle.unity3d";
    public string expectedHash = "a1b2c3d4e5f6..."; // SHA-256 hash of bundle

    void Start() {
        // Verify URL scheme
        if (!assetBundleUrl.StartsWith("https://")) {
            Debug.LogError("Asset bundle must use HTTPS");
            return;
        }

        StartCoroutine(LoadAssetBundleSecure());
    }

    IEnumerator LoadAssetBundleSecure() {
        using (UnityWebRequest www = UnityWebRequestAssetBundle.GetAssetBundle(assetBundleUrl)) {
            yield return www.SendWebRequest();

            if (www.result == UnityWebRequest.Result.Success) {
                byte[] data = www.downloadHandler.data;

                // Verify hash
                string actualHash = ComputeSHA256(data);

                if (actualHash != expectedHash) {
                    Debug.LogError($"Asset bundle hash mismatch! Expected: {expectedHash}, Actual: {actualHash}");
                    yield break;
                }

                AssetBundle bundle = DownloadHandlerAssetBundle.GetContent(www);

                // Validate before loading
                if (!ValidateAssetBundle(bundle)) {
                    Debug.LogError("Asset bundle validation failed");
                    yield break;
                }

                // Load with whitelist
                GameObject prefab = bundle.LoadAsset<GameObject>("Prefab");

                // Validate prefab
                if (!ValidatePrefab(prefab)) {
                    Debug.LogError("Prefab validation failed");
                    yield break;
                }

                Instantiate(prefab);
            } else {
                Debug.LogError($"Failed to load asset bundle: {www.error}");
            }
        }
    }

    private string ComputeSHA256(byte[] data) {
        using (SHA256 sha256 = SHA256.Create()) {
            byte[] hash = sha256.ComputeHash(data);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

    private bool ValidateAssetBundle(AssetBundle bundle) {
        // Implement validation logic
        // Check for unexpected assets, scripts, etc.
        return true;
    }

    private bool ValidatePrefab(GameObject prefab) {
        // Implement validation logic
        // Check for malicious components, scripts, etc.
        return true;
    }
}
```

## 5. globalgamemanagers Access

### Extracting Configuration

```bash
#!/bin/bash
# extract_globalgamemanagers.sh

DATA_DIR=$1

if [ -z "$DATA_DIR" ]; then
    echo "Usage: $0 <data_dir>"
    exit 1
fi

GLOBALGAMEMANAGERS="$DATA_DIR/globalgamemanagers"

if [ ! -f "$GLOBALGAMEMANAGERS" ]; then
    echo "[-] globalgamemanagers not found"
    exit 1
fi

echo "[*] Extracting configuration from globalgamemanagers..."

# Extract all strings
strings "$GLOBALGAMEMANAGERS" > globalgamemanagers_strings.txt

# Search for API endpoints
echo "[*] API Endpoints:"
grep -oE "https?://[a-zA-Z0-9./?=_-]+" globalgamemanagers_strings.txt | grep -E "api|service|endpoint|server" | sort -u

# Search for keys
echo "[*] Potential API Keys:"
grep -iE "[a-zA-Z0-9]{32,}" globalgamemanagers_strings.txt | head -20

# Search for game configuration
echo "[*] Game Configuration:"
grep -iE "level|difficulty|score|player|character|weapon" globalgamemanagers_strings.txt | head -20

# Search for developer/debug flags
echo "[*] Debug/Development Flags:"
grep -iE "debug|dev|test|cheat|console" globalgamemanagers_strings.txt

# Search for URLs
echo "[*] All URLs:"
grep -oE "https?://[a-zA-Z0-9./?=_-]+" globalgamemanagers_strings.txt | sort -u > urls.txt

URL_COUNT=$(wc -l < urls.txt)
echo "[+] Found $URL_COUNT unique URLs"
```

### Frida Script to Monitor globalgamemanagers Access

```javascript
// Monitor globalgamemanagers file access
if (ObjC.available) {
    try {
        // Hook file reading
        const fopen = Module.findGlobalExportByName('fopen');

        Interceptor.attach(fopen, {
            onEnter: function(args) {
                const filename = args[0].readUtf8String();
                this.isGlobalGameManagers = filename && filename.includes("globalgamemanagers");
                this.filename = filename;
            },
            onLeave: function(retval) {
                if (this.isGlobalGameManagers && !retval.isNull()) {
                    console.log(`[+] globalgamemanagers opened: ${this.filename}`);
                }
            }
        });

        console.log("[+] File access monitoring installed");
    } catch (e) {
        console.log("[-] Error installing hooks: " + e);
    }
}
```

## Testing Checklist

### Unity Framework
- [ ] Detect Unity version and framework
- [ ] Identify IL2CPP vs Mono backend
- [ ] Analyze UnityFramework exports
- [ ] Check for globalgamemanagers
- [ ] Verify Data directory structure

### IL2CPP Analysis
- [ ] Detect IL2CPP runtime
- [ ] Enumerate IL2CPP exports
- [ ] Hook IL2CPP methods
- [ ] Analyze IL2CPP metadata
- [ ] Check for debug symbols

### Data Directory
- [ ] Extract and analyze globalgamemanagers
- [ ] Review StreamingAssets
- [ ] Check for hardcoded secrets
- [ ] Extract URLs and endpoints
- [ ] Analyze level files

### Asset Bundles
- [ ] Locate asset bundles
- [ ] Extract bundle contents
- [ ] Validate bundle integrity
- [ ] Check for malicious assets
- [ ] Test asset loading security

### Network Security
- [ ] Check AssetBundleLoader implementation
- [ ] Test SSL/TLS usage
- [ ] Verify hash validation
- [ ] Check for certificate pinning
- [ ] Test for MITM vulnerabilities

### Storage Security
- [ ] Check PlayerPrefs usage
- [ ] Analyze file system access
- [ ] Review encryption implementation
- [ ] Check for sensitive data storage
- [ ] Test data integrity

## Running Unity IL2CPP apps in the iOS Simulator (Apple Silicon)

Unity games converted for the simulator (e.g. via SimForge) install and sign fine but
**abort during graphics init**. This is a GPU-driver incompatibility, not a packaging error,
and it affects essentially every Unity Metal game on the simulator.

### Symptom

The app launches, reaches Metal init, then `SIGABRT`. The backtrace shows:

```
abort → __assert_rtn → Metal MTLReportFailure
MTLSimDriver   -[MTLSimDevice newHeapWithDescriptor:]
UnityFramework MetalHeap::CreateHeap(MTLHeapDescriptor*)
UnityFramework MetalHeap::CreateBuffer(...MetalScratchBufferArea...)
```

Capture the **exact assertion** by launching with the console attached:

```bash
xcrun simctl launch --console-pty --terminate-running-process "<UDID>" "<bundle-id>"
# -[MTLSimDevice newHeapWithDescriptor:]:1211: failed assertion
#   `MTLStorageModePrivate is required for heaps'
```

### Root cause

The simulator's Metal driver (`MTLSimDriver`) **requires `MTLHeap`s to use
`MTLStorageModePrivate`**. Unity creates Shared-storage scratch heaps (valid on real
unified-memory devices). The simulator rejects them and aborts. Reproduces identically
across simulator runtimes (verified on iOS 17.x and iOS 18.x).

### Fix — interposer dylib that forces Unity's non-heap path

Inject a dylib that makes `-[MTLSimDevice newHeapWithDescriptor:]` **return `nil`**. Unity's
`MetalHeap::CreateHeap` then falls back to **direct (non-heap) buffer allocation**, which the
simulator supports with Shared storage. The app runs and renders.

> **Discarded approach (don't repeat):** forcing `descriptor.storageMode = Private` clears
> the heap assertion but only moves the crash to
> `-[MTLSimHeap newBufferWithLength:options:offset:useOffset:]` (XPC error), because Unity's
> CPU-written scratch buffers can't live in a GPU-private heap. Returning `nil` is the
> correct fix.

Two subtleties matter:
1. **Hook timing.** You can't swizzle `MTLSimDevice` in the dylib's constructor — that class
   isn't registered until Metal initializes. Instead `DYLD_INTERPOSE` the C function
   `MTLCreateSystemDefaultDevice()`; install the swizzle inside it (the device — and thus the
   class — exists by then), guarded by `dispatch_once`.
2. **Launch detached.** Use a plain `xcrun simctl launch` (no `--console-pty`); an attached
   console kills the app when the connection closes.

Source: [`assets/dylibs/metalheapfix.m`](../assets/dylibs/metalheapfix.m). One-command driver:
[`scripts/unity_sim_metalfix.sh`](../scripts/unity_sim_metalfix.sh).

```bash
# Manual flow (or just: scripts/unity_sim_metalfix.sh "<UDID>" "<bundle-id>")
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -dynamiclib -fobjc-arc -Wno-incompatible-function-pointer-types \
  -isysroot "$SDK" -target arm64-apple-ios15.0-simulator \
  -framework Foundation -framework Metal \
  -o metalheapfix.dylib assets/dylibs/metalheapfix.m
codesign -f -s - metalheapfix.dylib

xcrun simctl terminate "<UDID>" "<bundle-id>" 2>/dev/null
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$PWD/metalheapfix.dylib" \
  xcrun simctl launch "<UDID>" "<bundle-id>"

# Verify it stayed alive and rendered
xcrun simctl spawn "<UDID>" launchctl list | grep "<bundle-id>"
xcrun simctl io "<UDID>" screenshot /tmp/verify.png
```

Expected log lines from the dylib: `MTLCreateSystemDefaultDevice intercepted` →
`installed heap swizzle on MTLSimDevice` → `newHeapWithDescriptor: -> returning nil`.

> The same dylib can be combined with Frida Gadget (add both to
> `DYLD_INSERT_LIBRARIES`) for dynamic analysis once the game is running.
> See also `references/simforge-crash-triage.md` → "Unity Metal heap assertion".

## IL2CPP reverse engineering on macOS (Il2CppDumper)

For Unity IL2CPP apps, the C# logic can be reconstructed from the native binary plus the
metadata file — **no jailbreak, no device**. This recovers class/method/field names and
signatures, which is enough to audit game economy, IAP, and anti-cheat logic statically.

### Is the metadata reversible?

```bash
APP=Payload/YourApp.app
xxd "$APP/Data/Managed/Metadata/global-metadata.dat" | head -1
# magic 0xFAB11BAF (bytes: af 1b b1 fa) == UNENCRYPTED IL2CPP metadata → fully reversible
```

Unencrypted metadata is itself a resilience finding (trivial RE / cheat development); flag it.

### Install the .NET runtime without root (macOS)

Il2CppDumper is a .NET app. The Homebrew cask needs `sudo`; instead use the official script,
which installs to `~/.dotnet` with no admin rights:

```bash
curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- \
  --channel 8.0 --runtime dotnet --install-dir "$HOME/.dotnet"
```

Il2CppDumper publishes `net7`/`net6` builds (no `net8`). Run a `net7` build on the `.NET 8`
runtime with rollforward:

```bash
export DOTNET_ROLL_FORWARD=Major
~/.dotnet/dotnet Il2CppDumper.dll \
  "$APP/Frameworks/UnityFramework.framework/UnityFramework" \
  "$APP/Data/Managed/Metadata/global-metadata.dat" \
  ./il2cpp_out
# Outputs: dump.cs (full pseudo-C#), il2cpp.h, script.json, DummyDll/
# A trailing "press any key" exception is harmless — files are already written.
```

### Reading `dump.cs` for game security (generic methodology)

`dump.cs` gives method signatures (bodies are native, shown as RVAs), enough to answer:

- **Is the economy client- or server-authoritative?** Look for a save class holding currencies
  (e.g. `*SaveData` with int/double balance fields) plus a method that pushes the whole blob to
  the backend (`UpdatePlayerDataToServer`-style). If the client computes balances and the server
  just persists them, currency tampering is viable → game-integrity finding.
- **Is IAP validated server-side?** Look for receipt validation through the game backend
  (e.g. `ValidateIOSReceipt` on PlayFab, or AppsFlyer/`validateAndLog`). Server-side receipt
  validation is the **secure** pattern — don't report IAP spoofing if it's present. Blind trust
  in a local `PurchaseEventArgs` is the vulnerable pattern.
- **What does the anti-cheat actually cover?** Client-side cheat detectors (`Cheat*`,
  `*Detector`) frequently only catch **clock manipulation** (compare device time vs a server/
  world-time API), not direct value edits. State that scope precisely instead of assuming it
  blocks all tampering.

> Backend names above (PlayFab, AppsFlyer) are common examples, not findings — search the
> actual `dump.cs`/string literals to see which backend a given app uses.

Combine with runtime confirmation: hook the save-class setters or the cheat-flag setter with
Frida, then trigger the server-sync method, to prove a value-tampering path end to end.

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0002**: Identify Development and Security Protections
- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security
- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0084**: Testing the Binary (iOS)

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **objection**: Runtime exploration
- **Il2CppDumper**: IL2CPP decompilation
- **AssetStudio**: Unity asset extraction
- **UnityEX**: Unity package extraction

### Reference Materials
- [Unity Security Guide](https://docs.unity3d.com/Manual/Security.html)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [IL2CPP Documentation](https://docs.unity3d.com/Manual/IL2CPP.html)
- [AssetBundle Documentation](https://docs.unity3d.com/Manual/AssetBundlesIntro.html)
