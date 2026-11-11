# Compatibility Reference: iOS Sim Emulation

> Compatibility matrix and fundamental limitations that determine if an iOS app can run on a simulator. Complements `simforge-emulation-flow.md` (procedure) and `simforge-crash-triage.md` (diagnosis).

## When this guide is relevant

Before investing time in the patching flow, validate:

1. Is the IPA decrypted? (FairPlay / App Store encryption)
2. Is the Swift/SDK version it was compiled with compatible with the host's SimRuntime and toolchain?
3. Does the app have hardware dependencies that the simulator doesn't provide?

If any answer is "no", the simulator **CANNOT** run the app, no matter how much patching is done.

---

## §1. FairPlay / App Store Encryption

### The problem

Apps downloaded from the App Store are **FairPlay-encrypted**. The on-disk binary has:

- `LC_ENCRYPTION_INFO_64 cryptid 1`
- Real content (`__text` section, `__stubs`, etc.) is **encrypted data**, not readable ARM64 instructions.
- Only decrypts at runtime on a real device with the FairPlay key corresponding to the purchaser's Apple ID.

The **iOS simulator has no FairPlay daemon**. It cannot decrypt these binaries. Period.

### How to detect (pre-flight check)

```bash
BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"

# Check 1: Is cryptid 1?
otool -l "$BIN" | rg -A 4 LC_ENCRYPTION | rg "cryptid\s+1" \
  && echo "FAIRPLAY ENCRYPTED" || echo "decrypted"

# Check 2: Is content executable or random data?
# (After cryptoff, first bytes must be readable ARM64 instructions)
python3 -c "
with open('$BIN', 'rb') as f:
    f.seek(16384)  # typical cryptoff
    sample = f.read(64)
    # Real ARM64 instructions have recognizable bytes
    # Encrypted data is basically random
    import collections
    counter = collections.Counter(sample)
    entropy = len(counter) / 64
    if entropy > 0.7:
        print('Likely encrypted (high entropy)')
    else:
        print('Likely unencrypted (structured data)')
"
```

### Symptoms when attempting to run on simulator

- `LSInstallType: StoreDownload` in SpringBoard logs (treats it as App Store placeholder).
- `SBMainWorkspace` denial without crash report (system doesn't even attempt spawn).
- If it manages to spawn: binary crashes immediately with `EXC_CRASH SIGABRT` during page-in.

### Workarounds

| Option | Procedure | Cost |
|---|---|---|
| **frida-ios-dump on jailbroken device** | Connect iPhone, `frida-ios-dump -b <bundleid>`, output is a decrypted .ipa | Needs physical device + jailbreak |
| **bagbak on jailbroken device** | `bagbak <bundleid>`, similar to frida-ios-dump | Needs physical device + jailbreak |
| **Manual dump with Frida Gadget** | Compile Frida Gadget, inject into encrypted app, dump memory on execution | Complex, but 100% on device |
| **App Store .ipa "thinned" variants** | App Store apps have device variants. Simulator ones (iOS Simulator slices) are NOT encrypted | Only useful if you have an .ipa from Xcode, not App Store |
| **Enterprise / TestFlight build** | Internal distribution builds (not App Store) are NOT encrypted | If you have developer program access |

### Workaround that does NOT work

- "Copy the binary to another empty .app with valid entitlements" — the binary is still encrypted, won't execute.
- "Remove LC_ENCRYPTION_INFO_64 with vtool" — only changes the flag, content remains encrypted.
- "Set cryptid=0 manually" — the simulator doesn't validate cryptid, but when executing the binary, encrypted data gets mapped and the CPU can't interpret it → instant crash.

---

## §2. Swift ABI Version Mismatch

### The problem

Swift runtime libraries (`libswiftCore.dylib`, `libswiftFoundation.dylib`, etc.) have **strict ABI versioning**. An app compiled with Swift X.Y requires `libswiftCore.dylib` with `current version` equal or compatible.

**In modern iOS simulators (iOS 17+):**
- The `libswift*.dylib` in `/usr/lib/swift/` of the SimRuntime are **placeholders / shared cache stubs** (`compatibility version 0.0.0`, `current version 0.0.0`).
- The real lib is in the **dyld shared cache** and loads automatically.
- The shared cache's real version is that of the SimRuntime (e.g., iOS 26.5 brings Swift 6.x).

**If the app was compiled with an old SDK (Swift 5.x), the current shared cache provides an incompatible lib** → crash with "incompatible platforms: iOS-simulator - iOS" (deceptive) or "Library not loaded: @rpath/libswiftCore.dylib".

### How to detect

```bash
# 1. What Swift version does the app request?
otool -L "$APP/Binary" | rg "libswiftCore" | head -1
# Ex: @rpath/libswiftCore.dylib (compatibility version 1.0.0, current version 5.9.0)

# 2. What Swift version does the local toolchain have?
otool -L "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib" | head -1
# Ex: current version 1001.0.82 (Swift 6.0)

# 3. What is the Swift version of the installed Xcode?
swift --version
# Apple Swift version 6.3.2
```

### Compatibility matrix

| App compiled with SDK | Requires libswift version | Toolchain that provides it | Compatible with SimRuntime |
|---|---|---|---|
| iOS 18.x SDK (Swift 6) | 1001.x | Xcode 16+ | iOS 18+ sim |
| iOS 17.x SDK (Swift 5.9) | 5.9.0 | Xcode 15 | iOS 17+ sim |
| iOS 16.x SDK (Swift 5.7-5.8) | 5.7.x / 5.8.x | Xcode 14 | iOS 16+ sim (with Xcode 14) |
| iOS 15.x SDK (Swift 5.5) | 1300.x | Xcode 13 | iOS 15+ sim (with Xcode 13) |
| iOS 14.x SDK (Swift 5.3) | 1300.x | Xcode 12 | iOS 14+ sim (with Xcode 12) |
| < iOS 14 SDK (Swift < 5.3) | various | Xcode 11 or older | Rarely compatible with modern sim |

> **"Compatible SimRuntime" depends on the toolchain you use**, not the installed Xcode. If your Xcode is 16, you can run apps compiled with Swift 6 but NOT apps that require Swift 5.9.

### Workarounds (best to worst)

1. **Install the correct Xcode version in parallel**:
   ```bash
   # Download Xcode 15.x from developer.apple.com
   # Extract to /Applications/Xcode-15.x.app
   # Select with xcode-select
   sudo xcode-select -s /Applications/Xcode-15.x.app/Contents/Developer
   ```
   Re-sign the .app with this old toolchain, re-install.

2. **Re-compile the app from source** with current Xcode. Requires source code access.

3. **Use older simulator runtime**: if your Mac has iOS 17.x simulator runtime installed, a Swift 5.9 app might run on it. Verify with `xcrun simctl list runtimes`.

4. **Escalate to jailbroken physical device**: real devices provide the `libswift*.dylib` corresponding to their iOS version, not the sim's shared cache.

5. **No pure simulator workaround**: copying `libswift*.dylib` to the bundle does NOT work because the shared cache takes priority.

---

## §3. Hardware / Capability Limitations

The iOS simulator **does NOT provide** the following capabilities. If the app checks or depends on them, the simulator will fail or have reduced behavior.

| Capability | Behavior in sim | Mitigation |
|---|---|---|
| **Secure Enclave** | Doesn't exist; `kSecAttrTokenIDSecureEnclave` fails | Rewrite to use regular keychain in sim |
| **Touch ID / Face ID** | Simulated, configurable via Hardware > Face ID/Touch ID in Simulator.app | Enable manually |
| **NFC** | Doesn't exist | Don't test NFC flows in sim |
| **Bluetooth** | Very limited, only if host has it | Physical device required for BLE testing |
| **Camera (photo/video)** | Captures host display or shows dummy | Physical device for real capture |
| **CoreMotion (accelerometer, gyroscope)** | Simulates values via Features menu | OK for testing |
| **Location Services** | Simulates via Debug > Location in Simulator.app | OK |
| **Push notifications (APNs)** | No real server; registration works but push doesn't arrive | Physical device with real server |
| **Apple Pay** | Doesn't work in sim (requires real provisioning) | Physical device |
| **In-App Purchases** | Only works in sim with sandbox accounts (StoreKit Configuration) | OK with config |
| **Background App Refresh** | Very limited, doesn't truly execute in background | Physical device to validate |
| **CarPlay** | Doesn't exist in sim | Physical device |
| **HealthKit** | Dummy data | OK for basic testing |
| **ARKit** | Limited | Physical device for AR |
| **Metal heaps (Unity / heavy games)** | `MTLSimDriver` requires `MTLStorageModePrivate` heaps; Unity creates Shared heaps → `SIGABRT` at graphics init | Inject the metalheapfix interposer dylib (`scripts/unity_sim_metalfix.sh`) — see `references/unity-ios-security.md` |

> **Unity (Metal) games**: the simulator's Metal driver rejects the Shared-storage `MTLHeap`s
> Unity allocates, aborting with `MTLStorageModePrivate is required for heaps`. This is
> fixable (not a hard limitation): force Unity's non-heap path with the interposer dylib in
> `assets/dylibs/metalheapfix.m`. Full procedure in `references/unity-ios-security.md`;
> triage entry in `references/simforge-crash-triage.md`.

### How to detect hardware dependencies

```bash
# Search in Info.plist and entitlements
plutil -p "$APP/Info.plist" | rg -i "(nfc|nearfield|health|camera|bluetooth|location|push|carplay|arkit|secureEnclave)"
codesign -d --entitlements - "$APP" 2>&1 | rg -i "(nfc|nearfield|health|camera|bluetooth|location|push|carplay|arkit|secureEnclave)"

# Search in binary (frameworks used)
otool -L "$APP/Binary" | rg -i "(Health|ARKit|CoreNFC|NearField|LocalAuthentication|CarPlay)"
```

If the app **actively uses Secure Enclave** (not just Face ID, which is simulated), the simulator **CANNOT run the business logic**.

---

## §4. Provisioning / Entitlements

### What works in the simulator

- Ad-hoc signing with `codesign -f -s -` (no provisioning profile).
- Empty or basic flag entitlements (`get-task-allow=false`).
- Any bundle ID (doesn't need to be the App Store one).

### What does NOT work in the simulator

| Capability | Reason | Workaround |
|---|---|---|
| **APNs production** (`aps-environment=production`) | Requires entitlement + provisioning | Use `aps-environment=development` (sim tolerates) |
| **App Groups** between two apps from same developer | Require valid provisioning | Configure in both .app with same group ID manually |
| **Keychain Sharing** between apps | Requires keychain-access-groups with team ID | Re-sign with ad-hoc entitlements that simulate the group |
| **Associated Domains / Universal Links** | Requires validated domain in app-site-association | Not testable in sim, requires device + DNS |
| **In-App Payments (Apple Pay)** | Requires merchant identifier with provisioning | Not testable in sim |
| **iCloud (CloudKit, Key-Value)** | Requires container identifier with team | Not testable in sim |
| **Push Notifications (real push)** | Requires APNs cert + device token | Use `simctl push` to simulate push, but it's not real |
| **Network Extensions** | Requires special entitlement | Not testable in sim |
| **Personal VPN** | Requires entitlement | Not testable in sim |

### How to diagnose entitlement issues

```bash
# See current embedded entitlements
codesign -d --entitlements - "$APP" 2>&1

# If empty or missing required ones, the app may fail when requesting
# capabilities that require real provisioning
```

---

## §5. Summary: when to abandon the simulator

**Abandon and escalate to jailbroken physical device** when:

1. The app is FairPlay-encrypted (not decryptable without device).
2. The app was compiled with an SDK incompatible with the host's Swift toolchain AND an older Xcode cannot be installed.
3. The app has critical hardware dependencies (Secure Enclave for crypto, NFC, baseband).
4. The app requires production entitlements (APNs prod, real IAP, etc).

**Continue with simulator** when:

1. The app is decrypted (cryptid 0).
2. The app is compatible with the current Swift toolchain.
3. Analysis focuses on UI, business logic, network, storage, IPC (not hardware-specific).
4. It's acceptable for some features to be reduced or mocked.

**Hybrid** (sim + device) when:

1. Initial analysis in sim (fast, no device risk).
2. Final validation on jailbroken device (frida-server + frida-ios-dump).
3. Compare sim vs device behavior to detect anti-tamper or anti-sim checks.

## §6. Choosing the Right SimRuntime

### The problem

If you only have one SimRuntime (e.g., iOS 26.5) and all apps you want to test require Swift 5.9, you'll fail again and again. The solution is to **have multiple SimRuntimes installed** and choose the one that matches the target.

### Swift ABI map by SimRuntime

| SimRuntime | Included Swift ABI | Apps it can run (compiled with) |
|---|---|---|
| **iOS 26.5** | Swift 6.3 | Xcode 26+ (very new apps, 2025+) |
| **iOS 18.x** | Swift 6.0 | Xcode 16+ (apps 2024-2025) |
| **iOS 17.x** | **Swift 5.9** | Xcode 15 (apps 2023-2024) — **sweet spot** |
| iOS 16.x | Swift 5.7 | Xcode 14 (apps 2022-2023) |
| iOS 15.x | Swift 5.5 | Xcode 13 (apps 2021-2022) |

> **Practical decision for pentesting**: iOS 17.x covers the most apps (2023-Q1 2025), iOS 18.x for newer apps, iOS 26.x for cutting edge.

### Installing multiple SimRuntimes

**From Xcode UI** (recommended):
1. Open Xcode → Settings (Cmd+,) → Components
2. Download desired iOS Simulator runtimes (each ~3-4 GB)
3. Xcode installs them in `/Library/Developer/CoreSimulator/Profiles/Runtimes/`

**CLI verification**:

```bash
# List installed runtimes
xcrun simctl list runtimes
# Expected output with multiple runtimes:
#   iOS 17.5 (17.5 - 21F79) - com.apple.CoreSimulator.SimRuntime.iOS-17-5
#   iOS 18.6 (18.6 - 22G86) - com.apple.CoreSimulator.SimRuntime.iOS-18-6
#   iOS 26.5 (26.5 - 23F77) - com.apple.CoreSimulator.SimRuntime.iOS-26-5

# Create a specific simulator for a runtime
xcrun simctl create "iPhone 15 (iOS 17)" "iPhone 15" "com.apple.CoreSimulator.SimRuntime.iOS-17-5"
xcrun simctl create "iPhone 16 (iOS 18)" "iPhone 16 Pro" "com.apple.CoreSimulator.SimRuntime.iOS-18-6"

# Boot the one you need
xcrun simctl boot "iPhone 15 (iOS 17)"
```

### Decision tree: which SimRuntime to use?

```
Was the app compiled with Xcode 26+ (Swift 6.3)?
├── Yes → iOS 26.x runtime
└── No (Xcode 16+ / Swift 6.0)
    └── Xcode 15 (Swift 5.9) — typical app 2023-2024?
        ├── Yes → iOS 17.x runtime (RECOMMENDED)
        └── No (Xcode 14 or older)
            └── iOS 16.x or 15.x runtime
```

### ⚠️ Critical trade-off: iOS 17.x is more tolerant of legacy frameworks than iOS 26.x

**Empirical finding**: in apps with legacy frameworks (compiled with Xcode < 13, without modern `LC_BUILD_VERSION`, only `LC_VERSION_MIN_IPHONEOS`), **the SimRuntime matters more than the toolchain**. A legacy framework can:

| SimRuntime | Typical behavior |
|---|---|
| **iOS 26.x** (strict) | Rejects legacy binaries with `LC_BUILD_VERSION platform 7` if not perfectly signed. Errors like `Assertion failed: ... Header.cpp:336` or `mach-o file (...)` truncated rejection. |
| **iOS 17.x** (permissive) | Accepts legacy frameworks that only have `LC_VERSION_MIN_IPHONEOS` (without `LC_BUILD_VERSION`). More tolerant of `cryptid=0` and Apple's dyld cache semantics. |

**Practical implication**: if an app fails on iOS 26.5 with a dyld message about a legacy framework, **try iOS 17.5 before abandoning**. The same app may run perfectly on the older runtime without re-patching.

**Workaround documented in this skill**:
- If preflight passes with `[WARN] simruntime_coverage` (suggests installing iOS 17.x), explicitly boot it.
- If the full flow (simforge + sign + install + launch) fails with `Library missing` or `Header.cpp:336` on iOS 26.x, **try the same bundle on iOS 17.x** — it generally runs.

### SimRuntime auto-selection (what the script does)

The `simforge_install_launch.sh` script currently boots "the first available iPhone". For a more sophisticated version, it could choose the SimRuntime based on the preflight check.

**Quick manual workaround**: if you know your app target is iOS 17.x, boot explicitly:

```bash
# Find and boot the first simulator with iOS 17
DEVICE=$(xcrun simctl list devices available | rg "iOS 17" | head -1 | rg -o "[A-F0-9-]{36}")
xcrun simctl boot "$DEVICE"
```

### When multiple runtimes DON'T help

- **FairPlay encryption** — the runtime can't decrypt, no runtime will.
- **Hardware dependencies** (Secure Enclave, NFC) — needs physical device.
- **Provisioning / production entitlements** — needs physical device with real provisioning.
- **Swift ABI incompatible with ALL Xcode available on the host** — you'd need to install another Xcode via `xcode-select`.

### Final recommendation

For an iOS pentesting station, **install at least these 3 runtimes** (≈10-12 GB total):

| Runtime | For apps with | When to download |
|---|---|---|
| iOS 17.x (RECOMMENDED) | Swift 5.9 (Xcode 15) | 2023-2024 — majority of apps |
| iOS 18.x | Swift 6.0 (Xcode 16) | 2024-2025 — newer apps |
| iOS 26.x (you already have) | Swift 6.3 (Xcode 26) | 2025+ — cutting edge |

With these 3, you can run >95% of App Store apps in simulator (assuming they're decrypted).
