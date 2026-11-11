# Crash Triage: iOS Simulator Launch Failures

> Case-agnostic methodology for diagnosing **any** failure when launching an app on the iOS simulator. Applicable to the simforge flow, but also to any other method (frida-ios-dump, custom patching, manual resigning).

## When to use this guide

- `simctl launch` returned a PID and the process died immediately.
- `simctl launch` returned a `SBMainWorkspace` / `FBSOpenApplicationServiceErrorDomain` error.
- The app installs OK but doesn't open.
- An app that worked yesterday now crashes (stale cache, framework updated, etc).

---

## The crash report: where it is and how to parse it

### Simulator log locations

```bash
# 1. iOS crash reports (format .ips, JSON-line-prefixed)
ls -t ~/Library/Logs/DiagnosticReports/"<AppName>"-*.ips | head -1

# 2. SpringBoard / runningboardd / launchd_sim logs
xcrun simctl spawn booted log show \
  --predicate 'process == "SpringBoard" AND eventMessage CONTAINS "<bundleid>"' \
  --last 1m --style compact

# 3. runningboardd logs (where spawn failures appear)
xcrun simctl spawn booted log show \
  --predicate 'process == "runningboardd" AND eventMessage CONTAINS "<bundleid>"' \
  --last 1m --style compact
```

> **Rule**: if there's a recent `.ips`, **start there**. It has more detailed info than SpringBoard logs.

### Universal `.ips` parser

`.ips` files have **two lines**: the first is metadata, the second is the JSON with the stack trace. Critical messages (`termination.reasons[]`) are in that second line, but **can be truncated in the IDE screen**. Use this Python script to see the full content:

```python
import json
import sys

with open(sys.argv[1]) as f:
    f.readline()  # skip metadata line
    data = json.load(f)

t = data['termination']
print(f"namespace: {t.get('namespace')}")
print(f"indicator: {t.get('indicator')}")
print(f"code: {t.get('code')}")
print()
for i, r in enumerate(t.get('reasons', [])):
    print(f"--- reason {i} (full) ---")
    print(r)
```

This parser is already shipped with the skill as `scripts/simforge_triage.py` — there is no separate `parse_ips_crash.py` to create. Run it with:

```bash
python3 scripts/simforge_triage.py "<path-to-ips>"
python3 scripts/simforge_triage.py --latest   # most recent .ips in ~/Library/Logs/DiagnosticReports
```

### Why the truncation

`.ips` files seen in Console.app or `Console.app` have automatic truncation by Apple. The **raw file on disk** is complete. The Python parser above reads the complete file without truncation.

> **Additional**: sometimes even the raw file doesn't contain the complete message (reporter bugs). In that case, resort to `dyld_sim` or `runningboardd` logs to reconstruct.

---

## Decision tree: `termination.namespace` + `termination.indicator`

The `namespace` field tells you who killed the process. The `indicator` tells you how.

| namespace | indicator | Diagnosis | Action |
|---|---|---|---|
| `DYLD` | `Library missing` | A dylib/framework didn't load | See § "dyld Library missing" |
| `DYLD` | `Symbol missing` | A function/symbol not found in loaded binary | See § "dyld Symbol missing" |
| `DYLD` | `assertion failed.*Header.cpp:336` | Mixed load commands (LC_VERSION_MIN_IPHONEOS + LC_BUILD_VERSION) | See § "Mixed load commands" |
| `DYLD` | `malformed/missing LC_xxx` | Corrupt binary (bad load command) | Re-extract IPA and start from scratch |
| `LIBXPC` | `service not available` | XPC service not initialized | Simulator failure, not app |
| `EXIT` | `Namespace EXIT` | App called `exit()` with code != 0 | Search for `print`/`os_log`/`NSLog` in app code |
| `SPRINGBOARD` / `FBS` | `request denied` | SpringBoard rejected launch (Info.plist, entitlement, signature) | See § "SBMainWorkspace denial" |
| `POSIX` | `E2BIG (153)` | launchd couldn't spawn — corrupt Mach-O binary or size limit | Re-extract, redo patching |
| `POSIX` | `ENOENT (2)` | launchd couldn't find required binary or lib | Re-extract IPA |
| `EXC_CRASH` with `SIGABRT` | (no indicator) | App crashed during initialization (Swift fatal, NSException) | See stack trace in `threads[0].frames` |
| `EXC_CRASH` with `SIGABRT` | stack has `MTLSimDriver` / `newHeapWithDescriptor:` / `MetalHeap::CreateHeap` | Unity (Metal) creates Shared-storage heaps the simulator rejects | See § "Unity Metal heap assertion" |

---

## Specific cases and their solutions

### dyld "Library missing"

The most common case. The `reasons[2]` tells you **which lib is missing and where it looked**.

**Diagnostic workflow**:

1. Identify the missing lib (e.g., `MyFramework.framework/MyFramework`).
2. Verify **if it exists** in the bundle:
   ```bash
   find "$APP" -name "Bolts*" -o -name "libBolts*"
   ```
3. If it doesn't exist → does the app have that dep but we lost it on extract? Re-extract the IPA.
4. If it exists → verify **if it's patched to simulator**:
   ```bash
   otool -l <path> | rg -A 1 LC_BUILD_VERSION
   # Must say "platform 7"
   ```
5. If not patched → `simforge convert` or `vtool`.
6. If patched → **verify signature** (see § "code signature invalid" below).

**Deceptive variant**: the message says "incompatible platforms" when it's actually **incompatible ABI/Swift version**. The app requests `libswiftCore.dylib` with `current version X.Y.Z` and the SimRuntime or toolchain provides a different version. **Solution**: see `simforge-compatibility.md` § "Swift ABI version mismatch".

### Mixed load commands (LC_VERSION_MIN_IPHONEOS + LC_BUILD_VERSION)

**Symptom**: Crash with `dyld assertion failed: (err.noError()), function platformAndVersions_block_invoke, file Header.cpp, line 336` or `SIGSEGV` on launch.

**Cause**: Framework has **BOTH** `LC_VERSION_MIN_IPHONEOS` (legacy, says "iOS device") and `LC_BUILD_VERSION` (added by SimForge, says "iOS Simulator"). Modern dyld rejects binaries with inconsistent version commands.

**Detection**:

```bash
# Check for mixed commands
otool -l "$APP/Frameworks/Suspect.framework/Suspect" | grep -A3 "LC_VERSION_MIN\|LC_BUILD"

# Bad output (has both):
#   cmd LC_VERSION_MIN_IPHONEOS
#  version 10.0
#   cmd LC_BUILD_VERSION
#  platform 7
```

**Fix**: See [SimForge Legacy Load Command Cleanup](simforge-legacy-loadcmd-cleanup.md).

Quick fix:

```bash
# Use LIEF to remove LC_VERSION_MIN_IPHONEOS
python3 << 'EOF'
import lief
binary = lief.parse("Framework.framework/Binary")
for idx in reversed([i for i, c in enumerate(binary.commands)
                     if c.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS]):
    binary.remove_command(idx)
binary.write("Framework.framework/Binary")
EOF

# Re-sign
codesign -f -s - Framework.framework

# Relaunch
xcrun simctl launch booted com.example.app
```

**Common affected frameworks**:
- OneSignal (all variants: Core, Extension, Framework, InAppMessages, etc.)
- FPBExtractoriOS (biometric authentication)
- Microblink (OCR)
- Facebook SDK (older versions)

### code signature invalid

dyld found the framework on disk but its **embedded signature doesn't validate** because the binary was modified after being signed.

**Diagnosis** (4 checks in order):

```bash
APP="<path>"
FW="$APP/Frameworks/Suspect.framework"

# 1. Is the signature ad-hoc (re-signed by us) or original App Store?
codesign -dvv "$FW/Suspect" 2>&1 | rg "Authority"
# If says "Apple Distribution: <vendor>" → old signature, not ad-hoc
# If says "Signature=adhoc" → our signature, should be OK

# 2. Does it pass codesign -v --strict?
codesign -v --strict "$FW/Suspect"
# If says "invalid Info.plist (plist or signature have been modified)" → there's a mismatch

# 3. Does it have ad-hoc flags (0x2)?
codesign -dvv "$FW/Suspect" 2>&1 | rg "flags"
# If says "flags=0x0(none)" → signature without ad-hoc flag (orphaned)
```

**Fix**: re-sign **explicitly** (not `--deep`):

```bash
# Remove all signatures
codesign --remove-signature "$FW/Suspect"
codesign --remove-signature "$FW"
codesign --remove-signature "$APP"

# Re-sign in the correct order: inner binary → bundle wrapper → main app
codesign -f -s - "$FW/Suspect"
codesign -f -s - "$FW"
codesign -f -s - "$APP"
```

### SBMainWorkspace denial (no crash report)

Launch returns `FBSOpenApplicationServiceErrorDomain code=1` but **there's no `.ips`**. Means SpringBoard rejected the launch BEFORE attempting to spawn the process.

**Diagnosis**:

```bash
# 1. SpringBoard logs
xcrun simctl spawn booted log show \
  --predicate 'process == "SpringBoard" AND eventMessage CONTAINS "<bundleid>"' \
  --last 1m --style compact 2>&1 | rg -i "(deny|denied|invalid|reason|placeholder)"

# 2. installcoordinationd logs (mentions "no entitlements", etc)
xcrun simctl spawn booted log show \
  --predicate 'process == "installcoordinationd" AND eventMessage CONTAINS "<bundleid>"' \
  --last 1m --style compact 2>&1 | rg -i "(no entitlement|placeholder|invalid)"

# 3. Look for common markers:
#    "app not found" → app didn't finish installing (try reinstall)
#    "had no entitlements" → ad-hoc signature without embedded entitlements (OK, doesn't block)
#    "LSInstallType: StoreDownload" → FairPlay-encrypted binary, marked as App Store placeholder
#    "had invalid signature" → re-sign
#    "Bootstrapping failed" → passed SBMainWorkspace but launchd failed (see runningboardd)
```

**Common causes and fix**:

| Log marker | Cause | Fix |
|---|---|---|
| `LSInstallType: StoreDownload` | FairPlay encrypted, not decrypted | STOP — decrypt first |
| `Executable for <bundle> ... had no entitlements` | Ad-hoc signature without entitlements | OK, doesn't block (informational warning) |
| `app not found` | Install incomplete or app uninstalled | `xcrun simctl install booted <path>` |
| `prohibited from launch` | Profile restrictions or MDM | Not applicable to standard emulation |
| `Provisioning profile expired` | App signed with expired cert | Re-sign ad-hoc and re-install |

### launchd spawn failure (POSIX 153 / E2BIG)

dyld loaded everything OK, but when `launchd` tries to execute the binary, it fails. Typically means the Mach-O is **structurally corrupt**.

**Diagnosis**:

```bash
# Is the Mach-O header intact?
otool -h "$APP/Binary" 2>&1 | rg "magic cputype"
# Must return magic=0xfeedfacf, cputype=arm64

# How many load commands and do they sum sizeofcmds?
otool -l "$APP/Binary" 2>&1 | rg "load command" | wc -l
# Compare with original backup
```

**Typical cause**: using **two tools that patch the binary simultaneously** (simforge + vtool, or multiple vtool invocations without re-signing between them) can leave `LC_CODE_SIGNATURE` pointing to incorrect offsets. **Fix**: re-extract IPA from the original and apply patches with **one tool at a time**, re-signing between each.

### "incompatible platforms" (deceptive!)

Symptom: dyld reports `incompatible platforms: iOS-simulator - iOS` on a binary that clearly says `platform 7` in its `LC_BUILD_VERSION`.

**Real cause**: **Swift ABI version mismatch**. The framework in question requires `libswift*.dylib` with `current version X.Y.Z` (e.g., 5.9.0), but the one available in the current SimRuntime has a different version.

**Verification workflow**:

```bash
# 1. What version does the framework request?
otool -L "$APP/Frameworks/Suspect.framework/Suspect" | rg "libswift"
# Ex: @rpath/libswiftCore.dylib (compatibility version 1.0.0, current version 5.9.0)

# 2. What version does the SimRuntime provide?
SWIFT_RT="/Library/Developer/CoreSimulator/Volumes/iOS_<VER>/.../RuntimeRoot/usr/lib/swift"
otool -L "$SWIFT_RT/libswiftCore.dylib" | head -1
# If has current version 0.0.0 → it's a shared cache placeholder, NOT a real file

# 3. What version does your Xcode provide?
otool -L "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib" | head -1
# If app requests 5.9 and your Xcode has 1001+ → ABI mismatch
```

**Fix**: see `simforge-compatibility.md` § "Swift ABI version mismatch".

---

### Unity Metal heap assertion (`MTLStorageModePrivate is required for heaps`)

**Symptom**: A Unity (IL2CPP) game installs/signs fine, launches, reaches Metal init, then
`SIGABRT`. Backtrace:

```
abort → __assert_rtn → Metal MTLReportFailure
MTLSimDriver   -[MTLSimDevice newHeapWithDescriptor:]
UnityFramework MetalHeap::CreateHeap(MTLHeapDescriptor*)
UnityFramework MetalHeap::CreateBuffer(...MetalScratchBufferArea...)
```

**Capture the exact assertion** (the `.ips` may not show it; the console does):

```bash
xcrun simctl launch --console-pty --terminate-running-process "<UDID>" "<bundle-id>"
# -[MTLSimDevice newHeapWithDescriptor:]:1211: failed assertion
#   `MTLStorageModePrivate is required for heaps'
```

**Cause**: the simulator's Metal driver requires `MTLHeap`s to use `MTLStorageModePrivate`,
but Unity creates Shared-storage scratch heaps (valid on real devices). GPU-driver layer —
not a signing or load-command problem. Reproduces on every simulator runtime.

**Fix**: inject an interposer dylib that makes `newHeapWithDescriptor:` return `nil`, forcing
Unity's non-heap allocation path. One command:

```bash
scripts/unity_sim_metalfix.sh "<UDID>" "<bundle-id>"
```

Full methodology, source, and the discarded "force Private" approach:
`references/unity-ios-security.md` → "Running Unity IL2CPP apps in the iOS Simulator"
(asset: `assets/dylibs/metalheapfix.m`).

---

## Iteration pattern: framework by framework

In apps with many frameworks, it's **common** for launch to advance one framework per iteration:

```
Launch → crash on Framework_A → fix → relaunch
       → crash on Framework_B → fix → relaunch
       → ... → app runs ✓
```

This is because dyld loads frameworks **in topological dependency order** and only fails on the first one it can't resolve. Each fix reveals the next link.

**That's why it's important**:
- Don't sign everything at once without verifying — a fix may reveal another deeper problem.
- Re-launch after EACH change (don't accumulate changes hoping "everything will be fine").
- Keep a log of which framework fails and why — the pattern emerges after 2-3 iterations.

---

## Additional debugging: live log streaming

```bash
# Live log stream while the app runs
xcrun simctl spawn booted log stream \
  --predicate 'process == "YourApp" OR (process == "SpringBoard" AND eventMessage CONTAINS "YourApp")' \
  --level debug

# Filter only errors/warnings
xcrun simctl spawn booted log stream \
  --predicate 'process == "YourApp"' --level=error
```

For a smoke test (to see if the app at least starts its `applicationDidFinishLaunching`):

```bash
# Launch with --console (stream process output)
xcrun simctl launch --console booted "<bundleid>"
# Ctrl+C to exit
```

If the app is stuck at a point and doesn't crash, `--console` shows the `NSLog`/`print` that tells you how far it got.

> **Capturing exact native assertions**: `--console-pty` streams the child's stderr, which is
> where native frameworks print the *exact* assertion text (file:line + reason) right before
> `abort()`. This text is often missing/truncated from the `.ips`. Use it to turn a vague
> `EXC_CRASH SIGABRT` into an actionable message (e.g. the Unity Metal heap assertion above).
> Caveat: `--console`/`--console-pty` keep the app attached — when the console closes the app
> is terminated, so once you have the message, relaunch **detached** (plain `simctl launch`)
> to keep it running.

---

## When to escalate the diagnosis

If after applying the canonical flow in `simforge-emulation-flow.md`:

- The crash persists with the same namespace/indicator
- And `simforge-compatibility.md` has no workaround
- And there's no physical device for testing

→ **Escalate to jailbroken physical device**. The simulator is not universally capable of running all apps — some require FairPlay daemon, real hardware drivers (camera, Secure Enclave, NFC), or the production entitlements system. Escalating is the correct decision, not a failure.
