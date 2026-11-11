# Frida + iOS Simulator: Canonical Workflow Reference

> **Single source of truth** for all Frida work against iOS apps running in the Xcode iOS Simulator (Apple Silicon, Frida 17+). Every other file in this skill references this document — not the other way around.

---

## When to Use This Document

- You are running Frida 17+ against an iOS app in the Xcode Simulator on Apple Silicon.
- You need to hook ObjC methods, bypass protections, or extract runtime data from a simulator process.
- You are getting `unable to intercept function at 0x...` or `unable to find process with name` errors.
- You are converting apps to simulator with SimForge and need Frida to attach to them.

If you are working on a **physical device** (jailbroken, USB), use `references/frida-ios-guide.md` instead — the patterns there use `-U` and the method-handle hook form, which do not apply here.

---

## Critical Rules

These are the five rules that differentiate simulator Frida from device Frida. Violating any of them produces silent failures or confusing errors.

### Rule 1: Always use `.implementation` to hook ObjC methods

```javascript
// CORRECT — works on Frida 17 / arm64e simulator
const m = ObjC.classes.SomeClass["+ someClassMethod"];
Interceptor.attach(m.implementation, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});
```

**Why**: `m.implementation` is a `NativePointer` (raw function address). Frida's Interceptor hooks raw C function pointers reliably on arm64e simulator. Passing the `ObjC.Method` handle directly (without `.implementation`) triggers a Frida 17 arm64e-simulator regression.

```javascript
// BROKEN — "unable to intercept function at 0x...; please file a bug"
Interceptor.attach(ObjC.classes.SomeClass["- someMethod"], { onLeave: ... });

// BROKEN — no error but hook never fires
ObjC.classes.SomeClass["- someMethod"].implementation = function() { return 0; };
```

The `.implementation` setter expects a `NativeFunction` or `NativeCallback`, not a raw JS function. Even when it doesn't error, the hook is non-functional.

### Rule 2: Attach by PID, not by bundle ID

```bash
# CORRECT
PID=$(xcrun simctl spawn $UDID launchctl list | rg "<bundle.id>" | awk '{print $1}')
frida -D $UDID -p $PID -l script.js

# UNRELIABLE — bundle ID != process name on simulator
frida -D $UDID -N "<bundle.id>"
```

The simulator process is named after the **binary**, not the bundle ID. A binary named "MyApp" with bundle ID "com.example.myapp" will not be found with `-N com.example.myapp`.

### Rule 3: Never use `-U` for simulator work

```bash
# CORRECT — -D accepts a simulator UDID
frida -D 7A792F36-0516-49B4-8799-3B48DC2D2B82 -p $PID -l script.js

// WRONG — -U is USB-only, simulator is local
frida -U -p $PID -l script.js
```

`-U` targets USB-connected devices. The iOS Simulator is a local process. Use `-D <UDID>` where UDID comes from `xcrun simctl list devices booted`.

### Rule 4: Do not use `-q --exit-on-error` with async work

The `frida` CLI with `-q` is designed for load-eval-exit workflows. Pending `setTimeout` / `setInterval` callbacks are **not guaranteed to run** before the process exits.

For non-trivial work (polling, multi-step triggers, late-loaded class hooks), either:
- Drop `-q` and let the REPL stay open, or
- Use the Python API for full lifecycle control.

### Rule 5: Match Swift ABI with the correct SimRuntime

If the app uses Swift, the SimRuntime's Swift version must be compatible. A Swift 5.9 app on an iOS 26 simulator will crash immediately. Use the runtime that SimForge preflight recommends — it is a requirement, not a suggestion.

### Rule 6: The simulator must be visible by default

Unless the user explicitly indicates otherwise (`--headless`, invisible mode, etc.), **always** launch the simulator in visible mode.

This applies to both `xcrun simctl boot` and `simforge_install_launch.sh`. Headless mode should only be used when the user clearly requests it.

---

## Hook Pattern Compatibility Matrix

| Pattern | Simulator (Frida 17) | Physical Device |
|---|---|---|
| `Interceptor.attach(class[method].implementation, ...)` | Works | Works |
| `Interceptor.attach(NativePointer from Module.findGlobalExportByName, ...)` | Works | Works |
| `Interceptor.replace(ptr, new NativeCallback(...))` for C functions | Works (most cases) | Works |
| `Interceptor.attach(class[method], ...)` (method handle) | **Fails** | Works |
| `class[method].implementation = jsFunction` | Silent failure (no hook) | Works |
| `Interceptor.attach(+alloc)` on UIViewController etc. | **Fails** | Variable |

**Decision rule**: On the simulator, use `.implementation` for ObjC methods and `Interceptor.replace` + `NativeCallback` for C functions. Never pass a method handle directly to `Interceptor.attach`.

---

## Frida 17 CLI Syntax Changes

Older tutorials reference flags that no longer exist:

| Old (Frida <= 12) | New (Frida 17) |
|---|---|
| `--no-pause` | Removed. Default behavior is resume. |
| `--pause` | Opt-in with `--pause`. |
| `-U -N <bundle>` on simulator | `-D <UDID> -p <PID>` |
| `-q --exit-on-error` for async scripts | Drops pending timers. Drop `-q` or use Python API. |

---

## Attaching to a Simulator Process

### Step-by-step

```bash
# 1. Identify the booted simulator
xcrun simctl list devices booted
# -> iPhone 15 (iOS 17.5) (7A792F36-0516-49B4-8799-3B48DC2D2B82) (Booted)

# 2. Launch the app
xcrun simctl launch $UDID com.example.app
sleep 2

# 3. Get the PID
PID=$(xcrun simctl spawn $UDID launchctl list | rg "com.example.app" | awk '{print $1}')

# 4. Attach
frida -D $UDID -p $PID -l script.js
```

### Verifying attachment

```
     ____
    / _  |   Frida 17.11.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object    -> Memory object inspector
                  device    -> Device manager
                  exit      -> Exit Frida
                  .

[*] [hook] Found 9 jailbreak detection methods across 3 classes
[*] [hook] All methods hooked successfully
[Local::PID::12345]->
```

---

## Auto-Discovery of Methods

### Pattern: scan all ObjC classes for target methods

This pattern finds every relevant method without hardcoding class names:

```javascript
var targets = ["isJailbroken", "isJailBroken", "isDeviceJailbroken"];
var hookedCount = 0;

for (var className in ObjC.classes) {
    try {
        var clazz = ObjC.classes[className];
        targets.forEach(function(methodName) {
            var classMethod = "+ " + methodName;
            var instanceMethod = "- " + methodName;

            if (clazz[classMethod]) {
                Interceptor.attach(clazz[classMethod].implementation, {
                    onLeave: function(retval) { retval.replace(ptr(0)); }
                });
                hookedCount++;
                console.log("[+] Hooked " + className + " " + classMethod);
            }
            if (clazz[instanceMethod]) {
                Interceptor.attach(clazz[instanceMethod].implementation, {
                    onLeave: function(retval) { retval.replace(ptr(0)); }
                });
                hookedCount++;
                console.log("[+] Hooked " + className + " " + instanceMethod);
            }
        });
    } catch (e) { /* skip classes that throw on access */ }
}
console.log("[*] Total methods hooked: " + hookedCount);
```

### Pattern: keyword scan with `$ownMethods`

For finding methods by keyword rather than exact name:

```javascript
var keyword = "jailbreak";
for (var className in ObjC.classes) {
    try {
        var methods = ObjC.classes[className].$ownMethods;
        methods.forEach(function(m) {
            if (m.toLowerCase().indexOf(keyword) !== -1) {
                Interceptor.attach(ObjC.classes[className][m].implementation, {
                    onLeave: function(retval) {
                        console.log("[*] " + className + " " + m + " -> " + retval);
                        retval.replace(ptr(0));
                    }
                });
            }
        });
    } catch (e) {}
}
```

### Static analysis companion

Run these before Frida to know what to look for:

```bash
# Strings revealing detection paths/URLs
strings "<app-binary>" | rg -i "jailbreak|cydia|sileo|mobilesubstrate|apt|sshd"

# Swift/ObjC symbol names revealing detection methods
nm -gU "<app-binary>" | rg -i "jailbreak|isJailBroken|detection"
```

---

## Polling for Late-Loaded Classes

Classes that only load after the user navigates to a specific screen won't be available at attach time. Use polling to wait for them:

```javascript
var targetClassName = "SomeViewController";
var poll = setInterval(function() {
    if (ObjC.classes[targetClassName]) {
        clearInterval(poll);
        console.log("[*] " + targetClassName + " is now loaded");

        // Hook methods on the class
        var methods = ObjC.classes[targetClassName].$ownMethods;
        methods.forEach(function(m) {
            if (m.indexOf("someKeyword") !== -1) {
                Interceptor.attach(ObjC.classes[targetClassName][m].implementation, {
                    onLeave: function(retval) { console.log(m + " returned " + retval); }
                });
            }
        });
    }
}, 1000);

// Safety timeout
setTimeout(function() { clearInterval(poll); }, 30000);
```

---

## Known Limitations in Simulator Context

### Syscall Hooks

Some C-level syscalls cannot be intercepted in the iOS Simulator context due to simulator isolation and the way simulator processes are structured. These hooks will fail with "not a function" or similar errors when using `Module.findGlobalExportByName()`:

| Syscall | Status | Error Pattern | Alternative |
|---------|--------|---------------|-------------|
| `stat()` | ❌ Fails | `stat is not a function` | Hook ObjC `fileExistsAtPath:` instead |
| `fopen()` | ❌ Fails | `fopen is not a function` | Hook ObjC file methods instead |
| `fork()` | ❌ Fails | `fork is not a function` | Not applicable in simulator context |
| `posix_spawn()` | ❌ Fails | `posix_spawn is not a function` | Not applicable in simulator context |
| `dlopen()` | ⚠️ Unreliable | May fail silently | Not typically needed in simulator |

**Impact**: Apps that use C-level file/syscall checks for jailbreak detection may bypass simulator-based hooks if they rely solely on these C functions. For complete coverage, test on physical jailbroken device.

**What works reliably**: ObjC method hooks via `.implementation` pattern work consistently:
- `NSFileManager.fileExistsAtPath:`
- `NSFileManager.isReadableFileAtPath:`
- `UIApplication.canOpenURL:`

**Decision rule**: If your script depends on C-level syscall interception for critical functionality (e.g., comprehensive jailbreak bypass), consider simulator testing as partial coverage and escalate to physical device testing.

---

## Navigation via RootViewController and ObjC.choose

To trigger app screens programmatically from Frida:

```javascript
// 1. Navigate to a screen via the root view controller
ObjC.choose(ObjC.classes.RootViewController, {
    onMatch: function(root) {
        var showMethod = root["- showSomeFeature"];
        if (showMethod) {
            showMethod.call(root);
            console.log("[*] Navigated to feature screen");
        }
    },
    onComplete: function() {}
});

// 2. Wait for the target controller to load, then find its instance
setTimeout(function() {
    ObjC.choose(ObjC.classes.SomeViewController, {
        onMatch: function(inst) {
            // 3. Trigger action methods
            var actionMethods = inst.$ownMethods.filter(function(m) {
                return m.indexOf("Tapped:") !== -1 || m.indexOf("test") !== -1;
            });
            actionMethods.forEach(function(m, i) {
                setTimeout(function() {
                    try {
                        inst[m].call(inst);
                        console.log("[*] Triggered " + m);
                    } catch (e) {
                        console.log("[!] Error triggering " + m + ": " + e);
                    }
                }, 1500 * (i + 1));
            });
        },
        onComplete: function() {}
    });
}, 2500);
```

**Key insight**: `ObjC.choose` finds live instances on the heap. Use it when you need to call instance methods, not just class methods.

---

## Swift ABI Matching with SimForge

When converting an iOS app to run in the simulator with SimForge, the runtime Swift ABI version must match.

```bash
# Run preflight to get the recommendation
python3 scripts/simforge_preflight.py "<App.app>"

# Output will indicate:
#   [OK]    swift_abi    Swift ABI matches iOS 17 SimRuntime (libswiftCore 5.9.0).
#                        Boot that runtime explicitly.

# List available runtimes
xcrun simctl list runtimes

# Boot the recommended one
xcrun simctl shutdown "<other-UDID>"
xcrun simctl boot "<recommended-runtime-UDID>"
```

If you boot the wrong runtime (e.g., iOS 26 with a Swift 5.9 app), the app crashes on launch with an `LC_BUILD_VERSION` mismatch or sigtrap.

**Reference**: Full compatibility matrix in `references/simforge-compatibility.md` section 2 and section 6.

---

## Process Lifecycle Management

### CLI mode (simple, synchronous work)

```bash
# Drop -q. Let the REPL stay open to keep timers alive.
frida -D $UDID -p $PID -l script.js --exit-on-error
```

The process keeps running while there are pending timers. Use `exit` or Ctrl+D when done.

### Python API (complex, async work)

For multi-step orchestration with timing dependencies:

```python
import frida, time

dev = frida.get_device("<UDID>")
sess = dev.attach("<PID>")
script = sess.create_script(open("script.js").read())

script.on("message", lambda msg, data: print(msg))
script.load()

# Call RPC exports defined in the script
script.exports_sync.navigate()
time.sleep(2)
script.exports_sync.auto_trigger()
time.sleep(15)

sess.detach()
```

Use the Python API when:
- The script needs multiple async RPC calls with timing dependencies.
- You need structured message payloads back to the host.
- The CLI keeps timing out or exiting prematurely.
- You need to spawn or manipulate child processes.

---

## Troubleshooting Matrix

| Symptom | Cause | Fix |
|---|---|---|
| `unable to intercept function at 0x...; please file a bug` | Frida 17 arm64e sim bug — passing method handle instead of `.implementation` | Use `Interceptor.attach(class[method].implementation, ...)` |
| `unable to find process with name '<bundle.id>'` | Bundle ID is not the process name on simulator | Use `-p <PID>` via `xcrun simctl spawn <UDID> launchctl list` |
| `module not found at "/usr/lib/libSystem.B.dylib"` | Frida 16 on macOS 26 where libSystem is in dyld cache | Upgrade to Frida 17+ |
| Frida process exits before async hooks fire | `-q --exit-on-error` kills pending timers | Drop `-q` or use Python API |
| `--no-pause` unknown argument | Frida 17 removed the flag | Remove it (default is now resume) |
| `Device '<UDID>' not found` with `-D` | UDID doesn't match a booted device | Run `xcrun simctl list devices booted` |
| App crashes immediately on launch (SimForge) | Swift ABI mismatch | Boot the SimRuntime SimForge preflight recommends |
| Hook fires but `retval.replace()` has no visible effect | Method returns void (e.g., IBAction `Tapped:` handler) — return value is undefined | The hook log is the proof of bypass; don't rely on `replace` for void methods |
| `frida-ps -D <UDID>` returns empty | UDID format or device not booted | Verify with `xcrun simctl list devices booted`; try the full UDID string |
| `Objective-C runtime NOT available` | Target is not an ObjC app or process died | Verify process is running: `frida-ps -D <UDID>` |
| Hook works but detection still triggers | Only hooked some detection vectors; production apps use multiple | Hook file existence, URL schemes, write tests, and direct methods — see `references/frida-dynamic-analysis-ios.md` section 6 |
| `Library not loaded: @rpath/libswiftCore.dylib` | Swift ABI mismatch between app and SimRuntime | See `references/simforge-compatibility.md` section 2 |
| `code signature invalid` on framework | `codesign --deep` missed the binary inside the framework | Sign the internal binary explicitly: `codesign -f -s - Framework.framework/FrameworkBinary` |

---

## Verified Recipe

### Bypass jailbreak detection on iOS Simulator

```bash
# Step 1: Get the booted simulator UDID
UDID=$(xcrun simctl list devices booted | rg -o "[A-F0-9-]{36}" | head -1)

# Step 2: Launch the target app
xcrun simctl launch $UDID com.example.app
sleep 2

# Step 3: Get the PID
PID=$(xcrun simctl spawn $UDID launchctl list | rg "com.example.app" | awk '{print $1}')

# Step 4: Attach with the canonical bypass script
frida -D $UDID -p $PID -l assets/frida-scripts/jailbreak-bypass-ios.js --exit-on-error
```

The canonical `jailbreak-bypass-ios.js` will:
1. Scan every ObjC class for `isJailbroken` / `isJailBroken` / `isDeviceJailbroken` methods.
2. Hook all of them with `.implementation` and force return FALSE.
3. Scan `$ownMethods` for any method containing "jailbreak" (case-insensitive).
4. Print every discovered method and hook confirmation.

### Dump app-specific UserDefaults

```bash
PID=$(xcrun simctl spawn $UDID launchctl list | rg "com.example.app" | awk '{print $1}')
frida -D $UDID -p $PID -l assets/frida-scripts/nsuserdefaults-dumper.js
```

### Explore classes at runtime

```bash
PID=$(xcrun simctl spawn $UDID launchctl list | rg "com.example.app" | awk '{print $1}')
frida -D $UDID -p $PID -l assets/frida-scripts/class-explorer-ios.js
```

### Full Python orchestration template

```python
import frida, time, sys

UDID = sys.argv[1]
BUNDLE = sys.argv[2]

dev = frida.get_device(UDID)

# Attach by PID
import subprocess
result = subprocess.run(
    ["xcrun", "simctl", "spawn", UDID, "launchctl", "list"],
    capture_output=True, text=True
)
for line in result.stdout.splitlines():
    if BUNDLE in line:
        PID = int(line.split()[0])
        break

sess = dev.attach(PID)
script = sess.create_script(open("script.js").read())

output = []
script.on("message", lambda msg, data: output.append(msg))
script.load()

time.sleep(10)
for msg in output:
    print(msg)

sess.detach()
```

---

## Reusable Jailbreak Bypass Pattern

Complete pattern for bypassing jailbreak detection in any iOS app (works on both simulator and device). This covers the common detection vectors: ObjC file existence checks, URL scheme checks, and direct detection methods.

```javascript
/**
 * Universal Jailbreak Bypass - Works on Simulator & Device
 * Compatible with Frida 17+ (.implementation pattern)
 * Copy to your script or use as template
 */

(function() {
    'use strict';

    // Wait for ObjC runtime
    if (typeof ObjC === 'undefined' || !ObjC.available) {
        console.log("[-] Objective-C runtime NOT available");
        return;
    }

    console.log('\n[*] Jailbreak Bypass - Loading...');

    // ────────────────────────────────────────────
    // Jailbreak indicators to block
    // ────────────────────────────────────────────
    var JB_PATHS = [
        '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/FakeCarrier.app',
        '/Applications/Icy.app', '/Applications/IntelliScreen.app', '/Applications/MxTube.app',
        '/Applications/RockApp.app', '/Applications/SBSettings.app', '/Applications/WinterBoard.app',
        '/Library/MobileSubstrate/DynamicLibraries', '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/usr/sbin/sshd', '/usr/bin/sshd', '/usr/libexec/ssh-keysign',
        '/usr/libexec/sftp-server', '/usr/bin/ssh', '/usr/libexec/cydia',
        '/var/tmp/cydia.log', '/etc/apt', '/var/lib/cydia',
        '/var/cache/apt', '/var/lib/apt', '/private/var/lib/apt/',
        '/private/var/lib/cydia/', '/private/var/tmp/cydia.log',
        '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        '/usr/lib/libexcsecarm64.dylib', '/.installed_unc0ver',
        '/.installed_electra', '/var/containers/Bundle/Application',
        '/var/mobile/Library/Cydia'
    ];

    var JB_SCHEMES = ['cydia://', 'sileo://', 'zbra://', 'filza://', 'activator://'];

    function isJailbreakIndicator(path) {
        if (!path) return false;
        var p = path.toString().toLowerCase();
        for (var i = 0; i < JB_PATHS.length; i++) {
            if (p.indexOf(JB_PATHS[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    var hooksApplied = 0;

    // ────────────────────────────────────────────
    // 1. NSFileManager hooks (ObjC file checks)
    // ────────────────────────────────────────────
    try {
        var NSFM = ObjC.classes.NSFileManager;
        if (NSFM) {
            var fileMethods = [
                '- fileExistsAtPath:',
                '- fileExistsAtPath:isDirectory:',
                '- isReadableFileAtPath:',
                '- isWritableFileAtPath:',
                '- createFileAtPath:contents:attributes:'
            ];

            fileMethods.forEach(function(selector) {
                if (NSFM[selector]) {
                    Interceptor.attach(NSFM[selector].implementation, {
                        onEnter: function(args) {
                            var path = ObjC.Object(args[2]).toString();
                            if (isJailbreakIndicator(path)) {
                                this.block = true;
                                console.log('[+] Blocked: ' + selector + ' -> ' + path);
                            }
                        },
                        onLeave: function(retval) {
                            if (this.block) retval.replace(ptr(0));
                        }
                    });
                    hooksApplied++;
                }
            });
        }
    } catch (e) {
        console.log('[!] NSFileManager hooks failed: ' + e.message);
    }

    // ────────────────────────────────────────────
    // 2. UIApplication canOpenURL: (scheme checks)
    // ────────────────────────────────────────────
    try {
        var app = ObjC.classes.UIApplication.sharedApplication();
        if (app && app['- canOpenURL:']) {
            Interceptor.attach(app['- canOpenURL:'].implementation, {
                onEnter: function(args) {
                    var url = ObjC.Object(args[2]).absoluteString().toString();
                    for (var i = 0; i < JB_SCHEMES.length; i++) {
                        if (url.toLowerCase().indexOf(JB_SCHEMES[i]) === 0) {
                            this.block = true;
                            console.log('[+] Blocked: canOpenURL -> ' + url);
                            return;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.block) retval.replace(ptr(0));
                }
            });
            hooksApplied++;
        }
    } catch (e) {
        console.log('[!] UIApplication hooks failed: ' + e.message);
    }

    // ────────────────────────────────────────────
    // 3. Auto-discovery of detection methods
    // ────────────────────────────────────────────
    var targets = [
        '+ isJailbroken', '- isJailbroken',
        '+ isJailBroken', '- isJailBroken',
        '+ isDeviceJailbroken', '- isDeviceJailbroken',
        '+ jailbreakTest', '- jailbreakTest',
        '+ checkJailbreak', '- checkJailbreak'
    ];

    var methodHooks = 0;
    for (var className in ObjC.classes) {
        try {
            var clazz = ObjC.classes[className];
            targets.forEach(function(selector) {
                if (clazz[selector]) {
                    Interceptor.attach(clazz[selector].implementation, {
                        onLeave: function(retval) {
                            retval.replace(ptr(0)); // Return NO/false
                        }
                    });
                    methodHooks++;
                }
            });
        } catch (e) {
            // Class access failed - skip
        }
    }

    console.log('[*] Jailbreak bypass active:');
    console.log('    - ObjC file methods: ' + hooksApplied + ' hooks');
    console.log('    - Detection methods: ' + methodHooks + ' hooks');
    console.log('    - Total: ' + (hooksApplied + methodHooks) + ' hooks\n');

})();
```

**Usage**: Copy this pattern into any Frida script for iOS jailbreak bypass. It uses the `.implementation` pattern required for Frida 17+ on simulator.

**Note**: This pattern covers ObjC-level checks. C-level syscall hooks (`stat`, `fopen`, etc.) are not included because they fail on simulator (see "Known Limitations" section above).

---

## See Also

- `assets/frida-scripts/jailbreak-bypass-ios.js` — canonical bypass script (uses `.implementation` pattern)
- `assets/frida-scripts/jailbreak-detection-bypass.js` — broader coverage but uses the broken pattern on Frida 17 simulator; do NOT use on simulator
- `references/frida-ios-guide.md` — general Frida usage on iOS (physical device syntax)
- `references/frida-dynamic-analysis-ios.md` — verified dynamic analysis techniques
- `references/frida-scripts-index.md` — index of all Frida scripts
- `references/simforge-emulation-flow.md` — converting apps to run in the simulator
- `references/simforge-compatibility.md` — Swift ABI, FairPlay, and hardware compatibility matrix
- `references/simulator-mitm-setup.md` — MITM proxy setup (proxy host is `127.0.0.1`, not the Mac's LAN IP)
