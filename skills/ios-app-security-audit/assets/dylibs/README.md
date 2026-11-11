# Native interposer dylibs (`assets/dylibs/`)

Compiled-at-use Objective-C/C interposer libraries injected into a target via
`DYLD_INSERT_LIBRARIES` (on the simulator: `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES`).

Unlike `assets/frida-scripts/` (JavaScript loaded by Frida at runtime), these are **native
`.m` sources** compiled against the iOS Simulator SDK and ad-hoc signed. Only the `.m`
source is kept here — the `.dylib` is rebuilt per SDK, never committed.

| Source | Purpose | Maps to |
|--------|---------|---------|
| `metalheapfix.m` | Makes Unity (Metal) games run in the iOS Simulator by forcing Unity's non-heap allocation path (the simulator rejects Shared-storage `MTLHeap`s). | Phase 4 — `references/unity-ios-security.md`, `references/simforge-crash-triage.md` |

## metalheapfix.m

**When to use:** A Unity IL2CPP game converted for the simulator aborts at graphics init with
`-[MTLSimDevice newHeapWithDescriptor:]: failed assertion 'MTLStorageModePrivate is required
for heaps'`.

**Build, sign, inject** (or just run `scripts/unity_sim_metalfix.sh <UDID> <bundle-id>`):

```bash
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -dynamiclib -fobjc-arc -Wno-incompatible-function-pointer-types \
  -isysroot "$SDK" -target arm64-apple-ios15.0-simulator \
  -framework Foundation -framework Metal \
  -o metalheapfix.dylib assets/dylibs/metalheapfix.m
codesign -f -s - metalheapfix.dylib

# Launch DETACHED — never with --console-pty (that kills the app when the console closes)
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$PWD/metalheapfix.dylib" \
  xcrun simctl launch "<UDID>" "<bundle-id>"
```

Full methodology (root cause, discarded approaches, IL2CPP dumping): see
`references/unity-ios-security.md` → "Running Unity IL2CPP apps in the iOS Simulator".
