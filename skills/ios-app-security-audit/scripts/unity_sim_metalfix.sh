#!/usr/bin/env bash
# unity_sim_metalfix.sh — Run a Unity (Metal) game in the iOS Simulator on Apple Silicon.
#
# Unity IL2CPP games converted for the simulator (e.g. via SimForge) abort at graphics init:
#   -[MTLSimDevice newHeapWithDescriptor:]: failed assertion
#     'MTLStorageModePrivate is required for heaps'
# This script compiles + ad-hoc signs the metalheapfix interposer dylib and launches the
# target with it injected, so Unity falls back to its non-heap allocation path and renders.
#
# Generic: the target is passed as arguments — no app-specific identifiers are hardcoded.
#
# Usage:
#   scripts/unity_sim_metalfix.sh <SIMULATOR_UDID> <BUNDLE_ID>
#   scripts/unity_sim_metalfix.sh booted <BUNDLE_ID>
#
# Prereqs: app already installed on the (booted) simulator; Xcode CLT; Apple Silicon.
set -euo pipefail

UDID="${1:-}"
BUNDLE_ID="${2:-}"
if [[ -z "$UDID" || -z "$BUNDLE_ID" ]]; then
  echo "Usage: $0 <SIMULATOR_UDID|booted> <BUNDLE_ID>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$SKILL_DIR/assets/dylibs/metalheapfix.m"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/metalheapfix.XXXXXX")"
DYLIB="$WORK/metalheapfix.dylib"

# Source of truth is the asset; fall back to an embedded copy so the script is self-contained.
if [[ ! -f "$SRC" ]]; then
  SRC="$WORK/metalheapfix.m"
  cat > "$SRC" <<'OBJC'
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#define DYLD_INTERPOSE(_repl,_orig) \
  __attribute__((used)) static struct{ const void* r; const void* o; } _interpose_##_orig \
  __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_repl, (const void*)(unsigned long)&_orig };
static IMP gOrigNewHeap = NULL;
static id swizzled_newHeapWithDescriptor(id self, SEL _cmd, id descriptor) {
    NSLog(@"[metalheapfix] newHeapWithDescriptor: -> returning nil (force non-heap path)");
    return nil;
}
static void installHeapSwizzle(id device) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class cls = device ? object_getClass(device) : objc_getClass("MTLSimDevice");
        if (!cls) { NSLog(@"[metalheapfix] device class unavailable"); return; }
        SEL sel = @selector(newHeapWithDescriptor:);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) { NSLog(@"[metalheapfix] newHeapWithDescriptor: not found on %s", class_getName(cls)); return; }
        gOrigNewHeap = method_getImplementation(m);
        method_setImplementation(m, (IMP)swizzled_newHeapWithDescriptor);
        NSLog(@"[metalheapfix] installed heap swizzle on %s", class_getName(cls));
    });
}
static id<MTLDevice> (*orig_MTLCreateSystemDefaultDevice)(void) = (id<MTLDevice>(*)(void))MTLCreateSystemDefaultDevice;
static id<MTLDevice> my_MTLCreateSystemDefaultDevice(void) {
    id<MTLDevice> dev = orig_MTLCreateSystemDefaultDevice();
    installHeapSwizzle(dev);
    return dev;
}
DYLD_INTERPOSE(my_MTLCreateSystemDefaultDevice, MTLCreateSystemDefaultDevice)
__attribute__((constructor)) static void boot(void) { NSLog(@"[metalheapfix] loaded"); }
OBJC
fi

echo "[*] Compiling interposer for the simulator SDK..."
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
clang -dynamiclib -fobjc-arc -Wno-incompatible-function-pointer-types \
  -isysroot "$SDK" -target arm64-apple-ios15.0-simulator \
  -framework Foundation -framework Metal \
  -o "$DYLIB" "$SRC"
codesign -f -s - "$DYLIB"
echo "[*] Built + signed: $DYLIB"

echo "[*] Terminating any running instance of $BUNDLE_ID..."
xcrun simctl terminate "$UDID" "$BUNDLE_ID" 2>/dev/null || true

echo "[*] Launching DETACHED with the interposer injected..."
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$DYLIB" \
  xcrun simctl launch "$UDID" "$BUNDLE_ID"

echo
echo "[*] Verify it stayed alive:"
echo "      xcrun simctl spawn $UDID launchctl list | grep '$BUNDLE_ID'"
echo "      xcrun simctl io $UDID screenshot /tmp/verify.png"
echo "[i] dylib kept at: $DYLIB (re-usable until you delete $WORK)"
