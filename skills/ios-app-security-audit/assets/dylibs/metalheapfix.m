// metalheapfix.m — Run Unity (Metal) games in the iOS Simulator on Apple Silicon.
//
// PROBLEM
//   Unity IL2CPP games converted for the simulator (e.g. via SimForge) install and sign
//   fine but abort during graphics init with:
//     -[MTLSimDevice newHeapWithDescriptor:]:1211: failed assertion
//       `MTLStorageModePrivate is required for heaps'
//   The simulator's Metal driver (MTLSimDriver) requires MTLHeaps to use
//   MTLStorageModePrivate, but Unity creates Shared-storage scratch heaps (valid on real
//   unified-memory devices). The simulator rejects them and aborts.
//
// FIX
//   Make -[MTLSimDevice newHeapWithDescriptor:] return nil. Unity's MetalHeap::CreateHeap
//   then falls back to direct (non-heap) buffer allocation, which the simulator supports
//   with Shared storage. The app runs and renders.
//
//   We cannot swizzle MTLSimDevice in this dylib's constructor — that class isn't
//   registered until Metal initializes. Instead we DYLD_INTERPOSE the C function
//   MTLCreateSystemDefaultDevice(): when the app asks for the device, MTLSimDevice exists,
//   so we install the heap swizzle there (guarded by dispatch_once).
//
// WHY NOT FORCE storageMode = Private?
//   Coercing the descriptor to Private clears the heap assertion but just moves the crash to
//   -[MTLSimHeap newBufferWithLength:options:offset:useOffset:] (XPC error), because Unity's
//   CPU-written scratch buffers can't live in a GPU-private heap. Returning nil is correct.
//
// BUILD (simulator SDK, arm64):
//   SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
//   clang -dynamiclib -fobjc-arc -Wno-incompatible-function-pointer-types \
//     -isysroot "$SDK" -target arm64-apple-ios15.0-simulator \
//     -framework Foundation -framework Metal -o metalheapfix.dylib metalheapfix.m
//   codesign -f -s - metalheapfix.dylib
//
// INJECT (launch DETACHED — not with --console-pty, which kills the app on disconnect):
//   SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/abs/path/metalheapfix.dylib \
//     xcrun simctl launch <UDID> <bundle-id>
//
// Generic: works for any Unity Metal game on the simulator. No app-specific identifiers.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define DYLD_INTERPOSE(_repl,_orig) \
  __attribute__((used)) static struct{ const void* r; const void* o; } _interpose_##_orig \
  __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_repl, (const void*)(unsigned long)&_orig };

static IMP gOrigNewHeap = NULL;

static id swizzled_newHeapWithDescriptor(id self, SEL _cmd, id descriptor) {
    // Returning nil forces Unity's non-heap allocation path (Shared buffers the sim supports).
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
    NSLog(@"[metalheapfix] MTLCreateSystemDefaultDevice intercepted (device=%@)", dev);
    installHeapSwizzle(dev);
    return dev;
}
DYLD_INTERPOSE(my_MTLCreateSystemDefaultDevice, MTLCreateSystemDefaultDevice)

__attribute__((constructor))
static void boot(void) { NSLog(@"[metalheapfix] loaded, waiting for Metal device creation"); }
