/**
 * iOS RASP Bypass - Full Hook Script
 * Hooks termination functions and simulator detection syscalls
 */

console.log("=== iOS RASP Bypass Script Loading ===");

// Hook exit functions
try {
    Interceptor.replace(Module.findGlobalExportByName("exit"), new NativeCallback(function(status) {
        console.log("[BYPASS] exit(" + status + ") BLOCKED");
    }, "void", ["int"]));
    console.log("[✓] exit() hooked");
} catch(e) { console.log("[✗] exit() hook failed:", e.message); }

try {
    Interceptor.replace(Module.findGlobalExportByName("_exit"), new NativeCallback(function(status) {
        console.log("[BYPASS] _exit(" + status + ") BLOCKED");
    }, "void", ["int"]));
    console.log("[✓] _exit() hooked");
} catch(e) { console.log("[✗] _exit() hook failed:", e.message); }

try {
    Interceptor.replace(Module.findGlobalExportByName("abort"), new NativeCallback(function() {
        console.log("[BYPASS] abort() BLOCKED");
    }, "void", []));
    console.log("[✓] abort() hooked");
} catch(e) { console.log("[✗] abort() hook failed:", e.message); }

// Hook pthread_kill
try {
    Interceptor.replace(Module.findGlobalExportByName("pthread_kill"), new NativeCallback(function(thread, sig) {
        console.log("[BYPASS] pthread_kill(" + thread + ", " + sig + ") BLOCKED");
        return 0;
    }, "int", ["int", "int"]));
    console.log("[✓] pthread_kill() hooked");
} catch(e) { console.log("[✗] pthread_kill() hook failed:", e.message); }

// Hook kill
try {
    Interceptor.replace(Module.findGlobalExportByName("kill"), new NativeCallback(function(pid, sig) {
        console.log("[BYPASS] kill(" + pid + ", " + sig + ") BLOCKED");
        return 0;
    }, "int", ["int", "int"]));
    console.log("[✓] kill() hooked");
} catch(e) { console.log("[✗] kill() hook failed:", e.message); }

// Hook C++ exceptions
try {
    var cxa_throw = Module.findGlobalExportByName("__cxa_throw");
    if (cxa_throw) {
        Interceptor.replace(cxa_throw, new NativeCallback(function(exc, type_info, dest) {
            console.log("[BYPASS] __cxa_throw BLOCKED");
        }, "void", ["pointer", "pointer", "pointer"]));
        console.log("[✓] __cxa_throw hooked");
    }
} catch(e) { console.log("[✗] __cxa_throw hook failed:", e.message); }

try {
    var cxa_allocate = Module.findGlobalExportByName("__cxa_allocate_exception");
    if (cxa_allocate) {
        Interceptor.replace(cxa_allocate, new NativeCallback(function(size) {
            console.log("[BYPASS] __cxa_allocate_exception BLOCKED");
            return ptr(0);
        }, "pointer", ["size_t"]));
        console.log("[✓] __cxa_allocate_exception hooked");
    }
} catch(e) { console.log("[✗] __cxa_allocate_exception hook failed:", e.message); }

// Hook sysctl for simulator detection
try {
    var sysctl = Module.findGlobalExportByName("sysctl");
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onEnter: function(args) {
                this.namePtr = args[0];
                this.namelen = args[1];
                this.oldp = args[2];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.oldp.isNull() === false) {
                    var name = this.namePtr.readU32();
                    // CTL_HW = 1, HW_MACHINE = 1
                    if (name === 1 || name === 0x100000001) {
                        var result = this.oldp.readUtf8String();
                        if (result && (result.indexOf("i386") !== -1 ||
                                       result.indexOf("x86_64") !== -1 ||
                                       result.indexOf("arm64") !== -1 && result.indexOf("sim") !== -1)) {
                            console.log("[BYPASS] sysctl HW_MACHINE: " + result + " -> BLOCKED");
                            // Could replace with device identifier
                            this.oldp.writeUtf8String("iPhone14, 2");
                        }
                    }
                }
            }
        });
        console.log("[✓] sysctl() hooked");
    }
} catch(e) { console.log("[✗] sysctl() hook failed:", e.message); }

console.log("=== iOS RASP Bypass Script Loaded ===");
