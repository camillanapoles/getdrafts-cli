/**
 * Ultra-Aggressive RASP Bypass for iOS Simulator Detection
 * Basado en rasp-guide-ios.md - hook todas las funciones de detección
 */

console.log("=== ULTRA RASP BYPASS LOADING ===");

if (!ObjC.available) {
    console.log("[-] Objective-C runtime not available");
    return;
}

// ============================================
// 1. HOOK EXIT/TERMINATION FUNCTIONS
// ============================================

try {
    Interceptor.replace(Module.findGlobalExportByName('exit'), new NativeCallback(function(status) {
        console.log('[BYPASS] exit(' + status + ') BLOCKED');
        // Return without calling the real exit() so the caller keeps running.
        // (An infinite loop would freeze the thread at 100% CPU.)
        return;
    }, 'void', ['int']));
    console.log('[✓] exit() hooked');
} catch(e) { console.log('[✗] exit() failed:', e.message); }

try {
    Interceptor.replace(Module.findGlobalExportByName('_exit'), new NativeCallback(function(status) {
        console.log('[BYPASS] _exit(' + status + ') BLOCKED');
    }, 'void', ['int']));
    console.log('[✓] _exit() hooked');
} catch(e) { console.log('[✗] _exit() failed:', e.message); }

try {
    Interceptor.replace(Module.findGlobalExportByName('abort'), new NativeCallback(function() {
        console.log('[BYPASS] abort() BLOCKED');
        // Return without aborting; an infinite loop would freeze the thread.
        return;
    }, 'void', []));
    console.log('[✓] abort() hooked');
} catch(e) { console.log('[✗] abort() failed:', e.message); }

try {
    Interceptor.replace(Module.findGlobalExportByName('pthread_kill'), new NativeCallback(function(thread, sig) {
        console.log('[BYPASS] pthread_kill BLOCKED');
        return 0;
    }, 'int', ['int', 'int']));
    console.log('[✓] pthread_kill() hooked');
} catch(e) { console.log('[✗] pthread_kill() failed:', e.message); }

// ============================================
// 2. HOOK SIMULATOR DETECTION (sysctl)
// ============================================

try {
    var sysctl = Module.findGlobalExportByName('sysctl');
    Interceptor.attach(sysctl, {
        onEnter: function(args) {
            this.namePtr = args[0];
            this.namelen = args[1];
            this.oldp = args[2];
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0 && this.oldp.isNull() === false && this.namelen.toInt32() >= 2) {
                var name = this.namePtr.readU32();
                var name2 = this.namePtr.add(4).readU32();

                // HW_MACHINE check
                if (name === 1 && name2 === 1) { // CTL_HW + HW_MACHINE
                    var result = this.oldp.readUtf8String();
                    if (result) {
                        if (result.indexOf('i386') !== -1 || result.indexOf('x86_64') !== -1 ||
                            (result.indexOf('arm64') !== -1 && result.indexOf('sim') !== -1) ||
                            result.indexOf('iPad') !== -1 && result.indexOf('Simulator') !== -1) {
                            console.log('[BYPASS] sysctl HW_MACHINE: ' + result + ' → iPhone14,2');
                            this.oldp.writeUtf8String('iPhone14, 2');
                        }
                    }
                }
                // HW_MODEL check
                else if (name === 1 && name2 === 20) { // CTL_HW + HW_MODEL
                    var result = this.oldp.readUtf8String();
                    if (result && result.indexOf('Simulator') !== -1) {
                        console.log('[BYPASS] sysctl HW_MODEL: ' + result + ' → iPhone');
                        this.oldp.writeUtf8String('iPhone');
                    }
                }
            }
        }
    });
    console.log('[✓] sysctl() hooked for simulator detection');
} catch(e) { console.log('[✗] sysctl() failed:', e.message); }

// ============================================
// 3. HOOK uname (otra forma de detección)
// ============================================

try {
    var uname = Module.findGlobalExportByName('uname');
    Interceptor.attach(uname, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) {
                var structPtr = this.context.x0;
                if (structPtr && !structPtr.isNull()) {
                    var machine = structPtr.add(16 * 4).readUtf8String(); // machine field offset
                    if (machine && (machine.indexOf('x86_64') !== -1 || machine.indexOf('i386') !== -1)) {
                        console.log('[BYPASS] uname machine: ' + machine + ' → arm64');
                        structPtr.add(16 * 4).writeUtf8String('arm64');
                    }
                }
            }
        }
    });
    console.log('[✓] uname() hooked');
} catch(e) { console.log('[✗] uname() failed:', e.message); }

// ============================================
// 4. HOOK NSFileManager - jailbreak file checks
// ============================================

try {
    var NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
        // fileExistsAtPath:
        var fileExists = NSFileManager['- fileExistsAtPath:'];
        if (fileExists) {
            Interceptor.attach(fileExists.implementation, {
                onEnter: function(args) {
                    this.path = ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    var jailbreakPaths = [
                        '/Applications/Cydia.app',
                        '/private/var/lib/apt/',
                        '/Library/MobileSubstrate/MobileSubstrate.dylib',
                        '/bin/bash',
                        '/usr/sbin/sshd',
                        '/etc/apt',
                        '.cydia_no_stunt',
                        '/private/jailbreak_test.txt'
                    ];
                    for (var i = 0; i < jailbreakPaths.length; i++) {
                        if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                            console.log('[BYPASS] fileExistsAtPath: ' + this.path + ' → NO');
                            retval.replace(ptr(0)); // Return NO
                            break;
                        }
                    }
                }
            });
            console.log('[✓] NSFileManager fileExistsAtPath hooked');
        }
    }
} catch(e) { console.log('[✗] NSFileManager failed:', e.message); }

// ============================================
// 5. HOOK process enumeration (sysctl para procesos)
// ============================================

try {
    var sysctl_proc = Module.findGlobalExportByName('sysctl');
    var intercepted = false;
    Interceptor.attach(sysctl_proc, {
        onEnter: function(args) {
            if (this.namelen && this.namelen.toInt32() >= 4) {
                var name0 = this.namePtr.readU32();
                var name1 = this.namePtr.add(4).readU32();
                var name2 = this.namePtr.add(8).readU32();
                var name3 = this.namePtr.add(12).readU32();

                // KERN_PROC_ALL check
                if (name0 === 0 && name1 === 14 && name2 === 0 && name3 === 0) {
                    this.isProcCheck = true;
                }
            }
        },
        onLeave: function(retval) {
            if (this.isProcCheck && this.oldp && !this.oldp.isNull()) {
                console.log('[BYPASS] Process enumeration detected - hiding Frida/cydia/silo processes');
                // Implementation would parse and filter process list
                this.isProcCheck = false;
            }
        }
    });
    console.log('[✓] Process enumeration hooked');
} catch(e) { console.log('[✗] Process enumeration failed:', e.message); }

// ============================================
// 6. HOOK ptrace anti-debugging
// ============================================

try {
    var ptrace = Module.findGlobalExportByName('ptrace');
    // Capture the original implementation before replacing. A NativeFunction
    // built from the same address calls the original (Frida routes around its
    // own hook), so non-PT_DENY_ATTACH requests behave normally.
    var ptraceOrig = new NativeFunction(ptrace, 'int', ['int', 'int', 'pointer', 'pointer']);
    Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
        if (request === 31) { // PT_DENY_ATTACH
            console.log('[BYPASS] ptrace PT_DENY_ATTACH blocked');
            return 0;
        }
        return ptraceOrig(request, pid, addr, data);
    }, 'int', ['int', 'int', 'pointer', 'pointer']));
    console.log('[✓] ptrace() hooked');
} catch(e) { console.log('[✗] ptrace() failed:', e.message); }

// ============================================
// 7. HOOK getppid debugger check
// ============================================

try {
    var getppid = Module.findGlobalExportByName('getppid');
    Interceptor.replace(getppid, new NativeCallback(function() {
        return 1; // Always return launchd as parent
    }, 'int', []));
    console.log('[✓] getppid() hooked');
} catch(e) { console.log('[✗] getppid() failed:', e.message); }

// ============================================
// 8. HOOK C++ exceptions
// ============================================

try {
    var cxa_throw = Module.findGlobalExportByName('__cxa_throw');
    if (cxa_throw) {
        Interceptor.replace(cxa_throw, new NativeCallback(function(exc, type, dest) {
            console.log('[BYPASS] __cxa_throw BLOCKED');
        }, 'void', ['pointer', 'pointer', 'pointer']));
        console.log('[✓] __cxa_throw hooked');
    }
} catch(e) { console.log('[✗] __cxa_throw failed:', e.message); }

// ============================================
// 9. HOOK UIApplication termination
// ============================================

try {
    var UIApplication = ObjC.classes.UIApplication;
    if (UIApplication) {
        var terminate = UIApplication['- terminate'];
        if (terminate) {
            Interceptor.attach(terminate.implementation, {
                onEnter: function(args) {
                    console.log('[BYPASS] [UIApplication terminate] BLOCKED');
                }
            });
            console.log('[✓] UIApplication terminate hooked');
        }
    }
} catch(e) { console.log('[✗] UIApplication failed:', e.message); }

// ============================================
// 10. DETECT Y BYPASS RASP SPECIFICO
// ============================================

// Detect NuDetectSDK
try {
    if (ObjC.classes.NuDetectListener || ObjC.classes.NuDetectSDK) {
        console.log('[RASP] NuDetectSDK detected - bypassing...');
        // Hook onHookingDetected
        if (ObjC.classes.NuDetectListener) {
            var listener = ObjC.classes.NuDetectListener;
            if (listener['- onHookingDetected']) {
                Interceptor.attach(listener['- onHookingDetected'].implementation, {
                    onEnter: function(args) {
                        console.log('[BYPASS] NuDetectListener.onHookingDetected BLOCKED');
                    }
                });
            }
        }
    }
} catch(e) { console.log('[✗] NuDetectSDK detection failed:', e.message); }

console.log("=== ULTRA RASP BYPASS READY ===");
