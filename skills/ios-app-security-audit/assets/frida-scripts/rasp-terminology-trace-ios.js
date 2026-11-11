/**
 * RASP Termination Trace - Spawn Mode
 *
 * Objetivo: Identificar el método exacto que RASP usa para terminar el app.
 * Se inyecta ANTES de main() para capturar llamadas tempranas.
 *
 * USO: frida -U -f com.namutek.kash -l rasp-terminology-trace-ios.js
 */

const LOG_FILE = "/tmp/frida_rasp_trace.log";

function log(msg) {
    const timestamp = new Date().toISOString();
    const fullMsg = `[${timestamp}] ${msg}\n`;
    console.log(fullMsg);
    send({type: "log", message: fullMsg});
}

// ============================================
// 1. NATIVE FUNCTION HOOKS
// ============================================

log("=== RASP TERMINATION TRACE - SPAWN MODE ===");

// Hook exit
try {
    const exitPtr = Module.findGlobalExportByName("exit");
    if (exitPtr) {
        Interceptor.attach(exitPtr, {
            onEnter: function(args) {
                const status = args[0].toInt32();
                log(`[EXIT] exit(${status}) called`);
                log(`[EXIT] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
            }
        });
        log("[HOOK] exit() hooked");
    }
} catch (e) {
    log(`[ERROR] exit hook failed: ${e}`);
}

// Hook abort
try {
    const abortPtr = Module.findGlobalExportByName("abort");
    if (abortPtr) {
        Interceptor.attach(abortPtr, {
            onEnter: function(args) {
                log(`[ABORT] abort() called`);
                log(`[ABORT] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
            }
        });
        log("[HOOK] abort() hooked");
    }
} catch (e) {
    log(`[ERROR] abort hook failed: ${e}`);
}

// Hook _Exit
try {
    const _ExitPtr = Module.findGlobalExportByName("_Exit");
    if (_ExitPtr) {
        Interceptor.attach(_ExitPtr, {
            onEnter: function(args) {
                const status = args[0].toInt32();
                log(`[_EXIT] _Exit(${status}) called`);
                log(`[_EXIT] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
            }
        });
        log("[HOOK] _Exit() hooked");
    }
} catch (e) {
    log(`[ERROR] _Exit hook failed: ${e}`);
}

// Hook pthread_kill
try {
    const pthread_killPtr = Module.findGlobalExportByName("pthread_kill");
    if (pthread_killPtr) {
        Interceptor.attach(pthread_killPtr, {
            onEnter: function(args) {
                const thread = args[0];
                const sig = args[1].toInt32();
                log(`[PTHREAD_KILL] pthread_kill(thread=${thread}, sig=${sig})`);
            }
        });
        log("[HOOK] pthread_kill() hooked");
    }
} catch (e) {
    log(`[ERROR] pthread_kill hook failed: ${e}`);
}

// Hook kill
try {
    const killPtr = Module.findGlobalExportByName("kill");
    if (killPtr) {
        Interceptor.attach(killPtr, {
            onEnter: function(args) {
                const pid = args[0].toInt32();
                const sig = args[1].toInt32();
                log(`[KILL] kill(pid=${pid}, sig=${sig})`);
            }
        });
        log("[HOOK] kill() hooked");
    }
} catch (e) {
    log(`[ERROR] kill hook failed: ${e}`);
}

// Hook raise
try {
    const raisePtr = Module.findGlobalExportByName("raise");
    if (raisePtr) {
        Interceptor.attach(raisePtr, {
            onEnter: function(args) {
                const sig = args[0].toInt32();
                log(`[RAISE] raise(${sig})`);
            }
        });
        log("[HOOK] raise() hooked");
    }
} catch (e) {
    log(`[ERROR] raise hook failed: ${e}`);
}

// ============================================
// 2. OBJECTIVE-C TERMINATION HOOKS
// ============================================

if (ObjC.available) {
    log("[OBJC] Objective-C runtime available");

    // Hook UIApplication methods
    try {
        const UIApplication = ObjC.classes.UIApplication;
        if (UIApplication) {
            // Hook terminateWithSuccess
            const terminateMethod = UIApplication["- terminateWithSuccess"];
            if (terminateMethod) {
                Interceptor.attach(terminateMethod.implementation, {
                    onEnter: function(args) {
                        log(`[UIAPP] terminateWithSuccess() called`);
                        log(`[UIAPP] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
                    }
                });
                log("[HOOK] UIApplication.terminateWithSuccess hooked");
            }

            // Hook terminate
            const terminateMethod2 = UIApplication["- terminate"];
            if (terminateMethod2) {
                Interceptor.attach(terminateMethod2.implementation, {
                    onEnter: function(args) {
                        log(`[UIAPP] terminate() called`);
                    }
                });
                log("[HOOK] UIApplication.terminate hooked");
            }
        }
    } catch (e) {
        log(`[ERROR] UIApplication hook failed: ${e}`);
    }

    // Hook general exit methods
    try {
        const selector = ObjC.selector("exit");
        log(`[OBJC] Exit selector: ${selector}`);
    } catch (e) {
        // Ignore
    }
}

// ============================================
// 3. DISPATCH HOOKS
// ============================================

try {
    const dispatch_exitPtr = Module.findGlobalExportByName("dispatch_exit");
    if (dispatch_exitPtr && !dispatch_exitPtr.isNull()) {
        Interceptor.attach(dispatch_exitPtr, {
            onEnter: function(args) {
                log(`[DISPATCH] dispatch_exit() called`);
            }
        });
        log("[HOOK] dispatch_exit() hooked");
    } else {
        log("[INFO] dispatch_exit is NULL (simulator - expected)");
    }
} catch (e) {
    log(`[ERROR] dispatch_exit hook failed: ${e}`);
}

// ============================================
// 4. PROCESS EXIT HOOK (POSIX)
// ============================================

try {
    const _exitPtr = Module.findGlobalExportByName("_exit");
    if (_exitPtr) {
        Interceptor.attach(_exitPtr, {
            onEnter: function(args) {
                const status = args[0].toInt32();
                log(`[_EXIT] _exit(${status}) called - POSIX direct exit`);
                log(`[_EXIT] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
            }
        });
        log("[HOOK] _exit() hooked");
    }
} catch (e) {
    log(`[ERROR] _exit hook failed: ${e}`);
}

// ============================================
// 5. DYLD EXIT HOOKS
// ============================================

try {
    const dyld_exitPtr = Module.findGlobalExportByName("dyld_exit");
    if (dyld_exitPtr) {
        Interceptor.attach(dyld_exitPtr, {
            onEnter: function(args) {
                log(`[DYLD] dyld_exit() called - DYLD IS EXITING PROCESS`);
            }
        });
        log("[HOOK] dyld_exit() hooked");
    } else {
        log("[INFO] dyld_exit not found (expected - internal)");
    }
} catch (e) {
    log(`[ERROR] dyld_exit hook failed: ${e}`);
}

// ============================================
// 6. C++ TERMINATION HOOKS
// ============================================

try {
    // std::terminate()
    const std_terminatePtr = Module.findGlobalExportByName("_ZSt9terminatev");
    if (std_terminatePtr) {
        Interceptor.attach(std_terminatePtr, {
            onEnter: function(args) {
                log(`[C++] std::terminate() called`);
                log(`[C++] Stack trace:\n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
            }
        });
        log("[HOOK] std::terminate() hooked");
    }
} catch (e) {
    log(`[ERROR] std::terminate hook failed: ${e}`);
}

// ============================================
// 7. MONITOR PROCESS LIFECYCLE
// ============================================

let processMonitored = false;

// Hook after main() starts
const mainPtr = Module.findGlobalExportByName("main");
if (mainPtr) {
    Interceptor.attach(mainPtr, {
        onEnter: function(args) {
            log("[MAIN] main() entered - process is running");
            processMonitored = true;
        },
        onLeave: function(retval) {
            log(`[MAIN] main() exiting with return value: ${retval}`);
        }
    });
    log("[HOOK] main() hooked for lifecycle monitoring");
}

// ============================================
// 8. SCAN FOR NAMESPACE HOOKS
// ============================================

function scanForTerminators() {
    log("[SCAN] Scanning for termination-related methods...");

    const keywords = ["termin", "exit", "kill", "destroy", "close", "shutdown"];

    for (const className of Object.keys(ObjC.classes)) {
        if (className.includes("NuDetect") || className.includes("RNNuDetect")) {
            try {
                const cls = ObjC.classes[className];
                const methods = ObjC.classes[className].$ownMethods;

                for (const method of methods) {
                    const methodLower = method.toLowerCase();
                    for (const keyword of keywords) {
                        if (methodLower.includes(keyword)) {
                            log(`[SCAN] Found termination method in ${className}: ${method}`);

                            // Hook it
                            try {
                                const impl = cls[method].implementation;
                                Interceptor.attach(impl, {
                                    onEnter: function(args) {
                                        log(`[NuDetect] ${className} ${method} called`);
                                    }
                                });
                            } catch (e) {
                                // Method might not be hookable
                            }
                        }
                    }
                }
            } catch (e) {
                // Class might not be accessible
            }
        }
    }
}

// Scan after a delay
if (ObjC.available) {
    setTimeout(scanForTerminators, 1000);
}

// ============================================
// 9. FINAL STATUS
// ============================================

log("[INIT] All hooks installed - monitoring for termination...");
log("[INIT] Waiting for process events...");

// Report every 5 seconds that we're still alive
setInterval(() => {
    log(`[HEARTBEAT] Process still alive at ${new Date().toISOString()}`);
}, 5000);
