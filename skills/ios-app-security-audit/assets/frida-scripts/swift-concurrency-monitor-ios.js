/**
 * Swift Concurrency Monitor for iOS
 *
 * Monitors Swift concurrency operations (async/await, actors, tasks).
 * Note: Swift concurrency is Swift-native and doesn't expose ObjC symbols.
 * This script provides limited detection through framework hooks.
 *
 * Compatible with: Frida 16.x+ and iOS 15+
 * Usage: frida -U -f <bundle_id> -l swift-concurrency-monitor-ios.js
 * OWASP MASTG: MSTG-ARCH-1, MSTG-COVER-2
 *
 * Limitations: Swift concurrency doesn't expose ObjC runtime symbols.
 * This script focuses on detectable patterns and framework interactions.
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Swift Concurrency Monitor iOS Script Started");

    var CONFIG = {
        detectActorLeaks: true,
        detectTaskLeaks: true,
        DEBUG_MODE: false
    };

    var actorOperations = 0;
    var taskCreations = 0;

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            // Swift concurrency uses libswift_Concurrency.dylib
            // Try to detect its presence
            var swiftConcurrencyFound = false;

            Process.enumerateModules().forEach(function(module) {
                if (module.name.indexOf("swift_Concurrency") !== -1 ||
                    module.name.indexOf("libswift") !== -1) {
                    swiftConcurrencyFound = true;
                    console.log("\x1b[32m[+]\x1b[0m Swift concurrency module found: " + module.name);
                }
            });

            if (!swiftConcurrencyFound) {
                console.log("\x1b[33m[*]\x1b[0m Swift Concurrency module not explicitly found (may be statically linked)");
            }

            // Scan for Swift concurrency symbols
            try {
                var concurrencySymbols = [];

                Process.enumerateModules().forEach(function(module) {
                    try {
                        module.enumerateSymbols().forEach(function(symbol) {
                            var name = symbol.name;
                            if (name.indexOf("async") !== -1 ||
                                name.indexOf("await") !== -1 ||
                                name.indexOf("Task") !== -1 ||
                                name.indexOf("Actor") !== -1 ||
                                name.indexOf("executor") !== -1) {
                                concurrencySymbols.push(module.name + "::" + name);
                            }
                        });
                    } catch (e) {
                        // Symbol enumeration may fail
                    }
                });

                if (concurrencySymbols.length > 0) {
                    console.log("\x1b[32m[+]\x1b[0m Swift Concurrency symbols detected:");
                    concurrencySymbols.slice(0, 15).forEach(function(sym) {
                        console.log("    " + sym);
                    });
                    if (concurrencySymbols.length > 15) {
                        console.log("    ... and " + (concurrencySymbols.length - 15) + " more");
                    }
                } else {
                    console.log("\x1b[33m[*]\x1b[0m No explicit concurrency symbols found (Swift 5.5+ may be statically linked)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Symbol scan failed: " + e.message);
            }

            // Hook dispatch_queue for task execution monitoring
            // Swift concurrency uses dispatch underneath
            try {
                var dispatch_async = Module.findGlobalExportByName("dispatch_async");
                if (dispatch_async) {
                    Interceptor.attach(dispatch_async, {
                        onEnter: function(args) {
                            this.queue = args[0];
                            this.block = args[1];
                        },
                        onLeave: function(retval) {
                            taskCreations++;
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m dispatch_async hooked (monitors task execution)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m dispatch_async hook failed: " + e.message);
            }

            // Hook pthread operations (used by Swift tasks)
            try {
                var pthread_create = Module.findGlobalExportByName("pthread_create");
                if (pthread_create) {
                    Interceptor.attach(pthread_create, {
                        onEnter: function(args) {
                            console.log("\x1b[36m[i]\x1b[0m Thread created (possible Task execution)");
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m pthread_create hooked (monitors thread creation)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m pthread_create hook failed: " + e.message);
            }

            // Look for MainActor class (ObjC-exposed)
            try {
                var MainActor = ObjC.classes._TtC4swift8MainActor;
                if (MainActor) {
                    console.log("\x1b[32m[+]\x1b[0m MainActor class detected (@objc MainActor)");
                } else {
                    // Try alternative naming
                    if (ObjC.classes.MainActor) {
                        console.log("\x1b[32m[+]\x1b[0m MainActor class detected (objc name)");
                    }
                }
            } catch (e) {
                console.log("\x1b[33m[*]\x1b[0m MainActor not ObjC-exposed (Swift-only)");
            }

            // Hook NSThread for UI thread monitoring
            try {
                var NSThread = ObjC.classes.NSThread;
                if (NSThread) {
                    var isMainThread = NSThread["+ isMainThread"];
                    if (isMainThread) {
                        Interceptor.attach(isMainThread.implementation, {
                            onLeave: function(retval) {
                                var isMain = retval.toInt32() === 1;
                                if (!isMain && CONFIG.DEBUG_MODE) {
                                    console.log("\x1b[33m[*]\x1b[0m isMainThread: false (background thread)");
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSThread.isMainThread hooked");
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSThread hook failed: " + e.message);
            }

            console.log("\x1b[33m[*]\x1b[0m Swift Concurrency Monitor iOS Script Loaded");
            console.log("\x1b[36m[*]\x1b[0m Note: Swift concurrency has limited ObjC runtime visibility");

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Swift Concurrency Monitor iOS error: " + e.message);
        }
    });

    setInterval(function() {
        if (actorOperations > 0 || taskCreations > 0) {
            console.log("\x1b[36m[*]\x1b[0m Stats - Actor ops: " + actorOperations + " | Task creations: " + taskCreations);
        }
    }, 30000);

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
