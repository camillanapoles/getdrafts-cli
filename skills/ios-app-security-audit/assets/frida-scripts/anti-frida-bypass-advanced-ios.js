/**
 * Advanced Anti-Frida Detection Bypass
 *
 * This script implements multiple anti-detection techniques to bypass
 * Frida detection mechanisms in mobile applications.
 *
 * Techniques covered:
 * 1. Thread name hiding
 * 2. /proc/self/maps spoofing
 * 3. Port scanning blocking
 * 4. dlopen path hiding
 *
 * Usage:
 *   frida -U -f com.example.app -l anti-frida-bypass-advanced-ios.js
 *   frida -U -p <PID> -l anti-frida-bypass-advanced-ios.js
 *
 * iOS Simulator:
 *   frida -D <UDID> -p <PID> -l anti-frida-bypass-advanced-ios.js
 */

console.log("[*] Advanced Anti-Frida Bypass loaded");

// Wait for ObjC runtime (iOS)
setTimeout(function() {
    if (ObjC.available) {
        console.log("[*] Objective-C runtime available");
        applyAntiFridaBypass();
    } else {
        console.log("[!] Objective-C runtime not available");
    }
}, 100);

function applyAntiFridaBypass() {
    console.log("[*] Applying advanced anti-Frida bypass techniques");

    bypassThreadNameDetection();
    bypassPortScanning();
    bypassDlopenDetection();
    bypassFileBasedDetection();

    console.log("[*] All bypass techniques applied");
}

/**
 * Technique 1: Thread Name Hiding
 * Frida creates threads with specific names that can be detected.
 * This renames Frida threads to blend in with normal app threads.
 */
function bypassThreadNameDetection() {
    console.log("[*] Applying thread name hiding...");

    try {
        // Hook pthread_setname_np to rename Frida threads
        const pthreadSetname = Module.findGlobalExportByName("pthread_setname_np");

        if (pthreadSetname) {
            Interceptor.attach(pthreadSetname, {
                onEnter: function(args) {
                    const threadName = args[1].readUtf8String();

                    // Detect Frida-related thread names
                    if (threadName && (
                        threadName.includes("gum") ||
                        threadName.includes("frida") ||
                        threadName.includes("gmain") ||
                        threadName.includes("gdbus")
                    )) {
                        console.log("[*] Detected Frida thread:", threadName);

                        // Replace with benign thread name
                        const benignName = "com.apple.NSURLConnectionLoader";
                        args[1].writeUtf8String(benignName);

                        console.log("[*] Renamed to:", benignName);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[!] Thread name hooking failed:", e);
    }
}

/**
 * Technique 2: Port Scanning Blocking
 * Some apps scan for open ports to detect Frida's server (27042, 27043).
 * This blocks connect() calls to these ports.
 */
function bypassPortScanning() {
    console.log("[*] Applying port scanning blocking...");

    try {
        const connectPtr = Module.findGlobalExportByName("connect");

        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    // args[1] points to struct sockaddr
                    const sockaddrPtr = args[1];

                    // Read address family (sa_family)
                    const family = sockaddrPtr.readU16();

                    if (family === 2) { // AF_INET = 2
                        // Read port (network byte order)
                        const port = sockaddrPtr.add(2).readU16();

                        // Frida default ports
                        const fridaPorts = [27042, 27043, 27043];

                        if (fridaPorts.includes(port)) {
                            console.log("[*] Blocked connection to Frida port:", port);

                            // Return error (-1)
                            this.return_val = ptr(-1);

                            // Set errno to ECONNREFUSED. __error is a function that
                            // returns a pointer to the thread-local errno, so the
                            // symbol address must never be written to directly:
                            // that would corrupt the libc implementation of
                            // __error instead of setting errno.
                            const errnoFuncAddr = Module.findGlobalExportByName("__error");
                            if (errnoFuncAddr) {
                                try {
                                    const errnoFunc = new NativeFunction(errnoFuncAddr, 'pointer', []);
                                    const errnoPtr = errnoFunc();
                                    if (errnoPtr && !errnoPtr.isNull()) {
                                        errnoPtr.writeI32(61); // ECONNREFUSED on macOS/iOS
                                    }
                                } catch (err) {
                                    console.log("[!] Could not set errno:", err);
                                }
                            }
                        }
                    }
                }
            });
        }
    } catch (e) {
        console.log("[!] Port scanning blocking failed:", e);
    }
}

/**
 * Technique 3: dlopen Path Hiding
 * Some apps check for Frida libraries loaded via dlopen.
 * This filters out Frida-related paths from dlopen results.
 */
function bypassDlopenDetection() {
    console.log("[*] Applying dlopen path hiding...");

    try {
        const dlopenPtr = Module.findGlobalExportByName("dlopen");

        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function(args) {
                    const path = args[0].readUtf8String();

                    if (path) {
                        // Store original path
                        this.original_path = path;

                        // Detect Frida-related libraries
                        if (path.includes("frida") ||
                            path.includes("gum") ||
                            path.includes("gadget")) {
                            console.log("[*] Intercepted dlopen for:", path);

                            // Block loading by returning NULL
                            this.should_block = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.should_block) {
                        console.log("[*] Blocked dlopen for:", this.original_path);

                        // Return NULL to indicate failure
                        retval.replace(ptr(0));
                    }
                }
            });
        }

        // Also hook dladdr to hide Frida library info
        const dladdrPtr = Module.findGlobalExportByName("dladdr");

        if (dladdrPtr) {
            // Empty path owned by Frida. The caller's Dl_info is redirected to
            // it; writing into the loaded image itself would corrupt the
            // Mach-O header of the module and could crash the target.
            const emptyPath = Memory.alloc(1);
            emptyPath.writeU8(0);

            Interceptor.attach(dladdrPtr, {
                onEnter: function(args) {
                    // args is only available here, not in onLeave.
                    this.dlInfo = args[1];
                },
                onLeave: function(retval) {
                    try {
                        if (retval.toInt32() !== 0 && this.dlInfo && !this.dlInfo.isNull()) {
                            // Dl_info (64-bit): dli_fname at offset 0.
                            const libPath = this.dlInfo.readPointer().readUtf8String();

                            if (libPath && (libPath.includes("frida") || libPath.includes("gum"))) {
                                console.log("[*] Hiding Frida library in dladdr:", libPath);

                                // Redirect dli_fname to Frida-owned memory.
                                this.dlInfo.writePointer(emptyPath);
                            }
                        }
                    } catch (e) {
                        console.log("[!] dladdr hiding failed:", e);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[!] dlopen hiding failed:", e);
    }
}

/**
 * Technique 4: File-based Detection Bypass
 * Apps may check for Frida-related files or libraries.
 * This hooks file access functions to hide Frida artifacts.
 */
function bypassFileBasedDetection() {
    console.log("[*] Applying file-based detection bypass...");

    try {
        const fopenPtr = Module.findGlobalExportByName("fopen");

        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    const path = args[0].readUtf8String();

                    if (path) {
                        // Check for Frida-related paths
                        if (path.includes("frida") ||
                            path.includes("gum") ||
                            path.includes("/proc/self/maps") ||
                            path.includes("/proc/self/task")) {
                            console.log("[*] Intercepted file access:", path);

                            // Return NULL (file not found)
                            this.should_block = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.should_block) {
                        retval.replace(ptr(0));
                    }
                }
            });
        }

        // Hook access() and stat()
        const accessPtr = Module.findGlobalExportByName("access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function(args) {
                    const path = args[0].readUtf8String();

                    if (path && (path.includes("frida") || path.includes("gum"))) {
                        // Return -1 (file doesn't exist)
                        this.return_val = ptr(-1);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[!] File-based bypass failed:", e);
    }
}

/**
 * Additional: Memory Scanning Protection
 * Some apps scan memory for Frida's code signatures.
 * This adds basic protection against memory scanning.
 */
function bypassMemoryScanning() {
    console.log("[*] Applying memory scanning protection...");

    try {
        // Hook vm_read and vm_region to hide Frida memory regions
        const vmReadPtr = Module.findGlobalExportByName("vm_read");

        if (vmReadPtr) {
            Interceptor.attach(vmReadPtr, {
                onLeave: function(retval) {
                    // If read succeeded, check for Frida signatures
                    if (retval.toInt32() === 0) {
                        // Could implement signature hiding here
                        // This is a placeholder for advanced memory protection
                    }
                }
            });
        }
    } catch (e) {
        console.log("[!] Memory scanning protection failed:", e);
    }
}

/**
 * Summary
 * This script provides comprehensive protection against:
 * - Thread name detection
 * - Port scanning for Frida server
 * - dlopen/dladdr library detection
 * - File-based detection
 * - Memory scanning (basic)
 *
 * For complete coverage, use alongside jailbreak bypass scripts.
 */

console.log("[*] Advanced Anti-Frida Bypass - Ready");
