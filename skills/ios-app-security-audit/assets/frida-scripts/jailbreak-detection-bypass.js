/**
 * UNIVERSAL JAILBREAK DETECTION BYPASS - iOS
 *
 * Comprehensive Frida script to bypass jailbreak detection in iOS applications.
 * Hooks multiple detection methods including file system checks, URL scheme checks,
 * process spawning, and system calls.
 *
 * Coverage: NSFileManager (fileExistsAtPath, isReadableFileAtPath, createFileAtPath write test),
 *           UIApplication (canOpenURL), stat(), fopen(), fork(), posix_spawn(), dlopen(),
 *           UIDevice.jailbroken properties, direct +/-isJailbroken & *jailbreakTest* methods,
 *           common jailbreak paths
 *
 * Compatible with: Frida 16.x+, iOS 11-18
 * Usage: frida -U -f <BUNDLE_ID> -l jailbreak-detection-bypass.js
 *        or
 *        frida -U <BUNDLE_ID> -l jailbreak-detection-bypass.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0086: Test for Jailbreak Detection
 * - MASTG-TECH-0090: Anti-Jailbreak Detection Techniques
 *
 * Credits:
 * - objection: https://github.com/sensepost/objection
 * - Frida-ios-dump: https://github.com/AloneMonkey/frida-ios-dump
 * - ios-security-suite: https://github.com/securing/IOSSecuritySuite
 */

const DEBUG_MODE = true;

const JAILBREAK_PATHS = [
    "/bin/bash",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/sftp-server",
    "/var/tmp/cydia.log",
    "/etc/apt",
    "/var/lib/cydia",
    "/var/cache/apt",
    "/var/lib/apt",
    "/usr/bin/ssh",
    "/usr/libexec/cydia",
    "/Applications/blackra1n.app",
    "/Applications/blacksn0w.app",
    "/applications/limera1n.app",
    "/Library/MobileSubstrate",
    "/jb/usr/bin/",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia/",
    "/private/var/tmp/cydia.log",
    "/usr/libexec/ssh-keysign",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
];

const JAILBREAK_SCHEMES = [
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "activator://"
];

function isJailbreakPath(path) {
    if (!path) return false;
    const pathLower = path.toLowerCase();
    for (const jbPath of JAILBREAK_PATHS) {
        if (pathLower.includes(jbPath.toLowerCase())) {
            return true;
        }
    }
    return false;
}

const CACHED_STRINGS = new Map();
function getCachedString(str) {
    if (CACHED_STRINGS.has(str)) {
        return CACHED_STRINGS.get(str);
    }
    const cached = Memory.allocUtf8String(str);
    CACHED_STRINGS.set(str, cached);
    return cached;
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] JAILBREAK DETECTION BYPASS - iOS STARTED");
            console.log("[*] ================================================");

            // Frida 17: getModuleByName() throws when the module is not loaded and
            // getExportByName() throws when the symbol is missing; the "find" variants return null.
            function findExport(moduleName, symbolName) {
                var mod = Process.findModuleByName(moduleName);
                return mod ? mod.findExportByName(symbolName) : null;
            }

            let hooksApplied = 0;

            try {
                const NSFileManager = ObjC.classes.NSFileManager;
                const originalFileExistsAtPath = NSFileManager['- fileExistsAtPath:'];

                if (originalFileExistsAtPath) {
                    Interceptor.attach(originalFileExistsAtPath.implementation, {
                        onEnter: function(args) {
                            const path = ObjC.Object(args[2]).toString();
                            if (isJailbreakPath(path)) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.fileExistsAtPath: - Blocked: " + path);
                                }
                                this.shouldBlock = true;
                            }
                        },
                        onLeave: function(retval) {
                            if (this.shouldBlock) {
                                retval.replace(ptr(0)); // NO
                            }
                        }
                    });
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.fileExistsAtPath: hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSFileManager.fileExistsAtPath: hook failed: " + e.message);
            }

            try {
                const NSFileManager = ObjC.classes.NSFileManager;
                const originalFileExistsAtPathIsDir = NSFileManager['- fileExistsAtPath:isDirectory:'];

                if (originalFileExistsAtPathIsDir) {
                    Interceptor.attach(originalFileExistsAtPathIsDir.implementation, {
                        onEnter: function(args) {
                            const path = ObjC.Object(args[2]).toString();
                            if (isJailbreakPath(path)) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.fileExistsAtPath:isDirectory: - Blocked: " + path);
                                }
                                this.shouldBlock = true;
                            }
                        },
                        onLeave: function(retval) {
                            if (this.shouldBlock) {
                                retval.replace(ptr(0)); // NO
                            }
                        }
                    });
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.fileExistsAtPath:isDirectory: hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSFileManager.fileExistsAtPath:isDirectory: hook failed: " + e.message);
            }

            try {
                const NSFileManager = ObjC.classes.NSFileManager;
                const originalIsReadableFile = NSFileManager['- isReadableFileAtPath:'];

                if (originalIsReadableFile) {
                    Interceptor.attach(originalIsReadableFile.implementation, {
                        onEnter: function(args) {
                            const path = ObjC.Object(args[2]).toString();
                            if (isJailbreakPath(path)) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.isReadableFileAtPath: - Blocked: " + path);
                                }
                                this.shouldBlock = true;
                            }
                        },
                        onLeave: function(retval) {
                            if (this.shouldBlock) {
                                retval.replace(ptr(0)); // NO
                            }
                        }
                    });
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.isReadableFileAtPath: hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSFileManager.isReadableFileAtPath: hook failed: " + e.message);
            }

            try {
                const UIApplication = ObjC.classes.UIApplication;
                const sharedApp = UIApplication.sharedApplication();
                if (sharedApp) {
                    const originalCanOpenURL = sharedApp['- canOpenURL:'];

                    if (originalCanOpenURL) {
                        Interceptor.attach(originalCanOpenURL.implementation, {
                            onEnter: function(args) {
                                const url = new ObjC.Object(args[2]);
                                const urlStr = url.absoluteString().toString();
                                for (const scheme of JAILBREAK_SCHEMES) {
                                    if (urlStr.toLowerCase().startsWith(scheme)) {
                                        if (DEBUG_MODE) {
                                            console.log("\x1b[32m[+]\x1b[0m UIApplication.canOpenURL: - Blocked: " + urlStr);
                                        }
                                        this.shouldBlock = true;
                                        break;
                                    }
                                }
                            },
                            onLeave: function(retval) {
                                if (this.shouldBlock) {
                                    retval.replace(ptr(0)); // NO
                                }
                            }
                        });
                        hooksApplied++;
                        console.log("\x1b[32m[+]\x1b[0m UIApplication.canOpenURL: hooked successfully");
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UIApplication.canOpenURL: hook failed: " + e.message);
            }

            try {
                const statPtr = findExport('libsystem_kernel.dylib', 'stat');
                if (statPtr) {
                    const stat = new NativeFunction(statPtr, 'int', ['pointer', 'pointer']);
                    const statHook = new NativeCallback(function(path, buf) {
                        const pathStr = (path && !path.isNull()) ? path.readUtf8String() : null;
                        if (isJailbreakPath(pathStr)) {
                            if (DEBUG_MODE) {
                                console.log("\x1b[32m[+]\x1b[0m stat() - Blocked: " + pathStr);
                            }
                            return -1; // Return error
                        }
                        return stat(path, buf);
                    }, 'int', ['pointer', 'pointer']);
                    Interceptor.replace(statPtr, statHook);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m stat() hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m stat() hook failed: " + e.message);
            }

            try {
                const fopenPtr = findExport('libsystem_c.dylib', 'fopen');
                if (fopenPtr) {
                    const fopen = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
                    const fopenHook = new NativeCallback(function(path, mode) {
                        const pathStr = (path && !path.isNull()) ? path.readUtf8String() : null;
                        if (isJailbreakPath(pathStr)) {
                            if (DEBUG_MODE) {
                                console.log("\x1b[32m[+]\x1b[0m fopen() - Blocked: " + pathStr);
                            }
                            return ptr(0); // Return NULL
                        }
                        return fopen(path, mode);
                    }, 'pointer', ['pointer', 'pointer']);
                    Interceptor.replace(fopenPtr, fopenHook);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m fopen() hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m fopen() hook failed: " + e.message);
            }

            try {
                const forkPtr = findExport('libsystem_kernel.dylib', 'fork');
                if (forkPtr) {
                    const forkHook = new NativeCallback(function() {
                        if (DEBUG_MODE) {
                            console.log("\x1b[32m[+]\x1b[0m fork() - Blocked");
                        }
                        return -1; // Return error
                    }, 'int', []);
                    Interceptor.replace(forkPtr, forkHook);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m fork() hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m fork() hook failed: " + e.message);
            }

            try {
                const posixSpawnPtr = findExport('libsystem_kernel.dylib', 'posix_spawn');
                if (posixSpawnPtr) {
                    const posixSpawn = new NativeFunction(posixSpawnPtr, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                    const posixSpawnHook = new NativeCallback(function(pid, path, file_actions, attrp, argv, envp) {
                        const pathStr = (path && !path.isNull()) ? path.readUtf8String() : null;
                        if (isJailbreakPath(pathStr) || (pathStr && (pathStr.includes('/bin/bash') || pathStr.includes('/bin/sh')))) {
                            if (DEBUG_MODE) {
                                console.log("\x1b[32m[+]\x1b[0m posix_spawn() - Blocked: " + pathStr);
                            }
                            return -1; // Return error
                        }
                        return posixSpawn(pid, path, file_actions, attrp, argv, envp);
                    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                    Interceptor.replace(posixSpawnPtr, posixSpawnHook);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m posix_spawn() hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m posix_spawn() hook failed: " + e.message);
            }

            try {
                const UIDevice = ObjC.classes.UIDevice;
                const device = UIDevice.currentDevice();
                if (device) {
                    const jailbrokenMethod = device['- isJailbroken'];
                    if (jailbrokenMethod) {
                        Interceptor.attach(jailbrokenMethod.implementation, {
                            onLeave: function(retval) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m UIDevice.isJailbroken - Bypassed");
                                }
                                retval.replace(ptr(0)); // NO
                            }
                        });
                        hooksApplied++;
                    }

                    try {
                        const value = device.valueForKey_('isJailbroken');
                        if (value !== null) {
                            const originalValueForKey = device['- valueForKey:'];
                            if (originalValueForKey) {
                                Interceptor.attach(originalValueForKey.implementation, {
                                    onEnter: function(args) {
                                        const key = ObjC.Object(args[2]).toString();
                                        if (key.toLowerCase().includes('jailbroken')) {
                                            if (DEBUG_MODE) {
                                                console.log("\x1b[32m[+]\x1b[0m UIDevice.valueForKey: - Bypassed for: " + key);
                                            }
                                            this.shouldBlock = true;
                                        }
                                    },
                                    onLeave: function(retval) {
                                        if (this.shouldBlock) {
                                            retval.replace(ObjC.classes.NSNumber.numberWithBool_(0));
                                        }
                                    }
                                });
                                hooksApplied++;
                            }
                        }
                    } catch (e) {
                        // valueForKey: not relevant, continue
                    }

                    console.log("\x1b[32m[+]\x1b[0m UIDevice jailbroken detection hooked");
                }
            } catch (e) {
                console.log("[!] UIDevice jailbroken detection hook failed: " + e.message);
            }

            try {
                const dlopenPtr = Module.getGlobalExportByName('dlopen');
                if (dlopenPtr) {
                    const dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
                    const dlopenHook = new NativeCallback(function(path, mode) {
                        const pathStr = (path && !path.isNull()) ? path.readUtf8String() : null;
                        if (pathStr && (pathStr.toLowerCase().includes('frida') || pathStr.toLowerCase().includes('substrate') || pathStr.toLowerCase().includes('cydia'))) {
                            if (DEBUG_MODE) {
                                console.log("\x1b[32m[+]\x1b[0m dlopen() - Blocked: " + pathStr);
                            }
                            return ptr(0); // Return NULL
                        }
                        return dlopen(path, mode);
                    }, 'pointer', ['pointer', 'int']);
                    Interceptor.replace(dlopenPtr, dlopenHook);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m dlopen() hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m dlopen() hook failed: " + e.message);
            }

            try {
                // Blocks jailbreak "write test" probes (e.g. writing to /private/)
                const NSFileManager = ObjC.classes.NSFileManager;
                const originalCreateFile = NSFileManager['- createFileAtPath:contents:attributes:'];

                if (originalCreateFile) {
                    Interceptor.attach(originalCreateFile.implementation, {
                        onEnter: function(args) {
                            const path = ObjC.Object(args[2]).toString();
                            if (path.startsWith("/private/") || isJailbreakPath(path)) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.createFileAtPath: - Blocked write test: " + path);
                                }
                                this.shouldBlock = true;
                            }
                        },
                        onLeave: function(retval) {
                            if (this.shouldBlock) {
                                retval.replace(ptr(0)); // NO (write failed)
                            }
                        }
                    });
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m NSFileManager.createFileAtPath:contents:attributes: hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSFileManager.createFileAtPath: hook failed: " + e.message);
            }

            try {
                // +isJailbroken / -isJailbroken / isJailBroken / isDeviceJailbroken
                // and any *jailbreakTest* method (covers app-specific routines)
                const detectionSelectors = [
                    "+ isJailbroken", "- isJailbroken",
                    "+ isJailBroken", "- isJailBroken",
                    "+ isDeviceJailbroken", "- isDeviceJailbroken"
                ];

                for (const className in ObjC.classes) {
                    const clazz = ObjC.classes[className];

                    for (const sel of detectionSelectors) {
                        try {
                            if (clazz[sel]) {
                                Interceptor.attach(clazz[sel].implementation, {
                                    onLeave: function(retval) {
                                        retval.replace(ptr(0)); // FALSE
                                    }
                                });
                                hooksApplied++;
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m Hooked " + className + " " + sel);
                                }
                            }
                        } catch (e) { /* selector not present on this class */ }
                    }

                    try {
                        clazz.$ownMethods.forEach(function(method) {
                            if (method.toLowerCase().indexOf("jailbreaktest") !== -1) {
                                Interceptor.attach(clazz[method].implementation, {
                                    onLeave: function(retval) {
                                        retval.replace(ptr(0)); // FALSE
                                    }
                                });
                                hooksApplied++;
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m Hooked " + className + " " + method);
                                }
                            }
                        });
                    } catch (e) { /* $ownMethods not enumerable */ }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Direct method discovery failed: " + e.message);
            }

            console.log("[*] ================================================");
            console.log("[*] Total hooks applied: " + hooksApplied);
            console.log("[*] Jailbreak Detection Bypass Complete");
            console.log("[*] ================================================");
        });
    } catch (e) {
        console.log("\x1b[31m[!]\x1b[0m Fatal error in main execution: " + e.message);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
