/**
 * Data Protection Level Checker (BETA)
 *
 * Verifies Data Protection levels on files in app sandbox:
 * - Enumerate files in Documents, Library, tmp
 * - Check NSFileProtectionKey attribute
 * - Report unprotected files
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l data-protection-check.js
 * OWASP MASVS: MSTG-STORAGE-2, MSTG-STORAGE-3
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Data Protection Checker Script Started (BETA)");

    var CONFIG = {
        sandboxPath: null,
        maxDepth: 3,
        checkDirectories: ["Documents", "Library", "tmp"],
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            var NSBundle = ObjC.classes.NSBundle;
            var NSURL = ObjC.classes.NSURL;

            function getSandboxPath() {
                if (CONFIG.sandboxPath) return CONFIG.sandboxPath;

                try {
                    var mainBundle = NSBundle.mainBundle();
                    var bundlePath = mainBundle.bundlePath();
                    var components = bundlePath.pathComponents();
                    var sandboxPath = "";

                    for (var i = 0; i < components.length - 1; i++) {
                        sandboxPath += "/" + components[i].toString();
                    }

                    return sandboxPath;
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Failed to detect sandbox path: " + e.message);
                    return "/var/mobile/Containers/Data/Application";
                }
            }

            function getDataProtectionLevel(filePath) {
                var fileManager = NSFileManager.defaultManager();

                try {
                    var fileURL = NSURL.fileURLWithPath_(filePath);
                    var attributes = fileManager.attributesOfItemAtPath_error_(filePath, null);

                    if (attributes) {
                        var protection = attributes.objectForKey_("NSFileProtectionKey");
                        return protection ? protection.toString() : "None";
                    }
                } catch (e) {
                    return "Error: " + e.message;
                }

                return "Unknown";
            }

            function enumerateDirectory(dirPath, depth) {
                if (depth > CONFIG.maxDepth) return;

                var fileManager = NSFileManager.defaultManager();

                try {
                    var files = fileManager.contentsOfDirectoryAtPath_error_(dirPath, null);

                    if (files) {
                        for (var i = 0; i < files.count(); i++) {
                            var fileName = files.objectAtIndex_(i);
                            var filePath = dirPath + "/" + fileName.toString();
                            // fileExistsAtPath:isDirectory: takes a BOOL* out-parameter.
                            // Allocate a single byte via Memory.alloc so the ObjC runtime
                            // can write into it and we can read it back. (RefBool is NOT
                            // a Frida API and was the source of a silent crash.)
                            var isDirPtr = Memory.alloc(1);

                            fileManager.fileExistsAtPath_isDirectory_(filePath, isDirPtr);

                            if (isDirPtr.readU8() !== 0) {
                                if (CONFIG.DEBUG_MODE) {
                                    console.log("    Directory: " + fileName.toString());
                                }
                                enumerateDirectory(filePath, depth + 1);
                            } else {
                                var protection = getDataProtectionLevel(filePath);

                                if (protection === "NSFileProtectionNone" || protection === "None") {
                                    console.log("\x1b[31m[!]\x1b[0m VULNERABLE: " + filePath);
                                    console.log("    Protection: " + protection);
                                } else if (protection.indexOf("Error") === -1) {
                                    console.log("\x1b[32m[+]\x1b[0m OK: " + filePath);
                                    console.log("    Protection: " + protection);
                                }
                            }
                        }
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Error enumerating " + dirPath + ": " + e.message);
                }
            }

            function scanDataProtection() {
                var sandboxPath = getSandboxPath();

                console.log("\x1b[33m[*]\x1b[0m Scanning Data Protection levels...");
                console.log("    Sandbox: " + sandboxPath);
                console.log("    Max Depth: " + CONFIG.maxDepth);
                console.log("");

                for (var i = 0; i < CONFIG.checkDirectories.length; i++) {
                    var dir = CONFIG.checkDirectories[i];
                    var dirPath = sandboxPath + "/" + dir;

                    console.log("\x1b[33m[*]\x1b[0m Scanning: " + dirPath);
                    enumerateDirectory(dirPath, 0);
                }
            }

            try {
                var UIApplication = ObjC.classes.UIApplication;

                var originalDidFinishLaunching = UIApplication["- _run"];
                const origImpl = new NativeFunction(
                    originalDidFinishLaunching.implementation,
                    'void', ['pointer', 'pointer']
                );
                Interceptor.replace(originalDidFinishLaunching.implementation, new NativeCallback(function(self, sel) {
                    origImpl(self, sel);

                    setTimeout(function() {
                        scanDataProtection();
                    }, 1000);
                }, 'void', ['pointer', 'pointer']));

                console.log("\x1b[32m[+]\x1b[0m Application hook installed, scan will start after launch");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Failed to install application hook: " + e.message);
                console.log("\x1b[33m[*]\x1b[0m Running immediate scan...");
                scanDataProtection();
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Data Protection Checker error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Data Protection Checker Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
