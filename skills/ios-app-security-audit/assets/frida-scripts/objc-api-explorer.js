/**
 * ObjC API Explorer - Comprehensive iOS Instrumentation [STABLE]
 *
 * Purpose: Advanced Objective-C runtime exploration and instrumentation
 * Usage: frida -U -f <BUNDLE_ID> -l objc-api-explorer.js
 *
 * Features:
 * - ObjC API discovery and enumeration
 * - Method hooking patterns with argument extraction
 * - NSURL initialization monitoring
 * - NSFileManager file access tracking
 * - CFDataRef data extraction
 * - CryptoKit AES encryption monitoring
 * - Swift data type handling
 * - Security finding classification with CVSS severity
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0071: Method Analysis
 * - MASTG-TEST-0051: Runtime Analysis
 * - MASTG-TEST-0075: Method Tracing
 * - MASTG-STORAGE-002: File System Access
 * - MASTG-CRYPTO-001: Cryptographic Implementation
 * - MASTG-NETWORK-1: Communication Security
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    try {
        console.log("[*] ObjC API Explorer - iOS STARTED");

        var CONFIG = {
            monitorURLInit: true,
            monitorFileAccess: true,
            monitorCrypto: true,
            verboseLogging: false,
            maxDataLength: 200,
            colorOutput: true
        };

        function checkObjCAvailability() {
            console.log("\x1b[31m[🔴 CRITICAL]\x1b[0m " + message);
        }

        function logHigh(message) {
            console.log("\x1b[33m[🟠 HIGH]\x1b[0m " + message);
        }

        function logMedium(message) {
            console.log("\x1b[33m[🟡 MEDIUM]\x1b[0m " + message);
        }

        function logLow(message) {
            console.log("\x1b[32m[🟢 LOW]\x1b[0m " + message);
        }

        function logInfo(message) {
            console.log("\x1b[36m[*]\x1b[0m " + message);
        }

        function logSuccess(message) {
            console.log("\x1b[32m[+]\x1b[0m " + message);
        }

        function logError(message) {
            console.log("\x1b[31m[!]\x1b[0m " + message);
        }

        function getTimestamp() {
            var date = new Date();
            return date.toISOString().substr(11, 12);
        }

        function truncateString(str, maxLength) {
            if (!str) {
                return "null";
            }
            maxLength = maxLength || CONFIG.maxDataLength;
            if (str.length <= maxLength) {
                return str;
            }
            return str.substring(0, maxLength) + "...";
        }

        function formatObjCValue(value) {
            try {
                if (!value) {
                    return "null";
                }

                if (typeof value === "object" && value.handle) {
                    try {
                        var obj = new ObjC.Object(value);
                        return obj.toString();
                    } catch (e) {
                        return ptr(value);
                    }
                }

                if (typeof value.toString === "function") {
                    return truncateString(value.toString());
                }

                return String(value);
            } catch (e) {
                return String(value);
            }
        }

        function hexDump(buffer, length) {
            var output = "";
            var bytes = new Uint8Array(buffer);
            length = Math.min(length, bytes.length);

            for (var i = 0; i < length; i++) {
                output += bytes[i].toString(16).padStart(2, "0") + " ";
                if ((i + 1) % 16 === 0) {
                    output += "\n  ";
                }
            }
            return output;
        }

        function checkObjCAvailability() {
            if (ObjC.available) {
                logSuccess("Objective-C runtime available");

                // Total classes
                var classCount = Object.keys(ObjC.classes).length;
                logInfo("Total classes loaded: " + classCount);

                return true;
            } else {
                logError("Objective-C runtime NOT available");
                return false;
            }
        }

        function enumerateClasses() {
            logInfo("\nEnumerating Objective-C classes...");

            var allClasses = Object.keys(ObjC.classes);
            var sampleSize = Math.min(10, allClasses.length);

            logInfo("Sample classes (" + sampleSize + " of " + allClasses.length + "):");
            for (var i = 0; i < sampleSize; i++) {
                logInfo("  - " + allClasses[i]);
            }
        }

        function exploreClass(className) {
            var clazz = ObjC.classes[className];
            if (!clazz) {
                logError("Class not found: " + className);
                return;
            }

            console.log("\n=== Class: " + className + " ===");

            // $ownMethods - Only methods defined by this class
            console.log("\nOwn methods: " + clazz.$ownMethods.length);
            if (CONFIG.verboseLogging) {
                clazz.$ownMethods.forEach(function(method) {
                    console.log("  " + method);
                });
            }

            // $methods - All methods including inherited
            console.log("All methods: " + clazz.$methods.length);

            // $moduleName - Framework the class belongs to
            if (clazz.$moduleName) {
                console.log("Framework: " + clazz.$moduleName);
            }
        }

        function hookMethod(className, methodName, onEnter, onLeave) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return;
                }

                var method = clazz[methodName];
                if (!method) {
                    logError("Method not found: " + className + " " + methodName);
                    return;
                }

                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        // args[0] = self (the object instance)
                        // args[1] = selector (method name)
                        // args[2] = first argument
                        // args[3] = second argument (if multiple args)

                        if (onEnter) {
                            try {
                                var self = ObjC.Object(args[0]);
                                var selector = ObjC.selectorAsString(args[1]);

                                var context = {
                                    self: self,
                                    selector: selector,
                                    args: args
                                };

                                onEnter(context);
                            } catch (e) {
                                logError("Exception in onEnter: " + e.message);
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (onLeave) {
                            try {
                                var returnValue = ObjC.Object(retval);
                                onLeave(returnValue);
                            } catch (e) {
                                onLeave(retval);
                            }
                        }
                    }
                });

                logSuccess("Hooked: " + className + " " + methodName);
            } catch (e) {
                logError("Exception in hookMethod: " + e.message);
            }
        }

        function monitorNSURLInitialization() {
            if (!CONFIG.monitorURLInit) {
                return;
            }

            logInfo("\n=== Monitoring NSURL Initialization ===");

            // Hook -[NSURL initWithString:]
            hookMethod("NSURL", "- initWithString:", function(context) {
                if (!context.args[2] || context.args[2].isNull()) return;
                var urlStr = new ObjC.Object(context.args[2]);
                var urlString = urlStr.toString();

                logInfo("NSURL init: " + urlString);

                // Check for sensitive data
                if (urlString.includes("token=") || urlString.includes("api_key=")) {
                    logCritical("Token detected in URL initialization!");
                    console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
                    console.log("  URL: " + urlString);
                } else if (urlString.includes("password=") || urlString.includes("secret=")) {
                    logHigh("Credentials detected in URL initialization!");
                    console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N");
                    console.log("  URL: " + urlString);
                }

                // Check for OAuth codes
                if (urlString.includes("code=") && urlString.includes("state=")) {
                    logHigh("OAuth authorization code detected!");
                    console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
                    console.log("  URL: " + urlString);
                }

                // Check for bearer tokens
                if (urlString.includes("bearer") || urlString.includes("Bearer")) {
                    logHigh("Bearer token detected in URL!");
                    console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
                    console.log("  URL: " + urlString);
                }

            }, function(retval) {
                // Optional: log return value
            });

            // Hook -[NSURL URLWithString:]
            hookMethod("NSURL", "+ URLWithString:", function(context) {
                if (!context.args[2] || context.args[2].isNull()) return;
                var urlStr = new ObjC.Object(context.args[2]);
                var urlString = urlStr.toString();

                logInfo("NSURL URLWithString: " + urlString);

                // Same checks as initWithString:
                if (urlString.includes("token=") || urlString.includes("api_key=")) {
                    logCritical("Token detected in URL initialization!");
                    console.log("  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
                    console.log("  URL: " + urlString);
                }
            }, null);
        }

        function monitorFileAccess() {
            if (!CONFIG.monitorFileAccess) {
                return;
            }

            logInfo("\n=== Monitoring NSFileManager File Access ===");

            // Hook -[NSFileManager fileExistsAtPath:]
            hookMethod("NSFileManager", "- fileExistsAtPath:", function(context) {
                if (!context.args[2] || context.args[2].isNull()) return;
                var pathObj = new ObjC.Object(context.args[2]);
                var filePath = pathObj.toString();

                logInfo("File check: " + filePath);

                // Check for sensitive paths
                if (filePath.includes("private") || filePath.includes("etc/passwd")) {
                    logHigh("Access to sensitive system path!");
                    console.log("  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N");
                    console.log("  Path: " + filePath);
                }

                // Check for keychain access
                if (filePath.includes("keychain") || filePath.includes(".db")) {
                    logMedium("Potential keychain/database access");
                    console.log("  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N");
                    console.log("  Path: " + filePath);
                }
            }, null);

            // Hook -[NSFileManager fileExistsAtPath:isDirectory:]
            hookMethod("NSFileManager", "- fileExistsAtPath:isDirectory:", function(context) {
                if (!context.args[2] || context.args[2].isNull()) return;
                var pathObj = new ObjC.Object(context.args[2]);
                var filePath = pathObj.toString();

                logInfo("File check (with dir): " + filePath);

                if (filePath.includes("private") || filePath.includes("etc")) {
                    logHigh("Access to sensitive system path!");
                    console.log("  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N");
                    console.log("  Path: " + filePath);
                }
            }, null);

            // Hook -[NSFileManager contentsOfDirectoryAtPath:]
            hookMethod("NSFileManager", "- contentsOfDirectoryAtPath:", function(context) {
                if (!context.args[2] || context.args[2].isNull()) return;
                var pathObj = new ObjC.Object(context.args[2]);
                var filePath = pathObj.toString();

                logInfo("Directory listing: " + filePath);

                if (filePath.includes("Documents") || filePath.includes("Library")) {
                    logMedium("Access to app data directory");
                    console.log("  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N");
                    console.log("  Path: " + filePath);
                }
            }, null);
        }

        function readCFData(cfDataRef) {
            try {
                var cfData = new ObjC.Object(cfDataRef);

                // Check if it has bytes() method
                if (cfData.bytes) {
                    var bytes = cfData.bytes();
                    var length = cfData.length();

                    if (length && length.toInt32 && length.toInt32() > 0) {
                        var len = length.toInt32();
                        var string = bytes.readUtf8String(len);

                        return {
                            data: string,
                            length: len,
                            hex: hexDump(bytes, Math.min(32, len))
                        };
                    }
                }

                return null;
            } catch (e) {
                logError("Exception reading CFData: " + e.message);
                return null;
            }
        }

        function hookCFDataMethods() {
            logInfo("\n=== Monitoring CFData Operations ===");

            // Hook NSData methods that may contain CFData
            var NSData = ObjC.classes.NSData;

            // Hook dataWithBytes:length:
            hookMethod("NSData", "+ dataWithBytes:length:", function(context) {
                var bytesPtr = context.args[2];
                var length = context.args[3].toInt32();

                if (length > 0 && length < 10000 && bytesPtr && !bytesPtr.isNull()) {
                    var dataStr = bytesPtr.readUtf8String(length);
                    logInfo("NSData creation with " + length + " bytes");

                    // Check for sensitive data patterns
                    if (dataStr && (dataStr.includes("token") || dataStr.includes("password"))) {
                        logHigh("Sensitive data in NSData!");
                        console.log("  CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N");
                        console.log("  Data: " + truncateString(dataStr, 100));
                    }
                }
            }, null);
        }

        function monitorCryptoKit() {
            if (!CONFIG.monitorCrypto) {
                return;
            }

            logInfo("\n=== Monitoring CryptoKit Operations ===");

            // Find CryptoKit symbols
            var modules = Process.enumerateModules();
            var cryptoKitModule = null;

            for (var i = 0; i < modules.length; i++) {
                if (modules[i].name.includes("CryptoKit")) {
                    cryptoKitModule = modules[i];
                    break;
                }
            }

            if (cryptoKitModule) {
                logInfo("CryptoKit module found: " + cryptoKitModule.name);

                // Enumerate exports to find AES.GCM.seal functions
                var exports = cryptoKitModule.enumerateExports();

                exports.forEach(function(exp) {
                    if (exp.name.includes("AES") && exp.name.includes("seal")) {
                        logInfo("Found CryptoKit seal function: " + exp.name);

                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                logInfo("CryptoKit AES.GCM.seal called");
                                logCritical("AES encryption detected - extracting plaintext!");
                                console.log("  CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N");

                                // Try to extract data from args
                                // Note: The exact parameter positions depend on Swift ABI
                                for (var i = 0; i < 8; i++) {
                                    try {
                                        var argData = readCFData(args[i]);
                                        if (argData && argData.data.length > 0) {
                                            logInfo("  Arg " + i + " data: " + truncateString(argData.data, 100));
                                            logInfo("  Hex: " + argData.hex);
                                        }
                                    } catch (e) {
                                        // Ignore
                                    }
                                }
                            },
                            onLeave: function(retval) {
                                // Try to read encrypted output
                                try {
                                    var outputData = readCFData(retval);
                                    if (outputData && outputData.data.length > 0) {
                                        logInfo("  Encrypted output length: " + outputData.length);
                                        logInfo("  Hex: " + outputData.hex);
                                    }
                                } catch (e) {
                                }
                            }
                        });

                        logSuccess("Hooked: " + exp.name);
                    }
                });
            } else {
                logInfo("CryptoKit module not found in process");
            }
        }

        function readSwiftString(swiftString) {
            try {
                // Swift strings have different internal representations
                // This is a simplified approach - real Swift string handling is more complex

                var obj = new ObjC.Object(swiftString);

                // Try standard Objective-C methods first
                if (obj.toString) {
                    return obj.toString();
                }

                // Try accessing as NSString
                var str = obj.toString();

                if (str && str.length > 0) {
                    return str;
                }

                return null;
            } catch (e) {
                return null;
            }
        }

        function hookSwiftMethods() {
            logInfo("\n=== Monitoring Swift Methods ===");

            // Find classes that might be Swift classes
            var allClasses = Object.keys(ObjC.classes);
            var swiftClasses = [];

            for (var i = 0; i < allClasses.length; i++) {
                var className = allClasses[i];

                // Swift classes often have specific naming patterns
                if (className.includes("_Tt") || className.match(/^\d+/)) {
                    swiftClasses.push(className);
                }
            }

            logInfo("Found " + swiftClasses.length + " potential Swift classes");

            // Hook common Swift method patterns
        }

        function resolveObjCMethods(pattern) {
            logInfo("\n=== Resolving ObjC Methods: " + pattern + " ===");

            try {
                var resolver = new ApiResolver('objc');
                var matches = resolver.enumerateMatchesSync(pattern);

                logInfo("Found " + matches.length + " matches");

                matches.forEach(function(match) {
                    console.log("  Name: " + match.name);
                    console.log("  Address: " + match.address);

                    // Optionally hook the method
                    if (match.name.includes("fileExists") || match.name.includes("URL")) {
                        Interceptor.attach(ptr(match.address), {
                            onEnter: function(args) {
                                logInfo("Called: " + match.name);

                                // Try to extract arguments
                                if (args[2]) {
                                    try {
                                        var argObj = new ObjC.Object(args[2]);
                                        var argStr = argObj.toString();
                                        logInfo("  Arg: " + truncateString(argStr, 100));
                                    } catch (e) {
                                    }
                                }
                            }
                        });
                        logSuccess("Hooked: " + match.name);
                    }
                });

                return matches;
            } catch (e) {
                logError("Exception in resolveObjCMethods: " + e.message);
                return [];
            }
        }

        function main() {
            try {
                // Check ObjC availability
                if (!checkObjCAvailability()) {
                    return;
                }

                // Enumerate classes
                enumerateClasses();

                // Explore security-relevant classes
                logInfo("\n=== Exploring Security-Relevant Classes ===");
                var securityClasses = [
                    "NSURL",
                    "NSURLSession",
                    "NSFileManager",
                    "NSUserDefaults",
                    "SecKey",
                    "SecCertificate"
                ];

                securityClasses.forEach(function(className) {
                    try {
                        exploreClass(className);
                    } catch (e) {
                    }
                });

                // Start monitoring
                monitorNSURLInitialization();
                monitorFileAccess();
                hookCFDataMethods();
                monitorCryptoKit();
                hookSwiftMethods();

                // Resolve methods using ApiResolver
                resolveObjCMethods("-[* fileExists*]");
                resolveObjCMethods("-[* URL*]");

                logSuccess("\n=== ObjC API Explorer Ready ===");
                logInfo("Monitoring active. Interact with the app to see findings.");

                // Display configuration
                logInfo("\nConfiguration:");
                console.log("  monitorURLInit: " + CONFIG.monitorURLInit);
                console.log("  monitorFileAccess: " + CONFIG.monitorFileAccess);
                console.log("  monitorCrypto: " + CONFIG.monitorCrypto);
                console.log("  verboseLogging: " + CONFIG.verboseLogging);

            } catch (e) {
                logError("Exception in main: " + e.message);
                console.log(e.stack);
            }
        }

        main();

    } catch (e) {
        console.log("\x1b[31m[!] ERROR: " + e.message + "\x1b[0m");
        console.log(e.stack);
    }
} else {
    console.log("[!] Objective-C runtime not available - this script requires an iOS target");
}
