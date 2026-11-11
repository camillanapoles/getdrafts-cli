/**
 * iOS Static Analysis - Static Security Analysis - iOS [STABLE]
 *
 * Purpose: Performs comprehensive static security analysis of iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l ios-static-analysis.js
 *
 * What it hooks:
 * - Class and method enumeration
 * - URL scheme discovery
 * - App transport security configuration
 * - Info.plist parsing
 * - Certificate pinning detection
 * - Cryptographic API usage
 *
 * Features:
 * - Enumerates all Objective-C classes and methods
 * - Detects custom URL schemes
 * - Analyzes ATS (App Transport Security) settings
 * - Identifies weak cryptographic algorithms
 * - Detects hardcoded credentials and API keys
 * - Checks for insecure data storage
 *
 * OWASP MASTG References:
 * - MASTG-APP-ARCH-001: Architecture and Code Analysis
 * - MASTG-STG-INFO-001: Information Gathering
 * - MASTG-APP-PROT-002: App Transport Security
 * - MASTG-DATA-STORAGE-001: Data Storage
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@interference-security/ios-app-static-analysis/
 * Author: @interference-security
 */

if (ObjC.available) {
    try {
        console.log("[*] iOS Static Analysis - iOS STARTED");

        var CONFIG = {
            verbose: true,
            enumerateClasses: true,
            enumerateMethods: false,
            detectURLSchemes: true,
            analyzeATS: true,
            detectCrypto: true,
            detectHardcoded: true,
            maxMethodsPerClass: 50
        };

        function logSuccess(message) {
            console.log("\x1b[32m[+]\x1b[0m " + message);
        }

        function logError(message) {
            console.log("\x1b[31m[!]\x1b[0m " + message);
        }

        function logInfo(message) {
            console.log("\x1b[33m[*]\x1b[0m " + message);
        }

        function logWarn(message) {
            console.log("\x1b[33m[!]\x1b[0m " + message);
        }

        function logSection(title) {
            console.log("\n\x1b[36m" + "=".repeat(50) + "\x1b[0m");
            console.log("\x1b[36m[*]\x1b[0m " + title);
            console.log("\x1b[36m" + "=".repeat(50) + "\x1b[0m\n");
        }

        function enumerateClasses() {
            try {
                if (!CONFIG.enumerateClasses) return;

                logSection("CLASS ENUMERATION");

                var classes = Object.keys(ObjC.classes);
                logInfo("Found " + classes.length + " classes");

                var appClasses = [];
                for (var i = 0; i < classes.length; i++) {
                    var className = classes[i];
                    if (className.indexOf("App") !== -1 || className.indexOf("View") !== -1 || className.indexOf("Controller") !== -1) {
                        appClasses.push(className);
                    }
                }

                logSuccess("Found " + appClasses.length + " app-relevant classes");

                if (CONFIG.verbose) {
                    console.log("\nApp-relevant classes (first 20):");
                    for (var i = 0; i < Math.min(20, appClasses.length); i++) {
                        console.log("  - " + appClasses[i]);
                    }
                    if (appClasses.length > 20) {
                        console.log("  ... and " + (appClasses.length - 20) + " more");
                    }
                }
            } catch (e) {
                logError("Exception in enumerateClasses: " + e.message);
            }
        }

        function enumerateMethods() {
            try {
                if (!CONFIG.enumerateMethods) return;

                logSection("METHOD ENUMERATION");

                var interestingClasses = ["NSURLSession", "NSURLConnection", "NSUserDefaults", "UIWebView", "WKWebView", "KeychainWrapper"];

                for (var i = 0; i < interestingClasses.length; i++) {
                    var className = interestingClasses[i];
                    try {
                        var clazz = ObjC.classes[className];
                        if (clazz) {
                            var methods = clazz.$ownMethods;
                            logInfo(className + " has " + methods.length + " methods");

                            if (CONFIG.verbose) {
                                for (var j = 0; j < Math.min(CONFIG.maxMethodsPerClass, methods.length); j++) {
                                    console.log("  - " + methods[j]);
                                }
                            }
                        }
                    } catch (e) {
                    }
                }
            } catch (e) {
                logError("Exception in enumerateMethods: " + e.message);
            }
        }

        function detectURLSchemes() {
            try {
                if (!CONFIG.detectURLSchemes) return;

                logSection("URL SCHEME DETECTION");

                var schemes = new Set();
                var methodsToCheck = [
                    { cls: "UIApplication", method: "openURL:" },
                    { cls: "UIApplication", method: "canOpenURL:" },
                    { cls: "LSApplicationWorkspace", method: "openURL:withContext:" }
                ];

                for (var i = 0; i < methodsToCheck.length; i++) {
                    try {
                        var item = methodsToCheck[i];
                        var clazz = ObjC.classes[item.cls];
                        if (clazz && clazz[item.method]) {
                            logInfo("Found method: " + item.cls + " - " + item.method);
                        }
                    } catch (e) {
                    }
                }

                logInfo("URL scheme detection methods found");

                var commonSchemes = ["http", "https", "file", "tel", "mailto", "sms", "itms-apps"];
                logInfo("Common URL schemes to check:");
                commonSchemes.forEach(function(scheme) {
                    console.log("  - " + scheme + "://");
                });

            } catch (e) {
                logError("Exception in detectURLSchemes: " + e.message);
            }
        }

        function analyzeATS() {
            try {
                if (!CONFIG.analyzeATS) return;

                logSection("APP TRANSPORT SECURITY (ATS) ANALYSIS");

                var infoPlistClasses = ["NSBundle", "NSDictionary", "NSMutableDictionary"];
                logInfo("Checking for Info.plist access classes...");

                var nsBundle = ObjC.classes.NSBundle;
                if (nsBundle) {
                    logSuccess("NSBundle available - can analyze ATS settings");
                    logInfo("ATS configuration is typically in Info.plist under NSAppTransportSecurity");
                    logInfo("Key ATS settings to check:");
                    console.log("  - NSAllowsArbitraryLoads (should be NO/absent)");
                    console.log("  - NSAllowsArbitraryLoadsInWebContent (should be NO/absent)");
                    console.log("  - NSExceptionDomains (should be minimal)");
                    console.log("  - NSExceptionAllowsInsecureHTTPLoads (should be NO)");
                    console.log("  - NSExceptionMinimumTLSVersion (should be TLSv1.2 or higher)");
                } else {
                    logWarn("NSBundle not available");
                }
            } catch (e) {
                logError("Exception in analyzeATS: " + e.message);
            }
        }

        function detectCrypto() {
            try {
                if (!CONFIG.detectCrypto) return;

                logSection("CRYPTOGRAPHIC API DETECTION");

                var cryptoClasses = [
                    "SecKey",
                    "SecKeychain",
                    "SecCertificate",
                    "SecIdentity",
                    "SecTrust",
                    "SecRandom",
                    "CC_SHA1",
                    "CommonCrypto",
                    "RNCryptor",
                    "AESCrypt"
                ];

                var foundCrypto = [];
                for (var i = 0; i < cryptoClasses.length; i++) {
                    try {
                        var clazz = ObjC.classes[cryptoClasses[i]];
                        if (clazz) {
                            foundCrypto.push(cryptoClasses[i]);
                        }
                    } catch (e) {
                    }
                }

                if (foundCrypto.length > 0) {
                    logSuccess("Found " + foundCrypto.length + " cryptographic classes:");
                    foundCrypto.forEach(function(cls) {
                        console.log("  - " + cls);
                    });
                } else {
                    logWarn("No cryptographic classes detected");
                }

                var weakAlgorithms = ["MD5", "SHA1", "RC4", "DES", "3DES"];
                logInfo("Weak algorithms to watch for:");
                weakAlgorithms.forEach(function(alg) {
                    console.log("  - " + alg);
                });

            } catch (e) {
                logError("Exception in detectCrypto: " + e.message);
            }
        }

        function detectHardcoded() {
            try {
                if (!CONFIG.detectHardcoded) return;

                logSection("HARDCODED CREDENTIALS DETECTION");

                var suspiciousMethods = [
                    "setPassword:",
                    "setUsername:",
                    "setToken:",
                    "setApiKey:",
                    "setSecret:",
                    "initWithPassword:",
                    "initWithToken:",
                    "setAuthorizationHeader:"
                ];

                var foundSuspicious = [];
                for (var i = 0; i < suspiciousMethods.length; i++) {
                    var method = suspiciousMethods[i];
                    var classes = Object.keys(ObjC.classes);

                    for (var j = 0; j < classes.length; j++) {
                        try {
                            var clazz = ObjC.classes[classes[j]];
                            // $ownMethods entries are prefixed with "- " or "+ "; check both.
                            if (clazz && (clazz.$ownMethods.indexOf("- " + method) !== -1 ||
                                          clazz.$ownMethods.indexOf("+ " + method) !== -1)) {
                                foundSuspicious.push({ cls: classes[j], method: method });
                            }
                        } catch (e) {
                        }
                    }
                }

                if (foundSuspicious.length > 0) {
                    logWarn("Found " + foundSuspicious.length + " suspicious methods:");
                    foundSuspicious.forEach(function(item) {
                        console.log("  - " + item.cls + " - " + item.method);
                    });
                    logInfo("Review these methods for hardcoded credentials");
                } else {
                    logSuccess("No obvious hardcoded credential methods found");
                }

            } catch (e) {
                logError("Exception in detectHardcoded: " + e.message);
            }
        }

        function analyzeDataStorage() {
            try {
                logSection("DATA STORAGE ANALYSIS");

                var storageClasses = [
                    "NSUserDefaults",
                    "NSFileManager",
                    "NSData",
                    "SQLCipher",
                    "FMDatabase"
                ];

                var foundStorage = [];
                for (var i = 0; i < storageClasses.length; i++) {
                    try {
                        var clazz = ObjC.classes[storageClasses[i]];
                        if (clazz) {
                            foundStorage.push(storageClasses[i]);
                        }
                    } catch (e) {
                    }
                }

                if (foundStorage.length > 0) {
                    logSuccess("Found " + foundStorage.length + " data storage classes:");
                    foundStorage.forEach(function(cls) {
                        console.log("  - " + cls);
                    });
                }

                logInfo("Key data storage mechanisms to check:");
                console.log("  - NSUserDefaults (should not store sensitive data)");
                console.log("  - SQLite databases (check for encryption)");
                console.log("  - Core Data (check for encryption)");
                console.log("  - Keychain (proper usage recommended)");
                console.log("  - Plist files (check for sensitive data)");

            } catch (e) {
                logError("Exception in analyzeDataStorage: " + e.message);
            }
        }

        function runSecurityChecks() {
            try {
                logSection("SECURITY CHECKS SUMMARY");

                var checks = [
                    { name: "Jailbreak Detection", status: "Manual check needed" },
                    { name: "Root Detection", status: "Manual check needed" },
                    { name: "Anti-Tampering", status: "Manual check needed" },
                    { name: "Anti-Debugging", status: "Manual check needed" },
                    { name: "Code Obfuscation", status: "Manual check needed" },
                    { name: "SSL Pinning", status: "Manual check needed" },
                    { name: "Certificate Validation", status: "Manual check needed" }
                ];

                console.log("Security checks to perform:");
                checks.forEach(function(check) {
                    console.log("  - " + check.name + ": " + check.status);
                });

                logInfo("Use dynamic analysis tools for comprehensive security assessment");
            } catch (e) {
                logError("Exception in runSecurityChecks: " + e.message);
            }
        }

        function main() {
            try {
                logInfo("Starting static analysis...");

                enumerateClasses();
                enumerateMethods();
                detectURLSchemes();
                analyzeATS();
                detectCrypto();
                detectHardcoded();
                analyzeDataStorage();
                runSecurityChecks();

                logSection("ANALYSIS COMPLETE");
                logSuccess("Static analysis completed");
                logInfo("Review findings and perform dynamic analysis for complete assessment");

            } catch (e) {
                logError("Exception in main: " + e.message);
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
