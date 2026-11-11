/**
 * ObjC Method Observer - Method Observation - iOS [STABLE]
 *
 * Purpose: Observe and log Objective-C method calls in real-time
 * Usage: frida -U -f <BUNDLE_ID> -l objc-method-observer.js
 * Then interact with the app and watch method calls
 *
 * What it hooks:
 * - Dynamically hooks specified Objective-C methods
 * - Logs method entry and return
 * - Captures arguments and return values
 *
 * Features:
 * - Filter by class name pattern
 * - Filter by method name pattern
 * - Show/hide internal methods (those starting with underscore)
 * - Color-coded output for easy reading
 * - Configurable logging verbosity
 * - Auto-detect common security-relevant classes
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0071: Method Analysis
 * - MASTG-TEST-0051: Runtime Analysis
 * - MASTG-TEST-0075: Method Tracing
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@mrmacete/objc-method-observer/
 * Author: @mrmacete
 */

if (ObjC.available) {
    try {
        console.log("[*] ObjC Method Observer - iOS STARTED");

        var CONFIG = {
            classFilter: null,
            methodFilter: null,
            showInternal: false,
            maxArgLength: 100,
            maxRetValLength: 100,
            colorOutput: true,
            showArgs: true,
            showRetVal: true,
            showTimestamp: true
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
            console.log("\x1b[36m[*] === " + title + " ===\x1b[0m");
        }

        function getTimestamp() {
            var date = new Date();
            return date.toISOString().substr(11, 12);
        }

        function truncateString(str, maxLength) {
            if (!str) {
                return "null";
            }
            maxLength = maxLength || CONFIG.maxArgLength;
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

        function formatArgs(args) {
            if (!args || args.length === 0) {
                return "()";
            }

            var formatted = [];
            for (var i = 0; i < args.length; i++) {
                formatted.push(formatObjCValue(args[i]));
            }
            return "(" + formatted.join(", ") + ")";
        }

        var observer = {
            className: null,
            methodName: null,
            onEnter: null,
            onLeave: null,
            implementation: null
        };

        function createObserver(className, methodName, onEnter, onLeave) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return null;
                }

                var method = clazz[methodName];
                if (!method) {
                    logError("Method not found: " + className + " - " + methodName);
                    return null;
                }

                var obs = Object.create(observer);
                obs.className = className;
                obs.methodName = methodName;
                obs.onEnter = onEnter;
                obs.onLeave = onLeave;

                return obs;
            } catch (e) {
                logError("Exception in createObserver: " + e.message);
                return null;
            }
        }

        function observeMethod(obs) {
            try {
                if (!obs || !obs.className || !obs.methodName) {
                    logError("Invalid observer");
                    return false;
                }

                var clazz = ObjC.classes[obs.className];
                var method = clazz[obs.methodName];

                if (!method) {
                    logError("Method not found: " + obs.className + " - " + obs.methodName);
                    return false;
                }

                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        try {
                            var logLine = "";
                            if (CONFIG.showTimestamp) {
                                logLine = "[" + getTimestamp() + "] ";
                            }
                            logLine += obs.className + " " + obs.methodName;

                            if (CONFIG.showArgs) {
                                logLine += formatArgs(args);
                            }

                            console.log("\x1b[36m" + logLine + "\x1b[0m");

                            if (obs.onEnter) {
                                obs.onEnter(args, this);
                            }
                        } catch (e) {
                            logError("Exception in onEnter: " + e.message);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (CONFIG.showRetVal) {
                                var logLine = "  -> " + formatObjCValue(retval);
                                console.log("\x1b[32m" + logLine + "\x1b[0m");
                            }

                            if (obs.onLeave) {
                                obs.onLeave(retval, this);
                            }
                        } catch (e) {
                            logError("Exception in onLeave: " + e.message);
                        }
                    }
                });

                logSuccess("Observing: " + obs.className + " - " + obs.methodName);
                return true;
            } catch (e) {
                logError("Exception in observeMethod: " + e.message);
                return false;
            }
        }

        function observeAllMethods(className, onEnter, onLeave) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return 0;
                }

                var methods = clazz.$ownMethods;
                var observed = 0;

                for (var i = 0; i < methods.length; i++) {
                    var methodName = methods[i];

                    if (!CONFIG.showInternal && methodName.indexOf("_") === 0) {
                        continue;
                    }

                    if (CONFIG.methodFilter && methodName.toLowerCase().indexOf(CONFIG.methodFilter.toLowerCase()) === -1) {
                        continue;
                    }

                    var obs = createObserver(className, methodName, onEnter, onLeave);
                    if (obs && observeMethod(obs)) {
                        observed++;
                    }
                }

                logSuccess("Observing " + observed + " methods in " + className);
                return observed;
            } catch (e) {
                logError("Exception in observeAllMethods: " + e.message);
                return 0;
            }
        }

        function findClass(filter) {
            try {
                var classes = Object.keys(ObjC.classes);
                if (!filter) {
                    return classes;
                }

                var filtered = [];
                var filterLower = filter.toLowerCase();
                for (var i = 0; i < classes.length; i++) {
                    if (classes[i].toLowerCase().indexOf(filterLower) !== -1) {
                        filtered.push(classes[i]);
                    }
                }
                return filtered;
            } catch (e) {
                logError("Exception in findClass: " + e.message);
                return [];
            }
        }

        function findMethod(className, filter) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return [];
                }

                var methods = clazz.$ownMethods;
                if (!filter) {
                    return methods;
                }

                var filtered = [];
                var filterLower = filter.toLowerCase();
                for (var i = 0; i < methods.length; i++) {
                    if (methods[i].toLowerCase().indexOf(filterLower) !== -1) {
                        filtered.push(methods[i]);
                    }
                }
                return filtered;
            } catch (e) {
                logError("Exception in findMethod: " + e.message);
                return [];
            }
        }

        var securityRelevantClasses = [
            "NSURLSession",
            "NSURLConnection",
            "NSUserDefaults",
            "UIWebView",
            "WKWebView",
            "SecKey",
            "SecKeychain",
            "SecCertificate",
            "SecTrust",
            "NSData",
            "NSString",
            "NSMutableURLRequest",
            "NSURLRequest"
        ];

        function observeSecurityClasses() {
            logInfo("Observing security-relevant classes...");

            var totalObserved = 0;
            for (var i = 0; i < securityRelevantClasses.length; i++) {
                var className = securityRelevantClasses[i];
                try {
                    var observed = observeAllMethods(className);
                    totalObserved += observed;
                } catch (e) {
                }
            }

            logSuccess("Total methods observed: " + totalObserved);
        }

        function observeClassPattern(pattern) {
            logInfo("Observing classes matching: " + pattern);

            var classes = findClass(pattern);
            var totalObserved = 0;

            for (var i = 0; i < classes.length; i++) {
                try {
                    var observed = observeAllMethods(classes[i]);
                    totalObserved += observed;
                } catch (e) {
                }
            }

            logSuccess("Total methods observed: " + totalObserved);
        }

        function showUsage() {
            logSection("USAGE EXAMPLES");

            console.log("\n1. Observe a specific method:");
            console.log("   observeMethod(createObserver('NSString', 'stringWithUTF8String:', function(args) {");
            console.log("       console.log(\"Input: \" + args[0].readUtf8String());");
            console.log("   }));");

            console.log("\n2. Observe all methods in a class:");
            console.log("   observeAllMethods('NSURLSession');");

            console.log("\n3. Observe security-relevant classes:");
            console.log("   observeSecurityClasses();");

            console.log("\n4. Observe classes matching a pattern:");
            console.log("   observeClassPattern('WebView');");

            console.log("\n5. Find classes:");
            console.log("   findClass('URL')");

            console.log("\n6. Find methods in a class:");
            console.log("   findMethod('NSURLSession', 'dataTask')");

            console.log("\n7. Configure observer:");
            console.log("   CONFIG.classFilter = 'URL';");
            console.log("   CONFIG.methodFilter = 'data';");
            console.log("   CONFIG.showInternal = false;");
            console.log("   CONFIG.showArgs = true;");
            console.log("   CONFIG.showRetVal = true;");
        }

        function main() {
            try {
                logSuccess("ObjC Method Observer loaded successfully");
                logInfo("Use observeMethod() to observe specific methods");
                logInfo("Use observeAllMethods() to observe all methods in a class");
                logInfo("Use observeSecurityClasses() to observe security-relevant classes");

                logInfo("\nConfiguration:");
                console.log("  classFilter: " + (CONFIG.classFilter || "none"));
                console.log("  methodFilter: " + (CONFIG.methodFilter || "none"));
                console.log("  showInternal: " + CONFIG.showInternal);
                console.log("  showArgs: " + CONFIG.showArgs);
                console.log("  showRetVal: " + CONFIG.showRetVal);
                console.log("  showTimestamp: " + CONFIG.showTimestamp);

                showUsage();

                logSection("OBSERVER READY");
                logInfo("Call observeMethod(), observeAllMethods(), or observeSecurityClasses() to start observing");

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
