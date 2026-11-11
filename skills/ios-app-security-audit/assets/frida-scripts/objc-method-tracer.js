/**
 * OBJC METHOD TRACER - iOS [STABLE]
 *
 * Purpose: Generic Objective-C method tracer for iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l objc-method-tracer.js
 *        or
 *        frida -U <BUNDLE_ID> -l objc-method-tracer.js
 *
 * What it does:
 * - Dynamically trace all methods of a specific class
 * - Log method calls with arguments
 * - Log return values
 * - Show backtraces (optional)
 * - Filter methods by regex pattern
 *
 * Configuration:
 * - CONFIG.targetClass: Class name to trace (required)
 * - CONFIG.methodFilter: Regex to filter methods (optional)
 * - CONFIG.includeGetters: Include property getters (default: false)
 * - CONFIG.verbose: Show backtraces and details (default: false)
 * - CONFIG.logArgs: Log method arguments (default: true)
 * - CONFIG.logReturn: Log return values (default: true)
 *
 * Features:
 * - Supports instance (-) and class (+) methods
 * - Method name filtering with regex
 * - Argument type detection and formatting
 * - Return value detection and formatting
 * - Backtrace support for debugging
 *
 * OWASP MASTG References:
 * - MASTG-APP-001: Dynamic Analysis
 * - MASTG-TECH-004: Runtime Manipulation
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] OBJC METHOD TRACER - iOS STARTED");
    console.log("[*] ================================================");

    var CONFIG = {
        // Target class to trace (required)
        targetClass: "",

        // Regex filter for method names (optional, empty = all)
        methodFilter: "",

        // Include property getters
        includeGetters: false,

        // Verbose mode (show backtraces and details)
        verbose: false,

        // Log method arguments
        logArgs: true,

        // Log return values
        logReturn: true,

        // Maximum argument string length
        maxArgLength: 200,

        // Maximum backtrace depth
        backtraceDepth: 8,

        // Color codes
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue
            debug: "\x1b[36m"       // Cyan
        }
    };

    var hooksApplied = 0;
    var methodCallCount = 0;

    function logSuccess(message) {
        console.log(CONFIG.colors.success + CONFIG.colors.bright + "[+]\x1b[0m " + message);
    }

    function logError(message) {
        console.log(CONFIG.colors.error + CONFIG.colors.bright + "[!]\x1b[0m " + message);
    }

    function logWarn(message) {
        console.log(CONFIG.colors.warn + CONFIG.colors.bright + "[*]\x1b[0m " + message);
    }

    function logInfo(message) {
        console.log(CONFIG.colors.info + CONFIG.colors.bright + "[i]\x1b[0m " + message);
    }

    function logDebug(message) {
        console.log(CONFIG.colors.debug + CONFIG.colors.bright + "[d]\x1b[0m " + message);
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function formatArgument(arg, argType) {
        if (arg === null || arg === undefined) {
            return "nil";
        }

        try {
            var ptr = new NativePointer(arg);

            if (ptr.isNull()) {
                return "nil";
            }

            // Try to interpret as ObjC object
            try {
                var obj = new ObjC.Object(ptr);
                var className = obj.$className;

                if (className === "NSString") {
                    return '"' + obj.toString() + '"';
                } else if (className === "NSNumber") {
                    return obj.toString();
                } else if (className === "NSDate") {
                    return obj.description().toString();
                } else if (className === "__NSCFBoolean") {
                    return obj.toString();
                } else if (className === "__NSCFString") {
                    return '"' + obj.toString() + '"';
                } else {
                    return "<" + className + ": " + ptr + ">";
                }
            } catch (e) {
                // Not an ObjC object, treat as raw pointer
                return "0x" + ptr.toString(16);
            }
        } catch (e) {
            return String(arg);
        }
    }

    function formatReturnValue(retval, retType) {
        if (retval === null || retval === undefined) {
            return "nil";
        }

        try {
            var ptr = new NativePointer(retval);

            if (ptr.isNull()) {
                return "nil";
            }

            // Try to interpret as ObjC object
            try {
                var obj = new ObjC.Object(ptr);
                var className = obj.$className;

                if (className === "NSString") {
                    return '"' + obj.toString() + '"';
                } else if (className === "NSNumber") {
                    return obj.toString();
                } else if (className === "__NSCFBoolean") {
                    return obj.toString();
                } else {
                    return "<" + className + ": " + ptr + ">";
                }
            } catch (e) {
                return "0x" + ptr.toString(16);
            }
        } catch (e) {
            return String(retval);
        }
    }

    function shouldTraceMethod(methodName) {
        // Skip getters if not included
        if (!CONFIG.includeGetters) {
            if (/^is[A-Z]/.test(methodName) || /^has[A-Z]/.test(methodName)) {
                return false;
            }
        }

        // Apply method filter
        if (CONFIG.methodFilter) {
            try {
                var filter = new RegExp(CONFIG.methodFilter);
                return filter.test(methodName);
            } catch (e) {
                logError("Invalid method filter regex: " + e.message);
                return true;
            }
        }

        return true;
    }

    function getBacktrace(invocationContext) {
        if (!CONFIG.verbose) {
            return "";
        }

        try {
            var backtrace = Thread.backtrace(invocationContext, Backtracer.ACCURATE);
            var traceStr = "\n    Backtrace:";
            var depth = Math.min(backtrace.length, CONFIG.backtraceDepth);

            for (var i = 0; i < depth; i++) {
                var symbol = DebugSymbol.fromAddress(backtrace[i]);
                traceStr += "\n      " + symbol.name + " (" + symbol.address + ")";
            }

            return traceStr;
        } catch (e) {
            return "";
        }
    }

    function parseMethodSignature(methodName) {
        var parts = methodName.split(':');
        var isInstanceMethod = methodName.startsWith('-');
        var cleanName = methodName.substring(1).trim();

        return {
            type: isInstanceMethod ? 'instance' : 'class',
            name: cleanName,
            parts: parts,
            argCount: Math.max(0, parts.length - 1)
        };
    }

    function traceClass(className) {
        try {
            var targetClass = ObjC.classes[className];

            if (!targetClass) {
                logError("Class not found: " + className);
                return 0;
            }

            logSuccess("Tracing class: " + className);

            var ownMethods = targetClass.$ownMethods;
            logInfo("Found " + ownMethods.length + " own methods");

            var hooks = 0;

            for (var i = 0; i < ownMethods.length; i++) {
                var methodName = ownMethods[i];

                if (!shouldTraceMethod(methodName)) {
                    continue;
                }

                try {
                    var method = targetClass[methodName];

                    if (method) {
                        var originalImpl = method.implementation;
                        var methodSig = parseMethodSignature(methodName);

                        (function(capturedMethod, capturedImpl, capturedSig, capturedName) {
                            const origFn = new NativeFunction(capturedImpl, 'pointer', ['pointer', 'pointer', '...']);
                            Interceptor.replace(capturedMethod.implementation, new NativeCallback(function() {
                                // arguments: self, sel, [methodArgs...]
                                var self = arguments[0];
                                var sel = arguments[1];

                                methodCallCount++;

                                var args = [];
                                if (CONFIG.logArgs) {
                                    // skip self (0) and sel (1); log the actual method args
                                    for (var j = 2; j < arguments.length; j++) {
                                        var argStr = formatArgument(arguments[j]);
                                        args.push(truncate(argStr, CONFIG.maxArgLength));
                                    }
                                }

                                var logPrefix = capturedSig.type === 'instance' ? '-' : '+';
                                var logArgs = args.length > 0 ? ':' + args.join(' :') : '';

                                console.log("");
                                logSuccess("Method Call #" + methodCallCount + ": [" + className + " " + logPrefix + "]" + capturedName + logArgs);

                                if (CONFIG.verbose) {
                                    logDebug("  Method type: " + capturedSig.type);
                                    logDebug("  Argument count: " + (arguments.length - 2));
                                }

                                var result = capturedImpl.apply(null, arguments);

                                if (CONFIG.logReturn) {
                                    var retStr = formatReturnValue(result);
                                    logInfo("  Return: " + truncate(retStr, CONFIG.maxArgLength));
                                }

                                if (CONFIG.verbose) {
                                    var backtrace = getBacktrace(null);
                                    if (backtrace) {
                                        console.log(backtrace);
                                    }
                                }

                                return result;
                            }, 'pointer', ['pointer', 'pointer', '...']));
                        })(method, originalImpl, methodSig, methodName);

                        hooks++;

                        if (hooks <= 10) {
                            logInfo("  Hooked: " + methodName);
                        }
                    }
                } catch (e) {
                    // Method hooking failed, continue
                    if (CONFIG.verbose) {
                        logError("  Failed to hook " + methodName + ": " + e.message);
                    }
                }
            }

            if (hooks > 10) {
                logInfo("  ... and " + (hooks - 10) + " more methods");
            }

            return hooks;
        } catch (e) {
            logError("Error tracing class " + className + ": " + e.message);
            return 0;
        }
    }

    try {
        if (!CONFIG.targetClass) {
            logError("CONFIG.targetClass is required!");
            console.log("");
            logWarn("Usage:");
            logWarn("  frida -U -f <BUNDLE_ID> -l objc-method-tracer.js");
            logWarn("");
            logWarn("  Then in Frida REPL:");
            logWarn("    CONFIG.targetClass = 'YourClassName'");
            logWarn("    traceClass(CONFIG.targetClass)");
            console.log("");
        } else {
            var hooks = traceClass(CONFIG.targetClass);

            console.log("");
            console.log("[*] ================================================");
            console.log("[*] Total methods hooked: " + hooks);
            console.log("[*] Method calls traced: " + methodCallCount);
            console.log("[*] ObjC Method Tracer Ready");
            console.log("[*] ================================================");
            console.log("");
            logInfo("To trace another class:");
            logInfo("  CONFIG.targetClass = 'NewClassName'");
            logInfo("  traceClass(CONFIG.targetClass)");
        }
    } catch (e) {
        logError("Fatal error: " + e.message);
        console.log(e.stack);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}

// Export traceClass function for use in Frida REPL
rpc.exports = {
    traceClass: traceClass,
    setTargetClass: function(className) {
        CONFIG.targetClass = className;
    },
    setMethodFilter: function(filter) {
        CONFIG.methodFilter = filter;
    },
    setVerbose: function(verbose) {
        CONFIG.verbose = verbose;
    }
};
