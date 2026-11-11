/**
 * iOS Utilities - Multi-Tool Collection - iOS [STABLE]
 *
 * Purpose: Collection of useful iOS pentesting utilities and helpers
 * Usage: frida -U -f <BUNDLE_ID> -l ios-utilities.js
 *
 * What it hooks:
 * - Various Objective-C runtime functions
 * - File system operations
 * - Memory operations
 * - Network operations
 * - Cryptographic functions
 *
 * Features:
 * - Memory inspection and dumping
 * - Class and method enumeration
 * - File system navigation
 * - Environment variable inspection
 * - Process information gathering
 * - Method hooking utilities
 * - String manipulation helpers
 * - Data type conversions
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0041: File System Storage Testing
 * - MASTG-TEST-0051: Memory Analysis
 * - MASTG-TEST-0071: Process Analysis
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@lichao890427/ios-utils/
 * Author: @lichao890427
 */

if (ObjC.available) {
    try {
        console.log("[*] ================================================");
        console.log("[*] iOS Utilities - Multi-Tool Collection - iOS STARTED");
        console.log("[*] ================================================");

        var CONFIG = {
            verbose: true,
            maxOutputLength: 200,
            colorOutput: true
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

        var NSString = ObjC.classes.NSString;

        function ocString(jsString) {
            try {
                return NSString.stringWithUTF8String_(Memory.allocUtf8String(jsString)).toString();
            } catch (e) {
                logError("Exception in ocString: " + e.message);
                return null;
            }
        }

        function jsString(ocString) {
            try {
                return ObjC.Object(ocString).toString();
            } catch (e) {
                logError("Exception in jsString: " + e.message);
                return null;
            }
        }

        function truncateString(str, maxLength) {
            maxLength = maxLength || CONFIG.maxOutputLength;
            if (!str || str.length <= maxLength) {
                return str;
            }
            return str.substring(0, maxLength) + "... (truncated)";
        }

        function readMemory(address, size) {
            try {
                if (typeof address === "string") {
                    address = ptr(address);
                }
                if (typeof address === "number") {
                    address = ptr(address);
                }

                if (!address || address.isNull()) {
                    logError("readMemory: null address");
                    return null;
                }

                if (!size || size <= 0) {
                    return null;
                }

                var result = address.readByteArray(size);
                return result;
            } catch (e) {
                logError("Exception in readMemory: " + e.message);
                return null;
            }
        }

        function dumpMemory(address, size) {
            try {
                if (typeof address === "string") {
                    address = ptr(address);
                }
                if (typeof address === "number") {
                    address = ptr(address);
                }

                if (!address || address.isNull()) {
                    logError("dumpMemory: null address");
                    return;
                }

                if (!size || size <= 0) {
                    logError("Invalid size for memory dump");
                    return;
                }

                var data = address.readByteArray(size);
                console.log(hexdump(data, {
                    offset: 0,
                    length: size,
                    header: true,
                    ansi: true
                }));
            } catch (e) {
                logError("Exception in dumpMemory: " + e.message);
            }
        }

        function readUTF8String(address) {
            try {
                if (typeof address === "string") {
                    address = ptr(address);
                }
                if (typeof address === "number") {
                    address = ptr(address);
                }
                if (!address || address.isNull()) {
                    logError("readUTF8String: null address");
                    return null;
                }
                return address.readUtf8String();
            } catch (e) {
                logError("Exception in readUTF8String: " + e.message);
                return null;
            }
        }

        function readPointer(address) {
            try {
                if (typeof address === "string") {
                    address = ptr(address);
                }
                if (typeof address === "number") {
                    address = ptr(address);
                }
                if (!address || address.isNull()) {
                    logError("readPointer: null address");
                    return ptr(0);
                }
                return address.readPointer();
            } catch (e) {
                logError("Exception in readPointer: " + e.message);
                return ptr(0);
            }
        }

        function findModule(name) {
            try {
                var modules = Process.enumerateModules();
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].name === name || modules[i].path.indexOf(name) !== -1) {
                        return modules[i];
                    }
                }
                return null;
            } catch (e) {
                logError("Exception in findModule: " + e.message);
                return null;
            }
        }

        function findModuleByAddress(address) {
            try {
                if (typeof address === "number") {
                    address = ptr(address);
                }
                return Process.findModuleByAddress(address);
            } catch (e) {
                logError("Exception in findModuleByAddress: " + e.message);
                return null;
            }
        }

        function enumerateModules(filter) {
            try {
                var modules = Process.enumerateModules();
                if (!filter) {
                    return modules;
                }

                var filtered = [];
                var filterLower = filter.toLowerCase();
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].name.toLowerCase().indexOf(filterLower) !== -1 ||
                        modules[i].path.toLowerCase().indexOf(filterLower) !== -1) {
                        filtered.push(modules[i]);
                    }
                }
                return filtered;
            } catch (e) {
                logError("Exception in enumerateModules: " + e.message);
                return [];
            }
        }

        function findClass(className) {
            try {
                return ObjC.classes[className];
            } catch (e) {
                if (CONFIG.verbose) {
                    logWarn("Class not found: " + className);
                }
                return null;
            }
        }

        function enumerateClasses(filter) {
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
                logError("Exception in enumerateClasses: " + e.message);
                return [];
            }
        }

        function enumerateMethods(className) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return [];
                }
                return clazz.$ownMethods;
            } catch (e) {
                logError("Exception in enumerateMethods: " + e.message);
                return [];
            }
        }

        function hookMethod(className, methodName, callback) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return false;
                }

                var method = clazz[methodName];
                if (!method) {
                    logError("Method not found: " + className + " - " + methodName);
                    return false;
                }

                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        callback.onEnter && callback.onEnter(args, this);
                    },
                    onLeave: function(retval) {
                        callback.onLeave && callback.onLeave(retval, this);
                    }
                });

                logSuccess("Hooked: " + className + " - " + methodName);
                return true;
            } catch (e) {
                logError("Exception in hookMethod: " + e.message);
                return false;
            }
        }

        function hookAllMethods(className, callback) {
            try {
                var clazz = ObjC.classes[className];
                if (!clazz) {
                    logError("Class not found: " + className);
                    return 0;
                }

                var methods = clazz.$ownMethods;
                var hooked = 0;

                for (var i = 0; i < methods.length; i++) {
                    try {
                        var method = clazz[methods[i]];
                        if (method) {
                            Interceptor.attach(method.implementation, {
                                onEnter: function(args) {
                                    callback.onEnter && callback.onEnter(args, this, methods[i]);
                                },
                                onLeave: function(retval) {
                                    callback.onLeave && callback.onLeave(retval, this, methods[i]);
                                }
                            });
                            hooked++;
                        }
                    } catch (e) {
                    }
                }

                logSuccess("Hooked " + hooked + " methods in " + className);
                return hooked;
            } catch (e) {
                logError("Exception in hookAllMethods: " + e.message);
                return 0;
            }
        }

        function findExportFunction(moduleName, functionName) {
            try {
                // Frida 17: getModuleByName() throws when the module is not loaded and
                // getExportByName() throws when the symbol is missing; the "find" variants return null.
                var mod = Process.findModuleByName(moduleName);
                var funcPtr = mod ? mod.findExportByName(functionName) : null;
                if (!funcPtr) {
                    logWarn("Export not found: " + moduleName + " - " + functionName);
                    return null;
                }
                return funcPtr;
            } catch (e) {
                logError("Exception in findExportFunction: " + e.message);
                return null;
            }
        }

        function callNativeFunction(address, returnType, argTypes, args) {
            try {
                var func = new NativeFunction(address, returnType, argTypes);
                return func.apply(null, args);
            } catch (e) {
                logError("Exception in callNativeFunction: " + e.message);
                return null;
            }
        }

        function getCurrentProcess() {
            try {
                return {
                    pid: Process.id,
                    threads: Process.enumerateThreadsSync().length,
                    modules: Process.enumerateModules().length,
                    ranges: Process.enumerateRangesSync({
                        protection: '---',
                        coalesce: false
                    }).length
                };
            } catch (e) {
                logError("Exception in getCurrentProcess: " + e.message);
                return null;
            }
        }

        function enumerateThreads() {
            try {
                return Process.enumerateThreadsSync();
            } catch (e) {
                logError("Exception in enumerateThreads: " + e.message);
                return [];
            }
        }

        function enumerateRanges(options) {
            try {
                options = options || { protection: 'r--', coalesce: false };
                return Process.enumerateRangesSync(options);
            } catch (e) {
                logError("Exception in enumerateRanges: " + e.message);
                return [];
            }
        }

        function printObject(obj) {
            try {
                if (!obj) {
                    console.log("null");
                    return;
                }

                if (typeof obj === "object") {
                    console.log(JSON.stringify(obj, null, 2));
                } else if (typeof obj.toString === "function") {
                    var str = obj.toString();
                    console.log(truncateString(str));
                } else {
                    console.log(String(obj));
                }
            } catch (e) {
                logError("Exception in printObject: " + e.message);
            }
        }

        function getArgumentsInfo(args) {
            try {
                if (!args || args.length === 0) {
                    return "No arguments";
                }

                var info = [];
                for (var i = 0; i < args.length; i++) {
                    var arg = args[i];
                    var type = typeof arg;

                    if (arg && arg.toString) {
                        info.push("arg[" + i + "]: " + truncateString(arg.toString()));
                    } else {
                        info.push("arg[" + i + "]: " + type + " (" + arg + ")");
                    }
                }

                return info.join("\n");
            } catch (e) {
                logError("Exception in getArgumentsInfo: " + e.message);
                return "Error getting arguments info";
            }
        }

        function demoClassEnumeration() {
            logSection("CLASS ENUMERATION DEMO");

            var filter = "UIView";
            var classes = enumerateClasses(filter);

            logInfo("Found " + classes.length + " classes matching '" + filter + "'");

            if (classes.length > 0) {
                console.log("\nFirst 10 classes:");
                for (var i = 0; i < Math.min(10, classes.length); i++) {
                    console.log("  - " + classes[i]);
                }
            }
        }

        function demoModuleEnumeration() {
            logSection("MODULE ENUMERATION DEMO");

            var modules = enumerateModules();

            logInfo("Found " + modules.length + " loaded modules");

            console.log("\nFirst 10 modules:");
            for (var i = 0; i < Math.min(10, modules.length); i++) {
                var mod = modules[i];
                console.log("  - " + mod.name);
                console.log("    Base: " + mod.base);
                console.log("    Size: 0x" + mod.size.toString(16));
                console.log("    Path: " + mod.path);
            }
        }

        function demoProcessInfo() {
            logSection("PROCESS INFO DEMO");

            var proc = getCurrentProcess();
            if (proc) {
                logInfo("Process ID: " + proc.pid);
                logInfo("Threads: " + proc.threads);
                logInfo("Modules: " + proc.modules);
                logInfo("Memory Ranges: " + proc.ranges);
            }

            var threads = enumerateThreads();
            logInfo("Thread IDs: " + threads.map(function(t) { return t.id; }).join(", "));
        }

        function main() {
            try {
                logInfo("iOS Utilities loaded successfully");
                logInfo("Available utilities:");
                console.log("  - String utilities: ocString(), jsString(), truncateString()");
                console.log("  - Memory utilities: readMemory(), dumpMemory(), readUTF8String()");
                console.log("  - Module utilities: findModule(), findModuleByAddress(), enumerateModules()");
                console.log("  - Class utilities: findClass(), enumerateClasses(), enumerateMethods()");
                console.log("  - Method hooking: hookMethod(), hookAllMethods()");
                console.log("  - File system: findExportFunction(), callNativeFunction()");
                console.log("  - Process: getCurrentProcess(), enumerateThreads(), enumerateRanges()");
                console.log("\nDemo functions:");
                console.log("  demoClassEnumeration()");
                console.log("  demoModuleEnumeration()");
                console.log("  demoProcessInfo()");

                logSection("RUNNING DEMOS");

                demoClassEnumeration();
                demoModuleEnumeration();
                demoProcessInfo();

                logSection("UTILITIES READY");
                logSuccess("iOS utilities ready for use");

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
