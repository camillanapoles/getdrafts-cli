/**
 * NSUserDefaults Dumper - iOS (Comprehensive)
 *
 * Purpose: Dump and monitor all NSUserDefaults values in iOS applications
 * Usage: frida -U -f <bundle_id> -l nsuserdefaults-dumper.js
 *        or
 *        frida -U <bundle_id> -l nsuserdefaults-dumper.js
 *
 * What it hooks:
 * - NSUserDefaults.standardUserDefaults
 * - NSUserDefaults.dictionaryRepresentation (dump all keys/values)
 * - NSUserDefaults.objectForKey (read access)
 * - NSUserDefaults.setObject:forKey (write access)
 * - NSUserDefaults.suiteWithName (App Groups support)
 *
 * Features:
 * - Color-coded output with sensitive data highlighted
 * - Sensitive pattern detection
 * - System key filtering (reduce noise)
 * - Monitoring hooks (read/write access)
 * - App Groups support
 * - Summary statistics
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0076: Test Local Data Storage
 * - MASTG-STORAGE-004: Insecure Storage of Sensitive Data
 *
 * Configuration: Edit CONFIG object below to customize
 */

if (ObjC.available) {
    var CONFIG = {
        // Sensitive patterns to detect
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /authorization/i,
            /session/i,
            /credit[_-]?card/i,
            /ssn/i,
            /pin/i,
            /auth/i,
            /credential/i,
            /cookie/i,
            /private[_-]?key/i,
            /access[_-]?token/i,
            /refresh[_-]?token/i
        ],

        // System key prefixes to filter out (reduce noise)
        systemPrefixes: [
            "WebKit",
            "Apple",
            "NS",
            "PK",
            "AI",
            "_",
            "kCF",
            "com.apple"
        ],

        // Custom App Group suites to monitor
        customSuites: [],

        // Filter system keys (true = show only app-specific keys)
        filterSystemKeys: false,

        // Color codes (terminal)
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",
            dim: "\x1b[2m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            info: "\x1b[34m",       // Blue
            warn: "\x1b[33m",       // Yellow
            sensitive: "\x1b[35m",   // Magenta
            system: "\x1b[36m"       // Cyan
        }
    };

    var DEBUG_MODE = false;

    // Statistics
    var stats = {
        totalKeys: 0,
        appKeys: 0,
        systemKeys: 0,
        sensitiveKeys: 0,
        readOperations: 0,
        writeOperations: 0
    };

    function colorLabel(label, color) {
        return CONFIG.colors[color] + CONFIG.colors.bright + label + CONFIG.colors.reset;
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function isSystemKey(key) {
        for (var i = 0; i < CONFIG.systemPrefixes.length; i++) {
            if (key.indexOf(CONFIG.systemPrefixes[i]) === 0) {
                return true;
            }
        }
        return false;
    }

    function detectSensitiveData(key, value) {
        var keyLower = key.toLowerCase();
        var valueLower = String(value).toLowerCase();

        for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
            var pattern = CONFIG.sensitivePatterns[i];
            if (pattern.test(keyLower) || pattern.test(valueLower)) {
                return true;
            }
        }
        return false;
    }

    function formatValue(value) {
        if (value === null) return "null";
        if (value === undefined) return "undefined";

        // Guard against ObjC nil pointer
        try {
            var _probe = new ObjC.Object(value);
            if (_probe.isNil()) return "nil";
        } catch (e) {
            return "<invalid>";
        }

        var objValue = new ObjC.Object(value);
        var className = objValue.$className;

        if (className === "NSString" || className === "__NSCFString" || className === "NSTaggedPointerString") {
            return '"' + objValue.toString() + '"';
        } else if (className === "NSNumber" || className === "__NSCFNumber") {
            return objValue.toString();
        } else if (className === "NSDate") {
            return objValue.description().toString();
        } else if (className === "NSArray" || className === "NSMutableArray" || className === "__NSArrayI" || className === "__NSArrayM") {
            return "[" + objValue.count() + " items]";
        } else if (className === "NSDictionary" || className === "NSMutableDictionary" || className === "__NSDictionaryI" || className === "__NSDictionaryM") {
            return "{" + objValue.count() + " keys}";
        } else if (className === "NSData" || className === "_NSInlineData") {
            return "<NSData: " + objValue.length() + " bytes>";
        } else if (className === "NSURL") {
            return objValue.absoluteString().toString();
        } else if (className === "NSNull") {
            return "<null>";
        } else if (className === "__NSCFBoolean") {
            return objValue.toString();
        } else {
            return "<" + className + ">";
        }
    }

    function dumpUserDefaults(suiteName, userDefaults) {
        var label = suiteName ? suiteName : "Standard";
        console.log("\n" + colorLabel("=== NSUserDefaults: " + label + " ===", "info"));
        console.log(" ".repeat(60));

        try {
            var dict = userDefaults.dictionaryRepresentation();
            var keys = dict.allKeys();
            var count = keys.count();

            stats.totalKeys += count;
            var localAppKeys = 0;
            var localSystemKeys = 0;
            var localSensitiveKeys = 0;

            if (count === 0) {
                console.log("    (empty)");
                return;
            }

            console.log(colorLabel("[*] Found " + count + " keys", "info") + "\n");

            for (var i = 0; i < count; i++) {
                var key = keys.objectAtIndex_(i).toString();
                var value = dict.objectForKey_(key);

                var isSystem = isSystemKey(key);
                var isSensitive = detectSensitiveData(key, value);

                // Track statistics
                if (isSystem) {
                    localSystemKeys++;
                } else {
                    localAppKeys++;
                }
                if (isSensitive) {
                    localSensitiveKeys++;
                    stats.sensitiveKeys++;
                }

                // Skip system keys if filtering is enabled
                if (CONFIG.filterSystemKeys && isSystem) {
                    continue;
                }

                var valueStr = formatValue(value);
                valueStr = truncate(valueStr, 500);

                if (isSensitive) {
                    console.log(colorLabel("    [!] SENSITIVE", "sensitive") + " [" + key + "]: " + valueStr);
                } else if (isSystem) {
                    if (!CONFIG.filterSystemKeys) {
                        console.log(CONFIG.colors.system + "    [SYSTEM] " + key + ": " + valueStr + CONFIG.colors.reset);
                    }
                } else {
                    console.log("    " + key + ": " + valueStr);
                }
            }

            stats.appKeys += localAppKeys;
            stats.systemKeys += localSystemKeys;

            console.log("\n" + colorLabel("Summary:", "info"));
            console.log("    - App-specific keys: " + localAppKeys);
            if (!CONFIG.filterSystemKeys) {
                console.log("    - System keys: " + localSystemKeys);
            }
            console.log("    - Sensitive keys: " + colorLabel(localSensitiveKeys, "sensitive"));
        } catch (e) {
            console.log(colorLabel("    [!] Error dumping: ", "error") + e);
        }
    }

    function printSummary() {
        console.log("\n" + colorLabel("=== NSUserDefaults Dumper Summary ===", "info"));
        console.log(" ".repeat(60));
        console.log("    Total keys across all suites: " + stats.totalKeys);
        console.log("    App-specific keys: " + stats.appKeys);
        console.log("    System keys: " + stats.systemKeys);
        console.log("    Sensitive keys: " + colorLabel(stats.sensitiveKeys, "sensitive"));
        console.log("    Read operations monitored: " + stats.readOperations);
        console.log("    Write operations monitored: " + stats.writeOperations);

        if (stats.sensitiveKeys > 0) {
            console.log("\n" + colorLabel("[!] VULNERABILITY: Sensitive data stored in UserDefaults", "warn"));
            console.log("    Consider using Keychain for sensitive data storage");
        }

        if (stats.appKeys === 0) {
            console.log("\n" + colorLabel("[*] No app-specific keys found", "info"));
            console.log("    App might not use UserDefaults yet, or stores data elsewhere");
            console.log("    Try: Keychain (keychain-dumper-ios.js), CoreData, SQLite");
        }
    }

    // Hook standardUserDefaults
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        var originalStandardUserDefaults = NSUserDefaults['+ standardUserDefaults'];

        Interceptor.attach(originalStandardUserDefaults.implementation, {
            onLeave: function(retval) {
                if (retval && !retval.isNull()) {
                    var userDefaults = new ObjC.Object(retval);
                    dumpUserDefaults("Standard", userDefaults);
                }
            }
        });

        console.log(colorLabel("[+] NSUserDefaults.standardUserDefaults hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook standardUserDefaults: ", "error") + e);
    }

    // Hook initWithSuiteName (App Groups)
    try {
        var originalInitWithSuiteName = NSUserDefaults.initWithSuiteName_;
        const originalImpl = new NativeFunction(originalInitWithSuiteName.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, suiteName) {
            const suiteStr = ObjC.Object(suiteName).toString();
            const result = originalImpl(self, sel, suiteName);

            if (result && !result.isNull()) {
                dumpUserDefaults(suiteStr, result);
            }

            if (DEBUG_MODE) {
                console.log("[*] Suite created: " + suiteStr);
            }

            return result;
        }, 'pointer', ['pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalInitWithSuiteName.implementation, bypassCallback);
        console.log(colorLabel("[+] NSUserDefaults.initWithSuiteName hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook initWithSuiteName: ", "error") + e);
    }

    // Hook objectForKey (read monitoring)
    try {
        var originalObjectForKey = NSUserDefaults.objectForKey_;
        const originalImpl = new NativeFunction(originalObjectForKey.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, key) {
            const keyStr = ObjC.Object(key).toString();
            const result = originalImpl(self, sel, key);
            stats.readOperations++;

            if (DEBUG_MODE) {
                const isSensitive = detectSensitiveData(keyStr, result);
                const valueStr = formatValue(result);
                const truncated = truncate(valueStr, 100);

                if (isSensitive) {
                    console.log(colorLabel("[*] READ SENSITIVE", "sensitive") + " [" + keyStr + "]: " + truncated);
                } else {
                    console.log("[*] READ [" + keyStr + "]: " + truncated);
                }
            }

            return result;
        }, 'pointer', ['pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalObjectForKey.implementation, bypassCallback);
        console.log(colorLabel("[+] NSUserDefaults.objectForKey hooked (read monitoring)", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook objectForKey: ", "error") + e);
    }

    // Hook setObject:forKey (write monitoring)
    try {
        var originalSetObjectForKey = NSUserDefaults.setObject_forKey_;
        const originalImpl = new NativeFunction(originalSetObjectForKey.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, value, key) {
            const keyStr = ObjC.Object(key).toString();
            const isSensitive = detectSensitiveData(keyStr, value);
            const valueStr = formatValue(value);
            const truncated = truncate(valueStr, 100);
            stats.writeOperations++;

            if (isSensitive) {
                console.log(colorLabel("[!] WRITE SENSITIVE", "sensitive") + " [" + keyStr + "]: " + truncated);
            } else if (DEBUG_MODE) {
                console.log("[*] WRITE [" + keyStr + "]: " + truncated);
            }

            return originalImpl(self, sel, value, key);
        }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalSetObjectForKey.implementation, bypassCallback);
        console.log(colorLabel("[+] NSUserDefaults.setObject:forKey: hooked (write monitoring)", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook setObject:forKey: ", "error") + e);
    }

    // Dump custom suites if specified
    if (CONFIG.customSuites.length > 0) {
        console.log("\n" + colorLabel("[*] Dumping custom suites...", "info"));
        for (var i = 0; i < CONFIG.customSuites.length; i++) {
            try {
                var suite = NSUserDefaults.alloc().initWithSuiteName_(CONFIG.customSuites[i]);
                dumpUserDefaults(CONFIG.customSuites[i], suite);
            } catch (e) {
                console.log(colorLabel("[!] Failed to dump suite " + CONFIG.customSuites[i] + ": ", "error") + e);
            }
        }
    }

    console.log("\n" + colorLabel("[*] NSUserDefaults Dumper Ready", "success"));
    console.log(" ".repeat(60));
    console.log("[*] Monitoring read/write operations...");
    console.log("[*] Press Ctrl+C to exit and see summary");

    // Frida has no Node-style process.on("exit"): the global does not exist
    // and referencing it aborted the script at load time. The summary is
    // printed on a timer and can also be requested by the host with
    // recv("summary"), so it is always reachable.
    setInterval(printSummary, 30000);

    recv('summary', function () {
        printSummary();
    });

} else {
    console.log(colorLabel("[!] Objective-C runtime not available", "error"));
    console.log("    This script requires iOS");
}

/**
 * Configuration Options
 *
 * Edit CONFIG at the top of this script to customize:
 *
 * 1. filterSystemKeys: Set to true to hide system keys (WebKit, Apple, etc.)
 * 2. sensitivePatterns: Add regex patterns for sensitive data detection
 * 3. systemPrefixes: Add prefixes to filter as system keys
 * 4. customSuites: Add App Group suite names to dump
 * 5. DEBUG_MODE: Set to true for verbose read/write logging
 *
 * Usage Examples:
 *
 * Basic dump:
 * frida -U -f com.example.app -l nsuserdefaults-dumper.js
 *
 * Attach to running app:
 * frida -U com.example.app -l nsuserdefaults-dumper.js
 *
 * With custom App Groups (edit customSuites first):
 * frida -U -f com.example.app -l nsuserdefaults-dumper.js
 */
