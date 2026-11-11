/**
 * Clipboard Data Exfiltration Detector (BETA)
 *
 * Detects clipboard data exfiltration:
 * - Monitor UIPasteboard writes
 * - Monitor UIPasteboard reads
 * - Detect sensitive data patterns in clipboard
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l clipboard-exfiltration.js
 * OWASP MASVS: MSTG-STR-2
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Clipboard Exfiltration Detector Script Started (BETA)");

    var CONFIG = {
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,  // email
            /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/,  // phone
            /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/  // credit card
        ],
        alertOnWrite: true,
        logReads: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function detectSensitiveData(data) {
                var results = [];

                if (!data) return results;

                var str = data.toString();

                for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
                    var pattern = CONFIG.sensitivePatterns[i];
                    var matches = str.match(pattern);
                    if (matches) {
                        results.push({
                            pattern: pattern.toString(),
                            matches: matches.length
                        });
                    }
                }

                return results;
            }

            function truncateString(str, maxLength) {
                if (!str) return "null";
                maxLength = maxLength || 50;
                if (str.length <= maxLength) return str;
                return str.substring(0, maxLength) + "...";
            }

            try {
                var UIPasteboard = ObjC.classes.UIPasteboard;

                var originalSetString = UIPasteboard["- setString:"];
                const originalImpl = new NativeFunction(originalSetString.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, string) {
                    var str = string ? string.toString() : "null";

                    console.log("\x1b[32m[+]\x1b[0m UIPasteboard.setString:");
                    console.log("    Content: " + truncateString(str, 100));

                    var sensitive = detectSensitiveData(str);
                    if (sensitive.length > 0) {
                        console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA DETECTED:");
                        for (var i = 0; i < sensitive.length; i++) {
                            console.log("      Pattern: " + sensitive[i].pattern);
                            console.log("      Matches: " + sensitive[i].matches);
                        }
                    }

                    return originalImpl(self, sel, string);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetString.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m UIPasteboard.setString: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UIPasteboard.setString: hook failed: " + e.message);
            }

            try {
                var originalSetData = UIPasteboard["- setData:forPasteboardType:"];
                const originalImpl = new NativeFunction(originalSetData.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, data, type) {
                    var typeStr = type ? type.toString() : "null";

                    console.log("\x1b[32m[+]\x1b[0m UIPasteboard.setData:");
                    console.log("    Type: " + typeStr);
                    console.log("    Size: " + (data ? data.length() : 0) + " bytes");

                    if (data && typeStr === "public.utf8-plain-text") {
                        try {
                            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                            var sensitive = detectSensitiveData(str);
                            if (sensitive.length > 0) {
                                console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA DETECTED:");
                                for (var i = 0; i < sensitive.length; i++) {
                                    console.log("      Pattern: " + sensitive[i].pattern);
                                }
                            }
                        } catch (e) {}
                    }

                    return originalImpl(self, sel, data, type);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetData.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m UIPasteboard.setData:forPasteboardType: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UIPasteboard.setData:forPasteboardType: hook failed: " + e.message);
            }

            if (CONFIG.logReads) {
                try {
                    var originalString = UIPasteboard["- string"];
                    const originalImpl = new NativeFunction(originalString.implementation, 'pointer', ['pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel) {
                        var result = originalImpl(self, sel);

                        if (result) {
                            var str = result.toString();
                            console.log("\x1b[32m[+]\x1b[0m UIPasteboard.string (READ):");
                            console.log("    Content: " + truncateString(str, 50));

                            var sensitive = detectSensitiveData(str);
                            if (sensitive.length > 0) {
                                console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA READ FROM CLIPBOARD:");
                                for (var i = 0; i < sensitive.length; i++) {
                                    console.log("      Pattern: " + sensitive[i].pattern);
                                }
                            }
                        }

                        return result;
                    }, 'pointer', ['pointer', 'pointer']);

                    Interceptor.replace(originalString.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m UIPasteboard.string hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m UIPasteboard.string hook failed: " + e.message);
                }

                try {
                    var originalData = UIPasteboard["- dataForPasteboardType:"];
                    const originalImpl = new NativeFunction(originalData.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, type) {
                        var typeStr = type ? type.toString() : "null";
                        var result = originalImpl(self, sel, type);

                        console.log("\x1b[32m[+]\x1b[0m UIPasteboard.dataForPasteboardType: (READ):");
                        console.log("    Type: " + typeStr);
                        console.log("    Size: " + (result ? result.length() : 0) + " bytes");

                        return result;
                    }, 'pointer', ['pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalData.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m UIPasteboard.dataForPasteboardType: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m UIPasteboard.dataForPasteboardType: hook failed: " + e.message);
                }
            }

            try {
                var originalItems = UIPasteboard["- items"];
                const originalImpl = new NativeFunction(originalItems.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    var result = originalImpl(self, sel);

                    if (result && result.count() > 0) {
                        console.log("\x1b[32m[+]\x1b[0m UIPasteboard.items (READ):");
                        console.log("    Count: " + result.count());
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(originalItems.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m UIPasteboard.items hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UIPasteboard.items hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Clipboard Exfiltration Detector error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Clipboard Exfiltration Detector Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
