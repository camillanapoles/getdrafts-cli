/**
 * PASTEBOARD MONITOR - iOS [STABLE]
 *
 * Purpose: Monitor clipboard (pasteboard) access in iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l pasteboard-monitor.js
 *        or
 *        frida -U <BUNDLE_ID> -l pasteboard-monitor.js
 *
 * What it hooks:
 * - UIPasteboard.general.string getter (read string from clipboard)
 * - UIPasteboard.general.string setter (write string to clipboard)
 * - UIPasteboard.general.items getter (read items from clipboard)
 * - UIPasteboard.general.setData:forPasteboardType: (write data to clipboard)
 * - UIPasteboard.string getter/setter (legacy)
 *
 * What it logs:
 * - Clipboard read operations
 * - Clipboard write operations
 * - Data being read/written
 * - Sensitive data detection (passwords, tokens, etc.)
 * - Source of clipboard access
 *
 * Features:
 * - Polling mode for periodic clipboard checks
 * - Detect sensitive patterns in clipboard data
 * - Track read/write operations separately
 * - Support for multiple pasteboard types
 * - Configurable polling interval
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0078: Test Clipboard Data
 * - MASTG-STORAGE-010: Clipboard Data Storage
 * - MASVS-STORAGE-005: Secure Clipboard Usage
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] PASTEBOARD MONITOR - iOS STARTED");
    console.log("[*] ================================================");
    var CONFIG = {
        // Polling interval in milliseconds (0 = disable polling)
        pollInterval: 2000,

        // Maximum clipboard length to display
        maxClipboardLength: 500,

        // Detect sensitive patterns in clipboard data
        detectSensitivePatterns: true,

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
            /bearer/i
        ],

        // Track clipboard history (number of items to keep)
        historySize: 10,

        // Color codes
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue
            sensitive: "\x1b[35m"   // Magenta
        }
    };

    var hooksApplied = 0;
    var readCount = 0;
    var writeCount = 0;
    var lastClipboardValue = "";
    var clipboardHistory = [];
    var pollingActive = false;
    var generalPasteboard = null;
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

    function logSensitive(message) {
        console.log(CONFIG.colors.sensitive + CONFIG.colors.bright + "[!]\x1b[0m SENSITIVE " + CONFIG.colors.reset + message);
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function detectSensitiveData(content) {
        if (!content) return false;

        var contentStr = String(content).toLowerCase();

        for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
            if (CONFIG.sensitivePatterns[i].test(contentStr)) {
                return true;
            }
        }
        return false;
    }

    function addToHistory(type, content) {
        if (!CONFIG.detectSensitivePatterns) return;

        var entry = {
            type: type,
            content: content,
            timestamp: new Date().toISOString(),
            isSensitive: detectSensitiveData(content)
        };

        clipboardHistory.unshift(entry);

        if (clipboardHistory.length > CONFIG.historySize) {
            clipboardHistory.pop();
        }
    }

    function getBacktrace() {
        try {
            return Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .join('\n    ');
        } catch (e) {
            return "Backtrace not available";
        }
    }
    function startPolling() {
        if (CONFIG.pollInterval <= 0 || pollingActive) {
            return;
        }

        pollingActive = true;
        logWarn("Starting pasteboard polling (interval: " + CONFIG.pollInterval + "ms)");

        setInterval(function() {
            try {
                var UIPasteboard = ObjC.classes.UIPasteboard;
                if (UIPasteboard) {
                    var pasteboard = UIPasteboard.generalPasteboard();
                    if (pasteboard) {
                        var currentString = pasteboard.string();

                        if (currentString && !currentString.isNull()) {
                            var currentStr = currentString.toString();

                            if (currentStr !== lastClipboardValue) {
                                logWarn("Clipboard changed (polling):");
                                logInfo("    Content: " + truncate(currentStr, CONFIG.maxClipboardLength));

                                if (CONFIG.detectSensitivePatterns && detectSensitiveData(currentStr)) {
                                    logSensitive("    Sensitive data detected in clipboard!");
                                }

                                lastClipboardValue = currentStr;
                            }
                        }
                    }
                }
            } catch (e) {
                // Polling error - continue
            }
        }, CONFIG.pollInterval);
    }
    try {
        var UIPasteboard = ObjC.classes.UIPasteboard;

        if (UIPasteboard) {
            var originalGeneral = UIPasteboard['+ generalPasteboard'];

            if (originalGeneral) {
                generalPasteboard = originalGeneral.call(UIPasteboard);

                if (generalPasteboard) {
                    var originalStringGetter = generalPasteboard['- string'];

                    if (originalStringGetter) {
                        const originalImpl = new NativeFunction(originalStringGetter.implementation, 'pointer', ['pointer', 'pointer']);

                        const bypassCallback = new NativeCallback(function(self, sel) {
                            const result = originalImpl(self, sel);

                            if (result && !result.isNull()) {
                                readCount++;
                                const resultStr = result.toString();

                                console.log("");
                                logSuccess("Clipboard READ #" + readCount);
                                logInfo("    Content: " + truncate(resultStr, CONFIG.maxClipboardLength));

                                if (CONFIG.detectSensitivePatterns && detectSensitiveData(resultStr)) {
                                    logSensitive("    Sensitive data detected in clipboard!");
                                }

                                addToHistory('read', resultStr);
                            }

                            return result;
                        }, 'pointer', ['pointer', 'pointer']);

                        Interceptor.replace(originalStringGetter.implementation, bypassCallback);

                        hooksApplied++;
                        logSuccess("UIPasteboard.general.string getter hooked");
                    }
                }
            }
        }
    } catch (e) {
        logError("UIPasteboard.general.string getter hook failed: " + e.message);
    }
    try {
        if (generalPasteboard) {
            var originalStringSetter = generalPasteboard['- setString:'];

            if (originalStringSetter) {
                const originalImpl = new NativeFunction(originalStringSetter.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, string) {
                    if (string && !string.isNull()) {
                        writeCount++;
                        const stringObj = new ObjC.Object(string);
                        const stringStr = stringObj.toString();

                        console.log("");
                        logSuccess("Clipboard WRITE #" + writeCount);
                        logInfo("    Content: " + truncate(stringStr, CONFIG.maxClipboardLength));

                        if (CONFIG.detectSensitivePatterns && detectSensitiveData(stringStr)) {
                            logSensitive("    Sensitive data detected in clipboard!");
                        }

                        addToHistory('write', stringStr);
                        lastClipboardValue = stringStr;
                    }

                    return originalImpl(self, sel, string);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalStringSetter.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIPasteboard.general.string setter hooked");
            }
        }
    } catch (e) {
        logError("UIPasteboard.general.string setter hook failed: " + e.message);
    }
    try {
        if (generalPasteboard) {
            var originalItemsGetter = generalPasteboard['- items'];

            if (originalItemsGetter) {
                const originalImpl = new NativeFunction(originalItemsGetter.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    const result = originalImpl(self, sel);

                    if (result && !result.isNull()) {
                        readCount++;

                        const itemsObj = new ObjC.Object(result);
                        const count = itemsObj.count();

                        console.log("");
                        logSuccess("Clipboard ITEMS READ #" + readCount);
                        logInfo("    Number of items: " + count);

                        for (var i = 0; i < count && i < 5; i++) {
                            const item = itemsObj.objectAtIndex_(i);
                            const itemKeys = item.allKeys();
                            const keyCount = itemKeys.count();

                            var itemStr = "";
                            for (var j = 0; j < keyCount; j++) {
                                const key = itemKeys.objectAtIndex_(j).toString();
                                itemStr += key + ", ";
                            }

                            logInfo("    Item " + (i + 1) + ": " + truncate(itemStr, 100));
                        }
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(originalItemsGetter.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIPasteboard.general.items getter hooked");
            }
        }
    } catch (e) {
        logError("UIPasteboard.general.items getter hook failed: " + e.message);
    }
    try {
        if (generalPasteboard) {
            var originalSetData = generalPasteboard['- setData:forPasteboardType:'];

            if (originalSetData) {
                const originalImpl = new NativeFunction(originalSetData.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, data, pasteboardType) {
                    writeCount++;

                    const typeObj = new ObjC.Object(pasteboardType);
                    const typeStr = typeObj.toString();

                    console.log("");
                    logSuccess("Clipboard DATA WRITE #" + writeCount);
                    logInfo("    Type: " + typeStr);

                    if (data && !data.isNull()) {
                        const dataObj = new ObjC.Object(data);
                        const length = dataObj.length();
                        logInfo("    Length: " + length + " bytes");
                    }

                    return originalImpl(self, sel, data, pasteboardType);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetData.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIPasteboard.general.setData:forPasteboardType: hooked");
            }
        }
    } catch (e) {
        logError("UIPasteboard.general.setData:forPasteboardType: hook failed: " + e.message);
    }
    try {
        if (UIPasteboard) {
            var legacyStringGetter = UIPasteboard['- string'];

            if (legacyStringGetter) {
                const originalImpl = new NativeFunction(legacyStringGetter.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    const result = originalImpl(self, sel);

                    if (result && !result.isNull()) {
                        readCount++;
                        const resultStr = result.toString();

                        console.log("");
                        logSuccess("Clipboard READ (legacy) #" + readCount);
                        logInfo("    Content: " + truncate(resultStr, CONFIG.maxClipboardLength));

                        if (CONFIG.detectSensitivePatterns && detectSensitiveData(resultStr)) {
                            logSensitive("    Sensitive data detected in clipboard!");
                        }

                        addToHistory('read', resultStr);
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(legacyStringGetter.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIPasteboard.string getter (legacy) hooked");
            }

            var legacyStringSetter = UIPasteboard['- setString:'];

            if (legacyStringSetter) {
                const originalImpl = new NativeFunction(legacyStringSetter.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, string) {
                    if (string && !string.isNull()) {
                        writeCount++;
                        const stringObj = new ObjC.Object(string);
                        const stringStr = stringObj.toString();

                        console.log("");
                        logSuccess("Clipboard WRITE (legacy) #" + writeCount);
                        logInfo("    Content: " + truncate(stringStr, CONFIG.maxClipboardLength));

                        if (CONFIG.detectSensitivePatterns && detectSensitiveData(stringStr)) {
                            logSensitive("    Sensitive data detected in clipboard!");
                        }

                        addToHistory('write', stringStr);
                        lastClipboardValue = stringStr;
                    }

                    return originalImpl(self, sel, string);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(legacyStringSetter.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIPasteboard.string setter (legacy) hooked");
            }
        }
    } catch (e) {
        logError("UIPasteboard string getter/setter (legacy) hook failed: " + e.message);
    }

    console.log("[*] ================================================");
    console.log("[*] Total hooks applied: " + hooksApplied);
    console.log("[*] Reads logged: " + readCount);
    console.log("[*] Writes logged: " + writeCount);
    console.log("[*] Pasteboard Monitor Ready");
    console.log("[*] ================================================");

    // Start polling if enabled
    if (CONFIG.pollInterval > 0) {
        startPolling();
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
