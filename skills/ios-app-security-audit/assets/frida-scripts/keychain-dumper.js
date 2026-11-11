/**
 * KEYCHAIN DUMPER - iOS [STABLE]
 *
 * Purpose: Dump and analyze all Keychain items in iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l keychain-dumper.js
 *        or
 *        frida -U <BUNDLE_ID> -l keychain-dumper.js
 *
 * What it queries:
 * - kSecClassGenericPassword (generic passwords)
 * - kSecClassInternetPassword (internet passwords)
 * - kSecClassCertificate (certificates)
 * - kSecClassKey (cryptographic keys)
 * - kSecClassIdentity (identities)
 *
 * What it dumps:
 * - kSecAttrAccount (account name)
 * - kSecAttrService (service name)
 * - kSecAttrAccessGroup (access group)
 * - kSecAttrAccessible (protection level)
 * - kSecAttrServer (server for internet passwords)
 * - kSecAttrPort (port for internet passwords)
 * - kSecAttrPath (path for internet passwords)
 *
 * Features:
 * - Color-coded protection levels
 * - Detects insecure storage (Always, AfterFirstUnlock)
 * - Supports App Groups
 * - Shows Keychain access control
 * - Filters by class and access group
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0076: Test Local Data Storage
 * - MASTG-STORAGE-001: Insecure Data Storage
 * - MASTG-STORAGE-004: Keychain Data Storage
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] KEYCHAIN DUMPER - iOS STARTED");

    var CONFIG = {
        // Classes to dump
        dumpClasses: {
            kSecClassGenericPassword: true,
            kSecClassInternetPassword: true,
            kSecClassCertificate: false,
            kSecClassKey: false,
            kSecClassIdentity: false
        },

        // Attributes to dump
        dumpAttributes: [
            'kSecAttrAccount',
            'kSecAttrService',
            'kSecLabel',
            'kSecAttrAccessGroup',
            'kSecAttrAccessible',
            'kSecAttrServer',
            'kSecAttrPort',
            'kSecAttrPath',
            'kSecAttrCreationDate',
            'kSecAttrModificationDate'
        ],

        // Protection level colors
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue

            // Protection level colors
            protectionAlways: "\x1b[31m",        // Red - Very insecure
            protectionAfterFirstUnlock: "\x1b[33m", // Yellow - Insecure
            protectionWhenUnlocked: "\x1b[32m",   // Green - Secure
            protectionDefault: "\x1b[36m"        // Cyan - Unknown
        },

        // Filter by access group (empty = all)
        filterAccessGroup: "",

        // Dump actual data values
        dumpData: false,

        // Truncate long values
        maxStringLength: 200
    };

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

    function getProtectionColor(accessible) {
        if (!accessible) return CONFIG.colors.protectionDefault;

        var accessibleStr = String(accessible);

        if (accessibleStr.includes('Always')) {
            return CONFIG.colors.protectionAlways;
        } else if (accessibleStr.includes('AfterFirstUnlock') && !accessibleStr.includes('ThisDeviceOnly')) {
            return CONFIG.colors.protectionAfterFirstUnlock;
        } else if (accessibleStr.includes('WhenUnlocked')) {
            return CONFIG.colors.protectionWhenUnlocked;
        } else {
            return CONFIG.colors.protectionDefault;
        }
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function formatValue(value) {
        if (value === null) return "null";
        if (value === undefined) return "undefined";

        try {
            var objValue = new ObjC.Object(value);
            var className = objValue.$className;

            if (className === "NSString") {
                return '"' + objValue.toString() + '"';
            } else if (className === "NSNumber") {
                return objValue.toString();
            } else if (className === "NSDate") {
                return objValue.description().toString();
            } else if (className === "NSArray" || className === "NSMutableArray") {
                return "[" + objValue.count() + " items]";
            } else if (className === "NSDictionary" || className === "NSMutableDictionary") {
                return "{" + objValue.count() + " keys}";
            } else if (className === "NSData") {
                return "<NSData: " + objValue.length() + " bytes>";
            } else if (className === "__NSCFBoolean") {
                return objValue.toString();
            } else {
                return "<" + className + ">";
            }
        } catch (e) {
            return "<raw: " + value + ">";
        }
    }

    function getClassShortName(classValue) {
        if (typeof classValue === 'string') {
            if (classValue.includes('genp')) return 'GenericPassword';
            if (classValue.includes('inet')) return 'InternetPassword';
            if (classValue.includes('cert')) return 'Certificate';
            if (classValue.includes('keys')) return 'Key';
            if (classValue.includes('idnt')) return 'Identity';
        }
        return String(classValue);
    }

    function queryKeychain(className) {
        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        var secItemCopyMatchingPtr = findExport('Security', 'SecItemCopyMatching') ||
            Module.getGlobalExportByName('SecItemCopyMatching');
        if (!secItemCopyMatchingPtr) {
            logError('SecItemCopyMatching not found in Security framework');
            return null;
        }
        var SecItemCopyMatching = new NativeFunction(
            secItemCopyMatchingPtr,
            'int',
            ['pointer', 'pointer']
        );

        var queryDict = ObjC.classes.NSMutableDictionary.alloc().init();

        // Set class
        var classKey = ObjC.classes.NSString.stringWithString_('kSecClass');
        var classValue;

        if (className === 'kSecClassGenericPassword') {
            classValue = ObjC.classes.NSString.stringWithString_('genp');
        } else if (className === 'kSecClassInternetPassword') {
            classValue = ObjC.classes.NSString.stringWithString_('inet');
        } else if (className === 'kSecClassCertificate') {
            classValue = ObjC.classes.NSString.stringWithString_('cert');
        } else if (className === 'kSecClassKey') {
            classValue = ObjC.classes.NSString.stringWithString_('keys');
        } else if (className === 'kSecClassIdentity') {
            classValue = ObjC.classes.NSString.stringWithString_('idnt');
        }

        queryDict.setObject_forKey_(classValue, classKey);

        // Return all matching items
        var returnDataKey = ObjC.classes.NSString.stringWithString_('kSecReturnData');
        var returnDataValue = ObjC.classes.NSNumber.numberWithBool_(CONFIG.dumpData ? 1 : 0);
        queryDict.setObject_forKey_(returnDataValue, returnDataKey);

        var returnAttributesKey = ObjC.classes.NSString.stringWithString_('kSecReturnAttributes');
        var returnAttributesValue = ObjC.classes.NSNumber.numberWithBool_(1);
        queryDict.setObject_forKey_(returnAttributesValue, returnAttributesKey);

        var returnRefKey = ObjC.classes.NSString.stringWithString_('kSecReturnRef');
        var returnRefValue = ObjC.classes.NSNumber.numberWithBool_(0);
        queryDict.setObject_forKey_(returnRefValue, returnRefKey);

        var matchLimitKey = ObjC.classes.NSString.stringWithString_('kSecMatchLimit');
        var matchLimitValue = ObjC.classes.NSString.stringWithString_('kSecMatchLimitAll');
        queryDict.setObject_forKey_(matchLimitValue, matchLimitKey);

        // Filter by access group if specified
        if (CONFIG.filterAccessGroup) {
            var accessGroupKey = ObjC.classes.NSString.stringWithString_('kSecAttrAccessGroup');
            var accessGroupValue = ObjC.classes.NSString.stringWithString_(CONFIG.filterAccessGroup);
            queryDict.setObject_forKey_(accessGroupValue, accessGroupKey);
        }

        var resultPtr = Memory.alloc(Process.pointerSize);
        resultPtr.writePointer(ptr(0));

        var status = SecItemCopyMatching(queryDict.handle, resultPtr);

        if (status === 0) {
            var resultObj = new ObjC.Object(resultPtr.readPointer());

            if (resultObj.$className === 'NSArray' || resultObj.$className === '__NSArrayI' || resultObj.$className === '__NSArray0') {
                return resultObj;
            } else {
                var array = ObjC.classes.NSArray.arrayWithObject_(resultObj);
                return array;
            }
        } else if (status === -25300) {
            return ObjC.classes.NSArray.array();
        } else {
            logError("Query failed with status: " + status);
            return null;
        }
    }

    function dumpKeychainClass(className) {
        if (!CONFIG.dumpClasses[className]) {
            return;
        }

        logWarn("Querying: " + className);

        var results = queryKeychain(className);

        if (!results) {
            return;
        }

        var count = results.count();

        if (count === 0) {
            logInfo("  No items found");
            console.log("");
            return;
        }

        logSuccess("  Found " + count + " item(s)");
        console.log("");

        for (var i = 0; i < count; i++) {
            var item = results.objectAtIndex_(i);
            var itemDict = new ObjC.Object(item);

            console.log("  --- Item " + (i + 1) + " ---");

            // Dump all attributes
            var keys = itemDict.allKeys();
            var keyCount = keys.count();

            for (var j = 0; j < keyCount; j++) {
                var key = keys.objectAtIndex_(j).toString();
                var value = itemDict.objectForKey_(keys.objectAtIndex_(j));

                var valueStr = formatValue(value);
                valueStr = truncate(valueStr, CONFIG.maxStringLength);

                // Special handling for protection level
                if (key === 'kSecAttrAccessible') {
                    var color = getProtectionColor(valueStr);
                    console.log("  " + color + key + ":" + CONFIG.colors.reset + " " + valueStr);

                    // Warn about insecure protection
                    if (color === CONFIG.colors.protectionAlways) {
                        logError("    [!] VERY INSECURE - Always accessible");
                    } else if (color === CONFIG.colors.protectionAfterFirstUnlock) {
                        logWarn("    [!] Insecure - After first unlock");
                    }
                } else if (key === 'kSecAttrAccessGroup') {
                    console.log("  " + key + ": " + CONFIG.colors.info + valueStr + CONFIG.colors.reset);
                } else {
                    console.log("  " + key + ": " + valueStr);
                }
            }

            console.log("");
        }
    }

    try {
        console.log("");

        // Dump each class
        dumpKeychainClass('kSecClassGenericPassword');
        dumpKeychainClass('kSecClassInternetPassword');
        dumpKeychainClass('kSecClassCertificate');
        dumpKeychainClass('kSecClassKey');
        dumpKeychainClass('kSecClassIdentity');

        console.log("[*] KEYCHAIN DUMP COMPLETE");
    } catch (e) {
        logError("Fatal error: " + e.message);
        console.log(e.stack);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
