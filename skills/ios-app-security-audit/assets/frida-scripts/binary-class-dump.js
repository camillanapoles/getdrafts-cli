/**
 * BINARY CLASS DUMP - iOS [STABLE]
 *
 * Purpose: Runtime class dump for iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l binary-class-dump.js
 *        or
 *        frida -U <BUNDLE_ID> -l binary-class-dump.js
 *
 * What it does:
 * - Enumerate all loaded Objective-C classes
 * - List methods, properties, and ivars for each class
 * - Show class hierarchy and inheritance
 * - Filter classes by regex pattern
 * - Search for specific classes
 *
 * Configuration:
 * - CONFIG.filter: Regex to filter classes (optional, empty = all)
 * - CONFIG.showMethods: Show method listings (default: true)
 * - CONFIG.showIvars: Show instance variables (default: false)
 * - CONFIG.showProtocols: Show protocol conformance (default: false)
 * - CONFIG.showInheritance: Show inheritance tree (default: true)
 * - CONFIG.maxClasses: Maximum classes to dump (default: 500)
 * - CONFIG.searchMode: Search for specific class (default: false)
 * - CONFIG.searchClass: Class name to search for (searchMode only)
 *
 * Features:
 * - List all loaded classes
 * - Show class hierarchy
 * - Method signature parsing
 * - Instance variable listing
 * - Protocol conformance tracking
 * - Class filtering with regex
 *
 * OWASP MASTG References:
 * - MASTG-APP-001: Dynamic Analysis
 * - MASTG-TECH-004: Runtime Manipulation
 * - MASTG-REV-001: Binary Analysis
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] BINARY CLASS DUMP - iOS STARTED");
    console.log("[*] ================================================");

    var CONFIG = {
        // Filter classes by regex (optional, empty = all)
        filter: "",

        // Show method listings
        showMethods: true,

        // Show instance variables
        showIvars: false,

        // Show protocol conformance
        showProtocols: false,

        // Show inheritance tree
        showInheritance: true,

        // Maximum classes to dump (0 = unlimited)
        maxClasses: 500,

        // Search mode: find specific class
        searchMode: false,

        // Class name to search for (searchMode only)
        searchClass: "",

        // Show system classes (UIKit, Foundation, etc.)
        showSystemClasses: false,

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

    var totalClasses = 0;
    var totalMethods = 0;
    var totalIvars = 0;

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

    function isSystemClass(className) {
        if (!className) return true;  // Add this line
        var systemPrefixes = [
            'NS',
            'UI',
            'CG',
            'CF',
            'CA',
            'GK',
            'SK',
            'SC',
            'AV',
            'MP',
            'CM',
            'CT',
            'MK',
            'CL',
            'CI',
            'AB',
            'EK',
            'CK',
            'AU',
            'QL',
            'MF',
            'WK',
            'CT',
            'LA',
            'SS',
            'TK',
            'GEO',
            'LN',
            'OS',
            'MTL',
            'ARKit'
        ];

        for (var i = 0; i < systemPrefixes.length; i++) {
            if (className.startsWith(systemPrefixes[i])) {
                return true;
            }
        }

        return false;
    }

    function shouldDumpClass(className) {
        // Skip system classes if not showing them
        if (!CONFIG.showSystemClasses && isSystemClass(className)) {
            return false;
        }

        // Search mode: only match search class
        if (CONFIG.searchMode) {
            if (CONFIG.searchClass) {
                return className === CONFIG.searchClass || className.includes(CONFIG.searchClass);
            }
            return false;
        }

        // Apply filter
        if (CONFIG.filter) {
            try {
                var filter = new RegExp(CONFIG.filter);
                return filter.test(className);
            } catch (e) {
                logError("Invalid filter regex: " + e.message);
                return true;
            }
        }

        return true;
    }

    function getClassHierarchy(className) {
        var hierarchy = [];
        var currentClass = ObjC.classes[className];

        while (currentClass) {
            var superName = currentClass.$superClass ? currentClass.$superClass.$className : "";
            if (superName) {
                hierarchy.unshift(superName);
            } else {
                break;
            }

            currentClass = currentClass.$superClass;
            if (currentClass && currentClass.$className === "NSObject") {
                hierarchy.unshift("NSObject");
                break;
            }
        }

        hierarchy.push(className);

        return hierarchy;
    }

    function formatMethodSignature(methodName) {
        var parts = methodName.split(':');
        var cleanParts = [];

        for (var i = 0; i < parts.length; i++) {
            if (parts[i]) {
                cleanParts.push(parts[i]);
            }
        }

        return cleanParts.join(':');
    }

    function dumpClass(className) {
        try {
            var targetClass = ObjC.classes[className];

            if (!targetClass) {
                logError("Class not found: " + className);
                return;
            }

            console.log("");
            console.log("═══════════════════════════════════════════════════");

            // Class name and type
            var isMeta = className.startsWith('+') || className.endsWith('_');
            logSuccess("Class: " + className);

            // Inheritance hierarchy
            if (CONFIG.showInheritance) {
                try {
                    var hierarchy = getClassHierarchy(className);
                    if (hierarchy.length > 1) {
                        logInfo("Inheritance: " + hierarchy.join(" -> "));
                    }
                } catch (e) {
                    // Hierarchy parsing failed
                }
            }

            // Own methods
            if (CONFIG.showMethods) {
                try {
                    var ownMethods = targetClass.$ownMethods;
                    if (ownMethods && ownMethods.length > 0) {
                        logInfo("Methods (" + ownMethods.length + "):");

                        var instanceMethods = [];
                        var classMethods = [];

                        for (var i = 0; i < ownMethods.length; i++) {
                            var methodName = ownMethods[i];
                            if (methodName.startsWith('-')) {
                                instanceMethods.push(methodName);
                            } else if (methodName.startsWith('+')) {
                                classMethods.push(methodName);
                            }
                        }

                        if (instanceMethods.length > 0) {
                            logDebug("  Instance methods:");
                            for (var i = 0; i < instanceMethods.length; i++) {
                                var formatted = formatMethodSignature(instanceMethods[i]);
                                console.log("    - " + formatted);
                            }
                        }

                        if (classMethods.length > 0) {
                            logDebug("  Class methods:");
                            for (var i = 0; i < classMethods.length; i++) {
                                var formatted = formatMethodSignature(classMethods[i]);
                                console.log("    + " + formatted);
                            }
                        }

                        totalMethods += ownMethods.length;
                    } else {
                        logInfo("Methods: (none)");
                    }
                } catch (e) {
                    logWarn("  Failed to get methods: " + e.message);
                }
            }

            // Instance variables
            if (CONFIG.showIvars) {
                try {
                    var ivars = targetClass.$ivars;
                    if (ivars) {
                        var ivarNames = Object.keys(ivars);
                        if (ivarNames.length > 0) {
                            logInfo("Instance Variables (" + ivarNames.length + "):");
                            for (var i = 0; i < ivarNames.length; i++) {
                                console.log("    " + ivarNames[i]);
                            }
                            totalIvars += ivarNames.length;
                        }
                    }
                } catch (e) {
                    logWarn("  Failed to get ivars: " + e.message);
                }
            }

            // Protocols
            if (CONFIG.showProtocols) {
                try {
                    var protocols = targetClass.$protocols;
                    if (protocols) {
                        var protocolNames = Object.keys(protocols);
                        if (protocolNames.length > 0) {
                            logInfo("Protocols (" + protocolNames.length + "):");
                            for (var i = 0; i < protocolNames.length; i++) {
                                console.log("    " + protocolNames[i]);
                            }
                        }
                    }
                } catch (e) {
                    logWarn("  Failed to get protocols: " + e.message);
                }
            }

        } catch (e) {
            logError("Error dumping class " + className + ": " + e.message);
        }
    }

    function dumpAllClasses() {
        var classNames = Object.keys(ObjC.classes);
        var sortedClasses = classNames.sort();
        var dumpedClasses = 0;

        logInfo("Found " + sortedClasses.length + " total classes");

        for (var i = 0; i < sortedClasses.length; i++) {
            var className = sortedClasses[i];

            if (shouldDumpClass(className)) {
                dumpClass(className);
                dumpedClasses++;
                totalClasses++;

                if (CONFIG.maxClasses > 0 && dumpedClasses >= CONFIG.maxClasses) {
                    logWarn("Reached maximum class limit (" + CONFIG.maxClasses + ")");
                    break;
                }
            }
        }
    }

    function searchClass(searchTerm) {
        logInfo("Searching for class: " + searchTerm);

        var classNames = Object.keys(ObjC.classes);
        var matches = [];

        for (var i = 0; i < classNames.length; i++) {
            var className = classNames[i];
            if (className.includes(searchTerm)) {
                matches.push(className);
            }
        }

        if (matches.length === 0) {
            logWarn("No classes found matching: " + searchTerm);
        } else {
            logSuccess("Found " + matches.length + " matching classes:");
            for (var i = 0; i < matches.length; i++) {
                console.log("  - " + matches[i]);
            }
        }

        return matches;
    }

    try {
        if (CONFIG.searchMode && CONFIG.searchClass) {
            // Search mode
            searchClass(CONFIG.searchClass);
        } else {
            // Dump mode
            dumpAllClasses();
        }

        console.log("");
        console.log("[*] ================================================");
        console.log("[*] Binary Class Dump Summary:");
        console.log("[*]   Classes dumped: " + totalClasses);
        console.log("[*]   Total methods: " + totalMethods);
        console.log("[*]   Total ivars: " + totalIvars);
        console.log("[*] ================================================");
        console.log("");
        logInfo("To search for a specific class:");
        logInfo("  CONFIG.searchMode = true");
        logInfo("  CONFIG.searchClass = 'ClassName'");
        logInfo("  searchClass(CONFIG.searchClass)");
    } catch (e) {
        logError("Fatal error: " + e.message);
        console.log(e.stack);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}

// Export functions for use in Frida REPL
rpc.exports = {
    dumpClass: dumpClass,
    dumpAllClasses: dumpAllClasses,
    searchClass: searchClass,
    setFilter: function(filter) {
        CONFIG.filter = filter;
    },
    setShowMethods: function(show) {
        CONFIG.showMethods = show;
    },
    setShowIvars: function(show) {
        CONFIG.showIvars = show;
    },
    setShowProtocols: function(show) {
        CONFIG.showProtocols = show;
    },
    setSearchClass: function(className) {
        CONFIG.searchMode = true;
        CONFIG.searchClass = className;
    }
};
