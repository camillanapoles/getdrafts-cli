/**
 * iOS Class Explorer for Frida
 * Purpose: List all classes and their methods in an iOS app
 * Usage: frida -p <PID> -l class-explorer-ios.js
 *
 * This is a generalized tool for iOS app reconnaissance during dynamic analysis.
 */

console.log("[*] iOS Class Explorer");
console.log("[*] Listing Objective-C classes and methods...\n");

if (ObjC.available) {
    var classNameFilter = ""; // Set to a substring to filter, or "" for all classes
    var showAllMethods = true; // Set to true to see ALL methods (can be huge)

    var classCount = 0;
    var matchedClasses = [];

    // Enumerate all classes
    for (var className in ObjC.classes) {
        // Filter if specified
        if (classNameFilter === "" || className.toLowerCase().includes(classNameFilter.toLowerCase())) {
            matchedClasses.push(className);
        }
    }

    console.log("[*] Found " + matchedClasses.length + " classes matching filter: '" + classNameFilter + "'\n");

    // Show classes and their methods
    matchedClasses.sort().forEach(function(className) {
        var clazz = ObjC.classes[className];

        console.log("[+] " + className);

        if (showAllMethods || classNameFilter !== "") {
            // Get Objective-C methods
            try {
                var methods = clazz.$ownMethods || clazz.$methods || [];
                if (methods.length > 0) {
                    methods.forEach(function(method) {
                        console.log("    " + method);
                    });
                    console.log("    (" + methods.length + " methods)");
                } else {
                    console.log("    (no methods exposed)");
                }
            } catch (e) {
                console.log("    (error reading methods: " + e.message + ")");
            }
        }

        classCount++;
    });

    console.log("\n[*] Analysis complete:");
    console.log("    - Total classes listed: " + classCount);
    console.log("    - Set 'classNameFilter' to search for specific classes");
    console.log("    - Set 'showAllMethods = true' to see all methods");

} else {
    console.log("[-] Objective-C runtime NOT available");
}
