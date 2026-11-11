/**
 * Simple Frida Test for iOS Simulator
 * Purpose: Verify Frida connection to simulator app
 * Usage: frida -e <bundle_id> -l simple-test-ios.js
 *        frida -e <bundle_id>
 *
 * CUSTOMIZATION:
 * - Set TARGET_MODULE_FILTER to filter specific modules (empty string = show all)
 * - Set TARGET_CLASS to check for a specific class (null = skip class check)
 */

// ===== CONFIGURATION =====
const TARGET_MODULE_FILTER = "";  // Empty = show all modules; e.g. "MyApp" = only modules whose name contains "MyApp"
const TARGET_CLASS = null;         // null = skip class check, "AppDelegate" = check for that class

console.log("[*] Frida iOS Simulator Test Script");
console.log("[*] Objective: Verify connection and list modules");

if (ObjC.available) {
    console.log("[+] Objective-C runtime is available");

    try {
        // List main app modules
        console.log("[*] Main Modules:");
        Process.enumerateModules().forEach(function(module) {
            // Apply filter if set, otherwise show all modules
            if (TARGET_MODULE_FILTER === "" || module.name.includes(TARGET_MODULE_FILTER)) {
                console.log("    - " + module.name + " @ " + module.base);
            }
        });

        // Try to detect a specific class if configured
        if (TARGET_CLASS !== null) {
            if (ObjC.classes[TARGET_CLASS]) {
                console.log("[+] Found " + TARGET_CLASS + " class");
            } else {
                console.log("[-] " + TARGET_CLASS + " not found (might be different class)");
            }
        } else {
            console.log("[*] No specific class check configured (set TARGET_CLASS to enable)");
        }

        console.log("[+] Frida connection successful!");
        console.log("[*] Script completed successfully - Frida is working with the simulator.");
        console.log("[*] Customize TARGET_MODULE_FILTER and TARGET_CLASS at the top for specific apps.");

    } catch (e) {
        console.log("[-] Error: " + e.message);
    }
} else {
    console.log("[-] Objective-C runtime NOT available");
    console.log("[*] Target might not be an iOS app");
}
