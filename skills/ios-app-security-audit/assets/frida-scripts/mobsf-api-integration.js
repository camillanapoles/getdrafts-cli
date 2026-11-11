/**
 * MobSF API Integration Helper
 *
 * Optional Frida script that helps integrate MobSF scan results
 * with dynamic runtime analysis.
 *
 * Usage:
 *   frida -U -f com.example.app -l mobsf-api-integration.js
 *
 * This script is optional and not required for MobSF integration.
 */

if (ObjC.available) {
    console.log("[*] Objective-C runtime available");
} else {
    console.log("[!] Objective-C runtime not available");
}

function logFinding(id, title, severity, description, evidence) {
    const finding = {
        id: id,
        title: title,
        severity: severity,
        description: description,
        evidence: evidence,
        source: "frida",
        confidence: "Runtime Confirmed",
        needs_verification: false
    };

    console.log("[FINDING] " + JSON.stringify(finding));
    return finding;
}

function logMethodCall(className, methodName, args) {
    const timestamp = new Date().toISOString();
    const args_str = Array.from(args || []).map(a => a.toString()).join(', ');

    console.log(`[${timestamp}] ${className}.${methodName}(${args_str})`);
}

function hookSecurityMethods() {
    console.log("[*] Hooking security-sensitive methods...");

    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    // URL Scheme handling
    const UIApplication = ObjC.classes.UIApplication;
    if (UIApplication) {
        const openURLMethod = UIApplication['- openURL:'];
        if (!openURLMethod) {
            console.log("[-] UIApplication -openURL: not found (removed in iOS 18+), skipping");
        }
        if (openURLMethod) Interceptor.attach(openURLMethod.implementation, {
            onEnter: function(args) {
                const url = ObjC.Object(args[2]).toString();
                logFinding(
                    "FRIDA-URL-001",
                    "URL Scheme Open Called",
                    "Medium",
                    "Application opening URL via openURL: - verify URL validation and sanitization",
                    `URL: ${url}`
                );
                logMethodCall("UIApplication", "openURL:", [url]);
            }
        });
    }

    // File operations
    const NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
        Interceptor.attach(NSFileManager['- createFileAtPath:contents:attributes:'].implementation, {
            onEnter: function(args) {
                const path = ObjC.Object(args[2]).toString();
                if (path.includes("..") || path.startsWith("/")) {
                    logFinding(
                        "FRIDA-FILE-001",
                        "Potential Path Traversal",
                        "High",
                        "Creating file with potentially malicious path - verify path sanitization",
                        `Path: ${path}`
                    );
                }
                logMethodCall("NSFileManager", "createFileAtPath:contents:attributes:", [path]);
            }
        });
    }

    // Keychain operations
    const secItemAddAddr = findExport('Security', 'SecItemAdd');
    const secItemCopyMatchingAddr = findExport('Security', 'SecItemCopyMatching');
    const SecItem = {
        Add: secItemAddAddr ? new NativeFunction(secItemAddAddr, 'int', ['pointer', 'pointer']) : null,
        CopyMatching: secItemCopyMatchingAddr ? new NativeFunction(secItemCopyMatchingAddr, 'int', ['pointer', 'pointer']) : null
    };

    if (!SecItem.Add) {
        console.log("[-] SecItemAdd not found in Security framework");
    }

    if (SecItem.Add) Interceptor.attach(SecItem.Add, {
        onEnter: function(args) {
            const query = new ObjC.Object(args[0]);
            logFinding(
                "FRIDA-KEYCHAIN-001",
                "Keychain Item Added",
                "Low",
                "Adding item to keychain - verify data encryption and accessibility settings",
                `Query: ${query.toString()}`
            );
        }
    });

    // Pasteboard access
    const UIPasteboard = ObjC.classes.UIPasteboard;
    if (UIPasteboard) {
        Interceptor.attach(UIPasteboard['- string'].implementation, {
            onLeave: function(retval) {
                const clipboard = ObjC.Object(retval).toString();
                if (clipboard && clipboard.length > 0) {
                    logFinding(
                        "FRIDA-PASTE-001",
                        "Pasteboard Accessed",
                        "Low",
                        "Reading from system pasteboard - verify data sensitivity and user consent",
                        `Length: ${clipboard.length} chars`
                    );
                }
            }
        });
    }

    // Network requests (NSURLSession)
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                const request = ObjC.Object(args[2]);
                const url = request.URL().toString();
                logFinding(
                    "FRIDA-NET-001",
                    "Network Request Initiated",
                    "Low",
                    "Making network request - verify TLS/ATS configuration and data encryption",
                    `URL: ${url}`
                );
            }
        });
    }

    // Crypto operations
    const ccCryptorCreateAddr = Module.getGlobalExportByName('CCCryptorCreate');
    const CommonCrypto = {
        CCCryptorCreate: ccCryptorCreateAddr ? new NativeFunction(ccCryptorCreateAddr, 'int', ['uint', 'uint', 'uint', 'pointer', 'uint', 'pointer', 'pointer']) : null
    };

    if (!CommonCrypto.CCCryptorCreate) {
        console.log("[-] CCCryptorCreate not found");
    }

    if (CommonCrypto.CCCryptorCreate) Interceptor.attach(CommonCrypto.CCCryptorCreate, {
        onEnter: function(args) {
            const algorithm = args[0].toInt32();
            const mode = args[1].toInt32();

            let algName = "Unknown";
            if (algorithm === 0) algName = "AES";
            else if (algorithm === 1) algName = "3DES";
            else if (algorithm === 2) algName = "CAST";
            else if (algorithm === 3) algName = "RC4";
            else if (algorithm === 4) algName = "RC2";
            else if (algorithm === 5) algName = "Blowfish";

            let modeName = "Unknown";
            if (mode === 0) modeName = "ECB";
            else if (mode === 1) modeName = "CBC";
            else if (mode === 2) modeName = "CFB";

            if (modeName === "ECB") {
                logFinding(
                    "FRIDA-CRYPTO-001",
                    "Weak Crypto Mode Detected",
                    "High",
                    "Using ECB mode which is not semantically secure - consider using CBC or GCM",
                    `Algorithm: ${algName}, Mode: ${modeName}`
                );
            }
        }
    });

    console.log("[+] Security method hooks installed");
}

function dumpLoadedClasses() {
    console.log("[*] Dumping loaded classes for MobSF correlation...");

    // ObjC.classes is a plain JS object keyed by class name. It does NOT
    // have a .count() method nor .forEach() — use Object.keys().
    const classNames = Object.keys(ObjC.classes);
    console.log(`[+] Total loaded classes: ${classNames.length}`);

    // Log in batches to avoid overwhelming the output
    let batch = [];
    const batchSize = 100;

    for (let i = 0; i < classNames.length; i++) {
        batch.push(classNames[i]);
        if (batch.length >= batchSize) {
            console.log(`[CLASSES] ${batch.join(',')}`);
            batch = [];
        }
    }

    if (batch.length > 0) {
        console.log(`[CLASSES] ${batch.join(',')}`);
    }

    console.log("[+] Class dump completed");
}

function dumpLoadedModules() {
    console.log("[*] Dumping loaded modules for MobSF correlation...");

    // Use the modern synchronous API. The old callback API is deprecated
    // in modern Frida and emits a warning on every call.
    const modules = Process.enumerateModules();
    for (const module of modules) {
        if (module.name.indexOf(".dylib") !== -1 || module.name.indexOf(".framework") !== -1) {
            console.log(`[MODULE] ${module.name} @ ${module.base}`);
        }
    }
    console.log("[+] Module dump completed");
}

function main() {
    console.log("[*] MobSF API Integration Helper Started");
    console.log("[*] This script logs findings in MobSF-compatible format");
    console.log("");

    // Install hooks
    hookSecurityMethods();

    // Perform initial analysis
    setTimeout(function() {
        console.log("\n[*] Performing initial analysis...");
        dumpLoadedClasses();
        dumpLoadedModules();

        console.log("\n[*] Analysis complete. Watch for [FINDING] messages.");
    }, 2000);
}

// Start the script
main();
