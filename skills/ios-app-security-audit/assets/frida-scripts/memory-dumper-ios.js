/**
 * Memory Dumper for iOS Apps
 *
 * Description: Scans process memory for common secret patterns (API keys, tokens, passwords)
 *
 * Usage:
 *   frida -U -f com.example.app -l memory-dumper-ios.js
 *   frida -e com.example.app -l memory-dumper-ios.js  # For emulator
 *
 * Output: JSON array of found secrets with memory addresses
 *
 * Author: iOS-Pentesting-Skill
 * Version: 1.0.0
 * License: MIT
 */

if (ObjC.available) {
    console.log("[*] Memory Dumper for iOS Apps");
    console.log("[*] Scanning for secrets in memory...");

    var secrets = [];
    var scannedRanges = 0;

    // Common secret patterns
    var patterns = [
        { name: "Stripe Key", regex: /sk_[a-z0-9]{24,}/g },
        { name: "Stripe Publishable Key", regex: /pk_[a-z0-9]{24,}/g },
        { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret Key", regex: /[A-Za-z0-9+/]{40}/g },
        { name: "GitHub Token", regex: /gh[pou]_[a-zA-Z0-9]{36}/g },
        { name: "GitHub OAuth", regex: /gho_[a-zA-Z0-9]{36}/g },
        { name: "JWT Token", regex: /ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
        { name: "Bearer Token", regex: /Bearer [a-zA-Z0-9\-._~+/]*/g },
        { name: "API Key (generic)", regex: /api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,}/gi },
        { name: "Email:Password", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}:[^\s]{8,}/g }
    ];

    // Scan a memory region for secrets
    function scanRegion(range) {
        try {
            // Read the region as bytes
            var bytes = range.base.readByteArray(range.size);
            var str = "";

            // Convert to string (handle potential encoding issues)
            var bytesView = new Uint8Array(bytes);
            for (var i = 0; i < bytesView.length; i++) {
                var byte = bytesView[i];
                // Only keep printable ASCII characters
                if (byte >= 32 && byte <= 126) {
                    str += String.fromCharCode(byte);
                } else if (byte === 0 || byte === 10 || byte === 13) {
                    // Null, newline, carriage return
                    str += " ";
                }
            }

            // Check against patterns
            patterns.forEach(function(pattern) {
                var matches = str.match(pattern.regex);
                if (matches) {
                    matches.forEach(function(match) {
                        // Skip if too short or likely a false positive
                        if (match.length < 10) return;

                        // Check if already found (deduplicate)
                        var alreadyFound = secrets.some(function(s) {
                            return s.secret === match && s.pattern === pattern.name;
                        });

                        if (!alreadyFound) {
                            // Calculate approximate offset within region
                            var offset = str.indexOf(match);

                            secrets.push({
                                pattern: pattern.name,
                                secret: match,
                                address: range.base.add(offset).toString(),
                                length: match.length,
                                region: range.protection
                            });

                            console.log("[+] Found " + pattern.name + " at " +
                                      range.base.add(offset) + ": " +
                                      match.substring(0, 50) + (match.length > 50 ? "..." : ""));
                        }
                    });
                }
            });

            scannedRanges++;

        } catch (e) {
            // Some regions may not be readable
        }
    }

    // Scan specific module (executable)
    function scanModule(moduleName) {
        console.log("[*] Scanning module: " + moduleName);

        try {
            var module = Process.findModuleByName(moduleName);
            if (module) {
                var base = module.base;
                var size = module.size;

                // Scan in chunks to avoid overwhelming memory
                var chunkSize = 1024 * 1024; // 1MB chunks
                for (var offset = 0; offset < size; offset += chunkSize) {
                    try {
                        var chunkBase = base.add(offset);
                        var thisChunkSize = Math.min(chunkSize, size - offset);

                        scanRegion({
                            base: chunkBase,
                            size: thisChunkSize,
                            protection: "r-x"
                        });
                    } catch (e) {}
                }
            }
        } catch (e) {
            console.log("[-] Error scanning module: " + e);
        }
    }

    // Scan heap memory
    function scanHeap() {
        console.log("[*] Scanning heap memory...");

        try {
            // Get all readable memory ranges
            var ranges = Process.enumerateRanges('r--');
            ranges = ranges.concat(Process.enumerateRanges('rw-'));

            // Scan each range (limit to avoid overwhelming)
            var maxRanges = 100;
            ranges.slice(0, maxRanges).forEach(scanRegion);

            console.log("[*] Scanned " + Math.min(ranges.length, maxRanges) + " memory ranges");
        } catch (e) {
            console.log("[-] Error scanning heap: " + e);
        }
    }

    // Search for NSString objects with interesting content
    function scanNSStrings() {
        console.log("[*] Scanning NSString objects...");

        try {
            var NSString = ObjC.classes.NSString;

            ObjC.chooseSync(NSString).forEach(function(instance) {
                try {
                    var str = instance.toString();

                    // Check if string matches any pattern
                    patterns.forEach(function(pattern) {
                        if (pattern.regex.test(str) && str.length > 10) {
                            // Check if already found
                            var alreadyFound = secrets.some(function(s) {
                                return s.secret === str && s.pattern === pattern.name;
                            });

                            if (!alreadyFound && str.length < 200) {
                                secrets.push({
                                    pattern: pattern.name + " (NSString)",
                                    secret: str,
                                    address: instance.toString(),
                                    length: str.length,
                                    region: "heap"
                                });

                                console.log("[+] NSString " + pattern.name + ": " +
                                          str.substring(0, 50) + (str.length > 50 ? "..." : ""));
                            }
                        }
                    });
                } catch (e) {}
            });
        } catch (e) {
            console.log("[-] Error scanning NSStrings: " + e);
        }
    }

    // Main execution
    setTimeout(function() {
        // Scan main executable
        var appname = ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_("CFBundleName").toString();
        scanModule(appname);

        // Scan heap
        scanHeap();

        // Scan NSStrings
        scanNSStrings();

        // Wait a bit for async operations
        setTimeout(function() {
            console.log("[*] Scan complete. Total regions scanned: " + scannedRanges);
            console.log("[*] Total secrets found: " + secrets.length);

            if (secrets.length > 0) {
                console.log("\n[*] Summary:");
                console.log(JSON.stringify(secrets, null, 2));
            } else {
                console.log("[*] No secrets found with current patterns.");
                console.log("[*] Try triggering sensitive operations (login, API calls) and run again.");
            }
        }, 2000);
    }, 1000);

} else {
    console.log("[-] This script requires Objective-C runtime (iOS app)");
}
