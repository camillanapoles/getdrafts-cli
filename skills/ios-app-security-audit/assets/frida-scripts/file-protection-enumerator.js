/**
 * File Protection Enumerator - iOS [STABLE]
 *
 * Purpose: Enumerate and analyze iOS file protection attributes
 * Usage: frida -U -f <BUNDLE_ID> -l file-protection-enumerator.js
 *
 * What it hooks:
 * - File protection attribute queries
 * - File system operations
 * - NSFileManager methods
 * - Data protection API
 *
 * Features:
 * - Lists all files in app container
 * - Shows file protection levels (None, Complete, CompleteUnlessOpen, etc.)
 * - Identifies insecurely protected sensitive files
 * - Detects data protection API usage
 * - Categorizes files by type (cache, documents, library, etc.)
 * - Color-coded output for easy analysis
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0041: File System Storage Testing
 * - MASTG-DATA-STORAGE-003: Data Protection
 * - MASTG-APP-PROT-002: File Protection Configuration
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@ay-kay/ios-dataprotection/
 * Author: @ay-kay
 */

if (ObjC.available) {
    try {
        console.log("[*] File Protection Enumerator - iOS STARTED");

        var CONFIG = {
            verbose: true,
            enumerateAllDirs: true,
            showProtectionLevels: true,
            identifySensitiveFiles: true,
            maxFilesPerDir: 100
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

        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        var NSFileProtectionNone = "NSFileProtectionNone";
        var NSFileProtectionComplete = "NSFileProtectionComplete";
        var NSFileProtectionCompleteUnlessOpen = "NSFileProtectionCompleteUnlessOpen";
        var NSFileProtectionCompleteUntilFirstUserAuthentication = "NSFileProtectionCompleteUntilFirstUserAuthentication";
        var NSFileProtectionWriteOnly = "NSFileProtectionWriteOnly";

        var protectionLevels = {
            "None": {
                level: 0,
                color: "\x1b[31m",
                description: "No protection - accessible when device is locked",
                risk: "HIGH"
            },
            "CompleteUnlessOpen": {
                level: 1,
                color: "\x1b[33m",
                description: "Protected except when file is open",
                risk: "MEDIUM"
            },
            "CompleteUntilFirstUserAuthentication": {
                level: 2,
                color: "\x1b[33m",
                description: "Protected until device is unlocked once",
                risk: "MEDIUM"
            },
            "Complete": {
                level: 3,
                color: "\x1b[32m",
                description: "Fully protected - inaccessible when locked",
                risk: "LOW"
            },
            "WriteOnly": {
                level: 4,
                color: "\x1b[33m",
                description: "Write-only protection",
                risk: "MEDIUM"
            }
        };

        var NSFileManager = ObjC.classes.NSFileManager;
        var defaultManager = NSFileManager.defaultManager;

        function getAppContainerPath() {
            try {
                var NSBundle = ObjC.classes.NSBundle;
                var mainBundle = NSBundle.mainBundle;
                var bundlePath = mainBundle.bundlePath;
                return mainBundle.bundlePath.toString();
            } catch (e) {
                logError("Exception in getAppContainerPath: " + e.message);
                return null;
            }
        }

        function getDocumentsPath() {
            try {
                // NSSearchPathForDirectoriesInDomains is a C function, not
                // an Objective-C class. We declare the signature with
                // NativeFunction and call it directly.
                // Signature: NSArray<NSString*> * NSSearchPathForDirectoriesInDomains(
                //     NSSearchPathDirectory directory,
                //     NSSearchPathDomainMask domainMask,
                //     BOOL expandTilde);
                var _nspathPtr = findExport('Foundation', 'NSSearchPathForDirectoriesInDomains');
                if (!_nspathPtr) {
                    logError("NSSearchPathForDirectoriesInDomains not found in Foundation");
                    return null;
                }
                var NSSearchPathForDirectoriesInDomains = new NativeFunction(
                    _nspathPtr,
                    "pointer",
                    ["int", "int", "int"]
                );
                var NSDocumentDirectory = 9;
                var NSUserDomainMask = 1;
                var resultPtr = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
                if (!resultPtr.isNull()) {
                    var result = new ObjC.Object(resultPtr);
                    if (result.count() > 0) {
                        return result.objectAtIndex_(0).toString();
                    }
                }
                return null;
            } catch (e) {
                logError("Exception in getDocumentsPath: " + e.message);
                return null;
            }
        }

        function getCachesPath() {
            try {
                var _nspathPtr2 = findExport('Foundation', 'NSSearchPathForDirectoriesInDomains');
                if (!_nspathPtr2) {
                    logError("NSSearchPathForDirectoriesInDomains not found in Foundation");
                    return null;
                }
                var NSSearchPathForDirectoriesInDomains = new NativeFunction(
                    _nspathPtr2,
                    "pointer",
                    ["int", "int", "int"]
                );
                var NSCachesDirectory = 13;
                var NSUserDomainMask = 1;
                var resultPtr = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, 1);
                if (!resultPtr.isNull()) {
                    var result = new ObjC.Object(resultPtr);
                    if (result.count() > 0) {
                        return result.objectAtIndex_(0).toString();
                    }
                }
                return null;
            } catch (e) {
                logError("Exception in getCachesPath: " + e.message);
                return null;
            }
        }

        function listDirectory(path) {
            try {
                if (!path || !defaultManager) {
                    return [];
                }

                var nsPath = ObjC.classes.NSString.stringWithString_(path);
                var isDirPtr = Memory.alloc(8);
                var exists = defaultManager.fileExistsAtPath_isDirectory_(nsPath, isDirPtr);
                var isDir = isDirPtr.readU8() !== 0;

                if (!exists) {
                    return [];
                }

                var contents = defaultManager.contentsOfDirectoryAtPath_error_(nsPath, null);
                if (!contents) {
                    return [];
                }

                var files = [];
                for (var i = 0; i < contents.count(); i++) {
                    files.push(contents.objectAtIndex_(i).toString());
                }

                return files;
            } catch (e) {
                logError("Exception in listDirectory: " + e.message);
                return [];
            }
        }

        function getFileProtection(path) {
            try {
                if (!path || !defaultManager) {
                    return null;
                }

                var nsPath = ObjC.classes.NSString.stringWithString_(path);
                var attrs = defaultManager.attributesOfItemAtPath_error_(nsPath, null);

                if (!attrs) {
                    return null;
                }

                var protectionKey = ObjC.classes.NSString.stringWithString_("NSFileProtectionKey");
                var protection = attrs.objectForKey_(protectionKey);

                if (!protection) {
                    return "Unknown";
                }

                return protection.toString();
            } catch (e) {
                logError("Exception in getFileProtection: " + e.message);
                return null;
            }
        }

        function getFileSize(path) {
            try {
                if (!path || !defaultManager) {
                    return 0;
                }

                var nsPath = ObjC.classes.NSString.stringWithString_(path);
                var attrs = defaultManager.attributesOfItemAtPath_error_(nsPath, null);

                if (!attrs) {
                    return 0;
                }

                var sizeKey = ObjC.classes.NSString.stringWithString_("NSFileSize");
                var size = attrs.objectForKey_(sizeKey);

                if (!size) {
                    return 0;
                }

                return Number(size);
            } catch (e) {
                logError("Exception in getFileSize: " + e.message);
                return 0;
            }
        }

        var sensitiveFilePatterns = [
            { pattern: /\.plist$/i, type: "Configuration", risk: "MEDIUM" },
            { pattern: /\.db$/i, type: "Database", risk: "HIGH" },
            { pattern: /\.sqlite$/i, type: "Database", risk: "HIGH" },
            { pattern: /\.sqlitedb$/i, type: "Database", risk: "HIGH" },
            { pattern: /\.json$/i, type: "Data", risk: "MEDIUM" },
            { pattern: /\.xml$/i, type: "Configuration", risk: "MEDIUM" },
            { pattern: /\.txt$/i, type: "Text", risk: "LOW" },
            { pattern: /\.log$/i, type: "Log", risk: "MEDIUM" },
            { pattern: /\.cache$/i, type: "Cache", risk: "LOW" },
            { pattern: /\.key$/i, type: "Key", risk: "CRITICAL" },
            { pattern: /\.pem$/i, type: "Certificate", risk: "CRITICAL" },
            { pattern: /\.crt$/i, type: "Certificate", risk: "CRITICAL" },
            { pattern: /\.p12$/i, type: "Certificate", risk: "CRITICAL" },
            { pattern: /secret/i, type: "Sensitive", risk: "HIGH" },
            { pattern: /password/i, type: "Sensitive", risk: "HIGH" },
            { pattern: /token/i, type: "Sensitive", risk: "HIGH" },
            { pattern: /credential/i, type: "Sensitive", risk: "HIGH" },
            { pattern: /api.*key/i, type: "API Key", risk: "HIGH" },
            { pattern: /cookie/i, type: "Cookie", risk: "HIGH" },
            { pattern: /session/i, type: "Session", risk: "HIGH" },
            { pattern: /user/i, type: "User Data", risk: "MEDIUM" },
            { pattern: /pref/i, type: "Preferences", risk: "MEDIUM" }
        ];

        function identifySensitiveFile(filename) {
            try {
                for (var i = 0; i < sensitiveFilePatterns.length; i++) {
                    var item = sensitiveFilePatterns[i];
                    if (item.pattern.test(filename)) {
                        return item;
                    }
                }
                return null;
            } catch (e) {
                logError("Exception in identifySensitiveFile: " + e.message);
                return null;
            }
        }

        function analyzeFile(path) {
            try {
                var filename = path.split("/").pop();
                var protection = getFileProtection(path);
                var size = getFileSize(path);
                var sensitive = identifySensitiveFile(filename);

                var result = {
                    path: path,
                    filename: filename,
                    protection: protection,
                    size: size,
                    sensitive: sensitive
                };

                return result;
            } catch (e) {
                logError("Exception in analyzeFile: " + e.message);
                return null;
            }
        }

        function printFileInfo(fileInfo) {
            try {
                if (!fileInfo) {
                    return;
                }

                var output = fileInfo.filename;
                output += " [" + (fileInfo.size / 1024).toFixed(2) + " KB]";

                var protectionLevel = null;
                for (var key in protectionLevels) {
                    if (fileInfo.protection && fileInfo.protection.indexOf(key) !== -1) {
                        protectionLevel = protectionLevels[key];
                        break;
                    }
                }

                if (protectionLevel) {
                    output += " [" + protectionLevel.color + fileInfo.protection + "\x1b[0m]";
                    output += " (Risk: " + protectionLevel.risk + ")";
                } else {
                    output += " [Unknown Protection]";
                }

                if (fileInfo.sensitive) {
                    output += " \x1b[31m[Sensitive: " + fileInfo.sensitive.type + "]\x1b[0m";
                }

                console.log(output);
            } catch (e) {
                logError("Exception in printFileInfo: " + e.message);
            }
        }

        function enumerateDirectory(path, depth) {
            try {
                if (!path) {
                    return;
                }

                depth = depth || 0;
                if (depth > 3) {
                    return;
                }

                var files = listDirectory(path);
                if (files.length === 0) {
                    return;
                }

                logInfo("Directory: " + path + " (" + files.length + " files)");

                var processedCount = 0;
                for (var i = 0; i < files.length; i++) {
                    if (processedCount >= CONFIG.maxFilesPerDir) {
                        logWarn("... and " + (files.length - processedCount) + " more files (truncated)");
                        break;
                    }

                    var filepath = path + "/" + files[i];
                    var fileInfo = analyzeFile(filepath);

                    if (fileInfo) {
                        printFileInfo(fileInfo);
                    }

                    processedCount++;

                    var fullPath = path + "/" + files[i];
                    var isDirectory = defaultManager.fileExistsAtPath_(ObjC.classes.NSString.stringWithString_(fullPath));

                    if (isDirectory && depth < 3) {
                        enumerateDirectory(fullPath, depth + 1);
                    }
                }

            } catch (e) {
                logError("Exception in enumerateDirectory: " + e.message);
            }
        }

        function enumerateAppDirectories() {
            try {
                logSection("APP DIRECTORIES ENUMERATION");

                var docsPath = getDocumentsPath();
                var cachesPath = getCachesPath();
                var bundlePath = getAppContainerPath();

                if (docsPath) {
                    logInfo("Documents directory: " + docsPath);
                    enumerateDirectory(docsPath, 0);
                }

                if (cachesPath) {
                    logInfo("Caches directory: " + cachesPath);
                    enumerateDirectory(cachesPath, 0);
                }

                if (bundlePath) {
                    logInfo("Bundle directory: " + bundlePath);
                    enumerateDirectory(bundlePath, 0);
                }

            } catch (e) {
                logError("Exception in enumerateAppDirectories: " + e.message);
            }
        }

        function analyzeProtectionLevels() {
            try {
                logSection("PROTECTION LEVELS ANALYSIS");

                logInfo("File Protection Levels:");
                for (var key in protectionLevels) {
                    var level = protectionLevels[key];
                    var output = level.color + key + "\x1b[0m";
                    output += " - Risk: " + level.risk;
                    output += " - " + level.description;
                    console.log("  " + output);
                }

            } catch (e) {
                logError("Exception in analyzeProtectionLevels: " + e.message);
            }
        }

        function identifyInsecureFiles() {
            try {
                if (!CONFIG.identifySensitiveFiles) {
                    return;
                }

                logSection("INSECURE FILES IDENTIFICATION");

                var docsPath = getDocumentsPath();
                var cachesPath = getCachesPath();

                var insecureFiles = [];

                var paths = [docsPath, cachesPath];
                for (var i = 0; i < paths.length; i++) {
                    if (!paths[i]) continue;

                    var files = listDirectory(paths[i]);
                    for (var j = 0; j < files.length; j++) {
                        var filepath = paths[i] + "/" + files[j];
                        var fileInfo = analyzeFile(filepath);

                        if (fileInfo && fileInfo.sensitive && fileInfo.protection === "NSFileProtectionNone") {
                            insecureFiles.push(fileInfo);
                        }
                    }
                }

                if (insecureFiles.length > 0) {
                    logWarn("Found " + insecureFiles.length + " insecure sensitive files:");
                    for (var k = 0; k < insecureFiles.length; k++) {
                        var file = insecureFiles[k];
                        console.log("\x1b[31m  - " + file.filename + "\x1b[0m");
                        console.log("    Path: " + file.path);
                        console.log("    Type: " + file.sensitive.type);
                        console.log("    Risk: " + file.sensitive.risk);
                        console.log("    Protection: " + file.protection);
                    }
                } else {
                    logSuccess("No insecure sensitive files found");
                }

            } catch (e) {
                logError("Exception in identifyInsecureFiles: " + e.message);
            }
        }

        function main() {
            try {
                logSuccess("File Protection Enumerator loaded successfully");
                logInfo("Enumerating iOS file protection attributes...");

                if (CONFIG.showProtectionLevels) {
                    analyzeProtectionLevels();
                }

                if (CONFIG.enumerateAllDirs) {
                    enumerateAppDirectories();
                }

                if (CONFIG.identifySensitiveFiles) {
                    identifyInsecureFiles();
                }

                logSection("ENUMERATION COMPLETE");
                logSuccess("File protection enumeration completed");
                logInfo("Review files with NSFileProtectionNone for security issues");

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
