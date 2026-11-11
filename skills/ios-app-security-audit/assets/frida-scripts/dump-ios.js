/**
 * DUMP iOS - Binary Decryption - iOS [STABLE]
 *
 * Purpose: Dumps decrypted iOS app binaries and dynamic libraries from memory
 * Usage: frida -U -f <BUNDLE_ID> -l dump-ios.js
 * Then call: dumpModule("AppName.app") or dumpModule("library.dylib")
 *
 * What it hooks:
 * - Memory reading utilities (Memory.read*)
 * - File I/O operations (open, read, write, lseek)
 * - Mach-O header parsing and encryption info extraction
 *
 * Features:
 * - Decrypts encrypted iOS app binaries in-memory
 * - Supports both .app binaries and .dylib libraries
 * - Handles 32-bit and 64-bit Mach-O formats
 * - Automatically finds writable directory for output
 * - Removes encryption flags from dumped binary
 *
 * OWASP MASTG References:
 * - MASTG-APP-ARCH-001: Architecture and Code Analysis
 * - MASTG-APP-PROT-004: Code Obfuscation and Encryption
 *
 * Compatible with: Frida 16.x+, iOS 12-17
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@lichao890427/dump-ios/
 * Author: @lichao890427
 */

if (ObjC.available) {
    try {
        console.log("[*] ================================================");
        console.log("[*] DUMP iOS - Binary Decryption - iOS STARTED");
        console.log("[*] ================================================");

        var CONFIG = {
            verbose: true,
            bufferSize: 4096,
            searchDirsMax: 10
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

        var O_RDONLY = 0;
        var O_WRONLY = 1;
        var O_RDWR = 2;
        var O_CREAT = 512;

        var SEEK_SET = 0;
        var SEEK_CUR = 1;
        var SEEK_END = 2;

        var MH_MAGIC = 0xfeedface;
        var MH_CIGAM = 0xcefaedfe;
        var MH_MAGIC_64 = 0xfeedfacf;
        var MH_CIGAM_64 = 0xcffaedfe;
        var LC_SEGMENT = 0x1;
        var LC_SEGMENT_64 = 0x19;
        var LC_ENCRYPTION_INFO = 0x21;
        var LC_ENCRYPTION_INFO_64 = 0x2C;

        NSString = ObjC.classes.NSString;
        NSFileManager = ObjC.classes.NSFileManager;

        function allocStr(str) {
            return Memory.allocUtf8String(str);
        }

        function getNSString(str) {
            return NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
        }

        function getStr(addr) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readUtf8String();
        }

        function getStrSize(addr, size) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readUtf8String(size);
        }

        function putStr(addr, str) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.writeUtf8String(str);
        }

        function getU8(addr) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readU8();
        }

        function putU8(addr, n) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.writeU8(n);
        }

        function getU16(addr) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readU16();
        }

        function putU16(addr, n) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.writeU16(n);
        }

        function getU32(addr) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readU32();
        }

        function putU32(addr, n) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.writeU32(n);
        }

        function getU64(addr) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.readU64();
        }

        function putU64(addr, n) {
            if (typeof addr == "number") {
                addr = ptr(addr);
            }
            return addr.writeU64(n);
        }

        function malloc(size) {
            return Memory.alloc(size);
        }

        function getExportFunction(type, name, ret, args) {
            try {
                var nptr = Module.getGlobalExportByName(name);
                if (nptr === null) {
                    logError("Cannot find export: " + name);
                    return null;
                } else {
                    if (type === "f") {
                        var funclet = new NativeFunction(nptr, ret, args);
                        if (typeof funclet === "undefined") {
                            logError("Parse error for: " + name);
                            return null;
                        }
                        return funclet;
                    } else if (type === "d") {
                        var datalet = nptr.readPointer();
                        if (typeof datalet === "undefined") {
                            logError("Parse error for: " + name);
                            return null;
                        }
                        return datalet;
                    }
                }
            } catch (e) {
                logError("Exception in getExportFunction(" + name + "): " + e.message);
                return null;
            }
        }

        var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
        var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
        var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
        var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
        var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
        var close = getExportFunction("f", "close", "int", ["int"]);

        if (!NSSearchPathForDirectoriesInDomains || !wrapper_open || !read || !write || !lseek || !close) {
            logError("One or more required native functions could not be resolved. dumpModule() will not work.");
        }

        function getCacheDir(index) {
            try {
                var NSUserDomainMask = 1;
                var npdirs = NSSearchPathForDirectoriesInDomains(index, NSUserDomainMask, 1);
                var len = ObjC.Object(npdirs).count();
                if (len == 0) {
                    return "";
                }
                return ObjC.Object(npdirs).objectAtIndex_(0).toString();
            } catch (e) {
                logError("Exception in getCacheDir: " + e.message);
                return "";
            }
        }

        function open(pathname, flags, mode) {
            if (typeof pathname == "string") {
                pathname = allocStr(pathname);
            }
            return wrapper_open(pathname, flags, mode);
        }

        var modules = null;
        function getAllAppModules() {
            try {
                if (modules == null) {
                    modules = new Array();
                    var tmpmods = Process.enumerateModules();
                    for (var i = 0; i < tmpmods.length; i++) {
                        if (tmpmods[i].path.indexOf(".app") != -1) {
                            modules.push(tmpmods[i]);
                        }
                    }
                    if (CONFIG.verbose) {
                        logInfo("Found " + modules.length + " app modules");
                    }
                }
                return modules;
            } catch (e) {
                logError("Exception in getAllAppModules: " + e.message);
                return [];
            }
        }

        function dumpModule(name) {
            try {
                if (!NSSearchPathForDirectoriesInDomains || !wrapper_open || !read || !write || !lseek || !close) {
                    logError("dumpModule: required native functions are not available. Aborting.");
                    return;
                }

                if (modules == null) {
                    modules = getAllAppModules();
                }

                var targetmod = null;
                var targetIndex = -1;
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].path.indexOf(name) != -1) {
                        targetmod = modules[i];
                        targetIndex = i;
                        break;
                    }
                }

                if (targetmod == null) {
                    logError("Cannot find module: " + name);
                    logInfo("Available modules:");
                    for (var i = 0; i < modules.length; i++) {
                        console.log("  - " + modules[i].name + " (" + modules[i].path + ")");
                    }
                    return;
                }

                logInfo("Target module: " + targetmod.name);
                logInfo("Base address: " + targetmod.base);
                logInfo("Size: 0x" + targetmod.size.toString(16));

                var modbase = modules[targetIndex].base;
                var modsize = modules[targetIndex].size;
                var newmodname = modules[targetIndex].name + ".decrypted";
                var newmodpath = "";
                var fmodule = -1;
                var index = 1;

                logInfo("Searching for writable directory...");
                while (index <= CONFIG.searchDirsMax) {
                    try {
                        var base = getCacheDir(index);
                        if (base != null && base != "") {
                            newmodpath = base + "/" + newmodname;
                            fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
                            if (fmodule != -1) {
                                logSuccess("Found writable directory: " + newmodpath);
                                break;
                            }
                        }
                    } catch (e) {
                        if (CONFIG.verbose) {
                            logError("Exception while searching directory " + index + ": " + e.message);
                        }
                    }
                    index++;
                }

                if (fmodule == -1) {
                    logError("Cannot find writable directory");
                    return;
                }

                var oldmodpath = modules[targetIndex].path;
                var foldmodule = open(oldmodpath, O_RDONLY, 0);
                if (fmodule == -1 || foldmodule == -1) {
                    logError("Cannot open files");
                    close(fmodule);
                    close(foldmodule);
                    return;
                }

                logInfo("Copying original file...");
                var buffer = malloc(CONFIG.bufferSize);
                var bytesRead = 0;
                while ((bytesRead = read(foldmodule, buffer, CONFIG.bufferSize)) > 0) {
                    write(fmodule, buffer, bytesRead);
                }

                logInfo("Processing Mach-O encryption info...");
                var is64bit = false;
                var size_of_mach_header = 0;
                var magic = getU32(modbase);

                if (magic == MH_MAGIC || magic == MH_CIGAM) {
                    is64bit = false;
                    size_of_mach_header = 28;
                    logInfo("Detected 32-bit Mach-O binary");
                } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
                    is64bit = true;
                    size_of_mach_header = 32;
                    logInfo("Detected 64-bit Mach-O binary");
                } else {
                    logError("Invalid Mach-O magic: 0x" + magic.toString(16));
                    close(fmodule);
                    close(foldmodule);
                    return;
                }

                var ncmds = getU32(modbase.add(16));
                logInfo("Number of load commands: " + ncmds);

                var off = size_of_mach_header;
                var offset_cryptoff = -1;
                var crypt_off = 0;
                var crypt_size = 0;

                for (var i = 0; i < ncmds; i++) {
                    var cmd = getU32(modbase.add(off));
                    var cmdsize = getU32(modbase.add(off + 4));

                    if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
                        offset_cryptoff = off + 8;
                        crypt_off = getU32(modbase.add(off + 8));
                        crypt_size = getU32(modbase.add(off + 12));
                        logInfo("Found encryption info at offset: 0x" + off.toString(16));
                        logInfo("  cryptoff: 0x" + crypt_off.toString(16));
                        logInfo("  cryptsize: 0x" + crypt_size.toString(16));
                    }

                    off += cmdsize;
                }

                if (offset_cryptoff != -1) {
                    logInfo("Removing encryption flags...");
                    var tpbuf = malloc(8);
                    putU64(tpbuf, 0);
                    lseek(fmodule, offset_cryptoff, SEEK_SET);
                    write(fmodule, tpbuf, 8);
                    logSuccess("Removed encryption flags");

                    logInfo("Writing decrypted data...");
                    lseek(fmodule, crypt_off, SEEK_SET);
                    write(fmodule, modbase.add(crypt_off), crypt_size);
                    logSuccess("Wrote decrypted data (0x" + crypt_size.toString(16) + " bytes)");
                } else {
                    logWarn("No encryption info found - binary may already be decrypted");
                }

                logSuccess("Decrypted file saved to: " + newmodpath);
                logInfo("File size: 0x" + modsize.toString(16) + " bytes");

                close(fmodule);
                close(foldmodule);

                logInfo("Usage:");
                logInfo("  1. Copy file from device: scp root@device_ip:" + newmodpath + " .");
                logInfo("  2. Analyze with class-dump, Hopper, IDA, etc.");

            } catch (e) {
                logError("Exception in dumpModule: " + e.message);
                if (CONFIG.verbose) {
                    console.log(e.stack);
                }
            }
        }

        logInfo("Script loaded successfully");
        logInfo("Usage: dumpModule(\"AppName.app\") or dumpModule(\"library.dylib\")");
        logInfo("Example: dumpModule(\".app\")");

    } catch (e) {
        console.log("\x1b[31m[!] ERROR: " + e.message + "\x1b[0m");
        console.log(e.stack);
    }
} else {
    console.log("[!] Objective-C runtime not available - this script requires an iOS target");
}
