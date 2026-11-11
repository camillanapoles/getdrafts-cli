/**
 * Secure Enclave Usage Probe (BETA)
 *
 * Probes Secure Enclave usage in the application:
 * - Hook SecAccessControlCreateWithFlags
 * - Hook SecKeyCreateRandomKey with Secure Enclave
 * - Hook SecKeyCreateDecryptedData
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l secure-enclave-probe.js
 * OWASP MASVS: MSTG-CRYPTO-5, MSTG-CRYPTO-6
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Secure Enclave Probe Script Started (BETA)");

    var CONFIG = {
        logKeyCreation: true,
        logDecryptOps: true,
        checkAccessControl: true,
        DEBUG_MODE: false
    };
    function accessControlFlagsToString(flags) {
        var flagsArr = [];

        if (flags === null) return "null";

        if (flags & 1) flagsArr.push("kSecAccessControlUserPresence");
        if (flags & 2) flagsArr.push("kSecAccessControlBiometryAny");
        if (flags & 4) flagsArr.push("kSecAccessControlBiometryCurrentSet");
        if (flags & 8) flagsArr.push("kSecAccessControlDevicePasscode");
        if (flags & 16) flagsArr.push("kSecAccessControlApplicationPassword");
        if (flags & 32) flagsArr.push("kSecAccessControlWatch");
        if (flags & 64) flagsArr.push("kSecAccessControlCompanionPasscode");

        return flagsArr.length > 0 ? flagsArr.join(" | ") : "0x" + flags.toString(16);
    }
    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    if (CONFIG.checkAccessControl) {
        var secACCFAddr = findExport('Security', 'SecAccessControlCreateWithFlags');
        if (secACCFAddr) {
            try {
                Interceptor.attach(secACCFAddr, {
                    onEnter: function(args) {
                        try {
                            // args[2] = SecAccessControlCreateFlags (CFOptionFlags = ulong)
                            var flags = args[2].toUInt32();
                            console.log("\x1b[32m[+]\x1b[0m SecAccessControlCreateWithFlags:");
                            console.log("    Flags: " + accessControlFlagsToString(flags));
                        } catch (e) {
                            console.log("    <error reading flags: " + e.message + ">");
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                console.log("    Created successfully");
                            } else {
                                console.log("\x1b[31m[!]\x1b[0m SecAccessControlCreateWithFlags returned NULL");
                            }
                        } catch (e) { /* ignore */ }
                    }
                });
                console.log("\x1b[32m[+]\x1b[0m SecAccessControlCreateWithFlags hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecAccessControlCreateWithFlags hook failed: " + e.message);
            }
        } else {
            console.log("[-] SecAccessControlCreateWithFlags not found in Security framework");
        }
    }
    if (CONFIG.logKeyCreation) {
        var secKeyCreateRandomKeyAddr = findExport('Security', 'SecKeyCreateRandomKey');
        if (secKeyCreateRandomKeyAddr) {
            try {
                Interceptor.attach(secKeyCreateRandomKeyAddr, {
                    onEnter: function(args) {
                        try {
                            // args[0] = CFDictionaryRef attributes
                            // Wrap as ObjC dict only if non-null
                            if (args[0] && !args[0].isNull()) {
                                var attrs = ObjC.Object(args[0]);
                                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateRandomKey:");
                                try {
                                    console.log("    Attributes: " + attrs.description().toString());
                                } catch (e2) {
                                    console.log("    Attributes: <cannot read CFDictionary>");
                                }
                            } else {
                                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateRandomKey: (null attributes)");
                            }
                        } catch (e) {
                            console.log("\x1b[32m[+]\x1b[0m SecKeyCreateRandomKey: <error reading args: " + e.message + ">");
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                console.log("    Key created successfully");
                            } else {
                                console.log("\x1b[31m[!]\x1b[0m SecKeyCreateRandomKey returned NULL (check error param)");
                            }
                        } catch (e) { /* ignore */ }
                    }
                });
                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateRandomKey hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecKeyCreateRandomKey hook failed: " + e.message);
            }
        } else {
            console.log("[-] SecKeyCreateRandomKey not found in Security framework");
        }
    }
    if (CONFIG.logDecryptOps) {
        var secKeyDecryptAddr = findExport('Security', 'SecKeyCreateDecryptedData');
        if (secKeyDecryptAddr) {
            try {
                Interceptor.attach(secKeyDecryptAddr, {
                    onEnter: function(args) {
                        try {
                            // args[0] = SecKeyRef key, args[1] = CFStringRef algorithm, args[2] = CFDataRef ciphertext
                            console.log("\x1b[32m[+]\x1b[0m SecKeyCreateDecryptedData:");
                            if (args[1] && !args[1].isNull()) {
                                try {
                                    console.log("    Algorithm: " + ObjC.Object(args[1]).toString());
                                } catch (e2) {
                                    console.log("    Algorithm: <cannot read>");
                                }
                            }
                            if (args[2] && !args[2].isNull()) {
                                try {
                                    var ciphertext = ObjC.Object(args[2]);
                                    console.log("    Ciphertext Size: " + ciphertext.length() + " bytes");
                                } catch (e2) {
                                    console.log("    Ciphertext: <cannot read size>");
                                }
                            }
                        } catch (e) {
                            console.log("    <error reading args: " + e.message + ">");
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                try {
                                    console.log("    Plaintext Size: " + ObjC.Object(retval).length() + " bytes");
                                } catch (e) {
                                    console.log("    Decryption succeeded");
                                }
                            } else {
                                console.log("\x1b[31m[!]\x1b[0m Decryption failed (returned NULL)");
                            }
                        } catch (e) { /* ignore */ }
                    }
                });
                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateDecryptedData hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecKeyCreateDecryptedData hook failed: " + e.message);
            }
        } else {
            console.log("[-] SecKeyCreateDecryptedData not found in Security framework");
        }
    }
    var secKeySignAddr = findExport('Security', 'SecKeyCreateSignature');
    if (secKeySignAddr) {
        try {
            Interceptor.attach(secKeySignAddr, {
                onEnter: function(args) {
                    try {
                        console.log("\x1b[32m[+]\x1b[0m SecKeyCreateSignature:");
                        if (args[1] && !args[1].isNull()) {
                            try {
                                console.log("    Algorithm: " + ObjC.Object(args[1]).toString());
                            } catch (e2) {
                                console.log("    Algorithm: <cannot read>");
                            }
                        }
                        if (args[2] && !args[2].isNull()) {
                            try {
                                var digest = ObjC.Object(args[2]);
                                console.log("    Digest Size: " + digest.length() + " bytes");
                            } catch (e2) {
                                console.log("    Digest: <cannot read size>");
                            }
                        }
                    } catch (e) {
                        console.log("    <error reading args: " + e.message + ">");
                    }
                },
                onLeave: function(retval) {
                    try {
                        if (retval && !retval.isNull()) {
                            try {
                                console.log("    Signature Size: " + ObjC.Object(retval).length() + " bytes");
                            } catch (e) {
                                console.log("    Signature created");
                            }
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log("\x1b[32m[+]\x1b[0m SecKeyCreateSignature hooked successfully");
        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m SecKeyCreateSignature hook failed: " + e.message);
        }
    } else {
        console.log("[-] SecKeyCreateSignature not found in Security framework");
    }

    // ========================================
    // 6. Hook SecKeyCopyKeyExchangeResult (C function)
    // ========================================
    var secKeyExchangeAddr = findExport('Security', 'SecKeyCopyKeyExchangeResult');
    if (secKeyExchangeAddr) {
        try {
            Interceptor.attach(secKeyExchangeAddr, {
                onEnter: function(args) {
                    try {
                        console.log("\x1b[32m[+]\x1b[0m SecKeyCopyKeyExchangeResult:");
                        if (args[1] && !args[1].isNull()) {
                            try {
                                console.log("    Algorithm: " + ObjC.Object(args[1]).toString());
                            } catch (e2) {
                                console.log("    Algorithm: <cannot read>");
                            }
                        }
                    } catch (e) {
                        console.log("    <error reading args: " + e.message + ">");
                    }
                },
                onLeave: function(retval) {
                    try {
                        if (retval && !retval.isNull()) {
                            try {
                                console.log("    Shared Secret Size: " + ObjC.Object(retval).length() + " bytes");
                            } catch (e) {
                                console.log("    Key exchange succeeded");
                            }
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log("\x1b[32m[+]\x1b[0m SecKeyCopyKeyExchangeResult hooked successfully");
        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m SecKeyCopyKeyExchangeResult hook failed: " + e.message);
        }
    } else {
        console.log("[-] SecKeyCopyKeyExchangeResult not found in Security framework");
    }

    console.log("\x1b[33m[*]\x1b[0m Secure Enclave Probe Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
