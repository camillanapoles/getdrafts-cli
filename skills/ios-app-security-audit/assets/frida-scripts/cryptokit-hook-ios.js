/**
 * CryptoKit Monitor for iOS
 *
 * Monitors Swift CryptoKit cryptographic operations.
 * CryptoKit is Swift-only and doesn't expose ObjC symbols, so this script
 * uses indirect detection and lower-level hooks.
 *
 * What it monitors:
 * - CryptoKit AES.GCM operations
 * - CryptoKit ChaChaPoly1305 operations
 * - CryptoKit HMAC/SHA operations
 * - CryptoKit key derivation
 * - CryptoKit digital signatures
 * - Underlying crypto operations that CryptoKit uses
 *
 * Compatible with: Frida 16.x+ and iOS 13+
 * Usage: frida -U -f <bundle_id> -l cryptokit-hook-ios.js
 * OWASP MASTG: MSTG-CRYPTO-1, MSTG-CRYPTO-2
 *
 * Note: CryptoKit is Swift-native and doesn't expose ObjC runtime symbols.
 * This script hooks the underlying Apple crypto framework calls.
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m CryptoKit Monitor iOS Script Started");

    var CONFIG = {
        maxDataLength: 256,
        logFullKey: false,
        detectWeakCrypto: true,
        DEBUG_MODE: false
    };

    var cryptoCount = 0;
    var weakCryptoCount = 0;

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function bytesToHex(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || CONFIG.maxDataLength;
                var hex = "";

                try {
                    var totalLen;
                    if (bytes instanceof ArrayBuffer) {
                        totalLen = bytes.byteLength;
                    } else if (bytes && typeof bytes.byteLength === "number") {
                        totalLen = bytes.byteLength;
                    } else {
                        totalLen = maxLength;
                    }

                    var bytesToRead = Math.min(totalLen, maxLength);
                    for (var i = 0; i < bytesToRead; i++) {
                        var b;
                        if (bytes instanceof ArrayBuffer) {
                            b = new Uint8Array(bytes)[i];
                        } else if (bytes && typeof bytes.readU8 === "function") {
                            b = bytes.add(i).readU8();
                        } else {
                            return "<unsupported bytes type>";
                        }
                        hex += ("0" + b.toString(16)).slice(-2);
                    }
                    if (totalLen > maxLength) {
                        hex += "... (" + totalLen + " bytes total)";
                    }
                } catch (e) {
                    hex = "<cannot read>";
                }

                return hex;
            }

            function nsDataToHex(data, maxLength) {
                if (!data) return "null";
                try {
                    return bytesToHex(data.bytes(), maxLength);
                } catch (e) {
                    return "<data>";
                }
            }

            // CryptoKit internally uses Apple's corecrypto library
            // Hook corecrypto AES operations (used by CryptoKit.AES)
            try {
                var ccaes = Module.findGlobalExportByName("ccaes_ecb_encrypt_mode");
                if (ccaes) {
                    console.log("\x1b[32m[+]\x1b[0m corecrypto AES module detected (CryptoKit likely in use)");
                }

                // Try to hook CommonCrypto (CryptoKit may fall back to it).
                // CommonCrypto is not a standalone module on iOS: its symbols are
                // exported from libSystem, so a module-scoped lookup cannot be
                // relied on. A global search finds them regardless of the layout.
                var _ccCryptAddr = Module.findGlobalExportByName('CCCrypt');
                if (_ccCryptAddr) {
                    console.log("\x1b[32m[+]\x1b[0m CommonCrypto symbol found");

                    var CCCrypt = new NativeFunction(
                        _ccCryptAddr,
                        'int',
                        ['uint32', 'uint32', 'uint32', 'pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'pointer']
                    );

                    Interceptor.attach(CCCrypt, {
                        onEnter: function(args) {
                            this.op = args[0].toInt32();
                            this.alg = args[1].toInt32();
                            this.key = args[3];
                            this.keyLength = args[4].toInt32();
                            this.dataIn = args[6];
                            this.dataInLength = args[7].toInt32();
                        },
                        onLeave: function(retval) {
                            cryptoCount++;
                            try {
                                var opStr = this.op === 0 ? "ENCRYPT" : this.op === 1 ? "DECRYPT" : "UNKNOWN";
                                var algStr = this.alg === 0 ? "AES128" : this.alg === 10 ? "AES256" : "UNKNOWN";

                                console.log("\x1b[32m[+]\x1b[0m CryptoKit/CommonCrypto: " + opStr + "-" + algStr);
                                console.log("    Key: " + (CONFIG.logFullKey ? bytesToHex(this.key, this.keyLength) : bytesToHex(this.key, 8) + "..."));

                                if (this.dataIn && !this.dataIn.isNull() && this.dataInLength > 0) {
                                    var inputData = this.dataIn.readByteArray(Math.min(this.dataInLength, 64));
                                    console.log("    Input: " + hexdump(inputData, { length: Math.min(this.dataInLength, 64), ansi: true }));
                                }
                            } catch (ex) {
                                console.log("\x1b[31m[!]\x1b[0m CCCrypt error: " + ex.message);
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m CCCrypt hooked (monitors CryptoKit AES operations)");
                } else {
                    console.log("\x1b[31m[-]\x1b[0m CommonCrypto not found (app may use pure CryptoKit)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CommonCrypto hook failed: " + e.message);
            }

            // Hook SecKey operations (used by CryptoKit for asymmetric crypto)
            try {
                var Security = Process.findModuleByName('Security');
                if (Security) {
                    var _secCreateAddr = Security.getExportByName('SecKeyCreateWithData');
                    if (_secCreateAddr) {
                        var SecKeyCreateWithData = new NativeFunction(
                            _secCreateAddr,
                            'pointer',
                            ['pointer', 'pointer', 'pointer']
                        );

                        Interceptor.attach(SecKeyCreateWithData, {
                            onLeave: function(retval) {
                                cryptoCount++;
                                try {
                                    console.log("\x1b[36m[i]\x1b[0m CryptoKit SecKeyCreateWithData: Key created");

                                    if (retval && !retval.isNull()) {
                                        var key = ObjC.Object(retval);
                                        console.log("    Key type: " + key.$className);
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m SecKeyCreateWithData error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m SecKeyCreateWithData hooked");
                    }

                    var _secSignAddr = Security.getExportByName('SecKeyCreateSignature');
                    if (_secSignAddr) {
                        var SecKeyCreateSignature = new NativeFunction(
                            _secSignAddr,
                            'pointer',
                            ['pointer', 'pointer', 'pointer', 'pointer']
                        );

                        Interceptor.attach(SecKeyCreateSignature, {
                            onEnter: function(args) {
                                this.algorithm = args[1];
                                this.data = args[2];
                            },
                            onLeave: function(retval) {
                                cryptoCount++;
                                try {
                                    console.log("\x1b[36m[i]\x1b[0m CryptoKit SecKeyCreateSignature: Signing operation");

                                    if (this.data && !this.data.isNull()) {
                                        var dataObj = ObjC.Object(this.data);
                                        console.log("    Data: " + nsDataToHex(dataObj, 64));
                                    }

                                    if (retval && !retval.isNull()) {
                                        var signature = ObjC.Object(retval);
                                        console.log("    Signature: " + nsDataToHex(signature, 64));
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m SecKeyCreateSignature error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m SecKeyCreateSignature hooked");
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Security framework hook failed: " + e.message);
            }

            // Detect Swift classes that indicate CryptoKit usage
            try {
                console.log("\x1b[36m[*]\x1b[0m Scanning for CryptoKit symbols...");

                var cryptoKitSymbols = [
                    "AES",
                    "ChaChaPoly",
                    "HMAC",
                    "SHA256",
                    "SHA384",
                    "SHA512",
                    "Curve25519",
                    "P256",
                    "P384",
                    "P521"
                ];

                var foundSymbols = [];

                Process.enumerateModules().forEach(function(module) {
                    if (module.name.indexOf("Swift") !== -1 || module.name.indexOf("CryptoKit") !== -1) {
                        try {
                            module.enumerateSymbols().forEach(function(symbol) {
                                var name = symbol.name;
                                cryptoKitSymbols.forEach(function(cryptoSym) {
                                    if (name.indexOf(cryptoSym) !== -1) {
                                        foundSymbols.push(module.name + "::" + name);
                                    }
                                });
                            });
                        } catch (e) {
                            // Symbol enumeration may fail for some modules
                        }
                    }
                });

                if (foundSymbols.length > 0) {
                    console.log("\x1b[32m[+]\x1b[0m CryptoKit symbols detected:");
                    foundSymbols.slice(0, 20).forEach(function(sym) {
                        console.log("    " + sym);
                    });
                    if (foundSymbols.length > 20) {
                        console.log("    ... and " + (foundSymbols.length - 20) + " more");
                    }
                } else {
                    console.log("\x1b[33m[*]\x1b[0m No CryptoKit symbols found (app may not use CryptoKit)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Symbol scan failed: " + e.message);
            }

            // Check for CryptoKit.SymmetricKey usage patterns
            try {
                if (ObjC.available) {
                    // Check if any Swift classes are available (limited detection)
                    var swiftModuleNames = Object.keys(ObjC.classes).filter(function(cls) {
                        return cls.indexOf("$") === 0; // Swift mangled names start with $
                    });

                    var cryptoKitClasses = swiftModuleNames.filter(function(cls) {
                        return cls.toLowerCase().indexOf("cryptokit") !== -1 ||
                               cls.toLowerCase().indexOf("symmetrickey") !== -1 ||
                               cls.toLowerCase().indexOf("sha") !== -1;
                    });

                    if (cryptoKitClasses.length > 0) {
                        console.log("\x1b[32m[+]\x1b[0m CryptoKit Swift classes detected:");
                        cryptoKitClasses.slice(0, 10).forEach(function(cls) {
                            console.log("    " + cls);
                        });
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Swift class scan failed: " + e.message);
            }

            console.log("\x1b[33m[*]\x1b[0m CryptoKit Monitor iOS Script Loaded");
            console.log("\x1b[36m[*]\x1b[0m Monitoring for cryptographic operations...");

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m CryptoKit Monitor iOS error: " + e.message);
        }
    });

    setInterval(function() {
        if (cryptoCount > 0) {
            console.log("\x1b[36m[*]\x1b[0m Stats - Crypto ops: " + cryptoCount + " | Weak crypto: " + weakCryptoCount);
        }
    }, 30000);

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
