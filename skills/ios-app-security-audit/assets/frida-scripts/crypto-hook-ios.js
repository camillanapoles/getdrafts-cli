/**
 * Cryptographic Operations Hook for iOS (BETA)
 *
 * Hooks and logs all cryptographic operations:
 * - CCCrypt (CommonCrypto)
 * - CCDigest (CommonCrypto)
 * - CCHmac (CommonCrypto)
 * - CCKeyDerivationPBKDF
 * - SecKeyCreateDecryptedData (asymmetric decrypt)
 * - SecKeyCreateEncryptedData (asymmetric encrypt)
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l crypto-hook-ios.js
 * OWASP MASVS: MSTG-CRYPTO-1, MSTG-CRYPTO-2
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Crypto Hook iOS Script Started (BETA)");

    var CONFIG = {
        maxDataLength: 256,
        logFullKey: false,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function bytesToHex(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || CONFIG.maxDataLength;
                var hex = "";

                try {
                    // The caller may pass either a NativePointer or a JS ArrayBuffer
                    // view. Normalize to a length we can read safely.
                    var totalLen;
                    if (bytes instanceof ArrayBuffer) {
                        totalLen = bytes.byteLength;
                    } else if (bytes && typeof bytes.byteLength === "number") {
                        totalLen = bytes.byteLength;
                    } else {
                        // Treat as NativePointer — read up to 4KB to stay safe.
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

            // Frida 17: getModuleByName() throws when the module is not loaded and
            // getExportByName() throws when the symbol is missing; the "find"
            // variants return null so an absent module or symbol does not abort
            // the hook.
            function findExport(moduleName, symbolName) {
                var mod = Process.findModuleByName(moduleName);
                return mod ? mod.findExportByName(symbolName) : null;
            }

            function getCipherName(op, alg, options) {
                var opStr = "";
                if (op === 0) opStr = "ENCRYPT";
                else if (op === 1) opStr = "DECRYPT";
                else opStr = "UNKNOWN(" + op + ")";

                var algStr = "";
                if (alg === 0) algStr = "AES128";
                else if (alg === 1) algStr = "DES";
                else if (alg === 2) algStr = "3DES";
                else if (alg === 3) algStr = "CAST";
                else if (alg === 4) algStr = "RC4";
                else if (alg === 5) algStr = "RC2";
                else if (alg === 6) algStr = "Blowfish";
                else if (alg === 10) algStr = "AES256";
                else algStr = "UNKNOWN(" + alg + ")";

                return opStr + "-" + algStr;
            }

            try {
                // CommonCrypto is not a standalone module on iOS: its symbols are
                // exported from libSystem, so a module-scoped lookup cannot be
                // relied on. A global search finds them regardless of the layout.
                var _ccCryptAddr = Module.findGlobalExportByName('CCCrypt');
                if (!_ccCryptAddr) {
                    console.log("\x1b[31m[-]\x1b[0m CCCrypt symbol not found in CommonCrypto");
                } else {
                var CCCrypt = new NativeFunction(
                    _ccCryptAddr,
                    'int',
                    ['uint32', 'uint32', 'uint32', 'pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'pointer']
                );

                Interceptor.attach(CCCrypt, {
                    onEnter: function(args) {
                        this.op = args[0].toInt32();
                        this.alg = args[1].toInt32();
                        this.options = args[2].toInt32();
                        this.key = args[3];
                        this.keyLength = args[4].toInt32();
                        this.iv = args[5];
                        this.dataIn = args[6];
                        this.dataInLength = args[7].toInt32();
                        this.dataOut = args[8];
                        this.dataOutAvailable = args[9].toInt32();
                        this.dataOutMoved = args[10];
                    },
                    onLeave: function(retval) {
                        try {
                            var cipherName = getCipherName(this.op, this.alg, this.options);

                            console.log("\x1b[32m[+]\x1b[0m CCCrypt:");
                            console.log("    Operation: " + cipherName);
                            console.log("    Key: " + (CONFIG.logFullKey ? bytesToHex(this.key, this.keyLength) : bytesToHex(this.key, 8) + "..."));

                            if (this.iv && !this.iv.isNull()) {
                                console.log("    IV: " + bytesToHex(this.iv, 16));
                            }

                            if (this.dataIn && !this.dataIn.isNull() && this.dataInLength > 0) {
                                var inputData = this.dataIn.readByteArray(Math.min(this.dataInLength, CONFIG.maxDataLength));
                                console.log("    Input: " + hexdump(inputData, { length: Math.min(this.dataInLength, 64), ansi: true }));
                            }

                            if (this.dataOut && !this.dataOut.isNull() && this.dataOutMoved && !this.dataOutMoved.isNull()) {
                                var outputLength = this.dataOutMoved.readU32();
                                if (outputLength > 0) {
                                    var outputData = this.dataOut.readByteArray(Math.min(outputLength, CONFIG.maxDataLength));
                                    console.log("    Output: " + hexdump(outputData, { length: Math.min(outputLength, 64), ansi: true }));
                                }
                            }
                        } catch (ex) {
                            console.log("\x1b[31m[!]\x1b[0m CCCrypt onLeave error: " + ex.message);
                        }
                    }
                });

                console.log("\x1b[32m[+]\x1b[0m CCCrypt hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CCCrypt hook failed: " + e.message);
            }

            try {
                var _ccDigestAddr = Module.findGlobalExportByName('CCDigest');
                if (!_ccDigestAddr) {
                    console.log("\x1b[31m[-]\x1b[0m CCDigest symbol not found in CommonCrypto");
                } else {
                var CCDigest = new NativeFunction(
                    _ccDigestAddr,
                    'pointer',
                    ['uint32', 'pointer', 'uint32']
                );

                Interceptor.attach(CCDigest, {
                    onEnter: function(args) {
                        this.algorithm = args[0].toInt32();
                        this.data = args[1];
                        this.dataLength = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        try {
                            var algStr = "";
                            if (this.algorithm === 1) algStr = "MD5";
                            else if (this.algorithm === 2) algStr = "SHA1";
                            else if (this.algorithm === 3) algStr = "SHA224";
                            else if (this.algorithm === 4) algStr = "SHA256";
                            else if (this.algorithm === 5) algStr = "SHA384";
                            else if (this.algorithm === 6) algStr = "SHA512";
                            else algStr = "UNKNOWN(" + this.algorithm + ")";

                            console.log("\x1b[32m[+]\x1b[0m CCDigest:");
                            console.log("    Algorithm: " + algStr);

                            if (this.data && !this.data.isNull() && this.dataLength > 0) {
                                var inputData = this.data.readByteArray(Math.min(this.dataLength, CONFIG.maxDataLength));
                                console.log("    Input: " + hexdump(inputData, { length: Math.min(this.dataLength, 64), ansi: true }));
                            }

                            // CCDigest(algorithm, data, len) returns a pointer to
                            // the digest; it does not take an output buffer.
                            if (retval && !retval.isNull()) {
                                var digestLength = (this.algorithm === 1) ? 16 : (this.algorithm === 2) ? 20 : (this.algorithm === 3) ? 28 : (this.algorithm === 4) ? 32 : (this.algorithm === 5) ? 48 : 64;
                                var outputData = retval.readByteArray(digestLength);
                                console.log("    Output: " + hexdump(outputData, { ansi: true }));
                            }
                        } catch (ex) {
                            console.log("\x1b[31m[!]\x1b[0m CCDigest onLeave error: " + ex.message);
                        }
                    }
                });

                console.log("\x1b[32m[+]\x1b[0m CCDigest hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CCDigest hook failed: " + e.message);
            }

            try {
                var _ccHmacAddr = Module.findGlobalExportByName('CCHmac');
                if (!_ccHmacAddr) {
                    console.log("\x1b[31m[-]\x1b[0m CCHmac symbol not found in CommonCrypto");
                } else {
                var CCHmac = new NativeFunction(
                    _ccHmacAddr,
                    'void',
                    ['uint32', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer']
                );

                Interceptor.attach(CCHmac, {
                    onEnter: function(args) {
                        this.algorithm = args[0].toInt32();
                        this.key = args[1];
                        this.keyLength = args[2].toInt32();
                        this.data = args[3];
                        this.dataLength = args[4].toInt32();
                        this.macOut = args[5];
                    },
                    onLeave: function(retval) {
                        try {
                            var algStr = "";
                            if (this.algorithm === 1) algStr = "MD5";
                            else if (this.algorithm === 2) algStr = "SHA1";
                            else if (this.algorithm === 3) algStr = "SHA224";
                            else if (this.algorithm === 4) algStr = "SHA256";
                            else if (this.algorithm === 5) algStr = "SHA384";
                            else if (this.algorithm === 6) algStr = "SHA512";
                            else algStr = "UNKNOWN(" + this.algorithm + ")";

                            console.log("\x1b[32m[+]\x1b[0m CCHmac:");
                            console.log("    Algorithm: " + algStr);
                            console.log("    Key: " + (CONFIG.logFullKey ? bytesToHex(this.key, this.keyLength) : bytesToHex(this.key, 8) + "..."));

                            if (this.data && !this.data.isNull() && this.dataLength > 0) {
                                var inputData = this.data.readByteArray(Math.min(this.dataLength, CONFIG.maxDataLength));
                                console.log("    Input: " + hexdump(inputData, { length: Math.min(this.dataLength, 64), ansi: true }));
                            }

                            if (this.macOut && !this.macOut.isNull()) {
                                var macLength = (this.algorithm === 1) ? 16 : (this.algorithm === 2) ? 20 : (this.algorithm === 3) ? 28 : (this.algorithm === 4) ? 32 : 48;
                                var macData = this.macOut.readByteArray(macLength);
                                console.log("    HMAC: " + hexdump(macData, { ansi: true }));
                            }
                        } catch (ex) {
                            console.log("\x1b[31m[!]\x1b[0m CCHmac onLeave error: " + ex.message);
                        }
                    }
                });

                console.log("\x1b[32m[+]\x1b[0m CCHmac hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CCHmac hook failed: " + e.message);
            }

            try {
                var _secDecryptAddr = findExport('Security', 'SecKeyCreateDecryptedData');
                if (!_secDecryptAddr) {
                    console.log("\x1b[31m[-]\x1b[0m SecKeyCreateDecryptedData symbol not found in Security");
                } else {
                var SecKeyCreateDecryptedData = new NativeFunction(
                    _secDecryptAddr,
                    'pointer',
                    ['pointer', 'pointer', 'pointer', 'pointer']
                );

                Interceptor.attach(SecKeyCreateDecryptedData, {
                    onEnter: function(args) {
                        this.key = args[0];
                        this.algorithm = args[1];
                        this.ciphertext = args[2];
                        this.error = args[3];
                    },
                    onLeave: function(retval) {
                        try {
                            console.log("\x1b[32m[+]\x1b[0m SecKeyCreateDecryptedData:");

                            if (this.ciphertext && !this.ciphertext.isNull()) {
                                var ciphertextData = ObjC.Object(this.ciphertext);
                                console.log("    Ciphertext: " + nsDataToHex(ciphertextData, 64));
                            }

                            if (retval && !retval.isNull()) {
                                var plaintextData = ObjC.Object(retval);
                                console.log("    Plaintext: " + nsDataToHex(plaintextData, 64));
                            }
                        } catch (ex) {
                            console.log("\x1b[31m[!]\x1b[0m SecKeyCreateDecryptedData onLeave error: " + ex.message);
                        }
                    }
                });

                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateDecryptedData hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecKeyCreateDecryptedData hook failed: " + e.message);
            }

            try {
                var _secEncryptAddr = findExport('Security', 'SecKeyCreateEncryptedData');
                if (!_secEncryptAddr) {
                    console.log("\x1b[31m[-]\x1b[0m SecKeyCreateEncryptedData symbol not found in Security");
                } else {
                var SecKeyCreateEncryptedData = new NativeFunction(
                    _secEncryptAddr,
                    'pointer',
                    ['pointer', 'pointer', 'pointer', 'pointer']
                );

                Interceptor.attach(SecKeyCreateEncryptedData, {
                    onEnter: function(args) {
                        this.key = args[0];
                        this.algorithm = args[1];
                        this.plaintext = args[2];
                        this.error = args[3];
                    },
                    onLeave: function(retval) {
                        try {
                            console.log("\x1b[32m[+]\x1b[0m SecKeyCreateEncryptedData:");

                            if (this.plaintext && !this.plaintext.isNull()) {
                                var plaintextData = ObjC.Object(this.plaintext);
                                console.log("    Plaintext: " + nsDataToHex(plaintextData, 64));
                            }

                            if (retval && !retval.isNull()) {
                                var ciphertextData = ObjC.Object(retval);
                                console.log("    Ciphertext: " + nsDataToHex(ciphertextData, 64));
                            }
                        } catch (ex) {
                            console.log("\x1b[31m[!]\x1b[0m SecKeyCreateEncryptedData onLeave error: " + ex.message);
                        }
                    }
                });

                console.log("\x1b[32m[+]\x1b[0m SecKeyCreateEncryptedData hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecKeyCreateEncryptedData hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Crypto Hook iOS error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Crypto Hook iOS Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
