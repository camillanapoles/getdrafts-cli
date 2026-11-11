/**
 * Passkeys (WebAuthn/FIDO2) Hook for iOS
 *
 * Monitors Passkeys/WebAuthn operations introduced in iOS 16+:
 * - ASAuthorizationPlatformPublicKeyCredentialProvider operations
 * - Passkey registration (creation)
 * - Passkey authentication (assertion)
 * - Secure Enclave key storage
 * - Biometric enforcement
 *
 * Compatible with: Frida 16.x+ and iOS 16+
 * Usage: frida -U -f <bundle_id> -l passkeys-hook-ios.js
 * OWASP MASTG: MASTG-TEST-0046, MSTG-AUTH-1
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Passkeys Hook iOS Script Started (WebAuthn/FIDO2)");

    var CONFIG = {
        logChallenges: true,
        logUserHandles: true,
        detectWeakConfig: true,
        DEBUG_MODE: false
    };

    var registrationCount = 0;
    var authenticationCount = 0;
    var weakConfigCount = 0;

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function bytesToHex(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || 64;
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

            function bytesToString(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || 128;
                try {
                    var totalLen = typeof bytes.byteLength === "number" ? bytes.byteLength : maxLength;
                    var bytesToRead = Math.min(totalLen, maxLength);

                    var result = "";
                    for (var i = 0; i < bytesToRead; i++) {
                        var b;
                        if (bytes instanceof ArrayBuffer) {
                            b = new Uint8Array(bytes)[i];
                        } else if (bytes && typeof bytes.readU8 === "function") {
                            b = bytes.add(i).readU8();
                        } else {
                            break;
                        }
                        if (b >= 32 && b <= 126) {
                            result += String.fromCharCode(b);
                        } else {
                            result += ".";
                        }
                    }
                    return result;
                } catch (e) {
                    return "<cannot read>";
                }
            }

            // Check for AuthenticationServices framework
            try {
                var AuthServices = ObjC.classes.ASAuthorizationPlatformPublicKeyCredentialProvider;
                if (AuthServices) {
                    console.log("\x1b[32m[+]\x1b[0m ASAuthorizationPlatformPublicKeyCredentialProvider found (Passkeys enabled)");

                    // Hook provider initialization
                    var initWithRelyingParty = AuthServices["- initWithRelyingPartyIdentifier:"];
                    if (initWithRelyingParty) {
                        Interceptor.attach(initWithRelyingParty.implementation, {
                            onEnter: function(args) {
                                this.rpID = ObjC.Object(args[2]);
                            },
                            onLeave: function(retval) {
                                try {
                                    var rpIDStr = this.rpID.toString();
                                    console.log("\x1b[36m[i]\x1b[0m Passkey Provider initialized:");
                                    console.log("    RP ID: " + rpIDStr);

                                    // Check for weak RP ID
                                    if (CONFIG.detectWeakConfig) {
                                        if (rpIDStr.startsWith(".") || rpIDStr.length < 8) {
                                            console.log("\x1b[31m[!]\x1b[0m WARNING: Weak RP ID detected - " + rpIDStr);
                                            weakConfigCount++;
                                        }
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m initWithRelyingParty error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m ASAuthorizationPlatformPublicKeyCredentialProvider.initWithRelyingParty: hooked");
                    }

                    // Hook registration request creation
                    var createRegistrationRequest = AuthServices["- createRegistrationRequest:challenge:userHandle:userName:displayName:"];
                    if (createRegistrationRequest) {
                        Interceptor.attach(createRegistrationRequest.implementation, {
                            onEnter: function(args) {
                                this.challenge = args[2];
                                this.userHandle = args[3];
                                this.userName = ObjC.Object(args[4]);
                                this.displayName = ObjC.Object(args[5]);
                            },
                            onLeave: function(retval) {
                                registrationCount++;
                                try {
                                    console.log("\x1b[32m[+]\x1b[0m Passkey Registration Request:");

                                    if (CONFIG.logChallenges && this.challenge && !this.challenge.isNull()) {
                                        var challengeData = ObjC.Object(this.challenge);
                                        console.log("    Challenge: " + bytesToHex(challengeData.bytes(), 32));
                                        console.log("    Length: " + challengeData.length());
                                    }

                                    if (CONFIG.logUserHandles && this.userName) {
                                        console.log("    Username: " + this.userName.toString());
                                        console.log("    Display Name: " + this.displayName.toString());
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m createRegistrationRequest error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m createRegistrationRequest hooked");
                    }

                    // Hook assertion request creation (authentication)
                    var createAssertionRequest = AuthServices["- createAssertionRequest:challenge:"];
                    if (createAssertionRequest) {
                        Interceptor.attach(createAssertionRequest.implementation, {
                            onEnter: function(args) {
                                this.challenge = args[2];
                            },
                            onLeave: function(retval) {
                                authenticationCount++;
                                try {
                                    console.log("\x1b[32m[+]\x1b[0m Passkey Authentication Request:");

                                    if (CONFIG.logChallenges && this.challenge && !this.challenge.isNull()) {
                                        var challengeData = ObjC.Object(this.challenge);
                                        console.log("    Challenge: " + bytesToHex(challengeData.bytes(), 32));
                                        console.log("    Length: " + challengeData.length());
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m createAssertionRequest error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m createAssertionRequest hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m ASAuthorizationPlatformPublicKeyCredentialProvider not found (Passkeys not in use)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Passkey provider hook failed: " + e.message);
            }

            // Hook ASAuthorizationController for monitoring authorization flow
            try {
                var ASAuthController = ObjC.classes.ASAuthorizationController;
                if (ASAuthController) {
                    var authorize = ASAuthController["- authorizeWithCompletionHandler:"];
                    if (authorize) {
                        Interceptor.attach(authorize.implementation, {
                            onEnter: function(args) {
                                this.handler = args[2];
                                console.log("\x1b[36m[i]\x1b[0m ASAuthorizationController.authorize called");
                            },
                            onLeave: function(retval) {
                                try {
                                    if (this.handler && !this.handler.isNull()) {
                                        console.log("\x1b[36m[i]\x1b[0m Completion handler set");
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m authorize error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m ASAuthorizationController.authorize hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m ASAuthorizationController not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m ASAuthorizationController hook failed: " + e.message);
            }

            // Hook Keychain operations for passkey storage monitoring
            try {
                // Frida 17: la busqueda por modulo se hace sobre el objeto Module.
                var securityModule = Process.findModuleByName('Security');
                var SecItemAdd = securityModule ? securityModule.findExportByName('SecItemAdd') : null;
                if (SecItemAdd) {
                    Interceptor.attach(SecItemAdd, {
                        onEnter: function(args) {
                            try {
                                var query = ObjC.Object(args[0]);
                                var className = query.$className;

                                if (className.indexOf("Dictionary") !== -1 || className.indexOf("NSDictionary") !== -1) {
                                    var keys = query.allKeys();
                                    var hasPasskey = false;

                                    for (var i = 0; i < keys.count(); i++) {
                                        var key = keys.objectAtIndex_(i).toString();
                                        if (key.indexOf("Credential") !== -1 || key.indexOf("Passkey") !== -1 || key.indexOf("WebAuthn") !== -1) {
                                            hasPasskey = true;
                                            break;
                                        }
                                    }

                                    if (hasPasskey) {
                                        console.log("\x1b[36m[i]\x1b[0m Passkey credential storage detected in Keychain");
                                    }
                                }
                            } catch (ex) {
                                // Ignore Keychain query errors
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m SecItemAdd hooked (monitoring passkey storage)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Keychain hook failed: " + e.message);
            }

            // Check for Secure Enclave key storage
            try {
                var SecKeyCreateRandomKey = securityModule ? securityModule.findExportByName('SecKeyCreateRandomKey') : null;
                if (SecKeyCreateRandomKey) {
                    Interceptor.attach(SecKeyCreateRandomKey, {
                        onEnter: function(args) {
                            try {
                                var attributes = ObjC.Object(args[0]);
                                var tokenAttr = attributes.objectForKey_("kSecAttrTokenID");

                                if (tokenAttr && !tokenAttr.isNull()) {
                                    var tokenStr = tokenAttr.toString();
                                    if (tokenStr.indexOf("SecureEnclave") !== -1) {
                                        console.log("\x1b[36m[i]\x1b[0m Secure Enclave key creation (possible passkey)");
                                    }
                                }
                            } catch (ex) {
                                // Ignore attribute reading errors
                            }
                        },
                        onLeave: function(retval) {
                            if (retval && !retval.isNull()) {
                                console.log("\x1b[32m[+]\x1b[0m Secure Enclave key created successfully");
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m SecKeyCreateRandomKey hooked (monitoring Secure Enclave)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Secure Enclave hook failed: " + e.message);
            }

            // Scan for WebAuthn/FIDO2 symbols
            try {
                console.log("\x1b[36m[*]\x1b[0m Scanning for WebAuthn/FIDO2 symbols...");

                var webAuthnSymbols = [];

                Process.enumerateModules().forEach(function(module) {
                    if (module.name.indexOf("AuthenticationServices") !== -1) {
                        try {
                            module.enumerateSymbols().forEach(function(symbol) {
                                var name = symbol.name;
                                if (name.indexOf("PlatformPublicKeyCredential") !== -1 ||
                                    name.indexOf("WebAuthn") !== -1 ||
                                    name.indexOf("FIDO") !== -1) {
                                    webAuthnSymbols.push(module.name + "::" + name);
                                }
                            });
                        } catch (e) {
                            // Symbol enumeration may fail
                        }
                    }
                });

                if (webAuthnSymbols.length > 0) {
                    console.log("\x1b[32m[+]\x1b[0m WebAuthn symbols detected:");
                    webAuthnSymbols.slice(0, 10).forEach(function(sym) {
                        console.log("    " + sym);
                    });
                    if (webAuthnSymbols.length > 10) {
                        console.log("    ... and " + (webAuthnSymbols.length - 10) + " more");
                    }
                } else {
                    console.log("\x1b[33m[*]\x1b[0m No WebAuthn symbols found in AuthenticationServices");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Symbol scan failed: " + e.message);
            }

            console.log("\x1b[33m[*]\x1b[0m Passkeys Hook iOS Script Loaded");
            console.log("\x1b[36m[*]\x1b[0m Monitoring for Passkeys/WebAuthn operations...");

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Passkeys Hook iOS error: " + e.message);
        }
    });

    setInterval(function() {
        if (registrationCount > 0 || authenticationCount > 0 || weakConfigCount > 0) {
            console.log("\x1b[36m[*]\x1b[0m Stats - Registrations: " + registrationCount + " | Authentications: " + authenticationCount + " | Weak config: " + weakConfigCount);
        }
    }, 30000);

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
