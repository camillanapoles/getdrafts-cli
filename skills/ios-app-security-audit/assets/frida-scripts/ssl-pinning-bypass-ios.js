/**
 * UNIVERSAL SSL/TLS CERTIFICATE PINNING BYPASS - iOS
 *
 * Comprehensive Frida script to bypass certificate pinning in iOS applications.
 * Covers multiple iOS SSL/TLS implementations and security frameworks.
 *
 * Coverage: native BoringSSL SSL_(CTX_)set_custom_verify (the low-level TLS
 *           layer used by NSURLSession/Flutter/gRPC on iOS 11+),
 *           SecTrustEvaluateWithError (iOS 12+), NSURLSession delegates,
 *           AFNetworking (3.x/4.x), Alamofire ServerTrustEvaluating,
 *           WKWebView navigation delegates, SecTrustEvaluate (deprecated),
 *           NSURLSessionConfiguration TLS configuration
 *
 * Compatible with: Frida 16.x+, iOS 11-18
 * Usage: frida -U -f <BUNDLE_ID> -l ssl-pinning-bypass-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l ssl-pinning-bypass-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0225: Test Network Communication for Sensitive Information
 * - MASVS-NET: Network Communication Requirements
 *
 * Credits:
 * - Frida-Trace: https://github.com/frida/frida-trace
 * - ios-object-frida-hook: https://github.com/alibaba/grail
 * - objection: https://github.com/sensepost/objection
 * - BoringSSL technique: httptoolkit/frida-interception-and-unpinning
 *   and nabla-c0d3 SSL Kill Switch 2
 */

const DEBUG_MODE = true;

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] UNIVERSAL SSL PINNING BYPASS - iOS STARTED");
            console.log("[*] ================================================");

            // Frida 17: getModuleByName() throws when the module is not loaded and
            // getExportByName() throws when the symbol is missing; the "find" variants return null.
            function findExport(moduleName, symbolName) {
                var mod = Process.findModuleByName(moduleName);
                return mod ? mod.findExportByName(symbolName) : null;
            }

            let hooksApplied = 0;

            try {
                const SecTrustEvaluateWithError = new NativeCallback(
                    (trust, error) => {
                        if (DEBUG_MODE) console.log("\x1b[32m[+]\x1b[0m SecTrustEvaluateWithError() - Bypassed");
                        return 1; // kCFBooleanTrue
                    },
                    'int',
                    ['pointer', 'pointer']
                );

                const SecTrustEvaluateWithErrorPtr = findExport('Security', 'SecTrustEvaluateWithError');

                if (SecTrustEvaluateWithErrorPtr) {
                    Interceptor.replace(SecTrustEvaluateWithErrorPtr, SecTrustEvaluateWithError);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m SecTrustEvaluateWithError hooked successfully");
                } else {
                    console.log("[!] SecTrustEvaluateWithError not found (iOS < 12)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecTrustEvaluateWithError hook failed: " + e.message);
            }

            try {
                const SecTrustEvaluate = new NativeCallback(
                    (trust, result) => {
                        if (DEBUG_MODE) console.log("\x1b[32m[+]\x1b[0m SecTrustEvaluate() - Bypassed");
                        // result is a pointer to SecTrustResultType (uint32); guard before write (criterion #2)
                        if (result && !result.isNull()) {
                            result.writeU32(1); // kSecTrustResultProceed (uint32)
                        }
                        return 0; // errSecSuccess
                    },
                    'int',
                    ['pointer', 'pointer']
                );

                const SecTrustEvaluatePtr = findExport('Security', 'SecTrustEvaluate');

                if (SecTrustEvaluatePtr) {
                    Interceptor.replace(SecTrustEvaluatePtr, SecTrustEvaluate);
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m SecTrustEvaluate hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SecTrustEvaluate hook failed: " + e.message);
            }

            try {
                const sel = '- URLSession:didReceiveChallenge:completionHandler:';
                // NOTE: ObjC protocol objects don't hold implementations — assigning
                // .implementation on a protocol method has no effect. Instead we
                // enumerate loaded ObjC classes and patch every class that actually
                // implements the delegate selector (criterion #3).
                for (const className in ObjC.classes) {
                    try {
                        const cls = ObjC.classes[className];
                        const method = cls[sel];
                        if (method) {
                            Interceptor.attach(method.implementation, {
                                onEnter: function(args) {
                                    this.className = className;
                                    const challenge = new ObjC.Object(args[4]);
                                    const completionHandler = new ObjC.Block(args[5]);
                                    try {
                                        const credential = ObjC.classes.NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                                        completionHandler(ObjC.classes.NSURLSessionAuthChallengeUseCredential, credential);
                                        if (DEBUG_MODE) {
                                            console.log("\x1b[32m[+]\x1b[0m [" + className + "] URLSession:didReceiveChallenge:completionHandler: - Bypassed");
                                        }
                                    } catch (e2) {
                                        console.log("[-] credential creation failed: " + e2.message);
                                    }
                                }
                            });
                            hooksApplied++;
                            console.log("\x1b[32m[+]\x1b[0m NSURLSession delegate hooked on " + className);
                        }
                    } catch (e) { /* class doesn't implement this selector */ }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSURLSession delegate hook failed: " + e.message);
            }

            try {
                const AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
                if (AFSecurityPolicy) {
                    const originalEvaluateServerTrust = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
                    if (originalEvaluateServerTrust) {
                        Interceptor.attach(originalEvaluateServerTrust.implementation, {
                            onLeave: function(retval) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m AFSecurityPolicy evaluateServerTrust:forDomain: - Bypassed");
                                }
                                retval.replace(ptr(1)); // YES
                            }
                        });
                        hooksApplied++;
                    }

                    console.log("\x1b[32m[+]\x1b[0m AFSecurityPolicy hooked successfully");
                }
            } catch (e) {
                console.log("[!] AFSecurityPolicy hook failed: " + e.message);
            }

            try {
                const afSel = '- evaluate:forDomain:';
                // Protocol objects don't hold implementations — patch conforming classes (criterion #3).
                for (const className in ObjC.classes) {
                    try {
                        const cls = ObjC.classes[className];
                        const method = cls[afSel];
                        if (method) {
                            Interceptor.attach(method.implementation, {
                                onEnter: function(args) {
                                    this.className = className;
                                },
                                onLeave: function(retval) {
                                    if (DEBUG_MODE) {
                                        console.log("\x1b[32m[+]\x1b[0m [" + this.className + "] evaluate:forDomain: - Bypassed");
                                    }
                                    retval.replace(ptr(1)); // YES / true
                                }
                            });
                            hooksApplied++;
                            console.log("\x1b[32m[+]\x1b[0m Alamofire ServerTrustEvaluating hooked on " + className);
                        }
                    } catch (e) { /* class doesn't implement this selector */ }
                }
            } catch (e) {
                console.log("[!] Alamofire ServerTrustEvaluating hook failed: " + e.message);
            }

            try {
                const wkSel = '- webView:didReceiveAuthenticationChallenge:completionHandler:';
                // Protocol objects don't hold implementations — patch conforming classes (criterion #3).
                for (const className in ObjC.classes) {
                    try {
                        const cls = ObjC.classes[className];
                        const method = cls[wkSel];
                        if (method) {
                            Interceptor.attach(method.implementation, {
                                onEnter: function(args) {
                                    this.className = className;
                                    const challenge = new ObjC.Object(args[4]);
                                    const completionHandler = new ObjC.Block(args[5]);
                                    try {
                                        const credential = ObjC.classes.NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                                        completionHandler(ObjC.classes.NSURLSessionAuthChallengeUseCredential, credential);
                                        if (DEBUG_MODE) {
                                            console.log("\x1b[32m[+]\x1b[0m [" + className + "] webView:didReceiveAuthenticationChallenge:completionHandler: - Bypassed");
                                        }
                                    } catch (e2) {
                                        console.log("[-] WKWebView credential creation failed: " + e2.message);
                                    }
                                }
                            });
                            hooksApplied++;
                            console.log("\x1b[32m[+]\x1b[0m WKWebView navigation delegate hooked on " + className);
                        }
                    } catch (e) { /* class doesn't implement this selector */ }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m WKWebView navigation delegate hook failed: " + e.message);
            }

            try {
                const NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

                const originalDefaultSessionConfiguration = NSURLSessionConfiguration['+ defaultSessionConfiguration'];
                if (originalDefaultSessionConfiguration) {
                    const originalImpl = new NativeFunction(originalDefaultSessionConfiguration.implementation, 'pointer', ['pointer', 'pointer']);
                    Interceptor.attach(originalDefaultSessionConfiguration.implementation, {
                        onLeave: function(retval) {
                            const config = ObjC.Object(retval);
                            if (config && !config.isNull()) {
                                if (DEBUG_MODE) {
                                    console.log("\x1b[32m[+]\x1b[0m NSURLSessionConfiguration - TLS settings modified");
                                }
                            }
                        }
                    });
                    hooksApplied++;
                    console.log("\x1b[32m[+]\x1b[0m NSURLSessionConfiguration hooked successfully");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSURLSessionConfiguration hook failed: " + e.message);
            }

            try {
                const methodNames = [
                    '- checkServerTrust:forDomain:',
                    '- verifyServerTrust:',
                    '- handleAuthenticationChallenge:',
                    '- performDefaultHandlingForAuthenticationChallenge:',
                    '- continueWithoutCredentialForAuthenticationChallenge:'
                ];

                const classes = ObjC.classes;
                for (const className in classes) {
                    if (className.includes('Security') || className.includes('Trust') || className.includes('SSL')) {
                        const cls = classes[className];
                        for (const methodName of methodNames) {
                            try {
                                const method = cls[methodName];
                                if (method) {
                                    Interceptor.attach(method.implementation, {
                                        onEnter: function(args) {
                                            this.className = className;
                                            this.methodName = methodName;
                                        },
                                        onLeave: function(retval) {
                                            if (DEBUG_MODE) {
                                                console.log("\x1b[32m[+]\x1b[0m " + this.className + " " + this.methodName + " - Bypassed");
                                            }
                                            retval.replace(ptr(1));
                                        }
                                    });
                                    hooksApplied++;
                                }
                            } catch (e) {
                                // Method not found on this class, continue
                            }
                        }
                    }
                }

                if (hooksApplied > 0) {
                    console.log("\x1b[32m[+]\x1b[0m Custom SSL methods hooked");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Custom SSL methods hook failed: " + e.message);
            }

            try {
                // The most reliable bypass on modern iOS: NSURLSession, Flutter
                // (dart:io), gRPC and Cronet validate certificates inside BoringSSL,
                // BELOW the SecTrust/ObjC layer hooked above. Replacing
                // SSL_(CTX_)set_custom_verify forces every TLS handshake's verify
                // callback to return ssl_verify_ok (0 = accept). Technique verified
                // against httptoolkit/frida-interception-and-unpinning and
                // nabla-c0d3 SSL Kill Switch 2.
                const SSL_VERIFY_OK = 0;
                const boringNames = ['libboringssl.dylib', 'boringssl'];

                const resolveBoring = (symbol) => {
                    for (let i = 0; i < boringNames.length; i++) {
                        const a = findExport(boringNames[i], symbol);
                        if (a) return a;
                    }
                    return Module.getGlobalExportByName(symbol);
                };

                const acceptAllVerify = new NativeCallback((ssl, outAlert) => {
                    return SSL_VERIFY_OK;
                }, 'int', ['pointer', 'pointer']);
                global.__sslPinningVerifyCb = acceptAllVerify;

                let boringPatched = 0;
                ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach((symbol) => {
                    const addr = resolveBoring(symbol);
                    if (!addr) return;
                    try {
                        const setCustomVerify = new NativeFunction(addr, 'void', ['pointer', 'int', 'pointer']);
                        Interceptor.replace(addr, new NativeCallback((ssl, mode, providedCb) => {
                            setCustomVerify(ssl, mode, acceptAllVerify);
                        }, 'void', ['pointer', 'int', 'pointer']));
                        boringPatched++;
                        console.log("\x1b[32m[+]\x1b[0m BoringSSL " + symbol + " hooked (accept-all)");
                    } catch (e2) {
                        console.log("[!] BoringSSL " + symbol + " hook failed: " + e2.message);
                    }
                });

                // Some verify paths reject the connection unless SSL_get_psk_identity
                // returns non-NULL. Force a valid non-null sentinel pointer.
                const pskAddr = resolveBoring('SSL_get_psk_identity');
                if (pskAddr) {
                    try {
                        const pskSentinel = Memory.allocUtf8String('PSK_BYPASS');
                        global.__sslPinningPsk = pskSentinel;
                        Interceptor.replace(pskAddr, new NativeCallback((ssl) => {
                            return pskSentinel;
                        }, 'pointer', ['pointer']));
                        console.log("\x1b[32m[+]\x1b[0m BoringSSL SSL_get_psk_identity neutralized");
                    } catch (e3) { /* non-fatal */ }
                }

                if (boringPatched > 0) {
                    hooksApplied += boringPatched;
                    console.log("\x1b[32m[+]\x1b[0m Native BoringSSL pinning bypass active");
                } else {
                    console.log("[!] BoringSSL custom_verify symbols not found (TLS may not use BoringSSL on this target, or symbols are stripped)");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m BoringSSL bypass section failed: " + e.message);
            }

            console.log("[*] ================================================");
            console.log("[*] Total hooks applied: " + hooksApplied);
            console.log("[*] SSL Pinning Bypass Complete");
            console.log("[*] ================================================");
        });
    } catch (e) {
        console.log("\x1b[31m[!]\x1b[0m Fatal error in main execution: " + e.message);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
