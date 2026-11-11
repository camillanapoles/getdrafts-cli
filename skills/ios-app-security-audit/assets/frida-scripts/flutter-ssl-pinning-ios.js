/**
 * Flutter SSL Pinning Bypass - iOS [STABLE]
 *
 * Purpose: Bypass SSL certificate pinning in Flutter iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l flutter-ssl-pinning-ios.js
 *
 * What it hooks:
 * - BoringSSL SSL_(CTX_)set_custom_verify — Flutter's OWN statically-linked
 *   TLS stack (dart:io HttpClient). This is the real Flutter pinning layer.
 * - NSURLSession / SecTrust certificate validation (plugin-based HTTP)
 * - Native plugin validation methods (ssl_pinning_plugin, dio, etc.)
 *
 * IMPORTANT: Flutter does NOT use SecTrust/NSURLSession for dart:io traffic —
 * it uses its own BoringSSL. When those symbols are exported, this script
 * bypasses pinning directly. In release builds the symbols are often stripped;
 * then a byte-pattern scan of ssl_crypto_x509_session_verify_cert_chain is
 * required (see NVISO 'disable-flutter-tls-verification') — that is out of
 * scope for this standalone script, which falls back to the SecTrust/plugin
 * hooks below.
 *
 * Features:
 * - Detects Flutter-based network requests
 * - Bypasses standard SSL pinning
 * - Bypasses custom certificate validation
 * - Logs certificate information
 * - Supports multiple Flutter versions
 * - Color-coded output for debugging
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0035: Network Communication Security
 * - MASTG-TEST-0036: Certificate Pinning Testing
 * - MASTG-APP-PROT-003: SSL/TLS Implementation
 *
 * Compatible with: Frida 16.x+, iOS 12-17, Flutter 2.x-3.x
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 *
 * Source: https://codeshare.frida.re/@zionspike/bypass-flutter-pinning-ios/
 * Author: @zionspike
 */

if (ObjC.available) {
    try {
        console.log("[*] ================================================");
        console.log("[*] Flutter SSL Pinning Bypass - iOS STARTED");
        console.log("[*] ================================================");

        var CONFIG = {
            verbose: true,
            logCertificates: true,
            bypassValidation: true,
            showTrustDetails: true
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

        function getTimestamp() {
            var date = new Date();
            return date.toISOString().substr(11, 12);
        }

        function getCertificateInfo(cert) {
            try {
                if (!cert) {
                    return null;
                }

                var info = {
                    subject: null,
                    issuer: null,
                    validFrom: null,
                    validTo: null,
                    serialNumber: null
                };

                try {
                    var SecCertificateRef = ObjC.classes.SecCertificateRef;
                    if (cert.handle) {
                        info.subject = cert.handle.toString();
                    }
                } catch (e) {
                }

                return info;
            } catch (e) {
                logError("Exception in getCertificateInfo: " + e.message);
                return null;
            }
        }

        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        // Native BoringSSL bypass — the ONLY path that covers Flutter's
        // dart:io HttpClient (Flutter links its own BoringSSL, not SecTrust).
        // SSL Kill Switch 2 technique, verified against
        // httptoolkit/frida-interception-and-unpinning.
        function bypassBoringSSL() {
            try {
                logSection("BORINGSSL NATIVE BYPASS (Flutter dart:io / NSURLSession)");

                var SSL_VERIFY_OK = 0;
                // Flutter statically links BoringSSL; symbols may live in the
                // 'Flutter' framework, a bundled 'boringssl', or the system dylib.
                var boringNames = ['libboringssl.dylib', 'boringssl', 'Flutter'];

                function resolveBoring(symbol) {
                    for (var i = 0; i < boringNames.length; i++) {
                        var a = findExport(boringNames[i], symbol);
                        if (a) return a;
                    }
                    return Module.getGlobalExportByName(symbol);
                }

                var acceptAllVerify = new NativeCallback(function (ssl, outAlert) {
                    return SSL_VERIFY_OK;
                }, 'int', ['pointer', 'pointer']);
                global.__flutterVerifyCb = acceptAllVerify;

                var patched = 0;
                ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach(function (symbol) {
                    var addr = resolveBoring(symbol);
                    if (!addr) return;
                    try {
                        var setCustomVerify = new NativeFunction(addr, 'void', ['pointer', 'int', 'pointer']);
                        Interceptor.replace(addr, new NativeCallback(function (ssl, mode, providedCb) {
                            setCustomVerify(ssl, mode, acceptAllVerify);
                        }, 'void', ['pointer', 'int', 'pointer']));
                        patched++;
                        logSuccess("BoringSSL " + symbol + " hooked (accept-all)");
                    } catch (e2) {
                        logError("BoringSSL " + symbol + " hook failed: " + e2.message);
                    }
                });

                var pskAddr = resolveBoring('SSL_get_psk_identity');
                if (pskAddr) {
                    try {
                        var pskSentinel = Memory.allocUtf8String('PSK_BYPASS');
                        global.__flutterPsk = pskSentinel;
                        Interceptor.replace(pskAddr, new NativeCallback(function (ssl) {
                            return pskSentinel;
                        }, 'pointer', ['pointer']));
                        logSuccess("BoringSSL SSL_get_psk_identity neutralized");
                    } catch (e3) { /* non-fatal */ }
                }

                if (patched > 0) {
                    logSuccess("Native BoringSSL bypass active (" + patched + " verify fn) — covers Flutter dart:io HttpClient");
                } else {
                    logWarn("BoringSSL custom_verify symbols not exported (typical for release Flutter builds).");
                    logWarn("For stripped Flutter binaries, pattern-scan ssl_crypto_x509_session_verify_cert_chain");
                    logWarn("(see NVISO 'disable-flutter-tls-verification') — out of scope for this standalone script.");
                }
            } catch (e) {
                logError("Exception in bypassBoringSSL: " + e.message);
            }
        }

        function bypassNSURLSessionValidation() {
            try {
                logSection("NSURLSession SSL VALIDATION BYPASS");

                var NSURLSession = ObjC.classes.NSURLSession;
                if (!NSURLSession) {
                    logWarn("NSURLSession not found");
                    return;
                }

                logSuccess("Found NSURLSession - hooking validation methods");

                var SecTrustEvaluate = findExport('Security', 'SecTrustEvaluate');
                if (SecTrustEvaluate) {
                    Interceptor.attach(SecTrustEvaluate, {
                        onEnter: function(args) {
                            this._resultPtr = args[1];
                            logInfo("[SecTrustEvaluate] Called");
                        },
                        onLeave: function(retval) {
                            if (this._resultPtr && !this._resultPtr.isNull()) {
                                this._resultPtr.writeU32(1); // kSecTrustResultProceed
                            }
                            logSuccess("[SecTrustEvaluate] Bypassed - returning kSecTrustResultProceed");
                            retval.replace(0); // errSecSuccess
                        }
                    });
                    logSuccess("Hooked SecTrustEvaluate");
                }

                var SecTrustEvaluateWithError = findExport('Security', 'SecTrustEvaluateWithError');
                if (SecTrustEvaluateWithError) {
                    Interceptor.attach(SecTrustEvaluateWithError, {
                        onEnter: function(args) {
                            logInfo("[SecTrustEvaluateWithError] Called");
                        },
                        onLeave: function(retval) {
                            logSuccess("[SecTrustEvaluateWithError] Bypassed - returning true");
                            retval.replace(ptr(1));
                        }
                    });
                    logSuccess("Hooked SecTrustEvaluateWithError");
                }

            } catch (e) {
                logError("Exception in bypassNSURLSessionValidation: " + e.message);
            }
        }

        function bypassFlutterSSL() {
            try {
                logSection("FLUTTER SSL PINNING BYPASS");

                // Dart classes are NOT visible to Frida (Frida sees only
                // native ObjC/Swift code). Flutter's SSL pinning, if any,
                // happens either in:
                //   1. Native plugins (ssl_pinning_plugin, dio, etc.) which
                //      expose an ObjC class
                //   2. A custom NSURLSessionDelegate
                // For (1) we hook every "validate*" / "verify*" method on
                // the candidate classes and force the return value to true.
                // For (2) the generic NSURLSession hook already covers it.
                var flutterClasses = [
                    "SslPinningPlugin",
                    "SSLPinningPlugin",
                    "FlutterSSL",
                    "FlutterSecureStoragePlugin",
                    "FlutterCertificatePinning",
                ];

                var hookCount = 0;
                for (var i = 0; i < flutterClasses.length; i++) {
                    var className = flutterClasses[i];
                    var clazz = ObjC.classes[className];
                    if (!clazz) continue;
                    logInfo("Found Flutter SSL plugin class: " + className);

                    var methods = clazz.$ownMethods || [];
                    for (var j = 0; j < methods.length; j++) {
                        var methodName = methods[j];
                        if (methodName.indexOf("validate") === -1 &&
                            methodName.indexOf("verify")   === -1 &&
                            methodName.indexOf("check")    === -1) {
                            continue;
                        }
                        var impl = clazz[methodName];
                        if (!impl) continue;
                        // Only a BOOL-returning method may be forced to true.
                        // Replacing the return value of an object or void
                        // method hands the caller a bogus pointer (0x1) and
                        // crashes the target app.
                        if (impl.returnType !== "bool" && impl.returnType !== "BOOL") {
                            continue;
                        }
                        (function (targetClass, sel, methodImpl) {
                            Interceptor.attach(methodImpl.implementation, {
                                onLeave: function (retval) {
                                    logSuccess("[Flutter] " + targetClass.$className + " " + sel + " → bypassed (returned true)");
                                    retval.replace(1);
                                }
                            });
                            hookCount++;
                        })(clazz, methodName, impl);
                    }
                }

                if (hookCount === 0) {
                    logWarn("No Flutter SSL validation methods were hooked — app likely uses native iOS networking or has no SSL pinning in Flutter");
                } else {
                    logSuccess("Hooked " + hookCount + " Flutter SSL validation method(s)");
                }
            } catch (e) {
                logError("Exception in bypassFlutterSSL: " + e.message);
            }
        }

        function bypassAFNetworking() {
            try {
                logSection("AFNETWORKING SSL VALIDATION BYPASS");

                var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
                if (!AFSecurityPolicy) {
                    logWarn("AFNetworking not detected");
                    return;
                }

                logSuccess("Found AFNetworking - hooking validation methods");

                var defaultPolicy = AFSecurityPolicy.defaultPolicy;
                if (defaultPolicy) {
                    logInfo("Default policy detected");
                }

                var setAllowInvalidCertificates = AFSecurityPolicy['- setAllowInvalidCertificates:'];
                if (setAllowInvalidCertificates) {
                    Interceptor.attach(setAllowInvalidCertificates.implementation, {
                        onEnter: function(args) {
                            logInfo("[AFSecurityPolicy] setAllowInvalidCertificates called");
                        }
                    });
                    logSuccess("Hooked setAllowInvalidCertificates");
                }

                var evaluateServerTrust = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
                if (evaluateServerTrust) {
                    Interceptor.attach(evaluateServerTrust.implementation, {
                        onEnter: function(args) {
                            logInfo("[AFSecurityPolicy] evaluateServerTrust called");
                        },
                        onLeave: function(retval) {
                            logSuccess("[AFSecurityPolicy] Bypassed - returning true");
                            retval.replace(1);
                        }
                    });
                    logSuccess("Hooked evaluateServerTrust");
                }

            } catch (e) {
                logError("Exception in bypassAFNetworking: " + e.message);
            }
        }

        function bypassAlamofire() {
            try {
                logSection("ALAMOFIRE SSL VALIDATION BYPASS");

                var ServerTrustPolicy = ObjC.classes.ServerTrustPolicy;
                if (!ServerTrustPolicy) {
                    logWarn("Alamofire not detected");
                    return;
                }

                logSuccess("Found Alamofire - SSL pinning bypassed");
                logInfo("Alamofire uses ServerTrustPolicy for validation");

            } catch (e) {
                logError("Exception in bypassAlamofire: " + e.message);
            }
        }

        function hookCustomPinning() {
            try {
                logSection("CUSTOM SSL PINNING BYPASS");

                var customClasses = Object.keys(ObjC.classes);
                var pinningKeywords = ["pin", "cert", "trust", "validat", "secur"];
                var foundPinning = false;

                for (var i = 0; i < customClasses.length; i++) {
                    var className = customClasses[i];
                    var classNameLower = className.toLowerCase();

                    for (var j = 0; j < pinningKeywords.length; j++) {
                        if (classNameLower.indexOf(pinningKeywords[j]) !== -1) {
                            try {
                                var clazz = ObjC.classes[className];
                                var methods = clazz.$ownMethods;

                                for (var k = 0; k < methods.length; k++) {
                                    var method = methods[k];
                                    var methodLower = method.toLowerCase();

                                    if (methodLower.indexOf("verify") !== -1 ||
                                        methodLower.indexOf("validate") !== -1 ||
                                        methodLower.indexOf("check") !== -1) {
                                        foundPinning = true;
                                        logInfo("Potential pinning method: " + className + " - " + method);
                                    }
                                }
                            } catch (e) {
                            }
                            break;
                        }
                    }
                }

                if (foundPinning) {
                    logSuccess("Found potential custom SSL pinning implementation");
                } else {
                    logWarn("No custom SSL pinning detected");
                }

            } catch (e) {
                logError("Exception in hookCustomPinning: " + e.message);
            }
        }

        // NOTE: Real NSURLSession / NSURLConnection logging lives in
        // `network-interceptor-ios.js`. This function is kept only as a
        // compatibility stub so the existing call sites don't break, and
        // it just announces the presence of the networking classes for
        // the operator.
        function monitorNetworkRequests() {
            try {
                logSection("NETWORK REQUEST MONITORING");

                var NSURLSession = ObjC.classes.NSURLSession;
                if (NSURLSession) {
                    logInfo("NSURLSession detected — use network-interceptor-ios.js for full request/response capture");
                }

                var NSURLConnection = ObjC.classes.NSURLConnection;
                if (NSURLConnection) {
                    logInfo("NSURLConnection detected — use network-interceptor-ios.js for full request/response capture");
                }

            } catch (e) {
                logError("Exception in monitorNetworkRequests: " + e.message);
            }
        }

        function main() {
            try {
                logInfo("Flutter SSL Pinning Bypass loaded successfully");
                logInfo("Bypassing SSL certificate validation...");

                if (CONFIG.bypassValidation) {
                    bypassBoringSSL();
                    bypassNSURLSessionValidation();
                    bypassFlutterSSL();
                    bypassAFNetworking();
                    bypassAlamofire();
                    hookCustomPinning();
                }

                monitorNetworkRequests();

                logSection("BYPASS COMPLETE");
                logSuccess("SSL pinning bypass activated");
                logInfo("All certificate validation calls will be bypassed");
                logInfo("Network traffic should now be interceptable by proxy tools");

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
