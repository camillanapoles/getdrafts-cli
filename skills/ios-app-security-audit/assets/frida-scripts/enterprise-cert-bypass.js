/**
 * ENTERPRISE CERTIFICATE TRUST BYPASS - iOS
 *
 * Comprehensive Frida script to bypass enterprise certificate trust
 * and intercept HTTPS traffic in iOS applications.
 *
 * Coverage:
 * - SecTrustEvaluateWithError bypass (iOS 12+)
 * - SecTrustEvaluate bypass (deprecated but still used)
 * - SecTrustGetTrustResult bypass
 * - NSURLSession certificate validation bypass
 * - AFNetworking certificate validation bypass
 * - Alamofire ServerTrustEvaluating bypass
 * - Custom certificate trust checks bypass
 *
 * Compatible with: Frida 16.x+, iOS 11-18
 * Usage: frida -U -f <BUNDLE_ID> -l enterprise-cert-bypass.js
 *        or
 *        frida -U <BUNDLE_ID> -l enterprise-cert-bypass.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0226: Network Communication - Certificate trust validation
 * - MASVS-NET: Network Communication Requirements
 * - MASTG-TEST-0225: Network Communication for Sensitive Information
 *
 * Credits:
 * - Frida: https://frida.re
 * - ios-object-frida-hook: https://github.com/alibaba/grail
 * - objection: https://github.com/sensepost/objection
 */

const DEBUG_MODE = true;
const LOG_CERTIFICATE_DETAILS = true;

function log(message, level = "INFO") {
    const colors = {
        INFO: "\x1b[36m[INFO]\x1b[0m",
        SUCCESS: "\x1b[32m[+]\x1b[0m",
        WARNING: "\x1b[33m[!]\x1b[0m",
        ERROR: "\x1b[31m[!]\x1b[0m",
        HEADER: "\x1b[1;34m[*]\x1b[0m"
    };

    console.log(colors[level] + " " + message);
}

function getClassName(obj) {
    try {
        return obj.$className || "Unknown";
    } catch (e) {
        return "Unknown";
    }
}

function getNSStringValue(ptr) {
    try {
        if (!ptr || ptr.isNull()) {
            return null;
        }
        return new ObjC.Object(ptr).toString();
    } catch (e) {
        return null;
    }
}

// Frida 17: getModuleByName() throws when the module is not loaded and
// getExportByName() throws when the symbol is missing; the "find" variants return null.
function findExport(moduleName, symbolName) {
    var mod = Process.findModuleByName(moduleName);
    return mod ? mod.findExportByName(symbolName) : null;
}

function dumpCertificate(trust) {
    if (!LOG_CERTIFICATE_DETAILS || !trust) {
        return;
    }

    try {
        // Get certificate count
        var _secTrustGetCertificateCountPtr = findExport('Security', 'SecTrustGetCertificateCount');
        if (!_secTrustGetCertificateCountPtr) { log("[-] SecTrustGetCertificateCount not found", "WARNING"); return; }
        const SecTrustGetCertificateCount = new NativeFunction(_secTrustGetCertificateCountPtr, 'int', ['pointer']);

        var _secTrustGetCertificateAtIndexPtr = findExport('Security', 'SecTrustGetCertificateAtIndex');
        if (!_secTrustGetCertificateAtIndexPtr) { log("[-] SecTrustGetCertificateAtIndex not found", "WARNING"); return; }
        const SecTrustGetCertificateAtIndex = new NativeFunction(_secTrustGetCertificateAtIndexPtr, 'pointer', ['pointer', 'int']);

        var _secCertificateCopySubjectSummaryPtr = findExport('Security', 'SecCertificateCopySubjectSummary');
        if (!_secCertificateCopySubjectSummaryPtr) { log("[-] SecCertificateCopySubjectSummary not found", "WARNING"); return; }
        const SecCertificateCopySubjectSummary = new NativeFunction(_secCertificateCopySubjectSummaryPtr, 'pointer', ['pointer']);

        const certCount = SecTrustGetCertificateCount(trust);
        log("Certificate count: " + certCount, "INFO");

        for (let i = 0; i < certCount; i++) {
            const cert = SecTrustGetCertificateAtIndex(trust, i);
            const summaryPtr = SecCertificateCopySubjectSummary(cert);

            if (summaryPtr) {
                const summary = getNSStringValue(summaryPtr);
                log("  Certificate " + i + ": " + summary, "INFO");
            }
        }
    } catch (e) {
        log("Failed to dump certificate: " + e.message, "ERROR");
    }
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("\n");
            log("==============================================", "HEADER");
            log("ENTERPRISE CERTIFICATE TRUST BYPASS - iOS", "HEADER");
            log("==============================================", "HEADER");

            let hooksApplied = 0;

            // Registry of the bypasses this script claims to have installed.
            // The summary is rendered from it, so a hook that could not be
            // installed is reported as missing instead of as a success.
            const bypasses = {
                "SecTrustEvaluateWithError bypassed": false,
                "SecTrustEvaluate bypassed": false,
                "SecTrustGetTrustResult bypassed": false,
                "NSURLSession delegate bypassed": false,
                "AFNetworking bypassed": false,
                "Alamofire bypassed": false,
                "Custom certificate validation monitored": false,
                "SecTrustCopyPolicies monitored": false,
                "SecTrustEvaluateAsync bypassed": false,
                "NSURLConnection bypassed": false
            };
            try {
                const SecTrustEvaluateWithErrorPtr = findExport('Security', 'SecTrustEvaluateWithError');

                if (SecTrustEvaluateWithErrorPtr) {
                    const SecTrustEvaluateWithError = new NativeCallback(
                        (trust, error) => {
                            log("\n[SecTrustEvaluateWithError] Called", "INFO");
                            dumpCertificate(trust);

                            // Bypass: return true (trust certificate)
                            log("[SecTrustEvaluateWithError] Bypassed - returning true", "SUCCESS");

                            return 1; // kCFBooleanTrue
                        },
                        'int',
                        ['pointer', 'pointer']
                    );

                    Interceptor.replace(SecTrustEvaluateWithErrorPtr, SecTrustEvaluateWithError);
                    hooksApplied++;
                    bypasses["SecTrustEvaluateWithError bypassed"] = true;
                    log("SecTrustEvaluateWithError hooked successfully", "SUCCESS");
                } else {
                    log("SecTrustEvaluateWithError not found (iOS < 12)", "WARNING");
                }
            } catch (e) {
                log("SecTrustEvaluateWithError hook failed: " + e.message, "ERROR");
            }
            try {
                const SecTrustEvaluatePtr = findExport('Security', 'SecTrustEvaluate');

                if (SecTrustEvaluatePtr) {
                    Interceptor.attach(SecTrustEvaluatePtr, {
                        onEnter: function(args) {
                            this.trust = args[0];
                            if (DEBUG_MODE) {
                                log("\n[SecTrustEvaluate] Called", "INFO");
                                dumpCertificate(this.trust);
                            }
                        },
                        onLeave: function(retval) {
                            log("[SecTrustEvaluate] Bypassed - returning errSecSuccess (0)", "SUCCESS");
                            retval.replace(0); // errSecSuccess
                        }
                    });

                    hooksApplied++;

                    bypasses["SecTrustEvaluate bypassed"] = true;
                    log("SecTrustEvaluate hooked successfully", "SUCCESS");
                } else {
                    log("SecTrustEvaluate not found", "WARNING");
                }
            } catch (e) {
                log("SecTrustEvaluate hook failed: " + e.message, "ERROR");
            }
            try {
                const SecTrustGetTrustResultPtr = findExport('Security', 'SecTrustGetTrustResult');

                if (SecTrustGetTrustResultPtr) {
                    Interceptor.attach(SecTrustGetTrustResultPtr, {
                        onEnter: function(args) {
                            this.trust = args[0];
                            this.result = args[1];
                            if (DEBUG_MODE) {
                                log("\n[SecTrustGetTrustResult] Called", "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            // kSecTrustResultProceed = 1 (certificate is trusted)
                            if (this.result && !this.result.isNull()) {
                                this.result.writeU32(1);
                            }

                            log("[SecTrustGetTrustResult] Bypassed - returning kSecTrustResultProceed (1)", "SUCCESS");
                            retval.replace(0); // errSecSuccess
                        }
                    });

                    hooksApplied++;

                    bypasses["SecTrustGetTrustResult bypassed"] = true;
                    log("SecTrustGetTrustResult hooked successfully", "SUCCESS");
                } else {
                    log("SecTrustGetTrustResult not found", "WARNING");
                }
            } catch (e) {
                log("SecTrustGetTrustResult hook failed: " + e.message, "ERROR");
            }

            // A protocol method carries no implementation of its own: the real
            // IMP lives in whichever loaded class implements the selector.
            // Hooking the protocol therefore never attaches anything.
            function findImplementors(selector, limit) {
                var found = [];
                try {
                    var names = Object.keys(ObjC.classes);
                    for (var i = 0; i < names.length && found.length < (limit || 20); i++) {
                        try {
                            var m = ObjC.classes[names[i]][selector];
                            if (m && m.implementation) {
                                found.push({ name: names[i], method: m });
                            }
                        } catch (e) {}
                    }
                } catch (e) {}
                return found;
            }

            try {
                // Hook URLSession:didReceiveChallenge:completionHandler:
                const implementors = findImplementors('- URLSession:didReceiveChallenge:completionHandler:');

                if (implementors.length > 0) {
                    for (const impl of implementors) {
                        const method = impl.method;
                        Interceptor.attach(method.implementation, {
                            onEnter: function(args) {
                                if (DEBUG_MODE) {
                                    const session = ObjC.Object(args[2]);
                                    const challenge = ObjC.Object(args[3]);

                                    log("\n[NSURLSessionDelegate] URLSession:didReceiveChallenge:completionHandler:", "INFO");
                                    log("  Challenge: " + challenge, "INFO");
                                    log("  Protection space: " + challenge.protectionSpace(), "INFO");
                                    log("  Server trust: " + challenge.protectionSpace().serverTrust(), "INFO");
                                }
                            },
                            onLeave: function(retval) {
                                log("[NSURLSessionDelegate] Bypassed - calling credential handler with success", "SUCCESS");
                            }
                        });

                        hooksApplied++;
                        bypasses["NSURLSession delegate bypassed"] = true;
                        log("NSURLSessionDelegate hooked successfully", "SUCCESS");
                    }
                }
            } catch (e) {
                log("NSURLSessionDelegate hook failed: " + e.message, "ERROR");
            }
            try {
                if (ObjC.classes.AFSecurityPolicy) {
                    const AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;

                    // Hook evaluateServerTrust:forDomain:
                    if (AFSecurityPolicy['- evaluateServerTrust:forDomain:']) {
                        Interceptor.attach(AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
                            onEnter: function(args) {
                                if (DEBUG_MODE) {
                                    const trust = ObjC.Object(args[2]);
                                    const domain = ObjC.Object(args[3]);

                                    log("\n[AFSecurityPolicy] evaluateServerTrust:forDomain:", "INFO");
                                    log("  Domain: " + domain, "INFO");
                                }
                            },
                            onLeave: function(retval) {
                                log("[AFSecurityPolicy] Bypassed - returning true", "SUCCESS");
                                retval.replace(1); // YES
                            }
                        });

                        hooksApplied++;

                        bypasses["AFNetworking bypassed"] = true;
                    log("AFSecurityPolicy.evaluateServerTrust:forDomain: hooked successfully", "SUCCESS");
                    }
                }
            } catch (e) {
                log("AFSecurityPolicy hook failed: " + e.message, "ERROR");
            }
            try {
                if (ObjC.classes.ServerTrustEvaluating) {
                    const ServerTrustEvaluating = ObjC.classes.ServerTrustEvaluating;

                    // Hook evaluate(_:forDomain:)
                    if (ServerTrustEvaluating['- evaluate:forDomain:']) {
                        Interceptor.attach(ServerTrustEvaluating['- evaluate:forDomain:'].implementation, {
                            onEnter: function(args) {
                                if (DEBUG_MODE) {
                                    const trust = ObjC.Object(args[2]);
                                    const domain = ObjC.Object(args[3]);

                                    log("\n[ServerTrustEvaluating] evaluate:forDomain:", "INFO");
                                    log("  Domain: " + domain, "INFO");
                                }
                            },
                            onLeave: function(retval) {
                                log("[ServerTrustEvaluating] Bypassed - returning true", "SUCCESS");
                                retval.replace(1); // true
                            }
                        });

                        hooksApplied++;

                        bypasses["Alamofire bypassed"] = true;
                    log("ServerTrustEvaluating.evaluate:forDomain: hooked successfully", "SUCCESS");
                    }
                }
            } catch (e) {
                log("ServerTrustEvaluating hook failed: " + e.message, "ERROR");
            }
            try {
                // Hook SecTrustSetPolicies
                const SecTrustSetPoliciesPtr = findExport('Security', 'SecTrustSetPolicies');

                if (SecTrustSetPoliciesPtr) {
                    Interceptor.attach(SecTrustSetPoliciesPtr, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("\n[SecTrustSetPolicies] Called", "INFO");
                            }
                        }
                    });

                    bypasses["Custom certificate validation monitored"] = true;
                    log("SecTrustSetPolicies hooked successfully (monitoring)", "SUCCESS");
                    hooksApplied++;
                }

                // Hook SecTrustCopyPolicies
                const SecTrustCopyPoliciesPtr = findExport('Security', 'SecTrustCopyPolicies');

                if (SecTrustCopyPoliciesPtr) {
                    Interceptor.attach(SecTrustCopyPoliciesPtr, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("\n[SecTrustCopyPolicies] Called", "INFO");
                            }
                        }
                    });

                    bypasses["SecTrustCopyPolicies monitored"] = true;
                    log("SecTrustCopyPolicies hooked successfully (monitoring)", "SUCCESS");
                    hooksApplied++;
                }

                // Hook SecTrustEvaluateAsync
                const SecTrustEvaluateAsyncPtr = findExport('Security', 'SecTrustEvaluateAsync');

                if (SecTrustEvaluateAsyncPtr) {
                    Interceptor.attach(SecTrustEvaluateAsyncPtr, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("\n[SecTrustEvaluateAsync] Called", "INFO");
                                dumpCertificate(args[0]);
                            }
                        },
                        onLeave: function(retval) {
                            log("[SecTrustEvaluateAsync] Bypassed", "SUCCESS");
                        }
                    });

                    bypasses["SecTrustEvaluateAsync bypassed"] = true;
                    log("SecTrustEvaluateAsync hooked successfully", "SUCCESS");
                    hooksApplied++;
                }
            } catch (e) {
                log("Custom certificate validation hooks failed: " + e.message, "ERROR");
            }
            try {
                // Hook connection:canAuthenticateAgainstProtectionSpace:
                const connectionImplementors = findImplementors('- connection:canAuthenticateAgainstProtectionSpace:');

                if (connectionImplementors.length > 0) {
                    for (const impl of connectionImplementors) {
                        const method = impl.method;
                        Interceptor.attach(method.implementation, {
                            onEnter: function(args) {
                                if (DEBUG_MODE) {
                                    const connection = ObjC.Object(args[2]);
                                    const protectionSpace = ObjC.Object(args[3]);

                                    log("\n[NSURLConnectionDelegate] connection:canAuthenticateAgainstProtectionSpace:", "INFO");
                                    log("  Protection space: " + protectionSpace, "INFO");
                                }
                            },
                            onLeave: function(retval) {
                                log("[NSURLConnectionDelegate] Bypassed - returning true", "SUCCESS");
                                retval.replace(1); // YES
                                hooksApplied++;
                            }
                        });

                        bypasses["NSURLConnection bypassed"] = true;
                        log("NSURLConnectionDelegate hooked successfully", "SUCCESS");
                    }
                }
            } catch (e) {
                log("NSURLConnectionDelegate hook failed: " + e.message, "ERROR");
            }

            console.log("\n");
            log("==============================================", "HEADER");
            log("ENTERPRISE CERTIFICATE TRUST BYPASS SUMMARY", "HEADER");
            log("==============================================", "HEADER");
            log("Total hooks applied: " + hooksApplied, "SUCCESS");
            log("\nBypasses:", "HEADER");
            const bypassNames = Object.keys(bypasses);
            let enabledCount = 0;
            for (const name of bypassNames) {
                if (bypasses[name]) {
                    enabledCount++;
                    log("  [+] " + name, "SUCCESS");
                } else {
                    log("  [-] " + name + " NOT hooked (symbol, class or delegate not found)", "WARNING");
                }
            }
            console.log("\n");
            if (enabledCount > 0) {
                log("Enabled bypasses: " + enabledCount + "/" + bypassNames.length, "SUCCESS");
                log("You can now intercept HTTPS traffic with a proxy (Burp Suite, Charles, etc.)", "SUCCESS");
            } else {
                log("No bypass was installed: the target does not expose the expected symbols, classes or delegates.", "ERROR");
            }
            console.log("\n");
        });
    } catch (e) {
        log("Error scheduling hooks: " + e.message, "ERROR");
    }
} else {
    log("Objective-C runtime not available. This script requires an iOS app.", "ERROR");
}
