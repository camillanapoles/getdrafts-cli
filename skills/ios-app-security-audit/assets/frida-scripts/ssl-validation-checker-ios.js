/**
 * SSL CERTIFICATE VALIDATION CHECKER - iOS
 *
 * Frida script to detect if an iOS app validates SSL/TLS certificates.
 * Apps that don't validate certificates are vulnerable to MITM attacks.
 *
 * Based on real vulnerability:
 * - H1-168538: Twitter iOS (6.62-6.62.1) did not validate SSL certificates.
 *   A transparent proxy was sufficient to intercept traffic and extract
 *   OAuth tokens without installing a trusted CA certificate.
 *
 * Usage: frida -U -f <BUNDLE_ID> -l ssl-validation-checker-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l ssl-validation-checker-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0225: Test Network Communication for Sensitive Information
 * - MASTG-TEST-0226: Test Network SSL/TLS
 * - MASVS-NET: Network Communication Requirements
 */

const DEBUG_MODE = true;
const ANALYSIS_DELAY = 5000;

let secTrustEvaluateCalled = false;
let challengeHandlerCalled = false;
let nsURLSessionUsed = false;

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] SSL CERTIFICATE VALIDATION CHECKER - iOS");
            console.log("[*] ================================================");
            console.log("[*] Checking if app validates SSL/TLS certificates...");
            console.log("[*] Analysis delay: " + (ANALYSIS_DELAY / 1000) + " seconds");
            console.log("[*] ");

            // Frida 17: getModuleByName() throws when the module is not loaded and
            // getExportByName() throws when the symbol is missing; the "find" variants return null.
            function findExport(moduleName, symbolName) {
                var mod = Process.findModuleByName(moduleName);
                return mod ? mod.findExportByName(symbolName) : null;
            }

            try {
                const SecTrustEvaluate = findExport('Security', 'SecTrustEvaluate');
                if (SecTrustEvaluate) {
                    Interceptor.attach(SecTrustEvaluate, {
                        onEnter: function(args) {
                            secTrustEvaluateCalled = true;
                            console.log('[+] SecTrustEvaluate called - certificate validation IS performed (GOOD)');
                        }
                    });
                    console.log('[+] Found: SecTrustEvaluate (certificate validation function)');
                } else {
                    console.log('[!] SecTrustEvaluate not found in loaded modules');
                }
            } catch (e) {
                console.log('[-] Failed to hook SecTrustEvaluate: ' + e);
            }

            try {
                const SecTrustEvaluateWithError = findExport('Security', 'SecTrustEvaluateWithError');
                if (SecTrustEvaluateWithError) {
                    Interceptor.attach(SecTrustEvaluateWithError, {
                        onEnter: function(args) {
                            secTrustEvaluateCalled = true;
                            console.log('[+] SecTrustEvaluateWithError called - certificate validation IS performed (GOOD)');
                        }
                    });
                    console.log('[+] Found: SecTrustEvaluateWithError (iOS 12+ certificate validation)');
                }
            } catch (e) {
                if (DEBUG_MODE) {
                    console.log('[-] SecTrustEvaluateWithError not available (iOS <12): ' + e);
                }
            }

            // The summary reports what was really hooked: the loop swallows
            // every per-class error, so an unconditional "Monitored for ..."
            // would be false coverage.
            let challengeHandlersHooked = 0;
            try {
                const challengeMethods = [
                    'URLSession:didReceiveChallenge:completionHandler:',
                    'URLSession:task:didReceiveChallenge:completionHandler:'
                ];

                for (const className in ObjC.classes) {
                    try {
                        const cls = ObjC.classes[className];

                        if (className.startsWith('WK') ||
                            className.startsWith('_') ||
                            className.startsWith('NS') ||
                            className.startsWith('UI')) {
                            continue;
                        }

                        for (const method of challengeMethods) {
                            try {
                                if (cls[method]) {
                                    Interceptor.attach(cls[method].implementation, {
                                        onEnter: function(args) {
                                            challengeHandlerCalled = true;
                                            if (DEBUG_MODE) {
                                                console.log('[+] Challenge handler called in ' + className);
                                            }
                                        }
                                    });
                                    challengeHandlersHooked++;
                                }
                            } catch (e) {
                            }
                        }
                    } catch (e) {
                    }
                }

                if (challengeHandlersHooked > 0) {
                    console.log('[+] Monitored for: NSURLSession challenge handlers (' + challengeHandlersHooked + ' hooked)');
                } else {
                    console.log('[-] No NSURLSession challenge handler was hooked');
                }
            } catch (e) {
                console.log('[-] Failed to monitor challenge handlers: ' + e);
            }

            try {
                const NSURLSession = ObjC.classes.NSURLSession;
                if (NSURLSession) {
                    const sessionWithDelegate = NSURLSession['+ sessionWithDelegate:queue:'];
                    if (sessionWithDelegate) {
                        Interceptor.attach(sessionWithDelegate.implementation, {
                            onEnter: function(args) {
                                nsURLSessionUsed = true;
                            }
                        });
                    }

                    const dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];
                    if (dataTask) {
                        Interceptor.attach(dataTask.implementation, {
                            onEnter: function(args) {
                                nsURLSessionUsed = true;
                            }
                        });
                    }

                    console.log('[+] Found: NSURLSession (has default TLS validation)');
                }
            } catch (e) {
                console.log('[-] Failed to hook NSURLSession: ' + e);
            }

            setTimeout(function() {
                console.log('[*] ================================================');
                console.log('[*] SSL VALIDATION ANALYSIS RESULTS');
                console.log('[*] ================================================');
                console.log('[*] ');

                console.log('[*] SecTrustEvaluate called: ' + (secTrustEvaluateCalled ? 'YES' : 'NO'));
                console.log('[*] Challenge handler called: ' + (challengeHandlerCalled ? 'YES' : 'NO'));
                console.log('[*] NSURLSession used: ' + (nsURLSessionUsed ? 'YES' : 'NO'));
                console.log('[*] ');

                if (secTrustEvaluateCalled || challengeHandlerCalled) {
                    console.log('[+] VALIDATION DETECTED');
                    console.log('[+] App DOES validate SSL certificates (good!)');
                    console.log('[+] MITM attacks require certificate pinning bypass');
                } else {
                    console.log('[!] CRITICAL VULNERABILITY');
                    console.log('[!] App does NOT validate SSL certificates!');
                    console.log('[!] MITM attacks possible WITHOUT any bypass needed');
                    console.log('[!] Reference: H1-168538 (Twitter iOS cert validation bypass)');
                    console.log('[!] ');
                    console.log('[!] Impact:');
                    console.log('[!]   - All HTTPS traffic can be intercepted');
                    console.log('[!]   - OAuth tokens, session cookies, passwords exposed');
                    console.log('[!]   - Sensitive data can be stolen transparently');
                    console.log('[!] ');
                    console.log('[!] Remediation:');
                    console.log('[!]   1. Implement NSURLSessionDelegate didReceiveChallenge');
                    console.log('[!]   2. Call SecTrustEvaluate on server certificate');
                    console.log('[!]   3. Consider certificate pinning for high-value endpoints');
                    console.log('[!]   4. Test with: nscurl --verbose https://api.example.com');
                }

                console.log('[*] ================================================');
                console.log('[*] ');

                if (!secTrustEvaluateCalled && !challengeHandlerCalled) {
                    console.log('[INFO] To confirm vulnerability:');
                    console.log('[INFO] 1. Set up Burp Suite proxy');
                    console.log('[INFO] 2. Configure device to use proxy');
                    console.log('[INFO] 3. Open app and trigger network requests');
                    console.log('[INFO] 4. If traffic visible in Burp without cert install -> VULNERABLE');
                }

            }, ANALYSIS_DELAY);

        });
    } catch (e) {
        console.log('[-] Failed to schedule on main queue: ' + e);
    }
} else {
    console.log("[-] Objective-C runtime not available. This script requires iOS.");
}

/**
 * Manual Testing Procedure
 *
 * 1. Static Analysis:
 *    nm -gU <binary> | grep -i "sectrust"
 *
 * 2. Runtime Testing with this script:
 *    frida -U -f com.example.app -l ssl-validation-checker-ios.js
 *
 * 3. Confirm with Proxy:
 *    a) Install Burp CA on device (Settings > General > About > Certificate Trust Settings)
 *    b) Configure device to use Burp proxy
 *    c) Open app - if traffic visible in Burp, validation is weak
 *
 * 4. Test with nscurl:
 *    nscurl --verbose --ats-diagnostic https://api.example.com
 *
 * 5. Remediation:
 *    - Implement proper NSURLSessionDelegate
 *    - Use certificate pinning for sensitive endpoints
 *    - Test with ssl-pinning-bypass-ios.js
 */
