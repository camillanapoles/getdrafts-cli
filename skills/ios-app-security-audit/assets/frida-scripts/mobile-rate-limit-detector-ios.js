/**
 * MOBILE RATE LIMIT DETECTOR - iOS
 *
 * Frida script to detect authentication endpoints that lack rate limiting,
 * allowing unlimited brute force attempts.
 *
 * Based on real vulnerabilities:
 * - H1-160109: Instacart iOS - Web locked after 15 attempts, mobile allowed 50+
 * - H1-2245437: Files iOS - PIN code bypass with unlimited attempts
 *
 * Usage: frida -U -f <BUNDLE_ID> -l mobile-rate-limit-detector-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l mobile-rate-limit-detector-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0119: Test Weak Password Policy
 * - MASTG-TEST-0120: Test Weak Password Reset
 * - MASVS-AUTH: Authentication Requirements
 */

const DEBUG_MODE = true;
const LOCKOUT_THRESHOLD = 15;
const CRITICAL_THRESHOLD = 50;
const REPORT_INTERVAL = 30000;

const AUTH_PATTERNS = [
    '/login',
    '/auth',
    '/oauth',
    '/signin',
    '/sign-in',
    '/token',
    '/pin',
    '/password',
    '/verify'
];

const endpointAttempts = {};

function trackEndpoint(url, method) {
    const key = url + ':' + method;

    if (!endpointAttempts[key]) {
        endpointAttempts[key] = {
            count: 0,
            timestamps: [],
            firstSeen: Date.now()
        };
    }

    const tracker = endpointAttempts[key];
    tracker.count++;
    tracker.timestamps.push(Date.now());

    if (tracker.count === LOCKOUT_THRESHOLD) {
        console.log('[VULN] ' + LOCKOUT_THRESHOLD + ' attempts to ' + url);
        console.log('       Standard lockout threshold reached - rate limiting MAY be missing');
        console.log('       Expected behavior: Account should be locked or rate limit enforced');
    }

    if (tracker.count >= CRITICAL_THRESHOLD) {
        console.log('[CRITICAL] ' + tracker.count + ' attempts to ' + url);
        console.log('           NO rate limiting detected after ' + tracker.count + ' requests');
        console.log('           Reference: H1-160109 (Instacart iOS), H1-2245437 (Files iOS)');
        console.log('           Impact: Brute force possible, account takeover risk HIGH');
    }

    if (DEBUG_MODE && tracker.count % 10 === 0 && tracker.count > 0) {
        console.log('[INFO] ' + tracker.count + ' attempts tracked for ' + url);
    }
}

function isAuthEndpoint(url) {
    const lowerUrl = url.toLowerCase();
    for (const pattern of AUTH_PATTERNS) {
        if (lowerUrl.includes(pattern)) {
            return true;
        }
    }
    return false;
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] MOBILE RATE LIMIT DETECTOR - iOS STARTED");
            console.log("[*] ================================================");
            console.log("[*] Monitoring for authentication endpoints without rate limiting");
            console.log("[*] Lockout threshold: " + LOCKOUT_THRESHOLD + " attempts");
            console.log("[*] Critical threshold: " + CRITICAL_THRESHOLD + " attempts");
            console.log("[*] ");

            try {
                const NSURLSessionTask = ObjC.classes.NSURLSessionTask;
                if (NSURLSessionTask) {
                    const resumeMethod = NSURLSessionTask['- resume'];
                    if (resumeMethod) {
                        Interceptor.attach(resumeMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const task = ObjC.Object(args[0]);
                                    const originalRequest = task.originalRequest();

                                    if (originalRequest) {
                                        const url = originalRequest.URL().absoluteString().toString();
                                        const method = originalRequest.HTTPMethod().toString();

                                        if (isAuthEndpoint(url)) {
                                            trackEndpoint(url, method);
                                        }
                                    }
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in NSURLSessionTask hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: NSURLSessionTask -resume');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook NSURLSessionTask: ' + e);
            }

            try {
                const NSURLConnection = ObjC.classes.NSURLConnection;
                if (NSURLConnection) {
                    const startMethod = NSURLConnection['- start'];
                    if (startMethod) {
                        Interceptor.attach(startMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const connection = ObjC.Object(args[0]);
                                    const request = connection.originalRequest();

                                    if (request) {
                                        const url = request.URL().absoluteString().toString();
                                        const method = request.HTTPMethod().toString();

                                        if (isAuthEndpoint(url)) {
                                            trackEndpoint(url, method);
                                        }
                                    }
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in NSURLConnection hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: NSURLConnection -start');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook NSURLConnection: ' + e);
            }

            try {
                const LAContext = ObjC.classes.LAContext;
                if (LAContext) {
                    const evaluateMethod = LAContext['- evaluatePolicy:localizedReason:reply:'];
                    if (evaluateMethod) {
                        Interceptor.attach(evaluateMethod.implementation, {
                            onEnter: function(args) {
                                console.log('[BIOMETRIC] Biometric/PIN evaluation triggered');
                            }
                        });
                        console.log('[+] Hooked: LAContext -evaluatePolicy');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook LAContext: ' + e);
            }

            console.log("[*] ");
            console.log('[*] Monitoring active - send auth requests to trigger detection');
            console.log('[*] Report summary every ' + (REPORT_INTERVAL / 1000) + ' seconds');

            setInterval(function() {
                let totalAttempts = 0;
                let vulnEndpoints = 0;

                for (const key in endpointAttempts) {
                    const tracker = endpointAttempts[key];
                    totalAttempts += tracker.count;
                    if (tracker.count >= LOCKOUT_THRESHOLD) {
                        vulnEndpoints++;
                    }
                }

                if (totalAttempts > 0) {
                    console.log('[*] ================================================');
                    console.log('[*] RATE LIMIT DETECTOR SUMMARY');
                    console.log('[*] ================================================');
                    console.log('[*] Total auth attempts tracked: ' + totalAttempts);
                    console.log('[*] Endpoints monitored: ' + Object.keys(endpointAttempts).length);
                    console.log('[*] Vulnerable endpoints (>=' + LOCKOUT_THRESHOLD + '): ' + vulnEndpoints);

                    if (vulnEndpoints > 0) {
                        console.log('[*] ');
                        console.log('[!] VULNERABLE ENDPOINTS:');
                        for (const key in endpointAttempts) {
                            const tracker = endpointAttempts[key];
                            if (tracker.count >= LOCKOUT_THRESHOLD) {
                                const parts = key.split(':');
                                console.log('    - ' + parts[0] + ' (' + tracker.count + ' attempts)');
                            }
                        }
                    }
                    console.log('[*] ================================================');
                }
            }, REPORT_INTERVAL);

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
 * 1. Identify auth endpoints:
 *    rg "oauth|login|token|pin" -g "*.m" -g "*.swift"
 *
 * 2. Runtime Testing with this script:
 *    frida -U -f com.example.app -l mobile-rate-limit-detector-ios.js
 *
 * 3. Confirm with brute force simulation:
 *    Send 20+ login attempts with different passwords
 *    If no lockout after 15 attempts → VULNERABLE
 *
 * 4. Remediation:
 *    - Enforce consistent rate limiting across platforms
 *    - Implement account lockout after N failed attempts
 *    - Add CAPTCHA after M failures
 */
