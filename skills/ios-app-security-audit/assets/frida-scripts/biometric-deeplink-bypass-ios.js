/**
 * BIOMETRIC DEEPLINK BYPASS DETECTOR - iOS
 *
 * Frida script to detect when deep links navigate to protected features
 * without requiring biometric re-authentication.
 *
 * Based on real vulnerability:
 * - H1-637194: Shopify Mobile - When app was open, deep links could
 *   bypass fingerprint authentication and directly access protected features.
 *
 * Usage: frida -U -f <BUNDLE_ID> -l biometric-deeplink-bypass-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l biometric-deeplink-bypass-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0107: Test Biometric Authentication
 * - MASTG-TEST-0114: Test Device Lock
 * - MASVS-AUTH: Authentication Requirements
 */

const DEBUG_MODE = true;
const REAUTH_TIMEOUT = 5000;

const PROTECTED_VIEW_PATTERNS = [
    'Settings',
    'Profile',
    'Account',
    'Payment',
    'Payments',
    'Wallet',
    'Bank',
    'Card',
    'Admin',
    'Dashboard',
    'History',
    'Orders',
    'Private',
    'Sensitive',
    'Security'
];

let biometricEvalCount = 0;
let lastBiometricTime = 0;
let deepLinkCount = 0;
let lastDeepLinkTime = 0;
let protectedViewNavigated = false;
let lastNavigationTime = 0;
let vulnerableNavigations = 0;

function isProtectedView(viewName) {
    if (!viewName) return false;

    const lowerName = viewName.toLowerCase();

    for (const pattern of PROTECTED_VIEW_PATTERNS) {
        if (lowerName.includes(pattern.toLowerCase())) {
            return true;
        }
    }

    return false;
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] BIOMETRIC DEEPLINK BYPASS DETECTOR - iOS");
            console.log("[*] ================================================");
            console.log("[*] Monitoring for deep links that bypass biometric re-auth");
            console.log("[*] Re-auth timeout: " + REAUTH_TIMEOUT + 'ms');
            console.log("[*] ");

            try {
                const LAContext = ObjC.classes.LAContext;
                if (LAContext) {
                    const evaluateMethod = LAContext['- evaluatePolicy:localizedReason:reply:'];
                    if (evaluateMethod) {
                        Interceptor.attach(evaluateMethod.implementation, {
                            onEnter: function(args) {
                                biometricEvalCount++;
                                lastBiometricTime = Date.now();

                                const policy = ObjC.Object(args[2]);
                                const policyValue = policy ? policy.toString() : '';

                                console.log('[BIOMETRIC] Biometric evaluation triggered (count: ' + biometricEvalCount + ')');
                                console.log('           Policy: ' + policyValue);
                            },
                            onLeave: function(retval) {
                                const success = retval.toInt32();
                                if (DEBUG_MODE) {
                                    console.log('[BIOMETRIC] Result: ' + (success === 1 ? 'SUCCESS' : 'FAILED'));
                                }
                            }
                        });
                        console.log('[+] Hooked: LAContext -evaluatePolicy');
                    } else {
                        console.log('[!] LAContext -evaluatePolicy not found');
                    }
                } else {
                    console.log('[!] LAContext class not found');
                }
            } catch (e) {
                console.log('[-] Failed to hook LAContext: ' + e);
            }

            try {
                const UIApplication = ObjC.classes.UIApplication;
                if (UIApplication) {
                    const openURLMethod = UIApplication['- openURL:'];
                    if (openURLMethod) {
                        Interceptor.attach(openURLMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const url = ObjC.Object(args[2]).toString();
                                    deepLinkCount++;
                                    lastDeepLinkTime = Date.now();

                                    console.log('[DEEPLINK] Deep link opened: ' + url);
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in openURL hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: UIApplication -openURL:');
                    }

                    const openURLWithOptions = UIApplication['- openURL:options:completionHandler:'];
                    if (openURLWithOptions) {
                        Interceptor.attach(openURLWithOptions.implementation, {
                            onEnter: function(args) {
                                try {
                                    const url = ObjC.Object(args[2]).toString();
                                    deepLinkCount++;
                                    lastDeepLinkTime = Date.now();

                                    console.log('[DEEPLINK] Deep link opened (iOS 10+): ' + url);
                                } catch (e) {}
                            }
                        });
                        console.log('[+] Hooked: UIApplication -openURL:options:completionHandler:');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook UIApplication: ' + e);
            }

            try {
                const UINavigationController = ObjC.classes.UINavigationController;
                if (UINavigationController) {
                    const pushVCMethod = UINavigationController['- pushViewController:animated:'];
                    if (pushVCMethod) {
                        Interceptor.attach(pushVCMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const pushedVC = ObjC.Object(args[2]);
                                    const vcName = pushedVC.$className;
                                    lastNavigationTime = Date.now();

                                    if (isProtectedView(vcName)) {
                                        protectedViewNavigated = true;

                                        const timeSinceBiometric = lastBiometricTime > 0 ? (Date.now() - lastBiometricTime) : -1;
                                        const timeSinceDeepLink = lastDeepLinkTime > 0 ? (Date.now() - lastDeepLinkTime) : -1;

                                        console.log('[NAVIGATE] Protected view accessed: ' + vcName);
                                        console.log('         Time since biometric: ' + timeSinceBiometric + 'ms');
                                        console.log('         Time since deep link: ' + timeSinceDeepLink + 'ms');

                                        if (timeSinceBiometric > REAUTH_TIMEOUT || timeSinceBiometric === -1) {
                                            if (timeSinceDeepLink < REAUTH_TIMEOUT && timeSinceDeepLink > 0) {
                                                vulnerableNavigations++;
                                                console.log('[VULN] Protected view accessed WITHOUT recent biometric');
                                                console.log('       View: ' + vcName);
                                                console.log('       Biometric was ' + (timeSinceBiometric === -1 ? 'NEVER used' : timeSinceBiometric + 'ms ago'));
                                                console.log('       Deep link was ' + timeSinceDeepLink + 'ms ago');
                                                console.log('       Expected: Biometric re-auth should be required');
                                                console.log('       Reference: H1-637194 (Shopify deeplink bypass)');
                                                console.log('       Impact: Attacker with deep link can access protected features');
                                            } else if (DEBUG_MODE) {
                                                console.log('[INFO] Protected view accessed - check if re-auth needed');
                                            }
                                        }
                                    }
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in navigation hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: UINavigationController -pushViewController:animated:');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook UINavigationController: ' + e);
            }

            try {
                for (const className in ObjC.classes) {
                    if (className.includes('Navigation') && !className.startsWith('_')) {
                        try {
                            const cls = ObjC.classes[className];
                            const pushMethod = cls['- pushViewController:animated:'];
                            if (pushMethod) {
                                Interceptor.attach(pushMethod.implementation, {
                                    onEnter: function(args) {
                                        try {
                                            const pushedVC = ObjC.Object(args[2]);
                                            const vcName = pushedVC.$className;

                                            if (isProtectedView(vcName) && DEBUG_MODE) {
                                                console.log('[NAVIGATE] ' + className + ' pushed: ' + vcName);
                                            }
                                        } catch (e) {}
                                    }
                                });
                            }
                        } catch (e) {}
                    }
                }
            } catch (e) {
                if (DEBUG_MODE) {
                    console.log('[-] Failed to scan for custom navigation classes: ' + e);
                }
            }

            console.log("[*] ");
            console.log('[*] Monitoring active - navigate to protected views to trigger detection');

            setInterval(function() {
                console.log('[*] ================================================');
                console.log('[*] BIOMETRIC DEEPLINK BYPASS SUMMARY');
                console.log('[*] ================================================');
                console.log('[*] Biometric evaluations: ' + biometricEvalCount);
                console.log('[*] Deep links opened: ' + deepLinkCount);
                console.log('[*] Protected views accessed: ' + (protectedViewNavigated ? 'YES' : 'NO'));
                console.log('[*] Vulnerable navigations: ' + vulnerableNavigations);

                if (vulnerableNavigations > 0) {
                    console.log('[!] VULNERABILITY DETECTED');
                    console.log('[!] Protected features accessible without biometric re-auth');
                    console.log('[!] Attack scenario: Craft malicious deep link -> victim clicks -> bypass biometric');
                    console.log('[!] ');
                    console.log('[!] Remediation:');
                    console.log('[!]   1. Require biometric re-auth after deep link navigation');
                    console.log('[!]   2. Validate deep link tokens for freshness');
                    console.log('[!]   3. Separate public and protected deep link namespaces');
                    console.log('[!]   4. Log and alert on suspicious deep link patterns');
                }
                console.log('[*] ================================================');
            }, 30000);

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
 * 1. Identify deep link schemes:
 *    plutil -p Info.plist | grep CFBundleURLSchemes
 *
 * 2. Identify protected views:
 *    Look for Settings, Profile, Payment views in UI
 *
 * 3. Test flow:
 *    a) Authenticate with biometric
 *    b) Wait 10+ seconds (past REAUTH_TIMEOUT)
 *    c) Trigger deep link to protected feature
 *       Example: myapp://settings
 *    d) If app opens settings WITHOUT biometric -> VULNERABLE
 *
 * 4. Verify with Frida:
 *    frida -U -f com.example.app -l biometric-deeplink-bypass-ios.js
 *
 * 5. Remediation:
 *    - Store biometric timestamp
 *    - Check timestamp before allowing protected feature access
 *    - Require re-auth if timestamp > REAUTH_TIMEOUT
 *    - Implement deep link token validation
 */
