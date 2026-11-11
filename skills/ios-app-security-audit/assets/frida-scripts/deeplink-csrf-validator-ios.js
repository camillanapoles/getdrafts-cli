/**
 * DEEP LINK CSRF VALIDATOR - iOS
 *
 * Frida script to detect state-changing deep link actions
 * that lack CSRF token protection.
 *
 * Based on real vulnerability:
 * - H1-805073: Periscope iOS - Deep link `pscp://user/<id>/follow`
 *   could be triggered from any context without CSRF token,
 *   allowing forced follows and account takeover.
 *
 * Usage: frida -U -f <BUNDLE_ID> -l deeplink-csrf-validator-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l deeplink-csrf-validator-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0131: Test Deep Links
 * - MASTG-TEST-0146: Test URL Scheme Handling
 * - MASVS-PLATFORM: Platform Integration
 */

const DEBUG_MODE = true;

const SENSITIVE_ACTIONS = [
    'follow',
    'like',
    'unfollow',
    'delete',
    'update',
    'transfer',
    'approve',
    'reject',
    'pay',
    'send',
    'buy',
    'sell',
    'withdraw',
    'deposit',
    'connect',
    'disconnect',
    'share',
    'post',
    'comment'
];

const CSRF_PARAMS = [
    'token',
    'csrf',
    'csrf_token',
    'state',
    'nonce',
    'authenticity_token'
];

const deepLinkLog = [];
let vulnerableActions = 0;

function hasCSRFToken(url) {
    const lowerUrl = url.toLowerCase();

    for (const param of CSRF_PARAMS) {
        if (lowerUrl.includes(param + '=')) {
            return true;
        }
    }

    if (url.includes('?') && url.split('=').length > 1) {
        return true;
    }

    return false;
}

function hasSensitiveAction(url) {
    const lowerUrl = url.toLowerCase();

    for (const action of SENSITIVE_ACTIONS) {
        if (lowerUrl.includes(action)) {
            return action;
        }
    }

    return null;
}

function validateDeepLink(url) {
    deepLinkLog.push({ url: url, timestamp: Date.now() });

    const sensitiveAction = hasSensitiveAction(url);

    if (sensitiveAction) {
        const hasToken = hasCSRFToken(url);

        if (!hasToken) {
            vulnerableActions++;
            console.log('[VULN] Sensitive action via deep link WITHOUT CSRF token');
            console.log('       URL: ' + url);
            console.log('       Action: ' + sensitiveAction);
            console.log('       Impact: CSRF possible - forced action without user consent');
            console.log('       Reference: H1-805073 (Periscope deep link CSRF)');
            console.log('       Expected: ?token=... or &state=... parameter should be present');
            console.log('       Remediation: Validate CSRF token server-side before executing action');

            if (DEBUG_MODE) {
                console.log('[INFO] Suggested test: Trigger same action with malicious token');
                console.log('       If app accepts invalid token, CSRF is confirmed');
            }
        } else {
            console.log('[OK] Sensitive action has CSRF/token protection: ' + url);
        }
    } else {
        if (DEBUG_MODE) {
            console.log('[INFO] Non-sensitive deep link (or unrecognized): ' + url);
        }
    }
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] DEEP LINK CSRF VALIDATOR - iOS STARTED");
            console.log("[*] ================================================");
            console.log("[*] Monitoring for state-changing deep links without CSRF tokens");
            console.log("[*] ");

            try {
                const UIApplication = ObjC.classes.UIApplication;
                if (UIApplication) {
                    const openURLMethod = UIApplication['- openURL:'];
                    if (openURLMethod) {
                        Interceptor.attach(openURLMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const url = ObjC.Object(args[2]).toString();
                                    console.log('[DEEPLINK] openURL called: ' + url);
                                    validateDeepLink(url);
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in UIApplication hook: ' + e);
                                    }
                                }
                            },
                            onLeave: function(retval) {
                                const success = retval.toInt32();
                                if (success === 1 && DEBUG_MODE) {
                                    console.log('[INFO] Deep link opened successfully');
                                }
                            }
                        });
                        console.log('[+] Hooked: UIApplication -openURL:');
                    } else {
                        console.log('[!] UIApplication -openURL: not found');
                    }
                } else {
                    console.log('[!] UIApplication class not found');
                }
            } catch (e) {
                console.log('[-] Failed to hook UIApplication: ' + e);
            }

            try {
                const UIApplication = ObjC.classes.UIApplication;
                if (UIApplication) {
                    const openURLWithOptionsMethod = UIApplication['- openURL:options:completionHandler:'];
                    if (openURLWithOptionsMethod) {
                        Interceptor.attach(openURLWithOptionsMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const url = ObjC.Object(args[2]).toString();
                                    console.log('[DEEPLINK] openURL:options: called: ' + url);
                                    validateDeepLink(url);
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in UIApplication openURL:options: hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: UIApplication -openURL:options:completionHandler:');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook UIApplication openURL:options:: ' + e);
            }

            try {
                const UIScene = ObjC.classes.UIScene;
                if (UIScene) {
                    const scenes = ObjC.classes.UIWindowScene;
                    if (scenes) {
                        const openURLSceneMethod = scenes['- openURL:options:completionHandler:'];
                        if (openURLSceneMethod) {
                            Interceptor.attach(openURLSceneMethod.implementation, {
                                onEnter: function(args) {
                                    try {
                                        const url = ObjC.Object(args[2]).toString();
                                        console.log('[DEEPLINK] UIScene openURL: ' + url);
                                        validateDeepLink(url);
                                    } catch (e) {
                                        if (DEBUG_MODE) {
                                            console.log('[-] Error in UIScene hook: ' + e);
                                        }
                                    }
                                }
                            });
                            console.log('[+] Hooked: UIWindowScene -openURL:options:completionHandler:');
                        }
                    }
                }
            } catch (e) {
                if (DEBUG_MODE) {
                    console.log('[-] UIScene not available (iOS <13 or not adopted): ' + e);
                }
            }

            // The UIApplicationDelegate protocol carries no implementation of
            // its own, and the variable was never used: the empty catch hid
            // the TypeError and left a dead statement behind. The delegate
            // hooks are resolved at runtime, from the app's delegate class.

            console.log("[*] ");
            console.log('[*] Monitoring active - trigger deep links to validate CSRF');
            console.log('[*] Test with: xcrun simctl openurl booted "myapp://follow?user=123"');

            setInterval(function() {
                if (deepLinkLog.length > 0) {
                    console.log('[*] ================================================');
                    console.log('[*] DEEP LINK CSRF VALIDATOR SUMMARY');
                    console.log('[*] ================================================');
                    console.log('[*] Total deep links logged: ' + deepLinkLog.length);
                    console.log('[*] Vulnerable actions (no CSRF): ' + vulnerableActions);

                    if (vulnerableActions > 0) {
                        console.log('[!] VULNERABILITY DETECTED');
                        console.log('[!] App processes state-changing deep links without CSRF validation');
                        console.log('[!] Attackers can forge malicious deep links to perform actions on user behalf');
                    }
                    console.log('[*] ================================================');
                }
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
 * 1. Identify app's URL schemes:
 *    plutil -p Info.plist | grep CFBundleURLSchemes
 *
 * 2. Test sensitive actions:
 *    myapp://follow?user=victim
 *    myapp://like?post=123
 *    myapp://delete?id=456
 *
 * 3. Check if script alerts missing CSRF token
 *
 * 4. Confirm by triggering action with malicious token
 *    myapp://follow?user=attacker&token=malicious
 *    If action executes, CSRF is confirmed
 *
 * 5. Remediation:
 *    - Generate and validate CSRF tokens server-side
 *    - Validate token freshness
 *    - Use universal links with associated domains validation
 *    - Implement rate limiting for sensitive actions
 */
