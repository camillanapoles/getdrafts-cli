/**
 * WEBVIEW XSS SCANNER - iOS
 *
 * Frida script to detect unsanitized HTML loading in WebViews,
 * which can lead to Cross-Site Scripting vulnerabilities.
 *
 * Based on real vulnerabilities:
 * - H1-575562: Nextcloud iOS - Blind XSS via unsanitized file content
 * - H1-991713: Brave iOS - HTML injection in reader mode title
 * - H1-993670: Brave iOS - Universal XSS through FIDO U2F
 * - H1-1436558: Brave iOS - Universal XSS with Playlist feature
 * - H1-1438028: Brave iOS - XSS on internal: privileged origin
 *
 * Usage: frida -U -f <BUNDLE_ID> -l webview-xss-scanner-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l webview-xss-scanner-ios.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0075: Test WebViews for Local Storage Access
 * - MASTG-TEST-0078: Test WebViews for JavaScript Injection
 * - MASVS-CLIENT: WebViews and Hybrid Apps
 */

const DEBUG_MODE = true;

const USER_INPUT_PATTERNS = [
    '{{',
    '${',
    '<%= ',
    '<%',
    'username',
    '{{user}}',
    '${user}',
    '{{email}}',
    '${email}'
];

const XSS_PATTERNS = [
    '<script>',
    'javascript:',
    'onerror=',
    'onload=',
    'onclick=',
    '<img src=x',
    '<body onload',
    'eval(',
    'innerHTML'
];

let unsanitizedLoadCount = 0;
let totalLoads = 0;

function containsDangerousPatterns(htmlString) {
    const lowerHtml = htmlString.toLowerCase();

    for (const pattern of USER_INPUT_PATTERNS) {
        if (htmlString.includes(pattern)) {
            return { found: true, pattern: pattern, type: 'template' };
        }
    }

    for (const pattern of XSS_PATTERNS) {
        if (lowerHtml.includes(pattern.toLowerCase())) {
            return { found: true, pattern: pattern, type: 'xss' };
        }
    }

    if (htmlString.includes('<script') && htmlString.includes('http')) {
        return { found: true, pattern: '<script> with remote URL', type: 'remote_script' };
    }

    return { found: false };
}

function analyzeHTML(htmlString, baseURL) {
    totalLoads++;

    if (htmlString.length > 10000) {
        if (DEBUG_MODE) {
            console.log('[INFO] Large HTML load (' + htmlString.length + ' chars) - skipping deep analysis');
        }
        return;
    }

    const result = containsDangerousPatterns(htmlString);

    if (result.found) {
        unsanitizedLoadCount++;
        console.log('[VULN] Unsabized HTML loading detected in WebView');
        console.log('       Pattern: ' + result.pattern);
        console.log('       Type: ' + result.type);
        console.log('       HTML length: ' + htmlString.length + ' chars');
        console.log('       Base URL: ' + baseURL);
        console.log('       Impact: XSS possible if attacker controls HTML source');
        console.log('       Reference: H1-575562 (Nextcloud WebView XSS)');

        if (result.type === 'template') {
            console.log('[INFO] Template injection detected - if template data is user-controlled, XSS is trivial');
        }
    }
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] WEBVIEW XSS SCANNER - iOS STARTED");
            console.log("[*] ================================================");
            console.log("[*] Monitoring for unsanitized HTML loading in WebViews");
            console.log("[*] ");

            try {
                const WKWebView = ObjC.classes.WKWebView;
                if (WKWebView) {
                    const loadHTMLMethod = WKWebView['- loadHTMLString:baseURL:'];
                    if (loadHTMLMethod) {
                        Interceptor.attach(loadHTMLMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const htmlString = ObjC.Object(args[2]).toString();
                                    const baseURL = args[3] ? ObjC.Object(args[3]).toString() : 'about:blank';

                                    analyzeHTML(htmlString, baseURL);
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in WKWebView hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: WKWebView -loadHTMLString:baseURL:');
                    } else {
                        console.log('[!] WKWebView -loadHTMLString:baseURL: not found');
                    }
                } else {
                    console.log('[!] WKWebView class not found');
                }
            } catch (e) {
                console.log('[-] Failed to hook WKWebView: ' + e);
            }

            try {
                const UIWebView = ObjC.classes.UIWebView;
                if (UIWebView) {
                    const loadHTMLMethod = UIWebView['- loadHTMLString:baseURL:'];
                    if (loadHTMLMethod) {
                        Interceptor.attach(loadHTMLMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const htmlString = ObjC.Object(args[2]).toString();
                                    const baseURL = args[3] ? ObjC.Object(args[3]).toString() : 'about:blank';

                                    console.log('[LEGACY] UIWebView loading HTML (deprecated, more vulnerable)');
                                    analyzeHTML(htmlString, baseURL);
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in UIWebView hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: UIWebView -loadHTMLString:baseURL: (legacy)');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook UIWebView: ' + e);
            }

            try {
                const WKWebView = ObjC.classes.WKWebView;
                if (WKWebView) {
                    const loadRequestMethod = WKWebView['- loadRequest:'];
                    if (loadRequestMethod) {
                        Interceptor.attach(loadRequestMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    const request = ObjC.Object(args[2]);
                                    const url = request.URL().absoluteString().toString();

                                    if (url.startsWith('file://') && (url.includes('.html') || url.includes('.htm'))) {
                                        console.log('[INFO] Loading file:// URL in WebView: ' + url);
                                        console.log('       If file content is user-controlled, test for XSS with HTML injection');
                                    }
                                } catch (e) {
                                    if (DEBUG_MODE) {
                                        console.log('[-] Error in WKWebView loadRequest hook: ' + e);
                                    }
                                }
                            }
                        });
                        console.log('[+] Hooked: WKWebView -loadRequest:');
                    }
                }
            } catch (e) {
                console.log('[-] Failed to hook WKWebView loadRequest: ' + e);
            }

            console.log("[*] ");
            console.log('[*] Monitoring active - load HTML in WebView to trigger detection');
            console.log('[*] Test with: <script>alert(document.domain)</script>');

            setInterval(function() {
                if (totalLoads > 0) {
                    console.log('[*] ================================================');
                    console.log('[*] WEBVIEW XSS SCANNER SUMMARY');
                    console.log('[*] ================================================');
                    console.log('[*] Total HTML loads: ' + totalLoads);
                    console.log('[*] Unsabized loads: ' + unsanitizedLoadCount);

                    if (unsanitizedLoadCount > 0) {
                        console.log('[!] VULNERABILITY DETECTED');
                        console.log('[!] App loads HTML without proper sanitization');
                        console.log('[!] Test with XSS payloads in user input fields');
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
 * XSS Testing Payloads (manual testing reference)
 *
 * Basic XSS:
 * <script>alert(1)</script>
 * <img src=x onerror=alert(1)>
 * <body onload=alert(1)>
 *
 * Template Injection:
 * {{7*7}}
 * ${7*7}
 * <%= 7*7 %>
 *
 * Context-Aware:
 * "><script>alert(1)</script>
 * ' onerror=alert(1) '
 * javascript:alert(1)
 */
