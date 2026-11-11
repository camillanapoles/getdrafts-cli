/**
 * DEEP LINK SECURITY ANALYZER - iOS [STABLE]
 *
 * Purpose: Detect token exposure, OAuth interception, and authentication bypass patterns in deep links
 * Usage: frida -U -f <BUNDLE_ID> -l deeplink-security-analyzer.js
 *        or
 *        frida -U <BUNDLE_ID> -l deeplink-security-analyzer.js
 *
 * What it hooks:
 * - UIApplication.openURL:options:completionHandler: (URL opens)
 * - UIApplicationDelegate.application:openURL:options: (incoming deep links)
 * - UIApplicationDelegate.application:continueUserActivity:restorationHandler: (Universal Links)
 * - UIApplication.sharedApplication.openURL (legacy URL opens)
 *
 * What it detects:
 * - Token/secret exposure in URLs (Bearer tokens, API keys, session tokens)
 * - OAuth code interception (authorization_code, state parameter manipulation)
 * - Authentication bypass patterns (session restoration without auth)
 * - CSRF via deep links (action execution without consent)
 *
 * Features:
 * - Comprehensive pattern detection for sensitive data in URLs
 * - OAuth flow security analysis (PKCE detection, state validation)
 * - Authentication bypass detection
 * - CSRF vulnerability identification
 * - Detailed logging with severity levels (CRITICAL, HIGH, MEDIUM, LOW)
 * - Remediation recommendations
 * - URL component analysis
 * - Query parameter extraction and validation
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0151: Test Deep Links
 * - MASTG-TEST-0152: Test Universal Links
 * - MASTG-APP-003: Deep Link Security
 * - MASTG-AUTH-002: Authentication Testing
 * - MASTG-STORAGE-0013: Insecure Data Storage
 *
 * CVSS 4.0 Scoring:
 * - Token exposure: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CRITICAL)
 * - OAuth code interception: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (HIGH)
 * - Auth bypass: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CRITICAL)
 * - CSRF via deep link: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N (HIGH)
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] DEEP LINK SECURITY ANALYZER - iOS STARTED");
    console.log("[*] ================================================");

    var CONFIG = {
        // Schemes to monitor (empty = all)
        filterSchemes: [],

        // Schemes to ignore (reduce noise)
        ignoreSchemes: [
            'prefs',
            'tel',
            'sms',
            'mailto',
            'facetime',
            'itms-apps',
            'itms',
            'calshow',
            'http',
            'https'
        ],

        // Token/Secret patterns - CRITICAL severity
        tokenPatterns: [
            /bearer\s+[a-zA-Z0-9\-._~+/]+/i,
            /token\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /access[_-]?token\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /api[_-]?key\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{16,}['"`]?/i,
            /secret\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{16,}['"`]?/i,
            /session[_-]?token\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /auth[_-]?token\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /credential\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{16,}['"`]?/i,
            /jwt\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}\./i
        ],

        // OAuth code patterns - HIGH severity
        oauthPatterns: [
            /code\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /authorization[_-]?code\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{20,}['"`]?/i,
            /state\s*[:=]\s*['"`]?[a-zA-Z0-9\-._~+/]{16,}['"`]?/i,
            /redirect[_-]?uri\s*[:=]\s*['"`]?(https?:\/\/[^\s'"]+)['"`]?/i
        ],

        // CSRF action patterns - HIGH severity
        csrfActionPatterns: [
            /action\s*[:=]\s*['"`]?(follow|like|purchase|delete|update|transfer|approve|reject)['"`]?/i,
            /command\s*[:=]\s*['"`]?(execute|run|perform|invoke)['"`]?/i
        ],

        // Authentication bypass patterns - CRITICAL severity
        authBypassPatterns: [
            /user\s*[:=]\s*['"`]?(admin|root|superuser)['"`]?/i,
            /login\s*[:=]\s*['"`]?true['"`]?/i,
            /authenticated\s*[:=]\s*['"`]?true['"`]?/i,
            /bypass\s*[:=]\s*['"`]?true['"`]?/i
        ],

        // Query parameters to check for sensitive data
        sensitiveParams: [
            'token',
            'access_token',
            'api_key',
            'secret',
            'password',
            'session',
            'auth',
            'credential',
            'code',
            'state',
            'authorization_code'
        ],

        // Maximum URL length to display
        maxUrlLength: 500,

        // Show query parameters
        showQueryParams: true,

        // Detect Universal Links
        monitorUniversalLinks: true,

        // Color codes
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue
            sensitive: "\x1b[35m",  // Magenta
            critical: "\x1b[91m",    // Bright Red
            high: "\x1b[93m"        // Bright Yellow
        }
    };

    var hooksApplied = 0;
    var urlCount = 0;
    var criticalCount = 0;
    var highCount = 0;
    var mediumCount = 0;
    var sharedApplication = null;

    function logSuccess(message) {
        console.log(CONFIG.colors.success + CONFIG.colors.bright + "[+]\x1b[0m " + message);
    }

    function logError(message) {
        console.log(CONFIG.colors.error + CONFIG.colors.bright + "[!]\x1b[0m " + message);
    }

    function logWarn(message) {
        console.log(CONFIG.colors.warn + CONFIG.colors.bright + "[*]\x1b[0m " + message);
    }

    function logInfo(message) {
        console.log(CONFIG.colors.info + CONFIG.colors.bright + "[i]\x1b[0m " + message);
    }

    function logCritical(message, cvss = "") {
        var prefix = "\x1b[91m[🔴 CRITICAL]\x1b[0m";
        if (cvss) prefix += " " + cvss;
        console.log(prefix + " " + message);
    }

    function logHigh(message, cvss = "") {
        var prefix = "\x1b[93m[🟠 HIGH]\x1b[0m";
        if (cvss) prefix += " " + cvss;
        console.log(prefix + " " + message);
    }

    function logMedium(message) {
        console.log("\x1b[33m[🟡 MEDIUM]\x1b[0m " + message);
    }

    function logLow(message) {
        console.log("\x1b[32m[🟢 LOW]\x1b[0m " + message);
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function parseUrlComponents(urlStr) {
        var components = {
            scheme: "",
            host: "",
            path: "",
            query: "",
            fragment: "",
            queryParams: {}
        };

        try {
            var urlObj = ObjC.classes.NSURL.URLWithString_(urlStr);

            if (urlObj) {
                components.scheme = urlObj.scheme().toString();
                components.host = urlObj.host().toString();
                components.path = urlObj.path().toString();
                components.query = urlObj.query().toString();
                components.fragment = urlObj.fragment().toString();

                // Parse query parameters
                if (components.query) {
                    var params = components.query.split('&');
                    for (var i = 0; i < params.length; i++) {
                        var param = params[i].split('=');
                        if (param.length === 2) {
                            components.queryParams[param[0]] = decodeURIComponent(param[1]);
                        }
                    }
                }
            }
        } catch (e) {
            // Parse manually if NSURL fails
            var match = urlStr.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/([^\/?#]*)([^\?#]*)(\?[^#]*)?(#.*)?$/);
            if (match) {
                components.scheme = match[1] || "";
                components.host = match[2] || "";
                components.path = match[3] || "";
                components.query = match[4] || "";
                components.fragment = match[5] || "";
            }
        }

        return components;
    }

    function detectTokenExposure(urlStr) {
        for (var i = 0; i < CONFIG.tokenPatterns.length; i++) {
            if (CONFIG.tokenPatterns[i].test(urlStr)) {
                var match = urlStr.match(CONFIG.tokenPatterns[i]);
                return {
                    found: true,
                    pattern: match ? match[0] : "Token pattern detected",
                    cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    recommendation: "Never pass tokens via deep links. Use PKCE for OAuth flows. Implement token binding. Use short-lived authorization codes instead."
                };
            }
        }

        // Check query parameters for sensitive param names
        var components = parseUrlComponents(urlStr);
        for (var param in components.queryParams) {
            for (var i = 0; i < CONFIG.sensitiveParams.length; i++) {
                if (param.toLowerCase() === CONFIG.sensitiveParams[i].toLowerCase() && components.queryParams[param].length > 10) {
                    return {
                        found: true,
                        pattern: param + " parameter with sensitive value",
                        cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                        recommendation: "Never pass sensitive data via URL parameters. Use secure storage (Keychain) and server-side validation."
                    };
                }
            }
        }

        return { found: false };
    }

    function detectOAuthCodeInterception(urlStr) {
        for (var i = 0; i < CONFIG.oauthPatterns.length; i++) {
            if (CONFIG.oauthPatterns[i].test(urlStr)) {
                var match = urlStr.match(CONFIG.oauthPatterns[i]);
                var param = match ? match[0].split('=')[0] : "OAuth parameter";
                return {
                    found: true,
                    pattern: match ? match[0] : "OAuth pattern detected",
                    cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    recommendation: "Implement PKCE (RFC 7636). Use universal links instead of custom schemes. Validate state parameter. Use short-lived codes (≤ 10 minutes)."
                };
            }
        }
        return { found: false };
    }

    function detectCSRFViaDeepLink(urlStr) {
        for (var i = 0; i < CONFIG.csrfActionPatterns.length; i++) {
            if (CONFIG.csrfActionPatterns[i].test(urlStr)) {
                var match = urlStr.match(CONFIG.csrfActionPatterns[i]);
                return {
                    found: true,
                    pattern: match ? match[0] : "CSRF action pattern detected",
                    cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N",
                    recommendation: "Require user confirmation for actions. Implement CSRF tokens. Use intent confirmation dialogs. Rate limit action endpoints."
                };
            }
        }
        return { found: false };
    }

    function detectAuthBypass(urlStr) {
        for (var i = 0; i < CONFIG.authBypassPatterns.length; i++) {
            if (CONFIG.authBypassPatterns[i].test(urlStr)) {
                var match = urlStr.match(CONFIG.authBypassPatterns[i]);
                return {
                    found: true,
                    pattern: match ? match[0] : "Auth bypass pattern detected",
                    cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    recommendation: "Check authentication status on ALL deep link handlers. Require re-authentication for sensitive actions. Invalidate session on background/foreground."
                };
            }
        }
        return { found: false };
    }

    function shouldMonitorUrl(urlStr) {
        // Check ignore list
        for (var i = 0; i < CONFIG.ignoreSchemes.length; i++) {
            if (urlStr.toLowerCase().startsWith(CONFIG.ignoreSchemes[i] + ':')) {
                return false;
            }
        }

        // Check filter list
        if (CONFIG.filterSchemes.length > 0) {
            for (var i = 0; i < CONFIG.filterSchemes.length; i++) {
                if (urlStr.toLowerCase().startsWith(CONFIG.filterSchemes[i].toLowerCase() + ':')) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    function formatUrlLog(urlStr, components) {
        var lines = [];

        if (components.scheme) {
            lines.push("    Scheme: " + CONFIG.colors.info + components.scheme + CONFIG.colors.reset);
        }

        if (components.host) {
            lines.push("    Host: " + CONFIG.colors.info + components.host + CONFIG.colors.reset);
        }

        if (components.path) {
            lines.push("    Path: " + components.path);
        }

        if (components.query && CONFIG.showQueryParams) {
            lines.push("    Query: " + components.query);
        }

        if (components.fragment) {
            lines.push("    Fragment: " + components.fragment);
        }

        return lines.join('\n');
    }

    function analyzeUrl(urlStr) {
        var findings = [];

        // Check for token exposure
        var tokenResult = detectTokenExposure(urlStr);
        if (tokenResult.found) {
            findings.push({
                severity: "CRITICAL",
                type: "Token Exposure",
                pattern: tokenResult.pattern,
                cvss: tokenResult.cvss,
                recommendation: tokenResult.recommendation
            });
            criticalCount++;
        }

        // Check for OAuth code interception
        var oauthResult = detectOAuthCodeInterception(urlStr);
        if (oauthResult.found && !tokenResult.found) {
            findings.push({
                severity: "HIGH",
                type: "OAuth Code Interception",
                pattern: oauthResult.pattern,
                cvss: oauthResult.cvss,
                recommendation: oauthResult.recommendation
            });
            highCount++;
        }

        // Check for authentication bypass
        var authResult = detectAuthBypass(urlStr);
        if (authResult.found && !tokenResult.found) {
            findings.push({
                severity: "CRITICAL",
                type: "Authentication Bypass",
                pattern: authResult.pattern,
                cvss: authResult.cvss,
                recommendation: authResult.recommendation
            });
            criticalCount++;
        }

        // Check for CSRF via deep link
        var csrfResult = detectCSRFViaDeepLink(urlStr);
        if (csrfResult.found && !tokenResult.found && !oauthResult.found && !authResult.found) {
            findings.push({
                severity: "HIGH",
                type: "CSRF via Deep Link",
                pattern: csrfResult.pattern,
                cvss: csrfResult.cvss,
                recommendation: csrfResult.recommendation
            });
            highCount++;
        }

        return findings;
    }

    function printFindings(urlStr, components, findings) {
        if (findings.length === 0) {
            logLow("URL #" + urlCount + " - No security issues detected");
            console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
            console.log(formatUrlLog(urlStr, components));
            return;
        }

        findings.forEach(function(finding) {
            if (finding.severity === "CRITICAL") {
                logCritical(finding.type + " detected", finding.cvss);
            } else if (finding.severity === "HIGH") {
                logHigh(finding.type + " detected", finding.cvss);
            } else {
                logMedium(finding.type + " detected");
            }

            console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
            console.log(formatUrlLog(urlStr, components));
            console.log("    Pattern: " + finding.pattern);
            console.log(CONFIG.colors.warn + "    Remediation: " + CONFIG.colors.reset + finding.recommendation);
        });
    }

    try {
        var UIApplication = ObjC.classes.UIApplication;

        if (UIApplication) {
            sharedApplication = UIApplication.sharedApplication();

            // The UIApplicationDelegate protocol carries no implementation of
            // its own: the real IMP lives in the app's delegate class, so it
            // has to be resolved at runtime.
            function resolveDelegateMethod(selector) {
                try {
                    var app = UIApplication.sharedApplication();
                    // The bridge returns a METHOD WRAPPER for any selector, so the
                    // delegate has to be invoked to get the object: reading
                    // `app.delegate` yields a function whose $className is
                    // undefined, and the hook would never be installed.
                    var delegate = app ? app.delegate() : null;
                    if (!delegate) return null;
                    var delegateClass = ObjC.classes[delegate.$className];
                    if (!delegateClass) return null;
                    return delegateClass[selector] || null;
                } catch (e) {
                    return null;
                }
            }

            if (sharedApplication) {
                var originalOpenURL = sharedApplication['- openURL:options:completionHandler:'];

                if (originalOpenURL) {
                    // -openURL:options:completionHandler: returns BOOL.
                    const originalImpl = new NativeFunction(originalOpenURL.implementation, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, url, options, completionHandler) {
                        var urlStr = new ObjC.Object(url).absoluteString().toString();

                        if (shouldMonitorUrl(urlStr)) {
                            urlCount++;

                            var components = parseUrlComponents(urlStr);
                            var findings = analyzeUrl(urlStr);

                            console.log("");
                            printFindings(urlStr, components, findings);

                            if (options) {
                                try {
                                    var optionsObj = new ObjC.Object(options);
                                    logInfo("    Options: " + optionsObj.toString());
                                } catch (e) {
                                    // Options parsing failed
                                }
                            }
                        }

                        return originalImpl(self, sel, url, options, completionHandler);
                    }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalOpenURL.implementation, bypassCallback);

                    hooksApplied++;
                    logSuccess("UIApplication.openURL:options:completionHandler: hooked");
                }
            }
        }
    } catch (e) {
        logError("UIApplication.openURL:options:completionHandler: hook failed: " + e.message);
    }

    try {
        var originalAppOpenURL = resolveDelegateMethod('- application:openURL:options:');

        if (originalAppOpenURL) {
            const originalImpl = new NativeFunction(originalAppOpenURL.implementation, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

            const bypassCallback = new NativeCallback(function(self, sel, application, url, options) {
                var urlStr = new ObjC.Object(url).absoluteString().toString();

                if (shouldMonitorUrl(urlStr)) {
                    urlCount++;

                    var components = parseUrlComponents(urlStr);
                    var findings = analyzeUrl(urlStr);

                    console.log("");
                    logInfo("Incoming Deep Link");
                    printFindings(urlStr, components, findings);

                    // Try to get source app from options
                    if (options) {
                        try {
                            var optionsObj = new ObjC.Object(options);
                            var sourceAppKey = ObjC.classes.NSString.stringWithString_('UIApplicationOpenURLOptionsSourceApplicationKey');
                            var sourceApp = optionsObj.objectForKey_(sourceAppKey);

                            if (sourceApp) {
                                logInfo("    Source App: " + sourceApp.toString());
                            }
                        } catch (e) {
                            // Source app parsing failed
                        }
                    }
                }

                return originalImpl(self, sel, application, url, options);
            }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

            Interceptor.replace(originalAppOpenURL.implementation, bypassCallback);

            hooksApplied++;
            logSuccess("UIApplicationDelegate.application:openURL:options: hooked");
        }
    } catch (e) {
        logError("UIApplicationDelegate.application:openURL:options: hook failed: " + e.message);
    }

    try {
        if (CONFIG.monitorUniversalLinks) {
            var originalContinueUserActivity = resolveDelegateMethod('- application:continueUserActivity:restorationHandler:');

            if (originalContinueUserActivity) {
                const originalImpl = new NativeFunction(originalContinueUserActivity.implementation, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, application, userActivity, restorationHandler) {
                    var activityObj = new ObjC.Object(userActivity);
                    var activityType = activityObj.activityType().toString();
                    var webpageURL = activityObj.webpageURL();

                    if (webpageURL) {
                        var urlStr = webpageURL.absoluteString().toString();

                        if (shouldMonitorUrl(urlStr)) {
                            urlCount++;

                            var components = parseUrlComponents(urlStr);
                            var findings = analyzeUrl(urlStr);

                            console.log("");
                            logInfo("Universal Link (Activity: " + activityType + ")");
                            printFindings(urlStr, components, findings);
                        }
                    }

                    return originalImpl(self, sel, application, userActivity, restorationHandler);
                }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalContinueUserActivity.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIApplicationDelegate.application:continueUserActivity:restorationHandler: hooked");
            }
        }
    } catch (e) {
        logError("UIApplicationDelegate.application:continueUserActivity:restorationHandler: hook failed: " + e.message);
    }

    try {
        if (sharedApplication) {
            var legacyOpenURL = sharedApplication['- openURL:'];

            if (legacyOpenURL) {
                const originalImpl = new NativeFunction(legacyOpenURL.implementation, 'bool', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, url) {
                    var urlStr = new ObjC.Object(url).absoluteString().toString();

                    if (shouldMonitorUrl(urlStr)) {
                        urlCount++;

                        var components = parseUrlComponents(urlStr);
                        var findings = analyzeUrl(urlStr);

                        console.log("");
                        logInfo("Opened (Legacy)");
                        printFindings(urlStr, components, findings);
                    }

                    return originalImpl(self, sel, url);
                }, 'bool', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(legacyOpenURL.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("UIApplication.sharedApplication.openURL (legacy) hooked");
            }
        }
    } catch (e) {
        logError("UIApplication.sharedApplication.openURL (legacy) hook failed: " + e.message);
    }

    console.log("[*] ================================================");
    console.log("[*] Total hooks applied: " + hooksApplied);
    console.log("[*] Deep Link Security Analyzer Ready");
    console.log("[*] ================================================");

    // Print security statistics on exit
    function printSecuritySummary() {
        if (urlCount > 0) {
            console.log("");
            console.log("[*] ================================================");
            console.log("[*] SECURITY ANALYSIS SUMMARY");
            console.log("[*] ================================================");
            console.log("[*] URLs analyzed: " + urlCount);
            if (criticalCount > 0) {
                console.log(CONFIG.colors.critical + "[!] CRITICAL findings: " + criticalCount + CONFIG.colors.reset);
            }
            if (highCount > 0) {
                console.log(CONFIG.colors.high + "[!] HIGH findings: " + highCount + CONFIG.colors.reset);
            }
            if (mediumCount > 0) {
                console.log(CONFIG.colors.warn + "[!] MEDIUM findings: " + mediumCount + CONFIG.colors.reset);
            }
            console.log("[*] ================================================");
        }
    }

    if (typeof Script !== 'undefined' && Script.events) {
        Script.events.listen('destroy', function() {
            printSecuritySummary();
        });
    }

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
