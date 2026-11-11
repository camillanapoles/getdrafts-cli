/**
 * URL SCHEME MONITOR - iOS [STABLE]
 *
 * Purpose: Monitor URL scheme opens and deep links in iOS applications
 * Usage: frida -U -f <BUNDLE_ID> -l url-scheme-monitor.js
 *        or
 *        frida -U <BUNDLE_ID> -l url-scheme-monitor.js
 *
 * What it hooks:
 * - UIApplication.openURL:options:completionHandler: (URL opens)
 * - UIApplicationDelegate.application:openURL:options: (incoming deep links)
 * - UIApplicationDelegate.application:continueUserActivity:restorationHandler: (Universal Links)
 * - UIApplication.sharedApplication.openURL (legacy URL opens)
 *
 * What it logs:
 * - URL scheme (e.g., myapp://, https://, file://)
 * - Host and path components
 * - Query parameters
 * - Source application (who opened the URL)
 * - Opening options
 * - Universal Links activity type
 *
 * Features:
 * - Filter schemes to reduce noise
 * - Detect sensitive data in URLs
 * - Track source applications
 * - Parse URL components
 * - Handle both iOS 13+ and legacy methods
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0151: Test Deep Links
 * - MASTG-TEST-0152: Test Universal Links
 * - MASTG-APP-003: Deep Link Security
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] URL SCHEME MONITOR - iOS STARTED");
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
            'calshow'
        ],

        // Detect sensitive patterns in URLs
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /session/i,
            /auth/i,
            /credential/i,
            /ssn/i,
            /pin/i
        ],

        // Log URL bodies/content
        logBodies: false,

        // Maximum URL length to display
        maxUrlLength: 500,

        // Show source app
        showSourceApp: true,

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
            sensitive: "\x1b[35m"   // Magenta
        }
    };

    var hooksApplied = 0;
    var urlCount = 0;
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

    function logSensitive(message) {
        console.log(CONFIG.colors.sensitive + CONFIG.colors.bright + "[!]\x1b[0m SENSITIVE " + CONFIG.colors.reset + message);
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
            fragment: ""
        };

        try {
            var urlObj = ObjC.classes.NSURL.URLWithString_(urlStr);

            if (urlObj && !urlObj.isNil()) {
                var _scheme = urlObj.scheme(); components.scheme = (_scheme && !_scheme.isNil()) ? _scheme.toString() : "";
                var _host   = urlObj.host();   components.host   = (_host   && !_host.isNil())   ? _host.toString()   : "";
                var _path   = urlObj.path();   components.path   = (_path   && !_path.isNil())   ? _path.toString()   : "";
                var _query  = urlObj.query();  components.query  = (_query  && !_query.isNil())  ? _query.toString()  : "";
                var _frag   = urlObj.fragment(); components.fragment = (_frag && !_frag.isNil()) ? _frag.toString()   : "";
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

    function detectSensitiveData(urlStr) {
        for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
            if (CONFIG.sensitivePatterns[i].test(urlStr)) {
                return true;
            }
        }
        return false;
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
            lines.push("    Scheme: " + components.scheme);
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
    try {
        var UIApplication = ObjC.classes.UIApplication;

        // The UIApplicationDelegate protocol carries no implementation of its
        // own: the real IMP lives in the app's delegate class, so it has to be
        // resolved at runtime.
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

        if (UIApplication) {
            sharedApplication = UIApplication.sharedApplication();

            if (sharedApplication) {
                var originalOpenURL = sharedApplication['- openURL:options:completionHandler:'];

                if (originalOpenURL) {
                    // -openURL:options:completionHandler: returns BOOL.
                    const originalImpl = new NativeFunction(originalOpenURL.implementation, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, url, options, completionHandler) {
                        if (!url || url.isNull()) return originalImpl(self, sel, url, options, completionHandler);
                        const urlStr = new ObjC.Object(url).absoluteString().toString();

                        if (shouldMonitorUrl(urlStr)) {
                            urlCount++;

                            const components = parseUrlComponents(urlStr);
                            const isSensitive = detectSensitiveData(urlStr);

                            console.log("");
                            if (isSensitive) {
                                logSensitive("URL #" + urlCount + " - Opened");
                            } else {
                                logSuccess("URL #" + urlCount + " - Opened");
                            }

                            console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                            console.log(formatUrlLog(urlStr, components));

                            if (options) {
                                try {
                                    const optionsObj = new ObjC.Object(options);
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
                if (!url || url.isNull()) return originalImpl(self, sel, application, url, options);
                const urlStr = new ObjC.Object(url).absoluteString().toString();

                if (shouldMonitorUrl(urlStr)) {
                    urlCount++;

                    const components = parseUrlComponents(urlStr);
                    const isSensitive = detectSensitiveData(urlStr);

                    console.log("");
                    if (isSensitive) {
                        logSensitive("URL #" + urlCount + " - Incoming Deep Link");
                    } else {
                        logSuccess("URL #" + urlCount + " - Incoming Deep Link");
                    }

                    console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                    console.log(formatUrlLog(urlStr, components));

                    // Try to get source app from options
                    if (options && CONFIG.showSourceApp) {
                        try {
                            const optionsObj = new ObjC.Object(options);
                            const sourceAppKey = ObjC.classes.NSString.stringWithString_('UIApplicationOpenURLOptionsSourceApplicationKey');
                            const sourceApp = optionsObj.objectForKey_(sourceAppKey);

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
                    const activityObj = new ObjC.Object(userActivity);
                    const activityType = activityObj.activityType().toString();
                    const webpageURL = activityObj.webpageURL();

                    if (webpageURL) {
                        const urlStr = webpageURL.absoluteString().toString();

                        if (shouldMonitorUrl(urlStr)) {
                            urlCount++;

                            const components = parseUrlComponents(urlStr);
                            const isSensitive = detectSensitiveData(urlStr);

                            console.log("");
                            if (isSensitive) {
                                logSensitive("URL #" + urlCount + " - Universal Link");
                            } else {
                                logSuccess("URL #" + urlCount + " - Universal Link");
                            }

                            console.log("    Activity Type: " + activityType);
                            console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                            console.log(formatUrlLog(urlStr, components));
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
                    const urlStr = new ObjC.Object(url).absoluteString().toString();

                    if (shouldMonitorUrl(urlStr)) {
                        urlCount++;

                        const components = parseUrlComponents(urlStr);
                        const isSensitive = detectSensitiveData(urlStr);

                        console.log("");
                        if (isSensitive) {
                            logSensitive("URL #" + urlCount + " - Opened (Legacy)");
                        } else {
                            logSuccess("URL #" + urlCount + " - Opened (Legacy)");
                        }

                        console.log("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                        console.log(formatUrlLog(urlStr, components));
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
    console.log("[*] URL Scheme Monitor Ready");
    console.log("[*] ================================================");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
