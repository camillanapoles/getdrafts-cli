/**
 * WEBVIEW INTERCEPTOR - iOS [STABLE]
 *
 * Purpose: Intercept and monitor WKWebView and UIWebView traffic in iOS apps
 * Usage: frida -U -f <BUNDLE_ID> -l uiwebview-interceptor.js
 *        or
 *        frida -U <BUNDLE_ID> -l uiwebview-interceptor.js
 *
 * What it hooks:
 * - WKWebView.loadRequest: (URL navigation)
 * - WKWebView.loadHTMLString:baseURL: (HTML content loading)
 * - WKWebView.evaluateJavaScript:completionHandler: (JS execution)
 * - WKUserContentController.addScriptMessageHandler:name: (message handler registration)
 * - WKWebView.setCustomUserAgent: (User-Agent changes)
 * - WKWebView.loadFileURL:allowingReadAccessToURL: (file loading)
 *
 * What it logs:
 * - Request URLs and methods
 * - HTML content (truncated)
 * - JavaScript code being executed
 * - Message handler registrations
 * - User-Agent changes
 * - Dangerous URL schemes (file://, javascript:, data:)
 *
 * Features:
 * - Detect dangerous URL schemes
 * - Detect XSS injection attempts
 * - Detect insecure data loading
 * - Track message handler registrations
 * - Monitor JavaScript execution
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0075: Test WebViews
 * - MASTG-APP-007: WebView Security
 * - MASVS-STORAGE: Storage Security
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] WEBVIEW INTERCEPTOR - iOS STARTED");
    console.log("[*] ================================================");
    var CONFIG = {
        // Log request/response bodies
        logBodies: true,

        // Maximum body length to log
        maxBodyLength: 500,

        // Detect and alert on dangerous patterns
        detectDangerous: true,

        // Dangerous patterns to detect
        dangerousPatterns: [
            /^file:\/\/.*$/i,
            /^javascript:/i,
            /^data:.*$/i,
            /<script/i,
            /eval\s*\(/i,
            /document\.write/i,
            /innerHTML\s*=/i
        ],

        // XSS patterns
        xssPatterns: [
            /<script.*?>.*?<\/script>/gi,
            /javascript:/gi,
            /onerror\s*=/gi,
            /onload\s*=/gi,
            /fromCharCode/gi
        ],

        // Detect sensitive data in HTML/JS
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /session/i,
            /credential/i,
            /ssn/i,
            /pin/i
        ],

        // Filter URLs (empty = all)
        filterUrls: [],

        // Log User-Agent changes
        logUserAgentChanges: true,

        // Log message handler registrations
        logMessageHandlers: true,

        // Color codes
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue
            sensitive: "\x1b[35m",   // Magenta
            dangerous: "\x1b[31m"   // Red
        }
    };

    var hooksApplied = 0;
    var requestCount = 0;
    var jsExecutionCount = 0;
    var messageHandlerCount = 0;
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

    function logDangerous(message) {
        console.log(CONFIG.colors.dangerous + CONFIG.colors.bright + "[!] DANGER " + CONFIG.colors.reset + message);
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    function detectDangerousUrl(urlStr) {
        for (var i = 0; i < CONFIG.dangerousPatterns.length; i++) {
            if (CONFIG.dangerousPatterns[i].test(urlStr)) {
                return true;
            }
        }
        return false;
    }

    function detectXss(content) {
        for (var i = 0; i < CONFIG.xssPatterns.length; i++) {
            if (CONFIG.xssPatterns[i].test(content)) {
                return true;
            }
        }
        return false;
    }

    function detectSensitiveData(content) {
        for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
            if (CONFIG.sensitivePatterns[i].test(content)) {
                return true;
            }
        }
        return false;
    }

    function formatUrl(urlStr) {
        if (!urlStr) return "";
        var isDangerous = detectDangerousUrl(urlStr);

        if (isDangerous && CONFIG.detectDangerous) {
            return CONFIG.colors.dangerous + truncated + CONFIG.colors.reset;
        } else {
            return truncated;
        }
    }

    // ========================================
    // HOOK 1: WKWebView.loadRequest:
    // ========================================
    try {
        var WKWebView = ObjC.classes.WKWebView;

        if (WKWebView) {
            var originalLoadRequest = WKWebView['- loadRequest:'];

            if (originalLoadRequest) {
                const originalImpl = new NativeFunction(originalLoadRequest.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request) {
                    requestCount++;

                    const requestObj = new ObjC.Object(request);
                    const url = requestObj.URL();
                    if (!url || url.isNull()) return originalImpl(self, sel, request);
                    const urlStr = url.absoluteString().toString();
                    const method = requestObj.HTTPMethod().toString();

                    console.log("");
                    logSuccess("Request #" + requestCount + " - loadRequest:");
                    logInfo("    Method: " + method);
                    logInfo("    URL: " + formatUrl(urlStr));

                    const isDangerous = detectDangerousUrl(urlStr);
                    if (isDangerous && CONFIG.detectDangerous) {
                        logDangerous("    Detected dangerous URL scheme!");
                    }

                    if (CONFIG.logBodies) {
                        const body = requestObj.HTTPBody();
                        if (body) {
                            const bodyLength = body.length();
                            logInfo("    Body: <" + bodyLength + " bytes>");
                        }
                    }

                    return originalImpl(self, sel, request);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalLoadRequest.implementation, bypassCallback);
                hooksApplied++;
                logSuccess("WKWebView.loadRequest: hooked");
            }
        }
    } catch (e) {
        logError("WKWebView.loadRequest: hook failed: " + e.message);
    }
    try {
        if (WKWebView) {
            var originalLoadHTMLString = WKWebView['- loadHTMLString:baseURL:'];

            if (originalLoadHTMLString) {
                const originalImpl = new NativeFunction(originalLoadHTMLString.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, htmlString, baseURL) {
                    requestCount++;

                    if (!htmlString || htmlString.isNull()) return originalImpl(self, sel, htmlString, baseURL);
                    const htmlObj = new ObjC.Object(htmlString);
                    const htmlContent = htmlObj.toString();

                    console.log("");
                    logSuccess("Request #" + requestCount + " - loadHTMLString:baseURL:");

                    let baseStr = "";
                    if (baseURL && !baseURL.isNull()) {
                        const baseObj = new ObjC.Object(baseURL);
                        baseStr = baseObj.absoluteString().toString();
                    }

                    if (baseStr) {
                        logInfo("    Base URL: " + formatUrl(baseStr));
                    }

                    if (CONFIG.logBodies) {
                        const htmlTruncated = truncate(htmlContent, CONFIG.maxBodyLength);
                        logInfo("    HTML: " + htmlTruncated);

                        const hasXss = detectXss(htmlContent);
                        if (hasXss && CONFIG.detectDangerous) {
                            logDangerous("    Potential XSS injection detected!");
                        }

                        const hasSensitive = detectSensitiveData(htmlContent);
                        if (hasSensitive) {
                            logSensitive("    Sensitive data detected in HTML!");
                        }
                    }

                    return originalImpl(self, sel, htmlString, baseURL);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalLoadHTMLString.implementation, bypassCallback);
                hooksApplied++;
                logSuccess("WKWebView.loadHTMLString:baseURL: hooked");
            }
        }
    } catch (e) {
        logError("WKWebView.loadHTMLString:baseURL: hook failed: " + e.message);
    }
    try {
        if (WKWebView) {
            var originalEvaluateJS = WKWebView['- evaluateJavaScript:completionHandler:'];

            if (originalEvaluateJS) {
                const originalImpl = new NativeFunction(originalEvaluateJS.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, javaScriptString, completionHandler) {
                    jsExecutionCount++;

                    if (!javaScriptString || ptr(javaScriptString).isNull()) return originalImpl(self, sel, javaScriptString, completionHandler);
                    const jsObj = new ObjC.Object(javaScriptString);
                    const jsCode = jsObj.toString();

                    console.log("");
                    logSuccess("JS Execution #" + jsExecutionCount + " - evaluateJavaScript:");

                    if (CONFIG.logBodies) {
                        const jsTruncated = truncate(jsCode, CONFIG.maxBodyLength);
                        logInfo("    Code: " + jsTruncated);

                        const hasEval = /eval\s*\(/i.test(jsCode) || /Function\s*\(/i.test(jsCode);
                        if (hasEval && CONFIG.detectDangerous) {
                            logDangerous("    Dynamic code execution (eval/Function) detected!");
                        }

                        const hasSensitive = detectSensitiveData(jsCode);
                        if (hasSensitive) {
                            logSensitive("    Sensitive data detected in JS!");
                        }
                    }

                    return originalImpl(self, sel, javaScriptString, completionHandler);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalEvaluateJS.implementation, bypassCallback);
                hooksApplied++;
                logSuccess("WKWebView.evaluateJavaScript:completionHandler: hooked");
            }
        }
    } catch (e) {
        logError("WKWebView.evaluateJavaScript:completionHandler: hook failed: " + e.message);
    }
    try {
        var WKUserContentController = ObjC.classes.WKUserContentController;

        if (WKUserContentController) {
            var originalAddHandler = WKUserContentController['- addScriptMessageHandler:name:'];

            if (originalAddHandler) {
                const originalImpl = new NativeFunction(originalAddHandler.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, scriptMessageHandler, name) {
                    messageHandlerCount++;

                    const nameObj = new ObjC.Object(name);
                    const handlerName = nameObj.toString();

                    const handlerObj = new ObjC.Object(scriptMessageHandler);
                    const handlerClass = handlerObj.$className;

                    console.log("");
                    logSuccess("Message Handler #" + messageHandlerCount + " - addScriptMessageHandler:name:");
                    logInfo("    Name: " + handlerName);
                    logInfo("    Handler Class: " + handlerClass);

                    // Check for common handler names
                    const commonHandlers = [
                        'messageHandler',
                        'postMessage',
                        'sendMessage',
                        'callback',
                        'native',
                        'ios'
                    ];

                    for (let i = 0; i < commonHandlers.length; i++) {
                        if (handlerName.toLowerCase().includes(commonHandlers[i])) {
                            logWarn("    Common handler name detected: " + commonHandlers[i]);
                            break;
                        }
                    }

                    return originalImpl(self, sel, scriptMessageHandler, name);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalAddHandler.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("WKUserContentController.addScriptMessageHandler:name: hooked");
            }
        }
    } catch (e) {
        logError("WKUserContentController.addScriptMessageHandler:name: hook failed: " + e.message);
    }
    try {
        if (WKWebView && CONFIG.logUserAgentChanges) {
            var originalSetUserAgent = WKWebView['- setCustomUserAgent:'];

            if (originalSetUserAgent) {
                const originalImpl = new NativeFunction(originalSetUserAgent.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, userAgentString) {
                    if (!userAgentString || ptr(userAgentString).isNull()) return originalImpl(self, sel, userAgentString);
                    const uaObj = new ObjC.Object(userAgentString);
                    const userAgent = uaObj.toString();

                    console.log("");
                    logSuccess("User-Agent Change - setCustomUserAgent:");
                    logInfo("    User-Agent: " + truncate(userAgent, CONFIG.maxBodyLength));

                    return originalImpl(self, sel, userAgentString);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetUserAgent.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("WKWebView.setCustomUserAgent: hooked");
            }
        }
    } catch (e) {
        logError("WKWebView.setCustomUserAgent: hook failed: " + e.message);
    }
    try {
        if (WKWebView) {
            var originalLoadFileURL = WKWebView['- loadFileURL:allowingReadAccessToURL:'];

            if (originalLoadFileURL) {
                const originalImpl = new NativeFunction(originalLoadFileURL.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, URL, readAccessURL) {
                    requestCount++;

                    if (!URL || ptr(URL).isNull()) return originalImpl(self, sel, URL, readAccessURL);
                    const urlObj = new ObjC.Object(URL);
                    const urlStr = urlObj.absoluteString().toString();

                    console.log("");
                    logSuccess("Request #" + requestCount + " - loadFileURL:allowingReadAccessToURL:");
                    logInfo("    File URL: " + formatUrl(urlStr));

                    if (readAccessURL && !readAccessURL.isNull()) {
                        const readAccessObj = new ObjC.Object(readAccessURL);
                        const readAccessStr = readAccessObj.absoluteString().toString();
                        logInfo("    Read Access: " + formatUrl(readAccessStr));
                    }

                    if (detectDangerousUrl(urlStr) && CONFIG.detectDangerous) {
                        logDangerous("    Loading file:// URL - potential file access bypass!");
                    }

                    return originalImpl(self, sel, URL, readAccessURL);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalLoadFileURL.implementation, bypassCallback);
                hooksApplied++;
                logSuccess("WKWebView.loadFileURL:allowingReadAccessToURL: hooked");
            }
        }
    } catch (e) {
        logError("WKWebView.loadFileURL:allowingReadAccessToURL: hook failed: " + e.message);
    }
    try {
        var UIWebView = ObjC.classes.UIWebView;

        if (UIWebView) {
            var originalLoadRequestLegacy = UIWebView['- loadRequest:'];

            if (originalLoadRequestLegacy) {
                const originalImpl = new NativeFunction(originalLoadRequestLegacy.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request) {
                    requestCount++;

                    const requestObj = new ObjC.Object(request);
                    const url = requestObj.URL();
                    if (!url || url.isNull()) return originalImpl(self, sel, request);
                    const urlStr = url.absoluteString().toString();

                    console.log("");
                    logSuccess("Request #" + requestCount + " - UIWebView.loadRequest:");
                    logInfo("    URL: " + formatUrl(urlStr));

                    return originalImpl(self, sel, request);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalLoadRequestLegacy.implementation, bypassCallback);
                hooksApplied++;
                logSuccess("UIWebView.loadRequest: (legacy) hooked");
            }
        }
    } catch (e) {
        logError("UIWebView.loadRequest: (legacy) hook failed: " + e.message);
    }

    console.log("[*] ================================================");
    console.log("[*] Total hooks applied: " + hooksApplied);
    console.log("[*] Requests logged: " + requestCount);
    console.log("[*] JS executions logged: " + jsExecutionCount);
    console.log("[*] Message handlers logged: " + messageHandlerCount);
    console.log("[*] WebView Interceptor Ready");
    console.log("[*] ================================================");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
