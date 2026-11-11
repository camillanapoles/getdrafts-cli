/**
 * APP TRANSPORT SECURITY MONITOR - iOS [STABLE]
 *
 * Purpose: Monitor App Transport Security (ATS) configuration and HTTP connections
 * Usage: frida -U -f <BUNDLE_ID> -l app-transport-security.js
 *        or
 *        frida -U <BUNDLE_ID> -l app-transport-security.js
 *
 * What it hooks:
 * - NSURLSession configuration initialization (ATS settings)
 * - NSURLConnection creation (HTTP/HTTPS detection)
 * - NSURLSession task creation (request inspection)
 * - CFNetwork internal calls (connection monitoring)
 *
 * What it logs:
 * - HTTP connections (non-HTTPS)
 * - ATS bypass attempts (allowsArbitraryLoads)
 * - Insecure domain exceptions
 * - Connection configuration details
 * - URL scheme violations
 *
 * Features:
 * - Detect HTTP connections
 * - Monitor ATS configuration
 * - Identify insecure domains
 * - Track NSURLConnection usage (deprecated)
 * - Support for both NSURLSession and NSURLConnection
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0225: Test Network Communication for Sensitive Information
 * - MASTG-NET-001: Network Communication Security
 * - MASVS-NET: Network Communication Requirements
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] ================================================");
    console.log("[*] APP TRANSPORT SECURITY MONITOR - iOS STARTED");
    console.log("[*] ================================================");

    var CONFIG = {
        // Alert on HTTP connections
        alertOnHTTP: true,

        // Log allowed domains (ATS exceptions)
        logAllowedDomains: true,

        // Log all HTTPS connections
        logHTTPS: false,

        // Detect and log NSURLConnection usage (deprecated)
        monitorDeprecatedAPIs: true,

        // Maximum URL length to display
        maxUrlLength: 300,

        // Color codes
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",

            success: "\x1b[32m",     // Green
            error: "\x1b[31m",      // Red
            warn: "\x1b[33m",       // Yellow
            info: "\x1b[34m",       // Blue
            dangerous: "\x1b[35m"   // Magenta
        }
    };

    var hooksApplied = 0;
    var httpConnectionCount = 0;
    var httpsConnectionCount = 0;
    var atsBypassCount = 0;
    var allowedDomains = new Set();

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

    function logDangerous(message) {
        console.log(CONFIG.colors.dangerous + CONFIG.colors.bright + "[!] DANGER " + CONFIG.colors.reset + message);
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }

    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    function getURLScheme(urlStr) {
        if (!urlStr) return "unknown";

        if (urlStr.toLowerCase().startsWith("https://")) {
            return "https";
        } else if (urlStr.toLowerCase().startsWith("http://")) {
            return "http";
        } else if (urlStr.toLowerCase().startsWith("file://")) {
            return "file";
        } else if (urlStr.toLowerCase().startsWith("data:")) {
            return "data";
        } else {
            return "other";
        }
    }

    function getDomainFromURL(urlStr) {
        try {
            var match = urlStr.match(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/([^\/?#]+)/);
            if (match && match[1]) {
                return match[1];
            }
        } catch (e) {
            // Parsing failed
        }
        return "";
    }

    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

        if (NSURLSessionConfiguration) {
            var originalDefaultSessionConfig = NSURLSessionConfiguration['+ defaultSessionConfiguration'];

            if (originalDefaultSessionConfig) {
                const originalImpl = new NativeFunction(originalDefaultSessionConfig.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    var result = originalImpl(self, sel);

                    if (result) {
                        var config = new ObjC.Object(result);

                        // Check ATS settings
                        var allowsArbitraryLoads = config.allowsArbitraryLoads();
                        if (allowsArbitraryLoads) {
                            atsBypassCount++;
                            console.log("");
                            logDangerous("ATS bypass detected in defaultSessionConfiguration");
                            logWarn("    allowsArbitraryLoads: YES (ATS disabled)");
                        }

                        var tlsMinimumSupportedProtocol = config.TLSMinimumSupportedProtocol();
                        var tlsMaximumSupportedProtocol = config.TLSMaximumSupportedProtocol();

                        if (tlsMinimumSupportedProtocol !== 0) {
                            logInfo("    TLSMinimumSupportedProtocol: " + tlsMinimumSupportedProtocol);
                        }

                        if (tlsMaximumSupportedProtocol !== 0) {
                            logInfo("    TLSMaximumSupportedProtocol: " + tlsMaximumSupportedProtocol);
                        }

                        // Check exception domains
                        try {
                            var exceptionDomains = config.exceptionDomains();
                            if (exceptionDomains) {
                                var domainKeys = exceptionDomains.allKeys();
                                var count = domainKeys.count();

                                if (count > 0 && CONFIG.logAllowedDomains) {
                                    logWarn("    ATS Exception Domains (" + count + "):");
                                    for (var i = 0; i < count; i++) {
                                        var domain = domainKeys.objectAtIndex_(i).toString();
                                        allowedDomains.add(domain);
                                        logInfo("      - " + domain);
                                    }
                                }
                            }
                        } catch (e) {
                            // Exception domains parsing failed
                        }
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(originalDefaultSessionConfig.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("NSURLSessionConfiguration.defaultSessionConfiguration hooked");
            }

            var originalEphemeralSessionConfig = NSURLSessionConfiguration['+ ephemeralSessionConfiguration'];

            if (originalEphemeralSessionConfig) {
                const originalImpl = new NativeFunction(originalEphemeralSessionConfig.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    var result = originalImpl(self, sel);

                    if (result) {
                        var config = new ObjC.Object(result);

                        var allowsArbitraryLoads = config.allowsArbitraryLoads();
                        if (allowsArbitraryLoads) {
                            atsBypassCount++;
                            console.log("");
                            logDangerous("ATS bypass detected in ephemeralSessionConfiguration");
                            logWarn("    allowsArbitraryLoads: YES (ATS disabled)");
                        }
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(originalEphemeralSessionConfig.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("NSURLSessionConfiguration.ephemeralSessionConfiguration hooked");
            }
        }
    } catch (e) {
        logError("NSURLSessionConfiguration hook failed: " + e.message);
    }

    try {
        var NSURLSession = ObjC.classes.NSURLSession;

        if (NSURLSession) {
            var originalDataTaskWithRequest = NSURLSession['- dataTaskWithRequest:'];

            if (originalDataTaskWithRequest) {
                const originalImpl = new NativeFunction(originalDataTaskWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request) {
                    var requestObj = new ObjC.Object(request);
                    var url = requestObj.URL();

                    if (url) {
                        var urlStr = url.absoluteString().toString();
                        var scheme = getURLScheme(urlStr);

                        if (scheme === "http") {
                            httpConnectionCount++;

                            if (CONFIG.alertOnHTTP) {
                                console.log("");
                                logDangerous("HTTP Connection #" + httpConnectionCount + " detected!");
                                logWarn("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));

                                var domain = getDomainFromURL(urlStr);
                                if (domain) {
                                    logInfo("    Domain: " + domain);
                                }

                                var method = requestObj.HTTPMethod();
                                if (method) {
                                    logInfo("    Method: " + method.toString());
                                }
                            }
                        } else if (scheme === "https") {
                            httpsConnectionCount++;

                            if (CONFIG.logHTTPS) {
                                console.log("");
                                logSuccess("HTTPS Connection #" + httpsConnectionCount);
                                logInfo("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                            }
                        }
                    }

                    return originalImpl(self, sel, request);
                }, 'pointer', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalDataTaskWithRequest.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("NSURLSession.dataTaskWithRequest: hooked");
            }
        }
    } catch (e) {
        logError("NSURLSession.dataTaskWithRequest: hook failed: " + e.message);
    }

    try {
        if (CONFIG.monitorDeprecatedAPIs) {
            var NSURLConnection = ObjC.classes.NSURLConnection;

            if (NSURLConnection) {
                var originalConnectionWithRequest = NSURLConnection['+ connectionWithRequest:delegate:'];

                if (originalConnectionWithRequest) {
                    const originalImpl = new NativeFunction(originalConnectionWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, request, delegate) {
                        var requestObj = new ObjC.Object(request);
                        var url = requestObj.URL();

                        if (url) {
                            var urlStr = url.absoluteString().toString();
                            var scheme = getURLScheme(urlStr);

                            if (scheme === "http") {
                                httpConnectionCount++;

                                if (CONFIG.alertOnHTTP) {
                                    console.log("");
                                    logDangerous("HTTP Connection (NSURLConnection - DEPRECATED) #" + httpConnectionCount + " detected!");
                                    logWarn("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                                    logWarn("    [!] NSURLConnection is deprecated - migrate to NSURLSession");
                                }
                            } else if (scheme === "https") {
                                httpsConnectionCount++;

                                if (CONFIG.logHTTPS) {
                                    console.log("");
                                    logSuccess("HTTPS Connection (NSURLConnection) #" + httpsConnectionCount);
                                    logInfo("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                                }
                            }
                        }

                        return originalImpl(self, sel, request, delegate);
                    }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalConnectionWithRequest.implementation, bypassCallback);

                    hooksApplied++;
                    logSuccess("NSURLConnection.connectionWithRequest:delegate: hooked");
                }
            }
        }
    } catch (e) {
        logError("NSURLConnection hook failed: " + e.message);
    }

    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            var originalTaskWithRequest = NSURLSession['- taskWithRequest:'];

            if (originalTaskWithRequest) {
                const originalImpl = new NativeFunction(originalTaskWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request) {
                    var requestObj = new ObjC.Object(request);
                    var url = requestObj.URL();

                    if (url) {
                        var urlStr = url.absoluteString().toString();
                        var scheme = getURLScheme(urlStr);

                        if (scheme === "http") {
                            httpConnectionCount++;

                            if (CONFIG.alertOnHTTP) {
                                console.log("");
                                logDangerous("HTTP Connection (taskWithRequest) #" + httpConnectionCount + " detected!");
                                logWarn("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                            }
                        } else if (scheme === "https" && CONFIG.logHTTPS) {
                            httpsConnectionCount++;
                            console.log("");
                            logSuccess("HTTPS Connection (taskWithRequest) #" + httpsConnectionCount);
                            logInfo("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                        }
                    }

                    return originalImpl(self, sel, request);
                }, 'pointer', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalTaskWithRequest.implementation, bypassCallback);

                hooksApplied++;
                logSuccess("NSURLSession.taskWithRequest: hooked");
            }
        }
    } catch (e) {
        logError("NSURLSession.taskWithRequest: hook failed: " + e.message);
    }

    try {
        var CFURLConnectionCreateWithProperties = findExport('CFNetwork', 'CFURLConnectionCreateWithProperties');

        if (CFURLConnectionCreateWithProperties) {
            Interceptor.attach(CFURLConnectionCreateWithProperties, {
                onEnter: function(args) {
                    try {
                        var urlPtr = args[1];
                        if (urlPtr && !urlPtr.isNull()) {
                            var urlObj = new ObjC.Object(urlPtr);
                            var urlStr = urlObj.absoluteString().toString();

                            var scheme = getURLScheme(urlStr);
                            if (scheme === "http" && CONFIG.alertOnHTTP) {
                                httpConnectionCount++;
                                console.log("");
                                logDangerous("HTTP Connection (CFNetwork) #" + httpConnectionCount + " detected!");
                                logWarn("    URL: " + truncate(urlStr, CONFIG.maxUrlLength));
                            }
                        }
                    } catch (e) {
                        // CFNetwork hook error
                    }
                }
            });

            hooksApplied++;
            logSuccess("CFNetwork CFURLConnectionCreateWithProperties hooked");
        } else {
            logInfo("CFURLConnectionCreateWithProperties not exported in this CFNetwork build");
        }
    } catch (e) {
        logError("CFNetwork hook failed: " + e.message);
    }

    console.log("[*] ================================================");
    console.log("[*] Total hooks applied: " + hooksApplied);
    console.log("[*] App Transport Security Monitor Ready");
    console.log("[*] ================================================");

    // Initial ATS status
    console.log("");
    logInfo("Initial ATS Status:");
    logInfo("  HTTP connections: " + httpConnectionCount);
    logInfo("  HTTPS connections: " + httpsConnectionCount);
    logInfo("  ATS bypasses detected: " + atsBypassCount);

    if (allowedDomains.size > 0) {
        logWarn("  Allowed ATS exception domains: " + allowedDomains.size);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
