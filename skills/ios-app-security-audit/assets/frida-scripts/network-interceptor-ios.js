/**
 * Frida Script: Network Traffic Interceptor (iOS)
 *
 * Purpose: Intercept and log all network traffic in iOS applications
 * Usage: frida -U -f <bundle_id> -l network-interceptor-ios.js
 *
 * What it hooks:
 * - NSURLSession.dataTaskWithRequest:completionHandler:
 * - NSURLSession.dataTaskWithURL:completionHandler:
 * - NSURLSession.uploadTaskWithRequest:fromData:completionHandler:
 * - NSURLSession.downloadTaskWithRequest:completionHandler:
 * - NSURLSession delegate methods
 *
 * Output Format:
 * Color-coded logs with request/response pairing
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0046: Test Network Communication
 * - MASTG-NET-002: Insecure Data Transport
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    console.log("[*] Network Interceptor iOS Script Started");

    var CONFIG = {
        // Filter by domain/host (empty = all domains)
        domainFilter: "",

        // Log full request/response bodies
        logBodies: true,

        // Truncate body length (0 = no truncation)
        maxBodyLength: 2000,

        // Log headers
        logHeaders: true,

        // Detect and alert on sensitive data
        detectSensitiveData: true,

        // Sensitive patterns to detect
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /authorization/i,
            /session/i,
            /credit[_-]?card/i,
            /ssn/i,
            /pin/i,
            /auth/i
        ],

        // Color codes (terminal)
        colors: {
            reset: "\x1b[0m",
            bright: "\x1b[1m",
            dim: "\x1b[2m",

            method: "\x1b[36m",     // Cyan
            url: "\x1b[33m",        // Yellow
            status: "\x1b[32m",      // Green
            statusErr: "\x1b[31m",    // Red
            statusWarn: "\x1b[35m",   // Magenta
            warn: "\x1b[35m",        // Magenta
            error: "\x1b[31m",       // Red
            info: "\x1b[34m",        // Blue
            debug: "\x1b[90m",       // Gray
            request: "\x1b[36m",     // Cyan
            response: "\x1b[32m",    // Green
            success: "\x1b[32m"      // Green (alias)
        }
    };

    var DEBUG_MODE = false;

    function shouldLogDomain(url) {
        if (CONFIG.domainFilter === "") return true;
        return url.toLowerCase().indexOf(CONFIG.domainFilter.toLowerCase()) !== -1;
    }

    function colorLabel(label, color) {
        return CONFIG.colors[color] + CONFIG.colors.bright + label + CONFIG.colors.reset;
    }

    function formatMethod(method) {
        return CONFIG.colors.method + CONFIG.colors.bright + method + CONFIG.colors.reset;
    }

    function formatUrl(url) {
        return CONFIG.colors.url + url + CONFIG.colors.reset;
    }

    function formatStatus(status) {
        var statusColor = status >= 200 && status < 300 ? CONFIG.colors.status :
                          status >= 300 && status < 400 ? CONFIG.colors.statusWarn :
                          status >= 400 ? CONFIG.colors.statusErr :
                          CONFIG.colors.warn;
        return statusColor + CONFIG.colors.bright + status + CONFIG.colors.reset;
    }

    function detectSensitiveData(text, source) {
        if (!CONFIG.detectSensitiveData || !text) return;

        var found = [];
        for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
            var pattern = CONFIG.sensitivePatterns[i];
            if (pattern.test(text)) {
                found.push(pattern.source);
            }
        }

        if (found.length > 0) {
            console.log(colorLabel("[!] SENSITIVE DATA DETECTED", "error") + " in " + source + ": " + found.join(", "));
            console.log("    Content: " + text.substring(0, 200) + (text.length > 200 ? "..." : ""));
        }
    }

    function truncate(str, maxLength) {
        if (!str) return "";
        if (CONFIG.maxBodyLength === 0) return str;
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + "\n... (truncated, " + str.length + " bytes total)";
    }

    function formatHeaders(headers, indent) {
        if (!CONFIG.logHeaders || !headers) return "";
        var result = "";
        try {
            // `headers` is already the NSDictionary returned by allHTTPHeaderFields
            var allHeaders = headers;
            var keys = allHeaders.allKeys();
            for (var i = 0; i < keys.count(); i++) {
                var key = keys.objectAtIndex_(i).toString();
                var value = allHeaders.objectForKey_(key).toString();

                // Don't log full Authorization header
                var displayValue = (key.toLowerCase() === "authorization" ||
                                   key.toLowerCase() === "cookie") ?
                                   "***REDACTED***" : value;

                result += indent + key + ": " + displayValue + "\n";
            }
        } catch (e) {
            result += indent + "[Error reading headers: " + e + "]\n";
        }
        return result;
    }

    function formatBody(data, label, indent) {
        if (!CONFIG.logBodies || !data) return "";

        var bodyStr = "";
        try {
            var nsData = new ObjC.Object(data);
            var NSData = ObjC.classes.NSData;
            var NSString = ObjC.classes.NSString;

            bodyStr = NSString.alloc().initWithData_encoding_(nsData, 4).toString();
        } catch (e) {
            bodyStr = "<" + data.toString() + ">";
        }

        // Try to pretty-print JSON
        var isJson = false;
        try {
            var trimmed = bodyStr.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                var jsonObj = JSON.parse(bodyStr);
                bodyStr = JSON.stringify(jsonObj, null, 2);
                isJson = true;
            }
        } catch (e) {
            // Not JSON, keep as-is
        }

        bodyStr = truncate(bodyStr, CONFIG.maxBodyLength);

        return indent + colorLabel(label + ":", "info") +
               (isJson ? "\n" : "") + bodyStr + "\n";
    }

    function extractMethodFromRequest(request) {
        var method = "UNKNOWN";
        try {
            method = request.HTTPMethod().toString();
        } catch (e) {
            // Some requests don't have HTTPMethod
        }
        return method;
    }

    try {
        var NSURLSession = ObjC.classes.NSURLSession;

        var originalDataTaskWithRequest = NSURLSession.dataTaskWithRequest_completionHandler_;
        const originalImpl = new NativeFunction(originalDataTaskWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, request, completionHandler) {
            const url = request.URL().absoluteString().toString();
            const method = extractMethodFromRequest(request);

            if (shouldLogDomain(url)) {
                console.log("\n" + colorLabel("=== NSURLSession REQUEST ===", "debug"));
                console.log("    " + colorLabel("Method:", "request") + " " + formatMethod(method));
                console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));
                console.log(colorLabel("    Headers:", "info"));
                console.log(formatHeaders(request.allHTTPHeaderFields(), "        "));

                if (CONFIG.logBodies && request.HTTPBody()) {
                    console.log(formatBody(request.HTTPBody(), "Body", "        "));
                }

                detectSensitiveData(url, "URL");
            }

            // Wrap completion handler to intercept response
            var wrappedHandler = null;
            if (!completionHandler.isNull()) {
                wrappedHandler = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(data, response, error) {
                        if (shouldLogDomain(url)) {
                            console.log("\n" + colorLabel("=== NSURLSession RESPONSE ===", "debug"));
                            console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));

                            if (!error.isNull()) {
                                var nsError = new ObjC.Object(error);
                                console.log(colorLabel("    Error:", "error") + " " + nsError.localizedDescription().toString());
                            }

                            if (!response.isNull()) {
                                var nsResponse = new ObjC.Object(response);
                                if (nsResponse.$className === "NSHTTPURLResponse") {
                                    var statusCode = nsResponse.statusCode();
                                    console.log("    " + colorLabel("Status:", "response") + " " + formatStatus(statusCode));
                                    console.log(colorLabel("    Headers:", "info"));
                                    console.log(formatHeaders(nsResponse.allHeaderFields(), "        "));
                                }
                            }

                            if (!data.isNull() && CONFIG.logBodies) {
                                console.log(formatBody(data, "Body", "        "));
                            }
                        }

                        // Call original handler
                        var originalHandler = new ObjC.Block(completionHandler);
                        originalHandler.implementation(data, response, error);
                    }
                });
            }

            return originalImpl(self, sel, request, wrappedHandler);
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalDataTaskWithRequest.implementation, bypassCallback);
        console.log(colorLabel("[+] NSURLSession.dataTaskWithRequest:completionHandler: hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook dataTaskWithRequest:completionHandler: ", "error") + e);
    }

    try {
        var originalDataTaskWithURL = NSURLSession.dataTaskWithURL_completionHandler_;
        const originalImpl = new NativeFunction(originalDataTaskWithURL.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, url, completionHandler) {
            const urlStr = new ObjC.Object(url).absoluteString().toString();

            if (shouldLogDomain(urlStr)) {
                console.log("\n" + colorLabel("=== NSURLSession GET REQUEST ===", "debug"));
                console.log("    " + colorLabel("Method:", "request") + " " + formatMethod("GET"));
                console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(urlStr));

                detectSensitiveData(urlStr, "URL");
            }

            // Wrap completion handler
            var wrappedHandler = null;
            if (!completionHandler.isNull()) {
                wrappedHandler = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(data, response, error) {
                        if (shouldLogDomain(urlStr)) {
                            console.log("\n" + colorLabel("=== NSURLSession RESPONSE ===", "debug"));
                            console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(urlStr));

                            if (!error.isNull()) {
                                var nsError = new ObjC.Object(error);
                                console.log(colorLabel("    Error:", "error") + " " + nsError.localizedDescription().toString());
                            }

                            if (!response.isNull()) {
                                var nsResponse = new ObjC.Object(response);
                                if (nsResponse.$className === "NSHTTPURLResponse") {
                                    var statusCode = nsResponse.statusCode();
                                    console.log("    " + colorLabel("Status:", "response") + " " + formatStatus(statusCode));
                                }
                            }

                            if (!data.isNull() && CONFIG.logBodies) {
                                console.log(formatBody(data, "Body", "        "));
                            }
                        }

                        var originalHandler = new ObjC.Block(completionHandler);
                        originalHandler.implementation(data, response, error);
                    }
                });
            }

            return originalImpl(self, sel, url, wrappedHandler);
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalDataTaskWithURL.implementation, bypassCallback);
        console.log(colorLabel("[+] NSURLSession.dataTaskWithURL:completionHandler: hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook dataTaskWithURL:completionHandler: ", "error") + e);
    }

    try {
        var originalUploadTaskWithRequest = NSURLSession.uploadTaskWithRequest_fromData_completionHandler_;
        const originalImpl = new NativeFunction(originalUploadTaskWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, request, bodyData, completionHandler) {
            const url = request.URL().absoluteString().toString();
            const method = extractMethodFromRequest(request);

            if (shouldLogDomain(url)) {
                console.log("\n" + colorLabel("=== NSURLSession UPLOAD REQUEST ===", "debug"));
                console.log("    " + colorLabel("Method:", "request") + " " + formatMethod(method));
                console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));
                console.log(colorLabel("    Headers:", "info"));
                console.log(formatHeaders(request.allHTTPHeaderFields(), "        "));

                if (!bodyData.isNull() && CONFIG.logBodies) {
                    console.log(formatBody(bodyData, "Upload Body", "        "));
                }

                detectSensitiveData(url, "URL");
            }

            // Wrap completion handler
            var wrappedHandler = null;
            if (!completionHandler.isNull()) {
                wrappedHandler = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(data, response, error) {
                        if (shouldLogDomain(url)) {
                            console.log("\n" + colorLabel("=== NSURLSession RESPONSE ===", "debug"));
                            console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));

                            if (!error.isNull()) {
                                var nsError = new ObjC.Object(error);
                                console.log(colorLabel("    Error:", "error") + " " + nsError.localizedDescription().toString());
                            }

                            if (!response.isNull()) {
                                var nsResponse = new ObjC.Object(response);
                                if (nsResponse.$className === "NSHTTPURLResponse") {
                                    var statusCode = nsResponse.statusCode();
                                    console.log("    " + colorLabel("Status:", "response") + " " + formatStatus(statusCode));
                                }
                            }

                            if (!data.isNull() && CONFIG.logBodies) {
                                console.log(formatBody(data, "Body", "        "));
                            }
                        }

                        var originalHandler = new ObjC.Block(completionHandler);
                        originalHandler.implementation(data, response, error);
                    }
                });
            }

            return originalImpl(self, sel, request, bodyData, wrappedHandler);
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalUploadTaskWithRequest.implementation, bypassCallback);
        console.log(colorLabel("[+] NSURLSession.uploadTaskWithRequest:fromData:completionHandler: hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook uploadTaskWithRequest:fromData:completionHandler: ", "error") + e);
    }

    try {
        var originalDownloadTaskWithRequest = NSURLSession.downloadTaskWithRequest_completionHandler_;
        const originalImpl = new NativeFunction(originalDownloadTaskWithRequest.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        const bypassCallback = new NativeCallback(function(self, sel, request, completionHandler) {
            const url = request.URL().absoluteString().toString();
            const method = extractMethodFromRequest(request);

            if (shouldLogDomain(url)) {
                console.log("\n" + colorLabel("=== NSURLSession DOWNLOAD REQUEST ===", "debug"));
                console.log("    " + colorLabel("Method:", "request") + " " + formatMethod(method));
                console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));
                console.log(colorLabel("    Headers:", "info"));
                console.log(formatHeaders(request.allHTTPHeaderFields(), "        "));

                detectSensitiveData(url, "URL");
            }

            // Wrap completion handler
            var wrappedHandler = null;
            if (!completionHandler.isNull()) {
                wrappedHandler = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['object', 'object', 'object'],
                    implementation: function(location, response, error) {
                        if (shouldLogDomain(url)) {
                            console.log("\n" + colorLabel("=== NSURLSession DOWNLOAD RESPONSE ===", "debug"));
                            console.log("    " + colorLabel("URL:", "url") + " " + formatUrl(url));

                            if (!error.isNull()) {
                                var nsError = new ObjC.Object(error);
                                console.log(colorLabel("    Error:", "error") + " " + nsError.localizedDescription().toString());
                            }

                            if (!response.isNull()) {
                                var nsResponse = new ObjC.Object(response);
                                if (nsResponse.$className === "NSHTTPURLResponse") {
                                    var statusCode = nsResponse.statusCode();
                                    console.log("    " + colorLabel("Status:", "response") + " " + formatStatus(statusCode));
                                }
                            }

                            if (!location.isNull()) {
                                var nsLocation = new ObjC.Object(location);
                                console.log("    " + colorLabel("Downloaded to:", "info") + " " + nsLocation.path().toString());
                            }
                        }

                        var originalHandler = new ObjC.Block(completionHandler);
                        originalHandler.implementation(location, response, error);
                    }
                });
            }

            return originalImpl(self, sel, request, wrappedHandler);
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(originalDownloadTaskWithRequest.implementation, bypassCallback);
        console.log(colorLabel("[+] NSURLSession.downloadTaskWithRequest:completionHandler: hooked", "success"));
    } catch (e) {
        console.log(colorLabel("[!] Failed to hook downloadTaskWithRequest:completionHandler: ", "error") + e);
    }

    console.log("\n" + colorLabel("[*] Network Interceptor iOS Script Ready", "success"));
} else {
    console.log(colorLabel("[!] Objective-C runtime not available", "error"));
}
