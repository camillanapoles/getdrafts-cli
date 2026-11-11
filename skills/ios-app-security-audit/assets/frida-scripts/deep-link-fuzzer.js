/**
 * Deep Link Fuzzer (BETA)
 *
 * URL scheme fuzzing tool for iOS applications:
 * - Read registered URL schemes from Info.plist
 * - Generate fuzz payloads
 * - Attempt to open URLs
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l deep-link-fuzzer.js
 * OWASP MASVS: MSTG-PLATFORM-4
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Deep Link Fuzzer Script Started (BETA)");

    var CONFIG = {
        targetScheme: null,
        payloadCount: 20,
        payloadCategories: {
            pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
            xss: ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            sqlInjection: ["' OR '1'='1", "' UNION SELECT NULL,NULL,NULL--"],
            commandInjection: ["; ls -la", "| whoami", "`cat /etc/passwd`"],
            formatString: ["%s%s%s%s%s", "%x%x%x%x%x", "%n%n%n%n%n"],
            nullByte: ["%00null", "\x00test"],
            longString: ["A".repeat(10000)],
            specialChars: ["!@#$%^&*()", "(){}[]<>", "\"';:,./*-+"]
        },
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var UIApplication = ObjC.classes.UIApplication;
            var NSBundle = ObjC.classes.NSBundle;
            var NSURL = ObjC.classes.NSURL;

            function getUrlSchemes() {
                try {
                    var mainBundle = NSBundle.mainBundle();
                    var infoDict = mainBundle.infoDictionary();
                    var urlTypes = infoDict.objectForKey_(ObjC.classes.NSString.stringWithString_("CFBundleURLTypes"));

                    var schemes = [];

                    if (urlTypes) {
                        for (var i = 0; i < urlTypes.count(); i++) {
                            var urlType = urlTypes.objectAtIndex_(i);
                            var urlSchemes = urlType.objectForKey_(ObjC.classes.NSString.stringWithString_("CFBundleURLSchemes"));

                            if (urlSchemes) {
                                for (var j = 0; j < urlSchemes.count(); j++) {
                                    schemes.push(urlSchemes.objectAtIndex_(j).toString());
                                }
                            }
                        }
                    }

                    return schemes;
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Failed to read URL schemes: " + e.message);
                    return [];
                }
            }

            function generatePayloads(scheme, count) {
                var payloads = [];
                var categories = Object.keys(CONFIG.payloadCategories);
                var payloadIndex = 0;

                for (var i = 0; i < count; i++) {
                    var category = categories[i % categories.length];
                    var categoryPayloads = CONFIG.payloadCategories[category];
                    var payload = categoryPayloads[i % categoryPayloads.length];

                    payloads.push({
                        category: category,
                        payload: payload,
                        url: scheme + "://test/" + payload
                    });
                }

                return payloads;
            }

            function fuzzUrl(url) {
                try {
                    var urlObj = NSURL.URLWithString_(url);
                    var result = UIApplication.sharedApplication().openURL_(urlObj);

                    console.log("    Result: " + (result ? "OPENED" : "FAILED"));

                    return result;
                } catch (e) {
                    console.log("    Result: ERROR - " + e.message);
                    return false;
                }
            }

            function runFuzzer() {
                var schemes = [];

                if (CONFIG.targetScheme) {
                    schemes.push(CONFIG.targetScheme);
                } else {
                    schemes = getUrlSchemes();
                }

                if (schemes.length === 0) {
                    console.log("\x1b[31m[!]\x1b[0m No URL schemes found");
                    return;
                }

                console.log("\x1b[33m[*]\x1b[0m Starting Deep Link Fuzzing");
                console.log("    Schemes: " + schemes.join(", "));
                console.log("    Payloads per scheme: " + CONFIG.payloadCount);
                console.log("");

                for (var i = 0; i < schemes.length; i++) {
                    var scheme = schemes[i];
                    console.log("\x1b[33m[*]\x1b[0m Fuzzing scheme: " + scheme);

                    var payloads = generatePayloads(scheme, CONFIG.payloadCount);

                    for (var j = 0; j < payloads.length; j++) {
                        var payload = payloads[j];
                        console.log("\x1b[32m[+]\x1b[0m [" + (j + 1) + "/" + payloads.length + "] " + payload.category.toUpperCase() + ":");
                        console.log("    URL: " + payload.url);
                        console.log("    Payload: " + payload.payload.substring(0, 100) + (payload.payload.length > 100 ? "..." : ""));

                        fuzzUrl(payload.url);

                        Thread.sleep(0.1);
                    }
                }

                console.log("\x1b[33m[*]\x1b[0m Fuzzing completed");
            }

            try {
                var originalDidFinish = UIApplication["- _run"];
                const origImpl = new NativeFunction(originalDidFinish.implementation, 'void', ['pointer', 'pointer']);
                Interceptor.replace(originalDidFinish.implementation, new NativeCallback(function(self, sel) {
                    var result = origImpl(self, sel);

                    setTimeout(function() {
                        runFuzzer();
                    }, 2000);

                    return result;
                }, 'void', ['pointer', 'pointer']));

                console.log("\x1b[32m[+]\x1b[0m Fuzzing will start after app launch");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Failed to install launch hook: " + e.message);
                console.log("\x1b[33m[*]\x1b[0m Starting immediate fuzzing...");
                runFuzzer();
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Deep Link Fuzzer error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Deep Link Fuzzer Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
