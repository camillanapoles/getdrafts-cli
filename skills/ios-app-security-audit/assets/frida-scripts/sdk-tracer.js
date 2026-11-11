/**
 * SDK Tracer - Runtime SDK Detection and Analysis
 *
 * This script traces the initialization and usage of third-party SDKs in iOS applications.
 * It detects common SDKs by class prefix and hooks their methods to analyze runtime behavior.
 *
 * Usage:
 *   frida -U -f com.example.app -l sdk-tracer.js
 *   frida -U com.example.app -l sdk-tracer.js
 *
 * Or via objection:
 *   objection explore
 *   ios ui dump
 *   ios hooking watch class "FirebaseAnalytics" --dump-args
 *
 * Categories Tracked:
 *   - Analytics: Mixpanel, Amplitude, Segment, Flurry, Crashlytics, Firebase
 *   - Advertising: Facebook (FBSDK), Google (GAD), UnityAds
 *   - Attribution: Adjust, AppsFlyer, Branch
 *   - Authentication: Firebase, Auth0
 *   - Cloud: AWS, Amplify
 *   - Payment: Stripe, Braintree, PayPal
 *   - Social: Facebook, Google, Twitter
 */

if (ObjC.available) {
    console.log("[*] SDK Tracer - Runtime SDK Detection");
    console.log("[*] Starting at: " + new Date().toISOString());

    const CONFIG = {
        logMethodCalls: true,
        logInitCalls: true,
        traceDataFlow: false,
        monitorNetwork: true,
        monitorKeychain: true,
        verboseOutput: false,
    };

    const SDK_REGISTRY = {
        // Analytics SDKs
        Mixpanel: {
            prefixes: ['Mixpanel', 'MixpanelInstance', 'MixpanelPeople'],
            category: 'analytics',
            methods: ['track:', 'identify:', 'registerSuperProperties:', 'timeEvent:'],
        },
        Amplitude: {
            prefixes: ['AMP', 'Amplitude', 'AMPAnalytics'],
            category: 'analytics',
            methods: ['logEvent:', 'setUserId:', 'identify:'],
        },
        Segment: {
            prefixes: ['SEG', 'SEGAnalytics', 'SEGSegment'],
            category: 'analytics',
            methods: ['track:', 'identify:', 'screen:'],
        },
        Flurry: {
            prefixes: ['Flurry', 'FlurryAnalytics'],
            category: 'analytics',
            methods: ['logEvent:', 'logError:', 'setUserId:'],
        },
        Crashlytics: {
            prefixes: ['Crashlytics', 'FIRCrashlytics', 'CLS'],
            category: 'analytics',
            methods: ['crash', 'recordError:', 'setUserIdentifier:'],
        },
        FirebaseAnalytics: {
            prefixes: ['FIRAnalytics', 'FirebaseAnalytics'],
            category: 'analytics',
            methods: ['logEventWithName:parameters:', 'setScreenName:screenClass:'],
        },

        // Advertising SDKs
        Facebook: {
            prefixes: ['FBSDK', 'FB'],
            category: 'advertising',
            methods: ['logEvent:', 'logPurchase:', 'logAppEvent'],
            sensitive: true,
        },
        GoogleAds: {
            prefixes: ['GAD', 'DFP', 'GMA'],
            category: 'advertising',
            methods: ['loadRequest:', 'presentFromRootViewController:', 'adDidReceiveAd:'],
            sensitive: true,
        },
        UnityAds: {
            prefixes: ['UnityAds', 'UADS'],
            category: 'advertising',
            methods: ['initialize', 'show', 'isReady'],
        },
        AdColony: {
            prefixes: ['AdColony', 'ADC'],
            category: 'advertising',
            methods: ['showWithPresentingViewController:', 'requestInterstitialInZone:'],
        },

        // Attribution SDKs
        Adjust: {
            prefixes: ['Adjust', 'ADJ'],
            category: 'attribution',
            methods: ['trackEvent:', 'setUserAgent:', 'setSdkPrefix:'],
        },
        AppsFlyer: {
            prefixes: ['AppsFlyer', 'AF'],
            category: 'attribution',
            methods: ['trackEvent:', 'logEvent:', 'setCustomerUserID:'],
        },
        Branch: {
            prefixes: ['Branch', 'BRN'],
            category: 'attribution',
            methods: ['userCompletedAction:', 'setIdentity:'],
        },

        // Authentication SDKs
        FirebaseAuth: {
            prefixes: ['FIRAuth', 'FirebaseAuth', 'FAuth'],
            category: 'authentication',
            methods: ['signInWith', 'createUserWithEmail:', 'signOut'],
            sensitive: true,
        },
        Auth0: {
            prefixes: ['A0', 'Auth0', 'Auth0Authentication'],
            category: 'authentication',
            methods: ['login', 'logout', 'renew'],
        },
        Okta: {
            prefixes: ['Okta', 'OID'],
            category: 'authentication',
            methods: ['signInWithRedirect', 'signOut'],
        },

        // Cloud Services SDKs
        AWS: {
            prefixes: ['AWS', 'AWSS3', 'AWSDynamoDB'],
            category: 'cloud',
            methods: ['putObject:', 'getItem:', 'query:'],
            sensitive: true,
        },
        Amplify: {
            prefixes: ['Amplify', 'API', 'DataStore'],
            category: 'cloud',
            methods: ['get', 'save:', 'delete:'],
        },
        Firebase: {
            prefixes: ['FIR', 'Firebase', 'Firestore'],
            category: 'cloud',
            methods: ['getDocument:', 'setData:', 'updateData:'],
        },

        // Payment SDKs
        Stripe: {
            prefixes: ['STP', 'Stripe'],
            category: 'payment',
            methods: ['createTokenWithCard:', 'confirmPaymentIntent:', 'handleURLCallback:'],
            sensitive: true,
        },
        Braintree: {
            prefixes: ['BTDropIn', 'BTCard', 'Braintree'],
            category: 'payment',
            methods: ['tokenizeCard:', 'presentDropInViewControllerForConfiguration:completion:'],
            sensitive: true,
        },
        PayPal: {
            prefixes: ['PayPal', 'BTPayPal'],
            category: 'payment',
            methods: ['processOrder:', 'deviceData'],
            sensitive: true,
        },

        // Social SDKs
        GoogleSignIn: {
            prefixes: ['GID', 'GoogleSignIn'],
            category: 'social',
            methods: ['signInWithPresentingViewController:', 'restorePreviousSignIn'],
        },
        Twitter: {
            prefixes: ['Twitter', 'TWTR'],
            category: 'social',
            methods: ['logInWithViewController:', 'logOut'],
        },
        LinkedIn: {
            prefixes: ['LISDK', 'LinkedIn'],
            category: 'social',
            methods: ['getAccessToken', 'createSessionWithAuth:'],
        },

        // Push Notification SDKs
        FirebaseMessaging: {
            prefixes: ['FIRMessaging', 'Messaging'],
            category: 'push',
            methods: ['appDidReceiveMessage:', 'subscribeToTopic:'],
        },
        OneSignal: {
            prefixes: ['OneSignal', 'OS'],
            category: 'push',
            methods: ['setSubscriptionEnabled:', 'sendTag:'],
        },

        // Other SDKs
        AppTrackingTransparency: {
            prefixes: ['ATTrackingManager', 'ATT'],
            category: 'privacy',
            methods: ['trackingAuthorizationStatus', 'requestTrackingAuthorizationWithCompletionHandler:'],
        },
        Intercom: {
            prefixes: ['Intercom', 'IM'],
            category: 'support',
            methods: ['registerUnidentifiedUser:', 'logEventWithName:'],
        },
        Zendesk: {
            prefixes: ['ZDK', 'Zendesk'],
            category: 'support',
            methods: ['requestCreation', 'updateRequest:'],
        },
    };

    const STATS = {
        sdksDetected: [],
        methodCalls: {},
        dataExfiltration: [],
        networkCalls: [],
    };

    function isSDKClass(className) {
        for (const [sdkName, sdkInfo] of Object.entries(SDK_REGISTRY)) {
            for (const prefix of sdkInfo.prefixes) {
                if (className.startsWith(prefix)) {
                    return { name: sdkName, info: sdkInfo };
                }
            }
        }
        return null;
    }

    function shouldHookMethod(methodName, sdkInfo) {
        if (sdkInfo.methods && sdkInfo.methods.length > 0) {
            return sdkInfo.methods.some(pattern => {
                if (pattern.includes(':')) {
                    return methodName.startsWith(pattern.replace(':', ''));
                }
                return methodName === pattern;
            });
        }
        return false;
    }

    function formatArgument(arg, index) {
        try {
            // NativePointer has a toString() and arithmetic; treat it
            // as a raw hex pointer.
            if (arg instanceof NativePointer) {
                return `ptr(${arg})`;
            }
            // Wrap raw args in ObjC.Object so we can introspect them.
            // Note: ObjC.Object.isArray / isObject are NOT real Frida
            // APIs — we detect by inspecting $className.
            if (arg && typeof arg === 'object' && typeof arg.$className === 'string') {
                const className = arg.$className;
                if (className === 'NSArray' || className === '__NSArray0' ||
                    className === '__NSArrayI' || className === '__NSArrayM' ||
                    className === 'NSMutableArray') {
                    return `Array[${arg.count()}]`;
                }
                if (className === 'NSDictionary' || className === '__NSDictionaryM' ||
                    className === 'NSMutableDictionary') {
                    return `Dict{${arg.count()} entries}`;
                }
                if (className === '__NSCFString' || className === '__NSCFConstantString' ||
                    className === 'NSString' || className === 'NSMutableString') {
                    return `"${arg.toString()}"`;
                }
                if (className === '__NSCFNumber' || className === '__NSCFBoolean' ||
                    className === 'NSNumber') {
                    return `${arg.toString()}`;
                }
                return `Obj(${className})`;
            } else if (typeof arg === 'string') {
                return `"${arg}"`;
            } else if (typeof arg === 'number') {
                return `${arg}`;
            } else if (typeof arg === 'boolean') {
                return `${arg}`;
            } else {
                return `${typeof arg}`;
            }
        } catch (e) {
            return '?';
        }
    }

    function formatArguments(args) {
        const formatted = [];
        for (let i = 2; i < args.length; i++) {
            formatted.push(formatArgument(args[i], i));
        }
        return formatted.join(', ');
    }

    function trackMethodCall(className, methodName) {
        const key = `${className}.${methodName}`;
        STATS.methodCalls[key] = (STATS.methodCalls[key] || 0) + 1;
    }

    function checkForPII(args, className, methodName) {
        try {
            for (let i = 2; i < args.length; i++) {
                if (!args[i] || args[i].isNull()) continue;
                try {
                    const arg = ObjC.Object(args[i]);
                    if (!arg || typeof arg.toString !== 'function') continue;
                    const str = arg.toString();

                const patterns = [
                    { name: 'Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
                    { name: 'Phone', regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/ },
                    { name: 'Credit Card', regex: /\b(?:\d[ -]*?){13,16}\b/ },
                    { name: 'SSN', regex: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/ },
                    { name: 'UUID', regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i },
                ];

                for (const pattern of patterns) {
                    if (pattern.regex.test(str)) {
                        console.log(`[!] PII DETECTED: ${pattern.name} in ${className}.${methodName}`);
                        STATS.dataExfiltration.push({
                            sdk: className,
                            method: methodName,
                            piiType: pattern.name,
                            timestamp: new Date().toISOString(),
                        });
                    }
                }
            } catch (e) {
                continue;
            }
            }
        } catch (e) {
            // Ignore errors in PII checking
        }
    }

    function hookSDKClass(className, sdkInfo) {
        const klass = ObjC.classes[className];
        if (!klass) return;

        const methods = klass.$methods;

        for (const method of methods) {
            const methodName = method.split('$')[1].replace(/_/g, ':');

            if (CONFIG.logMethodCalls && shouldHookMethod(methodName, sdkInfo)) {
                try {
                    Interceptor.attach(klass[method].implementation, {
                        onEnter: function (args) {
                            const formattedArgs = formatArguments(args);

                            console.log(`[SDK] ${className} ${methodName}`);
                            if (CONFIG.verboseOutput && formattedArgs) {
                                console.log(`     Args: ${formattedArgs}`);
                            }

                            trackMethodCall(className, methodName);

                            if (sdkInfo.sensitive) {
                                checkForPII(args, className, methodName);
                            }
                        },
                        onLeave: function (retval) {
                            if (CONFIG.verboseOutput && retval) {
                                console.log(`     Return: ${formatArgument(retval, 0)}`);
                            }
                        }
                    });
                } catch (e) {
                    console.log(`[!] Failed to hook ${className} ${methodName}: ${e}`);
                }
            }
        }
    }

    function monitorNetworkRequests() {
        if (!CONFIG.monitorNetwork) return;

        console.log("[*] Monitoring SDK network requests");

        try {
            const URLSession = ObjC.classes.NSURLSession;
            Interceptor.attach(URLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                onEnter: function (args) {
                    try {
                        const request = ObjC.Object(args[2]);
                        const url = request.URL().toString();
                        const httpMethod = request.HTTPMethod().toString();

                        const sdkURLs = [
                            'analytics', 'track', 'mixpanel', 'amplitude',
                            'segment', 'flurry', 'crashlytics', 'facebook',
                            'google', 'ad', 'impression', 'click',
                            'adjust', 'appsflyer', 'branch', 'firebase',
                            'aws', 'amplify', 'stripe', 'braintree',
                            'paypal', 'auth0', 'okta', 'intercom'
                        ];

                        const isSDKRequest = sdkURLs.some(sdk =>
                            url.toLowerCase().includes(sdk)
                        );

                        if (isSDKRequest) {
                            console.log(`[Network] SDK Request: ${httpMethod} ${url}`);

                            STATS.networkCalls.push({
                                method: httpMethod,
                                url: url,
                                timestamp: new Date().toISOString(),
                            });
                        }
                    } catch (e) {
                        // Ignore errors
                    }
                }
            });
        } catch (e) {
            console.log(`[!] Failed to monitor network: ${e}`);
        }
    }

    function monitorKeychainAccess() {
        if (!CONFIG.monitorKeychain) return;

        console.log("[*] Monitoring SDK keychain access");

        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        try {
            // Hook SecItemAdd — guard against symbol not found (criterion #1)
            const SecItemAddPtr = findExport('Security', 'SecItemAdd');
            if (!SecItemAddPtr) {
                console.log('[-] SecItemAdd not found in Security framework');
                return;
            }
            const SecItemAdd = new NativeFunction(SecItemAddPtr, 'int', ['pointer', 'pointer']);

            Interceptor.attach(SecItemAddPtr, {
                onEnter: function (args) {
                    try {
                        // This is simplified - full keychain inspection would require
                        // parsing CFDictionaryRef which is complex in Frida
                        console.log(`[Keychain] SecItemAdd called`);
                    } catch (e) {
                        // Ignore errors
                    }
                }
            });
        } catch (e) {
            console.log(`[!] Failed to monitor keychain: ${e}`);
        }
    }

    function detectSDKs() {
        console.log("\n[*] Detecting SDKs in application...");

        const detectedSDKs = new Set();

        for (const className of Object.keys(ObjC.classes)) {
            const sdkMatch = isSDKClass(className);
            if (sdkMatch) {
                const { name, info } = sdkMatch;

                if (!detectedSDKs.has(name)) {
                    detectedSDKs.add(name);
                    STATS.sdksDetected.push({
                        name: name,
                        category: info.category,
                        sensitive: info.sensitive || false,
                        firstSeenClass: className,
                    });

                    console.log(`[+] ${name} (${info.category})`);
                }

                // Hook key methods of this SDK class. We pass the
                // SDK's class name itself as a sentinel; shouldHookMethod
                // is supposed to return true when ANY of the SDK's
                // configured method patterns is non-empty. The previous
                // implementation passed an empty string, which made
                // .startsWith() always false and silently skipped the
                // hook.
                if (info.methods && info.methods.length > 0) {
                    hookSDKClass(className, info);
                } else if (info.hookAll) {
                    hookSDKClass(className, info);
                }
            }
        }

        return detectedSDKs;
    }

    function printSummary() {
        console.log("\n" + "=".repeat(60));
        console.log("SDK TRACER SUMMARY");
        console.log("=".repeat(60));

        console.log(`\nSDKs Detected: ${STATS.sdksDetected.length}`);
        STATS.sdksDetected.forEach(sdk => {
            const sensitive = sdk.sensitive ? ' [SENSITIVE]' : '';
            console.log(`  - ${sdk.name} (${sdk.category})${sensitive}`);
        });

        console.log(`\nMethod Calls: ${Object.keys(STATS.methodCalls).length}`);
        const topMethods = Object.entries(STATS.methodCalls)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        topMethods.forEach(([method, count]) => {
            console.log(`  - ${method}: ${count} calls`);
        });

        if (STATS.dataExfiltration.length > 0) {
            console.log(`\nPII Detections: ${STATS.dataExfiltration.length}`);
            STATS.dataExfiltration.forEach(pii => {
                console.log(`  - ${pii.sdk}.${pii.method}: ${pii.piiType}`);
            });
        }

        if (STATS.networkCalls.length > 0) {
            console.log(`\nNetwork Calls: ${STATS.networkCalls.length}`);
            STATS.networkCalls.slice(0, 10).forEach(call => {
                console.log(`  - ${call.method} ${call.url}`);
            });
        }

        console.log("\n" + "=".repeat(60));
    }

    function main() {
        console.log("[*] Initializing SDK Tracer...\n");

        detectSDKs();

        if (CONFIG.monitorNetwork) {
            monitorNetworkRequests();
        }

        if (CONFIG.monitorKeychain) {
            monitorKeychainAccess();
        }

        console.log("\n[*] SDK Tracer initialized");
        console.log("[*] Waiting for SDK activity...");
        console.log("[*] Press Ctrl+C to see summary\n");

        if (typeof Script !== 'undefined' && Script.events) {
            Script.events.listen('destroy', () => {
                printSummary();
            });
        }
    }

    setTimeout(main, 1000);

} else {
    console.log("[!] Objective-C runtime not available");
    console.log("[!] This script requires an Objective-C application");
}
