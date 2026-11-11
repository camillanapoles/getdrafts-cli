/**
 * React Native iOS Hooks (BETA)
 *
 * React Native hooks for iOS:
 * - Hook RCTBridge module loading
 * - Hook RCTModuleMethod invocation
 * - Hook RCTAsyncLocalStorage
 * - Hook RCTNetworking
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l react-native-ios-hook.js
 * OWASP MASVS: MSTG-PLATFORM-4
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m React Native iOS Hook Script Started (BETA)");

    var CONFIG = {
        filterModules: [],
        logStorage: true,
        logNetwork: true,
        logModules: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            if (!ObjC.classes.RCTBridge) {
                console.log("\x1b[31m[!]\x1b[0m React Native framework not detected");
                return;
            }

            var RCTBridge = ObjC.classes.RCTBridge;
            var RCTModuleMethod = ObjC.classes.RCTModuleMethod;
            var RCTAsyncLocalStorage = ObjC.classes.RCTAsyncLocalStorage;

            function shouldFilterModule(moduleName) {
                if (CONFIG.filterModules.length === 0) return false;
                return CONFIG.filterModules.indexOf(moduleName) !== -1;
            }

            function objectToString(obj) {
                if (!obj) return "null";
                try {
                    return obj.description().toString();
                } catch (e) {
                    return String(obj);
                }
            }

            function truncateString(str, maxLength) {
                if (!str) return "null";
                maxLength = maxLength || 100;
                var s = str.toString();
                if (s.length <= maxLength) return s;
                return s.substring(0, maxLength) + "...";
            }

            if (CONFIG.logModules) {
                try {
                    var originalBridgeInit = RCTBridge["- initWithDelegate:launchOptions:"];
                    const originalImpl = new NativeFunction(originalBridgeInit.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, delegate, options) {
                        console.log("\x1b[32m[+]\x1b[0m RCTBridge.initWithDelegate:launchOptions:");
                        console.log("    Delegate: " + objectToString(delegate));

                        return originalImpl(self, sel, delegate, options);
                    }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalBridgeInit.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTBridge.initWithDelegate:launchOptions: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTBridge.initWithDelegate:launchOptions: hook failed: " + e.message);
                }

                try {
                    var originalModules = RCTBridge["- modules"];
                    const originalImpl = new NativeFunction(originalModules.implementation, 'pointer', ['pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel) {
                        const result = originalImpl(self, sel);

                        if (result) {
                            console.log("\x1b[32m[+]\x1b[0m RCTBridge.modules:");
                            for (var i = 0; i < result.count(); i++) {
                                const module = result.objectAtIndex_(i);
                                var moduleName = "";

                                try {
                                    moduleName = module.name();
                                } catch (e) {
                                    moduleName = "<unknown>";
                                }

                                console.log("    [" + i + "] " + moduleName);
                            }
                        }

                        return result;
                    }, 'pointer', ['pointer', 'pointer']);

                    Interceptor.replace(originalModules.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTBridge.modules hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTBridge.modules hook failed: " + e.message);
                }
            }

            try {
                var originalInvoke = RCTModuleMethod["- invokeWithBridge:module:arguments:"];
                const originalImpl = new NativeFunction(originalInvoke.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, bridge, module, args) {
                    var methodName = "";

                    try {
                        methodName = new ObjC.Object(self).JSMethodName();
                    } catch (e) {
                        methodName = "<unknown>";
                    }

                    var moduleName = "";

                    try {
                        moduleName = module.name();
                    } catch (e) {
                        moduleName = "<unknown>";
                    }

                    if (shouldFilterModule(moduleName)) {
                        return originalImpl(self, sel, bridge, module, args);
                    }

                    console.log("\x1b[32m[+]\x1b[0m RCTModuleMethod.invokeWithBridge:module:arguments:");
                    console.log("    Module: " + moduleName);
                    console.log("    Method: " + methodName);

                    if (args) {
                        console.log("    Arguments Count: " + args.count());
                        if (args.count() > 0) {
                            for (var i = 0; i < Math.min(args.count(), 5); i++) {
                                console.log("      [" + i + "] " + truncateString(objectToString(args.objectAtIndex_(i))));
                            }
                        }
                    }

                    return originalImpl(self, sel, bridge, module, args);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalInvoke.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m RCTModuleMethod.invokeWithBridge:module:arguments: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m RCTModuleMethod.invokeWithBridge:module:arguments: hook failed: " + e.message);
            }

            if (CONFIG.logStorage) {
                try {
                    var originalMultiGet = RCTAsyncLocalStorage["- multiGet:callback:"];
                    const originalImpl = new NativeFunction(originalMultiGet.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, keys, callback) {
                        console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiGet:");

                        if (keys) {
                            console.log("    Keys Count: " + keys.count());
                            for (var i = 0; i < Math.min(keys.count(), 10); i++) {
                                console.log("      [" + i + "] " + truncateString(objectToString(keys.objectAtIndex_(i))));
                            }
                        }

                        return originalImpl(self, sel, keys, callback);
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalMultiGet.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiGet:callback: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTAsyncLocalStorage.multiGet:callback: hook failed: " + e.message);
                }

                try {
                    var originalMultiSet = RCTAsyncLocalStorage["- multiSet:callback:"];
                    const originalImpl = new NativeFunction(originalMultiSet.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, keyValuePairs, callback) {
                        console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiSet:");

                        if (keyValuePairs) {
                            console.log("    Pairs Count: " + keyValuePairs.count());
                            for (var i = 0; i < Math.min(keyValuePairs.count(), 10); i++) {
                                const pair = keyValuePairs.objectAtIndex_(i);
                                console.log("      [" + i + "] " + truncateString(objectToString(pair)));
                            }
                        }

                        return originalImpl(self, sel, keyValuePairs, callback);
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalMultiSet.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiSet:callback: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTAsyncLocalStorage.multiSet:callback: hook failed: " + e.message);
                }

                try {
                    var originalRemove = RCTAsyncLocalStorage["- multiRemove:callback:"];
                    const originalImpl = new NativeFunction(originalRemove.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, keys, callback) {
                        console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiRemove:");

                        if (keys) {
                            console.log("    Keys Count: " + keys.count());
                            for (var i = 0; i < Math.min(keys.count(), 10); i++) {
                                console.log("      [" + i + "] " + truncateString(objectToString(keys.objectAtIndex_(i))));
                            }
                        }

                        return originalImpl(self, sel, keys, callback);
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalRemove.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTAsyncLocalStorage.multiRemove:callback: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTAsyncLocalStorage.multiRemove:callback: hook failed: " + e.message);
                }
            }

            if (CONFIG.logNetwork) {
                try {
                    var RCTNetworking = ObjC.classes.RCTNetworking;

                    var originalSendRequest = RCTNetworking["- sendRequest:withIncrementalUpdates:responseType:progressHandler:completionHandler:"];
                    const originalImpl = new NativeFunction(originalSendRequest.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    const bypassCallback = new NativeCallback(function(self, sel, request, incremental, responseType, progress, completion) {
                        console.log("\x1b[32m[+]\x1b[0m RCTNetworking.sendRequest:");

                        try {
                            const url = request.URL();
                            console.log("    URL: " + url.toString());
                            console.log("    Method: " + request.HTTPMethod());
                        } catch (e) {
                            console.log("    <error reading request>");
                        }

                        return originalImpl(self, sel, request, incremental, responseType, progress, completion);
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalSendRequest.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m RCTNetworking.sendRequest hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m RCTNetworking hook failed: " + e.message);
                }
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m React Native iOS Hook error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m React Native iOS Hook Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
