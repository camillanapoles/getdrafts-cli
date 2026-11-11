/**
 * Flutter iOS Hooks (BETA)
 *
 * Flutter-specific hooks for iOS:
 * - Hook FlutterMethodChannel
 * - Hook FlutterEventChannel
 * - Hook FlutterStandardMethodCodec
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l flutter-ios-hook.js
 * OWASP MASVS: MSTG-PLATFORM-4
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Flutter iOS Hook Script Started (BETA)");

    var CONFIG = {
        filterChannels: [],
        logArguments: true,
        logMethods: true,
        logEvents: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            if (!ObjC.classes.FlutterMethodChannel) {
                console.log("\x1b[31m[!]\x1b[0m Flutter framework not detected");
                return;
            }

            var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
            var FlutterEventChannel = ObjC.classes.FlutterEventChannel;
            var FlutterStandardMethodCodec = ObjC.classes.FlutterStandardMethodCodec;
            var FlutterViewController = ObjC.classes.FlutterViewController;

            function shouldSkipChannel(channelName) {
                // CONFIG.filterChannels is treated as a *blacklist* of
                // channels to skip: anything listed here will NOT be
                // logged. An empty blacklist = log everything.
                if (!CONFIG.filterChannels || CONFIG.filterChannels.length === 0) return false;
                return CONFIG.filterChannels.indexOf(channelName) !== -1;
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
                if (str.length <= maxLength) return str.toString();
                return str.toString().substring(0, maxLength) + "...";
            }

            if (CONFIG.logMethods) {
                try {
                    var originalSetMethodHandler = FlutterMethodChannel["- setMethodCallHandler:"];
                    const originalImpl = new NativeFunction(
                        originalSetMethodHandler.implementation, 'void', ['pointer', 'pointer', 'pointer']
                    );

                    const bypassCallback = new NativeCallback(function(self, sel, handler) {
                        const selfObj = new ObjC.Object(self);
                        const channelName = selfObj.name();

                        if (shouldSkipChannel(channelName)) {
                            originalImpl(self, sel, handler);
                            return;
                        }

                        console.log("\x1b[32m[+]\x1b[0m FlutterMethodChannel.setMethodCallHandler:");
                        console.log("    Channel: " + channelName);

                        if (handler && !ptr(handler).isNull()) {
                            console.log("    Handler: " + objectToString(new ObjC.Object(handler)));
                        }

                        originalImpl(self, sel, handler);
                    }, 'void', ['pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalSetMethodHandler.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m FlutterMethodChannel.setMethodCallHandler: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m FlutterMethodChannel.setMethodCallHandler: hook failed: " + e.message);
                }
            }

            if (CONFIG.logEvents) {
                try {
                    var originalSetStreamHandler = FlutterEventChannel["- setStreamHandler:"];
                    const originalImpl = new NativeFunction(
                        originalSetStreamHandler.implementation, 'void', ['pointer', 'pointer', 'pointer']
                    );

                    const bypassCallback = new NativeCallback(function(self, sel, handler) {
                        const selfObj = new ObjC.Object(self);
                        const channelName = selfObj.name();

                        if (shouldSkipChannel(channelName)) {
                            originalImpl(self, sel, handler);
                            return;
                        }

                        console.log("\x1b[32m[+]\x1b[0m FlutterEventChannel.setStreamHandler:");
                        console.log("    Channel: " + channelName);

                        if (handler && !ptr(handler).isNull()) {
                            console.log("    Handler: " + objectToString(new ObjC.Object(handler)));
                        }

                        originalImpl(self, sel, handler);
                    }, 'void', ['pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalSetStreamHandler.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m FlutterEventChannel.setStreamHandler: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m FlutterEventChannel.setStreamHandler: hook failed: " + e.message);
                }
            }

            try {
                var originalDecode = FlutterStandardMethodCodec["- decodeMethodCall:"];
                const originalImpl = new NativeFunction(
                    originalDecode.implementation, 'pointer', ['pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel, data) {
                    console.log("\x1b[32m[+]\x1b[0m FlutterStandardMethodCodec.decodeMethodCall:");
                    if (data && !ptr(data).isNull()) {
                        try {
                            console.log("    Data Size: " + new ObjC.Object(data).length() + " bytes");
                        } catch (e) { /* length not available */ }
                    }

                    const resultPtr = originalImpl(self, sel, data);

                    if (resultPtr && !ptr(resultPtr).isNull() && CONFIG.logArguments) {
                        try {
                            const result = new ObjC.Object(resultPtr);
                            console.log("    Method: " + result.method());
                            console.log("    Arguments: " + objectToString(result.arguments()));
                        } catch (e) {
                            console.log("    Arguments: <error reading>");
                        }
                    }

                    return resultPtr;
                }, 'pointer', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalDecode.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m FlutterStandardMethodCodec.decodeMethodCall: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m FlutterStandardMethodCodec.decodeMethodCall: hook failed: " + e.message);
            }

            try {
                var originalEncode = FlutterStandardMethodCodec["- encodeMethodCall:"];
                const originalImpl = new NativeFunction(
                    originalEncode.implementation, 'pointer', ['pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel, methodCall) {
                    console.log("\x1b[32m[+]\x1b[0m FlutterStandardMethodCodec.encodeMethodCall:");

                    if (methodCall && !ptr(methodCall).isNull() && CONFIG.logArguments) {
                        try {
                            const mcObj = new ObjC.Object(methodCall);
                            console.log("    Method: " + mcObj.method());
                            console.log("    Arguments: " + objectToString(mcObj.arguments()));
                        } catch (e) {
                            console.log("    MethodCall: <error reading>");
                        }
                    }

                    return originalImpl(self, sel, methodCall);
                }, 'pointer', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalEncode.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m FlutterStandardMethodCodec.encodeMethodCall: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m FlutterStandardMethodCodec.encodeMethodCall: hook failed: " + e.message);
            }

            try {
                var originalInitEngine = FlutterViewController["- initWithEngine:nibName:bundle:"];
                const originalImpl = new NativeFunction(
                    originalInitEngine.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel, engine, nibName, bundle) {
                    console.log("\x1b[32m[+]\x1b[0m FlutterViewController.initWithEngine:nibName:bundle:");
                    if (engine && !ptr(engine).isNull()) {
                        console.log("    Engine: " + objectToString(new ObjC.Object(engine)));
                    }

                    return originalImpl(self, sel, engine, nibName, bundle);
                }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalInitEngine.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m FlutterViewController.initWithEngine:nibName:bundle: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m FlutterViewController.initWithEngine:nibName:bundle: hook failed: " + e.message);
            }

            try {
                var originalInitWithProject = FlutterViewController["- initWithProject:nibName:bundle:"];
                const originalImpl = new NativeFunction(
                    originalInitWithProject.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel, project, nibName, bundle) {
                    console.log("\x1b[32m[+]\x1b[0m FlutterViewController.initWithProject:nibName:bundle:");
                    if (project && !ptr(project).isNull()) {
                        console.log("    Project: " + objectToString(new ObjC.Object(project)));
                    }

                    return originalImpl(self, sel, project, nibName, bundle);
                }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalInitWithProject.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m FlutterViewController.initWithProject:nibName:bundle: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m FlutterViewController.initWithProject:nibName:bundle: hook failed: " + e.message);
            }

            try {
                var FlutterEngine = ObjC.classes.FlutterEngine;

                if (FlutterEngine) {
                    var originalEngineInit = FlutterEngine["- initWithName:"];
                    const originalImpl = new NativeFunction(
                        originalEngineInit.implementation, 'pointer', ['pointer', 'pointer', 'pointer']
                    );

                    const bypassCallback = new NativeCallback(function(self, sel, name) {
                        console.log("\x1b[32m[+]\x1b[0m FlutterEngine.initWithName:");
                        if (name && !ptr(name).isNull()) {
                            console.log("    Engine Name: " + new ObjC.Object(name).toString());
                        }

                        return originalImpl(self, sel, name);
                    }, 'pointer', ['pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalEngineInit.implementation, bypassCallback);
                }

                console.log("\x1b[32m[+]\x1b[0m FlutterEngine.initWithName: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m FlutterEngine.initWithName: hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Flutter iOS Hook error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Flutter iOS Hook Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
