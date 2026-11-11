/**
 * Push Notification Interceptor (BETA)
 *
 * Hooks and logs push notification handling:
 * - Hook AppDelegate notification handlers
 * - Hook UNUserNotificationCenter delegates
 * - Detect sensitive data in payloads
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l notification-interceptor.js
 * OWASP MASVS: MSTG-NETWORK-3
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Notification Interceptor Script Started (BETA)");

    var CONFIG = {
        logPayloads: true,
        detectSensitiveData: true,
        sensitivePatterns: [
            /password/i,
            /token/i,
            /api[_-]?key/i,
            /secret/i,
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/
        ],
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var UIApplication = ObjC.classes.UIApplication;
            var UNUserNotificationCenter = ObjC.classes.UNUserNotificationCenter;
            var NSDictionary = ObjC.classes.NSDictionary;

            function dictionaryToString(dict) {
                if (!dict) return "null";

                try {
                    return dict.description().toString();
                } catch (e) {
                    return "<dict>";
                }
            }

            function truncateString(str, maxLength) {
                if (!str) return "null";
                maxLength = maxLength || 200;
                if (str.toString().length <= maxLength) return str.toString();
                return str.toString().substring(0, maxLength) + "...";
            }

            function detectSensitiveInDict(dict) {
                if (!CONFIG.detectSensitiveData || !dict) return false;

                var dictStr = dictionaryToString(dict);

                for (var i = 0; i < CONFIG.sensitivePatterns.length; i++) {
                    if (CONFIG.sensitivePatterns[i].test(dictStr)) {
                        return true;
                    }
                }

                return false;
            }

            try {
                var originalDidReceiveRemote = UIApplication["- application:didReceiveRemoteNotification:fetchCompletionHandler:"];
                const originalImpl = new NativeFunction(originalDidReceiveRemote.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, application, userInfo, handler) {
                    console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didReceiveRemoteNotification:fetchCompletionHandler:");

                    if (CONFIG.logPayloads) {
                        console.log("    Payload: " + truncateString(dictionaryToString(userInfo), 300));

                        if (detectSensitiveInDict(userInfo)) {
                            console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA DETECTED in notification payload");
                        }
                    }

                    return originalImpl(self, sel, application, userInfo, handler);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalDidReceiveRemote.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didReceiveRemoteNotification:fetchCompletionHandler: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m AppDelegate.application:didReceiveRemoteNotification:fetchCompletionHandler: hook failed: " + e.message);
            }

            try {
                var originalDidRegister = UIApplication["- application:didRegisterForRemoteNotificationsWithDeviceToken:"];
                const originalImpl = new NativeFunction(originalDidRegister.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, application, deviceToken) {
                    console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didRegisterForRemoteNotificationsWithDeviceToken:");
                    console.log("    Device Token: " + deviceToken.description().toString());

                    return originalImpl(self, sel, application, deviceToken);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalDidRegister.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didRegisterForRemoteNotificationsWithDeviceToken: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m AppDelegate.application:didRegisterForRemoteNotificationsWithDeviceToken: hook failed: " + e.message);
            }

            try {
                var originalDidFail = UIApplication["- application:didFailToRegisterForRemoteNotificationsWithError:"];
                const originalImpl = new NativeFunction(originalDidFail.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, application, error) {
                    console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didFailToRegisterForRemoteNotificationsWithError:");
                    console.log("    Error: " + error.localizedDescription().toString());

                    return originalImpl(self, sel, application, error);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalDidFail.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:didFailToRegisterForRemoteNotificationsWithError: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m AppDelegate.application:didFailToRegisterForRemoteNotificationsWithError: hook failed: " + e.message);
            }

            try {
                var unDelegateProtocol = ObjC.protocols.UNUserNotificationCenterDelegate;
                var delegateClasses = [];
                if (unDelegateProtocol) {
                    var classes = ObjC.copyClassList ? ObjC.copyClassList() : Object.keys(ObjC.classes);
                    for (var ci = 0; ci < classes.length; ci++) {
                        var cls = ObjC.classes[classes[ci]];
                        if (!cls) continue;
                        try {
                            if (cls.conformsToProtocol_(unDelegateProtocol)) {
                                delegateClasses.push(cls);
                            }
                        } catch (_) {}
                    }
                }

                if (delegateClasses.length === 0) {
                    console.log("\x1b[33m[!]\x1b[0m No classes adopt UNUserNotificationCenterDelegate — skipping delegate hooks");
                } else {
                    console.log("\x1b[32m[+]\x1b[0m Found " + delegateClasses.length + " UNUserNotificationCenterDelegate class(es)");
                }

                for (var di = 0; di < delegateClasses.length; di++) {
                    var dc = delegateClasses[di];

                    var originalWillPresent = dc["- userNotificationCenter:willPresentNotification:withCompletionHandler:"];
                    if (originalWillPresent) {
                        (function (targetClass, method) {
                            const originalImpl = new NativeFunction(method.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                            const bypassCallback = new NativeCallback(function(self, sel, center, notification, handler) {
                                console.log("\x1b[32m[+]\x1b[0m " + targetClass.$className + ".userNotificationCenter:willPresentNotification:withCompletionHandler:");

                                try {
                                    var request = notification.request();
                                    var content = request.content();
                                    var title = content.title();
                                    var body = content.body();
                                    var userInfo = content.userInfo();

                                    console.log("    Title: " + (title ? truncateString(title) : "null"));
                                    console.log("    Body: " + (body ? truncateString(body) : "null"));

                                    if (CONFIG.logPayloads && userInfo) {
                                        console.log("    User Info: " + truncateString(dictionaryToString(userInfo), 300));

                                        if (detectSensitiveInDict(userInfo)) {
                                            console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA DETECTED in notification payload");
                                        }
                                    }
                                } catch (e) {
                                    console.log("    <error reading notification>");
                                }

                                return originalImpl(self, sel, center, notification, handler);
                            }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                            Interceptor.replace(method.implementation, bypassCallback);
                        })(dc, originalWillPresent);
                        console.log("\x1b[32m[+]\x1b[0m " + dc.$className + ".userNotificationCenter:willPresentNotification:withCompletionHandler: hooked");
                    }

                    var originalDidReceive = dc["- userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:"];
                    if (originalDidReceive) {
                        (function (targetClass, method) {
                            const originalImpl = new NativeFunction(method.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                            const bypassCallback = new NativeCallback(function(self, sel, center, response, handler) {
                                console.log("\x1b[32m[+]\x1b[0m " + targetClass.$className + ".userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:");

                                try {
                                    var notification = response.notification();
                                    var request = notification.request();
                                    var actionIdentifier = response.actionIdentifier();
                                    var userInfo = request.content().userInfo();

                                    console.log("    Action: " + actionIdentifier.toString());

                                    if (CONFIG.logPayloads && userInfo) {
                                        console.log("    User Info: " + truncateString(dictionaryToString(userInfo), 300));

                                        if (detectSensitiveInDict(userInfo)) {
                                            console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA DETECTED in notification payload");
                                        }
                                    }
                                } catch (e) {
                                    console.log("    <error reading response>");
                                }

                                return originalImpl(self, sel, center, response, handler);
                            }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                            Interceptor.replace(method.implementation, bypassCallback);
                        })(dc, originalDidReceive);
                        console.log("\x1b[32m[+]\x1b[0m " + dc.$className + ".userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler: hooked");
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UNUserNotificationCenterDelegate hook section failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Notification Interceptor error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Notification Interceptor Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
