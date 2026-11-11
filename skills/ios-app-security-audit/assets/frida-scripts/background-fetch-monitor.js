/**
 * Background Fetch Monitor (BETA)
 *
 * Monitors background activity in the application:
 * - Hook BGTaskScheduler.submitTaskRequest
 * - Hook application background fetch
 * - Hook URLSession background tasks
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l background-fetch-monitor.js
 * OWASP MASVS: MSTG-PLATFORM-4
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Background Fetch Monitor Script Started (BETA)");

    var CONFIG = {
        logTaskSubmission: true,
        logFetchHandling: true,
        logURLSessions: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var BGTaskScheduler = ObjC.classes.BGTaskScheduler;
            var BGTaskRequest = ObjC.classes.BGTaskRequest;
            var BGAppRefreshTask = ObjC.classes.BGAppRefreshTask;
            var BGProcessingTask = ObjC.classes.BGProcessingTask;

            function taskRequestToString(request) {
                var info = [];

                if (!request) return "null";

                try {
                    info.push("Identifier: " + request.identifier().toString());

                    var earliestBeginDate = request.earliestBeginDate();
                    if (earliestBeginDate) {
                        info.push("Earliest Begin: " + earliestBeginDate.toString());
                    }

                    if (request.$className === "BGAppRefreshTaskRequest") {
                        info.push("Type: BGAppRefreshTask");
                    } else if (request.$className === "BGProcessingTaskRequest") {
                        info.push("Type: BGProcessingTask");
                    }
                } catch (e) {
                    info.push("<error>");
                }

                return info.join(", ");
            }

            if (CONFIG.logTaskSubmission) {
                try {
                    if (!BGTaskScheduler) throw new Error("BGTaskScheduler class not loaded");
                    var originalSubmitTask = BGTaskScheduler["- submitTaskRequest:error:"];
                    const originalImpl = new NativeFunction(
                        originalSubmitTask.implementation,
                        'bool', ['pointer', 'pointer', 'pointer', 'pointer']
                    );

                    const bypassCallback = new NativeCallback(function(self, sel, request, error) {
                        console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.submitTaskRequest:");
                        const reqObj = request && !ptr(request).isNull() ? new ObjC.Object(request) : null;
                        console.log("    " + taskRequestToString(reqObj));

                        const result = originalImpl(self, sel, request, error);

                        if (!result && error && !ptr(error).isNull()) {
                            try {
                                const errorPtrVal = ptr(error).readPointer();
                                if (!errorPtrVal.isNull()) {
                                    const errorObj = new ObjC.Object(errorPtrVal);
                                    console.log("\x1b[31m[!]\x1b[0m Failed: " + errorObj.localizedDescription().toString());
                                }
                            } catch (_) {}
                        } else {
                            console.log("    Status: Submitted successfully");
                        }

                        return result;
                    }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalSubmitTask.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.submitTaskRequest hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m BGTaskScheduler.submitTaskRequest hook failed: " + e.message);
                }
            }

            try {
                if (!BGTaskScheduler) throw new Error("BGTaskScheduler class not loaded");
                var originalCancelTask = BGTaskScheduler["- cancelTaskRequestWithIdentifier:"];
                const originalImpl = new NativeFunction(
                    originalCancelTask.implementation,
                    'void', ['pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel, identifier) {
                    console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.cancelTaskRequestWithIdentifier:");
                    try { console.log("    Identifier: " + new ObjC.Object(identifier).toString()); } catch (e) { console.log("    Identifier: <unreadable>"); }

                    return originalImpl(self, sel, identifier);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalCancelTask.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.cancelTaskRequestWithIdentifier: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m BGTaskScheduler.cancelTaskRequestWithIdentifier: hook failed: " + e.message);
            }

            try {
                if (!BGTaskScheduler) throw new Error("BGTaskScheduler class not loaded");
                var originalCancelAll = BGTaskScheduler["- cancelAllTaskRequests"];
                const originalImpl = new NativeFunction(
                    originalCancelAll.implementation,
                    'void', ['pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, sel) {
                    console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.cancelAllTaskRequests");

                    return originalImpl(self, sel);
                }, 'void', ['pointer', 'pointer']);

                Interceptor.replace(originalCancelAll.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m BGTaskScheduler.cancelAllTaskRequests hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m BGTaskScheduler.cancelAllTaskRequests hook failed: " + e.message);
            }

            try {
                if (!BGTaskRequest) throw new Error("BGTaskRequest class not loaded");
                var originalSetCompleted = BGTaskRequest["- setTaskCompletedWithSuccess:"];
                const originalImpl = new NativeFunction(
                    originalSetCompleted.implementation,
                    'void', ['pointer', 'pointer', 'bool']
                );

                const bypassCallback = new NativeCallback(function(self, sel, success) {
                    const successStr = success ? "SUCCESS" : "FAILED";
                    console.log("\x1b[32m[+]\x1b[0m BGTask.setTaskCompletedWithSuccess:");
                    console.log("    Result: " + successStr);

                    return originalImpl(self, sel, success);
                }, 'void', ['pointer', 'pointer', 'bool']);

                Interceptor.replace(originalSetCompleted.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m BGTask.setTaskCompletedWithSuccess: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m BGTask.setTaskCompletedWithSuccess: hook failed: " + e.message);
            }

            if (CONFIG.logURLSessions) {
                try {
                    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
                    if (NSURLSessionConfiguration) {
                        var originalBackgroundConfig = NSURLSessionConfiguration["+ backgroundSessionConfigurationWithIdentifier:"];
                        const originalImpl = new NativeFunction(
                            originalBackgroundConfig.implementation,
                            'pointer', ['pointer', 'pointer', 'pointer']
                        );

                        const bypassCallback = new NativeCallback(function(self, sel, identifier) {
                            console.log("\x1b[32m[+]\x1b[0m NSURLSessionConfiguration.backgroundSessionConfigurationWithIdentifier:");
                            try { console.log("    Identifier: " + new ObjC.Object(identifier).toString()); } catch (e) { console.log("    Identifier: <unreadable>"); }
                            return originalImpl(self, sel, identifier);
                        }, 'pointer', ['pointer', 'pointer', 'pointer']);

                        Interceptor.replace(originalBackgroundConfig.implementation, bypassCallback);

                        console.log("\x1b[32m[+]\x1b[0m NSURLSessionConfiguration.backgroundSessionConfigurationWithIdentifier: hooked successfully");
                    } else {
                        console.log("\x1b[33m[!]\x1b[0m NSURLSessionConfiguration not loaded — skipping background session hook");
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m NSURLSessionConfiguration.backgroundSessionConfigurationWithIdentifier: hook failed: " + e.message);
                }
            }

            if (CONFIG.logFetchHandling) {
                try {
                    var UIApplication = ObjC.classes.UIApplication;
                    var delegate = UIApplication.sharedApplication().delegate();
                    if (delegate) {
                        const delegateObj = ObjC.Object(delegate);
                        const delegateClass = delegateObj.$class;

                        var originalPerformFetch = delegateClass["- application:performFetchWithCompletionHandler:"];
                        if (originalPerformFetch) {
                            const originalImpl = new NativeFunction(
                                originalPerformFetch.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']
                            );

                            const bypassCallback = new NativeCallback(function(self, sel, app, completionHandler) {
                                const fetchStart = Date.now();
                                console.log("\x1b[36m[*]\x1b[0m AppDelegate.application:performFetchWithCompletionHandler: CALLED");
                                console.log("    Timestamp: " + new Date(fetchStart).toISOString());

                                originalImpl(self, sel, app, completionHandler);

                                const elapsed = Date.now() - fetchStart;
                                console.log("\x1b[32m[+]\x1b[0m performFetch completed in " + elapsed + "ms");
                                hooksApplied++;
                            }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                            Interceptor.replace(originalPerformFetch.implementation, bypassCallback);

                            console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:performFetchWithCompletionHandler: hooked (class: " + delegateClass.$className + ")");
                        } else {
                            console.log("\x1b[33m[!]\x1b[0m AppDelegate does not implement application:performFetchWithCompletionHandler:");
                        }

                        var originalHandleEvents = delegateClass["- application:handleEventsForBackgroundURLSession:completionHandler:"];
                        if (originalHandleEvents) {
                            const originalImpl = new NativeFunction(
                                originalHandleEvents.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
                            );

                            const bypassCallback = new NativeCallback(function(self, sel, app, identifier, completionHandler) {
                                const sessionId = identifier ? ObjC.Object(identifier).toString() : "unknown";
                                console.log("\x1b[36m[*]\x1b[0m AppDelegate.handleEventsForBackgroundURLSession: CALLED");
                                console.log("    Session: " + sessionId);
                                console.log("    Timestamp: " + new Date().toISOString());

                                originalImpl(self, sel, app, identifier, completionHandler);

                                console.log("\x1b[32m[+]\x1b[0m handleEvents completed for session: " + sessionId);
                                hooksApplied++;
                            }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                            Interceptor.replace(originalHandleEvents.implementation, bypassCallback);

                            console.log("\x1b[32m[+]\x1b[0m AppDelegate.application:handleEventsForBackgroundURLSession:completionHandler: hooked (class: " + delegateClass.$className + ")");
                        } else {
                            console.log("\x1b[33m[!]\x1b[0m AppDelegate does not implement application:handleEventsForBackgroundURLSession:completionHandler:");
                        }
                    } else {
                        console.log("\x1b[33m[!]\x1b[0m UIApplication.delegate() returned null — AppDelegate hooks skipped");
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m AppDelegate hook enumeration failed: " + e.message);
                }
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Background Fetch Monitor error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Background Fetch Monitor Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
