/**
 * XPC Communications Tracer (BETA)
 *
 * Hooks and logs XPC communications:
 * - NSXPCConnection.initWithServiceName:
 * - NSXPCConnection.setExportedInterface:
 * - NSXPCConnection.setExportedObject:
 * - NSXPCConnection.remoteObjectProxy
 * - NSXPCConnection.resume
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l xpc-tracer.js
 * OWASP MASVS: MSTG-PLATFORM-2
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m XPC Tracer Script Started (BETA)");

    var CONFIG = {
        filterServiceName: null,
        logMessages: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function shouldFilterService(serviceName) {
                if (!CONFIG.filterServiceName) return false;
                var regex = new RegExp(CONFIG.filterServiceName);
                return regex.test(serviceName);
            }
            try {
                var NSXPCConnection = ObjC.classes.NSXPCConnection;

                var originalInitService = NSXPCConnection["- initWithServiceName:"];
                const originalImpl = new NativeFunction(originalInitService.implementation, 'pointer', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, serviceName) {
                    const name = serviceName.toString();

                    if (shouldFilterService(name)) {
                        return originalImpl(self, sel, serviceName);
                    }

                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.initWithServiceName:");
                    console.log("    Service Name: " + name);
                    console.log("    Connection: " + self.toString());

                    return originalImpl(self, sel, serviceName);
                }, 'pointer', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalInitService.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.initWithServiceName: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.initWithServiceName: hook failed: " + e.message);
            }
            try {
                var originalSetExportedInterface = NSXPCConnection["- setExportedInterface:"];
                const originalImpl = new NativeFunction(originalSetExportedInterface.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, iface) {
                    var interfaceName = "";

                    if (iface) {
                        try {
                            interfaceName = iface.protocol().toString();
                        } catch (e) {
                            interfaceName = iface.toString();
                        }
                    }

                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setExportedInterface:");
                    console.log("    Interface: " + interfaceName);

                    return originalImpl(self, sel, iface);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetExportedInterface.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setExportedInterface: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.setExportedInterface: hook failed: " + e.message);
            }
            try {
                var originalSetExportedObject = NSXPCConnection["- setExportedObject:"];
                const originalImpl = new NativeFunction(originalSetExportedObject.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, obj) {
                    var className = "";

                    if (obj) {
                        try {
                            className = obj.className().toString();
                        } catch (e) {
                            className = "<unknown>";
                        }
                    }

                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setExportedObject:");
                    console.log("    Object Class: " + className);
                    console.log("    Connection: " + self.toString());

                    return originalImpl(self, sel, obj);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetExportedObject.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setExportedObject: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.setExportedObject: hook failed: " + e.message);
            }
            try {
                var originalRemoteObjectProxy = NSXPCConnection["- remoteObjectProxy"];
                const originalImpl = new NativeFunction(originalRemoteObjectProxy.implementation, 'pointer', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.remoteObjectProxy");
                    console.log("    Connection: " + self.toString());

                    const result = originalImpl(self, sel);

                    if (result) {
                        try {
                            console.log("    Proxy: " + result.toString());
                        } catch (e) {}
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer']);

                Interceptor.replace(originalRemoteObjectProxy.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.remoteObjectProxy hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.remoteObjectProxy hook failed: " + e.message);
            }
            try {
                var originalResume = NSXPCConnection["- resume"];
                const originalImpl = new NativeFunction(originalResume.implementation, 'void', ['pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel) {
                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.resume");
                    console.log("    Connection: " + self.toString());

                    return originalImpl(self, sel);
                }, 'void', ['pointer', 'pointer']);

                Interceptor.replace(originalResume.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.resume hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.resume hook failed: " + e.message);
            }

            // ========================================
            // 7. Hook NSXPCConnection.invalidationHandler
            try {
                var originalSetInvalidationHandler = NSXPCConnection["- setInvalidationHandler:"];
                const originalImpl = new NativeFunction(originalSetInvalidationHandler.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, handler) {
                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setInvalidationHandler");
                    console.log("    Connection: " + self.toString());

                    return originalImpl(self, sel, handler);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetInvalidationHandler.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setInvalidationHandler hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.setInvalidationHandler hook failed: " + e.message);
            }

            try {
                var originalSetInterruptionHandler = NSXPCConnection["- setInterruptionHandler:"];
                const originalImpl = new NativeFunction(originalSetInterruptionHandler.implementation, 'void', ['pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, handler) {
                    console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setInterruptionHandler");
                    console.log("    Connection: " + self.toString());

                    return originalImpl(self, sel, handler);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetInterruptionHandler.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSXPCConnection.setInterruptionHandler hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSXPCConnection.setInterruptionHandler hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m XPC Tracer error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m XPC Tracer Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
