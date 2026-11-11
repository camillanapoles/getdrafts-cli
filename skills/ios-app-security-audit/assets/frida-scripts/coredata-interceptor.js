/**
 * CoreData Operations Interceptor (BETA)
 *
 * Hooks and logs all CoreData stack operations:
 * - NSManagedObjectContext.executeFetchRequest:error:
 * - NSPersistentStoreCoordinator.addPersistentStoreWithDescription:completionHandler:
 * - NSFetchedResultsController init
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l coredata-interceptor.js
 * OWASP MASVS: MSTG-STR-2, MSTG-STR-3
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m CoreData Interceptor Script Started (BETA)");

    var CONFIG = {
        logResults: true,
        maxResultPreview: 10,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function objectToString(obj) {
                if (!obj) return "null";
                try {
                    return obj.toString();
                } catch (e) {
                    return String(obj);
                }
            }

            function nsDataToString(data) {
                if (!data) return "null";
                try {
                    var bytes = data.bytes();
                    var length = data.length();
                    var str = "";
                    for (var i = 0; i < Math.min(length, 100); i++) {
                        var b = bytes.add(i).readU8();
                        if (b >= 32 && b <= 126) {
                            str += String.fromCharCode(b);
                        } else {
                            str += ".";
                        }
                    }
                    return str + (length > 100 ? "..." : "");
                } catch (e) {
                    return "<data>";
                }
            }

            try {
                var NSManagedObjectContext = ObjC.classes.NSManagedObjectContext;

                var originalExecute = NSManagedObjectContext["- executeFetchRequest:error:"];
                const originalImpl = new NativeFunction(originalExecute.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request, error) {
                    var entityName = "";
                    var predicate = "";

                    try {
                        if (request && request.entity) {
                            entityName = request.entity.name().toString();
                        }
                        if (request && request.predicate) {
                            predicate = request.predicate.toString();
                        }
                    } catch (e) {}

                    console.log("\x1b[32m[+]\x1b[0m NSManagedObjectContext.executeFetchRequest:");
                    console.log("    Entity: " + entityName);
                    console.log("    Predicate: " + predicate);

                    var result = originalImpl(self, sel, request, error);

                    if (CONFIG.logResults && result) {
                        var count = result.count();
                        console.log("    Results: " + count + " objects");

                        if (count > 0 && count <= CONFIG.maxResultPreview) {
                            for (var i = 0; i < count; i++) {
                                var obj = result.objectAtIndex_(i);
                                console.log("      [" + i + "] " + objectToString(obj));
                            }
                        }
                    }

                    return result;
                }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalExecute.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSManagedObjectContext hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSManagedObjectContext hook failed: " + e.message);
            }

            try {
                var NSPersistentStoreCoordinator = ObjC.classes.NSPersistentStoreCoordinator;

                var originalAddStore = NSPersistentStoreCoordinator["- addPersistentStoreWithDescription:completionHandler:"];
                const originalImpl = new NativeFunction(originalAddStore.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, description, handler) {
                    var type = description.type().toString();
                    var URL = description.URL().toString();

                    console.log("\x1b[32m[+]\x1b[0m NSPersistentStoreCoordinator.addPersistentStore:");
                    console.log("    Type: " + type);
                    console.log("    URL: " + URL);

                    return originalImpl(self, sel, description, handler);
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalAddStore.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSPersistentStoreCoordinator hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSPersistentStoreCoordinator hook failed: " + e.message);
            }

            try {
                var NSFetchedResultsController = ObjC.classes.NSFetchedResultsController;

                var originalInit1 = NSFetchedResultsController["- initWithFetchRequest:managedObjectContext:sectionNameKeyPath:cacheName:"];
                const originalImpl = new NativeFunction(originalInit1.implementation, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                const bypassCallback = new NativeCallback(function(self, sel, request, context, sectionName, cacheName) {
                    var entityName = "";
                    var predicate = "";

                    try {
                        if (request && request.entity) {
                            entityName = request.entity.name().toString();
                        }
                        if (request && request.predicate) {
                            predicate = request.predicate.toString();
                        }
                    } catch (e) {}

                    console.log("\x1b[32m[+]\x1b[0m NSFetchedResultsController.init:");
                    console.log("    Entity: " + entityName);
                    console.log("    Predicate: " + predicate);
                    console.log("    Section Name: " + (sectionName ? sectionName.toString() : "null"));
                    console.log("    Cache: " + (cacheName ? cacheName.toString() : "null"));

                    return originalImpl(self, sel, request, context, sectionName, cacheName);
                }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalInit1.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSFetchedResultsController hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSFetchedResultsController hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m CoreData Interceptor error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m CoreData Interceptor Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
