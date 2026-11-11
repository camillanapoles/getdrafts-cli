/**
 * App Groups Inspector (BETA)
 *
 * Inspects shared containers between app and extensions:
 * - Enumerate app group identifiers
 * - List files in shared containers
 * - Read shared UserDefaults
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l app-groups-inspector.js
 * OWASP MASVS: MSTG-STORAGE-4
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m App Groups Inspector Script Started (BETA)");

    var CONFIG = {
        customGroupIds: [],
        listFiles: true,
        readDefaults: true,
        maxFiles: 50,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            var NSUserDefaults = ObjC.classes.NSUserDefaults;
            var NSBundle = ObjC.classes.NSBundle;

            function getAppGroups() {
                var groups = [];

                if (CONFIG.customGroupIds.length > 0) {
                    return CONFIG.customGroupIds;
                }

                try {
                    var mainBundle = NSBundle.mainBundle();
                    var infoDict = mainBundle.infoDictionary();
                    var appGroups = infoDict.objectForKey_(ObjC.classes.NSString.stringWithString_("com.apple.security.application-groups"));

                    if (appGroups) {
                        for (var i = 0; i < appGroups.count(); i++) {
                            groups.push(appGroups.objectAtIndex_(i).toString());
                        }
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Failed to read app groups: " + e.message);
                }

                return groups;
            }

            function listFilesInContainer(containerPath) {
                var fileManager = NSFileManager.defaultManager();
                var files = [];

                try {
                    var url = ObjC.classes.NSURL.fileURLWithPath_(containerPath);
                    var enumerator = fileManager.enumeratorAtURL_includingPropertiesForKeys_options_errorHandler_(
                        url,
                        null,
                        0,
                        null
                    );

                    var count = 0;
                    var fileURL;
                    while (enumerator && (fileURL = enumerator.nextObject()) && count < CONFIG.maxFiles) {
                        var path = fileURL.path();
                        files.push(path.toString());
                        count++;
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Error enumerating files: " + e.message);
                }

                return files;
            }

            function readUserDefaultsForGroup(groupId) {
                var defaults = NSUserDefaults.alloc().initWithSuiteName_(groupId);
                var dict = {};

                try {
                    var keys = defaults.dictionaryRepresentation().allKeys();

                    for (var i = 0; i < keys.count(); i++) {
                        var key = keys.objectAtIndex_(i).toString();
                        var value = defaults.objectForKey_(ObjC.classes.NSString.stringWithString_(key));

                        dict[key] = value ? value.toString() : "null";
                    }
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m Error reading defaults: " + e.message);
                }

                return dict;
            }

            function inspectAppGroup(groupId) {
                console.log("\x1b[33m[*]\x1b[0m Inspecting App Group: " + groupId);

                var fileManager = NSFileManager.defaultManager();
                var containerURL = fileManager.containerURLForSecurityApplicationGroupIdentifier_(groupId);

                if (!containerURL || containerURL.isNil()) {
                    console.log("\x1b[31m[!]\x1b[0m No container found for group: " + groupId);
                    return;
                }

                var containerPath = containerURL.path().toString();
                console.log("    Container Path: " + containerPath);

                // List files
                if (CONFIG.listFiles) {
                    console.log("\x1b[33m[*]\x1b[0m Files:");
                    var files = listFilesInContainer(containerPath);

                    if (files.length === 0) {
                        console.log("    <no files>");
                    } else {
                        for (var i = 0; i < Math.min(files.length, CONFIG.maxFiles); i++) {
                            console.log("    [" + (i + 1) + "] " + files[i]);
                        }
                        if (files.length >= CONFIG.maxFiles) {
                            console.log("    ... and " + (files.length - CONFIG.maxFiles) + " more files");
                        }
                    }
                }

                // Read UserDefaults
                if (CONFIG.readDefaults) {
                    console.log("\x1b[33m[*]\x1b[0m UserDefaults:");
                    var defaultsDict = readUserDefaultsForGroup(groupId);

                    var keys = Object.keys(defaultsDict);
                    if (keys.length === 0) {
                        console.log("    <no defaults>");
                    } else {
                        for (var i = 0; i < keys.length; i++) {
                            var key = keys[i];
                            var value = defaultsDict[key];
                            console.log("    " + key + ": " + (value.length > 100 ? value.substring(0, 100) + "..." : value));
                        }
                    }
                }
            }

            function inspectAllAppGroups() {
                var groups = getAppGroups();

                if (groups.length === 0) {
                    console.log("\x1b[31m[!]\x1b[0m No app groups found");
                    console.log("\x1b[33m[*]\x1b[0m Checking entitlements...");

                    try {
                        var mainBundle = NSBundle.mainBundle();
                        var infoDict = mainBundle.infoDictionary();

                        console.log("\x1b[33m[*]\x1b[0m Info.plist keys:");
                        var allKeys = infoDict.allKeys();
                        for (var i = 0; i < allKeys.count(); i++) {
                            var key = allKeys.objectAtIndex_(i).toString();
                            if (key.indexOf("Group") !== -1 || key.indexOf("group") !== -1) {
                                console.log("    " + key);
                            }
                        }
                    } catch (e) {}

                    return;
                }

                console.log("\x1b[33m[*]\x1b[0m Found " + groups.length + " app group(s)");
                console.log("");

                for (var i = 0; i < groups.length; i++) {
                    inspectAppGroup(groups[i]);
                    console.log("");
                }
            }

            try {
                var UIApplication = ObjC.classes.UIApplication;

                var originalDidFinish = UIApplication["- _run"];
                if (originalDidFinish) {
                    const origImpl = new NativeFunction(
                        originalDidFinish.implementation,
                        'void', ['pointer', 'pointer']
                    );
                    Interceptor.replace(originalDidFinish.implementation, new NativeCallback(function(self, sel) {
                        var result = origImpl(self, sel);

                        setTimeout(function() {
                            inspectAllAppGroups();
                        }, 1000);

                        return result;
                    }, 'void', ['pointer', 'pointer']));
                } else {
                    throw new Error("UIApplication does not expose - _run");
                }

                console.log("\x1b[32m[+]\x1b[0m Inspection will start after app launch");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m Failed to install launch hook: " + e.message);
                console.log("\x1b[33m[*]\x1b[0m Starting immediate inspection...");
                inspectAllAppGroups();
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m App Groups Inspector error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m App Groups Inspector Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
