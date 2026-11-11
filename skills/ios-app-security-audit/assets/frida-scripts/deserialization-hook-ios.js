/**
 * Insecure Deserialization Hook for iOS
 *
 * Hooks and logs deserialization operations that could lead to RCE:
 * - NSKeyedUnarchiver (NSKeyedArchiver)
 * - NSSecureCoding validation
 * - Property list deserialization
 * - JSON/Codable decoding (Swift)
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l deserialization-hook-ios.js
 * OWASP MASVS: MSTG-CRYPTO-1, MSTG-DESER-1
 * MASTG: TEST-0018 Insecure Deserialization
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Deserialization Hook iOS Script Started");

    var CONFIG = {
        maxDataLength: 512,
        logFullData: false,
        alertOnInsecure: true,
        DEBUG_MODE: false
    };

    var deserializationCount = 0;
    var insecureCount = 0;

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function bytesToHex(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || CONFIG.maxDataLength;
                var hex = "";

                try {
                    var totalLen;
                    if (bytes instanceof ArrayBuffer) {
                        totalLen = bytes.byteLength;
                    } else if (bytes && typeof bytes.byteLength === "number") {
                        totalLen = bytes.byteLength;
                    } else {
                        totalLen = maxLength;
                    }

                    var bytesToRead = Math.min(totalLen, maxLength);
                    for (var i = 0; i < bytesToRead; i++) {
                        var b;
                        if (bytes instanceof ArrayBuffer) {
                            b = new Uint8Array(bytes)[i];
                        } else if (bytes && typeof bytes.readU8 === "function") {
                            b = bytes.add(i).readU8();
                        } else {
                            return "<unsupported bytes type>";
                        }
                        hex += ("0" + b.toString(16)).slice(-2);
                    }
                    if (totalLen > maxLength) {
                        hex += "... (" + totalLen + " bytes total)";
                    }
                } catch (e) {
                    hex = "<cannot read>";
                }

                return hex;
            }

            function nsDataToHex(data, maxLength) {
                if (!data) return "null";
                try {
                    return bytesToHex(data.bytes(), maxLength);
                } catch (e) {
                    return "<data>";
                }
            }

            function getClassName(obj) {
                if (!obj || obj.isNull()) return "null";
                try {
                    return ObjC.Object(obj).$className;
                } catch (e) {
                    return "<unknown>";
                }
            }

            function getStackTrace() {
                return Thread.backtrace(Thread.backtrace(), Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .slice(0, 5)
                    .join("\n\t");
            }

            // NSKeyedUnarchiver - Primary deserialization vector
            try {
                var NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
                if (NSKeyedUnarchiver) {
                    // unarchiveObjectWithData:
                    var unarchiveObjectWithData = NSKeyedUnarchiver["- unarchiveObjectWithData:"];
                    if (unarchiveObjectWithData) {
                        Interceptor.attach(unarchiveObjectWithData.implementation, {
                            onEnter: function(args) {
                                this.data = args[2];
                                this.threadId = Process.getCurrentThreadId();
                            },
                            onLeave: function(retval) {
                                deserializationCount++;
                                try {
                                    console.log("\x1b[32m[+]\x1b[0m NSKeyedUnarchiver.unarchiveObjectWithData:");

                                    if (this.data && !this.data.isNull()) {
                                        var dataObj = ObjC.Object(this.data);
                                        console.log("    Data: " + nsDataToHex(dataObj, 64));
                                        console.log("    Length: " + dataObj.length());
                                    }

                                    if (retval && !retval.isNull()) {
                                        var resultObj = ObjC.Object(retval);
                                        console.log("    Result Class: " + resultObj.$className);

                                        if (CONFIG.alertOnInsecure) {
                                            console.log("\x1b[31m[!]\x1b[0m WARNING: Insecure deserialization detected - NSSecureCoding not enforced");
                                            insecureCount++;
                                        }
                                    }

                                    if (CONFIG.DEBUG_MODE) {
                                        console.log("    Stack trace:\n\t" + getStackTrace());
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m unarchiveObjectWithData error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSKeyedUnarchiver.unarchiveObjectWithData: hooked");
                    }

                    // unarchiveTopLevelObjectWithData:
                    var unarchiveTopLevelObject = NSKeyedUnarchiver["- unarchiveTopLevelObjectWithData:error:"];
                    if (unarchiveTopLevelObject) {
                        Interceptor.attach(unarchiveTopLevelObject.implementation, {
                            onEnter: function(args) {
                                this.data = args[2];
                            },
                            onLeave: function(retval) {
                                deserializationCount++;
                                try {
                                    console.log("\x1b[32m[+]\x1b[0m NSKeyedUnarchiver.unarchiveTopLevelObjectWithData:");

                                    if (this.data && !this.data.isNull()) {
                                        var dataObj = ObjC.Object(this.data);
                                        console.log("    Data: " + nsDataToHex(dataObj, 64));
                                    }

                                    if (retval && !retval.isNull()) {
                                        var resultObj = ObjC.Object(retval);
                                        console.log("    Result Class: " + resultObj.$className);
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m unarchiveTopLevelObjectWithData error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSKeyedUnarchiver.unarchiveTopLevelObjectWithData: hooked");
                    }

                    // allowsSecureCoding - Check if secure coding is enforced
                    var allowsSecureCoding = NSKeyedUnarchiver["+ setAllowsSecureCoding:"];
                    if (allowsSecureCoding) {
                        Interceptor.attach(allowsSecureCoding.implementation, {
                            onEnter: function(args) {
                                this.allows = args[2].toInt32();
                            },
                            onLeave: function(retval) {
                                try {
                                    var state = this.allows ? "ENABLED" : "DISABLED";
                                    if (this.allows === 0) {
                                        console.log("\x1b[31m[!]\x1b[0m NSKeyedUnarchiver.setAllowsSecureCoding: " + state + " - INSECURE");
                                        insecureCount++;
                                    } else {
                                        console.log("\x1b[36m[i]\x1b[0m NSKeyedUnarchiver.setAllowsSecureCoding: " + state + " - SECURE");
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m setAllowsSecureCoding error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSKeyedUnarchiver.setAllowsSecureCoding: hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m NSKeyedUnarchiver class not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSKeyedUnarchiver hook failed: " + e.message);
            }

            // NSKeyedArchiver - Monitor serialization that could be deserialized insecurely
            try {
                var NSKeyedArchiver = ObjC.classes.NSKeyedArchiver;
                if (NSKeyedArchiver) {
                    var archivedDataWithRootObject = NSKeyedArchiver["+ archivedDataWithRootObject:"];
                    if (archivedDataWithRootObject) {
                        Interceptor.attach(archivedDataWithRootObject.implementation, {
                            onEnter: function(args) {
                                this.rootObject = args[2];
                            },
                            onLeave: function(retval) {
                                try {
                                    console.log("\x1b[36m[i]\x1b[0m NSKeyedArchiver.archivedDataWithRootObject:");

                                    if (this.rootObject && !this.rootObject.isNull()) {
                                        var obj = ObjC.Object(this.rootObject);
                                        console.log("    Object Class: " + obj.$className);

                                        if (obj.$className.indexOf("NST") === 0 || obj.$className.indexOf("UI") === 0) {
                                            console.log("\x1b[33m[*]\x1b[0m System object being archived - monitor for gadget chains");
                                        }
                                    }

                                    if (retval && !retval.isNull()) {
                                        var dataObj = ObjC.Object(retval);
                                        console.log("    Archived Data Length: " + dataObj.length());
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m archivedDataWithRootObject error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSKeyedArchiver.archivedDataWithRootObject: hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m NSKeyedArchiver class not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSKeyedArchiver hook failed: " + e.message);
            }

            // Property list deserialization
            try {
                var NSPropertyListSerialization = ObjC.classes.NSPropertyListSerialization;
                if (NSPropertyListSerialization) {
                    var propertyListWithData = NSPropertyListSerialization["+ propertyListWithData:options:format:error:"];
                    if (propertyListWithData) {
                        Interceptor.attach(propertyListWithData.implementation, {
                            onEnter: function(args) {
                                this.data = args[2];
                                this.options = args[3].toInt32();
                            },
                            onLeave: function(retval) {
                                try {
                                    console.log("\x1b[36m[i]\x1b[0m NSPropertyListSerialization.propertyListWithData:");

                                    if (this.data && !this.data.isNull()) {
                                        var dataObj = ObjC.Object(this.data);
                                        console.log("    Data: " + nsDataToHex(dataObj, 64));
                                    }

                                    if (retval && !retval.isNull()) {
                                        var resultObj = ObjC.Object(retval);
                                        var resultClass = resultObj.$className;
                                        console.log("    Result Class: " + resultClass);

                                        if (resultClass === "NSDictionary" || resultClass === "__NSDictionaryI" || resultClass === "NSMutableDictionary") {
                                            console.log("\x1b[33m[*]\x1b[0m Dictionary deserialized - check for dangerous keys");
                                        }
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m propertyListWithData error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSPropertyListSerialization.propertyListWithData: hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m NSPropertyListSerialization class not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSPropertyListSerialization hook failed: " + e.message);
            }

            // JSON deserialization (JSONObjectWithData)
            try {
                var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
                if (NSJSONSerialization) {
                    var JSONObjectWithData = NSJSONSerialization["+ JSONObjectWithData:options:error:"];
                    if (JSONObjectWithData) {
                        Interceptor.attach(JSONObjectWithData.implementation, {
                            onEnter: function(args) {
                                this.data = args[2];
                            },
                            onLeave: function(retval) {
                                try {
                                    if (retval && !retval.isNull()) {
                                        var resultObj = ObjC.Object(retval);
                                        var resultClass = resultObj.$className;
                                        if (resultClass === "NSDictionary" || resultClass === "__NSDictionaryI" || resultClass === "NSMutableDictionary") {
                                            console.log("\x1b[36m[i]\x1b[0m NSJSONSerialization.JSONObjectWithData: Dictionary");
                                        }
                                    }
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m JSONObjectWithData error: " + ex.message);
                                }
                            }
                        });
                        console.log("\x1b[32m[+]\x1b[0m NSJSONSerialization.JSONObjectWithData: hooked");
                    }
                } else {
                    console.log("\x1b[31m[-]\x1b[0m NSJSONSerialization class not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSJSONSerialization hook failed: " + e.message);
            }

            // NSSecureCoding protocol check
            try {
                if (ObjC.classes.NSObject) {
                    console.log("\x1b[36m[*]\x1b[0m Scanning for classes conforming to NSSecureCoding...");

                    var secureCodingClasses = [];
                    var insecureClasses = [];

                    // ObjC.classes is a plain map (name -> binding), not an array.
                    Object.keys(ObjC.classes).forEach(function(className) {
                        try {
                            var classObj = ObjC.classes[className];
                            if (classObj.conformsToProtocol(ObjC.protocols.NSSecureCoding)) {
                                secureCodingClasses.push(className);
                            } else {
                                var classNameStr = className.toString();
                                if (classNameStr.indexOf("NS") === 0 || classNameStr.indexOf("UI") === 0) {
                                    if (classObj.respondsToSelector(ObjC.selector("initWithCoder:"))) {
                                        insecureClasses.push(classNameStr);
                                    }
                                }
                            }
                        } catch (e) {}
                    });

                    if (secureCodingClasses.length > 0) {
                        console.log("\x1b[32m[+]\x1b[0m Classes with NSSecureCoding: " + secureCodingClasses.slice(0, 10).join(", ") + (secureCodingClasses.length > 10 ? " ..." : ""));
                    }

                    if (insecureClasses.length > 0 && CONFIG.alertOnInsecure) {
                        console.log("\x1b[31m[!]\x1b[0m Classes WITHOUT NSSecureCoding but initWithCoder: (potential gadget chains):");
                        insecureClasses.slice(0, 20).forEach(function(cls) {
                            console.log("    - " + cls);
                        });
                        if (insecureClasses.length > 20) {
                            console.log("    ... and " + (insecureClasses.length - 20) + " more");
                        }
                    }
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSSecureCoding scan failed: " + e.message);
            }

            console.log("\x1b[33m[*]\x1b[0m Deserialization Hook iOS Script Loaded");
            console.log("\x1b[36m[*]\x1b[0m Monitoring for insecure deserialization vectors...");

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Deserialization Hook iOS error: " + e.message);
        }
    });

    setInterval(function() {
        if (deserializationCount > 0 || insecureCount > 0) {
            console.log("\x1b[36m[*]\x1b[0m Stats - Total: " + deserializationCount + " | Insecure: " + insecureCount);
        }
    }, 30000);

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
