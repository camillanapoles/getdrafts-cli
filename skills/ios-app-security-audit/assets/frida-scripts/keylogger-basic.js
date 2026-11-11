/**
 * Keylogger Basic (BETA)
 *
 * WARNING: For authorized security audits only
 *
 * Hooks and logs text field input changes:
 * - Hook UITextFieldDelegate
 * - Hook UITextViewDelegate
 * - Hook UITextField notifications
 *
 * Compatible with: Frida 16.x+ and iOS 12-17
 * Usage: frida -U -f <bundle_id> -l keylogger-basic.js
 * OWASP MASVS: MSTG-STR-2
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m Keylogger Basic Script Started (BETA)");
    console.log("\x1b[33m[*]\x1b[0m WARNING: For authorized security audits only");

    var CONFIG = {
        maxLength: 50,
        logFieldNames: true,
        logChanges: true,
        DEBUG_MODE: false
    };

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            var UITextField = ObjC.classes.UITextField;
            var UITextView = ObjC.classes.UITextView;
            var NSNotificationCenter = ObjC.classes.NSNotificationCenter;

            function truncateText(text, maxLength) {
                if (!text) return "null";
                maxLength = maxLength || CONFIG.maxLength;
                if (text.length() <= maxLength) return text.toString();
                return text.toString().substring(0, maxLength) + "...";
            }

            function getFieldName(field) {
                if (!CONFIG.logFieldNames) return "<field>";

                try {
                    var placeholder = "";
                    var accessibilityLabel = "";

                    if (field.$className === "UITextField") {
                        placeholder = field.placeholder();
                        accessibilityLabel = field.accessibilityLabel();
                    } else if (field.$className === "UITextView") {
                        accessibilityLabel = field.accessibilityLabel();
                    }

                    if (placeholder && !placeholder.isNil()) {
                        return "UITextField[" + placeholder.toString() + "]";
                    } else if (accessibilityLabel && !accessibilityLabel.isNil()) {
                        return field.$className + "[" + accessibilityLabel.toString() + "]";
                    } else {
                        return field.$className + "[" + field.toString().substring(0, 20) + "]";
                    }
                } catch (e) {
                    return "<field>";
                }
            }

            if (CONFIG.logChanges) {
                try {
                    var originalShouldChangeCharacters = UITextField["- textField:shouldChangeCharactersInRange:replacementString:"];
                    const originalImpl = new NativeFunction(
                        originalShouldChangeCharacters.implementation,
                        'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
                    );

                    const bypassCallback = new NativeCallback(function(self, _cmd, textField, range, string) {
                        var tfObj = new ObjC.Object(textField);
                        var fieldName = getFieldName(tfObj);
                        var oldText = tfObj.text();
                        var newString = string && !ptr(string).isNull() ? new ObjC.Object(string).toString() : "";

                        console.log("\x1b[32m[+]\x1b[0m UITextField.textField:shouldChangeCharactersInRange:replacementString:");
                        console.log("    Field: " + fieldName);
                        console.log("    Old Text: " + truncateText(oldText));
                        console.log("    Replacement: " + truncateText(newString));

                        var result = originalImpl(self, _cmd, textField, range, string);

                        console.log("    Will change: " + (result ? "YES" : "NO"));

                        return result;
                    }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                    Interceptor.replace(originalShouldChangeCharacters.implementation, bypassCallback);

                    console.log("\x1b[32m[+]\x1b[0m UITextFieldDelegate.textField:shouldChangeCharactersInRange:replacementString: hooked successfully");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m UITextFieldDelegate.textField:shouldChangeCharactersInRange:replacementString: hook failed: " + e.message);
                }
            }

            if (CONFIG.logChanges) {
                var hookedDelegates = 0;
                try {
                    var protocol = ObjC.protocols.UITextViewDelegate;
                    if (protocol) {
                        var classes = ObjC.copyClassList ? ObjC.copyClassList() : Object.keys(ObjC.classes);
                        for (var ci = 0; ci < classes.length; ci++) {
                            var className = classes[ci];
                            var cls = ObjC.classes[className];
                            if (!cls) continue;
                            try {
                                if (!cls.conformsToProtocol_(protocol)) continue;
                            } catch (_) {
                                continue;
                            }
                            var impl = cls["- textViewDidChange:"];
                            if (!impl) continue;
                            (function (targetClass, method) {
                                // Capture the original NativePointer BEFORE replacing.
                                const origImpl = new NativeFunction(
                                    method.implementation,
                                    'void', ['pointer', 'pointer', 'pointer']
                                );

                                const bypassCallback = new NativeCallback(function (self, _cmd, textView) {
                                    var tvObj = new ObjC.Object(textView);
                                    var fieldName = getFieldName(tvObj);
                                    var text = tvObj.text();
                                    console.log("\x1b[32m[+]\x1b[0m " + targetClass.$className + ".textViewDidChange:");
                                    console.log("    Field: " + fieldName);
                                    console.log("    Text: " + truncateText(text));
                                    return origImpl(self, _cmd, textView);
                                }, 'void', ['pointer', 'pointer', 'pointer']);

                                Interceptor.replace(method.implementation, bypassCallback);
                                hookedDelegates++;
                            })(cls, impl);
                        }
                    }
                    console.log("\x1b[32m[+]\x1b[0m textViewDidChange: hooked on " + hookedDelegates + " delegate class(es)");
                } catch (e) {
                    console.log("\x1b[31m[!]\x1b[0m textViewDidChange: hook failed: " + e.message);
                }
            }

            try {
                var textDidChangeNotification = ObjC.classes.NSString.stringWithString_("UITextFieldTextDidChangeNotification");
                var defaultCenter = NSNotificationCenter.defaultCenter();

                var originalAddObserver = defaultCenter["- addObserver:selector:name:object:"];
                const originalImpl = new NativeFunction(
                    originalAddObserver.implementation,
                    'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, _cmd, observer, selector, name, object) {
                    originalImpl(self, _cmd, observer, selector, name, object);

                    if (name && !ptr(name).isNull()) {
                        try {
                            var nameStr = new ObjC.Object(name).toString();
                            if (nameStr === "UITextFieldTextDidChangeNotification" ||
                                nameStr === "UITextViewTextDidChangeNotification") {
                                console.log("\x1b[32m[+]\x1b[0m Observer registered for: " + nameStr);
                            }
                        } catch (_) {}
                    }
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalAddObserver.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m NSNotificationCenter.addObserver hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m NSNotificationCenter.addObserver hook failed: " + e.message);
            }

            try {
                var originalSetText = UITextField["- setText:"];
                const originalImpl = new NativeFunction(
                    originalSetText.implementation,
                    'void', ['pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, _cmd, text) {
                    var selfObj = new ObjC.Object(self);
                    var fieldName = getFieldName(selfObj);

                    console.log("\x1b[32m[+]\x1b[0m UITextField.setText:");
                    console.log("    Field: " + fieldName);
                    console.log("    Text: " + truncateText(text && !ptr(text).isNull() ? new ObjC.Object(text) : null));

                    return originalImpl(self, _cmd, text);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalSetText.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m UITextField.setText: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UITextField.setText: hook failed: " + e.message);
            }

            try {
                var originalTVSetText = UITextView["- setText:"];
                const originalImpl = new NativeFunction(
                    originalTVSetText.implementation,
                    'void', ['pointer', 'pointer', 'pointer']
                );

                const bypassCallback = new NativeCallback(function(self, _cmd, text) {
                    var selfObj = new ObjC.Object(self);
                    var fieldName = getFieldName(selfObj);

                    console.log("\x1b[32m[+]\x1b[0m UITextView.setText:");
                    console.log("    Field: " + fieldName);
                    console.log("    Text: " + truncateText(text && !ptr(text).isNull() ? new ObjC.Object(text) : null));

                    return originalImpl(self, _cmd, text);
                }, 'void', ['pointer', 'pointer', 'pointer']);

                Interceptor.replace(originalTVSetText.implementation, bypassCallback);

                console.log("\x1b[32m[+]\x1b[0m UITextView.setText: hooked successfully");
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m UITextView.setText: hook failed: " + e.message);
            }

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m Keylogger Basic error: " + e.message);
        }
    });

    console.log("\x1b[33m[*]\x1b[0m Keylogger Basic Script Loaded");
} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
