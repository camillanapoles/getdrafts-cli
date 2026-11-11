/**
 * Keyboard Security Auditor for iOS
 *
 * Description: Audits keyboard-related data-leakage risks:
 *   (a) THIRD-PARTY KEYBOARDS — whether the app allows custom keyboards by
 *       inspecting -[<AppDelegate> application:shouldAllowExtensionPointIdentifier:]
 *       (custom keyboards are ALLOWED by default if the app never implements it).
 *   (b) SENSITIVE FIELDS — snapshots live UITextField/UITextView instances and
 *       reports whether secureTextEntry and autocorrectionType are configured
 *       safely for fields that look sensitive (password/card/cvv/pin/ssn).
 *
 *   NOTE: third-party keyboard policy is controlled by
 *   shouldAllowExtensionPointIdentifier:, NOT by interface-orientation APIs.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623122-application
 *   https://developer.apple.com/documentation/uikit/uitextinputtraits
 *   https://github.com/OWASP/owasp-mastg (keyboard caching / data leakage)
 *
 * Usage:
 *   frida -U -f com.example.app -l keyboard-security-check-ios.js
 *   # The field audit auto-runs ~3s after launch; call auditTextFields() again
 *   # from the REPL after navigating to a login/payment screen.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0054 / M9 (Insecure Data Storage)
 *
 * Author: DragonJAR iOS Pentesting Skill
 * Version: 1.0.0
 * License: MIT
 */

(function () {
    'use strict';

    if (!ObjC.available) {
        console.log('[-] Objective-C runtime not available. Exiting.');
        return;
    }

    console.log('[*] Keyboard Security Auditor for iOS');

    var SENSITIVE = /pass|pwd|secret|card|cvv|cvc|ccv|pin|ssn|social|account|token|secure|otp|seed|mnemonic/i;

    // autocorrectionType enum: 0 = Default, 1 = No, 2 = Yes
    function autocorrectName(v) {
        return v === 1 ? 'No' : (v === 2 ? 'Yes' : 'Default(Yes for most)');
    }

    function checkKeyboardPolicy() {
        try {
            var app = ObjC.classes.UIApplication.sharedApplication();
            var delegate = app.delegate();
            if (!delegate) {
                console.log('[?] No UIApplication delegate yet.');
                return;
            }
            var clsName = delegate.$className;
            var cls = ObjC.classes[clsName];
            var sel = '- application:shouldAllowExtensionPointIdentifier:';

            if (cls && cls[sel]) {
                console.log('[+] ' + clsName + ' implements shouldAllowExtensionPointIdentifier:');
                Interceptor.attach(cls[sel].implementation, {
                    onEnter: function (args) {
                        try { this.identifier = new ObjC.Object(args[3]).toString(); }
                        catch (e) { this.identifier = '?'; }
                    },
                    onLeave: function (retval) {
                        var allowed = retval.toInt32() !== 0;
                        if (this.identifier &&
                            this.identifier.indexOf('keyboard') !== -1) {
                            console.log('[KBD] custom keyboard request "' + this.identifier +
                                '" -> ' + (allowed ? 'ALLOWED [!] (risk)' : 'BLOCKED (good)'));
                        }
                    }
                });
            } else {
                console.log('[!] ' + clsName + ' does NOT implement ' +
                    'application:shouldAllowExtensionPointIdentifier:');
                console.log('    -> Third-party keyboards are ALLOWED by default (data-leak risk).');
            }
        } catch (e) {
            console.log('[-] keyboard policy check failed: ' + e);
        }
    }

    function auditOne(field, kind) {
        try {
            var secure = false;
            try { secure = field.isSecureTextEntry(); } catch (e) { /* UITextView has none */ }
            var autocorrect = 0;
            try { autocorrect = field.autocorrectionType(); } catch (e) { /* ignore */ }

            var ph = '';
            try { if (field.placeholder && field.placeholder()) ph = field.placeholder().toString(); } catch (e) {}
            var looksSensitive = SENSITIVE.test(ph) || SENSITIVE.test(field.$className);

            var flags = [];
            if (looksSensitive && !secure && kind === 'UITextField') {
                flags.push('NOT secureTextEntry [!]');
            }
            if (looksSensitive && autocorrect !== 1) {
                flags.push('autocorrect=' + autocorrectName(autocorrect) + ' (caches input) [!]');
            }

            console.log('  ' + kind + ' "' + ph + '" secure=' + secure +
                ' autocorrect=' + autocorrectName(autocorrect) +
                (flags.length ? '  => ' + flags.join(', ') : ''));
        } catch (e) { /* ignore one field */ }
    }

    function auditTextFields() {
        ObjC.schedule(ObjC.mainQueue, function () {
            console.log('\n[*] Auditing live text fields...');
            try {
                ObjC.chooseSync(ObjC.classes.UITextField).forEach(function (f) {
                    auditOne(f, 'UITextField');
                });
            } catch (e) { /* ignore */ }
            try {
                ObjC.chooseSync(ObjC.classes.UITextView).forEach(function (f) {
                    auditOne(f, 'UITextView');
                });
            } catch (e) { /* ignore */ }
            console.log('[*] Field audit complete.');
        });
    }

    // Expose for manual re-runs from the Frida REPL.
    global.auditTextFields = auditTextFields;

    checkKeyboardPolicy();
    setTimeout(auditTextFields, 3000);

    console.log('[+] Keyboard auditor installed (call auditTextFields() after navigating)');
})();
