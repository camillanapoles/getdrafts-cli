/**
 * Managed App Configuration Inspector for iOS (MDM)
 *
 * Description: Dumps the MDM-delivered managed configuration of an app. iOS
 *   exposes MDM "App Config" values via NSUserDefaults under the well-known key
 *   "com.apple.configuration.managed" (and feedback under
 *   "com.apple.feedback.managed"). This script reads and recursively prints
 *   that configuration and flags secrets pushed by the MDM server (API tokens,
 *   passwords, internal URLs) — useful for enterprise/MDM audits.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/foundation/userdefaults
 *   https://www.apple.com/business/docs/site/AppConfig_Best_Practices.pdf
 *   https://github.com/OWASP/owasp-mastg (platform / MDM chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l managed-app-inspector.js
 *   # Re-run dumpManagedConfig() from the REPL after the app reads its config.
 *
 * iOS Target: iOS 12 - 17 (managed app config requires an MDM-enrolled device).
 * MASTG: MASTG-TEST-0002 / M8 (Security Misconfiguration)
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

    console.log('[*] Managed App Configuration Inspector for iOS');

    var MANAGED_KEYS = [
        'com.apple.configuration.managed',
        'com.apple.feedback.managed'
    ];
    var SENSITIVE = /token|password|secret|key|credential|url|api|cert|pin|auth/i;

    function describe(value) {
        if (value === null || value.isNull()) return '<null>';
        var cn = value.$className;
        if (/String/.test(cn)) return '"' + value.toString() + '"';
        if (/Number|Boolean/.test(cn)) return value.toString();
        if (/Data/.test(cn)) return '<NSData ' + value.length() + ' bytes>';
        return value.toString();
    }

    function dumpDict(dict, indent) {
        try {
            var keys = dict.allKeys();
            var n = keys.count();
            for (var i = 0; i < n; i++) {
                var key = keys.objectAtIndex_(i);
                var keyStr = key.toString();
                var val = dict.objectForKey_(key);
                var sensitive = SENSITIVE.test(keyStr);

                if (val && !val.isNull() && /Dictionary/.test(val.$className)) {
                    console.log(indent + keyStr + ':');
                    dumpDict(val, indent + '  ');
                } else if (val && !val.isNull() && /Array/.test(val.$className)) {
                    console.log(indent + keyStr + ': [array, ' + val.count() + ' items]');
                    for (var a = 0; a < val.count(); a++) {
                        console.log(indent + '  - ' + describe(val.objectAtIndex_(a)));
                    }
                } else {
                    console.log(indent + keyStr + ' = ' + describe(val) +
                        (sensitive ? '   [!] sensitive' : ''));
                }
            }
        } catch (e) {
            console.log(indent + '[-] dump error: ' + e);
        }
    }

    function dumpManagedConfig() {
        var defaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
        var found = false;

        MANAGED_KEYS.forEach(function (k) {
            try {
                var dict = defaults.dictionaryForKey_(k);
                if (dict && !dict.isNull() && dict.count() > 0) {
                    found = true;
                    console.log('\n[+] ' + k + ' (' + dict.count() + ' keys):');
                    dumpDict(dict, '    ');
                }
            } catch (e) { /* ignore */ }
        });

        // Some apps read managed config from a custom suite name.
        try {
            var bundleId = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
            var suiteName = bundleId + '.managed';
            var suite = ObjC.classes.NSUserDefaults.alloc().initWithSuiteName_(suiteName);
            if (suite && !suite.isNull()) {
                var rep = suite.dictionaryRepresentation();
                if (rep && rep.count() > 0) {
                    console.log('\n[+] suite "' + suiteName + '":');
                    dumpDict(rep, '    ');
                    found = true;
                }
            }
        } catch (e) { /* ignore */ }

        if (!found) {
            console.log('[!] No managed configuration present.');
            console.log('    Device may not be MDM-enrolled, or the app has no App Config.');
        }
    }

    // Expose for manual re-runs from the Frida REPL.
    global.dumpManagedConfig = dumpManagedConfig;

    dumpManagedConfig();

    console.log('\n[+] Done. Re-run with dumpManagedConfig() after config is fetched.');
})();
