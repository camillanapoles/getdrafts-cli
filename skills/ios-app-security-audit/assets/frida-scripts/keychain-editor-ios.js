/**
 * Keychain Editor for iOS (runtime read interception)
 *
 * Description: Intercepts ALL Keychain operations at runtime. Hooks
 *   SecItemCopyMatching to (a) log every lookup and (b) inject alternative
 *   returned values for entries you target via CONFIG.overrides; and logs
 *   SecItemAdd / SecItemUpdate / SecItemDelete so you can see exactly what the
 *   app writes, updates, or clears (credentials, session tokens, flags). Handy
 *   for auth bypass, forcing a known session token, observing post-login
 *   storage, or testing how the app reacts to tampered secrets.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/security/1398306-secitemcopymatching
 *   https://codeshare.frida.re/@martinborse/ios-keychain-dumper/ (read patterns)
 *   https://github.com/OWASP/owasp-mastg (data storage chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l keychain-editor-ios.js
 *   # Edit CONFIG.overrides below: match by service/account, set the new value.
 *   # With no overrides the script is a passive Keychain-read logger.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0013 / M6 (Inadequate Privacy Controls), M3 (Insecure
 *   Authentication/Authorization)
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

    console.log('[*] Keychain Editor for iOS');

    var CONFIG = {
        overrides: [
            // { service: 'com.example.app', account: 'authToken', value: 'FORGED_TOKEN' },
            // { service: '', account: 'isPremium', value: 'true' },
        ]
    };

    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    var secItemCopyMatching = findExport('Security', 'SecItemCopyMatching') ||
        Module.getGlobalExportByName('SecItemCopyMatching');

    if (!secItemCopyMatching) {
        console.log('[-] SecItemCopyMatching not found. Exiting.');
        return;
    }

    // Keep injected NSData objects alive for the lifetime of the process.
    var injectedRefs = [];

    function findOverride(service, account) {
        for (var i = 0; i < CONFIG.overrides.length; i++) {
            var o = CONFIG.overrides[i];
            var svcOk = (!o.service || o.service === service);
            var accOk = (!o.account || o.account === account);
            if (svcOk && accOk) return o;
        }
        return null;
    }

    Interceptor.attach(secItemCopyMatching, {
        onEnter: function (args) {
            this.resultPtr = args[1]; // CFTypeRef *
            this.service = '';
            this.account = '';
            try {
                if (args[0] && !args[0].isNull()) {
                    var q = new ObjC.Object(args[0]);
                    var svc = q.objectForKey_('svce'); // kSecAttrService
                    var acc = q.objectForKey_('acct'); // kSecAttrAccount
                    if (svc && !svc.isNull()) this.service = svc.toString();
                    if (acc && !acc.isNull()) this.account = acc.toString();
                    var cls = q.objectForKey_('class'); // kSecClass
                    console.log('\n[KC read] class=' + (cls ? cls.toString() : '?') +
                        ' service="' + this.service + '" account="' + this.account + '"');
                }
            } catch (e) { /* ignore */ }
        },
        onLeave: function (retval) {
            var ov = findOverride(this.service, this.account);
            if (!ov) return;
            try {
                var nsValue = ObjC.classes.NSString
                    .stringWithString_(ov.value)
                    .dataUsingEncoding_(4); // NSUTF8StringEncoding
                injectedRefs.push(nsValue);

                if (this.resultPtr && !this.resultPtr.isNull()) {
                    this.resultPtr.writePointer(nsValue.handle);
                }
                retval.replace(ptr(0)); // errSecSuccess
                console.log('    [+] INJECTED value for service="' + this.service +
                    '" account="' + this.account + '" -> "' + ov.value + '"');
            } catch (e) {
                console.log('    [-] injection failed: ' + e);
            }
        }
    });

    function describeItem(dictPtr) {
        try {
            if (!dictPtr || dictPtr.isNull()) return '(none)';
            var d = new ObjC.Object(dictPtr);
            var cls = d.objectForKey_('class');   // kSecClass
            var svc = d.objectForKey_('svce');    // kSecAttrService
            var acc = d.objectForKey_('acct');    // kSecAttrAccount
            var hasData = d.objectForKey_('v_Data'); // kSecValueData
            return 'class=' + (cls && !cls.isNull() ? cls.toString() : '?') +
                ' service="' + (svc && !svc.isNull() ? svc.toString() : '') + '"' +
                ' account="' + (acc && !acc.isNull() ? acc.toString() : '') + '"' +
                (hasData && !hasData.isNull() ? ' [has value data]' : '');
        } catch (e) { return '(parse error)'; }
    }

    function hookSecItemOp(name, fields) {
        var p = findExport('Security', name) ||
            Module.getGlobalExportByName(name);
        if (!p) { console.log('[-] ' + name + ' not found'); return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                console.log('\n[KC ' + name.replace('SecItem', '').toLowerCase() + ']');
                fields.forEach(function (f) {
                    console.log('    ' + f.label + ': ' + describeItem(args[f.idx]));
                });
            }
        });
        console.log('[+] Hooked ' + name);
    }

    // OSStatus SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result)
    hookSecItemOp('SecItemAdd', [{ idx: 0, label: 'attributes' }]);
    // OSStatus SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate)
    hookSecItemOp('SecItemUpdate', [{ idx: 0, label: 'query' }, { idx: 1, label: 'changes' }]);
    hookSecItemOp('SecItemDelete', [{ idx: 0, label: 'query' }]);

    console.log('\n[+] Hooked SecItemCopyMatching (' +
        CONFIG.overrides.length + ' override(s) configured) + SecItemAdd/Update/Delete');
})();
