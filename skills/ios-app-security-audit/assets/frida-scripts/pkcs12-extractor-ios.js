/**
 * PKCS#12 Extractor for iOS
 *
 * Description: Captures client certificates and their passphrases as the app
 *   imports them. Hooks SecPKCS12Import to grab the raw .p12/.pfx blob and the
 *   import passphrase (kSecImportExportPassphrase). The blob is dumped to disk
 *   (and base64-printed) so it can be re-imported into Burp/OpenSSL for mutual-
 *   TLS interception.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/security/1396915-secpkcs12import
 *   https://codeshare.frida.re/ (SecPKCS12Import hooking patterns)
 *   https://github.com/OWASP/owasp-mastg (key management chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l pkcs12-extractor-ios.js
 *   # Set OUT_DIR below to a device-writable directory (default: app tmp).
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0012 / M1 (Improper Credential Usage), M10 (Insufficient
 *   Cryptography)
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

    console.log('[*] PKCS#12 Extractor for iOS');

    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    // null => use NSTemporaryDirectory() (always app-writable).
    var OUT_DIR = null;

    function outDir() {
        if (OUT_DIR) return OUT_DIR;
        try {
            // NSTemporaryDirectory is a C function in Foundation, not an ObjC class.
            var tmpDirPtr = findExport('Foundation', 'NSTemporaryDirectory');
            if (tmpDirPtr) {
                var NSTemporaryDirectory = new NativeFunction(tmpDirPtr, 'pointer', []);
                var dirPtr = NSTemporaryDirectory();
                if (dirPtr && !dirPtr.isNull()) {
                    return new ObjC.Object(dirPtr).toString();
                }
            }
        } catch (e) { /* fall through */ }
        return '/tmp/';
    }

    var importPtr = findExport('Security', 'SecPKCS12Import') ||
        Module.getGlobalExportByName('SecPKCS12Import');

    if (!importPtr) {
        console.log('[-] SecPKCS12Import not found. Exiting.');
        return;
    }

    var counter = 0;

    // OSStatus SecPKCS12Import(CFDataRef pkcs12_data, CFDictionaryRef options,
    //                          CFArrayRef *items)
    Interceptor.attach(importPtr, {
        onEnter: function (args) {
            counter++;
            console.log('\n[+] SecPKCS12Import called (#' + counter + ')');

            // ---- passphrase from the options dictionary ----
            try {
                if (args[1] && !args[1].isNull()) {
                    var opts = new ObjC.Object(args[1]);
                    // kSecImportExportPassphrase == "passphrase"
                    var pw = opts.objectForKey_('passphrase');
                    if (pw && !pw.isNull()) {
                        console.log('    [PASSPHRASE] "' + pw.toString() + '"');
                    } else {
                        console.log('    [PASSPHRASE] (none / not in options dict)');
                    }
                }
            } catch (e) {
                console.log('    [-] passphrase read failed: ' + e);
            }
            try {
                if (args[0] && !args[0].isNull()) {
                    var data = new ObjC.Object(args[0]); // NSData / CFData
                    var len = data.length();
                    console.log('    [DATA] ' + len + ' bytes');

                    var b64 = data.base64EncodedStringWithOptions_(0).toString();
                    console.log('    [BASE64] ' + b64);

                    var path = outDir();
                    if (path.charAt(path.length - 1) !== '/') path += '/';
                    path += 'extracted_' + counter + '.p12';

                    var ok = data.writeToFile_atomically_(
                        ObjC.classes.NSString.stringWithString_(path), true);
                    if (ok) {
                        console.log('    [SAVED] ' + path);
                        console.log('            # openssl pkcs12 -in ' + path + ' -info -nodes');
                    } else {
                        console.log('    [-] writeToFile failed (path not writable?): ' + path);
                    }
                }
            } catch (e) {
                console.log('    [-] data dump failed: ' + e);
            }
        }
    });

    console.log('[+] Hooked SecPKCS12Import');
})();
