/**
 * Proxy / VPN Detection Bypass for iOS
 *
 * Description: Hides the active HTTP proxy (and common VPN) configuration from
 *   apps that refuse to run when a proxy is set (a frequent MITM countermeasure).
 *   Replaces the system proxy settings dictionary with an empty (no-proxy) one:
 *     - CFNetworkCopySystemProxySettings()        -> empty CFDictionary
 *     - CFNetworkCopyProxiesForURL()              -> array with kCFProxyTypeNone
 *     - -[NSURLSessionConfiguration connectionProxyDictionary] -> empty dict
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/cfnetwork/1426754-cfnetworkcopysystemproxysettings
 *   https://codeshare.frida.re/ (proxy-detection bypass patterns)
 *   https://github.com/OWASP/owasp-mastg (network interception chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l proxy-detection-bypass-ios.js
 *   # Pair with ssl-pinning-bypass-ios.js for full MITM-friendly testing.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0011 / M5 (Insecure Communication)
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

    // Frida 17: getModuleByName() throws when the module is not loaded and
    // getExportByName() throws when the symbol is missing; the "find" variants return null.
    function findExport(moduleName, symbolName) {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(symbolName) : null;
    }

    console.log('[*] Proxy / VPN Detection Bypass for iOS');
    var copySysProxy = findExport('CFNetwork', 'CFNetworkCopySystemProxySettings');
    if (!copySysProxy) {
        copySysProxy = Module.getGlobalExportByName('CFNetworkCopySystemProxySettings');
    }
    if (copySysProxy) {
        try {
            Interceptor.replace(copySysProxy, new NativeCallback(function () {
                console.log('[+] CFNetworkCopySystemProxySettings -> empty (no proxy)');
                // alloc/init => retainCount 1, matching CF "Copy" ownership.
                var empty = ObjC.classes.NSDictionary.alloc().init();
                return empty;
            }, 'pointer', []));
            console.log('[+] Hooked CFNetworkCopySystemProxySettings');
        } catch (e) {
            console.log('[-] CFNetworkCopySystemProxySettings hook failed: ' + e);
        }
    } else {
        console.log('[-] CFNetworkCopySystemProxySettings not found');
    }
    var copyProxiesForURL = findExport('CFNetwork', 'CFNetworkCopyProxiesForURL');
    if (copyProxiesForURL) {
        try {
            Interceptor.replace(copyProxiesForURL, new NativeCallback(function (url, settings) {
                console.log('[+] CFNetworkCopyProxiesForURL -> [kCFProxyTypeNone]');
                // Build { kCFProxyTypeKey : kCFProxyTypeNone } inside an array.
                var typeKey = ObjC.classes.NSString.stringWithString_('kCFProxyType');
                var typeNone = ObjC.classes.NSString.stringWithString_('kCFProxyTypeNone');
                var dict = ObjC.classes.NSDictionary.dictionaryWithObject_forKey_(typeNone, typeKey);
                var arr = ObjC.classes.NSArray.alloc().initWithObjects_(dict, null);
                return arr;
            }, 'pointer', ['pointer', 'pointer']));
            console.log('[+] Hooked CFNetworkCopyProxiesForURL');
        } catch (e) {
            console.log('[-] CFNetworkCopyProxiesForURL hook failed: ' + e);
        }
    }
    try {
        var cfg = ObjC.classes.NSURLSessionConfiguration;
        if (cfg && cfg['- connectionProxyDictionary']) {
            Interceptor.attach(cfg['- connectionProxyDictionary'].implementation, {
                onLeave: function (retval) {
                    var empty = ObjC.classes.NSDictionary.dictionary();
                    retval.replace(empty);
                    console.log('[+] NSURLSessionConfiguration.connectionProxyDictionary -> empty');
                }
            });
            console.log('[+] Hooked NSURLSessionConfiguration.connectionProxyDictionary');
        }
    } catch (e) {
        console.log('[-] connectionProxyDictionary hook failed: ' + e);
    }

    console.log('[+] Proxy detection bypass installed');
})();
