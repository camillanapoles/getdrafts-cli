/**
 * Jailbreak Detection Tracer for iOS (non-destructive recon)
 *
 * Description: Maps HOW an app detects jailbreak — WITHOUT bypassing anything.
 *   Traces the paths and APIs the app probes (file existence, URL schemes,
 *   stat/access/fopen syscalls) and flags hits that match known jailbreak
 *   indicators. Run this FIRST to understand the detection surface, then use
 *   jailbreak-detection-bypass.js to defeat exactly what you observed.
 *
 * Source (consolidated):
 *   https://github.com/OWASP/owasp-mastg (anti-tamper / jailbreak chapter)
 *   https://codeshare.frida.re/ (jailbreak detection tracing patterns)
 *
 * Usage:
 *   frida -U -f com.example.app -l jailbreak-detection-tracer-ios.js
 *   # Read-only: never modifies return values. Set CONFIG.backtrace = true
 *   # to print the caller stack for each suspicious check.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0015 / M7 (Insufficient Binary Protection)
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

    console.log('[*] Jailbreak Detection Tracer for iOS (read-only)');

    var CONFIG = { backtrace: false };

    var JB_MARKERS = [
        'cydia', 'sileo', 'zebra', 'installer', 'apt', 'dpkg',
        '/bin/bash', '/bin/sh', '/usr/sbin/sshd', '/usr/bin/ssh',
        'mobilesubstrate', 'substrate', 'substitute', 'frida', 'cycript',
        'tweak', 'jailbreak', '/private/var/lib', '/private/var/stash',
        '/private/var/mobile/library/sbsettings', 'libhooker',
        'electra', 'chimera', 'unc0ver', 'checkra', 'taurine', 'rootless'
    ];

    function isSuspicious(s) {
        if (!s) return false;
        var lower = s.toLowerCase();
        for (var i = 0; i < JB_MARKERS.length; i++) {
            if (lower.indexOf(JB_MARKERS[i]) !== -1) return true;
        }
        return false;
    }

    function report(api, value) {
        var suspicious = isSuspicious(value);
        var tag = suspicious ? '[JB?] ' : '      ';
        console.log(tag + api + ' -> ' + value);
        if (suspicious && CONFIG.backtrace) {
            try {
                console.log('        ' + Thread.backtrace(this && this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).slice(0, 6).join('\n        '));
            } catch (e) { /* ignore */ }
        }
    }

    function attachObjC(cls, sel, argIndex, api) {
        try {
            var m = ObjC.classes[cls][sel];
            if (!m) return;
            Interceptor.attach(m.implementation, {
                onEnter: function (args) {
                    try {
                        var obj = new ObjC.Object(args[argIndex]);
                        report.call(this, api, obj.toString());
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Tracing ' + api);
        } catch (e) { /* class/method absent */ }
    }

    attachObjC('NSFileManager', '- fileExistsAtPath:', 2, '-[NSFileManager fileExistsAtPath:]');
    attachObjC('NSFileManager', '- fileExistsAtPath:isDirectory:', 2, '-[NSFileManager fileExistsAtPath:isDirectory:]');
    attachObjC('NSFileManager', '- isReadableFileAtPath:', 2, '-[NSFileManager isReadableFileAtPath:]');
    attachObjC('UIApplication', '- canOpenURL:', 2, '-[UIApplication canOpenURL:]');

    function attachNative(name, api) {
        var p = Module.getGlobalExportByName(name);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        if (args[0] && !args[0].isNull()) {
                            report.call(this, api, args[0].readUtf8String());
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Tracing ' + api);
        } catch (e) { /* ignore */ }
    }

    attachNative('stat', 'stat()');
    attachNative('lstat', 'lstat()');
    attachNative('stat64', 'stat64()');
    attachNative('access', 'access()');
    attachNative('fopen', 'fopen()');
    attachNative('open', 'open()');

    console.log('[+] Tracer active. [JB?] marks paths/URLs matching jailbreak indicators.');
    console.log('    Nothing is bypassed — run jailbreak-detection-bypass.js next.');
})();
