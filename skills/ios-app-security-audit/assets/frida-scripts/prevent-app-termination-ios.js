/**
 * Prevent App Termination for iOS
 *
 * Description: Stops an app from killing itself during instrumentation.
 *   Anti-tamper logic frequently calls exit()/abort() (or kill(getpid(),
 *   SIGKILL)) the instant it detects Frida, a debugger, or a failed integrity
 *   check. This script neutralizes those self-termination paths so you can keep
 *   analyzing. It does NOT stop the OS-enforced watchdog kill of a hung main
 *   thread — it only blocks the app's own termination calls.
 *
 * Source (consolidated):
 *   https://codeshare.frida.re/ (anti-tamper / exit-blocking patterns)
 *   https://github.com/OWASP/owasp-mastg (anti-tamper chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l prevent-app-termination-ios.js
 *   # Load FIRST (spawn with -f) and combine with rasp-bypass-ios.js +
 *   # anti-debugging-bypass-ios.js so the checks pass instead of merely
 *   # being prevented from quitting.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0016 / M7 (Insufficient Binary Protection)
 *
 * Author: DragonJAR iOS Pentesting Skill
 * Version: 1.0.0
 * License: MIT
 */

(function () {
    'use strict';

    console.log('[*] Prevent App Termination for iOS');
    // The summary reports what was really installed: a private API that is
    // absent must not be announced as a working guard.
    var guardsInstalled = 0;
    ['exit', '_exit', '_Exit'].forEach(function (name) {
        var p = Module.getGlobalExportByName(name);
        if (!p) return;
        try {
            Interceptor.replace(p, new NativeCallback(function (code) {
                console.log('[+] Blocked ' + name + '(' + code + ')');
            }, 'void', ['int']));
            console.log('[+] Hooked ' + name);
            guardsInstalled++;
        } catch (e) {
            console.log('[-] ' + name + ' hook failed: ' + e);
        }
    });

    var abortPtr = Module.getGlobalExportByName('abort');
    if (abortPtr) {
        try {
            Interceptor.replace(abortPtr, new NativeCallback(function () {
                console.log('[+] Blocked abort()');
            }, 'void', []));
            console.log('[+] Hooked abort');
            guardsInstalled++;
        } catch (e) {
            console.log('[-] abort hook failed: ' + e);
        }
    }
    var killPtr = Module.getGlobalExportByName('kill');
    var getpidPtr = Module.getGlobalExportByName('getpid');
    if (killPtr && getpidPtr) {
        try {
            var killOrig = new NativeFunction(killPtr, 'int', ['int', 'int']);
            var getpid = new NativeFunction(getpidPtr, 'int', []);
            var SIGKILL = 9, SIGTERM = 15, SIGSTOP = 17, SIGABRT = 6;
            var selfPid = getpid();

            Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
                var isSelf = (pid === selfPid || pid === 0 || pid === -1);
                var isTerm = (sig === SIGKILL || sig === SIGTERM ||
                    sig === SIGSTOP || sig === SIGABRT);
                if (isSelf && isTerm) {
                    console.log('[+] Blocked self-kill(pid=' + pid + ', sig=' + sig + ')');
                    return 0;
                }
                return killOrig(pid, sig);
            }, 'int', ['int', 'int']));
            console.log('[+] Hooked kill (self-termination filter)');
            guardsInstalled++;
        } catch (e) {
            console.log('[-] kill hook failed: ' + e);
        }
    }
    if (ObjC.available) {
        try {
            var UIApplication = ObjC.classes.UIApplication;
            if (UIApplication && UIApplication['- terminateWithSuccess']) {
                var method = UIApplication['- terminateWithSuccess'];
                Interceptor.replace(method.implementation, new NativeCallback(function (self, sel) {
                    console.log('[+] Blocked -[UIApplication terminateWithSuccess]');
                }, 'void', ['pointer', 'pointer']));
                console.log('[+] Replaced -[UIApplication terminateWithSuccess] with no-op');
                guardsInstalled++;
            }
        } catch (e) {
            console.log('[-] -[UIApplication terminateWithSuccess] unavailable: ' + e);
        }
    }

    if (guardsInstalled > 0) {
        console.log('[+] Termination guards installed: ' + guardsInstalled);
    } else {
        console.log('[-] No termination guard could be installed');
    }
})();
