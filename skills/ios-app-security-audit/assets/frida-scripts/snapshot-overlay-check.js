/**
 * App-Switcher Snapshot Protection Check for iOS
 *
 * Description: Verifies whether an app hides sensitive content before iOS takes
 *   the app-switcher snapshot. When an app backgrounds, iOS captures a screen
 *   image that persists on disk and shows in the multitasking switcher. Secure
 *   apps add a privacy overlay (blur/cover view) or hide the window in
 *   applicationDidEnterBackground:/applicationWillResignActive:. This script
 *   observes those lifecycle callbacks and reports whether a protective change
 *   to the key window was made — WITHOUT altering app behavior.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623111-applicationdidenterbackground
 *   https://github.com/OWASP/owasp-mastg (MASTG-TEST-0021 backgrounding)
 *
 * Usage:
 *   frida -U -f com.example.app -l snapshot-overlay-check.js
 *   # Background the app (Home / app-switcher) and read the verdict.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0021 / M9 (Insecure Data Storage)
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

    console.log('[*] App-Switcher Snapshot Protection Check for iOS');

    function keyWindow() {
        try {
            var app = ObjC.classes.UIApplication.sharedApplication();
            var w = app.keyWindow();
            if (w && !w.isNull()) return w;
            // iOS 13+ scenes: fall back to the first window.
            var windows = app.windows();
            if (windows && windows.count() > 0) return windows.objectAtIndex_(0);
        } catch (e) { /* ignore */ }
        return null;
    }

    function snapshotState() {
        var st = { subviews: 0, hidden: false, hasOverlay: false };
        var w = keyWindow();
        if (!w) return st;
        try {
            st.hidden = w.isHidden();
            var subs = w.subviews();
            st.subviews = subs ? subs.count() : 0;
            for (var i = 0; i < st.subviews; i++) {
                var v = subs.objectAtIndex_(i);
                var cn = v.$className;
                if (/VisualEffect|Blur|Privacy|Cover|Splash|Overlay|Secure/i.test(cn)) {
                    st.hasOverlay = true;
                }
            }
        } catch (e) { /* ignore */ }
        return st;
    }

    function verdict(before, after) {
        var protectedNow =
            after.hidden ||
            after.hasOverlay ||
            (after.subviews > before.subviews);

        if (protectedNow) {
            console.log('[+] PROTECTED: snapshot mitigation detected ' +
                '(hidden=' + after.hidden + ', overlay=' + after.hasOverlay +
                ', subviews ' + before.subviews + '->' + after.subviews + ')');
        } else {
            console.log('[!] VULNERABLE: no overlay/hide before backgrounding. ' +
                'iOS will snapshot the live (sensitive) UI. [MASTG-TEST-0021]');
        }
    }

    function hookLifecycle(sel) {
        try {
            var app = ObjC.classes.UIApplication.sharedApplication();
            var delegate = app.delegate();
            if (!delegate) return false;
            var cls = ObjC.classes[delegate.$className];
            if (!cls || !cls[sel]) return false;

            Interceptor.attach(cls[sel].implementation, {
                onEnter: function () {
                    this.before = snapshotState();
                    console.log('\n[*] ' + sel + ' (window subviews=' + this.before.subviews + ')');
                },
                onLeave: function () {
                    var after = snapshotState();
                    verdict(this.before, after);
                }
            });
            console.log('[+] Observing ' + delegate.$className + ' ' + sel);
            return true;
        } catch (e) {
            console.log('[-] hook failed for ' + sel + ': ' + e);
            return false;
        }
    }
    var hookedSceneClasses = {};
    function hookSceneLifecycle(sel) {
        var any = false;
        try {
            var app = ObjC.classes.UIApplication.sharedApplication();
            if (!app.respondsToSelector_(ObjC.selector('connectedScenes'))) return false;
            var scenes = app.connectedScenes();
            if (!scenes || scenes.isNull()) return false;
            var arr = scenes.allObjects();
            var n = arr.count();
            for (var i = 0; i < n; i++) {
                var del = arr.objectAtIndex_(i).delegate();
                if (!del || del.isNull()) continue;
                var clsName = del.$className;
                var key = clsName + ' ' + sel;
                if (hookedSceneClasses[key]) { any = true; continue; }
                var cls = ObjC.classes[clsName];
                if (!cls || !cls[sel]) continue;
                Interceptor.attach(cls[sel].implementation, {
                    onEnter: function () {
                        this.before = snapshotState();
                        console.log('\n[*] ' + sel + ' (window subviews=' + this.before.subviews + ')');
                    },
                    onLeave: function () {
                        verdict(this.before, snapshotState());
                    }
                });
                hookedSceneClasses[key] = true;
                console.log('[+] Observing ' + clsName + ' ' + sel + ' (scene)');
                any = true;
            }
        } catch (e) {
            console.log('[-] scene hook failed for ' + sel + ': ' + e);
        }
        return any;
    }

    var hooked = false;
    hooked = hookLifecycle('- applicationWillResignActive:') || hooked;
    hooked = hookLifecycle('- applicationDidEnterBackground:') || hooked;
    hooked = hookSceneLifecycle('- sceneWillResignActive:') || hooked;
    hooked = hookSceneLifecycle('- sceneDidEnterBackground:') || hooked;

    if (!hooked) {
        console.log('[!] Neither UIApplicationDelegate nor UIWindowSceneDelegate implement the');
        console.log('    backgrounding callbacks — the app adds no snapshot overlay there → likely VULNERABLE.');
        console.log('    [MASTG-TEST-0021]');
    }

    console.log('[+] Snapshot protection check active — background the app now.');
})();
