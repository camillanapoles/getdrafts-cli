/**
 * WKWebView Web Inspector Enabler for iOS
 *
 * Description: Force-enables Safari Web Inspector on WKWebView instances in
 *   production builds, where it is normally disabled. Once enabled, the app's
 *   web content shows up in Safari > Develop, exposing the DOM, JS console,
 *   network, and storage of the embedded web layer. Covers both the modern
 *   API (WKWebView.isInspectable, iOS 16.4+) and the legacy private preference
 *   (_developerExtrasEnabled / _setDeveloperExtrasEnabled:).
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/webkit/wkwebview/4111163-isinspectable
 *   https://codeshare.frida.re/ (WKWebView inspector patterns)
 *   https://github.com/OWASP/owasp-mastg (WebViews chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l webview-inspector-enable-ios.js
 *   # Then open Safari (macOS) > Develop > [device] > [app web view].
 *
 * iOS Target: iOS 12 - 17 (isInspectable applies to iOS 16.4+; the private
 *   preference covers earlier versions).
 * MASTG: MASTG-TEST-0045 / M4 (Insufficient Input/Output Validation), M8
 *   (Security Misconfiguration)
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

    console.log('[*] WKWebView Web Inspector Enabler for iOS');

    var WKWebView = ObjC.classes.WKWebView;
    if (!WKWebView) {
        console.log('[-] WKWebView class not present (app may use UIWebView).');
    }
    if (WKWebView && WKWebView['- isInspectable']) {
        try {
            Interceptor.attach(WKWebView['- isInspectable'].implementation, {
                onLeave: function (retval) {
                    if (retval.toInt32() === 0) {
                        retval.replace(ptr(1));
                        console.log('[+] -[WKWebView isInspectable] -> YES');
                    }
                }
            });
            console.log('[+] Hooked -[WKWebView isInspectable]');
        } catch (e) {
            console.log('[-] isInspectable hook failed: ' + e);
        }
    }
    function markInspectable(viewPtr) {
        try {
            var view = new ObjC.Object(viewPtr);
            if (view.respondsToSelector_(ObjC.selector('setInspectable:'))) {
                view.setInspectable_(true);
            }
            // Legacy private preference path (iOS < 16.4).
            try {
                var cfg = view.configuration();
                if (cfg) {
                    var prefs = cfg.preferences();
                    if (prefs && prefs.respondsToSelector_(ObjC.selector('_setDeveloperExtrasEnabled:'))) {
                        prefs['_setDeveloperExtrasEnabled:'](true);
                    } else if (prefs) {
                        prefs.setValue_forKey_(
                            ObjC.classes.NSNumber.numberWithBool_(true),
                            ObjC.classes.NSString.stringWithString_('developerExtrasEnabled'));
                    }
                }
            } catch (e) { /* legacy path optional */ }
        } catch (e) { /* ignore */ }
    }

    // The summary reports what was really installed: a selector that does not
    // exist leaves nothing hooked, and saying otherwise is false coverage.
    var hooksInstalled = 0;
    var initSelectors = ['- initWithFrame:configuration:', '- initWithCoder:', '- initWithFrame:'];
    initSelectors.forEach(function (sel) {
        if (!WKWebView || !WKWebView[sel]) return;
        try {
            Interceptor.attach(WKWebView[sel].implementation, {
                onLeave: function (retval) {
                    if (retval && !retval.isNull()) {
                        markInspectable(retval);
                        console.log('[+] WKWebView ' + sel + ' -> inspectable enabled');
                    }
                }
            });
            console.log('[+] Hooked WKWebView ' + sel);
            hooksInstalled++;
        } catch (e) {
            console.log('[-] Hook WKWebView ' + sel + ' failed: ' + e);
        }
    });

    if (hooksInstalled > 0) {
        console.log('[+] Web Inspector enabling hooks installed: ' + hooksInstalled);
    } else {
        console.log('[-] No Web Inspector hook could be installed');
    }
})();
