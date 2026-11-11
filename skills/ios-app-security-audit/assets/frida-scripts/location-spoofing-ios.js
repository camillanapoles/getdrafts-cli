/**
 * Location Spoofing for iOS (CLLocationManager)
 *
 * Description: Feeds the app fake GPS coordinates. Replaces the CLLocation
 *   objects delivered through CoreLocation so the app believes the device is
 *   somewhere else. Hooks the live location getter and rewrites the delegate
 *   callbacks (locationManager:didUpdateLocations: and the deprecated
 *   locationManager:didUpdateToLocation:fromLocation:). Configure the target
 *   latitude/longitude at the top of the script.
 *
 * Source (consolidated):
 *   https://developer.apple.com/documentation/corelocation/cllocationmanager
 *   https://codeshare.frida.re/ (CoreLocation spoofing patterns)
 *   https://github.com/OWASP/owasp-mastg (platform interaction chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l location-spoofing-ios.js
 *   # Edit CONFIG.latitude / CONFIG.longitude below before running.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0073 / M4 (Insufficient Input/Output Validation)
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

    var CONFIG = {
        latitude: 4.710989,
        longitude: -74.072092,
        altitude: 2640.0,
        horizontalAccuracy: 5.0,
        verticalAccuracy: 5.0
    };

    console.log('[*] Location Spoofing for iOS -> (' +
        CONFIG.latitude + ', ' + CONFIG.longitude + ')');

    var CLLocation = ObjC.classes.CLLocation;
    var CLLocationManager = ObjC.classes.CLLocationManager;

    if (!CLLocation || !CLLocationManager) {
        console.log('[-] CoreLocation classes not present. Exiting.');
        return;
    }

    // Build a fresh fake CLLocation (avoid caching: timestamp must look live).
    function fakeLocation() {
        var now = ObjC.classes.NSDate.date();
        return CLLocation.alloc().initWithCoordinate_altitude_horizontalAccuracy_verticalAccuracy_timestamp_(
            {latitude: CONFIG.latitude, longitude: CONFIG.longitude},
            CONFIG.altitude,
            CONFIG.horizontalAccuracy,
            CONFIG.verticalAccuracy,
            now
        );
    }

    try {
        var locationMethod = CLLocationManager['- location'];
        if (locationMethod) {
            Interceptor.attach(locationMethod.implementation, {
                onLeave: function (retval) {
                    var loc = fakeLocation();
                    retval.replace(loc);
                }
            });
            console.log('[+] Hooked -[CLLocationManager location]');
        } else {
            console.log('[-] -[CLLocationManager location] not found');
        }
    } catch (e) {
        console.log('[-] location getter hook failed: ' + e);
    }

    var patchedDelegates = {};

    function patchDelegate(delegatePtr) {
        try {
            if (!delegatePtr || delegatePtr.isNull()) return;
            var delegate = new ObjC.Object(delegatePtr);
            var clsName = delegate.$className;
            if (patchedDelegates[clsName]) return;
            patchedDelegates[clsName] = true;

            var cls = ObjC.classes[clsName];

            // Modern: locationManager:didUpdateLocations:
            var selNew = '- locationManager:didUpdateLocations:';
            if (cls[selNew]) {
                Interceptor.attach(cls[selNew].implementation, {
                    onEnter: function (args) {
                        try {
                            var arr = ObjC.classes.NSArray.arrayWithObject_(fakeLocation());
                            args[3] = arr; // replace locations array
                        } catch (e) { /* ignore */ }
                    }
                });
                console.log('[+] Patched ' + clsName + ' didUpdateLocations:');
            }

            // Deprecated: locationManager:didUpdateToLocation:fromLocation:
            var selOld = '- locationManager:didUpdateToLocation:fromLocation:';
            if (cls[selOld]) {
                Interceptor.attach(cls[selOld].implementation, {
                    onEnter: function (args) {
                        try { args[3] = fakeLocation(); } catch (e) { /* ignore */ }
                    }
                });
                console.log('[+] Patched ' + clsName + ' didUpdateToLocation:fromLocation:');
            }
        } catch (e) { /* ignore */ }
    }

    try {
        var setDelegateMethod = CLLocationManager['- setDelegate:'];
        if (setDelegateMethod) {
            Interceptor.attach(setDelegateMethod.implementation, {
                onEnter: function (args) { patchDelegate(args[2]); }
            });
            console.log('[+] Hooked -[CLLocationManager setDelegate:]');
        } else {
            console.log('[-] -[CLLocationManager setDelegate:] not found');
        }
    } catch (e) {
        console.log('[-] setDelegate: hook failed: ' + e);
    }

    console.log('[+] Location spoofing installed');
})();
