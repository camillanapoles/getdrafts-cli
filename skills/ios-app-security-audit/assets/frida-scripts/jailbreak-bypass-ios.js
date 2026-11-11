/**
 * iOS Jailbreak Detection Bypass (Universal)
 * Purpose: Bypass jailbreak detection in iOS apps during pentesting
 * Usage:
 *   Simulator: frida -D <UDID> -p <PID> -l jailbreak-bypass-ios.js
 *   Device: frida -U -f com.example.app -l jailbreak-bypass-ios.js
 *
 * Covers:
 * - ObjC file existence checks (NSFileManager)
 * - URL scheme checks (UIApplication.canOpenURL:)
 * - Direct detection methods (isJailbroken, isJailBroken, etc.)
 * - Custom jailbreak test methods
 *
 * Compatible with Frida 17+ on iOS Simulator (.implementation pattern)
 * See: references/frida-ios-simulator-workflow.md
 */

(function() {
    'use strict';

    if (typeof ObjC === 'undefined' || !ObjC.available) {
        console.log("[-] Objective-C runtime NOT available");
        return;
    }

    console.log("\n[*] iOS Jailbreak Detection Bypass");
    console.log("[*] Loading bypass hooks...\n");

    var JB_PATHS = [
        '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/FakeCarrier.app',
        '/Applications/Icy.app', '/Applications/IntelliScreen.app', '/Applications/MxTube.app',
        '/Applications/RockApp.app', '/Applications/SBSettings.app', '/Applications/WinterBoard.app',
        '/Library/MobileSubstrate/DynamicLibraries', '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/usr/sbin/sshd', '/usr/bin/sshd', '/usr/libexec/ssh-keysign',
        '/usr/libexec/sftp-server', '/usr/bin/ssh', '/usr/libexec/cydia',
        '/var/tmp/cydia.log', '/etc/apt', '/var/lib/cydia',
        '/var/cache/apt', '/var/lib/apt', '/private/var/lib/apt/',
        '/private/var/lib/cydia/', '/private/var/tmp/cydia.log',
        '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        '/usr/lib/libexcsecarm64.dylib', '/.installed_unc0ver',
        '/.installed_electra', '/var/containers/Bundle/Application',
        '/var/mobile/Library/Cydia'
    ];

    var JB_SCHEMES = ['cydia://', 'sileo://', 'zbra://', 'filza://', 'activator://'];

    function isJailbreakIndicator(path) {
        if (!path) return false;
        var p = path.toString().toLowerCase();
        for (var i = 0; i < JB_PATHS.length; i++) {
            if (p.indexOf(JB_PATHS[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    var hooksApplied = 0;
    var DEBUG = false;

    try {
        var NSFM = ObjC.classes.NSFileManager;
        if (NSFM) {
            var fileMethods = [
                '- fileExistsAtPath:',
                '- fileExistsAtPath:isDirectory:',
                '- isReadableFileAtPath:',
                '- isWritableFileAtPath:',
                '- createFileAtPath:contents:attributes:'
            ];

            fileMethods.forEach(function(selector) {
                if (NSFM[selector]) {
                    Interceptor.attach(NSFM[selector].implementation, {
                        onEnter: function(args) {
                            var path = ObjC.Object(args[2]).toString();
                            if (isJailbreakIndicator(path)) {
                                this.block = true;
                                if (DEBUG) console.log('[+] Blocked: ' + selector + ' -> ' + path);
                            }
                        },
                        onLeave: function(retval) {
                            if (this.block) retval.replace(ptr(0));
                        }
                    });
                    hooksApplied++;
                }
            });
            console.log('[+] NSFileManager hooks: ' + fileMethods.length + ' methods');
        }
    } catch (e) {
        console.log('[!] NSFileManager hooks failed: ' + e.message);
    }

    try {
        var app = ObjC.classes.UIApplication.sharedApplication();
        if (app && app['- canOpenURL:']) {
            Interceptor.attach(app['- canOpenURL:'].implementation, {
                onEnter: function(args) {
                    var url = ObjC.Object(args[2]).absoluteString().toString();
                    for (var i = 0; i < JB_SCHEMES.length; i++) {
                        if (url.toLowerCase().indexOf(JB_SCHEMES[i]) === 0) {
                            this.block = true;
                            if (DEBUG) console.log('[+] Blocked: canOpenURL -> ' + url);
                            return;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.block) retval.replace(ptr(0));
                }
            });
            hooksApplied++;
            console.log('[+] UIApplication.canOpenURL: hook applied');
        }
    } catch (e) {
        console.log('[!] UIApplication hooks failed: ' + e.message);
    }

    var targets = [
        '+ isJailbroken', '- isJailbroken',
        '+ isJailBroken', '- isJailBroken',
        '+ isDeviceJailbroken', '- isDeviceJailbroken',
        '+ jailbreakTest', '- jailbreakTest',
        '+ checkJailbreak', '- checkJailbreak',
        '+ deviceJailbroken', '- deviceJailbroken'
    ];

    var methodHooks = 0;
    var foundClasses = [];

    for (var className in ObjC.classes) {
        try {
            var clazz = ObjC.classes[className];
            var found = false;

            targets.forEach(function(selector) {
                if (clazz[selector]) {
                    Interceptor.attach(clazz[selector].implementation, {
                        onLeave: function(retval) {
                            if (DEBUG) console.log('[*] Bypassed: ' + selector);
                            retval.replace(ptr(0)); // Return NO/false
                        }
                    });
                    found = true;
                    methodHooks++;
                }
            });

            var methods = clazz.$ownMethods;
            if (methods) {
                methods.forEach(function(m) {
                    if (m.toLowerCase().indexOf('jailbreak') !== -1) {
                        try {
                            Interceptor.attach(clazz[m].implementation, {
                                onLeave: function(retval) {
                                    if (DEBUG) console.log('[*] Bypassed: ' + className + ' -> ' + m);
                                    retval.replace(ptr(0));
                                }
                            });
                            found = true;
                            methodHooks++;
                        } catch (e) {}
                    }
                });
            }

            if (found) foundClasses.push(className);
        } catch (e) {
            // Class access failed - skip
        }
    }

    console.log('[+] Detection method hooks: ' + methodHooks + ' methods');

    console.log('\n[*] Summary:');
    console.log('    - File method hooks: ' + (hooksApplied - 1));
    console.log('    - Detection method hooks: ' + methodHooks);
    console.log('    - Total hooks active: ' + (hooksApplied + methodHooks));

    if (methodHooks > 0) {
        console.log('\n[+] Jailbreak detection bypassed!');
        console.log('[*] All checks will return "Device NOT Jailbroken"');
    } else {
        console.log('\n[!] No detection methods found');
        console.log('[*] App may not have jailbreak detection');
    }
    console.log('');

})();
