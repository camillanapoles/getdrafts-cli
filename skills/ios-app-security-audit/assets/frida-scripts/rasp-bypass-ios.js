/**
 * RASP Bypass for iOS (commercial + open source)
 *
 * Description: Neutralizes Runtime Application Self-Protection (RASP) SDKs by
 *   forcing their detection methods to report a "clean" device. Targets:
 *     - IOSSecuritySuite (securing/IOSSecuritySuite)   [Swift static funcs]
 *     - FreeRASP / Talsec (talsec/talsec-app)          [ObjC + Swift]
 *     - JailMonkey (React Native)                      [ObjC class JailMonkey]
 *     - IBM Trusteer / Trusteer Mobile SDK             [ObjC ts_* classes]
 *     - IOSSecuritySlayer / generic in-house RASP      [ObjC BOOL methods]
 *   Detection getters (jailbreak/debugger/emulator/proxy/reverse-engineering/
 *   hook/tamper) are flipped to FALSE; safety getters (isSecure/isSafe/isTrusted)
 *   are flipped to TRUE.
 *
 * Source (consolidated):
 *   https://github.com/securing/IOSSecuritySuite
 *   https://github.com/talsec/Free-RASP-iOS
 *   https://github.com/GantMan/jail-monkey
 *   https://codeshare.frida.re/@dzonerzy/fridantiroot/ (pattern inspiration)
 *
 * Usage:
 *   frida -U -f com.example.app -l rasp-bypass-ios.js
 *   # Run alongside jailbreak-detection-bypass.js + anti-debugging-bypass-ios.js
 *   # for layered protections (file/syscall-level checks live there).
 *
 * iOS Target: iOS 12 - 17. ObjC paths are version independent; Swift paths
 *   match the public IOSSecuritySuite API symbol names.
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

    console.log('[*] RASP Bypass for iOS');

    // Selectors that must report "no threat" -> return BOOL false (0).
    var FORCE_FALSE = [
        'jailbroken', 'jailbreak', 'isjailbroken', 'isjailbreaked',
        'amijailbroken', 'isdevicejailbroken', 'jailbreaktest',
        'debug', 'debugger', 'isdebug', 'isdebugged', 'amidebugged',
        'beingdebugged', 'tracerpid', 'debuggerattached',
        'emulator', 'simulator', 'isemulator', 'issimulator', 'amiruninemulator',
        'proxy', 'isproxied', 'amiproxied', 'httpproxy', 'vpn', 'isvpn',
        'reverse', 'reverseengineer', 'amireverseengineered', 'isreverseengineered',
        'tamper', 'tampered', 'istampered', 'integritycompromised', 'appistampered',
        'hook', 'hooked', 'ishooked', 'frida', 'cycript', 'substrate', 'hookdetected',
        'cydia', 'sileo', 'piracy', 'pirated', 'cracked',
        'mocklocation', 'canmocklocation', 'trustfall', 'adbenabled',
        'suspicious', 'threat', 'detected', 'compromised', 'attack',
        'malware', 'inject', 'injected', 'manipulated', 'modified',
        'rooted', 'rooteddevice', 'isrooted',
        'developer', 'developmentmode', 'ide', 'xcode',
        'screenrecording', 'screenmirroring', 'miracast'
    ];

    // Selectors that must report "safe" -> return BOOL true (1).
    var FORCE_TRUE = [
        'issecure', 'issafe', 'istrusted', 'isintegrityok', 'isintact',
        'isgenuine', 'isclean', 'isdeviceclean'
    ];

    function classify(selLower) {
        // Order matters: an explicit "safe" intent wins over generic matches.
        for (var t = 0; t < FORCE_TRUE.length; t++) {
            if (selLower.indexOf(FORCE_TRUE[t]) !== -1) return 1;
        }
        for (var f = 0; f < FORCE_FALSE.length; f++) {
            if (selLower.indexOf(FORCE_FALSE[f]) !== -1) return 0;
        }
        return -1; // not a detection selector
    }

    var hookedCount = 0;

    function hookBoolMethod(cls, methodName, forcedValue, label) {
        try {
            var m = ObjC.classes[cls][methodName];
            if (!m) return;
            Interceptor.attach(m.implementation, {
                onLeave: function (retval) {
                    var original = retval.toInt32();
                    if (original !== forcedValue) {
                        retval.replace(ptr(forcedValue));
                        console.log('[+] ' + (label || cls) + ' ' + methodName +
                            ': ' + original + ' -> ' + forcedValue);
                    }
                }
            });
            hookedCount++;
        } catch (e) { /* method/class absent */ }
    }
    console.log('[*] Scanning Objective-C classes for RASP detection methods...');
    var classNames = Object.keys(ObjC.classes);
    for (var i = 0; i < classNames.length; i++) {
        var clsName = classNames[i];
        // Skip the bulk of Apple system classes to limit noise/cost.
        if (/^(NS|UI|CA|CF|CG|_|__|WK|AV|CL|SK|MK|GK)/.test(clsName)) continue;

        var cls = ObjC.classes[clsName];
        var methods;
        try { methods = cls.$ownMethods; } catch (e) { continue; }

        for (var j = 0; j < methods.length; j++) {
            var sel = methods[j];                 // e.g. "- isJailBroken"
            var selBody = sel.replace(/^[-+]\s*/, '');
            if (selBody.indexOf(':') !== -1) continue; // only zero-arg getters
            var forced = classify(selBody.toLowerCase());
            if (forced === -1) continue;
            hookBoolMethod(clsName, sel, forced, clsName);
        }
    }
    var jmMethods = ['- isJailBroken', '- isDebuggedMode', '- hookDetected',
        '- canMockLocation', '- trustFall', '- AdbEnabled'];
    for (var k = 0; k < jmMethods.length; k++) {
        hookBoolMethod('JailMonkey', jmMethods[k], 0, 'JailMonkey');
    }
    var swiftDetections = [
        'amIJailbroken', 'amIDebugged', 'amIRunInEmulator',
        'amIReverseEngineered', 'amIProxied', 'amIRunInVirtualMachine',
        'isDebuggerAttached', 'isFridaRunning', 'amITampered'
    ];

    function hookSwiftBoolSymbols(moduleName) {
        try {
            var syms = Module.enumerateSymbols(moduleName);
            for (var s = 0; s < syms.length; s++) {
                var sym = syms[s];
                if (!sym.address || sym.address.isNull()) continue;
                for (var d = 0; d < swiftDetections.length; d++) {
                    if (sym.name.indexOf(swiftDetections[d]) !== -1) {
                        (function (name, addr) {
                            try {
                                Interceptor.attach(addr, {
                                    onLeave: function (retval) {
                                        // Bool returns in x0 as 0/1; force "clean".
                                        if (retval.toInt32() !== 0) {
                                            retval.replace(ptr(0));
                                            console.log('[+] Swift RASP ' + name + ': true -> false');
                                        }
                                    }
                                });
                                hookedCount++;
                            } catch (e) { /* ignore */ }
                        })(sym.name, sym.address);
                        break;
                    }
                }
            }
        } catch (e) { /* module not present */ }
    }

    // Scan the main executable and any IOSSecuritySuite / Talsec frameworks.
    try {
        var mods = Process.enumerateModules();
        for (var mi = 0; mi < mods.length; mi++) {
            var mn = mods[mi].name;
            var isApp = (mods[mi].path && mods[mi].path.indexOf('.app/') !== -1 &&
                mods[mi].path.indexOf('/Frameworks/') === -1 &&
                mods[mi].path.indexOf('/System/') === -1);
            if (isApp || /IOSSecuritySuite|TalsecRuntime|freerasp|SecuritySuite/i.test(mn)) {
                hookSwiftBoolSymbols(mn);
            }
        }
    } catch (e) {
        console.log('[-] Swift symbol scan failed: ' + e);
    }

    console.log('[+] RASP bypass installed. Hooks placed: ' + hookedCount);
    if (hookedCount === 0) {
        console.log('[!] No RASP methods matched. The app may use pure-syscall checks');
        console.log('    -> also run anti-debugging-bypass-ios.js + jailbreak-detection-bypass.js');
    }

    // ============================================
    // Additional: Port Scanning Bypass (Frida detection)
    // ============================================
    var connectPtr = Module.findGlobalExportByName('connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    var addr = args[1];
                    var sinFamily = addr.readU16();
                    if (sinFamily === 2) { // AF_INET
                        var port = addr.add(2).readU16BE();
                        var fridaPorts = [27042, 27043, 27044, 27045, 27046, 27047];
                        if (fridaPorts.indexOf(port) !== -1) {
                            console.log('[+] Blocked connection to Frida port: ' + port);
                            this.block = true;
                        }
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.block) {
                    retval.replace(ptr(-1)); // Return error
                }
            }
        });
        console.log('[+] Port scanning bypass installed (Frida detection)');
    }

    // ============================================
    // Additional: DYLD Enumeration Bypass
    // ============================================
    var dyldGetImageName = Module.findGlobalExportByName('__dyld_get_image_name');
    if (dyldGetImageName) {
        Interceptor.attach(dyldGetImageName, {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    try {
                        var name = retval.readUtf8String();
                        if (name && (
                            name.toLowerCase().indexOf('frida') !== -1 ||
                            name.toLowerCase().indexOf('gadget') !== -1 ||
                            name.toLowerCase().indexOf('substrate') !== -1 ||
                            name.toLowerCase().indexOf('cycript') !== -1
                        )) {
                            retval.replace(ptr(0)); // Return NULL (image doesn't exist)
                            console.log('[+] Hidden from DYLD enumeration: ' + name);
                        }
                    } catch (e) {}
                }
            }
        });
        console.log('[+] DYLD enumeration bypass installed');
    }

    // ============================================
    // Additional: ptrace Bypass (PT_DENY_ATTACH)
    // ============================================
    var ptrace = Module.findGlobalExportByName('ptrace');
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(function () {
            console.log('[+] ptrace blocked - anti-debug bypassed');
            return 0;
        }, 'int', []));
        console.log('[+] ptrace bypass installed (PT_DENY_ATTACH)');
    }

    // ============================================
    // Additional: getppid Bypass (debugger detection)
    // ============================================
    var getppid = Module.findGlobalExportByName('getppid');
    if (getppid) {
        Interceptor.replace(getppid, new NativeCallback(function () {
            return 1; // Always return launchd (PID 1)
        }, 'int', []));
        console.log('[+] getppid bypass installed (debugger detection)');
    }

    // ============================================
    // Additional: Commercial RASP Class Hooks
    // ============================================
    var commercialRASPClasses = [
        'Promon', 'SHIELD', 'PShield',
        'Appdome', 'ADMobile', 'AD',
        'Arxan', 'AXProtection', 'ArxanGuard',
        'Guardsquare', 'iXProtect', 'XProtect',
        'Irdeto', 'IDTO',
        'WhiteCryption', 'Intertrust',
        'Verimatrix',
        'Zimperium', 'zDefend',
        'Pradeo',
        'VKey',
        'Build38'
    ];

    var commercialCount = 0;
    for (var i = 0; i < commercialRASPClasses.length; i++) {
        var pattern = commercialRASPClasses[i].toLowerCase();
        var allClasses = Object.keys(ObjC.classes);
        for (var j = 0; j < allClasses.length; j++) {
            var clsName = allClasses[j];
            if (clsName.toLowerCase().indexOf(pattern) !== -1) {
                try {
                    var cls = ObjC.classes[clsName];
                    var methods = cls.$ownMethods;
                    for (var k = 0; k < methods.length; k++) {
                        var m = methods[k];
                        var mName = m.toLowerCase();
                        if (mName.indexOf('check') !== -1 ||
                            mName.indexOf('detect') !== -1 ||
                            mName.indexOf('verify') !== -1 ||
                            mName.indexOf('validate') !== -1 ||
                            mName.indexOf('protect') !== -1 ||
                            mName.indexOf('security') !== -1 ||
                            mName.indexOf('integrity') !== -1 ||
                            mName.indexOf('threat') !== -1) {
                            try {
                                Interceptor.attach(cls[m].implementation, {
                                    onLeave: function (retval) {
                                        // Force "no threat" or "secure"
                                        if (retval.toInt32() !== 0) {
                                            retval.replace(ptr(0));
                                        }
                                    }
                                });
                                commercialCount++;
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
            }
        }
    }
    if (commercialCount > 0) {
        console.log('[+] Commercial RASP bypasses: ' + commercialCount + ' methods');
    }
})();
