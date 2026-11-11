/**
 * Anti-Debugging Bypass for iOS (native)
 *
 * Description: Defeats native anti-debugging primitives so a debugger/Frida
 *   can stay attached:
 *     - ptrace(PT_DENY_ATTACH / 31)  -> forced to succeed without denying
 *     - syscall(SYS_ptrace, ...)     -> same, for apps that bypass the libc stub
 *     - sysctl(KERN_PROC, KERN_PROC_PID) -> clears the P_TRACED flag in kinfo_proc
 *     - getppid()                    -> returns 1 (launchd) to defeat ppid checks
 *
 * Source (consolidated):
 *   https://codeshare.frida.re/@dzonerzy/fridantiroot/
 *   https://github.com/OWASP/owasp-mastg (anti-debugging chapter)
 *   https://www.theiphonewiki.com/wiki/Bypassing_PT_DENY_ATTACH
 *
 * Usage:
 *   frida -U -f com.example.app -l anti-debugging-bypass-ios.js
 *   # Spawn (-f) is recommended so the hooks land before main() runs the checks.
 *
 * iOS Target: iOS 12 - 17 (arm64).
 * MASTG: MASTG-TEST-0016 / M7 (Insufficient Binary Protection)
 *
 * Author: DragonJAR iOS Pentesting Skill
 * Version: 1.0.0
 * License: MIT
 */

(function () {
    'use strict';

    console.log('[*] Anti-Debugging Bypass for iOS');

    var PT_DENY_ATTACH = 31;
    var SYS_ptrace = 26;        // BSD syscall number for ptrace on Darwin
    var CTL_KERN = 1;
    var KERN_PROC = 14;
    var KERN_PROC_PID = 1;
    var P_TRACED = 0x00000800;  // proc.h: process is being traced

    var ptracePtr = Module.getGlobalExportByName('ptrace');
    if (ptracePtr) {
        try {
            var ptraceOrig = new NativeFunction(ptracePtr, 'int',
                ['int', 'int', 'pointer', 'int']);
            Interceptor.replace(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
                if (request === PT_DENY_ATTACH) {
                    console.log('[+] ptrace(PT_DENY_ATTACH) blocked');
                    return 0;
                }
                return ptraceOrig(request, pid, addr, data);
            }, 'int', ['int', 'int', 'pointer', 'int']));
            console.log('[+] Hooked ptrace');
        } catch (e) {
            console.log('[-] ptrace hook failed: ' + e);
        }
    } else {
        console.log('[-] ptrace export not found (may be called via syscall)');
    }

    var syscallPtr = Module.getGlobalExportByName('syscall');
    if (syscallPtr) {
        try {
            Interceptor.attach(syscallPtr, {
                onEnter: function (args) {
                    this.isPtraceDeny = (args[0].toInt32() === SYS_ptrace &&
                        args[1].toInt32() === PT_DENY_ATTACH);
                },
                onLeave: function (retval) {
                    if (this.isPtraceDeny) {
                        console.log('[+] syscall(SYS_ptrace, PT_DENY_ATTACH) neutralized');
                        retval.replace(ptr(0));
                    }
                }
            });
            console.log('[+] Hooked syscall (SYS_ptrace filter)');
        } catch (e) {
            console.log('[-] syscall hook failed: ' + e);
        }
    }

    var sysctlPtr = Module.getGlobalExportByName('sysctl');
    if (sysctlPtr) {
        try {
            Interceptor.attach(sysctlPtr, {
                onEnter: function (args) {
                    this.targetsProc = false;
                    try {
                        var name = args[0];
                        var namelen = args[1].toInt32();
                        if (!name.isNull() && namelen >= 4) {
                            if (name.readInt() === CTL_KERN &&
                                name.add(4).readInt() === KERN_PROC &&
                                name.add(8).readInt() === KERN_PROC_PID) {
                                this.targetsProc = true;
                                this.oldp = args[2];      // struct kinfo_proc *
                            }
                        }
                    } catch (e) { /* ignore */ }
                },
                onLeave: function (retval) {
                    if (!this.targetsProc || retval.toInt32() !== 0) return;
                    if (!this.oldp || this.oldp.isNull()) return;
                    try {
                        // kinfo_proc.kp_proc.p_flag is at offset 32.
                        var pFlagPtr = this.oldp.add(32);
                        var flags = pFlagPtr.readU32();
                        if (flags & P_TRACED) {
                            pFlagPtr.writeU32(flags & ~P_TRACED);
                            console.log('[+] sysctl(KERN_PROC): cleared P_TRACED flag');
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Hooked sysctl (P_TRACED scrub)');
        } catch (e) {
            console.log('[-] sysctl hook failed: ' + e);
        }
    }

    var getppidPtr = Module.getGlobalExportByName('getppid');
    if (getppidPtr) {
        try {
            Interceptor.replace(getppidPtr, new NativeCallback(function () {
                return 1;
            }, 'int', []));
            console.log('[+] Hooked getppid -> 1');
        } catch (e) {
            console.log('[-] getppid hook failed: ' + e);
        }
    }

    console.log('[+] Anti-debugging bypass installed');
})();
