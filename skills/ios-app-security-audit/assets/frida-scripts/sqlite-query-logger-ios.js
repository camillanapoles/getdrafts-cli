/**
 * SQLite Query Logger for iOS
 *
 * Description: Logs every SQL statement an app prepares, in real time, by
 *   hooking the SQLite prepare family and sqlite3_exec() BEFORE execution. Captures the raw SQL
 *   text (including hardcoded values) for both UTF-8 and UTF-16 entry points.
 *   Useful for finding SQL injection sinks, plaintext-stored secrets, and
 *   undocumented local schemas.
 *
 * Source (consolidated):
 *   https://www.sqlite.org/c3ref/prepare.html
 *   https://codeshare.frida.re/ (sqlite tracing patterns)
 *   https://github.com/OWASP/owasp-mastg (local storage chapter)
 *
 * Usage:
 *   frida -U -f com.example.app -l sqlite-query-logger-ios.js
 *   # Many apps bundle their own SQLite (e.g. via FMDB/GRDB); symbols still
 *   # resolve from libsqlite3.dylib in the shared cache.
 *
 * iOS Target: iOS 12 - 17.
 * MASTG: MASTG-TEST-0006 / M9 (Insecure Data Storage)
 *
 * Author: DragonJAR iOS Pentesting Skill
 * Version: 1.0.0
 * License: MIT
 */

(function () {
    'use strict';

    console.log('[*] SQLite Query Logger for iOS');

    var LIB = 'libsqlite3.dylib';
    var count = 0;

    function resolve(name) {
        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        return findExport(LIB, name) || Module.getGlobalExportByName(name);
    }

    function logQuery(source, sql) {
        if (sql === null || sql === undefined || sql.length === 0) return;
        count++;
        console.log('\n[SQL #' + count + '] (' + source + ')');
        console.log('    ' + sql.replace(/\s+/g, ' ').trim());

        var lower = sql.toLowerCase();
        if (/insert|update|delete|drop|alter/.test(lower)) {
            console.log('    [!] write/DDL statement');
        }
        if (/password|token|secret|card|cvv|ssn|api[_ ]?key/.test(lower)) {
            console.log('    [!] references a sensitive-looking column/value');
        }
    }
    ['sqlite3_prepare_v2', 'sqlite3_prepare_v3', 'sqlite3_prepare'].forEach(function (fn) {
        var p = resolve(fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        if (args[1] && !args[1].isNull()) {
                            logQuery(fn, args[1].readUtf8String());
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Hooked ' + fn);
        } catch (e) {
            console.log('[-] ' + fn + ' hook failed: ' + e);
        }
    });

    ['sqlite3_prepare16_v2', 'sqlite3_prepare16_v3', 'sqlite3_prepare16'].forEach(function (fn) {
        var p = resolve(fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        if (args[1] && !args[1].isNull()) {
                            logQuery(fn, args[1].readUtf16String());
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Hooked ' + fn);
        } catch (e) {
            console.log('[-] ' + fn + ' hook failed: ' + e);
        }
    });
    (function () {
        var p = resolve('sqlite3_exec');
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try {
                        if (args[1] && !args[1].isNull()) {
                            logQuery('sqlite3_exec', args[1].readUtf8String());
                        }
                    } catch (e) { /* ignore */ }
                }
            });
            console.log('[+] Hooked sqlite3_exec');
        } catch (e) {
            console.log('[-] sqlite3_exec hook failed: ' + e);
        }
    })();

    console.log('[+] SQLite query logging active');
})();
