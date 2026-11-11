/**
 * TLS Keylogger for iOS (BoringSSL)
 *
 * Description: Extracts TLS session secrets from libboringssl.dylib in the
 *   NSS Key Log format (SSLKEYLOGFILE). The captured lines let Wireshark
 *   decrypt the app's TLS traffic WITHOUT a MITM proxy or certificate
 *   installation — defeats certificate pinning by design, because keys are
 *   pulled straight from the crypto library. Supports TLS 1.2 (CLIENT_RANDOM)
 *   and TLS 1.3 (handshake/traffic secrets via the keylog callback).
 *
 * Source (consolidated):
 *   https://github.com/andydavies/ios-tls-keylogger
 *   https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
 *   https://codeshare.frida.re/@rompreghi/universalkeylogger/  (universalkeylogger)
 *   ios13-tls-keylogger / ios-15-tls-keylogger / ios-tls-keylogger-newoffset variants
 *
 * Usage:
 *   frida -U -f com.example.app -l tls-keylogger-ios.js | tee keylog.txt
 *   # Then in Wireshark: Preferences > Protocols > TLS >
 *   #   (Pre)-Master-Secret log filename = keylog.txt
 *   # Optional: set KEYLOG_PATH below to also persist on-device.
 *
 * iOS Target: iOS 12 - 17 (BoringSSL). Prefers the keylog-callback path
 *   (symbol-based, version independent). Falls back to master-key extraction.
 * MASTG: MASTG-TEST-0011 / M5 (Insecure Communication)
 *
 * Author: DragonJAR iOS Pentesting Skill
 * Version: 1.0.0
 * License: MIT
 */

(function () {
    'use strict';

    // Set to a device-writable path to ALSO persist keys on-device, e.g.
    // '/var/root/sslkeylog.txt' (rooted) or null to only print to console.
    var KEYLOG_PATH = null;

    var BORINGSSL_LIBS = ['libboringssl.dylib', 'libcoretls.dylib'];

    var keylogFile = null;
    if (KEYLOG_PATH) {
        try {
            keylogFile = new File(KEYLOG_PATH, 'a');
        } catch (e) {
            console.log('[-] Could not open KEYLOG_PATH (' + KEYLOG_PATH + '): ' + e);
        }
    }

    function emit(line) {
        console.log(line);
        if (keylogFile) {
            try {
                keylogFile.write(line + '\n');
                keylogFile.flush();
            } catch (e) { /* ignore per-line write errors */ }
        }
    }

    function resolve(name) {
        // Frida 17: getModuleByName() throws when the module is not loaded and
        // getExportByName() throws when the symbol is missing; the "find" variants return null.
        function findExport(moduleName, symbolName) {
            var mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(symbolName) : null;
        }

        for (var i = 0; i < BORINGSSL_LIBS.length; i++) {
            var p = findExport(BORINGSSL_LIBS[i], name);
            if (p) return p;
        }
        return Module.getGlobalExportByName(name);
    }

    function toHex(arrayBuffer) {
        var bytes = new Uint8Array(arrayBuffer);
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            out += ('0' + bytes[i].toString(16)).slice(-2);
        }
        return out;
    }

    console.log('[*] TLS Keylogger for iOS (BoringSSL)');
    var SSL_CTX_new = resolve('SSL_CTX_new');
    var SSL_CTX_set_keylog_callback_addr = resolve('SSL_CTX_set_keylog_callback');

    var installedCallbackPath = false;

    if (SSL_CTX_new && SSL_CTX_set_keylog_callback_addr) {
        try {
            var SSL_CTX_set_keylog_callback = new NativeFunction(
                SSL_CTX_set_keylog_callback_addr, 'void', ['pointer', 'pointer']);
            var keylogCb = new NativeCallback(function (ssl, linePtr) {
                try {
                    if (!linePtr.isNull()) {
                        var line = linePtr.readUtf8String();
                        if (line) emit(line);
                    }
                } catch (e) { /* ignore */ }
            }, 'void', ['pointer', 'pointer']);

            // Keep a reference so the callback is not GC'd.
            global.__tls_keylog_cb = keylogCb;

            Interceptor.attach(SSL_CTX_new, {
                onLeave: function (retval) {
                    if (retval && !retval.isNull()) {
                        try {
                            SSL_CTX_set_keylog_callback(retval, keylogCb);
                        } catch (e) { /* ignore */ }
                    }
                }
            });

            installedCallbackPath = true;
            console.log('[+] Hooked SSL_CTX_new + installed SSL_CTX_set_keylog_callback');
            console.log('[+] Capturing TLS 1.2/1.3 secrets in NSS key-log format');
        } catch (e) {
            console.log('[-] Keylog-callback path failed: ' + e);
        }
    }
    if (!installedCallbackPath) {
        var SSL_get_client_random_addr = resolve('SSL_get_client_random');
        var SSL_get_session_addr = resolve('SSL_get_session');
        var SSL_SESSION_get_master_key_addr = resolve('SSL_SESSION_get_master_key');
        var SSL_do_handshake_addr = resolve('SSL_do_handshake');

        if (SSL_get_client_random_addr && SSL_get_session_addr &&
            SSL_SESSION_get_master_key_addr && SSL_do_handshake_addr) {
            try {
                var SSL_get_client_random = new NativeFunction(
                    SSL_get_client_random_addr, 'size_t', ['pointer', 'pointer', 'size_t']);
                var SSL_get_session = new NativeFunction(
                    SSL_get_session_addr, 'pointer', ['pointer']);
                var SSL_SESSION_get_master_key = new NativeFunction(
                    SSL_SESSION_get_master_key_addr, 'size_t', ['pointer', 'pointer', 'size_t']);

                var seen = {};

                Interceptor.attach(SSL_do_handshake_addr, {
                    onEnter: function (args) { this.ssl = args[0]; },
                    onLeave: function () {
                        try {
                            var ssl = this.ssl;
                            if (!ssl || ssl.isNull()) return;

                            var crBuf = Memory.alloc(32);
                            var crLen = SSL_get_client_random(ssl, crBuf, 32).valueOf();
                            if (crLen <= 0) return;
                            var clientRandom = toHex(crBuf.readByteArray(crLen));

                            if (seen[clientRandom]) return; // de-dupe per session

                            var session = SSL_get_session(ssl);
                            if (!session || session.isNull()) return;

                            var mkBuf = Memory.alloc(64);
                            var mkLen = SSL_SESSION_get_master_key(session, mkBuf, 48).valueOf();
                            if (mkLen <= 0) return;
                            var masterKey = toHex(mkBuf.readByteArray(mkLen));

                            seen[clientRandom] = true;
                            emit('CLIENT_RANDOM ' + clientRandom + ' ' + masterKey);
                        } catch (e) { /* ignore */ }
                    }
                });

                console.log('[+] Fallback: hooked SSL_do_handshake (TLS 1.2 CLIENT_RANDOM)');
            } catch (e) {
                console.log('[-] Master-key fallback failed: ' + e);
            }
        } else {
            console.log('[-] BoringSSL key-extraction symbols not found.');
            console.log('    Resolved: SSL_CTX_new=' + SSL_CTX_new +
                ' keylog_cb=' + SSL_CTX_set_keylog_callback_addr);
        }
    }
})();
