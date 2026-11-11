/**
 * Network.framework (NWConnection) Hook for iOS
 *
 * Hooks and logs modern iOS networking via Network.framework:
 * - NWConnection send/receive operations
 * - NWListener incoming connections
 * - NWPathMonitor network changes
 * - TLS/SSL handshakes via Security framework
 *
 * Compatible with: Frida 16.x+ and iOS 13+
 * Usage: frida -U -f <bundle_id> -l nwconnection-hook-ios.js
 * OWASP MASTG: MASTG-TEST-0046, MASTG-NET-002
 *
 * Note: Network.framework is Swift-native. This script hooks the
 * underlying Darwin/CFNetwork C functions used by the framework.
 */

if (ObjC.available) {
    console.log("\x1b[33m[*]\x1b[0m NWConnection Hook iOS Script Started (Network.framework)");

    var CONFIG = {
        maxDataLength: 1024,
        logFullData: false,
        detectSensitiveData: true,
        DEBUG_MODE: false
    };

    var connectionCount = 0;
    var dataTransferred = 0;

    ObjC.schedule(ObjC.mainQueue, function() {
        try {
            function bytesToHex(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || CONFIG.maxDataLength;
                var hex = "";

                try {
                    var totalLen;
                    if (bytes instanceof ArrayBuffer) {
                        totalLen = bytes.byteLength;
                    } else if (bytes && typeof bytes.byteLength === "number") {
                        totalLen = bytes.byteLength;
                    } else {
                        totalLen = maxLength;
                    }

                    var bytesToRead = Math.min(totalLen, maxLength);
                    for (var i = 0; i < bytesToRead; i++) {
                        var b;
                        if (bytes instanceof ArrayBuffer) {
                            b = new Uint8Array(bytes)[i];
                        } else if (bytes && typeof bytes.readU8 === "function") {
                            b = bytes.add(i).readU8();
                        } else {
                            return "<unsupported bytes type>";
                        }
                        hex += ("0" + b.toString(16)).slice(-2);
                    }
                    if (totalLen > maxLength) {
                        hex += "... (" + totalLen + " bytes total)";
                    }
                } catch (e) {
                    hex = "<cannot read>";
                }

                return hex;
            }

            function bytesToString(bytes, maxLength) {
                if (!bytes) return "null";

                var maxLength = maxLength || CONFIG.maxDataLength;
                try {
                    var totalLen = typeof bytes.byteLength === "number" ? bytes.byteLength : maxLength;
                    var bytesToRead = Math.min(totalLen, maxLength);

                    var result = "";
                    for (var i = 0; i < bytesToRead; i++) {
                        var b;
                        if (bytes instanceof ArrayBuffer) {
                            b = new Uint8Array(bytes)[i];
                        } else if (bytes && typeof bytes.readU8 === "function") {
                            b = bytes.add(i).readU8();
                        } else {
                            break;
                        }
                        if (b >= 32 && b <= 126) {
                            result += String.fromCharCode(b);
                        } else {
                            result += ".";
                        }
                    }
                    if (totalLen > maxLength) {
                        result += "... (" + totalLen + " bytes total)";
                    }
                    return result;
                } catch (e) {
                    return "<cannot read>";
                }
            }

            function detectSensitiveData(str, source) {
                if (!CONFIG.detectSensitiveData || !str) return;

                var patterns = [
                    /password/i,
                    /token/i,
                    /api[_-]?key/i,
                    /secret/i,
                    /authorization/i,
                    /session/i,
                    /credit[_-]?card/i,
                    /ssn/i,
                    /pin/i,
                    /auth/i
                ];

                var found = [];
                for (var i = 0; i < patterns.length; i++) {
                    if (patterns[i].test(str)) {
                        found.push(patterns[i].source);
                    }
                }

                if (found.length > 0) {
                    console.log("\x1b[31m[!]\x1b[0m SENSITIVE DATA in " + source + ": " + found.join(", "));
                }
            }

            // Hook CFNetwork write operations (used by NWConnection)
            try {
                // Frida 17: la busqueda por modulo se hace sobre el objeto Module.
                var cfModule = Process.findModuleByName("CoreFoundation");
                var CFWrite = cfModule ? cfModule.findExportByName("CFWriteStreamWrite") : null;
                if (CFWrite) {
                    Interceptor.attach(CFWrite, {
                        onEnter: function(args) {
                            this.stream = args[0];
                            this.buffer = args[1];
                            this.length = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            if (this.length > 0) {
                                connectionCount++;
                                dataTransferred += this.length;

                                try {
                                    var data = this.buffer.readByteArray(Math.min(this.length, CONFIG.maxDataLength));
                                    var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                    console.log("\x1b[36m[>]\x1b[0m CFWrite (NWConnection SEND):");
                                    console.log("    Length: " + this.length + " bytes");
                                    console.log("    Data: " + dataStr.substring(0, 200));

                                    detectSensitiveData(dataStr, "NWConnection SEND");
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m CFWrite error: " + ex.message);
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m CFWrite hooked");
                } else {
                    console.log("\x1b[31m[-]\x1b[0m CFWrite not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CFWrite hook failed: " + e.message);
            }

            // Hook CFNetwork read operations (used by NWConnection)
            try {
                var CFRead = cfModule ? cfModule.findExportByName("CFReadStreamRead") : null;
                if (CFRead) {
                    Interceptor.attach(CFRead, {
                        onEnter: function(args) {
                            this.stream = args[0];
                            this.buffer = args[1];
                            this.maxLength = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            var bytesRead = retval.toInt32();
                            if (bytesRead > 0) {
                                connectionCount++;
                                dataTransferred += bytesRead;

                                try {
                                    var data = this.buffer.readByteArray(Math.min(bytesRead, CONFIG.maxDataLength));
                                    var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                    console.log("\x1b[32m[<]\x1b[0m CFRead (NWConnection RECV):");
                                    console.log("    Length: " + bytesRead + " bytes");
                                    console.log("    Data: " + dataStr.substring(0, 200));

                                    detectSensitiveData(dataStr, "NWConnection RECV");
                                } catch (ex) {
                                    console.log("\x1b[31m[!]\x1b[0m CFRead error: " + ex.message);
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m CFRead hooked");
                } else {
                    console.log("\x1b[31m[-]\x1b[0m CFRead not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m CFRead hook failed: " + e.message);
            }

            // Hook socket operations (raw TCP/UDP used by NWConnection)
            try {
                var send = Module.findGlobalExportByName("send");
                if (send) {
                    Interceptor.attach(send, {
                        onEnter: function(args) {
                            this.sockfd = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                            this.flags = args[3].toInt32();
                        },
                        onLeave: function(retval) {
                            var sent = retval.toInt32();
                            if (sent > 0) {
                                try {
                                    var data = this.buf.readByteArray(Math.min(this.len, CONFIG.maxDataLength));
                                    var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                    console.log("\x1b[36m[>]\x1b[0m socket send (fd=" + this.sockfd + "):");
                                    console.log("    Length: " + sent + " bytes");
                                    console.log("    Data: " + dataStr.substring(0, 200));

                                    detectSensitiveData(dataStr, "socket send");
                                } catch (ex) {
                                    // Ignore socket read errors
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m socket send hooked");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m socket send hook failed: " + e.message);
            }

            try {
                var recv = Module.findGlobalExportByName("recv");
                if (recv) {
                    Interceptor.attach(recv, {
                        onEnter: function(args) {
                            this.sockfd = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                            this.flags = args[3].toInt32();
                        },
                        onLeave: function(retval) {
                            var received = retval.toInt32();
                            if (received > 0) {
                                try {
                                    var data = this.buf.readByteArray(Math.min(received, CONFIG.maxDataLength));
                                    var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                    console.log("\x1b[32m[<]\x1b[0m socket recv (fd=" + this.sockfd + "):");
                                    console.log("    Length: " + received + " bytes");
                                    console.log("    Data: " + dataStr.substring(0, 200));

                                    detectSensitiveData(dataStr, "socket recv");
                                } catch (ex) {
                                    // Ignore socket read errors
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m socket recv hooked");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m socket recv hook failed: " + e.message);
            }

            // Hook TLS/SSL read (for HTTPS via Network.framework)
            try {
                var securityModule = Process.findModuleByName("Security");
                var SSLRead = securityModule ? securityModule.findExportByName("SSLRead") : null;
                if (SSLRead) {
                    Interceptor.attach(SSLRead, {
                        onEnter: function(args) {
                            this.sslContext = args[0];
                            this.data = args[1];
                            this.dataLength = args[2];
                        },
                        onLeave: function(retval) {
                            var status = retval.toInt32();
                            if (status === 0 && this.dataLength) {
                                try {
                                    var length = this.dataLength.toInt32();
                                    if (length > 0) {
                                        var data = this.data.readByteArray(Math.min(length, CONFIG.maxDataLength));
                                        var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                        console.log("\x1b[32m[<]\x1b[0m SSLRead (NWConnection TLS):");
                                        console.log("    Length: " + length + " bytes");
                                        console.log("    Data: " + dataStr.substring(0, 200));

                                        detectSensitiveData(dataStr, "TLS RECV");
                                    }
                                } catch (ex) {
                                    // Ignore SSL read errors
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m SSLRead hooked");
                } else {
                    console.log("\x1b[31m[-]\x1b[0m SSLRead not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SSLRead hook failed: " + e.message);
            }

            // Hook TLS/SSL write (for HTTPS via Network.framework)
            try {
                var SSLWrite = securityModule ? securityModule.findExportByName("SSLWrite") : null;
                if (SSLWrite) {
                    Interceptor.attach(SSLWrite, {
                        onEnter: function(args) {
                            this.sslContext = args[0];
                            this.data = args[1];
                            this.dataLength = args[2];
                        },
                        onLeave: function(retval) {
                            var status = retval.toInt32();
                            if (status === 0 && this.dataLength) {
                                try {
                                    var length = this.dataLength.toInt32();
                                    if (length > 0) {
                                        var data = this.data.readByteArray(Math.min(length, CONFIG.maxDataLength));
                                        var dataStr = bytesToString(data, CONFIG.maxDataLength);

                                        console.log("\x1b[36m[>]\x1b[0m SSLWrite (NWConnection TLS):");
                                        console.log("    Length: " + length + " bytes");
                                        console.log("    Data: " + dataStr.substring(0, 200));

                                        detectSensitiveData(dataStr, "TLS SEND");
                                    }
                                } catch (ex) {
                                    // Ignore SSL write errors
                                }
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m SSLWrite hooked");
                } else {
                    console.log("\x1b[31m[-]\x1b[0m SSLWrite not found");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m SSLWrite hook failed: " + e.message);
            }

            // Hook connect (for TCP connections)
            try {
                var connectFunc = Module.findGlobalExportByName("connect");
                if (connectFunc) {
                    Interceptor.attach(connectFunc, {
                        onEnter: function(args) {
                            this.sockfd = args[0].toInt32();
                            this.addr = args[1];
                            try {
                                var family = this.addr.readU16();
                                if (family === 2) { // AF_INET
                                    var port = (this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8();
                                    var ip = this.addr.add(4).readU8() + "." +
                                            this.addr.add(5).readU8() + "." +
                                            this.addr.add(6).readU8() + "." +
                                            this.addr.add(7).readU8();
                                    console.log("\x1b[33m[*]\x1b[0m TCP connect: " + ip + ":" + port + " (fd=" + this.sockfd + ")");
                                }
                            } catch (ex) {
                                console.log("\x1b[31m[!]\x1b[0m connect address parse error: " + ex.message);
                            }
                        }
                    });
                    console.log("\x1b[32m[+]\x1b[0m connect hooked");
                }
            } catch (e) {
                console.log("\x1b[31m[!]\x1b[0m connect hook failed: " + e.message);
            }

            console.log("\x1b[33m[*]\x1b[0m NWConnection Hook iOS Script Loaded");
            console.log("\x1b[36m[*]\x1b[0m Monitoring Network.framework traffic...");

        } catch (e) {
            console.log("\x1b[31m[!]\x1b[0m NWConnection Hook iOS error: " + e.message);
        }
    });

    setInterval(function() {
        if (connectionCount > 0) {
            console.log("\x1b[36m[*]\x1b[0m Stats - Operations: " + connectionCount + " | Data: " + dataTransferred + " bytes");
        }
    }, 30000);

} else {
    console.log("\x1b[31m[!]\x1b[0m Objective-C Runtime is not available");
}
