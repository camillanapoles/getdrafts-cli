/**
 * Cookie Dumper for iOS Apps
 *
 * Description: Extracts cookies from NSHTTPCookieStorage and outputs as JSON
 *
 * Usage:
 *   frida -U -f com.example.app -l cookie-dumper-ios.js
 *   frida -e com.example.app -l cookie-dumper-ios.js  # For emulator
 *
 * Output: JSON array of cookies with domain, name, value, and security flags
 *
 * Author: iOS-Pentesting-Skill
 * Version: 1.0.0
 * License: MIT
 */

if (ObjC.available) {

    console.log("[*] Cookie Dumper for iOS Apps");
    console.log("[*] Extracting cookies from NSHTTPCookieStorage...\n");

    try {
        var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
        var NSHTTPCookie = ObjC.classes.NSHTTPCookie;

        var cookieStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage();
        var cookies = cookieStorage.cookies();

        if (cookies === null || cookies.count() === 0) {
            console.log("[*] No cookies found");
        } else {
            console.log("[*] Found " + cookies.count() + " cookie(s)\n");

            var cookiesArray = [];
            var cookieCount = cookies.count();
            for (var i = 0; i < cookieCount; i++) {
                var cookie = cookies.objectAtIndex_(i);
                if (!cookie || cookie.isNull()) continue;

                try {
                    var cookieObj = {
                        domain: cookie.domain().toString(),
                        name: cookie.name().toString(),
                        value: cookie.value().toString(),
                        path: cookie.path().toString(),
                        secure: cookie.isSecure(),
                        httpOnly: cookie.isHTTPOnly(),
                        comment: cookie.comment() ? cookie.comment().toString() : "",
                        commentURL: cookie.commentURL() ? cookie.commentURL().absoluteString().toString() : "",
                        expires: cookie.expiresDate() ? cookie.expiresDate().toString() : "Session"
                    };

                    cookiesArray.push(cookieObj);
                    console.log("[+] Domain: " + cookieObj.domain);
                    console.log("    Name: " + cookieObj.name);
                    console.log("    Value: " + cookieObj.value);
                    console.log("    Path: " + cookieObj.path);
                    console.log("    Secure: " + cookieObj.secure);
                    console.log("    HttpOnly: " + cookieObj.httpOnly);
                    console.log("    Expires: " + cookieObj.expires);
                    console.log("");

                } catch (e) {
                    console.log("[-] Error reading cookie: " + e);
                }
            }

            console.log("[*] Cookie Summary (JSON):");
            console.log(JSON.stringify(cookiesArray, null, 2));

            console.log("\n[*] Security Analysis:");

            var insecureCookies = cookiesArray.filter(function(c) {
                return !c.secure || !c.httpOnly;
            });

            if (insecureCookies.length > 0) {
                console.log("[!] Found " + insecureCookies.length + " insecure cookie(s):");

                insecureCookies.forEach(function(c) {
                    if (!c.secure) {
                        console.log("    [!] " + c.name + "@" + c.domain + " - Secure flag missing");
                    }
                    if (!c.httpOnly) {
                        console.log("    [!] " + c.name + "@" + c.domain + " - HttpOnly flag missing");
                    }
                });
            } else {
                console.log("[+] All cookies have Secure and HttpOnly flags");
            }

            var sessionCookies = cookiesArray.filter(function(c) {
                return c.expires === "Session";
            });

            if (sessionCookies.length > 0) {
                console.log("\n[*] Session Cookies (no expiration): " + sessionCookies.length);
                sessionCookies.forEach(function(c) {
                    console.log("    [*] " + c.name + " = " + c.value.substring(0, 20) + "...");
                });
            }

            var authCookies = cookiesArray.filter(function(c) {
                var nameLower = c.name.toLowerCase();
                return nameLower.includes("session") ||
                       nameLower.includes("auth") ||
                       nameLower.includes("token");
            });

            if (authCookies.length > 0) {
                console.log("\n[*] Authentication-related cookies: " + authCookies.length);
                authCookies.forEach(function(c) {
                    console.log("    [*] " + c.name + "@" + c.domain);
                });
            }
        }

        console.log("\n[*] Checking WKWebsiteDataStore for cookies...");

        try {
            var WKWebsiteDataStore = ObjC.classes.WKWebsiteDataStore;
            var dataStore = WKWebsiteDataStore.defaultDataStore();

            if (dataStore !== null) {
                console.log("[+] WKWebsiteDataStore found");
                var httpCookieStore = dataStore.httpCookieStore();

                if (httpCookieStore !== null) {
                    console.log("[*] WKWebView cookies are managed separately");
                    console.log("[*] Use Simulator's Safari or inspector to extract");
                }
            }
        } catch(e) {
            console.log("[-] WKWebsiteDataStore not available");
        }

    } catch (e) {
        console.log("[-] Error accessing cookie storage: " + e);
    }

    console.log("\n[*] Cookie extraction complete");

} else {
    console.log("[-] This script requires Objective-C runtime (iOS app)");
}
