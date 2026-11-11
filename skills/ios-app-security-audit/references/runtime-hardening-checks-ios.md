# iOS Runtime Hardening Checks (Frequently Missed)

This reference covers iOS security controls that are commonly missed by
generic mobile-app testing checklists: snapshot/screen-recording
protection, custom keyboard risk, autofill, file protection classes,
biometric replay protection, URLSession auditing, cache cleanup, and
`nscurl`-based ATS testing.

These checks apply to **every** iOS app, regardless of framework
(React Native, Flutter, Swift/ObjC native, etc.).

---

## 1. Background Snapshot Protection

iOS captures a screenshot of the app when it is sent to the
background. The screenshot is shown in the App Switcher and, on
older iOS versions, persisted in `/var/mobile/Library/Caches/Snapshots/`.
Apps that handle sensitive data (banking, health, messaging) must
obscure the screenshot.

### Grep Patterns

```bash
# iOS will show whatever is rendered when willResignActive fires. The
# mitigation is to add a blurred/empty overlay view.
rg -t swift 'applicationWillResignActive|willResignActive' "<app-sources>"
rg -t objc  'applicationWillResignActive'                    "<app-sources>"

# Look for the inverse: views explicitly *not* hidden in background
rg -t swift 'isHidden'  "<app-sources>"
```

### What to look for

- Missing `applicationWillResignActive(_:)` / `sceneWillResignActive(_:)`
  handler that adds a privacy overlay (UIView with blur or solid color).
- App uses `UIScreen.main.snapshotView(afterScreenUpdates:)` but does
  not redraw sensitive content.
- The privacy overlay is added but never removed on
  `applicationDidBecomeActive` / `sceneDidBecomeActive`, so the user
  sees a permanent blur.

### Runtime verification

```bash
# Use Frida to detect overlay presence
frida -U -f com.example.app -l assets/frida-scripts/snapshot-overlay-check.js
```

---

## 2. Custom Keyboard Risk

Apps that allow data entry in sensitive fields should explicitly
reject third-party keyboards. iOS APIs to look for:

### Grep Patterns

```bash
# UITextInputAssistantController / UITextField smartQuotesType affect
# keyboard behavior but do NOT disable third-party keyboards.
# The real API is UITextInputTraits, but iOS offers no public
# per-field toggle to *forbid* third-party keyboards.

# Instead, look for the requestOpenAccess setting on the keyboard
# extension itself (a sibling .appex target). A custom keyboard
# with requestsOpenAccess = true can log everything the user types.
rg -t swift 'requestsOpenAccess'  "<app-extensions>/Keyboard/"
rg -t objc  'requestsOpenAccess'  "<app-extensions>/Keyboard/"
```

### What to look for

- App contains a custom keyboard extension (`.appex` of type
  `NSExtensionPointIdentifier = com.apple.keyboard-service`) — this
  is a *huge* attack surface on its own and should be flagged
  separately.
- Custom keyboards with `RequestsOpenAccess = YES` — the keyboard
  can access network and full text input.
- App does not call `isSecureTextEntry = true` for password fields
  (which suppresses keyboard suggestions and shared typing data
  but does NOT prevent third-party keyboards).

### Risk statement

Apple does not provide a per-field API to disable third-party
keyboards. The mitigations are:

1. App explicitly requires a passcode/biometric to switch keyboards.
2. Sensitive fields use `isSecureTextEntry = true`.
3. The app does not bundle a custom keyboard at all.

---

## 3. AutoFill / Password AutoFill

`ASCredentialIdentityStore` lets apps participate in iOS AutoFill.
Misconfiguration can leak credentials to the wrong service.

### Grep Patterns

```bash
rg -t swift 'ASCredentialIdentityStore|ASCredentialServiceIdentifier'
rg -t objc  'ASCredentialIdentityStore|ASCredentialServiceIdentifier'

# textContentType / textContentType drives AutoFill suggestions
rg -t swift 'textContentType\s*='
```

### What to look for

- App calls `storeCredentialIdentityEntries` with a `serviceIdentifier`
  that uses an unencrypted `URLCredentialIdentity` instead of
  `ASCredentialServiceIdentifier(identifier:serviceIdentifierType:)`.
- `textContentType = .username` and `.password` are set on the same
  field instead of separate fields (iOS requires a username+password
  pair for AutoFill to work correctly).
- App does not call `removeAllCredentialEntries` on logout, leaving
  stale credentials in the system AutoFill database.

---

## 4. Screen Recording / Replay Protection

iOS provides `UIScreen.isCaptured` (iOS 11+) which becomes `true`
when a screen recording or AirPlay mirroring is active. DRM,
banking, and content-protection apps must respond to this.

### Grep Patterns

```bash
rg -t swift 'isCaptured|UIScreen\.main\.isCaptured'
rg -t objc  'isCaptured'
```

### What to look for

- App does not check `UIScreen.main.isCaptured` in
  `applicationDidBecomeActive` or via KVO on `UIScreen.capturedDidChangeNotification`.
- The check is present but only logs a warning instead of hiding
  sensitive content.
- App does not have a `UIScreen.didCapturedChangeNotification`
  observer, so it misses the live transition.

---

## 5. URLSession Auditing (Core Networking)

`URLSession` is the primary networking surface on iOS. Most TLS,
cookie, and cache issues live here. Generic mobile checklists focus
on ATS and skip the URLSession layer entirely.

### Grep Patterns

```bash
# Direct URLSession construction
rg -t swift 'URLSession\.(shared|configuration:|init:)'
rg -t objc  'NSURLSession\s*'

# URLSessionConfiguration.ephemeral = better (no on-disk cache)
rg -t swift 'ephemeral|requestCachePolicy'

# URLCache leaks sensitive data
rg -t swift 'URLCache\.shared|URLCache\.removeAllCachedResponses'

# HTTP cookie storage
rg -t swift 'HTTPCookieStorage\.shared'
rg -t objc  'HTTPCookieStorage\s+sharedCookieStorage'

# Custom URLSessionDelegate / URLSessionTaskDelegate
rg -t swift 'URLSessionDelegate|urlSession\('
rg -t objc  'URLSession:didReceiveChallenge:'
```

### What to look for

- App uses `URLSession.shared` with default configuration (sends
  cookies, uses on-disk cache, persists credentials).
- `URLCache(memoryCapacity:diskCapacity:)` with non-zero
  `diskCapacity` — cached HTTPS responses may contain sensitive
  data. iOS encrypts the cache at rest when the app uses a
  data protection class, but the cache is still extractable via
  backup or jailbreak.
- App does not call `URLCache.shared.removeAllCachedResponses()`
  on logout / sensitive-action completion.
- `HTTPCookieStorage.shared.cookies` is not cleared on logout.
- `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)`
  accepts any certificate (custom trust evaluation that always
  returns `.useCredential`).
- Third-party libraries (Alamofire, AFNetworking) — make sure
  the underlying `URLSession` is configured correctly.

---

## 6. WKWebView Cache & Data Cleanup

`WKWebsiteDataStore` is the iOS 9+ replacement for the deprecated
`NSURLCache` for WebView content.

### Grep Patterns

```bash
rg -t swift 'WKWebsiteDataStore|removeData\('
rg -t objc  'WKWebsiteDataStore|removeData:'
```

### What to look for

- App uses `WKWebsiteDataStore.default()` (persists across launches
  and includes cookies + LocalStorage + IndexedDB).
- Sensitive flows (auth, payment) do not call
  `WKWebsiteDataStore.default().removeData(ofTypes:modifiedSince:)`
  after completion.
- App uses `HTTPCookieStorage.shared` from a WebView without calling
  `removeCookies(since:)`.

---

## 7. File Protection Classes (NSFileProtection)

`NSFileProtectionComplete` (and the `…UnlessOpen` /
`…UntilFirstAuthentication` variants) is the iOS way to make files
unreadable when the device is locked.

### Grep Patterns

```bash
rg -t swift 'NSFileProtectionComplete|FileProtectionType\.'
rg -t objc  'NSFileProtectionComplete|NSFileProtectionNone'
```

### What to look for

- Files written with `Data.write(to:options:)` without
  `.completeFileProtection` (or similar) — files are readable
  while the device is locked.
- `NSFileProtectionNone` — files are readable always, including
  before first unlock after boot. **Critical** for any file
  containing credentials, PII, or tokens.
- App relies on the bundle-level
  `com.apple.developer.default-data-protection` entitlement
  (defaults to `NSFileProtectionCompleteUntilFirstUserAuthentication`)
  but writes some files with explicit lower protection.

### Runtime verification

```bash
# data-protection-check.js enumerates all files in the app container
# and reports their NSFileProtection level.
frida -U -f com.example.app -l assets/frida-scripts/data-protection-check.js
```

---

## 8. Biometric Replay Protection (LAContext is not enough)

`LAContext.evaluatePolicy` only proves that *the user* authenticated.
It does NOT bind the authentication to a specific operation, so a
man-in-the-middle / replay attacker who can intercept the result can
re-use it.

The correct pattern is to combine a biometric prompt with a
cryptographically-protected key in the Secure Enclave (or
keychain with `SecAccessControl`):

### Insecure pattern (replayable)

```swift
LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                          localizedReason: "Confirm payment") { ok, _ in
    if ok { submitPayment(amount: 100) }   // ❌ attacker can replay this
}
```

### Secure pattern (biometric-bound key)

```swift
// 1. Generate a key that requires biometrics for every use
let access = SecAccessControlCreateWithFlags(nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet,
    nil)!
// 2. Store in keychain with the access control
// 3. To authorize the payment:
//    - Load the key (triggers Face ID / Touch ID prompt via LAContext)
//    - Use it to sign a server-side nonce
//    - Send (signed_nonce, op) to the server
//    - Server validates the signature — replay impossible
```

### Grep Patterns

```bash
# Detect apps that use evaluatePolicy without a corresponding
# SecAccessControl / Secure Enclave key
rg -t swift 'evaluatePolicy\('
rg -t objc  'evaluatePolicy:'
rg -t swift 'SecAccessControlCreateWithFlags'
```

### What to look for

- `evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` is
  used directly to gate sensitive operations without a
  cryptographic key being unlocked.
- The biometric prompt is the *only* gate; no server-side nonce
  is signed.
- `LAPolicy.deviceOwnerAuthentication` (the fallback to passcode)
  is used where the threat model requires biometric-only.

---

## 9. ATS Compliance Testing with `nscurl`

Apple's `nscurl` tool is the standard way to verify ATS
(App Transport Security) compliance against a real server.

### Usage

```bash
# Run all ATS diagnostics against a URL
xcrun nscurl --ats-diagnostics https://target.example.com

# Strict mode (forces TLS 1.2+ and forward secrecy)
xcrun nscurl --ats-diagnostics --minimum-tls-version TLSv1.2 \
            https://target.example.com

# Verbose output (recommended)
xcrun nscurl -v --ats-diagnostics https://target.example.com
```

### What to look for in the output

`nscurl` reports one line per check. A passing result looks like:

```
Default ATS Secure Connection: PASS
NSAllowsArbitraryLoadsInWebContent: PASS
NSAllowsLocalNetworking: PASS
```

A failing result is the kind of finding that belongs in the
report under "ATS exception allows insecure connection" or
"App pins to TLS 1.0 server".

### Combine with Info.plist audit

Pair `nscurl` output with the `NSAppTransportSecurity` and
`NSExceptionDomains` keys extracted from `Info.plist`
(see `references/ats-configuration-guide.md`).

---

## 10. Universal Links & Associated Domains

Universal Links (`apple-app-site-association`) are the only
deep-link mechanism that cannot be hijacked by another app — but
only if the `associated-domains` entitlement is configured
correctly and the server-hosted `apple-app-site-association`
file is properly signed.

### Grep / Runtime

```bash
# Entitlement
codesign -d --entitlements - Target.app/Target

# Expected entitlement format:
#   <key>com.apple.developer.associated-domains</key>
#   <array>
#       <string>applinks:example.com</string>
#   </array>

# Server-side: verify the AASA file is served over HTTPS and is
# either application/json or text/plain (Apple accepts both).
curl -v https://example.com/.well-known/apple-app-site-association
```

### What to look for

- `applinks:` is listed but the `apple-app-site-association` file
  is missing or malformed on the server.
- App handles Universal Links without validating the
  `_kCFWebPageURL` / `inputURL` parameter against an allowlist.
- App mixes URL schemes and Universal Links for the same path,
  creating a downgrade path (attacker uses the URL scheme on a
  device where the app is not installed for the Universal Link).

---

## 11. Cache & Temporary Directory Hygiene

iOS places files in three primary writeable locations:
`Documents/`, `Library/Caches/`, and `tmp/`. Each has different
backup and eviction semantics.

### Grep Patterns

```bash
rg -t swift 'NSTemporaryDirectory|FileManager\.default\.temporaryDirectory'
rg -t objc  'NSTemporaryDirectory'
rg -t swift 'Library/Caches|cachesDirectory'
```

### What to look for

- Sensitive data (tokens, PII) written to `tmp/` (evicted by iOS
  but **not encrypted by default**) instead of
  `Application Support/` with a data protection class.
- Cache files that contain decrypted responses from auth-sensitive
  endpoints.
- App relies on the OS to evict `Library/Caches/` — it may not
  happen for a long time, and the data is in the iTunes/Finder
  backup by default.
- `.completeFileProtection` is not set on sensitive files in
  any of the three directories.

---

## 12. App Group Containers (Cross-App Data)

App groups (`group.com.example.shared`) allow multiple apps from
the same vendor to share a container. Misconfigured access lets
*any* app in the group read files that were meant for a
specific app.

### Grep / Runtime

```bash
# Entitlement
codesign -d --entitlements - Target.app/Target

# Look for:
#   <key>com.apple.security.application-groups</key>
#   <array>
#       <string>group.com.example.shared</string>
#   </array>
```

### Frida runtime check

```bash
frida -U -f com.example.app -l assets/frida-scripts/app-groups-inspector.js
```

### What to look for

- Group container holds sensitive data (auth tokens, user PII)
  without per-file access control beyond the group ACL.
- Group container is readable by an app extension
  (`.appex`) that does not need the data.
- Group identifier is shared with a third-party SDK app (rare but
  possible if the SDK ships its own iOS app).

---

## Summary

Add these checks to every iOS engagement. They are *not* covered
by the standard OWASP MASTG checklist and are consistently the
source of high-severity findings in real-world audits:

| # | Check | Tool |
|---|-------|------|
| 1 | Background snapshot obfuscation | grep + Frida |
| 2 | Custom keyboard risk | grep + `requestsOpenAccess` |
| 3 | AutoFill / ASCredentialIdentityStore | grep |
| 4 | Screen recording detection | grep + Frida |
| 5 | URLSession audit | grep + Frida |
| 6 | WKWebView cache cleanup | grep + Frida |
| 7 | File protection classes | grep + `data-protection-check.js` |
| 8 | Biometric replay protection | grep + code review |
| 9 | ATS compliance | `nscurl --ats-diagnostics` |
| 10 | Universal Links validation | `codesign` + `curl` AASA |
| 11 | Cache & tmp hygiene | grep + filesystem audit |
| 12 | App group containers | `codesign` + `app-groups-inspector.js` |
