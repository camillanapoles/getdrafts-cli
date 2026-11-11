# iOS Static Analysis Patterns

**Comprehensive grep pattern catalog for iOS static security analysis.**

## Table of Contents

1. [Cross-Platform Compatibility](#1-cross-platform-compatibility)
2. [iOS File Inventory](#2-ios-file-inventory)
3. [WebView Security](#3-webview-security)
4. [IPC and URL Schemes](#4-ipc-and-url-schemes)
5. [Keychain Security](#5-keychain-security)
6. [UserDefaults Security](#6-userdefaults-security)
7. [Pasteboard Security](#7-pasteboard-security)
8. [Hardcoded Secrets](#8-hardcoded-secrets)
9. [Cryptography](#9-cryptography)
10. [TLS and ATS](#10-tls-and-ats)
11. [Logging](#11-logging)
12. [File I/O](#12-file-io)
13. [Background Tasks](#13-background-tasks)
14. [Biometric Authentication](#14-biometric-authentication)
15. [SQLite/CoreData](#15-sqlitecoredata)
16. [Networking](#16-networking)

---

## 1. Cross-Platform Compatibility

### Grep Command Compatibility

macOS uses BSD grep, which doesn't support PCRE (`-P` flag). Use these alternatives:

```bash
# Option 1: Use grep -E (extended regex - compatible)
grep -rnE "pattern" directory/

# Option 2: Use ripgrep (recommended - faster and cross-platform)
rg "pattern" directory/
# Install: brew install ripgrep

# Option 3: Install GNU grep on macOS
brew install grep
# Then use: ggrep -P "pattern" directory/

# Option 4: Use perl one-liner (universal fallback)
find . -type f -exec perl -nle 'print "$ARGV: $_" if /pattern/' {} \;
```

**⚠️ IMPORTANT**: This reference uses `rg` (ripgrep) patterns for cross-platform compatibility. If using `grep`, convert:
- `\d` → `[0-9]`
- `\w` → `[a-zA-Z0-9_]`
- `+` → `\+` (in grep -E, not needed)

---

## 2. iOS File Inventory

### Extracting IPA

```bash
# Extract IPA
unzip -q target.ipa -d extracted/

# Navigate to app
cd extracted/Payload/*.app/

# List contents
ls -la
```

### File Extensions

| Extension | Language | Notes |
|-----------|-----------|-------|
| `.m` | Objective-C | Source (if present) |
| `.swift` | Swift | Source (if present) |
| `.h` | Objective-C | Header (if present) |
| `.framework` | Any | Framework bundle |
| `.dylib` | Any | Dynamic library |
| `.plist` | Any | Property list (XML/binary) |

---

## 3. WebView Security

### WKWebView - Load URL Without Validation

**Pattern**: `loadURL` or `loadRequest` without URL validation

**Regex (ObjC)**:
```regex
(?i)loadRequest:.*NSUrlRequest.*NSURL
```

**Regex (Swift)**:
```regex
(?i)load\s*\(\s*URLRequest\s*\(
```

**File Types**: `.m`, `.swift`

**What it finds**: WebView loading arbitrary URLs without validation

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Validate URL scheme (allow only `https://`, `app-specific://`)
- Whitelist allowed domains
- Reject `file://`, `javascript:`, `data:` schemes

---

### WKWebView - JavaScript Interface

**Pattern**: Exposing JavaScript handlers that accept unsanitized input

**Regex (ObjC)**:
```regex
(?i)addScriptMessageHandler.*name:
```

**Regex (Swift)**:
```regex
(?i)add\s*\(\s*ScriptMessageHandler\s*\(
```

**File Types**: `.m`, `.swift`

**What it finds**: WKWebView script message handlers

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Validate message name
- Sanitize message body
- Restrict to trusted origins
- Use `WKUserContentController` properly

---

### WKWebView - User Agent Modification

**Pattern**: Custom user agent string (may indicate bypass detection)

**Regex (ObjC)**:
```regex
(?i)setCustomUserAgent:
```

**Regex (Swift)**:
```regex
(?i)customUserAgent\s*=
```

**File Types**: `.m`, `.swift`

**What it finds**: Custom user agent modification

**Severity**: Low

**False Positive Rate**: High

**Remediation**:
- Document legitimate use cases
- Avoid arbitrary user agent strings

---

### WKWebView - JavaScript Evaluation

**Pattern**: Dynamic JavaScript evaluation with unsanitized input

**Regex (ObjC)**:
```regex
(?i)evaluateJavaScript:
```

**Regex (Swift)**:
```regex
(?i)evaluateJavaScript\s*\(
```

**File Types**: `.m`, `.swift`

**What it finds**: JavaScript evaluation in WebView

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Sanitize JavaScript input
- Validate JSON responses
- Avoid user-controlled JavaScript

---

### WKWebView - File Access

**Pattern**: Enabling file access in WebView

**Regex (ObjC)**:
```regex
(?i)allowsFileAccess\s*=\s*YES
```

**Regex (Swift)**:
```regex
(?i)allowsFileAccess\s*=\s*true
```

**File Types**: `.m`, `.swift`

**What it finds**: File access enabled in WebView

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Disable file access unless absolutely necessary
- Use `allowsFileAccess = false`

---

### UIWebView - Deprecated

**Pattern**: Using deprecated UIWebView

**Regex (ObjC)**:
```regex
(?i)UIWebView
```

**Regex (Swift)**:
```regex
(?i)UIWebView\s*\(
```

**File Types**: `.m`, `.swift`

**What it finds**: Deprecated UIWebView usage

**Severity**: Medium

**False Positive Rate**: Low

**Remediation**:
- Migrate to WKWebView
- UIWebView is deprecated and has security issues

---

## 4. IPC and URL Schemes

### URL Scheme Handling - Missing Validation

**Pattern**: Handling URL schemes without validation

**Regex (ObjC)**:
```regex
(?i)application.*openURL.*options:
```

**Regex (Swift)**:
```regex
(?i)application\s*\(\s*_\s*:.*open\s*\(\s*url\s*:\s*URL
```

**File Types**: `.m`, `.swift`

**What it finds**: URL scheme handling in app delegate

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Validate URL scheme (whitelist allowed schemes)
- Validate URL path and parameters
- Reject generic schemes (`http://`, `https://`, `file://`)

---

### Deep Link - Path Traversal

**Pattern**: Using URL path directly without validation

**Regex (ObjC)**:
```regex
(?i)url\.(path|query)
```

**Regex (Swift)**:
```regex
(?i)url\.(path|query)\s*
```

**File Types**: `.m`, `.swift`

**What it finds**: Direct URL path usage

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Whitelist allowed paths
- Validate path format
- Reject path traversal (`../`)

---

### Universal Links - No Validation

**Pattern**: Universal link handler without origin validation

**Regex (ObjC)**:
```regex
(?i)continueUserActivity.*restorationHandler:
```

**Regex (Swift)**:
```regex
(?i)continue\s*\(\s*_\s*:.*userActivity.*restorationHandler
```

**File Types**: `.m`, `.swift`

**What it finds**: Universal link handling

**Severity**: Medium

**False Positive Rate**: Low

**Remediation**:
- Validate `NSUserActivity.webpageURL`
- Check domain whitelist
- Verify URL format

---

### CanOpenURL - Sensitive Schemes

**Pattern**: Querying for sensitive URL schemes

**Regex (ObjC)**:
```regex
(?i)canOpenURL.*(?i)(tel:|sms:|mailto:|itms:|itms-apps:|file:)
```

**Regex (Swift)**:
```regex
(?i)canOpen\s*\(\s*URL\s*\(\s*string\s*:\s*["'](?i)(tel:|sms:|mailto:|itms:|itms-apps:|file:)
```

**File Types**: `.m`, `.swift`

**What it finds**: Checking for sensitive URL schemes

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Document legitimate use cases
- Avoid checking for sensitive schemes

---

## 5. Keychain Security

### Keychain - No Access Control

**Pattern**: Keychain operations without access control

**Regex (ObjC)**:
```regex
(?i)SecItemAdd.*(?i)(?!kSecAttrAccessControl)
```

**Regex (Swift)**:
```regex
(?i)SecItemAdd\s*\(\s*(?!.*kSecAttrAccessControl)
```

**File Types**: `.m`, `.swift`

**What it finds**: Keychain operations without access control

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use `kSecAttrAccessControl` with user presence or biometric requirement
- Implement `kSecAccessControlUserPresence` for sensitive data

---

### Keychain - Plaintext Storage

**Pattern**: Storing plaintext data in Keychain

**Regex (ObjC)**:
```regex
(?i)SecItemAdd.*(?i)kSecValueData.*(?i)(NSString|NSData).*
```

**Regex (Swift)**:
```regex
(?i)SecItemAdd.*(?i)kSecValueData.*(?i)(String|Data)
```

**File Types**: `.m`, `.swift`

**What it finds**: Keychain storage without proper data type

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Use proper `NSData` format
- Encrypt sensitive data before storing
- Use `kSecAttrAccessible` with appropriate protection level

---

### Keychain - Deprecated `kSecAttrAccessibleAlways`

**Pattern**: Using the deprecated `kSecAttrAccessibleAlways` constant (deprecated in iOS 12)

**Regex (ObjC)**:
```regex
(?i)kSecAttrAccessibleAlways\b(?!ThisDeviceOnly|WhenPasscodeSet)
```

**Regex (Swift)**:
```regex
(?i)kSecAttrAccessibleAlways\b(?!ThisDeviceOnly|WhenPasscodeSet)
```

**File Types**: `.m`, `.swift`

**What it finds**: Use of the deprecated `kSecAttrAccessibleAlways` constant

**Severity**: High (deprecation + accessibility bypass when device locked)

**False Positive Rate**: Low

**Remediation**:
- Use `kSecAttrAccessibleWhenUnlocked` (default — appropriate for most cases)
- Use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for sensitive data
- Use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for non-critical data

> **Note**: `kSecAttrAccessibleWhenUnlocked` is the Apple default and is **not** a finding. Flag only `kSecAttrAccessibleAlways` (deprecated) and use of `AfterFirstUnlock` for credential storage.

---

## 6. UserDefaults Security

### UserDefaults - Sensitive Data

**Pattern**: Storing sensitive data in UserDefaults

**Regex (ObjC)**:
```regex
(?i)NSUserDefaults.*(?i)(password|token|secret|key|credential)
```

**Regex (Swift)**:
```regex
(?i)UserDefaults\.(standard|init).*(?i)(password|token|secret|key|credential)
```

**File Types**: `.m`, `.swift`

**What it finds**: Sensitive data in UserDefaults

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use Keychain for sensitive data
- Never store passwords, tokens, or keys in UserDefaults
- Use Keychain for authentication data

---

### UserDefaults - Not Synchronized

**Pattern**: Using UserDefaults without iCloud sync (may indicate sensitive data)

**Regex (ObjC)**:
```regex
(?i)NSUserDefaults.*initWithSuiteName:
```

**Regex (Swift)**:
```regex
(?i)UserDefaults\s*\(\s*suiteName\s*:
```

**File Types**: `.m`, `.swift`

**What it finds**: Custom UserDefaults suite

**Severity**: Low

**False Positive Rate**: High

**Remediation**:
- Document legitimate use cases
- Avoid storing sensitive data in custom suites

---

### UserDefaults - Plaintext

**Pattern**: Checking UserDefaults for plaintext values

**Regex (ObjC)**:
```regex
(?i)objectForKey.*(?i)(password|token|secret)
```

**Regex (Swift)**:
```regex
(?i)object\s*\(\s*forKey.*(?i)(password|token|secret)
```

**File Types**: `.m`, `.swift`

**What it finds**: Retrieving sensitive data from UserDefaults

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Migrate to Keychain
- Use `SecItemCopyMatching` for authentication data

---

## 7. Pasteboard Security

### UIPasteboard - Sensitive Data

**Pattern**: Reading from pasteboard

**Regex (ObjC)**:
```regex
(?i)UIPasteboard.*string
```

**Regex (Swift)**:
```regex
(?i)UIPasteboard.*string\s*
```

**File Types**: `.m`, `.swift`

**What it finds**: Pasteboard reading

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Validate pasteboard content before use
- Document legitimate use cases
- Avoid automatic pasteboard reading

---

### UIPasteboard - Writing Sensitive Data

**Pattern**: Writing sensitive data to pasteboard

**Regex (ObjC)**:
```regex
(?i)UIPasteboard.*setString.*(?i)(password|token|secret|key)
```

**Regex (Swift)**:
```regex
(?i)UIPasteboard.*string\s*=.*(?i)(password|token|secret|key)
```

**File Types**: `.m`, `.swift`

**What it finds**: Writing sensitive data to pasteboard

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Never write passwords or tokens to pasteboard
- Use secure copy/paste for sensitive data
- Clear pasteboard after use

---

## 8. Hardcoded Secrets

### API Keys

**Pattern**: Hardcoded API keys

**Regex (ObjC)**:
```regex
(?i)(@"|')([A-Za-z0-9_-]{20,})(@"|')
```

**Regex (Swift)**:
```regex
(?i)(?:"|')([A-Za-z0-9_-]{20,})(?:"|')
```

**File Types**: `.m`, `.swift`, `.plist`

**What it finds**: Potential API keys

**Severity**: Critical

**False Positive Rate**: High

**Remediation**:
- Remove hardcoded keys
- Use environment variables or secure configuration
- Use Apple's CryptoKit for key generation

---

### Hardcoded Passwords

**Pattern**: Hardcoded passwords

**Regex (ObjC)**:
```regex
(?i)password\s*=\s*@"[^"]+"
```

**Regex (Swift)**:
```regex
(?i)password\s*=\s*"[^"]+"
```

**File Types**: `.m`, `.swift`

**What it finds**: Hardcoded passwords

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Remove hardcoded passwords
- Use authentication frameworks (Keychain, LocalAuthentication)
- Implement proper authentication flow

---

### AWS Credentials

**Pattern**: AWS access keys

**Regex**:
```regex
(?i)(AKIA[0-9A-Z]{16})|(AWS.*Secret.*Key)
```

**File Types**: `.m`, `.swift`, `.plist`

**What it finds**: AWS credentials

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Remove hardcoded AWS credentials
- Use AWS SDK with proper configuration
- Use temporary credentials via STS

---

### Firebase Credentials

**Pattern**: Firebase configuration

**Regex**:
```regex
(?i)firebaseio\.com|firebaseapp\.com
```

**File Types**: `.plist`, `.m`, `.swift`

**What it finds**: Firebase configuration URLs

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use Firebase Authentication for access control
- Implement database rules
- Use App Check for additional protection

---

### Google API Keys

**Pattern**: Google API keys

**Regex**:
```regex
(?i)(AIza[0-9A-Za-z_-]{35})|(GOOGLE.*API.*KEY)
```

**File Types**: `.plist`, `.m`, `.swift`

**What it finds**: Google API keys

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Restrict API key usage in Google Cloud Console
- Use API key restrictions (HTTP referrer, IP addresses)
- Implement quota limits

---

## 9. Cryptography

### Weak Crypto - DES

**Pattern**: DES encryption algorithm

**Regex (ObjC)**:
```regex
(?i)kCCAlgorithmDES
```

**Regex (Swift)**:
```regex
(?i)kCCAlgorithmDES|\.DES
```

**File Types**: `.m`, `.swift`

**What it finds**: DES encryption usage

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use AES instead of DES
- Use CryptoKit for modern cryptography
- Avoid legacy encryption algorithms

---

### Weak Crypto - RC4

**Pattern**: RC4 encryption algorithm

**Regex (ObjC)**:
```regex
(?i)kCCAlgorithmRC4
```

**Regex (Swift)**:
```regex
(?i)kCCAlgorithmRC4|\.RC4
```

**File Types**: `.m`, `.swift`

**What it finds**: RC4 encryption usage

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use AES instead of RC4
- Use CryptoKit or CommonCrypto with proper configuration

---

### Weak Crypto - MD5

**Pattern**: MD5 hash algorithm

**Regex (ObjC)**:
```regex
(?i)CC_MD5
```

**Regex (Swift)**:
```regex
(?i)CC_MD5|\.MD5
```

**File Types**: `.m`, `.swift`

**What it finds**: MD5 hash usage

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use SHA-256 or SHA-512 instead of MD5
- Use CryptoKit's `SHA256` or `Insecure.SHA256`
- Avoid MD5 for security purposes

---

### Weak Crypto - SHA1

**Pattern**: SHA1 hash algorithm

**Regex (ObjC)**:
```regex
(?i)CC_SHA1
```

**Regex (Swift)**:
```regex
(?i)CC_SHA1|\.SHA1
```

**File Types**: `.m`, `.swift`

**What it finds**: SHA1 hash usage

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Use SHA-256 or higher
- Use CryptoKit's `SHA256`

---

### Hardcoded IV

**Pattern**: Hardcoded initialization vector

**Regex (ObjC)**:
```regex
(?i)iv.*=.*@"[a-zA-Z0-9+/=]+"
```

**Regex (Swift)**:
```regex
(?i)iv\s*=\s*"[a-zA-Z0-9+/=]+"
```

**File Types**: `.m`, `.swift`

**What it finds**: Hardcoded IV for encryption

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Generate random IV for each encryption
- Store IV with encrypted data
- Use CryptoKit's `AES.GCM` which handles IV automatically

---

### Hardcoded Salt

**Pattern**: Hardcoded salt for hashing

**Regex (ObjC)**:
```regex
(?i)salt.*=.*@"[a-zA-Z0-9+/=]+"
```

**Regex (Swift)**:
```regex
(?i)salt\s*=\s*"[a-zA-Z0-9+/=]+"
```

**File Types**: `.m`, `.swift`

**What it finds**: Hardcoded salt for hashing

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Use random salt for each password hash
- Store salt with hashed password
- Use PBKDF2, scrypt, or bcrypt with random salt

---

## 10. TLS and ATS

### Cleartext HTTP

**Pattern**: HTTP (non-HTTPS) URLs

**Regex**:
```regex
(?i)http://(?!localhost|127\.0\.0\.1)
```

**File Types**: `.m`, `.swift`, `.plist`

**What it finds**: Cleartext HTTP usage

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Use HTTPS only
- Configure ATS properly in Info.plist
- Remove `NSAllowsArbitraryLoads` from Info.plist

---

### ATS Disabled

**Pattern**: ATS disabled in Info.plist

**Regex**:
```regex
(?i)NSAllowsArbitraryLoads\s*=\s*true
```

**File Types**: `.plist`

**What it finds**: ATS completely disabled

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Enable ATS in Info.plist
- Remove `NSAllowsArbitraryLoads`
- Use HTTPS for all network communication

---

### ATS Domain Exception

**Pattern**: ATS domain exceptions

**Regex**:
```regex
(?i)NSExceptionDomains
```

**File Types**: `.plist`

**What it finds**: ATS domain exceptions

**Severity**: Medium

**False Positive Rate**: Low

**Remediation**:
- Review all domain exceptions
- Minimize exception scope
- Use specific subdomains instead of wildcards

---

### No SSL Pinning

**Pattern**: Network operations without SSL pinning

**Regex (ObjC)**:
```regex
(?i)NSURLConnection|NSURLSession.*(?i)(?!SSLPinning|Pinning)
```

**Regex (Swift)**:
```regex
(?i)URLSession|URLRequest.*(?i)(?!SSLPinning|Pinning)
```

**File Types**: `.m`, `.swift`

**What it finds**: Network operations without SSL pinning

**Severity**: Medium

**False Positive Rate**: High

**Remediation**:
- Implement SSL pinning for sensitive APIs
- Use `NSURLSession` with `NSURLSessionDelegate`
- Validate server certificates

---

## 11. Logging

### NSLog - Sensitive Data

**Pattern**: Logging sensitive data

**Regex (ObjC)**:
```regex
(?i)NSLog.*(?i)(password|token|secret|key|credential|credit.?card|ssn)
```

**Regex (Swift)**:
```regex
(?i)print\s*\(|NSLog.*(?i)(password|token|secret|key|credential|credit.?card|ssn)
```

**File Types**: `.m`, `.swift`

**What it finds**: Logging sensitive data

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Remove all sensitive data logging
- Use proper logging framework (OSLog, CocoaLumberjack) with appropriate levels
- Disable debug logging in production

---

### NSLog - Debug Statements

**Pattern**: Debug log statements

**Regex (ObjC)**:
```regex
(?i)NSLog.*(?i)(DEBUG|debug|test|TODO|FIXME)
```

**Regex (Swift)**:
```regex
(?i)print.*(?i)(DEBUG|debug|test|TODO|FIXME)|NSLog.*(?i)(DEBUG|debug|test|TODO|FIXME)
```

**File Types**: `.m`, `.swift`

**What it finds**: Debug log statements

**Severity**: Low

**False Positive Rate**: High

**Remediation**:
- Remove debug statements in production
- Use conditional compilation (`#if DEBUG`)
- Implement proper logging levels

---

### Console.log - Sensitive Data

**Pattern**: Console logging in Swift

**Regex (Swift)**:
```regex
(?i)console\.log.*(?i)(password|token|secret|key|credential)
```

**File Types**: `.swift`

**What it finds**: Console logging sensitive data

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Remove sensitive data from console logs
- Use OSLog with privacy options
- Disable logging in production

---

## 12. File I/O

### File Path Traversal

**Pattern**: Using user-provided path directly

**Regex (ObjC)**:
```regex
(?i)stringWithContentsOfFile.*(?i)(?!sanitized|validated)
```

**Regex (Swift)**:
```regex
(?i)try.*String\s*\(\s*contentsOfFile.*(?i)(?!sanitized|validated)
```

**File Types**: `.m`, `.swift`

**What it finds**: File operations without path validation

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Validate and sanitize file paths
- Use sandboxed file access
- Restrict to app container

---

### Document Directory Access

**Pattern**: Accessing document directory

**Regex (ObjC)**:
```regex
(?i)NSDocumentDirectory
```

**Regex (Swift)**:
```regex
(?i)DocumentDirectory|\.documentsDirectory
```

**File Types**: `.m`, `.swift`

**What it finds**: Document directory access

**Severity**: Low

**False Positive Rate**: High

**Remediation**:
- Document legitimate use cases
- Verify no sensitive data in Documents directory
- Check if file sharing is enabled

---

### Temporary File in Documents

**Pattern**: Creating temporary files in Documents

**Regex (ObjC)**:
```regex
(?i)writeToFile.*Documents.*tmp
```

**Regex (Swift)**:
```regex
(?i)write.*\(to.*Documents.*tmp
```

**File Types**: `.m`, `.swift`

**What it finds**: Temporary files in Documents directory

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Use proper temp directory (`NSTemporaryDirectory()`)
- Clean up temporary files
- Avoid storing temp data in Documents

---

## 13. Background Tasks

### Background Fetch

**Pattern**: Background fetch enabled

**Regex**:
```regex
(?i)UIBackgroundModes.*fetch
```

**File Types**: `.plist`

**What it finds**: Background fetch mode

**Severity**: Low

**False Positive Rate**: Low

**Remediation**:
- Document legitimate use cases
- Minimize data collected in background
- Implement proper error handling

---

### Background Location

**Pattern**: Background location updates

**Regex**:
```regex
(?i)UIBackgroundModes.*location
```

**File Types**: `.plist`

**What it finds**: Background location tracking

**Severity**: Medium

**False Positive Rate**: Low

**Remediation**:
- Document legitimate use cases
- Provide user consent
- Minimize data collection frequency

---

### Background Audio

**Pattern**: Background audio enabled

**Regex**:
```regex
(?i)UIBackgroundModes.*audio
```

**File Types**: `.plist`

**What it finds**: Background audio mode

**Severity**: Low

**False Positive Rate**: Low

**Remediation**:
- Document legitimate use cases
- Ensure audio stops when not needed

---

## 14. Biometric Authentication

### Face ID - No Passcode Fallback

**Pattern**: Face ID without passcode fallback

**Regex (ObjC)**:
```regex
(?i)evaluatePolicy.*deviceOwnerAuthenticationWithBiometrics
```

**Regex (Swift)**:
```regex
(?i)evaluatePolicy.*deviceOwnerAuthenticationWithBiometrics
```

**File Types**: `.m`, `.swift`

**What it finds**: Biometric authentication without passcode fallback

**Severity**: High

**False Positive Rate**: Low

**Remediation**:
- Use `deviceOwnerAuthentication` (includes passcode)
- Provide fallback authentication method
- Handle authentication errors properly

---

### Face ID - No Cancellation

**Pattern**: Face ID without user cancellation handling

**Regex (ObjC)**:
```regex
(?i)evaluatePolicy.*(?i)(?!userFallback|cancel)
```

**Regex (Swift)**:
```regex
(?i)evaluatePolicy.*(?i)(?!userFallback|cancel)
```

**File Types**: `.m`, `.swift`

**What it finds**: Biometric auth without cancellation handling

**Severity**: Medium

**False Positive Rate**: High

**Remediation**:
- Handle `.userCancel` error
- Provide UI for manual cancellation
- Implement proper error handling

---

### Face ID - Cached Auth

**Pattern**: Face ID with long-lived authentication

**Regex (ObjC)**:
```regex
(?i)evaluatePolicy.*(?i)(?!invalidate|timeout|expire)
```

**Regex (Swift)**:
```regex
(?i)evaluatePolicy.*(?i)(?!invalidate|timeout|expire)
```

**File Types**: `.m`, `.swift`

**What it finds**: Authentication without expiration

**Severity**: Medium

**False Positive Rate**: High

**Remediation**:
- Implement authentication timeout
- Invalidate authentication after sensitive operations
- Use `LAContext.invalidate()`

---

## 15. SQLite/CoreData

### SQL Injection - String Concatenation

**Pattern**: SQL queries with string concatenation

**Regex (ObjC)**:
```regex
(?i)SELECT.*FROM.*WHERE.*%@.*format:
```

**Regex (Swift)**:
```regex
(?i)SELECT.*FROM.*WHERE.*\(.*String\(format:
```

**File Types**: `.m`, `.swift`

**What it finds**: SQL injection vulnerability via string concatenation

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Use parameterized queries
- Use `FMDatabase` or CoreData with proper escaping
- Validate and sanitize all input

---

### CoreData - No Predicate Validation

**Pattern**: CoreData predicates without validation

**Regex (Swift)**:
```regex
(?i)NSPredicate.*format.*(?i)(?!sanitized|validated)
```

**File Types**: `.swift`, `.m`

**What it finds**: CoreData queries with unsanitized input

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Validate predicate input
- Use parameterized predicates
- Sanitize user input

---

### SQLite - Plaintext Storage

**Pattern**: Storing plaintext in SQLite

**Regex (ObjC)**:
```regex
(?i)executeUpdate.*(?i)(password|token|secret|key).*(?i)(?!encrypted|cipher)
```

**Regex (Swift)**:
```regex
(?i)execute.*(?i)(password|token|secret|key).*(?i)(?!encrypted|cipher)
```

**File Types**: `.m`, `.swift`

**What it finds**: Storing sensitive data in plaintext

**Severity**: Critical

**False Positive Rate**: Low

**Remediation**:
- Encrypt sensitive data before storage
- Use SQLCipher for database encryption
- Use Keychain for authentication data

---

## 16. Networking

### API Endpoint Hardcoded

**Pattern**: Hardcoded API endpoints

**Regex**:
```regex
(?i)https?://[a-zA-Z0-9.-]+\.[a-z]{2,}/api/
```

**File Types**: `.m`, `.swift`, `.plist`

**What it finds**: Hardcoded API endpoints

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Use configuration files or environment variables
- Document all API endpoints
- Implement proper endpoint management

---

### URLSession - No Timeout

**Pattern**: URLSession without timeout

**Regex (ObjC)**:
```regex
(?i)NSURLSession.*(?i)(?!timeoutInterval|timeout)
```

**Regex (Swift)**:
```regex
(?i)URLSession.*(?i)(?!timeoutInterval|timeout)
```

**File Types**: `.m`, `.swift`

**What it finds**: Network requests without timeout

**Severity**: Medium

**False Positive Rate**: Medium

**Remediation**:
- Set appropriate timeout intervals
- Handle timeout errors properly
- Implement retry logic with backoff

---

### Multipart Upload - No Size Limit

**Pattern**: Multipart upload without size limit

**Regex (ObjC)**:
```regex
(?i)appendPartWithFile.*(?i)(?!maxSize|limit|checkSize)
```

**Regex (Swift)**:
```regex
(?i)append.*\(.*withName.*(?i)(?!maxSize|limit|checkSize)
```

**File Types**: `.m`, `.swift`

**What it finds**: File upload without size validation

**Severity**: High

**False Positive Rate**: Medium

**Remediation**:
- Validate file size before upload
- Set maximum upload size
- Implement proper error handling

---

### JSON Parsing - No Validation

**Pattern**: JSON parsing without validation

**Regex (ObjC)**:
```regex
(?i)JSONObjectWithData.*(?i)(?!options.*allowFragments|NSJSONReadingAllowFragments)
```

**Regex (Swift)**:
```regex
(?i)JSON.*decode.*(?i)(?!try.*catch|validate)
```

**File Types**: `.m`, `.swift`

**What it finds**: JSON parsing without error handling

**Severity**: Medium

**False Positive Rate**: High

**Remediation**:
- Use `try-catch` for JSON parsing
- Validate JSON structure
- Handle parsing errors gracefully

---

## Namespace Filtering

### Filter System Frameworks

```bash
# Exclude system frameworks
rg "pattern" --type swift --type objc --type m | grep -v "/System/Library/Frameworks/"
rg "pattern" --type swift --type objc --type m | grep -v "/usr/lib/"

# Exclude Apple frameworks
rg "pattern" | grep -v "Apple\|Foundation\|UIKit\|CoreData\|CoreLocation"
```

### Include Only App Code

```bash
# Search only in app bundle
rg "pattern" Payload/*.app/

# Search only in source files
rg "pattern" --type swift --type objc
```

---

## Quick Scan Script

```bash
#!/bin/bash

DIR="${1:-.}"

echo "=== iOS Static Analysis Quick Scan ==="
echo ""
echo "Scanning: $DIR"
echo ""

# Check for hardcoded secrets
echo "1. Hardcoded Secrets:"
if rg -i "password|token|secret|api_key" --type swift --type objc "$DIR" | head -5; then
    echo "   Found potential secrets"
else
    echo "   No obvious secrets found"
fi
echo ""

# Check for weak crypto
echo "2. Weak Cryptography:"
if rg -i "DES|RC4|MD5|SHA1" --type swift --type objc "$DIR" | head -5; then
    echo "   Found weak cryptography"
else
    echo "   No weak cryptography found"
fi
echo ""

# Check for cleartext HTTP
echo "3. Cleartext HTTP:"
if rg -i "http://" --type swift --type objc "$DIR" --glob '!*.plist' | grep -v "localhost\|127.0.0.1" | head -5; then
    echo "   Found cleartext HTTP"
else
    echo "   No cleartext HTTP found"
fi
echo ""

# Check for logging sensitive data
echo "4. Sensitive Data Logging:"
if rg -i "NSLog.*password|NSLog.*token|print.*password" --type swift --type objc "$DIR" | head -5; then
    echo "   Found sensitive data logging"
else
    echo "   No sensitive data logging found"
fi
echo ""

# Check for WebView without validation
echo "5. WebView Security:"
if rg -i "loadRequest|load.*URL" --type swift --type objc "$DIR" | head -5; then
    echo "   Found WebView URL loading (review for validation)"
else
    echo "   No WebView URL loading found"
fi
echo ""

echo "=== Scan Complete ==="
```

Save as `quick-scan-ios.sh`, make executable: `chmod +x quick-scan-ios.sh`, run: `./quick-scan-ios.sh ./src/`

---

## Reference Links

- **OWASP MASTG**: https://mas.owasp.org/MASTG/
- **Apple Security Documentation**: https://developer.apple.com/security/
