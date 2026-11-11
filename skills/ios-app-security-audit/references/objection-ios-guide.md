# Objection Guide for iOS Security Testing

## Table of Contents

1. [Overview](#overview)
2. [Installation and Setup](#installation-and-setup)
3. [Basic Usage](#basic-usage)
4. [iOS-Specific Commands](#ios-specific-commands)
5. [Jailbreak Detection Bypass](#jailbreak-detection-bypass)
6. [SSL Pinning Bypass](#ssl-pinning-bypass)
7. [Keychain Operations](#keychain-operations)
8. [UserDefaults Access](#userdefaults-access)
9. [Biometrics Bypass](#biometrics-bypass)
10. [Pasteboard Monitoring](#pasteboard-monitoring)
11. [SQLite Database Access](#sqlite-database-access)
12. [Cookie and Credential Dumping](#cookie-and-credential-dumping)
13. [Binary and Bundle Analysis](#binary-and-bundle-analysis)
14. [Custom Script Loading](#custom-script-loading)
15. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

Objection is a runtime mobile exploration toolkit, powered by Frida, that provides a powerful command-line interface for iOS security testing. This guide covers Objection's iOS-specific commands, workflows, and techniques for comprehensive dynamic analysis.

### Why Objection?

- **Easy-to-use CLI**: No need to write Frida scripts from scratch
- **Pre-built commands**: Common tasks available out-of-the-box
- **Frida-powered**: Extensible with custom Frida scripts
- **Interactive REPL**: Real-time exploration and manipulation
- **Built-in bypasses**: Jailbreak detection, SSL pinning, biometrics

---

## Installation and Setup

### Installing Objection

```bash
# On host machine (macOS/Linux)

# Install via pip
pip3 install objection

# Verify installation
objection --version

# Update to latest version
pip3 install --upgrade objection
```

### Prerequisites

```bash
# Requirements:
# 1. Jailbroken iOS device
# 2. Frida server installed on device (see Frida Server guide)
# 3. Network connectivity (WiFi or USB)
# 4. USB tools for USB connections (optional but recommended)

# Install USB tools
brew install libusbmuxd usbmuxd libimobiledevice
```

### Device Connection

```bash
# Check device connection
frida-ps -U

# Start iproxy for USB connection (recommended)
iproxy 2222:22

# Or use direct WiFi connection
# Get device IP from Settings > WiFi

# Verify Objection can see device
objection list
```

---

## Basic Usage

### Starting an Objection Session

```bash
# Method 1: Spawn app (from bundle ID)
objection -g com.example.app explore

# Method 2: Attach to running process
objection -n "Example App" explore

# Method 3: Connect via IP
objection -N 192.168.1.100 -g com.example.app explore

# Method 4: Use specific Frida server port
objection -p 27042 -g com.example.app explore
```

### Objection REPL Commands

```bash
# Once in the REPL:

# Get help
help

# List available commands
help ios

# Exit session
exit or quit

# Clear screen
clear

# Run shell command
!ls

# Run multiple commands
command1 && command2
```

### Useful Utility Commands

```bash
# Get device info
env

# List loaded modules
modules list

# Search for modules containing string
modules search "<name>"

# List exported functions
exports list "<module_name>"

# Search for exported functions
exports search "<pattern>"

# List memory regions
memory list modules

# Search in memory
memory search "<pattern>" "<offset>" "<length>"

# Read memory at address
memory read "<address>" "<length>"

# Write to memory at address
memory write "<address>" "<hex_bytes>"

# Execute shell command on device
shell "<command>"

# Download file from device
file download "<remote_path>" "<local_path>"

# Upload file to device
file upload "<local_path>" "<remote_path>"
```

---

## iOS-Specific Commands

### iOS Command Overview

Objection provides many iOS-specific commands under the `ios` namespace:

```bash
# List all iOS commands
help ios

# Categories:
# - Jailbreak detection bypass
# - SSL pinning bypass
# - Keychain operations
# - UserDefaults access
# - Biometrics bypass
# - Pasteboard monitoring
# - Cookie and credential dumping
# - Binary and bundle analysis
# - WebView hooks
```

---

## Jailbreak Detection Bypass

### Basic Bypass

```bash
# Bypass jailbreak detection
ios jailbreak disable

# This command:
# 1. Hooks common jailbreak detection methods
# 2. Modifies return values to indicate device is not jailbroken
# 3. Bypasses Cydia app checks
# 4. Bypasses bash/sh checks
# 5. Bypasses filesystem checks

# Verify bypass
# App should continue running without jailbreak detection
```

### Advanced Bypass Options

```bash
# Bypass with verbose output
ios jailbreak disable --verbose

# Bypass specific detection methods
# Some apps have multiple detection mechanisms
# Run command multiple times if needed

# Check if bypass is active
# This will show currently active Frida hooks
frida-ps -U -a
```

### Common Detection Methods Bypassed

| Detection Type | Method | Bypass Approach |
|----------------|--------|-----------------|
| Cydia app | Checking for /Applications/Cydia.app | Return file not found |
| Bash | Checking for /bin/bash | Return file not found |
| SSH | Checking for /usr/sbin/sshd | Return file not found |
| Fork | Can't fork processes on jailbreak | Modify fork() result |
| Write tests | Attempting to write to protected paths | Allow writes temporarily |

---

## SSL Pinning Bypass

### Basic SSL Pinning Bypass

```bash
# Bypass SSL pinning
ios sslpinning disable

# This command:
# 1. Hooks SSL validation methods
# 2. Allows any certificate to be trusted
# 3. Bypasses NSURLSession SSL pinning
# 4. Bypasses AFNetworking pinning
# 5. Bypasses Alamofire pinning

# After bypass, use Burp Suite proxy to intercept traffic
# See SSL Pinning Bypass guide for details
```

### SSL Pinning Verification

```bash
# Test SSL pinning bypass
# 1. Set up Burp Suite proxy
# 2. Install Burp CA certificate on device
# 3. Run SSL pinning bypass
# 4. Make network request from app
# 5. Check Burp Proxy > Intercept

# If successful, you'll see intercepted HTTPS traffic
```

### Specific Framework Bypass

```bash
# NSURLSession bypass (automatic with sslpinning disable)
# Objection automatically hooks:
# - SecTrustEvaluate
# - SecTrustEvaluateWithError
# - NSURLSession delegate methods

# AFNetworking bypass
# Objection automatically hooks:
# - AFSecurityPolicy evaluateServerTrust

# Alamofire bypass
# Objection automatically hooks:
# - ServerTrustEvaluating evaluate

# For custom SSL pinning implementations, you may need custom Frida scripts
```

---

## Keychain Operations

### Dump Keychain

```bash
# Dump all keychain items
ios keychain dump

# Output format:
# Item Type: Generic Password
# Account: user@example.com
# Service: com.example.app
# Access Group: com.example.app
# Data: "<base64-encoded-data>"

# Dump to JSON file
ios keychain dump --json keychain_dump.json

# This is useful for:
# - Exporting keychain data for analysis
# - Importing into testing environments
# - Documenting findings in reports
```

### Search Keychain

```bash
# Search for specific items
ios keychain dump --filter com.example.app

# Search by type
ios keychain dump --generic_password  # Generic passwords only
ios keychain dump --internet_password  # Internet passwords only
ios keychain dump --certificate       # Certificates only
ios keychain dump --key               # Keys only
```

### Clear Keychain

```bash
# Clear entire keychain (BE CAREFUL!)
ios keychain clear

# Clear specific type
ios keychain clear --generic_password
ios keychain clear --internet_password
ios keychain clear --certificate
ios keychain clear --key

# Clear specific service
ios keychain clear --service com.example.app

# WARNING: This action is irreversible!
# Always backup keychain before clearing
```

### Keychain Item Details

```bash
# When dumping, you'll see detailed information:

# Generic Password Example:
# {
#   "account": "user@example.com",
#   "service": "com.example.app",
#   "access_group": "com.example.app",
#   "data": "base64_encoded_data_here",
#   "creation_date": "2024-04-03T12:00:00Z",
#   "modification_date": "2024-04-03T12:00:00Z"
# }

# Certificate Example:
# {
#   "subject": "CN=Example",
#   "issuer": "CN=Example CA",
#   "serial_number": "1234567890",
#   "data": "base64_encoded_certificate"
# }

# Key Example:
# {
#   "key_class": "private",
#   "key_type": "RSA",
#   "key_size": 2048,
#   "application_tag": "com.example.key"
# }
```

---

## UserDefaults Access

### Get UserDefaults

```bash
# Get all UserDefaults
ios userdefaults get

# Output:
# {
#   "isFirstLaunch": false,
#   "userId": "12345",
#   "preferences": {
#     "theme": "dark",
#     "language": "en"
#   }
# }

# Get specific key
ios userdefaults get userId

# Get from specific bundle
ios userdefaults get com.example.app
```

### Set UserDefaults

```bash
# Set a key-value pair
ios userdefaults set userId "99999"

# Set nested value
ios userdefaults set preferences.theme "light"

# Set boolean
ios userdefaults set isFirstLaunch true

# Set number
ios userdefaults set loginAttempts 0

# Set complex value (JSON)
ios userdefaults set complexData '{"key":"value","nested":{"item":123}}'
```

### UserDefaults for Different Bundles

```bash
# Get UserDefaults for specific bundle
ios userdefaults get com.example.app

# Set UserDefaults for specific bundle
ios userdefaults set --bundle com.example.app userId "99999"

# List all available bundles with UserDefaults
ios bundles list

# This helps identify which apps have accessible UserDefaults
```

### Common UserDefaults Attacks

```bash
# 1. Bypass first launch checks
ios userdefaults set isFirstLaunch true

# 2. Modify user ID to escalate privileges
ios userdefaults set userId "1"  # Admin user ID

# 3. Disable feature flags
ios userdefaults set showTutorial false

# 4. Change debug mode
ios userdefaults set debugMode true

# 5. Modify authentication tokens
ios userdefaults set authToken "stolen_token"

# 6. Clear tracking data
ios userdefaults set analyticsEnabled false
```

---

## Biometrics Bypass

### Bypass Touch ID / Face ID

```bash
# Bypass biometric authentication
ios biometrics bypass

# This command:
# 1. Hooks LAContext methods
# 2. Returns success for biometric evaluations
# 3. Allows bypassing Touch ID / Face ID
# 4. Works for LocalAuthentication framework

# Use case:
# - Testing biometric fallback flows
# - Accessing protected features
# - Testing error handling
```

### Biometrics Bypass Verification

```bash
# Test biometric bypass
# 1. Run bypass command
ios biometrics bypass

# 2. Trigger biometric prompt in app
# 3. App should proceed without actual biometric verification

# Common scenarios:
# - Unlocking protected content
# - Authorizing transactions
# - Accessing sensitive settings
```

### Limitations

```bash
# Limitations of biometrics bypass:
# 1. May not work with custom biometric implementations
# 2. Some apps have multiple layers of biometric checks
# 3. Server-side verification cannot be bypassed
# 4. Some implementations use Secure Enclave keys that require actual biometrics

# For advanced biometric bypass, you may need:
# - Custom Frida scripts
# - Analysis of specific biometric implementation
# - Testing of multiple bypass methods
```

---

## Pasteboard Monitoring

### Monitor Pasteboard

```bash
# Start pasteboard monitoring
ios pasteboard monitor

# This command:
# 1. Hooks UIPasteboard methods
# 2. Logs all copy operations
# 3. Logs all paste operations
# 4. Shows pasteboard contents

# Output example:
# [+] Pasteboard set to: "copied text"
# [+] Pasteboard get: "copied text"
```

### Get Current Pasteboard Contents

```bash
# Get current pasteboard string
ios pasteboard get

# Output:
# Current pasteboard content: "some text"
```

### Clear Pasteboard

```bash
# Clear pasteboard
ios pasteboard clear

# This is useful for:
# - Testing pasteboard security
# - Clearing sensitive data
# - Testing paste access flows
```

### Pasteboard Security Testing

```bash
# Test 1: Monitor pasteboard during app usage
ios pasteboard monitor

# Test 2: Check if app reads pasteboard on startup
# (Look for pasteboard read logs immediately after app launch)

# Test 3: Check if app writes to pasteboard
# (Copy text in app and monitor output)

# Test 4: Test pasteboard access in background
# (Copy text in one app, switch to test app)

# Security concerns:
# - Apps reading pasteboard without user permission
# - Apps writing sensitive data to pasteboard
# - Apps reading pasteboard periodically in background
```

---

## SQLite Database Access

### List SQLite Databases

```bash
# Find SQLite databases in app sandbox
shell find /var/mobile/Containers/Data/Application/ -name "*.db" -o -name "*.sqlite"

# Common locations:
# - /var/mobile/Containers/Data/Application/[UUID]/Documents/
# - /var/mobile/Containers/Data/Application/[UUID]/Library/
```

### Connect to SQLite Database

```sql
# Navigate to database directory
cd /var/mobile/Containers/Data/Application/[UUID]/Documents/

# Connect to database using sqlite3
sqlite3 database.db

# Now in SQLite shell:
.tables  # List all tables
.schema  # Show table schemas
select * from table_name;  # Query table
```

### Common SQLite Commands

```text
# List tables
.tables

# Show table structure
.schema table_name

# Query all data
select * from table_name;

# Query specific columns
select column1, column2 from table_name;

# Count rows
select count(*) from table_name;

# Search for data
select * from table_name where column like '%search_term%';

# Update data
update table_name set column='new_value' where id=1;

# Delete data
delete from table_name where id=1;

# Export to CSV
.output data.csv
.mode csv
select * from table_name;
.quit
```

### SQLite in Objection

```bash
# While in Objection session:

# Open SQLite database
sqlite connect /var/mobile/Containers/Data/Application/[UUID]/Documents/database.db

# Run queries
sqlite execute "select * from users;"

# List tables
sqlite tables

# Show schema
sqlite schema

# Export to file
sqlite execute "select * from users;" > users_export.txt
```

### Common SQLite Findings

```sql
# 1. User data
select * from users;
select * from profiles;

# 2. Authentication tokens
select * from tokens;
select * from sessions;

# 3. Cached data
select * from cache;
select * from preferences;

# 4. Sensitive data (passwords, keys, secrets)
select * from credentials;
select * from secrets;

# 5. Location data
select * from locations;
select * from geofences;

# 6. Analytics/tracking
select * from analytics;
select * from events;
```

---

## Cookie and Credential Dumping

### Dump HTTP Cookies

```bash
# Dump all HTTP cookies
ios cookies get

# Output format:
# Domain: example.com
# Name: session_id
# Value: abc123
# Path: /
# Secure: true
# HttpOnly: true
# Expiration: 2024-12-31

# Dump cookies for specific domain
ios cookies get --domain example.com

# Export cookies to Netscape format (for browser import)
ios cookies get --export cookies.txt
```

### Dump NSURLCredentialStorage

```bash
# Dump all credentials from NSURLCredentialStorage
ios nsurlcredentialstorage dump

# Output format:
# Protocol: https
# Host: api.example.com
# Port: 443
# Username: user@example.com
# Password: "<password>"
# Persistence: Permanent

# Dump credentials for specific host
ios nsurlcredentialstorage dump --host api.example.com

# Dump only HTTPS credentials
ios nsurlcredentialstorage dump --protocol https
```

### Credential Analysis

```bash
# When dumping credentials, analyze:
# 1. Username patterns (email, user ID, etc.)
# 2. Password strength and storage
# 3. Credential persistence settings
# 4. Which hosts store credentials
# 5. Authentication token format (JWT, session token, etc.)

# Security concerns:
# - Passwords stored in plain text
# - Weak credential storage
# - Credentials stored for insecure hosts
# - Long-lived authentication tokens
# - Credentials not encrypted
```

---

## Binary and Bundle Analysis

### List Binaries

```bash
# List all binaries in app bundle
ios binaries list

# Output:
# Application binary: /var/containers/Bundle/Application/[UUID]/Example.app/Example
# Frameworks:
#   - /System/Library/Frameworks/UIKit.framework/UIKit
#   - /System/Library/Frameworks/Foundation.framework/Foundation
#   - /var/containers/Bundle/Application/[UUID]/Example.app/Frameworks/MyFramework.framework/MyFramework

# List frameworks only
ios bundles list_frameworks

# List dynamic libraries
ios bundles list_libraries
```

### Analyze Binary

```bash
# While in Objection session:

# Get binary information
memory list modules

# Find specific module
memory find "MyCustomFramework"

# Examine exports
exports list MyCustomFramework

# Search for specific symbols
exports search "encrypt"

# Examine imports
imports list MyCustomFramework

# Search for imports
imports search "SecKey"
```

### Class Dumping

```bash
# Dump all Objective-C classes
ios heap dump_classes

# Output:
# ClassName1
# ClassName2
# ...

# Dump methods for specific class
ios heap dump_instances "<class_name>"

# Search for classes matching pattern
ios heap search "Manager"
ios heap search "Crypto"
ios heap search "Network"

# Find instances of class
ios heap find_instances "<class_name>"
```

### Memory Analysis

```bash
# List memory regions
memory list modules

# Read memory at address
memory read 0x12345678 100

# Write to memory
memory write 0x12345678 48656c6c6f  # "Hello"

# Search for pattern in memory
memory search "48656c6c6f" 0x100000000 0x10000000

# Search for string in memory
memory search "secret_key"

# Dump memory regions
memory dump "<address>" "<length>" "<output_file>"
```

---

## Custom Script Loading

### Loading Frida Scripts

```text
# Load custom Frida script
ios scripts load my_script.js

# This allows you to:
# 1. Run custom Frida scripts in Objection
# 2. Combine Objection's power with custom Frida code
# 3. Implement specialized bypasses
# 4. Create custom hooks not available in Objection

# Example custom script structure:
// my_script.js
if (ObjC.available) {
    var MyCustomClass = ObjC.classes.MyCustomClass;
    var myMethod = MyCustomClass["- myMethod"];

    Interceptor.attach(myMethod, {
        onEnter: function(args) {
            console.log("Custom hook: myMethod called");
        }
    });
}
```

### Script Management

```bash
# List loaded scripts
ios scripts list

# Reload script
ios scripts reload my_script.js

# Unload script
ios scripts unload my_script.js

# Create and load script inline
ios scripts create << 'EOF'
// Custom Frida code
console.log("Inline script loaded");
EOF
```

### Useful Custom Scripts

```javascript
// 1. Log all method calls in a class
// log_class_methods.js
var className = "MyClass";
var theClass = ObjC.classes[className];
theClass.$ownMethods.forEach(function(method) {
    Interceptor.attach(theClass[method], {
        onEnter: function(args) {
            console.log(className, method);
        }
    });
});

// 2. Hook specific network library
// network_hook.js
var AFNetworking = ObjC.classes.AFHTTPSessionManager;
Interceptor.attach(AFNetworking["- GET:parameters:progress:success:failure:"], {
    onEnter: function(args) {
        var url = ObjC.Object(args[2]);
        console.log("GET request:", url);
    }
});

// 3. Bypass specific protection
// custom_bypass.js
var ProtectionClass = ObjC.classes.ProtectionClass;
Interceptor.attach(ProtectionClass["- isProtected"], {
    onLeave: function(retval) {
        retval.replace(ptr(0));  // Always return false (not protected)
    }
});
```

---

## OWASP MASTG References

### Relevant MASTG Sections

| MASTG Section | Topic | Objection Application |
|---------------|-------|---------------------|
| MASTG-TEST-0010 | Dynamic Analysis Environment Setup | Objection setup |
| MASTG-TEST-0011 | Runtime Manipulation | Objection hooks |
| MASTG-APP-SEC-0010 | Runtime Manipulation Prevention | Bypassing protections |
| MASTG-TEST-0030 | Input Validation | UserDefaults modification |
| MASTG-TEST-0040 | Data Storage Security | Keychain analysis |
| MASTG-TEST-0050 | Cryptography | Crypto bypass and analysis |
| MASTG-TEST-0060 | Network Communication | SSL pinning bypass |

---

## Summary

This guide covered:
- Installation and setup of Objection
- Basic usage and REPL commands
- iOS-specific commands for security testing
- Jailbreak detection bypass
- SSL pinning bypass
- Keychain operations (dump, search, clear)
- UserDefaults access and modification
- Biometrics bypass
- Pasteboard monitoring
- SQLite database access
- Cookie and credential dumping
- Binary and bundle analysis
- Custom Frida script loading

Objection provides a powerful, user-friendly interface for dynamic iOS security testing. Combined with custom Frida scripts, it enables comprehensive runtime analysis and bypass of common security controls.

---

## References

### Official Documentation
- Objection GitHub: https://github.com/sensepost/objection
- Frida Documentation: https://frida.re/docs/
- OWASP MASTG: https://owasp.org/www-project-mobile-app-security-testing-guide/

### Additional Resources
- Objection Examples: https://github.com/sensepost/objection/tree/master/examples
- iOS Security Testing: https://github.com/iosre/iOSAppReverseEngineering
- Mobile Security Framework (MobSF): https://github.com/MobSF/Mobile-Security-Framework-MobSF

---

**Document Version:** 1.0
**Last Updated:** April 2024
**Target Audience:** Mobile security professionals, penetration testers, security researchers
**Prerequisites:** Jailbroken iOS device, Frida server installed, Python 3.7+
