# CloudKit Security - iOS Testing Guide

## Table of Contents

1. [Overview](#overview)
2. [Understanding CloudKit](#understanding-cloudkit)
3. [Container Security](#container-security)
4. [Testing Methodology](#testing-methodology)
5. [Common Vulnerabilities](#common-vulnerabilities)
6. [Secure Implementation](#secure-implementation)

---

## Overview

CloudKit is Apple's cloud data storage service. This guide covers CloudKit security testing, focusing on what data is synced, access controls, and configuration security.

### Why CloudKit Security Matters

- **Data Exposure**: Sensitive data synced to cloud
- **Access Controls**: Public vs private containers
- **Sync Configuration**: What gets uploaded automatically
- **Cross-Device**: Data visible on all user devices

---

## Understanding CloudKit

### Container Types

| Type | Description | Access |
|------|-------------|--------|
| Private | User-specific, device-specific | Only user's devices |
| Shared | Shared between users | Explicitly shared |
| Public | App-wide, readable by all | All users (read) |
| Database | Custom database zones | Configured access |

### CloudKit Stack

```
┌─────────────────────────────────────┐
│         Application                 │
│  (CKContainer, CKDatabase, CKRecord)│
├─────────────────────────────────────┤
│         CloudKit Framework           │
│  (Sync, Conflict Resolution)         │
├─────────────────────────────────────┤
│         iCloud Servers               │
│  (Apple Cloud Infrastructure)         │
└─────────────────────────────────────┘
```

---

## Container Security

### Private Container

```swift
let container = CKContainer(identifier: "iCloud.com.example.app")
let privateDB = container.privateCloudDatabase

// Only accessible by user on their devices
let record = CKRecord(recordType: "UserSettings")
record["apiKey"] = "secret_key" // Syncs to iCloud
privateDB.save(record) // Stored in user's private container
```

### Public Container

```swift
let publicDB = container.publicCloudDatabase

// Accessible by ALL app users
let record = CKRecord(recordType: "AppData")
record["announcement"] = "New feature"
publicDB.save(record) // Visible to all users
```

---

## Testing Methodology

### Static Analysis

```bash
# Find CloudKit usage
grep -r "CKContainer\|CKDatabase\|CKRecord" . --include="*.swift"

# Check container configuration
grep -r "iCloud\." . --include="*.swift" --include="*.plist"

# Find sync operations
grep -r "save\|fetch\|query" . --include="*.swift" | grep -i "cloudkit"
```

### Dynamic Analysis

#### Testing Steps

1. **Identify Container Configuration**
   - Check entitlements for iCloud container
   - Identify which databases are used
   - Note record types synced

2. **Test Data Exposure**
   - Monitor what gets synced
   - Check if sensitive data is in public container
   - Verify private container isolation

3. **Test Access Controls**
   - Try accessing another user's data
   - Test shared container boundaries
   - Verify query restrictions

4. **Network Analysis**
   - Capture CloudKit traffic (TLS)
   - Monitor record sync operations
   - Check for sensitive data in logs

---

## Common Vulnerabilities

### 1. Sensitive Data in Public Container

```swift
// Vulnerable: Storing sensitive data in public DB
let publicDB = container.publicCloudDatabase
let record = CKRecord(recordType: "UserData")
record["apiKey"] = userAPIKey // Exposed to all users!
publicDB.save(record)
```

**Fix**: Use private database for sensitive data

### 2. Missing Access Controls

```swift
// Vulnerable: No user validation
let query = CKQuery(recordType: "UserData", predicate: NSPredicate(value: true))
publicDB.performQuery(query) { results, error in
    // Returns ALL records without checking ownership
}
```

**Fix**: Add user ID to queries

### 3. Unvalidated Sync

```swift
// Vulnerable: Syncing without validation
func syncToCloud() {
    let record = CKRecord(recordType: "LocalData")
    record["userData"] = localData // No validation
    privateDB.save(record)
}
```

---

## Secure Implementation

### Best Practices

```swift
// 1. Use private container for sensitive data
let privateDB = container.privateCloudDatabase

// 2. Add ownership validation
let predicate = NSPredicate(format: "ownerID == %@", currentUserID)
let query = CKQuery(recordType: "UserData", predicate: predicate)

// 3. Validate before syncing
func syncSecurely(_ data: UserData) throws {
    guard validateData(data) else {
        throw SyncError.invalidData
    }
    let record = try CKRecord(from: data)
    privateDB.save(record)
}

// 4. Implement proper error handling
privateDB.save(record) { record, error in
    if let error = error {
        // Handle CloudKit errors properly
        handleError(error)
    }
}
```

---

## CVSS Scoring

| Vulnerability | Score | Vector |
|---------------|-------|--------|
| Public container data leak | 7.5 (High) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Access control bypass | 8.1 (High) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |

---

## Quick Reference

```bash
# Find CloudKit implementation
grep -r "CloudKit\|CKContainer\|CKDatabase" . --include="*.swift"

# Check entitlements
codesign -d --entitlements :- "<app_path>"

# Monitor traffic
frida -U -f "<bundle_id>" -l nwconnection-hook-ios.js
```

---

**Related**: See [icloud-private-relay-testing.md](icloud-private-relay-testing.md) for iCloud network privacy.
