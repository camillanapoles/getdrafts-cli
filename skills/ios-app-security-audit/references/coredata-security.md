# CoreData Security

## CoreData Stack

```swift
// Core components
let managedObjectModel = NSManagedObjectModel(contentsOf: modelURL)!
let persistentStoreCoordinator = NSPersistentStoreCoordinator(managedObjectModel: managedObjectModel)
let managedObjectContext = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
```

### Underlying SQLite
```bash
# Locate SQLite
find . -name "*.sqlite"
# Default: ~/Library/Application Support/[AppID]/[DatabaseName].sqlite
```

## Data Protection on Store Files

### Setting Protection Level
```swift
let options: [AnyHashable: Any] = [
    NSMigratePersistentStoresAutomaticallyOption: true,
    NSInferMappingModelAutomaticallyOption: true,
    NSPersistentStoreFileProtectionKey: FileProtectionType.complete
]
```

### Protection Levels
- `FileProtectionType.complete` - Encrypted until unlocked
- `FileProtectionType.completeUnlessOpen` - Encrypted unless open
- `FileProtectionType.completeUntilFirstUserAuthentication` - Encrypted until first unlock
- `FileProtectionType.none` - No encryption (default!)

## Common Misconfigurations

### 1. No Encryption
```swift
// ❌ BAD - Default is no protection
let coordinator = NSPersistentStoreCoordinator(managedObjectModel: model)

// ✅ GOOD - Set protection
let options: [AnyHashable: Any] = [
    NSPersistentStoreFileProtectionKey: FileProtectionType.complete
]
```

### 2. Plaintext Sensitive Data
```sql
-- SQLite may contain plaintext
SELECT * FROM ZUSER;
-- May contain: email, password, token
```

## Testing

### 1. Locate Database
```bash
find . -name "*.sqlite" -o -name "*.sqlite-shm" -o -name "*.sqlite-wal"
```

### 2. Check Protection
```bash
ls -la@ database.sqlite
xattr -l database.sqlite
```

### 3. Inspect Content
```bash
sqlite3 database.sqlite
.tables
SELECT * FROM ZUSER;
```

### 4. Frida Hooks
```javascript
// Hook executeFetchRequest
var MOC = ObjC.classes.NSManagedObjectContext;
Interceptor.attach(MOC["- executeFetchRequest:error:"].implementation, {
    onEnter: function(args) {
        var request = new ObjC.Object(args[2]);
        console.log("FetchRequest:", request.description());
    }
});
```

## Remediation

### 1. Enable File Protection
```swift
let options: [AnyHashable: Any] = [
    NSPersistentStoreFileProtectionKey: FileProtectionType.complete
]
```

### 2. Encrypt Sensitive Fields
```swift
import CryptoKit

func encryptString(_ plaintext: String, key: SymmetricKey) throws -> Data {
    let data = plaintext.data(using: .utf8)!
    return try AES.GCM.seal(data, using: key).combined
}
```

### 3. Use SQLCipher
```swift
// SQLCipher provides transparent encryption
// Better than FileProtectionType
```

## OWASP MASTG References
- MASTG-APP-DATA-003: CoreData Security
- MASTG-APP-STORAGE-001: Database Security
- MASTG-APP-ANALYSIS-008: Database Testing



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

