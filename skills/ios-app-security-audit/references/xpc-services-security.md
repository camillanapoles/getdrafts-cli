# XPC Services Security

## XPC Architecture

Inter-process communication mechanism providing secure, type-safe communication.

### Key Components
```swift
// Client connection
let connection = NSXPCConnection(serviceName: "com.example.xpcservice")
connection.remoteObjectInterface = NSXPCInterface(with: MyXPCProtocol.self)
connection.resume()

// Protocol
@objc protocol MyXPCProtocol {
    func processData(_ data: Data, reply: @escaping (Data) -> Void)
}
```

## Vulnerabilities

### 1. Missing Input Validation
```swift
// ❌ VULNERABLE - No validation
class MyXPCService: NSObject, MyXPCProtocol {
    func executeCommand(_ command: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = ["-c", command]
        try? task.run()
    }
}

// ✅ SECURE - Validate
class MyXPCService: NSObject, MyXPCProtocol {
    let allowedCommands = ["status", "version", "ping"]
    
    func executeCommand(_ command: String) {
        guard allowedCommands.contains(command) else { return }
        // Execute only allowed command
    }
}
```

### 2. Missing Authentication
```swift
// ❌ VULNERABLE - No auth check
class MyXPCService: NSObject, MyXPCProtocol {
    func performAdminTask() {
        // Anyone can call!
    }
}

// ✅ SECURE - Check caller
class MyXPCService: NSObject, MyXPCProtocol {
    func performAdminTask() {
        guard isAuthorized() else { return }
        // Perform task
    }
}
```

## Testing

### 1. Enumerate Services
```bash
find . -name "*.xpc" -type d
find . -name "*.plist" -path "*/XPCServices/*"
launchctl list | grep xpc
```

### 2. Frida Hooks
```javascript
// Hook NSXPCConnection
var XPCConnection = ObjC.classes.NSXPCConnection;
Interceptor.attach(XPCConnection["- remoteObjectInterface"].implementation, {
    onEnter: function(args) {
        var interface = new ObjC.Object(args[2]);
        console.log("Protocol:", interface.protocol().toString());
    }
});

// Hook methods
function traceXPCMethods(className) {
    var clazz = ObjC.classes[className];
    if (!clazz) return;
    
    var methods = clazz.$ownMethods;
    methods.forEach(function(method) {
        Interceptor.attach(clazz[method].implementation, {
            onEnter: function(args) {
                console.log(className + "." + method);
            }
        });
    });
}

traceXPCMethods("MyXPCService");
```

## Remediation

### 1. Validate All Inputs
```swift
@objc protocol MyXPCProtocol {
    func processData(_ data: Data, reply: @escaping (Data) -> Void)
}

class MyXPCService: NSObject, MyXPCProtocol {
    func processData(_ data: Data, reply: @escaping (Data) -> Void) {
        guard !data.isEmpty else { reply(Data()); return }
        guard data.count <= 1024 * 1024 else { reply(Data()); return }
        let result = processSecurely(data)
        reply(result)
    }
}
```

### 2. Implement Authentication
```swift
class AuthenticatedXPCService: NSObject, MyXPCProtocol {
    private var authorizedClients: [String] = []
    
    func receiveConnection(_ connection: NSXPCConnection) {
        if let callerID = connection.peerAuditToken {
            if validateCaller(callerID) {
                connection.remoteObjectInterface = NSXPCInterface(with: ClientProtocol.self)
                connection.resume()
            }
        }
    }
}
```

### 3. Use Type-Safe Protocols
```swift
@objc protocol SecureXPCProtocol {
    @objc func performTaskA(_ param: String)
    @objc func performTaskB(_ param: Int)
}
```

## OWASP MASTG References
- MASTG-APP-ARCH-011: XPC Architecture
- MASTG-APP-ANALYSIS-012: XPC Security Testing
- MASTG-APP-CODE-005: XPC Implementation Security



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

