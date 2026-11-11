# Objective-C Security Patterns

Objective-C's dynamic nature introduces unique security considerations including dynamic dispatch risks, swizzling abuse, KVO exploitation, method confusion, respondsToSelector bypass, and nil message sending vulnerabilities.

**MASTG References:**
- MASTG-TEST-0056: Testing Code Quality and Code Construction Issues
- MASTG-TEST-0057: Testing Code Quality (iOS)
- MASTG-TEST-0058: Testing Memory Corruption Bugs

## 1. Dynamic Dispatch Risks

### Vulnerability: Unvalidated Method Calls

```objective-c
// Vulnerable dynamic dispatch
@interface VulnerableClass : NSObject
@end

@implementation VulnerableClass

- (void)executeMethod:(NSString *)methodName {
    // VULNERABLE: Direct method call without validation
    SEL selector = NSSelectorFromString(methodName);

    if ([self respondsToSelector:selector]) {
        // Could execute sensitive methods
        [self performSelector:selector];
    }
}

// Sensitive methods
- (void)deleteAllData {
    // Dangerous operation
}

- (void)exposeAPIKey {
    // Exposes sensitive data
}

@end
```

### Exploitation

```objective-c
// Exploit code
VulnerableClass *obj = [[VulnerableClass alloc] init];
[obj executeMethod:@"deleteAllData"];
[obj executeMethod:@"exposeAPIKey"];
```

### Secure Implementation

```objective-c
// Secure implementation with whitelist
@interface SecureClass : NSObject
@property (nonatomic, strong) NSSet *allowedMethods;
@end

@implementation SecureClass

- (instancetype)init {
    self = [super init];
    if (self) {
        _allowedMethods = [NSSet setWithArray:@[
            @"safeMethod1",
            @"safeMethod2",
            @"safeMethod3"
        ]];
    }
    return self;
}

- (void)executeMethod:(NSString *)methodName {
    // Validate method name against whitelist
    if ([self.allowedMethods containsObject:methodName]) {
        SEL selector = NSSelectorFromString(methodName);

        if ([self respondsToSelector:selector]) {
            [self performSelector:selector];
        } else {
            NSLog(@"Method not found: %@", methodName);
        }
    } else {
        NSLog(@"Method not allowed: %@", methodName);
    }
}

@end
```

## 2. Swizzling Abuse

### Vulnerability: Unsafe Method Swizzling

```objective-c
// Vulnerable swizzling
@implementation MethodSwizzler

+ (void)swizzleClass:(Class)class
          originalSelector:(SEL)originalSelector
          swizzledSelector:(SEL)swizzledSelector {

    Method originalMethod = class_getInstanceMethod(class, originalSelector);
    Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);

    // VULNERABLE: No validation or error checking
    method_exchangeImplementations(originalMethod, swizzledMethod);
}

@end

// Usage
[MethodSwizzler swizzleClass:[NSString class]
                originalSelector:@selector(lowercaseString)
                swizzledSelector:@selector(maliciousLowercaseString)];
```

### Secure Swizzling

```objective-c
// Secure swizzling with validation
@implementation SecureMethodSwizzler

+ (BOOL)swizzleClass:(Class)class
          originalSelector:(SEL)originalSelector
          swizzledSelector:(SEL)swizzledSelector {

    // Validate inputs
    if (!class || !originalSelector || !swizzledSelector) {
        return NO;
    }

    // Get methods
    Method originalMethod = class_getInstanceMethod(class, originalSelector);
    Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);

    // Validate methods exist
    if (!originalMethod || !swizzledMethod) {
        return NO;
    }

    // Check if methods are different
    if (method_getImplementation(originalMethod) ==
        method_getImplementation(swizzledMethod)) {
        return NO;
    }

    // Add original method if it doesn't exist
    BOOL didAddMethod = class_addMethod(class,
                                        originalSelector,
                                        method_getImplementation(swizzledMethod),
                                        method_getTypeEncoding(swizzledMethod));

    if (didAddMethod) {
        class_replaceMethod(class,
                          swizzledSelector,
                          method_getImplementation(originalMethod),
                          method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }

    return YES;
}

@end
```

## 3. KVO Exploitation

### Vulnerability: Unvalidated KVO

```objective-c
// Vulnerable KVO usage
@interface VulnerableObject : NSObject
@property (nonatomic, strong) NSString *password;
@property (nonatomic, strong) NSString *apiKey;
@end

@implementation VulnerableObject
@end

// Attacker code
VulnerableObject *obj = [[VulnerableObject alloc] init];

// VULNERABLE: Can observe sensitive properties
[obj addObserver:attacker
      forKeyPath:@"password"
         options:NSKeyValueObservingOptionNew
         context:nil];

[obj addObserver:attacker
      forKeyPath:@"apiKey"
         options:NSKeyValueObservingOptionNew
         context:nil];

// Whenever password or apiKey changes, attacker receives notification
```

### Secure KVO

```objective-c
// Secure KVO implementation
@interface SecureObject : NSObject
@property (nonatomic, strong) NSString *password;
@property (nonatomic, strong) NSString *apiKey;
@end

@implementation SecureObject

// Override addObserver to protect sensitive properties
- (void)addObserver:(NSObject *)observer
         forKeyPath:(NSString *)keyPath
            options:(NSKeyValueObservingOptions)options
            context:(void *)context {

    // Define sensitive key paths
    NSSet *sensitiveKeyPaths = [NSSet setWithArray:@[
        @"password",
        @"apiKey",
        @"token",
        @"secret"
    ]];

    // Reject observation of sensitive properties
    if ([sensitiveKeyPaths containsObject:keyPath]) {
        NSLog(@"Cannot observe sensitive property: %@", keyPath);
        return;
    }

    // Allow observation of non-sensitive properties
    [super addObserver:observer forKeyPath:keyPath options:options context:context];
}

@end
```

## 4. Method Confusion

### Vulnerability: Method Confusion Attack

```objective-c
// Vulnerable to method confusion
@interface VulnerableAuth : NSObject
@end

@implementation VulnerableAuth

- (BOOL)authenticate:(NSString *)username
          password:(NSString *)password {
    // VULNERABLE: Assumes correct method signature
    if ([username length] > 0 && [password length] > 0) {
        return [self checkCredentials:username password:password];
    }
    return NO;
}

- (BOOL)checkCredentials:(NSString *)username
                password:(NSString *)password {
    // Authentication logic
    return YES;
}

- (BOOL)checkCredentials:(NSString *)username
                token:(NSString *)token {
    // Different method with similar name
    return YES;
}

@end

// Exploit
VulnerableAuth *auth = [[VulnerableAuth alloc] init];
// Method confusion - calls wrong method
[auth authenticate:@"user" password:@"pass"];
```

### Secure Implementation

```objective-c
// Secure implementation with type checking
@interface SecureAuth : NSObject
@end

@implementation SecureAuth

- (BOOL)authenticateWithUsername:(NSString *)username
                       password:(NSString *)password {
    // Clear method name prevents confusion
    if ([self isValidUsername:username] && [self isValidPassword:password]) {
        return [self performAuthenticationWithUsername:username
                                             password:password];
    }
    return NO;
}

- (BOOL)authenticateWithUsername:(NSString *)username
                          token:(NSString *)token {
    // Distinct method name
    if ([self isValidUsername:username] && [self isValidToken:token]) {
        return [self performAuthenticationWithUsername:username
                                               token:token];
    }
    return NO;
}

// Validation methods
- (BOOL)isValidUsername:(NSString *)username {
    return username.length > 0 && username.length <= 50;
}

- (BOOL)isValidPassword:(NSString *)password {
    return password.length >= 8 && password.length <= 100;
}

- (BOOL)isValidToken:(NSString *)token {
    return token.length > 0 && token.length <= 500;
}

@end
```

## 5. respondsToSelector Bypass

### Vulnerability: Bypass Validation

```objective-c
// Vulnerable validation
@interface Validator : NSObject
@end

@implementation Validator

- (BOOL)canExecuteMethod:(NSString *)methodName {
    SEL selector = NSSelectorFromString(methodName);

    // VULNERABLE: Only checks if method exists
    if ([self respondsToSelector:selector]) {
        return YES;
    }
    return NO;
}

- (void)executeMethod:(NSString *)methodName {
    if ([self canExecuteMethod:methodName]) {
        SEL selector = NSSelectorFromString(methodName);
        [self performSelector:selector];
    }
}

@end

// Exploit
Validator *validator = [[Validator alloc] init];
[validator executeMethod:@"dealloc"];  // Dangerous
[validator executeMethod:@"release"];  // Dangerous
```

### Secure Validation

```objective-c
// Secure validation with whitelist
@interface SecureValidator : NSObject
@property (nonatomic, strong) NSSet *allowedSelectors;
@end

@implementation SecureValidator

- (instancetype)init {
    self = [super init];
    if (self) {
        _allowedSelectors = [NSSet setWithObjects:
            NSStringFromSelector(@selector(safeMethod1)),
            NSStringFromSelector(@selector(safeMethod2)),
            nil];
    }
    return self;
}

- (BOOL)canExecuteMethod:(NSString *)methodName {
    SEL selector = NSSelectorFromString(methodName);

    // Check if method exists
    if (![self respondsToSelector:selector]) {
        return NO;
    }

    // Check if method is whitelisted
    NSString *selectorString = NSStringFromSelector(selector);
    return [self.allowedSelectors containsObject:selectorString];
}

- (void)executeMethod:(NSString *)methodName {
    if ([self canExecuteMethod:methodName]) {
        SEL selector = NSSelectorFromString(methodName);
        [self performSelector:selector];
    } else {
        NSLog(@"Method not allowed: %@", methodName);
    }
}

@end
```

## 6. Nil Message Sending

### Vulnerability: Nil Handling

```objective-c
// Vulnerable nil handling
@interface VulnerableManager : NSObject
@end

@implementation VulnerableManager

- (void)processData:(NSData *)data {
    // VULNERABLE: Assumes data is valid
    NSString *string = [[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding];

    // If data is nil, string is nil
    // Sending message to nil returns nil, not an error
    NSArray *components = [string componentsSeparatedByString:@","];

    // components is nil if string is nil
    // No error thrown, but logic is broken
    for (NSString *component in components) {
        NSLog(@"%@", component);
    }
}

@end
```

### Secure Implementation

```objective-c
// Secure nil handling
@interface SecureManager : NSObject
@end

@implementation SecureManager

- (void)processData:(NSData *)data {
    // Validate input
    if (!data || data.length == 0) {
        NSLog(@"Invalid data: nil or empty");
        return;
    }

    NSString *string = [[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding];

    // Validate conversion
    if (!string || string.length == 0) {
        NSLog(@"Failed to convert data to string");
        return;
    }

    NSArray *components = [string componentsSeparatedByString:@","];

    // Validate components
    if (!components || components.count == 0) {
        NSLog(@"No components found");
        return;
    }

    for (NSString *component in components) {
        // Validate each component
        if (component && component.length > 0) {
            NSLog(@"%@", component);
        }
    }
}

@end
```

## Testing Checklist

### Dynamic Dispatch
- [ ] Test unvalidated method calls
- [ ] Check for sensitive method exposure
- [ ] Verify input validation
- [ ] Test selector spoofing
- [ ] Check method existence validation

### Swizzling
- [ ] Test swizzling protection
- [ ] Verify method validation
- [ ] Check error handling
- [ ] Test swizzling detection
- [ ] Verify safe swizzling practices

### KVO
- [ ] Test property observation
- [ ] Check sensitive property protection
- [ ] Verify KVO restrictions
- [ ] Test observation bypass
- [ ] Check notification validation

### Method Confusion
- [ ] Test method signature validation
- [ ] Check for similar method names
- [ ] Verify type checking
- [ ] Test method resolution
- [ ] Check implementation verification

### Nil Handling
- [ ] Test nil message sending
- [ ] Verify nil checks
- [ ] Test input validation
- [ ] Check for silent failures
- [ ] Verify error reporting

## OWASP MASTG References

- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
- **MASTG-TEST-0057**: Testing Code Quality (iOS)
- **MASTG-TEST-0058**: Testing Memory Corruption Bugs

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **IDA Pro**: Binary analysis
- **Hopper**: Disassembler
- **Class-dump**: Class extraction

### Reference Materials
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Objective-C Runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
- [NSHipster](https://nshipster.com/)
