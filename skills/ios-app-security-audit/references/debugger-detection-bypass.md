# Debugger Detection Bypass

iOS apps often implement debugger detection to prevent reverse engineering. This guide covers iOS debugger detection methods including sysctl P_TRACED check, ptrace PT_DENY_ATTACH, getppid(), isatty(), and bypass techniques with Frida Interceptor.

**MASTG References:**
- MASTG-TEST-0013: Detection of Rooted or Jailbroken Devices
- MASTG-TEST-0084: Testing the Binary (iOS)
- MASTG-TEST-0085: Anti-Debugging Checks

## 1. sysctl P_TRACED Check

### Vulnerability: Simple Debugger Check

```c
// Vulnerable debugger detection
#include <sys/sysctl.h>

int is_debugger_attached() {
    // VULNERABLE: Simple sysctl check
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);

    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return 0;
    }

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
```

### Bypass with Frida

```javascript
// Bypass sysctl P_TRACED check
if (ObjC.available) {
    try {
        const sysctl = Module.findGlobalExportByName('sysctl');

        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    const name = args[0];
                    const namelen = args[1];

                    // Check if querying KERN_PROC
                    if (namelen.toInt32() == 4) {
                        const type = name.add(4).readInt();
                        if (type == 4) { // KERN_PROC
                            this.isProcCheck = true;
                            console.log("[+] sysctl KERN_PROC call detected");
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.isProcCheck) {
                        const oldp = this.context.r6; // x6 register contains oldp
                        const oldlenp = this.context.r7; // x7 register contains oldlenp

                        if (!oldp.isNull()) {
                            // Read kinfo_proc structure
                            const info = oldp.readByteArray(oldlenp.readU64());

                            // Clear P_TRACED flag
                            const p_flag_offset = 0x28; // Offset in kinfo_proc
                            const p_flag = oldp.add(p_flag_offset).readU32();

                            // Clear P_TRACED bit (0x800)
                            oldp.add(p_flag_offset).writeU32(p_flag & ~0x800);

                            console.log("[!] P_TRACED flag cleared");
                        }
                    }
                }
            });

            console.log("[+] sysctl bypass installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```c
// Secure debugger detection with multiple checks
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdio.h>

typedef struct {
    int sysctl_check;
    int ptrace_check;
    int ppid_check;
    int tty_check;
    int combined_check;
} DebuggerInfo;

DebuggerInfo get_debugger_info() {
    DebuggerInfo info = {0};

    // 1. sysctl check
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc proc_info;
    size_t size = sizeof(proc_info);

    if (sysctl(name, 4, &proc_info, &size, NULL, 0) == 0) {
        info.sysctl_check = (proc_info.kp_proc.p_flag & P_TRACED) != 0;
    }

    // 2. ptrace check
    info.ptrace_check = (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && errno != EPERM);

    // 3. ppid check
    pid_t ppid = getppid();
    info.ppid_check = (ppid != 1 && ppid != getpid());

    // 4. tty check
    info.tty_check = isatty(STDIN_FILENO) || isatty(STDOUT_FILENO);

    // Combined check
    info.combined_check = info.sysctl_check ||
                         info.ptrace_check ||
                         info.ppid_check ||
                         info.tty_check;

    return info;
}

int is_debugger_secure() {
    DebuggerInfo info = get_debugger_info();

    // Require multiple checks to fail
    int failed_checks = info.sysctl_check +
                       info.ptrace_check +
                       info.ppid_check +
                       info.tty_check;

    // Only flag as debugging if multiple checks fail
    return failed_checks >= 2;
}
```

## 2. ptrace PT_DENY_ATTACH

### Vulnerability: PT_DENY_ATTACH

```c
// Vulnerable PT_DENY_ATTACH usage
#include <sys/ptrace.h>

void anti_debug() {
    // VULNERABLE: Can be bypassed by hooking ptrace
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
}
```

### Bypass with Frida

```javascript
// Bypass PT_DENY_ATTACH
if (ObjC.available) {
    try {
        const ptrace = Module.findGlobalExportByName('ptrace');

        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    const request = args[0].toInt32();

                    console.log("[+] ptrace called: " + request);

                    // Check for PT_DENY_ATTACH (31)
                    if (request == 31) {
                        console.log("    [!] PT_DENY_ATTACH detected - bypassing");

                        // Return success without actually denying attach
                        this.bypass = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.bypass) {
                        // Return 0 (success)
                        retval.replace(0);
                    }
                }
            });

            console.log("[+] ptrace PT_DENY_ATTACH bypass installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```c
// Secure PT_DENY_ATTACH with validation
#include <sys/ptrace.h>
#include <signal.h>

static void signal_handler(int sig) {
    // If SIGTRAP is received, debugger might be attached
    _exit(1);
}

void secure_anti_debug() {
    // Install signal handler
    signal(SIGTRAP, signal_handler);

    // Attempt to deny attach
    int result = ptrace(PT_DENY_ATTACH, 0, 0, 0);

    if (result == -1 && errno == EPERM) {
        // Already being traced
        _exit(1);
    }

    // Additional checks
    if (is_debugger_attached()) {
        _exit(1);
    }

    // Periodic check
    pthread_t check_thread;
    pthread_create(&check_thread, NULL, periodic_debug_check, NULL);
    pthread_detach(check_thread);
}

void *periodic_debug_check(void *arg) {
    while (1) {
        if (is_debugger_attached()) {
            _exit(1);
        }
        sleep(1);
    }
    return NULL;
}
```

## 3. getppid() Check

### Vulnerability: Parent Process Check

```c
// Vulnerable getppid check
#include <unistd.h>

int is_parent_debugger() {
    // VULNERABLE: Can be bypassed by manipulating process tree
    pid_t ppid = getppid();

    // If parent is not launchd (PID 1), might be debugger
    return (ppid != 1);
}
```

### Bypass with Frida

```javascript
// Bypass getppid check
if (ObjC.available) {
    try {
        const getppid = Module.findGlobalExportByName('getppid');

        if (getppid) {
            Interceptor.attach(getppid, {
                onLeave: function(retval) {
                    const ppid = retval.toInt32();

                    console.log("[+] getppid called: " + ppid);

                    // Force return PID 1 (launchd)
                    if (ppid != 1) {
                        console.log("    [!] Bypassing - returning PID 1");
                        retval.replace(1);
                    }
                }
            });

            console.log("[+] getppid bypass installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```c
// Secure parent process check
#include <unistd.h>
#include <sys/sysctl.h>

int get_parent_process_info(pid_t ppid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    char comm[256];
    if (fgets(comm, sizeof(comm), fp)) {
        // Remove newline
        comm[strcspn(comm, "\n")] = 0;

        fclose(fp);

        // Check for known debuggers
        if (strstr(comm, "debugserver") ||
            strstr(comm, "lldb") ||
            strstr(comm, "Xcode")) {
            return 1; // Debugger detected
        }
    }

    fclose(fp);
    return 0;
}

int is_parent_secure() {
    pid_t ppid = getppid();

    // Allow launchd (PID 1)
    if (ppid == 1) {
        return 1;
    }

    // Check parent process name
    return get_parent_process_info(ppid) == 0;
}
```

## 4. isatty() Check

### Vulnerability: Terminal Check

```c
// Vulnerable isatty check
#include <unistd.h>

int is_running_in_terminal() {
    // VULNERABLE: Can be bypassed by redirecting stdin/stdout
    return isatty(STDIN_FILENO) || isatty(STDOUT_FILENO);
}
```

### Bypass with Frida

```javascript
// Bypass isatty check
if (ObjC.available) {
    try {
        const isatty = Module.findGlobalExportByName('isatty');

        if (isatty) {
            Interceptor.attach(isatty, {
                onLeave: function(retval) {
                    console.log("[+] isatty called");
                    console.log("    Original result: " + retval);

                    // Force return 0 (not a terminal)
                    if (!retval.isNull()) {
                        retval.replace(0);
                        console.log("    [!] Bypassed - returning 0");
                    }
                }
            });

            console.log("[+] isatty bypass installed");
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Secure Implementation

```c
// Secure terminal check
#include <unistd.h>
#include <sys/ioctl.h>

int is_terminal_secure() {
    // Check if file descriptors are terminals
    if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
        // Additional checks

        // Check terminal type
        char *term = getenv("TERM");
        if (term && (
            strcmp(term, "dumb") == 0 ||
            strcmp(term, "unknown") == 0)) {
            return 0; // Suspicious terminal
        }

        // Check terminal size
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
            // Zero size might indicate debugger
            if (ws.ws_row == 0 || ws.ws_col == 0) {
                return 0;
            }
        }

        return 0; // Running in terminal - suspicious
    }

    return 1; // Not a terminal - normal
}
```

## 5. Comprehensive Debugger Detection

### Combined Detection

```c
// Comprehensive debugger detection
#include <sys/sysctl.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

typedef struct {
    int detected;
    int method;
    char message[256];
} DebuggerDetection;

DebuggerDetection check_for_debugger() {
    DebuggerDetection result = {0, 0, ""};

    // Method 1: sysctl
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);

    if (sysctl(name, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            result.detected = 1;
            result.method = 1;
            snprintf(result.message, sizeof(result.message),
                    "Debugger detected via sysctl");
            return result;
        }
    }

    // Method 2: ptrace
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 && errno == EPERM) {
        result.detected = 1;
        result.method = 2;
        snprintf(result.message, sizeof(result.message),
                "Debugger detected via ptrace");
        return result;
    }

    // Method 3: ppid
    pid_t ppid = getppid();
    if (ppid != 1) {
        result.detected = 1;
        result.method = 3;
        snprintf(result.message, sizeof(result.message),
                "Debugger detected via ppid (parent: %d)", ppid);
        return result;
    }

    // Method 4: isatty
    if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
        result.detected = 1;
        result.method = 4;
        snprintf(result.message, sizeof(result.message),
                "Debugger detected via terminal check");
        return result;
    }

    return result;
}

void *continuous_debug_check(void *arg) {
    while (1) {
        DebuggerDetection result = check_for_debugger();

        if (result.detected) {
            // Log detection
            syslog(LOG_ALERT, "%s", result.message);

            // Exit or take action
            _exit(1);
        }

        sleep(1);
    }
    return NULL;
}

void setup_debug_protection() {
    // Install signal handler
    signal(SIGTRAP, signal_handler);

    // Start continuous check
    pthread_t check_thread;
    pthread_create(&check_thread, NULL, continuous_debug_check, NULL);
    pthread_detach(check_thread);
}

void signal_handler(int sig) {
    syslog(LOG_ALERT, "Signal %d received - debugger might be attached", sig);
    _exit(1);
}
```

## Modern Jailbreak Detection (Extended)

### File-Based Detection Patterns

#### Suspicious System Paths (Swift)

```swift
private static var suspiciousAppAndSystemPaths: [String] {
    return [
        // Frida-related
        "/usr/sbin/frida-server",
        "/usr/bin/frida-server",
        "/usr/lib/frida",
        "/usr/lib/frida-server",
        
        // Cydia and package managers
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        
        // Jailbreak frameworks
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        
        // Debian/Cydia package files
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/etc/apt/undecimus/undecimus.list",
        "/var/lib/dpkg/info/mobilesubstrate.md5sums",
        
        // Electra/Unc0ver specific
        "/.bootstrapped_electra",
        "/.installed_unc0ver",
        "/jb/lzma",
        "/jb/offsets.plist",
        "/jb/jailbreakd.plist",
        "/jb/amfid_payload.dylib",
        "/jb/libjailbreak.dylib",
        
        // System modification paths
        "/private/var/lib/apt",
        "/private/var/Users/",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/var/log/apt",
        "/var/cache/apt/",
        "/var/lib/cydia",
        "/var/lib/apt",
        "/var/lib/dpkg/info",
        
        // SSH and remote access
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd",
        "/etc/ssh/sshd_config",
        "/usr/bin/ssh",
        
        // Substrate and injection
        "/usr/lib/libjailbreak.dylib",
        "/usr/share/jailbreak/injectme.plist",
        
        // Alternative package managers
        "/Applications/checkra1n.app",
        "/Applications/Procursus.app"
    ]
}
```

#### File Existence Check Methods

```swift
// Using NSFileManager (detectable by hooking)
func checkFileExistence() -> Bool {
    let paths = suspiciousAppAndSystemPaths
    for path in paths {
        if FileManager.default.fileExists(atPath: path) {
            return true
        }
    }
    return false
}

// Using C functions (harder to detect)
func checkFilesUsingStat() -> Bool {
    let paths = suspiciousAppAndSystemPaths
    for path in paths {
        var statInfo = stat()
        if stat(path, &statInfo) == 0 {
            return true
        }
    }
    return false
}
```

### Advanced Detection Techniques

#### DYLD Environment Variable Check

```swift
// Check for DYLD_INSERT_LIBRARIES environment variable
func checkDYLDEnvironment() -> Bool {
    if let dyldInsert = getenv("DYLD_INSERT_LIBRARIES") {
        return true
    }
    return false
}

// Frida detection via environment
func checkForFridaEnvironment() -> Bool {
    let fridaEnvVars = [
        "FRIDA_AGENT_PATH",
        "FRIDA_CODE_SIGNATURE_PATH",
        "FRIDA_VERSION"
    ]
    
    for varName in fridaEnvVars {
        if getenv(varName) != nil {
            return true
        }
    }
    return false
}
```

#### OpenSSH Detection

```swift
// Check for OpenSSH running on loopback
func checkOpenSSH() -> Bool {
    let addresses = ["127.0.0.1:22", "127.0.0.1:44"]
    
    for address in addresses {
        if let colonIndex = address.firstIndex(of: ":") {
            let host = String(address[..<colonIndex])
            let portString = String(address[address.index(after: colonIndex)...])
            if let port = UInt16(portString) {
                // Attempt connection - if successful, SSH is running
                var hints = addrinfo()
                hints.ai_family = AF_INET
                hints.ai_socktype = SOCK_STREAM
                
                var result: UnsafeMutablePointer<addrinfo>?
                if getaddrinfo(host, String(port), &hints, &result) == 0 {
                    if let info = result {
                        let sock = socket(info.pointee.ai_family, 
                                        info.pointee.ai_socktype,
                                        info.pointee.ai_protocol)
                        if sock != -1 {
                            let connectResult = connect(sock, info.pointee.ai_addr, 
                                                       info.pointee.ai_addrlen)
                            close(sock)
                            if connectResult == 0 {
                                return true
                            }
                        }
                        freeaddrinfo(result)
                    }
                }
            }
        }
    }
    return false
}
```

#### Parent Process ID Check

```swift
// Check if parent process is launchd (PID 1)
func isParentLaunchd() -> Bool {
    return getppid() == 1
}

// More robust check
func checkParentProcess() -> Bool {
    let ppid = getppid()
    
    // launchd should always be PID 1
    if ppid == 1 {
        return false // Not jailbroken
    }
    
    // Get parent process name
    var pathBuffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
    let result = proc_pidpath(ppid, &pathBuffer, UInt32(PROC_PIDPATHINFO_MAXSIZE))
    
    if result > 0 {
        let path = String(cString: pathBuffer)
        let suspiciousParents = ["/debugserver", "/lldb", "/xpc"]
        for susp in suspiciousParents {
            if path.contains(susp) {
                return true // Likely being debugged
            }
        }
    }
    
    return false
}
```

### Frida Detection Bypass (Extended)

#### Process Name Hiding

```javascript
// Hide Frida processes from process enumeration
var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
var sysctlPtr = kernelMod ? kernelMod.findExportByName("sysctl") : null;

Interceptor.attach(sysctlPtr, {
    onEnter: function(args) {
        this.mib = args[0];
        this.size = args[1];
    },
    onLeave: function(retval) {
        // KERN_PROC_ALL = 1
        // Filter out Frida-related processes from results
    }
});

// Hook kill() to prevent detection via kill -0
var killPtr = kernelMod ? kernelMod.findExportByName("kill") : null;
Interceptor.attach(killPtr, {
    onEnter: function(args) {
        this.pid = args[0].toInt32();
        this.sig = args[1].toInt32();
    },
    onLeave: function(retval) {
        // If signal is 0 (process existence check), hide Frida
        if (this.sig === 0) {
            // Check if target is Frida server process
        }
    }
});
```

#### Frida Port Detection Bypass

```javascript
// Block connections to Frida default ports
var kernelMod = Process.findModuleByName("libsystem_kernel.dylib");
var connectPtr = kernelMod ? kernelMod.findExportByName("connect") : null;

Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        var addr = args[1];
        var sin_family = addr.add(0).readU16();
        
        if (sin_family === 2) { // AF_INET
            var port = addr.add(2).readU16BE();
            var fridaPorts = [27042, 27043, 27044, 27045];
            
            if (fridaPorts.indexOf(port) !== -1) {
                // Return error for Frida ports
                retval.replace(-1);
                return;
            }
        }
    }
});
```

#### Frida Version String Hiding

```javascript
// Hide Frida version strings from memory scanning
var libcMod = Process.findModuleByName("libsystem_c.dylib");
var strstrPtr = libcMod ? libcMod.findExportByName("strstr") : null;

Interceptor.attach(strstrPtr, {
    onEnter: function(args) {
        this.haystack = args[0];
        this.needle = args[1];
    },
    onLeave: function(retval) {
        if (!retval.isNull()) {
            try {
                var result = this.haystack.readCString();
                if (result && result.includes("frida")) {
                    retval.replace(ptr(0)); // Return NULL
                }
            } catch(e) {}
        }
    }
});
```

## Testing Checklist

### Detection Methods
- [ ] Test sysctl P_TRACED detection
- [ ] Check ptrace PT_DENY_ATTACH
- [ ] Verify getppid detection
- [ ] Test isatty detection
- [ ] Check combined detection
- [ ] Test file-based detection patterns
- [ ] Verify DYLD environment variable checks
- [ ] Test OpenSSH port detection
- [ ] Check parent process validation
- [ ] Test Frida-specific detection (ports, process names, strings)

### Bypass Techniques
- [ ] Test Frida hooking
- [ ] Verify bypass effectiveness
- [ ] Check for detection evasion
- [ ] Test multiple bypass methods
- [ ] Verify performance impact
- [ ] Test process name hiding
- [ ] Verify port detection blocking
- [ ] Test string hiding mechanisms
- [ ] Validate version fingerprint evasion

### Security
- [ ] Verify secure implementations
- [ ] Test bypass resistance
- [ ] Check for false positives
- [ ] Verify multi-layer protection
- [ ] Test continuous monitoring

## OWASP MASTG References

- **MASTG-TEST-0013**: Detection of Rooted or Jailbroken Devices
- **MASTG-TEST-0084**: Testing the Binary (iOS)
- **MASTG-TEST-0085**: Anti-Debugging Checks

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **LLDB**: Apple debugger
- **GDB**: GNU debugger
- **debugserver**: Remote debugging server

### Reference Materials
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Frida Documentation](https://frida.re/docs/)
- [LLDB Documentation](https://lldb.llvm.org/)
