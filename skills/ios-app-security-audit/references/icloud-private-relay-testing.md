# iCloud Private Relay Testing Guide for iOS Security Assessments

## Table of Contents

1. [Overview](#1-overview)
2. [Traffic Interception Challenges](#2-traffic-interception-challenges)
3. [Testing Approaches](#3-testing-approaches)
4. [Proxy Configuration](#4-proxy-configuration)
5. [Security Implications](#5-security-implications)
6. [Frida Interception Techniques](#6-frida-interception-techniques)
7. [OWASP MASTG References](#7-owasp-mastg-references)
8. [Practical Examples](#8-practical-examples)

---

## 1. Overview

### What is iCloud Private Relay?

iCloud Private Relay is an Apple privacy feature introduced in iOS 15 and macOS Monterey that enhances user privacy when browsing the web. When enabled, all Safari browser traffic and DNS queries pass through two separate internet relays, encrypting the user's IP address and browsing activity from trackers and network observers.

**Key Characteristics:**
- Available to iCloud+ subscribers (paid tier)
- Protects Safari traffic, DNS queries, and some app traffic using HTTP/3
- Does NOT protect all app traffic—only Safari and DNS by default
- Can be disabled per-network or globally
- Uses Oblivious DNS over HTTPS (ODoH) protocol

### Dual-Hop Architecture

iCloud Private Relay implements a two-proxy architecture designed to prevent any single entity from having complete visibility into both the user identity and the browsing destination:

```
┌─────────────┐     1st Hop (Apple)     ┌─────────────┐     2nd Hop (Third-Party)     ┌─────────────┐
│   iOS Device │ ──────────────────────▶│  Apple Proxy │ ─────────────────────────▶│  Partner Proxy │ ──▶ Destination
│  (Origin IP) │◀────────────────────── │ (Hides IP)   │◀─────────────────────────│  (Sees only   │
└─────────────┘                         └─────────────┘                              │  the domain)   │
                                                                                      └─────────────┘
```

**First Hop (Apple-Operated):**
- Receives the user's original IP address
- Encrypts the destination hostname
- Assigns an anonymous egress IP address
- Cannot see the final destination due to encryption

**Second Hop (Third-Party Partners like Cloudflare, Fastly):**
- Receives the encrypted destination
- Decrypts and establishes the actual connection
- Sees the domain but NOT the user's original IP
- Cannot identify the user due to the first hop's IP masking

**Security Implication:** Neither Apple nor the partner can simultaneously see both the user's identity and their browsing destination. This architecture fundamentally conflicts with traditional HTTPS interception approaches.

---

## 2. Traffic Interception Challenges

### Why Burp Suite and Fiddler Fail

Traditional proxy-based traffic interception relies on a man-in-the-middle (MITM) approach where the proxy presents its own certificate to decrypt HTTPS traffic. iCloud Private Relay breaks this model in several critical ways:

**Certificate Trust Failures:**

1. **Encrypted SNI (ESNI):** Private Relay encrypts the Server Name Indication (SNI) extension, which is normally visible during the TLS handshake. Without visible SNI, the proxy cannot determine the correct certificate to present.

2. **Encrypted DNS:** DNS queries are resolved via Oblivious DNS over HTTPS (ODoH), meaning the proxy never sees the actual domain being resolved—it only sees encrypted DNS requests to Apple's DNS servers.

3. **Certificate Pinning Bypass Required:** Even if you decrypt the traffic, many apps and Safari implement certificate pinning that rejects proxy certificates. Private Relay adds additional layers that further complicate pinning bypass.

**Protocol-Level Blocking:**

```
Traditional Flow:                    Private Relay Flow:
Device ──▶ Proxy (MITM) ──▶ Server   Device ──▶ Apple Relay ──▶ Partner Relay ──▶ Server
     │                                      │
     └── Proxy sees full URL               └── Only Apple sees origin IP
          and can intercept                     Partner sees only encrypted hostname
```

**Specific Failures:**

| Issue | Impact |
|-------|--------|
| ESNI Encryption | Proxy cannot determine target hostname |
| ODoH Protocol | DNS resolution hidden from proxy |
| QUIC/HTTP3 | Different protocol stack than traditional proxies |
| Double Encryption | Destination encrypted even from proxy |
| IP Masking | Source IP anonymized at two points |

**The Fundamental Problem:**

A MITM proxy needs to either:
1. Terminate the TLS connection (impossible due to certificate trust issues)
2. See the unencrypted hostname (impossible due to ESNI)
3. Intercept at DNS level (impossible due to ODoH)

### When Standard Proxies Work

Standard proxies CAN still intercept traffic in these scenarios:

- **Apps NOT using Safari:** Some apps make HTTP requests outside of Private Relay protection
- **Non-HTTP protocols:** FTP, raw sockets, etc.
- **Apps with custom networking:** Some apps bypass system proxy settings entirely
- **Explicit proxy configuration:** Some apps allow manual proxy settings
- **VPN-based interception:** Traffic routed through VPN before Private Relay processing

---

## 3. Testing Approaches

### Approach 1: Disabling iCloud Private Relay

**For Personal Testing Devices:**

1. Go to **Settings** → **[Your Name]** → **iCloud** → **Private Relay**
2. Toggle **Private Relay** to OFF
3. Confirm when prompted

**Limitations:**
- Only works on devices where you have the Apple ID password
- Some enterprise-managed devices may have this restricted
- Changes persist until manually re-enabled
- Not suitable for testing app behavior WITH relay enabled

**For Managed Enterprise Devices:**

If testing on an enterprise-managed device where Private Relay cannot be disabled:

1. **Check for Configuration Profile Restrictions:** MDM may have locked Private Relay settings
2. **Test Alternative Networks:** Private Relay can be disabled per-network; try a non-managed WiFi
3. **Use Cellular Data:** Private Relay protection varies on cellular connections

### Approach 2: Apple Configurator Profiles

Apple Configurator allows creating configuration profiles that can modify network settings, including proxy configurations.

**Workflow:**

1. Download **Apple Configurator 2** from the Mac App Store
2. Create a new configuration profile with:
   - Web Proxy (HTTP/HTTPS) settings pointing to your intercept proxy
   - Cellular settings modifications
   - Certificate trust settings
3. Export the profile as `.mobileconfig`
4. Transfer to iOS device via:
   - AirDrop
   - Email (open in Apple Configurator)
   - MDM enrollment (enterprise)

**Important Considerations:**

- Profile must be "trusted" by the user on the device
- Some organizations block profile installation
- Profiles can be removed via Settings → General → VPN & Device Management
- Certificate must be installed to Trusted Roots for HTTPS interception

**Profile Limitations:**

```
┌─────────────────────────────────────────────────────────────────┐
│  What Configurator CAN Do:                                      │
│  • Set system-wide proxy preferences                            │
│  • Install CA certificates                                      │
│  • Configure WiFi network settings                              │
│  • Disable certain privacy features                            │
│                                                                 │
│  What Configurator CANNOT Do:                                   │
│  • Bypass Private Relay's dual-hop encryption                   │
│  • Force apps to use the system proxy                           │
│  • Intercept ESNI-encrypted connections                         │
│  • Decrypt Private Relay-protected traffic                      │
└─────────────────────────────────────────────────────────────────┘
```

### Approach 3: VPN-Based Interception

A strategic approach is to route traffic through a VPN before it reaches Private Relay, creating an interception point at the VPN tunnel level.

**Architecture:**

```
App → VPN Tunnel → [YOUR VPN SERVER] → Internet
           ↓
    Inspect traffic here
    (before Private Relay encrypts)
```

**Implementation Steps:**

1. **Set up your interception proxy** (Burp, Charles, mitmproxy) on a reachable server
2. **Configure a VPN server** (WireGuard, OpenVPN, etc.) on that server
3. **Install the VPN profile** on the iOS device
4. **Route traffic through your VPN** before app processing
5. **Configure the VPN server** to forward traffic through your intercept proxy

**Caveats:**
- Some apps may detect and block VPN connections
- Performance impact from double-hop routing
- Apps may implement VPN detection and behave differently
- Split tunneling configuration is complex

### Approach 4: Network-Level Testing

For scenarios where interception isn't possible, conduct security testing through behavioral analysis:

1. **Network Traffic Analysis:** Monitor outgoing connections without decryption
2. **DNS Query Monitoring:** Use packet capture to observe DNS patterns
3. **Behavioral Testing:** Document app behavior with and without Private Relay
4. **Timing Attacks:** Analyze response patterns to infer information
5. **Metadata Analysis:** Examine unencrypted headers and timing data

---

## 4. Proxy Configuration

### Burp Suite Configuration

**Standard Proxy Setup:**

1. **Configure Burp Proxy Listener:**
   - Go to **Proxy** → **Options** → **Proxy Listeners**
   - Add listener on all interfaces (0.0.0.0) on port 8080
   - Enable **Support invisible proxy** for non-proxy-aware clients

2. **Install Burp's CA Certificate:**
   - Export certificate: **Proxy** → **Options** → **Import / Export CA Certificate**
   - Transfer to iOS device via AirDrop or email
   - Go to **Settings** → **General** → **About** → **Certificate Trust Settings**
   - Enable full trust for the Burp CA

3. **Configure iOS Proxy Settings:**
   - **Settings** → **WiFi** → Select network → **Configure Proxy**
   - Set to Manual
   - Enter your Burp proxy IP and port

**For Private Relay Traffic (Limited):**

When Private Relay IS enabled, Burp can only see:
- Unencrypted HTTP/3 initial handshake (without SNI)
- Traffic to Apple's relay endpoints (not final destinations)
- Encrypted content meant for Apple's relay

**What's Visible:**

```
Without Private Relay:              With Private Relay:
GET /api/data HTTP/1.1             CONNECT to <encrypted>
Host: api.target.com               <Encrypted payload>
                                    
→ Burp sees full request          → Burp sees only Apple relay IP
```

### Charles Proxy Configuration

**Setup Steps:**

1. **Enable Charles HTTP Proxy:**
   - **Proxy** → **Proxy Settings** → Enable HTTP proxy on port 8888
   - Enable **Enable transparent HTTP proxying**

2. **SSL Proxying Configuration:**
   - **Proxy** → **SSL Proxying Settings** → Enable SSL Proxying
   - Add locations: `*:*` for all hosts (or specific targets)

3. **Install Charles Root Certificate:**
   - **Help** → **Install Charles Root Certificate on Mobile Device**
   - Follow the displayed instructions
   - On iOS: Settings → General → About → Certificate Trust Settings

4. **iOS WiFi Configuration:**
   - Configure HTTP proxy to point to your Mac running Charles
   - Use your Mac's local IP address (not localhost)

**Charles Advantages over Burp:**

- Better handling of HTTP/3 and QUIC protocols
- Visual mapping of request flows
- Mobile app traffic analysis tools
- Bandwidth throttling for testing

### mitmproxy Configuration

**Quick Setup:**

```bash
# Install mitmproxy
brew install mitmproxy

# Run mitmproxy with SSL insecure mode (for testing only)
mitmproxy --listen-port 8080 --web-host 0.0.0.0

# Or use mitmdump for scripted interception
mitmdump --listen-port 8080 -s your_script.py
```

**Certificate Installation:**

```bash
# Generate the certificate (mitmproxy generates automatically)
# Certificate location: ~/.mitmproxy/mitmproxy-ca-cert.pem

# Convert to iOS-compatible format
openssl x509 -inform PEM -in ~/.mitmproxy/mitmproxy-ca-cert.pem \
  -outform DER -out ~/mitmproxy-ca-cert.cer

# Transfer to iOS device
scp ~/mitmproxy-ca-cert.cer user@ios-device:/path/
```

**iOS Configuration:**

1. Open the `.cer` file in Safari (download then open)
2. iOS prompts to install profile
3. Go to **Settings** → **General** → **VPN & Device Management**
4. Install the mitmproxy profile
5. Enable trust in **Settings** → **General** → **About** → **Certificate Trust Settings**

### General iOS Proxy Configuration

**Manual Proxy Setup per Network:**

1. **Settings** → **WiFi** → Tap **(i)** next to connected network
2. Scroll to **HTTP PROXY** section
3. Select **Manual**
4. Enter:
   - **Server:** Your proxy IP address
   - **Port:** Proxy port (8080, 8888, etc.)
5. For authenticated proxies:
   - Enable **Authentication**
   - Enter username and password

**PAC (Proxy Auto-Configuration):**

1. Host your PAC file on a web server
2. In proxy settings, select **Automatic**
3. Enter the PAC file URL: `http://yourserver/proxy.pac`

```javascript
// Example proxy.pac
function FindProxyForURL(url, host) {
  // Direct connection for local addresses
  if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
    return "DIRECT";
  }
  
  // Route HTTPS through proxy
  if (url.substring(0, 5) == "https") {
    return "PROXY proxy.example.com:8080";
  }
  
  // Default: direct connection
  return "DIRECT";
}
```

---

## 5. Security Implications

### Privacy vs. Security Trade-offs

**Privacy Benefits of Private Relay:**

| Benefit | Description |
|---------|-------------|
| IP Address Hiding | Websites cannot determine user's real IP |
| SNI Encryption | Observers cannot see which sites user visits |
| DNS Privacy | ISPs and network operators cannot monitor DNS queries |
| Reduced Tracking | Combining IP + browsing is prevented |

**Security Assessment Considerations:**

```
┌─────────────────────────────────────────────────────────────────┐
│ PRIVACY PERSPECTIVE                    SECURITY PERSPECTIVE     │
│ ───────────────────                    ───────────────────      │
│ Private Relay is beneficial            Private Relay complicates │
│ for users who want to                   security assessments     │
│ hide from trackers                      and incident response    │
│                                                                 │
│ • Stops mass surveillance              • Hinders threat hunting │
│ • Prevents ISP logging                  • Blocks packet analysis│
│ • Limits targeted advertising           • Complicates forensics   │
│ • Protects journalists/activists        • Masks malicious C2     │
└─────────────────────────────────────────────────────────────────┘
```

### Enterprise Security Considerations

**Arguments FOR Private Relay in Enterprises:**

1. **Reduced Attack Surface:** Attackers cannot easily determine employee's browsing habits
2. **Protection Against Network Attacks:** On-path attackers cannot intercept encrypted traffic
3. **Insider Threat Reduction:** IT cannot monitor browsing (arguably a feature OR a bug)
4. **Compliance Benefits:** Some regulations protect browsing privacy

**Arguments AGAINST Private Relay in Enterprises:**

1. **Security Blind Spots:** Security tools cannot inspect HTTPS traffic
2. **Incident Response Challenges:** Forensics become extremely difficult
3. **DLP Limitations:** Data Loss Prevention tools cannot scan content
4. **Malware Detection:** Some security products cannot inspect encrypted traffic
5. **Regulatory Compliance:** Some industries require traffic visibility

**Enterprise Recommendations:**

| Scenario | Recommendation |
|----------|----------------|
| General enterprise | Allow Private Relay; enhance endpoint security |
| Financial services | Consider restricting; implement CASB solutions |
| Healthcare | Consult compliance requirements; may need logging |
| Government/critical infrastructure | Restrict; maintain full traffic visibility |
| Security research | Allow; use dedicated testing environments |

### Testing Implications

**When Assessing Apps with Private Relay Enabled:**

1. **Accept Limitations:** Full traffic interception is not possible
2. **Focus on What's Visible:** Use behavioral analysis and metadata
3. **Test Without Relay:** When possible, conduct full testing with relay disabled
4. **Document Testing Scope:** Note which tests were limited by relay
5. **Alternative Techniques:** Use Frida, static analysis, and runtime inspection

---

## 6. Frida Interception Techniques

### Hooking Before Private Relay Processing

Frida can intercept network calls at the application level before they reach iOS's network stack and Private Relay.

**Technique 1: Hook NSURLSession**

```javascript
// NSURLSession hook to intercept HTTP traffic
var NSURLSession = ObjC.classes.NSURLSession;

Interceptor.attach(NSURLSession['+ sharedSession'].implementation, {
    onEnter: function(args) {
        console.log('[NSURLSession sharedSession called');
    }
});

// Hook dataTaskWithURL
var dataTaskWithURL = NSURLSession['- dataTaskWithURL:'];
Interceptor.attach(dataTaskWithURL.implementation, {
    onEnter: function(args) {
        var url = args[2].toString();
        console.log('[URLSession] Request URL: ' + url);
        // Store for response hook
        this.url = url;
    }
});
```

**Technique 2: Hook CFNetwork DNS Functions**

```javascript
// Hook DNS resolution to see what domains are being resolved
var sysInfoMod = Process.findModuleByName('libsystem_info.dylib');
var dnsResolver = sysInfoMod ? sysInfoMod.findExportByName('dns_lookup') : null;

Interceptor.attach(dnsResolver, {
    onEnter: function(args) {
        console.log('[DNS] Lookup: ' + args[0].readUtf8String());
    }
});
```

**Technique 3: Hook Socket Level**

```javascript
// Intercept at socket level before encryption
var kernelMod = Process.findModuleByName('libsystem_kernel.dylib');
var socketConnect = kernelMod ? kernelMod.findExportByName('connect') : null;

Interceptor.attach(socketConnect, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var sockaddr = args[1];
        // sockaddr structure contains IP:port
        console.log('[Socket] connect() fd=' + fd);
    }
});
```

### Certificate Bypass Techniques

**Bypass Single Certificate Pinning:**

```javascript
// Hook SecTrustEvaluate to bypass pinning
var securityMod = Process.findModuleByName('Security.framework');
var SecTrustEvaluate = securityMod ? securityMod.findExportByName('SecTrustEvaluate') : null;

Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) {
        console.log('[Security] SecTrustEvaluate returned: ' + retval);
        // Force trust (for testing only)
        retval.replace(0);  // errSecSuccess
    }
});
```

**Comprehensive Pinning Bypass:**

```javascript
// Universal certificate pinning bypass
var securityMod = Process.findModuleByName('Security.framework');
var implementations = [
    'SecTrustEvaluate',
    'SecTrustCopyCertificates',
    'SecTrustGetCertificateCount',
    'SecTrustGetValidationResult'
];

implementations.forEach(function(symbol) {
    var impl = securityMod ? securityMod.findExportByName(symbol) : null;
    if (impl) {
        Interceptor.attach(impl, {
            onLeave: function(retval) {
                console.log('[Pinning Bypass] ' + symbol + ' hooked');
            }
        });
    }
});
```

**NSURLConnection Pinning Bypass:**

```javascript
// Hook NSURLConnection delegate methods
var setDelegate = NSURLConnection['- setDelegate:'].implementation;

Interceptor.attach(setDelegate, {
    onEnter: function(args) {
        console.log('[NSURLConnection] Delegate set');
    }
});

// Hook didReceiveData to capture response bodies
var didReceiveData = NSURLConnection['- connection:didReceiveData:'].implementation;

Interceptor.attach(didReceiveData, {
    onEnter: function(args) {
        var data = args[2];
        console.log('[Response] Data received: ' + data.length() + ' bytes');
    }
});
```

### Network Bypass for Testing

**Disable Private Relay System-Wide (requires jailbreak):**

```javascript
// If running on jailbroken device
var privateRelayPath = '/System/Library/PrivateFrameworks/PrivateRelay.framework';

if (Module.available(privateRelayPath)) {
    console.log('[PrivateRelay] Framework found - bypass not implemented');
}
```

**Bypass via MobileSubstrate:**

Create a tweak that hooks the Private Relay framework to return early:

```objective-c
// PrivateRelayBypass.xm
#import <substrate.h>

// Hook the function that encrypts SNI
MSHookFunction(/* original function */, /* replacement */, /* store original */);
```

---

## 7. OWASP MASTG References

### Relevant Testing Techniques

The OWASP Mobile Application Security Testing Guide (MASTG) covers iCloud Private Relay testing under several sections:

**MASTG-APP-0013: Testing Network Communication Security**

> "Test applications that handle sensitive data over untrusted networks. On iOS, verify whether traffic is protected by iCloud Private Relay and understand the implications for security testing."

**Key Points:**
- Private Relay encrypts traffic but may complicate security testing
- Assess whether the application functions correctly with relay enabled
- Document any security controls that depend on network inspection

**MASTG-APP-0014: Testing Secure Network Configuration**

| Test Case | Private Relay Behavior |
|-----------|----------------------|
| HTTP traffic inspection | Only sees Apple relay endpoints |
| HTTPS traffic inspection | ESNI hides target hostname |
| DNS query monitoring | ODoH encrypts DNS requests |
| Certificate pinning | May still function at app level |

**MASTG-APP-0015: Testing Endpoint Identification**

When testing with Private Relay enabled:
- Source IP appears as Apple's egress IP, not device IP
- Cannot determine user's geographic location from IP
- May need to test from known IP ranges for certain functionality

### Testing Workflow (MASTG-Aligned)

```
1. PRE-TESTING PHASE
   ├── Document Private Relay status
   ├── Record egress IP addresses observed
   └── Note any app behaviors that differ

2. STANDARD TESTING (Relay Disabled)
   ├── Full HTTPS interception via proxy
   ├── Complete traffic analysis
   ├── Request/response manipulation
   └── Full vulnerability testing

3. ALTERNATIVE TESTING (Relay Enabled)
   ├── Proxy sees only relay endpoints
   ├── Behavioral analysis only
   ├── Frida-based interception at app level
   └── Metadata and timing analysis

4. REPORTING
   ├── Document testing methodology used
   ├── Note scope limitations from relay
   ├── Provide recommendations for enterprise
   └── Include both privacy and security perspectives
```

### References

- **OWASP MASVS:** Mobile Application Security Verification Standard
- **OWASP MASTG:** Mobile Application Security Testing Guide
- **Apple Platform Security:** iCloud Private Relay architecture
- **IETF RFC 9230:** Oblivious DNS over HTTPS (ODoH)

---

## 8. Practical Examples

### Example 1: Full Security Assessment Workflow

**Scenario:** Testing a banking iOS app that may have Private Relay enabled

**Step-by-Step:**

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: BASELINE WITH PRIVATE RELAY DISABLED                    │
└─────────────────────────────────────────────────────────────────┘
1. Disable Private Relay: Settings → iCloud → Private Relay → OFF
2. Configure Burp Suite proxy
3. Install Burp CA certificate as trusted
4. Configure iOS WiFi to use Burp proxy
5. Capture and analyze ALL HTTP/HTTPS traffic
6. Document:
   - API endpoints accessed
   - Data transmitted (PII, tokens, account info)
   - SSL/TLS configuration
   - Certificate pinning status
   - Any vulnerabilities found

┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: TESTING WITH PRIVATE RELAY ENABLED                      │
└─────────────────────────────────────────────────────────────────┘
1. Enable Private Relay: Settings → iCloud → Private Relay → ON
2. Keep proxy configuration in place
3. Observe what traffic IS visible:
   - Connections to Apple relay endpoints
   - DNS queries to Apple DNS (encrypted)
   - Any traffic bypassing Private Relay
4. Use Frida to intercept at app level:
   - Hook NSURLSession
   - Capture API calls before encryption
   - Monitor what data the app tries to send
5. Compare behaviors between enabled/disabled states

┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: ENTERPRISE-SPECIFIC TESTING                             │
└─────────────────────────────────────────────────────────────────┘
1. If MDM-managed device:
   - Check for Configuration Profile restrictions
   - Determine if Private Relay can be controlled
2. Test from enterprise network:
   - Check if Private Relay can be disabled
   - Test with corporate proxy (may conflict)
3. Document findings:
   - Security implications of relay
   - Testing scope limitations
   - Recommendations for enterprise policy
```

### Example 2: Frida Script for API Interception

```javascript
// save as: private_relay_interceptor.js
// Run with: frida -U -f com.example.app -l private_relay_interceptor.js

console.log('[*] Private Relay API Interceptor loaded');

// Hook NSURLSession for HTTP traffic
var NSURLSession = ObjC.classes.NSURLSession;
var NSURLConnection = ObjC.classes.NSURLConnection;

Interceptor.attach(NSURLSession['+ sharedSession'].implementation, {
    onEnter: function(args) {
        console.log('[+] NSURLSession sharedSession');
    }
});

// Hook all NSURLSession data tasks
var dataTaskSelector = ObjC.classes.NSURLSessionDataTask['- resume'].implementation;

Interceptor.attach(dataTaskSelector, {
    onEnter: function(args) {
        // Get the task's request
        var task = ObjC.Object(args[0]);
        try {
            var request = task.valueForKey_('originalRequest');
            if (request) {
                console.log('[+] Request URL: ' + request.URL().toString());
                console.log('[+] HTTP Method: ' + request.HTTPMethod().toString());
                
                var headers = request.allHTTPHeaderFields();
                for (var key in headers) {
                    console.log('    ' + key + ': ' + headers[key]);
                }
            }
        } catch (e) {
            console.log('[-] Error reading request: ' + e);
        }
    }
});

// Hook connection:didReceiveData
var didReceiveData = NSURLConnection['- connection:didReceiveData:'].implementation;

Interceptor.attach(didReceiveData, {
    onEnter: function(args) {
        var connection = ObjC.Object(args[0]);
        var data = ObjC.Object(args[2]);
        console.log('[+] Received ' + data.length() + ' bytes');
    }
});

// Hook SecTrustEvaluate for certificate analysis
var securityMod = Process.findModuleByName('Security.framework');
var SecTrustEvaluate = securityMod ? securityMod.findExportByName('SecTrustEvaluate') : null;

Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) {
        console.log('[+] SecTrustEvaluate called');
    }
});

console.log('[*] Interception hooks installed - monitoring traffic');
```

**Run the script:**

```bash
# List attached devices
frida-ps -U

# Attach to target app
frida -U -f com.example.app -l network-interceptor-ios.js

# Or attach by app name
frida -U "com.example.app" -l network-interceptor-ios.js
```

### Example 3: Burp Suite Configuration for iOS Testing

```
┌─────────────────────────────────────────────────────────────────┐
│ COMPLETE BURP CONFIGURATION WORKFLOW                            │
└─────────────────────────────────────────────────────────────────┘

PART A: BURP SUITE SETUP
─────────────────────────
1. Proxy → Options → Proxy Listeners
   - Add: 0.0.0.0:8080
   - ✓ Request handling: Support invisible proxy
   - ✓ Enable SSL Proxying

2. Proxy → Options → Certificate Interception
   - ✓ Generate CA-signed per-host certificates
   - ✓ Use private key if available

3. Project Options → Connections →Hostname Resolution
   - Add your lab server if testing locally

PART B: IOS DEVICE SETUP
────────────────────────
1. Export Burp Certificate:
   - Proxy → Options → Import/Export CA Certificate
   - Export in DER format (.cer)

2. Transfer to iOS:
   - AirDrop the certificate file
   - Or email to yourself and open attachment

3. Install Certificate:
   - iOS prompts "Profile Downloaded"
   - Go to Settings → General → VPN & Device Management
   - Tap Install next to PortSwigger CA

4. Trust Certificate:
   - Settings → General → About → Certificate Trust Settings
   - Enable full trust for PortSwigger Root CA

5. Configure Proxy:
   - Settings → WiFi → (i) icon
   - Configure Proxy → Manual
   - Server: <your Mac's IP>
   - Port: 8080

PART C: VERIFICATION
────────────────────
1. In Safari, visit http://burp/cert
2. Download and install the cacert.der
3. Visit https://example.com
4. Verify traffic appears in Burp Proxy → HTTP History

PART D: TROUBLESHOOTING
───────────────────────
Problem: No traffic appearing
Solution: 
  - Verify proxy IP/port correct
  - Check certificate is trusted
  - Try Safari (some apps ignore system proxy)

Problem: SSL errors
Solution:
  - Ensure certificate is fully trusted
  - Check certificate pinning in app
  - Use Frida to bypass pinning
```

### Example 4: Testing Without Interception Capability

When full interception isn't possible with Private Relay enabled:

```
┌─────────────────────────────────────────────────────────────────┐
│ WORKAROUND TESTING TECHNIQUES                                   │
└─────────────────────────────────────────────────────────────────┘

1. STATIC ANALYSIS (No Network Required)
   ─────────────────────────────────────
   • Disassemble/decompile the app
   • Analyze code for:
     - Hardcoded API endpoints
     - Authentication mechanisms
     - Data serialization formats
     - Security controls implemented

2. FRIDA DYNAMIC ANALYSIS (App-Level Hooking)
   ───────────────────────────────────────────
   • Hook JavaScriptCore/UIWebView
   • Intercept at app's networking layer
   • Bypass certificate pinning if present
   • Monitor internal API calls

3. LOGGING AND DEBUGGING
   ─────────────────────
   • Hook NSLog/print statements
   • Monitor app console output
   • Capture crash logs
   • Analyze system calls

4. BEHAVIORAL ANALYSIS
   ────────────────────
   • Document all visible network behaviors
   • Note response timing patterns
   • Observe error messages
   • Test with different inputs

5. DOCUMENTED LIMITATIONS
   ──────────────────────
   When reporting, clearly state:
   - Private Relay prevented full traffic analysis
   - Testing was limited to [list what was possible]
   - Recommend disabling relay for complete assessment
   - Note any privacy vs. security trade-offs observed
```

---

## Summary

iCloud Private Relay represents a significant architectural challenge for iOS security testing. Its dual-hop encryption model fundamentally prevents traditional proxy-based traffic interception, requiring security assessors to adopt alternative methodologies.

**Key Takeaways:**

| Aspect | Implication |
|--------|-------------|
| **Architecture** | Two-proxy model prevents any single party seeing both identity and destination |
| **Interception** | Standard proxies (Burp, Fiddler, Charles) cannot see Private Relay traffic |
| **Testing** | Requires Frida hooking, behavioral analysis, or VPN-based approaches |
| **Enterprise** | Organizations must balance user privacy against security monitoring needs |
| **Frida** | Most viable approach for intercepting app-level traffic with relay enabled |

**Recommended Testing Approach:**

1. **Always test WITH and WITHOUT Private Relay** for comprehensive coverage
2. **Use Frida** for app-level interception when relay is enabled
3. **Consider VPN-based interception** for full protocol visibility
4. **Document limitations** clearly in security assessment reports
5. **Provide enterprise guidance** on privacy vs. security trade-offs

---

## References

- Apple: [iCloud Private Relay Overview](https://support.apple.com/en-us/HT212614)
- Apple Platform Security: iCloud Private Relay Architecture
- OWASP MASTG v1.5: iOS Testing Guide
- IETF RFC 9230: Oblivious DNS over HTTPS (ODoH)
- NIST SP 800-53: Privacy Controls for Enterprise Networks

---

*Document Version: 1.0*  
*Last Updated: April 2026*  
*Target Audience: iOS Security Assessors, Penetration Testers, Security Architects*
