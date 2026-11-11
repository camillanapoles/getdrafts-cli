# CVSS 4.0 Scoring Guide for iOS App Vulnerabilities

## Table of Contents

1. [CVSS 4.0 Overview for iOS](#1-cvss-40-overview-for-ios)
2. [Base Metrics](#2-base-metrics)
3. [Threat Metrics](#3-threat-metrics)
4. [Environmental Metrics](#4-environmental-metrics)
5. [Supplemental Metrics](#5-supplemental-metrics)
6. [Vector String Format](#6-vector-string-format)
7. [Severity Ratings](#7-severity-ratings)
8. [iOS-Specific CVSS Scoring Examples](#8-ios-specific-cvss-scoring-examples)
9. [Quick Scoring Cheat Sheet](#9-quick-scoring-cheat-sheet)
10. [Severity-to-Priority Mapping](#10-severity-to-priority-mapping)

---

## 1. CVSS 4.0 Overview for iOS

CVSS (Common Vulnerability Scoring System) version 4.0 is an open framework for communicating the characteristics and severity of software vulnerabilities. CVSS v4.0 introduces significant changes from v3.1:

- **Scope removed**: Replaced with Vulnerable System (VC, VI, VA) and Subsequent System (SC, SI, SA) concepts
- **Attack Requirements (AT) added**: New mandatory base metric separating deployment conditions from exploit engineering complexity
- **User Interaction expanded**: Three values (None, Passive, Active) instead of two (None, Required)
- **Temporal renamed to Threat**: Metric group now focuses on exploit maturity and subsequent system impacts
- **Supplemental Metrics added**: Optional metrics for Safety, Automatable, Recovery, Value Density, Response Effort, and Provider Urgency

### CVSS Nomenclature

Always specify which metric groups are used when communicating scores:

| Score Type | Metrics Used |
|-------------|--------------|
| CVSS-B | Base metrics only |
| CVSS-BT | Base + Threat metrics |
| CVSS-BE | Base + Environmental metrics |
| CVSS-BTE | Base + Threat + Environmental metrics |

### iOS-Specific Considerations

When scoring iOS vulnerabilities, keep in mind:

- **Sandboxing**: All iOS apps run inside the iOS sandbox. "Local" attack vector usually means a co-installed malicious app or a jailbreak context.
- **Code signing**: All binaries must be signed. Bypassing `get-task-allow` and the signature is the prerequisite for binary patching.
- **Encrypted App Store binaries**: App Store IPAs are encrypted with FairPlay. Decryption (via jailbreak + frida-ios-dump, Clutch, etc.) is the prerequisite step for static analysis.
- **Keychain accessibility flags** (`kSecAttrAccessible*`) determine real-world exploitability of credential exposure.
- **App Transport Security (ATS)** exceptions are the most common network attack surface in iOS apps.
- **Jailbreak context**: Many findings (jailbreak detection bypass, SSL pinning bypass via Frida, RASP bypass) are only exploitable on a jailbroken device — this maps to `AT:P` (Attack Requirements: Present).

---

## 2. Base Metrics

Base metrics represent intrinsic qualities of a vulnerability that are constant over time and across user environments. All 8 base metrics are MANDATORY in the vector string.

### Attack Vector (AV)

How the vulnerable component is exploited.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Network (N) | Exploitable remotely without requiring network adjacency | Malicious deep link, universal link, push notification payload, server-side API vulnerability |
| Adjacent (A) | Exploitable from same network (broadcast, shared LAN) | WiFi MITM, Bluetooth attack, same ad-hoc network |
| Local (L) | Requires local execution or device access | Malicious app co-installed, jailbreak-required exploit, shared device |
| Physical (P) | Requires physical device access | USB connection, device theft, forensic acquisition on seized device |

### Attack Complexity (AC)

The conditions beyond the attacker's control that must exist to exploit.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Low (L) | No special conditions, straightforward exploit | Direct URL scheme injection, predictable parameter structure, hardcoded API key |
| High (H) | Requires specific conditions or timing | Race condition during app launch, specific iOS version required, memory corruption requiring heap grooming |

### Attack Requirements (AT) — NEW IN 4.0

Prerequisite deployment and execution conditions of the vulnerable system that enable the attack. This is MANDATORY in all v4.0 vectors.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| None (N) | No special deployment conditions needed | Default app configuration, standard App Transport Security |
| Present (P) | Requires specific deployment conditions | Jailbroken device, specific iOS version, debug build, MDM-enrolled device, custom app distribution |

### Privileges Required (PR)

The level of privileges the attacker must possess before successfully exploiting.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| None (N) | No authentication or permissions needed | Unauthenticated API endpoint, exported URL scheme with no validation |
| Low (L) | Basic user-level access | Standard iOS permissions (location-when-in-use, photo library, contacts) |
| High (H) | Requires elevated privileges | Jailbreak, MDM profile, full keychain access group, entitlement-gated API |

### User Interaction (UI)

The degree of user interaction required for exploitation.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| None (N) | Zero-click exploit | Background fetch, notification service extension, push payload, XPC daemon |
| Passive (P) | Limited involuntary interaction | Opening app, receiving notification, WebView rendering |
| Active (A) | Conscious user action required | Tapping deep link, granting permission via prompt, Face ID approval |

### Vulnerable System Impact Metrics

Impact on the vulnerable app/system itself (NOT the Subsequent System).

#### Vulnerable System Confidentiality (VC)

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| High (H) | Total loss of confidentiality | Keychain items dumped with sensitive data, full UserDefaults exfiltration, complete session hijack |
| Low (L) | Limited information disclosure | Single non-sensitive preference exposed, partial pasteboard read |
| None (N) | No confidentiality impact | Integrity or availability only |

#### Vulnerable System Integrity (VI)

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| High (H) | Total loss of integrity | Arbitrary file overwrite in app container, binary patching succeeds, full DB modification |
| Low (L) | Limited modification | Single preference tampered, partial file modification |
| None (N) | No integrity impact | Confidentiality or availability only |

#### Vulnerable System Availability (VA)

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| High (H) | Total loss of availability | App crash loop preventing all functions, persistent DoS via corrupted state |
| Low (L) | Limited disruption | Single feature unavailable, temporary performance degradation |
| None (N) | No availability impact | Confidentiality or integrity only |

---

## 3. Threat Metrics

Threat metrics reflect characteristics that change over time based on exploit intelligence. These metrics can reduce the Base score (not increase it).

### Exploit Maturity (E)

Current state of exploit intelligence.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Unreported (U) | No public exploit or PoC | Recently discovered, not weaponized |
| PoC (P) | Proof-of-concept exists but not active | Frida script in public repo, academic PoC |
| Active (A) | Active exploitation in the wild | Jailbreak chains in-the-wild, Frida-based malware in App Store review bypasses |

---

## 4. Environmental Metrics

Environmental metrics represent characteristics unique to a user's environment. These modify the Base score based on organizational context.

### Security Requirements

Impact of confidentiality, integrity, or availability loss on the organization.

| Metric | High | Medium | Low |
|--------|------|--------|-----|
| Confidentiality Requirement (CR) | Critical data, credentials, PII, health data | Sensitive business data | Public data |
| Integrity Requirement (IR) | Financial transactions, PII, business decisions | Non-critical business data | General data |
| Availability Requirement (AR) | < 24h recovery required | 1-5 days recovery required | > 5 days or redundant |

### Modified Base Metrics

If the environment differs from baseline assumptions, modify these metrics:

- MAV (Modified Attack Vector): E.g., Network but protected by MDM-allowed-only endpoints → Adjacent (A)
- MAC (Modified Attack Complexity): E.g., Additional mitigations increase complexity
- MAT (Modified Attack Requirements): E.g., Specific environment adds requirements
- MPR (Modified Privileges Required): E.g., App requires additional permissions in deployment
- MUI (Modified User Interaction): E.g., User awareness training changes interaction needed

### Modified Impact Metrics

If the vulnerable system's impact is amplified or reduced in your environment:

- MVC (Modified Vulnerable System Confidentiality)
- MVI (Modified Vulnerable System Integrity)
- MVA (Modified Vulnerable System Availability)

---

## 5. Supplemental Metrics

Supplemental metrics provide additional context but do NOT modify the CVSS score. All are optional. Use a single "S:" prefix.

### Safety (S)

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Negligible (N) | No safety impact | Banking app, social media app |
| Present (P) | Safety impact possible | Medical device companion app, automotive companion, ICS control |

### Automatable (AU)

Can the full exploit chain be automated at scale?

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| No (N) | Requires human intervention per target | Social engineering, complex multi-step, manual Frida hook |
| Yes (Y) | Fully automatable | Unauthenticated RCE via deep link, automated jailbreak + Frida injection |

### Recovery (RE)

Resilience after successful exploitation.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Automated (A) | Auto-recovery | App auto-restarts, keychain auto-rotates |
| User (U) | Requires manual recovery | Reinstall app, clear UserDefaults, re-authenticate |
| Irreversible (I) | Cannot recover | Persistent data corruption, permanent account takeover |

### Value Density (V)

Concentration of value in the vulnerable system.

| Value | Description | iOS Examples |
|--------|-------------|--------------|
| Diffuse (D) | Distributed value | Consumer banking apps, personal accounts |
| Concentrated (C) | Centralized value | Corporate MDM controller, enterprise key servers, banking session storage |

### Vulnerability Response Effort (U)

Effort required to remediate.

| Value | Description |
|--------|-------------|
| Low (L) | Simple Info.plist or entitlement change |
| Moderate (M) | Requires testing, some code changes |
| High (H) | Major architectural changes, significant testing required, app re-architecture |

### Provider Urgency

Vendor-assessed urgency (optional pass-through metric).

| Value | Description |
|--------|-------------|
| Clear (C) | Urgency is clear |
| Green (G) | Low urgency |
| Amber (A) | Medium urgency |
| Red (R) | High urgency |

---

## 6. Vector String Format

### Correct CVSS 4.0 Format

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:U
```

#### Format Breakdown

1. **Prefix**: `CVSS:4.0/`
2. **Base Metrics (mandatory)**: `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L`
3. **Subsequent System Impact** (optional, use if applicable): `SC:N/SI:N/SA:N`
4. **Threat Metrics** (optional): `E:U` (Exploit Maturity only - no CI, II, IA in CVSS 4.0)
5. **Environmental Metrics** (optional): `CR:H/IR:H/AR:H/MAV:A/...`
6. **Supplemental Metrics** (optional, single "S:" prefix): `S:Safety:N/AU:Y/...`

### Vector String Ordering

Metrics MUST appear in this order (as defined in specification):

**Base:**
1. AV (Attack Vector)
2. AC (Attack Complexity)
3. AT (Attack Requirements)
4. PR (Privileges Required)
5. UI (User Interaction)
6. VC (Vulnerable System Confidentiality)
7. VI (Vulnerable System Integrity)
8. VA (Vulnerable System Availability)

**Subsequent System Impacts:**
9. SC (Subsequent System Confidentiality)
10. SI (Subsequent System Integrity)
11. SA (Subsequent System Availability)

**Threat Metrics:**
12. E (Exploit Maturity)

**Environmental Metrics:**
13. CR (Confidentiality Requirement)
14. IR (Integrity Requirement)
15. AR (Availability Requirement)
16. MAV (Modified Attack Vector)
17. MAC (Modified Attack Complexity)
18. MAT (Modified Attack Requirements)
19. MPR (Modified Privileges Required)
20. MUI (Modified User Interaction)
21. MVC (Modified Vulnerable System Confidentiality)
22. MVI (Modified Vulnerable System Integrity)
23. MVA (Modified Vulnerable System Availability)

**Supplemental Metrics:**
24. S: (Single prefix for all supplemental metrics)

---

## 7. Severity Ratings

| Qualitative Rating | Score Range |
|--------------------|-------------|
| None | 0.0 |
| Low | 0.1 - 3.9 |
| Medium | 4.0 - 6.9 |
| High | 7.0 - 8.9 |
| Critical | 9.0 - 10.0 |

---

## 8. iOS-Specific CVSS Scoring Examples

### Example 1: URL Scheme Hijacking Leading to Token Theft

An app registers `myapp://` and processes a password-reset deep link that includes a token in the query string. The malicious app registers the same scheme and intercepts the token.

**Vulnerability:**
- Attack can be triggered by any app on the device sending the deep link
- No user authentication required to receive the link
- Token can be used immediately for account takeover

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:L — Requires a co-installed malicious app
- AC:L — Direct deep link delivery to the scheme
- AT:N — No jailbreak or special configuration required
- PR:N — No app permissions needed to send a URL
- UI:A — User must tap the malicious link (Active interaction) or the malicious app must be foregrounded
- VC:H — Full session token exposed
- VI:H — Attacker can use the token to modify account state
- VA:N — Service not disrupted
- SC:N/SI:N/SA:N — No impact on other systems
- E:U — No public exploit (default/base score)

**Score:** CVSS-B: 7.0 (HIGH)

---

### Example 2: ATS Bypass via NSAllowsArbitraryLoads

The app has `NSAppTransportSecurity → NSAllowsArbitraryLoads = true`, allowing HTTP traffic to any host.

**Vulnerability:**
- Network MITM can intercept all traffic from the app
- All API requests, including authenticated ones, are exposed in cleartext
- Affects all network endpoints, not just specific exception domains

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:A — Requires same network (WiFi MITM, rogue AP)
- AC:L — No special conditions beyond network position
- AT:N — Default app deployment
- PR:N — No authentication to perform MITM
- UI:P — User must be actively using the app
- VC:H — All API traffic (credentials, tokens, PII) exposed
- VI:L — Attacker can modify request/response bodies
- VA:N — App functionality not disrupted
- SC:N/SI:N/SA:N — No cross-system impact
- E:U — No public exploit

**Score:** CVSS-B: 6.5 (MEDIUM)

---

### Example 3: Hardcoded API Key in Production IPA

App contains a hardcoded production API key in plain text in `Info.plist` or in a Swift constant. The IPA is in the App Store (or distributed via MDM), and the key can be extracted via static analysis.

**Vulnerability:**
- Static analysis reveals the key in decompiled code or in `Info.plist`
- Any attacker with the IPA can extract the key
- The API key provides full read/write access to backend

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:N — IPA downloadable from App Store (or MDM, or backup)
- AC:L — Simple `strings` or `plutil` extraction
- AT:N — No special conditions
- PR:N — No authentication required to obtain the IPA
- UI:N — No user interaction needed
- VC:H — API key exposes full user account data via backend
- VI:L — Limited ability to modify data via the API
- VA:N — Service availability not impacted
- SC:N/SI:N/SA:N — No cross-system impact
- E:U — No public exploit

**Score:** CVSS-B: 7.5 (HIGH)

---

### Example 4: WebView XSS via Universal Link

A WKWebView loads arbitrary URLs from universal link parameters without origin or scheme validation, allowing XSS in the WebView context.

**Vulnerability:**
- Triggered by malicious universal link delivered via SMS, email, or any other app
- User must click the link
- XSS executes JavaScript in the WebView's origin
- Can read cookies, perform actions on behalf of the user

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N/E:U
```

**Metrics breakdown:**
- AV:N — Universal link can be delivered remotely
- AC:L — Straightforward XSS exploitation
- AT:N — No special deployment conditions
- PR:N — No app permissions needed
- UI:A — User must click malicious link (Active interaction)
- VC:L — Limited to WebView cookies / scoped data
- VI:L — JavaScript execution in WebView can perform limited actions
- VA:N — App functionality not disrupted
- SC:H — XSS steals cookies from the user's browser if linked to it (subsequent system)
- SI:H — XSS can perform actions in user's browser
- SA:N — No browser crash/DoS
- E:U — No public exploit

**Score:** CVSS-B: 7.8 (HIGH)

---

### Example 5: Keychain Items with kSecAttrAccessibleAlways

App stores authentication tokens in Keychain with `kSecAttrAccessibleAlways` (deprecated, accessible even when device is locked).

**Vulnerability:**
- Requires physical access to a powered, locked device
- Forensic tools can extract Keychain items
- Tokens accessible without device unlock

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N/E:U
```

**Metrics breakdown:**
- AV:P — Requires physical device access
- AC:L — Direct forensic extraction
- AT:N — No special deployment conditions
- PR:N — No authentication required for forensic access
- UI:N — No user interaction
- VC:H — Full credentials exposed
- VI:N — Cannot modify credentials (read-only)
- VA:N — Service not disrupted
- SC:H/SI:H/SA:N — Subsequent system (the user's account on the server) is impacted if the tokens are used
- E:U — No public exploit

**Score:** CVSS-B: 7.5 (HIGH)

---

### Example 6: SSL Pinning Missing with MITM Risk

App performs HTTPS API calls but lacks SSL pinning, vulnerable to MITM on compromised networks.

**Vulnerability:**
- Requires network adjacency
- Passive attack once MITM established (rogue CA, proxy)
- Exposes session tokens and API data

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:A — Requires network adjacency
- AC:H — Requires attacker-controlled network (rogue CA, MITM proxy)
- AT:N — No special deployment conditions
- PR:N — No authentication to perform MITM
- UI:P — Passive interaction (user using app)
- VC:L — Network traffic exposed (vs. data at rest)
- VI:L — Possible session hijacking or token injection
- VA:N — App functionality not disrupted
- SC:N/SI:N/SA:N — No cross-system impact
- E:U — No public exploit

**Score:** CVSS-B: 4.1 (MEDIUM)

---

### Example 7: Path Traversal in WKWebView loadFileURL

A WKWebView loads user-supplied paths via `loadFileURL:allowingReadAccessToURL:` without proper canonicalization, allowing read access outside the intended directory.

**Vulnerability:**
- Requires user interaction (deep link with crafted path, or attacker-controlled content)
- Allows reading arbitrary files in the app sandbox
- Limited to files accessible by the app

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:L — Requires malicious app installed or attacker-controlled deep link
- AC:L — Straightforward path traversal with `../`
- AT:N — No special deployment conditions
- PR:L — Attacker app or link needs basic interaction
- UI:A — User must trigger the file load (deep link, paste)
- VC:H — Full file content exposed (Keychain DB, sensitive plist, etc.)
- VI:N — Read-only operation
- VA:N — App functionality not disrupted
- SC:N/SI:N/SA:N — No cross-system impact
- E:U — No public exploit

**Score:** CVSS-B: 5.5 (MEDIUM)

---

### Example 8: Universal Link Hijack via apple-app-site-association Misconfiguration

The `apple-app-site-association` (AASA) file is misconfigured — it either allows a third-party component (e.g., a CDN that can be compromised) or doesn't restrict paths, enabling arbitrary app takeover via universal links.

**Vulnerability:**
- Attacker hosts a malicious page that triggers a universal link
- iOS opens the vulnerable app with attacker-controlled path/parameters
- No user prompt if AASA doesn't define restrictive `components` paths
- Can be exploited to inject state, reset passwords, or steal session if parameters are trusted

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P
```

**Metrics breakdown:**
- AV:N — Remote exploitation via hosted page
- AC:L — Direct universal link delivery
- AT:N — No jailbreak or special conditions
- PR:N — No authentication required
- UI:A — User must tap the universal link
- VC:H — Session/token exposure depending on parameters
- VI:H — State-changing actions possible (password reset, etc.)
- VA:N — Service not disrupted
- SC:N/SI:N/SA:N — No cross-system impact
- E:P — Public PoC exists (universal link abuse is well documented)

**Score:** CVSS-B: 8.5 (HIGH)

---

### Example 9: XPC Service IPC Injection

The app exposes an XPC service that accepts and processes messages. The interface allows arbitrary method invocation or doesn't validate the calling app's entitlement, leading to data leakage or modification.

**Vulnerability:**
- Requires malicious app installed
- Direct XPC message send
- Can read/write data the XPC service has access to

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U
```

**Metrics breakdown:**
- AV:L — Requires malicious app co-installed
- AC:L — Direct XPC connection
- AT:N — No special deployment conditions
- PR:L — Malicious app needs basic launch + XPC entitlement (or none for NSXPCConnection with `XPC_SERVICE_NAME`)
- UI:N — No user interaction
- VC:H — Full data read from XPC service
- VI:H — Arbitrary method invocation → state modification
- VA:N — Service not disrupted
- SC:N/SI:N/SA:N — No cross-system impact
- E:U — No public exploit

**Score:** CVSS-B: 7.1 (HIGH)

---

### Example 10: Jailbreak Detection Bypass Leading to Runtime Tampering

App implements jailbreak detection but uses a weak signature (e.g., checking for `/Applications/Cydia.app` only). On a jailbroken device, an attacker can bypass detection via Frida and then perform runtime tampering (SSL pinning bypass, method swizzling, etc.).

**Vulnerability:**
- Requires jailbroken device (Attack Requirements: Present)
- Attacker can bypass the weak detection via known Frida scripts
- Subsequent runtime tampering enables access to app internals

**CVSS 4.0 Vector:**
```
CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P
```

**Metrics breakdown:**
- AV:P — Requires physical device access (jailbroken)
- AC:L — Bypass is straightforward with public Frida scripts
- AT:P — Jailbroken device is the prerequisite
- PR:N — No app-level authentication required
- UI:N — No user interaction
- VC:L — Limited to whatever runtime tampering exposes
- VI:L — Limited integrity impact (bypass enables other attacks)
- VA:N — App functionality not directly disrupted
- SC:N/SI:N/SA:N — No cross-system impact (this finding is the prerequisite, not the final exploit)
- E:P — Public PoC exists (Frida bypass scripts widely available)

**Score:** CVSS-B: 3.4 (LOW)

> **Note**: This is a classic case where the bypass itself is LOW because it's a prerequisite, not the final impact. The real risk surfaces when the bypass enables the next step (SSL pinning bypass → MITM → data exfiltration). Score that next step independently.

---

## 9. Quick Scoring Cheat Sheet

### Base Metrics Quick Reference

| Metric | Value | Severity Level | Typical iOS Scenario |
|--------|--------|----------------|----------------------|
| AV | N (Network) | Highest | Universal link, API exploit, push notification payload |
| AV | A (Adjacent) | High | WiFi MITM, Bluetooth |
| AV | L (Local) | Medium | Co-installed app, app group abuse, pasteboard hijack |
| AV | P (Physical) | Low | USB, device theft, forensic acquisition |
| AC | L (Low) | Higher | Hardcoded secret, simple injection, predictable input |
| AC | H (High) | Lower | Race condition, native memory corruption, specific iOS version |
| AT | N (None) | Higher | Default config, no jailbreak needed |
| AT | P (Present) | Lower | Jailbreak required, MDM profile, debug build |
| PR | N (None) | Higher | No auth, exported component, no permission prompt |
| PR | L (Low) | Medium | Basic iOS permission (photos, location) |
| PR | H (High) | Lower | Keychain access group entitlement, jailbreak, MDM |
| UI | N (None) | Higher | Background XPC, notification payload, zero-click |
| UI | P (Passive) | Medium | App open, notification received |
| UI | A (Active) | Lower | Tap link, grant permission, Face ID |
| VC/VI/VA | H (High) | Highest | Full impact on Keychain/UserDefaults/files |
| VC/VI/VA | L (Low) | Medium | Partial impact |
| VC/VI/VA | N (None) | Lower | No impact |

### Subsequent System Impact Decision Tree

```
Does vulnerability affect OTHER systems?
├─ YES → Assess SC/SI/SA
│   ├─ Is it XSS/redirect affecting Safari cookies? → SC:H/SI:H/SA:N
│   ├─ Does it read/write data via App Group shared with another app? → SC:L/SI:L/SA:N
│   ├─ Can it pivot to the user's iCloud account? → SC:H/SI:H/SA:N
│   └─ Can it crash other components or system services? → SC:N/SI:N/SA:H
└─ NO → SC:N/SI:N/SA:N
```

### Exploit Maturity (Threat Metric)

| Exploit Status | E Value | Score Impact |
|---------------|---------|--------------|
| No public exploit | U (Unreported) | None (default) |
| PoC exists (Frida scripts, public Frida CodeShare) | P (PoC) | Reduces score slightly |
| In the wild (jailbreak chains, malware) | A (Active) | Reduces score significantly |

---

## 10. Severity-to-Priority Mapping

| Severity | Priority | Remediation Timeline | Example iOS Vulnerabilities |
|----------|----------|---------------------|------------------------------|
| CRITICAL (9.0-10.0) | Immediate | 0-7 days | Auth bypass via deep link, hardcoded production API key, unencrypted Keychain master keys |
| HIGH (7.0-8.9) | Urgent | 1-30 days | Universal link hijack, XPC injection, ATS fully disabled, biometric bypass, ATS bypass to cleartext |
| MEDIUM (4.0-6.9) | Standard | 30-90 days | Missing SSL pinning, weak Keychain accessibility, pasteboard data exposure, WebView XSS with limited scope |
| LOW (0.1-3.9) | Low | 90+ days | Information disclosure via NSLog, debug symbols, weak jailbreak detection, minor hardening issues |

### OWASP Mobile Top 10 (2024) Mapping to Typical CVSS 4.0 Ranges

| OWASP Category | Typical CVSS 4.0 Base Range |
|----------------|------------------------------|
| M1: Improper Credential Usage | 6.0-9.5 |
| M2: Inadequate Supply Chain Security | 5.0-8.0 |
| M3: Insecure Authentication/Authorization | 6.5-9.5 |
| M4: Insufficient Input/Output Validation | 4.0-8.5 |
| M5: Insecure Communication | 4.0-8.0 |
| M6: Inadequate Privacy Controls | 4.0-7.5 |
| M7: Insufficient Binary Protections | 3.0-7.0 |
| M8: Security Misconfiguration | 3.0-8.5 |
| M9: Insecure Data Storage | 5.0-8.0 |
| M10: Insufficient Cryptography | 4.0-8.0 |

---

## 11. Key Differences from CVSS 3.1

| Aspect | CVSS 3.1 | CVSS 4.0 |
|--------|-----------|-----------|
| Scope | S:U / S:C (Changed/Unchanged) | Removed → SC/SI/SA (Subsequent System impacts) |
| User Interaction | None / Required | None (N) / Passive (P) / Active (A) |
| Attack Requirements | None (part of AC) | New mandatory metric AT:N/P |
| Temporal Metrics | RL, RC, E | Threat: E (Exploit Maturity only) |
| Supplemental Metrics | None (optional) | Safety, Automatable, Recovery, Value Density, Response Effort, Provider Urgency |
| Vector Prefix | CVSS:3.1 | CVSS:4.0 |

---

## 12. Confidence Levels (iOS Pentesting)

| Confidence Level | Description | Action Required |
|------------------|-------------|-----------------|
| Confirmed | Full source-to-sink trace completed, exploitability verified via Frida/Objection on a test device | Report with full CVSS vector |
| Likely | Most of the attack path traced, one hop ambiguous or unverified (e.g., obfuscated native boundary) | Report with CVSS vector, note uncertainty |
| Needs Dynamic Confirmation | Static analysis cannot settle the path due to obfuscation, reflection, or runtime protection | Report as potential, do not assign CVSS score until confirmed |

---

## Additional Resources

- **CVSS v4.0 Calculator**: https://www.first.org/cvss/calculator/4.0
- **CVSS v4.0 Specification**: https://www.first.org/cvss/v4.0/specification-document
- **CVSS v4.0 User Guide**: https://www.first.org/cvss/v4.0/user-guide
- **CVSS v4.0 Examples**: https://www.first.org/cvss/v4.0/examples
- **CVSS v4.0 FAQ**: https://www.first.org/cvss/v4.0/faq
- **OWASP MASTG (iOS section)**: https://mas.owasp.org/MASSTG/0x06a-Testing-Platform-Interaction/

---

## Notes for iOS Pentesters

1. **Always specify CVSS nomenclature** (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE) when communicating scores
2. **Attack Requirements (AT) is mandatory** in all CVSS 4.0 vectors — never omit this metric
3. **Use SC/SI/SA for cross-app/cross-account impacts** — Universal Link abuse that hijacks iCloud session, App Group leak that exposes another app's data, WebView XSS that steals Safari cookies
4. **Supplemental metrics do NOT modify the score** — use them for additional context only
5. **Threat metrics can only reduce** the Base score based on exploit intelligence — they never increase severity
6. **Default/Not Defined values** are assumed for Threat and Environmental metrics unless explicitly specified
7. **Scope is gone** — do not use S:U or S:C notation; use SC/SI/SA for cross-system impacts
8. **User Interaction has 3 values** in 4.0 — distinguish between Passive (opening app, receiving notification) and Active (tapping link, granting permission)
9. **Jailbreak context maps to AT:P** — any finding that requires a jailbroken device (Frida attach, binary patching, runtime hooks on a real device) is AT:P, not AT:N
10. **Encrypted App Store binaries** — most real-world iOS pentests start with `frida-ios-dump` or Clutch. Note in the coverage statement when this step was required
