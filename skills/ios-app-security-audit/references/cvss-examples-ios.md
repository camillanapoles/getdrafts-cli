# CVSS 4.0 Examples for iOS

CVSS 4.0 (Common Vulnerability Scoring System version 4.0) calculation examples specific to iOS security testing. Includes 10 worked examples covering ATS bypass, Keychain exposure, URL scheme hijacking, jailbreak detection bypass, biometric bypass, and more.

## Example 1: ATS Bypass

**Finding**: App uses `NSAllowsArbitraryLoads = true` in Info.plist, allowing insecure HTTP connections.

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: High (VS:H)
**Subsequent System Impact**: None (S:N)

**CVSS 4.0 Score**: 8.2 (HIGH)

**Calculation**:
- Base Metrics: AV:N/AC:L/AT:N/PR:N/UI:N/VS:H/S:N
- Environmental Metrics: Not applicable
- Temporal Metrics: Not applicable

**Rationale**:
- Attack Vector: Network - attacker can intercept traffic
- Attack Complexity: Low - no special skills required
- Privileges Required: None - works on unauthenticated connections
- User Interaction: None - passive attack
- Vulnerable System Impact: High - can steal sensitive data

## Example 2: Keychain Exposure

**Finding**: Sensitive API keys stored in Keychain without proper access controls (kSecAttrAccessibleWhenUnlockedThisDeviceOnly not used).

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: Device Unlock (AT:P)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: High (VS:H)
**Subsequent System Impact**: Low (S:L)

**CVSS 4.0 Score**: 7.4 (HIGH)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:P/PR:N/UI:N/VS:H/S:L

**Rationale**:
- Attack Vector: Local - requires device access
- Attack Requirements: Physical - device must be unlocked
- Privileges Required: None - can access Keychain as any app
- Subsequent System Impact: Low - keys can be used for limited scope

## Example 3: URL Scheme Hijacking

**Finding**: App uses insecure custom URL scheme without validation, allowing malicious apps to hijack callbacks.

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: Low (PR:L)
**User Interaction**: Required (UI:R)
**Vulnerable System Impact**: Medium (VS:M)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 6.3 (MEDIUM)

**Calculation**:
- Base Metrics: AV:N/AC:L/AT:N/PR:L/UI:R/VS:M/S:H

**Rationale**:
- Attack Vector: Network - can exploit remotely
- Privileges Required: Low - need to install malicious app
- User Interaction: Required - user must open malicious link
- Subsequent System Impact: High - can access sensitive data

## Example 4: Jailbreak Detection Bypass

**Finding**: App uses simple jailbreak detection (checking for Cydia) that can be easily bypassed.

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: Physical (AT:P)
**Privileges Required**: Low (PR:L)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: Low (VS:L)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 5.8 (MEDIUM)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:P/PR:L/UI:N/VS:L/S:H

**Rationale**:
- Attack Vector: Local - requires device access
- Attack Requirements: Physical - jailbroken device required
- Vulnerable System Impact: Low - only bypasses detection
- Subsequent System Impact: High - enables further attacks

## Example 5: Biometric Bypass

**Finding**: Biometric authentication can be bypassed by hooking LAContext APIs with Frida.

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: Physical (AT:P)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: High (VS:H)
**Subsequent System Impact**: None (S:N)

**CVSS 4.0 Score**: 7.1 (HIGH)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:P/PR:N/UI:N/VS:H/S:N

**Rationale**:
- Attack Vector: Local - requires device access
- Attack Requirements: Physical - device access required
- Privileges Required: None - no authentication needed
- Vulnerable System Impact: High - bypasses security mechanism

## Example 6: Hardcoded API Key

**Finding**: API key hardcoded in Swift source code, exposed in compiled binary.

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: Medium (VS:M)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 7.4 (HIGH)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:N/PR:N/UI:N/VS:M/S:H

**Rationale**:
- Attack Vector: Local - requires binary access
- Privileges Required: None - can extract strings from binary
- Vulnerable System Impact: Medium - key exposure
- Subsequent System Impact: High - unauthorized API access

## Example 7: SQL Injection

**Finding**: SQLite query vulnerable to SQL injection through user input.

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: High (VS:H)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 8.2 (HIGH)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:N/PR:N/UI:N/VS:H/S:H

**Rationale**:
- Attack Vector: Local - requires app interaction
- Privileges Required: None - works as any user
- Vulnerable System Impact: High - database compromise
- Subsequent System Impact: High - data theft

## Example 8: Insecure UserDefaults

**Finding**: Sensitive authentication tokens stored in UserDefaults without encryption.

**Attack Vector**: Local (AV:L)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: Physical (AT:P)
**Privileges Required**: Low (PR:L)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: Medium (VS:M)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 6.3 (MEDIUM)

**Calculation**:
- Base Metrics: AV:L/AC:L/AT:P/PR:L/UI:N/VS:M/S:H

**Rationale**:
- Attack Vector: Local - requires device access
- Attack Requirements: Physical - device access required
- Privileges Required: Low - any installed app can read UserDefaults
- Vulnerable System Impact: Medium - token exposure

## Example 9: Certificate Pinning Bypass

**Finding**: SSL certificate pinning implementation can be bypassed by hooking SecTrustEvaluate.

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Vulnerable System Impact**: High (VS:H)
**Subsequent System Impact**: None (S:N)

**CVSS 4.0 Score**: 7.1 (HIGH)

**Calculation**:
- Base Metrics: AV:N/AC:L/AT:N/PR:N/UI:N/VS:H/S:N

**Rationale**:
- Attack Vector: Network - MITM attack possible
- Privileges Required: None - works on any connection
- Vulnerable System Impact: High - bypasses security control
- Attack Complexity: Low - requires Frida/Jailbreak

## Example 10: WebView XSS

**Finding**: WebView loads untrusted content without Content Security Policy, vulnerable to XSS.

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Attack Requirements**: None (AT:N)
**Privileges Required**: Low (PR:L)
**User Interaction**: Required (UI:R)
**Vulnerable System Impact**: Medium (VS:M)
**Subsequent System Impact**: High (S:H)

**CVSS 4.0 Score**: 6.3 (MEDIUM)

**Calculation**:
- Base Metrics: AV:N/AC:L/AT:N/PR:L/UI:R/VS:M/S:H

**Rationale**:
- Attack Vector: Network - can exploit remotely
- Privileges Required: Low - need to visit malicious site
- User Interaction: Required - user must visit malicious URL
- Subsequent System Impact: High - can steal sensitive data

## CVSS 4.0 Severity Rating

| Score | Severity |
|-------|----------|
| 0.0 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

## Reference

- [CVSS 4.0 Specification](https://www.first.org/cvss/v4.0/)
- [OWASP CVSS Calculator](https://www.first.org/cvss/calculator/4.0)
