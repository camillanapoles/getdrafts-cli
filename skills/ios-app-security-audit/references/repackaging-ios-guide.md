# IPA Repackaging Guide

## IPA Re-signing Overview

Extract, modify, and re-sign iOS app package for testing and analysis.

### Workflow
```
Original IPA
↓ Extract
↓ Modify
↓ Inject provisioning profile
↓ Re-sign
↓ Re-package
↓ Install
```

## Tools

### codesign
```bash
# Verify signature
codesign -dv --entitlements :- Payload/MyApp.app

# Remove signature
codesign --remove-signature Payload/MyApp.app

# Re-sign
codesign -f -s "iPhone Developer" --entitlements entitlements.plist Payload/MyApp.app
```

### zsign
```bash
pip3 install zsign

zsign -k certificate.p12 -p password -e entitlements.plist -o resigned.ipa original.ipa
```

### ios-deploy
```bash
ios-deploy -b Payload/MyApp.app
ios-deploy -b Payload/MyApp.app -d
```

## Generating Signing Certificates

### Free Apple Developer Account
```bash
# Limited to 7 days per app
# No App Store distribution

# Steps:
# 1. Open Xcode
# 2. Preferences → Accounts
# 3. Add Apple ID
# 4. Create new team (free)
```

### Paid Developer Account
```bash
# $99/year
# 1 year app certificates
# App Store distribution
```

### Self-Signed (Jailbroken)
```bash
openssl req -new -x509 -days 365 -keyout mykey.key -out mycert.crt
openssl pkcs12 -export -in mycert.crt -inkey mykey.key -out certificate.p12
```

## Entitlements Modification

### Creating entitlements.plist
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TEAMID.com.example.app</string>
    
    <key>get-task-allow</key>
    <true/>
    
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.app</string>
    </array>
</dict>
</plist>
```

## Provisioning Profile Injection

### Extract Profile
```bash
security cms -D -i embedded.mobileprovision > profile.plist
plutil -p profile.plist
```

### Inject Profile
```bash
cp profile.mobileprovision Payload/MyApp.app/embedded.mobileprovision
```

## Patching Binary

### 1. Hex Editing
```bash
hexedit Payload/MyApp.app/MyApp
```

### 2. Bypass Root Detection
```bash
// Patching with Frida
frida -U -l jailbreak-bypass-ios.js -f com.example.app
```

### 3. SSL Pinning Bypass
For SSL pinning bypass during a repackaging workflow, use the dedicated
`assets/frida-scripts/ssl-pinning-bypass-ios.js` script — do NOT patch
the binary in-place unless you are specifically testing bypass-resistance.
See `references/ssl-pinning-bypass-ios.md` for the full methodology.

## Installation Methods

### AltStore
```bash
# Non-jailbroken
# Max 3 apps at a time
# 7-day refresh required
```

### ios-deploy
```bash
# Requires USB connection
ios-deploy -b Payload/MyApp.app
```

### Sideloadly
```bash
# Modern alternative to Impactor
# Better stability
```

### Jailbroken
```bash
dpkg -i com.example.app_1.0.0_iphoneos-arm.deb
```

## Security Implications

### For Developers
- Piracy risk
- Security bypass
- Data theft

### Mitigation
```swift
// 1. Certificate pinning
// 2. Root/jailbreak detection
// 3. Binary integrity checks
// 4. Obfuscation
// 5. Server-side validation
```

## OWASP MASTG References
- MASTG-APP-ARCH-013: App Packaging and Distribution
- MASTG-APP-ANALYSIS-014: App Tampering Testing
- MASTG-APP-CODE-007: Anti-Tampering Techniques



## Additional Security Considerations

The generic deep-link security checklist — authentication and authorization,
data privacy, network security, the testing methodology and checklist, advanced
attack scenarios, OWASP MASVS / MASTG mappings, the remediation framework and
the tooling list — is maintained in one place:

> [`deep-link-security-checklist.md`](deep-link-security-checklist.md)

Read it when a deep link or universal link is in scope for the surface covered
by this guide.

