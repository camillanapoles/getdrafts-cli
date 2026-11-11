# iOS Version Security Changes

iOS security has evolved significantly across versions. This document tracks security changes from iOS 15-18, including new protections, deprecated APIs, sandbox changes, privacy improvements, and ATS updates.

**MASTG References:**
- MASTG-TEST-0002: Identify Development and Security Protections
- MASTG-TEST-0050: Testing Network Communication
- MASTG-TEST-0051: Testing Endpoint Transport Security

## iOS 15 (2021)

### New Protections
- **Private Relay**: Encrypted traffic routing for iCloud+
- **Hide My Email**: Randomized email addresses
- **App Privacy Report**: Data access tracking
- ** iCloud Private Relay**: Safari and app traffic protection

### Deprecated APIs
- **UIWebView**: Complete removal
- **Deprecated Encryption APIs**: Old CryptoKit methods

### Sandbox Changes
- **File Provider API**: Enhanced sandbox for file access
- **Photo Library Access**: Limited access model

### Privacy Improvements
- **App Privacy Report**: Track data access
- **Mail Privacy Protection**: Hide IP addresses
- **Safari Extensions**: Improved permission model

### ATS Updates
- **iOS 15.4**: New certificate validation requirements

## iOS 16 (2022)

### New Protections
- **Lockdown Mode**: Extreme security for high-risk users
- **Passkeys**: WebAuthn passwordless authentication
- **Security Keys**: FIDO2 support
- **Live Text in Video**: OCR capabilities

### Deprecated APIs
- **Old Location APIs**: CoreLocation updates
- **Legacy Camera APIs**: AVFoundation changes

### Sandbox Changes
- **App Groups**: Enhanced security checks
- **Shared Preferences**: Improved isolation

### Privacy Improvements
- **Lockdown Mode**: Restricted attack surface
- **App Transparency**: Enhanced tracking disclosures
- **Privacy Manifests**: Required for APIs

### ATS Updates
- **iOS 16.0**: TLS 1.3 minimum requirement
- **iOS 16.4**: Certificate authority updates

## iOS 17 (2023)

### New Protections
- **Link Tracking Protection**: URL tracking prevention
- **Sensitive Content Warning**: Explicit content detection
- **iCloud Keychain**: Enhanced password management
- **Face ID**: Improved security features

### Deprecated APIs
- **Old PassKit APIs**: Wallet updates
- **Legacy Contact APIs**: Contacts framework changes

### Sandbox Changes
- **File Access**: Enhanced permissions model
- **Bluetooth**: Require user authorization

### Privacy Improvements
- **Privacy Manifests**: Mandatory for certain APIs
- **Screen Time API**: Family controls
- **Sensitive Content Warning**: Child safety

### ATS Updates
- **iOS 17.0**: Strict certificate validation
- **iOS 17.2**: CA root updates

## iOS 18 (2024)

### New Protections
- **App Store Review**: Enhanced security checks
- **Live Activities**: Protected execution
- **SwiftUI Updates**: Secure by default
- **Core ML**: On-device model protection

### Deprecated APIs
- **Old Core Data**: Migration required
- **Legacy Foundation**: Modern alternatives

### Sandbox Changes
- **App Extensions**: Enhanced isolation
- **Network Extensions**: Improved filtering

### Privacy Improvements
- **App Transparency**: Enhanced disclosures
- **Location Accuracy**: Precision controls
- **Contact Access**: Granular permissions

### ATS Updates
- **iOS 18.0**: TLS 1.3 enforcement
- **iOS 18.1**: Certificate pinning improvements

## Security Testing by Version

### iOS 15 Testing Checklist
- [ ] Test Private Relay bypass
- [ ] Verify App Privacy Report data
- [ ] Check File Provider API security
- [ ] Test photo library access
- [ ] Verify ATS configuration

### iOS 16 Testing Checklist
- [ ] Test Lockdown Mode bypasses
- [ ] Verify Passkey implementation
- [ ] Check security key support
- [ ] Test app group isolation
- [ ] Verify privacy manifest requirements

### iOS 17 Testing Checklist
- [ ] Test link tracking protection
- [ ] Verify sensitive content detection
- [ ] Check iCloud Keychain security
- [ ] Test file access permissions
- [ ] Verify privacy manifest compliance

### iOS 18 Testing Checklist
- [ ] Test Live Activities security
- [ ] Verify Core ML protection
- [ ] Check app extension isolation
- [ ] Test network extension filtering
- [ ] Verify location accuracy controls

## Version Detection

### Frida Script

```javascript
// Detect iOS version
if (ObjC.available) {
    const UIDevice = ObjC.classes.UIDevice;
    const device = UIDevice.currentDevice();

    const systemVersion = device.systemVersion().toString();
    console.log("[+] iOS Version: " + systemVersion);

    // Parse version
    const versionParts = systemVersion.split('.').map(Number);
    const major = versionParts[0];
    const minor = versionParts[1];

    console.log("[+] Major: " + major);
    console.log("[+] Minor: " + minor);

    // Version-specific checks
    if (major >= 18) {
        console.log("[*] iOS 18+ detected - Check for new protections");
    } else if (major >= 17) {
        console.log("[*] iOS 17 detected - Check privacy manifests");
    } else if (major >= 16) {
        console.log("[*] iOS 16 detected - Check Lockdown Mode");
    } else if (major >= 15) {
        console.log("[*] iOS 15 detected - Check Private Relay");
    }
}
```

## OWASP MASTG References

- **MASTG-TEST-0002**: Identify Development and Security Protections
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security
