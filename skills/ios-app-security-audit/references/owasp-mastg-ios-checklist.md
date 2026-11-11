# OWASP MASTG iOS Testing Checklist

Complete OWASP Mobile Application Security Testing Guide (MASTG) iOS testing checklist organized by category with references to test IDs (MASTG-TEST-XXXX).

## 1. Information Gathering

### MASTG-TEST-0001: Information Gathering
- [ ] Identify the application type
- [ ] Gather application metadata
- [ ] Check for hardcoded values
- [ ] Identify third-party components
- [ ] Map the attack surface

### MASTG-TEST-0002: Identify Development and Security Protections
- [ ] Check for debug build
- [ ] Verify compiler protections
- [ ] Check for encryption
- [ ] Verify binary protections
- [ ] Identify security libraries

## 2. Local Data Storage

### MASTG-TEST-0038: Local Data Storage Analysis
- [ ] Analyze data storage locations
- [ ] Check for sensitive data in files
- [ ] Verify data encryption
- [ ] Check for data leakage
- [ ] Review data retention

### MASTG-TEST-0046: Testing for Local Storage
- [ ] Test file storage
- [ ] Check UserDefaults
- [ ] Verify Keychain usage
- [ ] Test Core Data
- [ ] Check for temporary files

### MASTG-TEST-0047: Testing for Keychain Data
- [ ] Extract Keychain items
- [ ] Check for sensitive data
- [ ] Verify access controls
- [ ] Test Keychain encryption
- [ ] Check for backup data

### MASTG-TEST-0048: Testing the Keychain (iOS)
- [ ] Test Keychain APIs
- [ ] Verify Keychain groups
- [ ] Check Keychain accessibility
- [ ] Test Keychain sharing
- [ ] Verify Keychain protection

## 3. Network Communication

### MASTG-TEST-0050: Testing Network Communication
- [ ] Identify network endpoints
- [ ] Test for insecure protocols
- [ ] Verify SSL/TLS usage
- [ ] Check for certificate validation
- [ ] Test for data interception

### MASTG-TEST-0051: Testing Endpoint Transport Security
- [ ] Test for SSL pinning
- [ ] Verify certificate validation
- [ ] Check for TLS configuration
- [ ] Test for protocol downgrade
- [ ] Verify cipher strength

### MASTG-TEST-0052: Testing Inter-Process Communication
- [ ] Test URL schemes
- [ ] Check for IPC abuse
- [ ] Test deep links
- [ ] Verify scheme validation
- [ ] Check for URL scheme injection

### MASTG-TEST-0053: Testing for Custom URL Schemes
- [ ] Enumerate URL schemes
- [ ] Test scheme validation
- [ ] Check for sensitive data in URLs
- [ ] Test scheme hijacking
- [ ] Verify scheme protection

## 4. Code Quality

### MASTG-TEST-0056: Testing Code Quality and Code Construction Issues
- [ ] Check for memory leaks
- [ ] Verify buffer boundaries
- [ ] Test for format string vulnerabilities
- [ ] Check for integer overflows
- [ ] Verify type safety

### MASTG-TEST-0057: Testing Code Quality (iOS)
- [ ] Check for Objective-C vulnerabilities
- [ ] Verify Swift safety
- [ ] Test for memory management issues
- [ ] Check for ARC issues
- [ ] Verify type conversion safety

### MASTG-TEST-0058: Testing Memory Corruption Bugs
- [ ] Test for buffer overflows
- [ ] Check for use-after-free
- [ ] Test for double-free
- [ ] Verify memory bounds
- [ ] Check for dangling pointers

## 5. Privacy

### MASTG-TEST-0060: Testing for Privacy Concerns
- [ ] Review data collection
- [ ] Check for privacy policy
- [ ] Verify consent mechanisms
- [ ] Test data sharing
- [ ] Check for analytics

### MASTG-TEST-0061: Testing for Data Privacy
- [ ] Verify data minimization
- [ ] Check for data encryption
- [ ] Test data retention
- [ ] Verify data deletion
- [ ] Check for data access controls

## 6. WebView

### MASTG-TEST-0073: Testing WebView Protocols
- [ ] Check for WebView usage
- [ ] Test JavaScript interfaces
- [ ] Verify file access
- [ ] Test for XSS
- [ ] Check for mixed content

### MASTG-TEST-0077: Testing for WebView Cache
- [ ] Analyze WebView cache
- [ ] Check for sensitive data in cache
- [ ] Test cache poisoning
- [ ] Verify cache encryption
- [ ] Check for local storage

## 7. Binary Protection

### MASTG-TEST-0083: Testing Binary Protection
- [ ] Check for encryption
- [ ] Verify PIE (Position Independent Executable)
- [ ] Test for stack canaries
- [ ] Check for ARC (Automatic Reference Counting)
- [ ] Verify bitcode

### MASTG-TEST-0084: Testing the Binary (iOS)
- [ ] Analyze binary structure
- [ ] Check for symbols
- [ ] Verify code signing
- [ ] Test for tampering
- [ ] Check for anti-debug

### MASTG-TEST-0085: Anti-Debugging Checks
- [ ] Test debugger detection
- [ ] Verify anti-tamper
- [ ] Check for integrity checks
- [ ] Test for hooking detection
- [ ] Verify anti-frida

## Summary

### Priority Tests (Critical)
1. **MASTG-TEST-0002**: Development and Security Protections
2. **MASTG-TEST-0047**: Keychain Data
3. **MASTG-TEST-0051**: Endpoint Transport Security
4. **MASTG-TEST-0083**: Binary Protection

### Priority Tests (High)
1. **MASTG-TEST-0046**: Local Storage
2. **MASTG-TEST-0050**: Network Communication
3. **MASTG-TEST-0052**: Inter-Process Communication
4. **MASTG-TEST-0084**: Binary Analysis

### Priority Tests (Medium)
1. **MASTG-TEST-0056**: Code Quality
2. **MASTG-TEST-0057**: iOS Code Quality
3. **MASTG-TEST-0073**: WebView Protocols
4. **MASTG-TEST-0085**: Anti-Debugging

## Tools Reference

### Required Tools
- **Frida**: Runtime instrumentation
- **MobSF**: Mobile Security Framework
- **objection**: Runtime exploration
- **class-dump**: Class extraction

### Optional Tools
- **IDA Pro**: Advanced analysis
- **Hopper**: Disassembler
- **Burp Suite**: Network testing
- **Keychain Access**: Keychain viewer
