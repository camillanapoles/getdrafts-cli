# SBOM and Supply Chain Security Guide for iOS Applications

## Overview

This guide provides comprehensive instructions for generating Software Bill of Materials (SBOM) and analyzing supply chain security for iOS applications using the iOS-Pentesting-Skill.

## Table of Contents

1. [Introduction](#introduction)
2. [What is an SBOM?](#what-is-an-sbom)
3. [Why Supply Chain Security Matters](#why-supply-chain-security-matters)
4. [SBOM Generation](#sbom-generation)
5. [Dependency Security Scanning](#dependency-security-scanning)
6. [Supply Chain Risk Assessment](#supply-chain-risk-assessment)
7. [Runtime SDK Tracing](#runtime-sdk-tracing)
8. [Best Practices](#best-practices)
9. [Integration with CI/CD](#integration-with-cicd)
10. [Compliance Requirements](#compliance-requirements)

---

## Introduction

Modern iOS applications depend on numerous third-party libraries, frameworks, and SDKs. Understanding and securing this dependency ecosystem is crucial for:

- Identifying known vulnerabilities
- Assessing license compliance
- Detecting supply chain attacks
- Meeting regulatory requirements
- Maintaining auditability

This guide covers static analysis (SBOM generation, dependency scanning) and runtime analysis (SDK tracing) for comprehensive supply chain security.

---

## What is an SBOM?

A **Software Bill of Materials (SBOM)** is a formal inventory of software components and dependencies. It serves as a critical artifact for:

- **Vulnerability Management**: Quickly identify affected components when CVEs are announced
- **License Compliance**: Track license obligations and restrictions
- **Supply Chain Transparency**: Understand the provenance of all code
- **Incident Response**: Accelerate remediation during security incidents

### SBOM Formats

This skill supports multiple SBOM formats:

#### CycloneDX 1.4

Industry-standard format with broad tooling support:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {
    "component": {
      "type": "application",
      "name": "MyApp",
      "version": "1.0.0"
    }
  },
  "components": [...]
}
```

**Advantages**:
- Industry standard with wide adoption
- Supports vulnerability data natively
- Rich metadata capabilities
- Tooling: CycloneDX CLI, Dependency-Track, Snyk

#### SPDX 2.3

Legal-focused format for license compliance:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "name": "MyApp-1.0.0",
  "packages": [...]
}
```

**Advantages**:
- Legal/industry standard for license reporting
- Required by some regulatory frameworks
- Rich relationship modeling
- Tooling: SPDX tools, FOSSology

#### Custom JSON

Simplified format for quick analysis:

```json
{
  "metadata": {...},
  "summary": {...},
  "dependencies": [...]
}
```

---

## Why Supply Chain Security Matters

### Recent Supply Chain Attacks

1. **SolarWinds (2020)**: Malicious code injected into software updates
2. **Codecov (2021)**: Uploader script compromised
3. **Log4j (2021)**: Critical vulnerability in ubiquitous library
4. **EventStream (2018)**: Malicious dependency published to npm

### iOS-Specific Risks

- **Third-party SDKs**: Analytics, ads, authentication, payments
- **App Store Dependencies**: Frameworks embedded in Xcode
- **CocoaPods/SPM Packages**: Public dependency repositories
- **Embedded Frameworks**: Frameworks bundled in the IPA

### Regulatory Requirements

- **US Executive Order 14028**: Requires SBOMs for critical software
- **CISA SBOM Guidelines**: Minimum elements and recommended practices
- **EU Cyber Resilience Act**: Software transparency requirements
- **FDA (Medical Devices)**: Supply chain security for health apps

---

## SBOM Generation

### Prerequisites

```bash
# Ensure Python 3 and required tools are installed
python3 --version
plutil -version
```

### Generating an SBOM

#### Basic Usage

```bash
# Generate JSON SBOM
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format json

# Generate CycloneDX SBOM
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format cyclonedx

# Generate SPDX SBOM
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format spdx

# Generate all formats
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format all
```

#### Advanced Options

```bash
# Specify output directory
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format cyclonedx \
  --output ./sboms/

# Analyze without generating SBOM
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --analyze

# Keep extracted files for inspection
python3 scripts/sbom_generator.py \
  --input app.ipa \
  --format json \
  --no-cleanup
```

### What Gets Detected

#### CocoaPods Dependencies

Parses `Podfile.lock` to identify:
- All installed pods
- Specific versions
- Subspec dependencies

Example:
```yaml
PODS:
  - Alamofire (5.6.2)
  - SDWebImage (5.12.5):
    - SDWebImage/Core (= 5.12.5)
```

#### Swift Package Manager Dependencies

Parses `Package.resolved` to identify:
- Swift packages
- Git references and versions
- Package URLs

Example:
```json
{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {
          "revision": "123456",
          "version": "5.6.2"
        }
      }
    ]
  }
}
```

#### Carthage Dependencies

Parses `Cartfile.resolved` to identify:
- Carthage frameworks
- GitHub repositories
- Version tags

Example:
```
github "Alamofire/Alamofire" "5.6.2"
```

#### Embedded Frameworks

Detects frameworks embedded in the app:
- Binary frameworks (`.framework`)
- Dynamic libraries (`.dylib`)
- Framework names and paths

### Example Output

#### CycloneDX SBOM

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "component": {
      "type": "application",
      "name": "MyApp",
      "version": "1.0.0",
      "purl": "pkg:ios/com.example.myapp@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "Alamofire",
      "version": "5.6.2",
      "purl": "pkg:cocoapods/alamofire@5.6.2",
      "description": "cocoapods library"
    }
  ]
}
```

---

## Dependency Security Scanning

### Scanning for CVEs

The dependency scanner checks multiple vulnerability databases:

#### Supported Sources

1. **NVD (National Vulnerability Database)**
   - Official US government CVE database
   - Complete CVE history
   - CVSS scores and severity ratings

2. **GitHub Advisory Database**
   - Community-driven security advisories
   - Open source focused
   - Dependency graph integration

3. **OSV (Open Source Vulnerabilities)**
   - Google's vulnerability database
   - Fast, API-driven
   - Good for recent vulnerabilities

### Basic Scanning

```bash
# Scan SBOM for vulnerabilities
python3 scripts/dependency_scanner.py \
  --sbom app-sbom.json \
  --output vulnerability-report.json

# Scan dependencies JSON
python3 scripts/dependency_scanner.py \
  --dependencies dependencies.json \
  --output report.json
```

### Scanning Options

```bash
# Check only for CVEs (default)
python3 scripts/dependency_scanner.py \
  --sbom app-sbom.json \
  --check-cves

# Check license compliance
python3 scripts/dependency_scanner.py \
  --sbom app-sbom.json \
  --check-licenses

# Check for typosquatting
python3 scripts/dependency_scanner.py \
  --sbom app-sbom.json \
  --check-typosquatting

# Run all checks
python3 scripts/dependency_scanner.py \
  --sbom app-sbom.json \
  --check-cves \
  --check-licenses \
  --check-typosquatting
```

### Understanding the Report

#### Report Structure

```json
{
  "metadata": {
    "generatedAt": "2024-01-15T10:30:00Z",
    "scanner": "iOS-Pentesting-Skill Dependency Scanner v1.0.0"
  },
  "summary": {
    "totalVulnerabilities": 15,
    "criticalVulnerabilities": 2,
    "highVulnerabilities": 5,
    "licenseIssues": 3,
    "supplyChainWarnings": 7,
    "overallRiskLevel": "HIGH"
  },
  "vulnerabilities": [...],
  "licenseIssues": [...],
  "supplyChainWarnings": [...],
  "recommendations": [...]
}
```

#### Vulnerability Entry

```json
{
  "cveId": "CVE-2023-12345",
  "description": "Remote code execution vulnerability in Alamofire...",
  "severity": "CRITICAL",
  "cvssScore": 9.8,
  "source": "NVD",
  "published": "2023-06-15T00:00:00Z",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
    "https://github.com/Alamofire/Alamofire/security/advisories/..."
  ]
}
```

### Vulnerability Severity Levels

- **CRITICAL (9.0-10.0)**: Immediate remediation required
- **HIGH (7.0-8.9)**: Urgent remediation recommended
- **MEDIUM (4.0-6.9)**: Remediation within 30 days
- **LOW (0.0-3.9)**: Remediation as part of normal updates

---

## Supply Chain Risk Assessment

### Typosquatting Detection

Typosquatting is a supply chain attack where malicious packages use names similar to popular packages.

#### Detection Patterns

The scanner identifies:
- npm-style naming in CocoaPods (`*-js`)
- Suspicious prefixes (`js-`)
- Similar names to popular packages (Levenshtein distance)
- Year suffixes (`*2024`)
- Suspicious suffixes (`-core`, `-app`)

#### Example Finding

```json
{
  "package": "Alamofire-js",
  "warningType": "typosquatting",
  "riskLevel": "high",
  "message": "Package name matches suspicious pattern: *-js",
  "evidence": "Similarity: 0.87 to Alamofire"
}
```

#### Mitigation

1. **Verify Source**: Check the package repository
2. **Review Code**: Inspect source code before integration
3. **Lock Versions**: Pin exact versions in Podfile.lock
4. **Monitor**: Regularly scan for new suspicious packages

### License Compliance

#### Copyleft Licenses

Copyleft licenses require source code disclosure and derivative licensing:

- **GPL**, **LGPL**: Strong copyleft requirements
- **AGPL**: Server-side code disclosure required
- **MPL**: Weak copyleft, file-level

**Risk**: Using copyleft-licensed code may require:
- Publishing app source code
- Licensing app under copyleft terms
- Legal review before deployment

#### Example Finding

```json
{
  "package": "SomeLibrary",
  "license": "GPL-3.0",
  "issueType": "copyleft_license",
  "riskLevel": "high",
  "message": "GPL-3.0 may require source code disclosure and viral licensing"
}
```

#### Permissive Licenses

These licenses are generally safe to use:

- **MIT**: Minimal requirements
- **Apache-2.0**: Patent clause included
- **BSD-2/3-Clause**: Minimal requirements
- **ISC**: Similar to MIT

#### Best Practices

1. **Review All Licenses**: Check dependencies before integration
2. **Legal Review**: Consult legal for copyleft licenses
3. **Document Decisions**: Track license reviews and approvals
4. **Automate Checks**: Integrate license scanning into CI/CD

### Other Supply Chain Risks

#### Outdated Dependencies

Old versions may be unmaintained:

```json
{
  "package": "OldLibrary",
  "warningType": "outdated_version",
  "riskLevel": "low",
  "message": "Package version 1.2.3 appears to be very old and potentially unmaintained"
}
```

#### Unknown Sources

Packages without clear source attribution:

```json
{
  "package": "UnknownLib",
  "warningType": "unknown_source",
  "riskLevel": "low",
  "message": "Package source unknown - manually verify authenticity"
}
```

---

## Runtime SDK Tracing

While SBOM provides static dependency information, runtime SDK tracing identifies which SDKs are actually active and what data they access.

### Why Runtime Tracing?

1. **Detect Unused SDKs**: SDKs included but not used
2. **Identify Active SDKs**: Which SDKs are actually initialized
3. **Monitor Data Access**: What data SDKs access
4. **Behavioral Analysis**: SDK method call patterns

### Using the SDK Tracer

```bash
# Deploy Frida server on device
frida-ps -U  # List processes

# Attach to app
frida -U -f com.example.app -l assets/frida-scripts/sdk-tracer.js

# Or attach to running app
frida -U com.example.app -l assets/frida-scripts/sdk-tracer.js
```

### Detected SDKs

The tracer identifies common SDKs by class prefix:

- **Analytics**: `Mixpanel`, `Amplitude`, `Segment`, `Flurry`, `Crashlytics`, `GSDK`
- **Ads**: `FBSDK` (Facebook), `GAD` (Google Ads), `UnityAds`
- **Attribution**: `Adjust`, `AppsFlyer`, `Branch`
- **Authentication**: `Firebase`, `Auth0`
- **Cloud**: `AWS`, `Amplify`
- **Payment**: `Stripe`, `Braintree`, `PayPal`

### Example Output

```
[*] SDK Tracer - Runtime SDK Detection
[SDK] Firebase detected: com.firebase.iOS
[SDK] Hooking class: FirebaseAnalytics
[SDK] FirebaseAnalytics logEvent called
[SDK] FirebaseAnalytics setUserID called
[SDK] FBSDK detected: com.facebook.sdk
[SDK] Hooking class: FBSDKAppEvents
[SDK] FBSDKAppEvents logEvent called
[*] SDK scan complete
```

### Analyzing SDK Behavior

#### Data Collection

Monitor what data SDKs collect:

```javascript
// Hook specific methods
Interceptor.attach(FBSDKAppEvents['- logEvent:parameters:'].implementation, {
    onEnter: function(args) {
        console.log('[SDK] Facebook Analytics event:');
        console.log('  Event:', ObjC.Object(args[2]).toString());
        console.log('  Params:', ObjC.Object(args[3]).toString());
    }
});
```

#### Network Activity

Track SDK network calls:

```javascript
// Hook URLSession
Interceptor.attach(ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
    onEnter: function(args) {
        var request = ObjC.Object(args[2]);
        console.log('[SDK] Request:', request.URL().toString());
    }
});
```

---

## Best Practices

### 1. Maintain an Up-to-Date SBOM

- **Generate Early**: Create SBOM during development
- **Update Regularly**: Regenerate after dependency changes
- **Version Control**: Commit SBOM to your repository
- **Multiple Formats**: Generate both CycloneDX and SPDX

### 2. Regular Vulnerability Scanning

```bash
# Add to CI/CD pipeline
- name: Generate SBOM
  run: python3 scripts/sbom_generator.py --input MyApp.ipa --format cyclonedx

- name: Scan for CVEs
  run: python3 scripts/dependency_scanner.py --sbom MyApp-sbom-cyclonedx.json
```

### 3. Dependency Hygiene

- **Minimize Dependencies**: Only include necessary SDKs
- **Review Regularly**: Audit dependencies monthly
- **Lock Versions**: Pin exact versions
- **Monitor Updates**: Follow security advisories

### 4. Vendor Risk Assessment

Before adding a new SDK:

1. **Check Security History**: CVEs, security posture
2. **Review Code**: Source code review if available
3. **Check License**: Understand licensing obligations
4. **Verify Company**: Company stability, support
5. **Test Thoroughly**: Sandbox and monitor behavior

### 5. Runtime Monitoring

- **Trace SDKs**: Use Frida scripts during testing
- **Monitor Network**: Capture SDK network traffic
- **Check Storage**: Review SDK file access
- **Audit Logs**: Analyze SDK logging

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Supply Chain Security

on:
  pull_request:
    paths:
      - 'Podfile.lock'
      - 'Package.resolved'
      - 'Cartfile.resolved'

jobs:
  sbom-generation:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build IPA
        run: xcodebuild -scheme MyApp -archivePath MyApp.xcarchive archive

      - name: Export IPA
        run: xcodebuild -exportArchive -archivePath MyApp.xcarchive -exportPath . -exportOptionsPlist export.plist

      - name: Generate SBOM
        run: |
          python3 scripts/sbom_generator.py \
            --input MyApp.ipa \
            --format cyclonedx \
            --output ./sboms/

      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: ./sboms/*.json

  vulnerability-scan:
    needs: sbom-generation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/download-artifact@v3
        with:
          name: sbom

      - name: Scan for CVEs
        run: |
          python3 scripts/dependency_scanner.py \
            --sbom MyApp-sbom-cyclonedx.json \
            --output vulnerability-report.json

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-report
          path: vulnerability-report.json

      - name: Fail on Critical CVEs
        run: |
          critical=$(jq '.summary.criticalVulnerabilities' vulnerability-report.json)
          if [ "$critical" -gt 0 ]; then
            echo "❌ Critical vulnerabilities found!"
            exit 1
          fi
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any

    stages {
        stage('SBOM Generation') {
            steps {
                sh '''
                    python3 scripts/sbom_generator.py \
                        --input MyApp.ipa \
                        --format cyclonedx \
                        --output ./sboms/
                '''
                archiveArtifacts artifacts: 'sboms/*.json', fingerprint: true
            }
        }

        stage('Vulnerability Scan') {
            steps {
                unarchive mapping: ['sboms/*.json': '.']
                sh '''
                    python3 scripts/dependency_scanner.py \
                        --sbom MyApp-sbom-cyclonedx.json \
                        --output vulnerability-report.json
                '''
                archiveArtifacts artifacts: 'vulnerability-report.json'
            }
        }

        stage('Risk Assessment') {
            steps {
                script {
                    def report = readJSON file: 'vulnerability-report.json'
                    def critical = report.summary.criticalVulnerabilities
                    def high = report.summary.highVulnerabilities

                    if (critical > 0 || high > 5) {
                        error("High/Critical vulnerabilities detected!")
                    }
                }
            }
        }
    }
}
```

---

## Compliance Requirements

### US Executive Order 14028

**Minimum SBOM Elements**:

1. **Authorship**: Who created the component
2. **Supply Chain**: Where it came from
3. **Purpose**: What it does
4. **Build**: How it was built

**Recommended Elements**:

1. **Vulnerability Data**: Known CVEs
2. **License Information**: License types
3. **Dependencies**: Transitive dependencies
4. **Provenance**: Source code repository

### CISA SBOM Guidelines

**Minimum Elements for Supply Chain Risk Management**:

1. **Component Name**: Standard naming
2. **Version**: Precise version identifier
3. **Supplier**: Who provided it
4. **Download Location**: Source repository
5. **Purpose**: Component purpose
6. **Dependencies**: List of dependencies
7. **License**: License information

### EU Cyber Resilience Act

**Requirements**:

1. **SBOM Delivery**: Provide SBOM to customers
2. **Vulnerability Disclosure**: Report within 72 hours
3. **Updates**: Provide security updates
4. **Documentation**: Security documentation
5. **Incident Response**: Response procedures

### FDA Medical Device Regulations

**Requirements**:

1. **Software Bill of Materials**: Complete dependency inventory
2. **Vulnerability Management**: Ongoing CVE monitoring
3. **Risk Assessment**: Supply chain risk analysis
4. **Incident Reporting**: Report to FDA
5. **Post-Market Surveillance**: Continuous monitoring

---

## Tools and Resources

### SBOM Tools

- **CycloneDX CLI**: `cyclonedx-cli`
- **Syft**: Generate SBOMs from containers/filesystems
- **Trivy**: Vulnerability scanner with SBOM support
- **OWASP Dependency-Track**: SBOM management platform

### Vulnerability Databases

- **NVD**: https://nvd.nist.gov/
- **GitHub Advisory**: https://github.com/advisories
- **OSV**: https://osv.dev/
- **CocoaPods Security**: https://guides.cocoapods.org/syntax/podfile.html#pod

### License Resources

- **SPDX License List**: https://spdx.org/licenses/
- **ChooseALicense**: https://choosealicense.com/
- **TLDRLegal**: https://www.tldrlegal.com/

### Community Resources

- **OWASP Software Supply Chain**: https://owasp.org/www-project-software-supply-chain/
- **OpenSSF**: https://openssf.org/
- **SBOM Community**: https://www.cisa.gov/sbom

---

## Summary

SBOM generation and supply chain security analysis are critical components of iOS application security. This guide provides:

1. **SBOM Generation**: CycloneDX, SPDX, and custom JSON formats
2. **CVE Scanning**: NVD, GitHub Advisory, and OSV databases
3. **Supply Chain Analysis**: Typosquatting, license compliance, and risk assessment
4. **Runtime Tracing**: Frida-based SDK monitoring
5. **CI/CD Integration**: Automated scanning workflows
6. **Compliance**: Meeting regulatory requirements

**Key Takeaways**:

- Generate SBOMs early and update regularly
- Scan for vulnerabilities continuously
- Review all licenses before integration
- Monitor SDK behavior at runtime
- Integrate into CI/CD pipelines
- Document supply chain decisions

**Next Steps**:

1. Generate SBOM for your app
2. Run vulnerability scan
3. Review license compliance
4. Test runtime SDK tracing
5. Integrate into CI/CD
6. Establish continuous monitoring

---

**Version**: 1.0.0
**Last Updated**: 2024-01-15
**Maintained By**: iOS-Pentesting-Skill Team
