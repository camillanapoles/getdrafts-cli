# CI/CD Integration for iOS Security

CI/CD pipelines for iOS security testing enable automated vulnerability detection during the development process. This guide covers GitHub Actions, MobSF integration, and automated IPA analysis.

## Architecture Overview

### CI/CD Security Pipeline

```
Code Push
    ↓
Build
    ↓
IPA Generation
    ↓
Security Scanning (MobSF, Static Analysis)
    ↓
SARIF Report
    ↓
PR/Issue Creation
```

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0002: Identify Development and Security Protections
- MASTG-TEST-0083: Testing Binary Protection

## 1. GitHub Actions iOS Security Workflow

### Basic Security Scan Workflow

```yaml
# .github/workflows/ios-security-scan.yml
name: iOS Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Xcode
      uses: maxim-lobanov/setup-xcode@v1
      with:
        xcode-version: latest-stable

    - name: Build iOS App
      run: |
        xcodebuild -workspace MyApp.xcworkspace \
                   -scheme MyApp \
                   -configuration Release \
                   -sdk iphoneos \
                   -archivePath build/MyApp.xcarchive \
                   archive

    - name: Export IPA
      run: |
        xcodebuild -exportArchive \
                   -archivePath build/MyApp.xcarchive \
                   -exportPath build/ipa \
                   -exportOptionsPlist exportOptions.plist

    - name: Install MobSF
      run: |
        git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
        cd Mobile-Security-Framework-MobSF
        pip3 install -r requirements.txt

    - name: Run MobSF Scan
      run: |
        # Start MobSF server
        cd Mobile-Security-Framework-MobSF
        # Bind to 127.0.0.1: MobSF has no authentication.
        python3 manage.py runserver 127.0.0.1:8000 &

        # Wait for server to start
        sleep 10

        # Upload IPA
        IPA_PATH=$(find build/ipa -name "*.ipa" | head -1)
        curl -F "file=@$IPA_PATH" \
             http://localhost:8000/api/v1/upload

        # Get scan results
        SCAN_ID=$(curl -s http://localhost:8000/api/v1/recent_scans | \
                   python3 -c "import sys, json; print(json.load(sys.stdin)[0]['hash'])")

        # Download report
        curl -s http://localhost:8000/api/v1/report_json?scan_id=$SCAN_ID \
             -o security_report.json

        # Download SARIF report
        curl -s http://localhost:8000/api/v1/download_pdf?scan_id=$SCAN_ID \
             -o security_report.pdf

    - name: Upload Security Report
      uses: actions/upload-artifact@v4
      with:
        name: security-report
        path: security_report.pdf

    - name: Upload SARIF Report
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security_report.json

    - name: Check for Critical Issues
      run: |
        CRITICAL=$(python3 -c "import json; data=json.load(open('security_report.json')); print(data['findings']['critical'])")

        if [ "$CRITICAL" -gt 0 ]; then
          echo "Found $CRITICAL critical security issues"
          exit 1
        fi

    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('security_report.json', 'utf8'));

          const critical = report.findings.critical;
          const high = report.findings.high;
          const medium = report.findings.medium;
          const low = report.findings.low;

          const body = `## Security Scan Results

          - **Critical**: ${critical}
          - **High**: ${high}
          - **Medium**: ${medium}
          - **Low**: ${low}

          ${critical > 0 || high > 0 ? '⚠️ Critical or High severity issues found. Please review and fix.' : '✅ No critical or high severity issues.'}

          See the [security report artifact](../actions/runs/${{ github.run_id }}) for details.`;

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: body
          });
```

## 2. MobSF Integration

> **Note on helper scripts**: The `scripts/mobsf_scan.py`, `scripts/mobsf_to_sarif.py`, and `scripts/detect_secrets.py` referenced in the workflows below are **copy-paste templates** — their full source is provided inline in this document (see *MobSF Scan Script*, *MobSF to SARIF Converter*, and *Secrets Detection Script*). Save them into your **own** CI repository's `scripts/` directory. They are not shipped by this skill. For local (non-CI) MobSF runs, use the skill's `scripts/mobsf_upload.py` and `scripts/mobsf_export.py` instead.
>
> `scripts/generate_sarif.py` is **not** provided by this skill and has no inline source here — you must author it in your own CI repository before the workflow in *Static Analysis Workflow* can run.

### MobSF Docker Setup

```yaml
# .github/workflows/mobsf-scan.yml
name: MobSF Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  mobsf-scan:
    runs-on: ubuntu-latest

    services:
      mobsf:
        image: opensecurity/mobile-security-framework-mobsf:latest
        ports:
          - 8000:8000
        options: >-
          --health-cmd "curl -f http://localhost:8000 || exit 1"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        pip3 install requests

    - name: Build IPA
      run: |
        # This would typically be done in a separate build job
        echo "Building IPA..."
        # xcodebuild commands here
        # For demo, we'll use a placeholder

    - name: Upload to MobSF
      env:
        MOBSF_URL: http://localhost:8000
      run: |
        python3 scripts/mobsf_scan.py \
          --ipa build/ipa/MyApp.ipa \
          --url $MOBSF_URL \
          --output mobsf_report

    - name: Generate SARIF
      run: |
        python3 scripts/mobsf_to_sarif.py \
          --input mobsf_report.json \
          --output mobsf_report.sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: mobsf_report.sarif

    - name: Upload PDF Report
      uses: actions/upload-artifact@v4
      with:
        name: mobsf-pdf-report
        path: mobsf_report.pdf
```

### MobSF Scan Script

```python
#!/usr/bin/env python3
# scripts/mobsf_scan.py

import argparse
import requests
import time
import json
import sys
import os
from pathlib import Path

def upload_and_scan(ipa_path, mobsf_url, output_prefix):
    """Upload IPA to MobSF and wait for scan completion"""

    if not os.path.exists(ipa_path):
        print(f"Error: IPA file not found: {ipa_path}")
        sys.exit(1)

    # Wait for MobSF to be ready
    print(f"[*] Waiting for MobSF at {mobsf_url}...")
    for _ in range(30):
        try:
            response = requests.get(f"{mobsf_url}/api_docs", timeout=5)
            if response.status_code == 200:
                print("[+] MobSF is ready")
                break
        except:
            time.sleep(2)
    else:
        print("[-] MobSF failed to start")
        sys.exit(1)

    # Upload IPA
    print(f"[*] Uploading IPA: {ipa_path}")
    with open(ipa_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(f"{mobsf_url}/api/v1/upload", files=files)

    if response.status_code != 200:
        print(f"[-] Upload failed: {response.text}")
        sys.exit(1)

    result = response.json()
    scan_id = result.get('hash')
    print(f"[+] Scan ID: {scan_id}")

    # Wait for scan to complete
    print("[*] Waiting for scan to complete...")
    while True:
        response = requests.get(f"{mobsf_url}/api/v1/scan?scan_id={scan_id}")
        result = response.json()

        status = result.get('status')
        if status == 'completed':
            print("[+] Scan completed")
            break
        elif status == 'failed':
            print("[-] Scan failed")
            sys.exit(1)

        time.sleep(5)

    # Download reports
    print("[*] Downloading reports...")

    # JSON report
    response = requests.get(f"{mobsf_url}/api/v1/report_json?scan_id={scan_id}")
    with open(f"{output_prefix}.json", 'w') as f:
        f.write(response.text)
    print(f"[+] JSON report: {output_prefix}.json")

    # PDF report
    response = requests.get(f"{mobsf_url}/api/v1/download_pdf?scan_id={scan_id}")
    with open(f"{output_prefix}.pdf", 'wb') as f:
        f.write(response.content)
    print(f"[+] PDF report: {output_prefix}.pdf")

    # Score
    response = requests.get(f"{mobsf_url}/api/v1/score?scan_id={scan_id}")
    score = response.json()
    print(f"\n[+] Security Score: {score.get('score', 0)}/100")
    print(f"    - Critical: {score.get('critical', 0)}")
    print(f"    - High: {score.get('high', 0)}")
    print(f"    - Medium: {score.get('medium', 0)}")
    print(f"    - Low: {score.get('low', 0)}")
    print(f"    - Info: {score.get('info', 0)}")

    return score

def main():
    parser = argparse.ArgumentParser(description='MobSF iOS Security Scanner')
    parser.add_argument('--ipa', required=True, help='Path to IPA file')
    parser.add_argument('--url', default='http://localhost:8000', help='MobSF URL')
    parser.add_argument('--output', default='mobsf_report', help='Output prefix')

    args = parser.parse_args()

    score = upload_and_scan(args.ipa, args.url, args.output)

    # Exit with error if critical or high issues found
    if score.get('critical', 0) > 0 or score.get('high', 0) > 0:
        print("\n[!] Critical or High severity issues found!")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### MobSF to SARIF Converter

```python
#!/usr/bin/env python3
# scripts/mobsf_to_sarif.py

import argparse
import json
import sys
from datetime import datetime

def mobsf_to_sarif(mobsf_report_path, sarif_output_path):
    """Convert MobSF JSON report to SARIF format"""

    with open(mobsf_report_path, 'r') as f:
        mobsf_data = json.load(f)

    # Create SARIF structure
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MobSF",
                        "version": mobsf_data.get('version', 'unknown'),
                        "informationUri": "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
                    }
                },
                "results": []
            }
        ]
    }

    # Map MobSF findings to SARIF results
    severity_map = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note'
    }

    # Process different finding types
    findings_types = [
        'binary_analysis',
        'permissions',
        'api_analysis',
        'code_analysis',
        'file_analysis',
        'libraries',
        'ios_api'
    ]

    for finding_type in findings_types:
        if finding_type in mobsf_data:
            findings = mobsf_data[finding_type]

            if isinstance(findings, dict):
                findings = findings.get('findings', [])

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                severity = finding.get('severity', 'info').lower()
                if severity not in severity_map:
                    continue

                result = {
                    "ruleId": finding.get('id', finding_type),
                    "level": severity_map[severity],
                    "message": {
                        "text": finding.get('description', finding.get('message', ''))
                    },
                    "locations": []
                }

                # Add location if available
                if 'file' in finding:
                    result['locations'].append({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding['file']
                            }
                        }
                    })

                sarif['runs'][0]['results'].append(result)

    # Write SARIF output
    with open(sarif_output_path, 'w') as f:
        json.dump(sarif, f, indent=2)

    print(f"[+] SARIF report generated: {sarif_output_path}")
    print(f"    Total findings: {len(sarif['runs'][0]['results'])}")

def main():
    parser = argparse.ArgumentParser(description='Convert MobSF report to SARIF')
    parser.add_argument('--input', required=True, help='MobSF JSON report path')
    parser.add_argument('--output', default='mobsf_report.sarif', help='SARIF output path')

    args = parser.parse_args()

    mobsf_to_sarif(args.input, args.output)

if __name__ == '__main__':
    main()
```

## 3. Automated IPA Analysis

### Static Analysis Workflow

```yaml
# .github/workflows/static-analysis.yml
name: iOS Static Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  static-analysis:
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Xcode
      uses: maxim-lobanov/setup-xcode@v1
      with:
        xcode-version: latest-stable

    - name: Build for analysis
      run: |
        xcodebuild -workspace MyApp.xcworkspace \
                   -scheme MyApp \
                   -configuration Debug \
                   -sdk iphoneos \
                   clean build \
                   | tee build.log

    - name: Analyze build log for issues
      run: |
        grep -i "warning\|error" build.log > analysis_issues.txt

    - name: Run SwiftLint
      run: |
        brew install swiftlint
        swiftlint lint --reporter json > swiftlint_report.json

    - name: Run SwiftFormat check
      run: |
        brew install swiftformat
        swiftformat --lint --report json > swiftformat_report.json

    - name: Check for hardcoded secrets
      run: |
        python3 scripts/detect_secrets.py \
          --directory ./MyApp \
          --output secrets_report.json

    - name: Generate SARIF
      run: |
        # NOTE: scripts/generate_sarif.py is NOT provided by this skill and has no
        #       inline source in this document. You must author it in your own CI
        #       repository before this step can run.
        python3 scripts/generate_sarif.py \
          --swiftlint swiftlint_report.json \
          --swiftformat swiftformat_report.json \
          --secrets secrets_report.json \
          --output static_analysis.sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: static_analysis.sarif

    - name: Check for secrets
      run: |
        SECRETS=$(python3 -c "import json; data=json.load(open('secrets_report.json')); print(len(data.get('secrets', [])))")

        if [ "$SECRETS" -gt 0 ]; then
          echo "Found $SECRETS potential secrets"
          exit 1
        fi
```

### Secrets Detection Script

```python
#!/usr/bin/env python3
# scripts/detect_secrets.py

import argparse
import json
import re
import os
from pathlib import Path
from typing import List, Dict

# Patterns for detecting secrets
SECRET_PATTERNS = [
    # API Keys
    (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'API Key'),
    (r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'API Key'),

    # AWS Keys
    (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\'](AKIA[0-9A-Z]{16})["\']', 'AWS Access Key'),
    (r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([0-9a-zA-Z/+]{40})["\']', 'AWS Secret Key'),

    # Google Cloud Keys
    (r'google[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{39})["\']', 'Google API Key'),

    # Passwords
    (r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password'),

    # Tokens
    (r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'Token'),
    (r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'Auth Token'),

    # Secret Keys
    (r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'Secret Key'),

    # Private Keys
    (r'-----BEGIN (RSA )?PRIVATE KEY-----', 'Private Key'),

    # URLs with sensitive info
    (r'(https?://[^"\s]+:[^"\s]+@[^"\s]+)', 'URL with credentials'),
]

def scan_file(file_path: str) -> List[Dict]:
    """Scan a single file for secrets"""
    secrets = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        for pattern_name, pattern in SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count('\n') + 1
                line_content = lines[line_number - 1].strip()

                secrets.append({
                    'file': file_path,
                    'line': line_number,
                    'type': pattern_name,
                    'pattern': match.group(0)[:100],
                    'content': line_content[:100]
                })

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return secrets

def scan_directory(directory: str, extensions: List[str]) -> List[Dict]:
    """Scan directory for secrets"""
    all_secrets = []

    for root, dirs, files in os.walk(directory):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in ['Pods', '.git', 'build', 'DerivedData']]

        for file in files:
            file_path = os.path.join(root, file)

            # Check file extension
            file_ext = os.path.splitext(file)[1]
            if file_ext not in extensions:
                continue

            secrets = scan_file(file_path)
            all_secrets.extend(secrets)

    return all_secrets

def main():
    parser = argparse.ArgumentParser(description='Detect secrets in iOS project')
    parser.add_argument('--directory', required=True, help='Project directory')
    parser.add_argument('--output', default='secrets_report.json', help='Output file')
    parser.add_argument('--extensions', nargs='+',
                        default=['.swift', '.m', '.h', '.plist', '.json', '.xml'],
                        help='File extensions to scan')

    args = parser.parse_args()

    print(f"[*] Scanning directory: {args.directory}")
    secrets = scan_directory(args.directory, args.extensions)

    if secrets:
        print(f"[!] Found {len(secrets)} potential secrets")

        # Group by type
        by_type = {}
        for secret in secrets:
            secret_type = secret['type']
            if secret_type not in by_type:
                by_type[secret_type] = []
            by_type[secret_type].append(secret)

        for secret_type, secrets_list in by_type.items():
            print(f"    - {secret_type}: {len(secrets_list)}")

        # Write report
        report = {
            'secrets': secrets,
            'summary': {
                'total': len(secrets),
                'by_type': {k: len(v) for k, v in by_type.items()}
            }
        }

        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"[+] Report saved to: {args.output}")
    else:
        print("[+] No secrets found")

if __name__ == '__main__':
    main()
```

## Testing Checklist

### CI/CD Pipeline
- [ ] Test IPA build workflow
- [ ] Verify MobSF integration
- [ ] Check SARIF generation
- [ ] Test PR commenting
- [ ] Verify artifact upload

### Security Scanning
- [ ] Test secrets detection
- [ ] Verify static analysis
- [ ] Check binary analysis
- [ ] Test vulnerability detection
- [ ] Verify report generation

### Integration
- [ ] Test with multiple branches
- [ ] Verify pull request triggers
- [ ] Check scheduled runs
- [ ] Test manual workflow dispatch
- [ ] Verify error handling

### Reporting
- [ ] Test SARIF format
- [ ] Verify GitHub integration
- [ ] Check report completeness
- [ ] Test notification settings
- [ ] Verify artifact retention

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0002**: Identify Development and Security Protections
- **MASTG-TEST-0083**: Testing Binary Protection

## Tools and Resources

### CI/CD Platforms
- **GitHub Actions**: Popular CI/CD platform
- **GitLab CI**: Alternative CI/CD platform
- **Bitbucket Pipelines**: Atlassian CI/CD
- **CircleCI**: Cloud-based CI/CD

### Security Tools
- **MobSF**: Mobile Security Framework
- **OWASP Dependency-Check**: Dependency vulnerability scanner
- **SwiftLint**: Swift linter
- **SwiftFormat**: Swift formatter

### Reference Materials
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [MobSF Documentation](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [SARIF Format](https://sarifweb.azurewebsites.net/)
