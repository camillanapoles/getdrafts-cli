# GitHub Actions iOS Security

Specific GitHub Actions templates for iOS security scanning including workflow YAML files, steps for plist analysis, binary strings extraction, and ATS checks.

**MASTG References:**
- MASTG-TEST-0001: Information Gathering
- MASTG-TEST-0050: Testing Network Communication
- MASTG-TEST-0051: Testing Endpoint Transport Security

## 1. Plist Analysis Workflow

```yaml
# .github/workflows/plist-analysis.yml
name: iOS Plist Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  plist-analysis:
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Extract and Analyze Info.plist
      run: |
        # Find all Info.plist files
        find . -name "Info.plist" -type f > plists.txt

        # Analyze each plist
        while read plist; do
          echo "Analyzing: $plist"

          # Convert to XML
          plutil -convert xml1 -o "$plist.xml" "$plist" 2>/dev/null || true

          # Parse to JSON
          plutil -p "$plist" > "$plist.parsed.txt" 2>/dev/null || true

          # Check for security issues
          echo "Security checks for $plist:" >> security_issues.txt

          # ATS Check
          if plutil -p "$plist" | grep -q "NSAllowsArbitraryLoads.*true"; then
            echo "  [!] CRITICAL: ATS bypass enabled" >> security_issues.txt
          fi

          # URL Schemes Check
          if plutil -p "$plist" | grep -q "CFBundleURLSchemes"; then
            echo "  [!] Custom URL schemes found" >> security_issues.txt
            plutil -p "$plist" | grep -A5 "CFBundleURLSchemes" >> security_issues.txt
          fi

          # Background Modes Check
          if plutil -p "$plist" | grep -q "UIBackgroundModes"; then
            echo "  [!] Background modes enabled" >> security_issues.txt
          fi

        done < plists.txt

    - name: Check for Security Issues
      run: |
        if [ -f security_issues.txt ] && [ -s security_issues.txt ]; then
          echo "[!] Security issues found:"
          cat security_issues.txt
          exit 1
        else
          echo "[+] No critical security issues found"
        fi

    - name: Upload Analysis Results
      uses: actions/upload-artifact@v4
      with:
        name: plist-analysis-results
        path: |
          **/*.plist.xml
          **/*.plist.parsed.txt
          security_issues.txt
```

## 2. Binary Strings Extraction Workflow

```yaml
# .github/workflows/binary-strings-analysis.yml
name: iOS Binary Strings Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  binary-analysis:
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Xcode
      uses: maxim-lobanov/setup-xcode@v1
      with:
        xcode-version: latest-stable

    - name: Build App
      run: |
        xcodebuild -workspace MyApp.xcworkspace \
                   -scheme MyApp \
                   -configuration Release \
                   -sdk iphoneos \
                   -archivePath build/MyApp.xcarchive \
                   archive

    - name: Extract Binary
      run: |
        # Find the main binary
        APP_PATH=$(find build/MyApp.xcarchive/Products -name "*.app" -type d | head -1)
        BINARY=$(find "$APP_PATH" -type f -perm +111 | head -1)

        cp "$BINARY" main_binary

        # Get binary info
        file main_binary > binary_info.txt
        lipo -info main_binary >> binary_info.txt 2>/dev/null || true

    - name: Extract Strings
      run: |
        # Extract all strings
        strings main_binary > binary_strings.txt

        # Extract URLs
        grep -oE "https?://[a-zA-Z0-9./?=_-]+" binary_strings.txt | \
          sort -u > urls.txt

        # Extract potential secrets
        grep -iE "api[_-]?key|secret|token|password|credential" \
          binary_strings.txt > potential_secrets.txt

        # Extract file paths
        grep -oE "/[a-zA-Z0-9_\-/\.]+" binary_strings.txt | \
          sort -u > file_paths.txt

        # Extract class/method names (Objective-C/Swift)
        grep -oE "\[[A-Za-z0-9_]+\s+[a-zA-Z0-9_:]+\]" binary_strings.txt | \
          sort -u > objc_methods.txt

    - name: Analyze Strings
      run: |
        echo "# Binary Strings Analysis" > analysis_report.md

        echo "## Statistics" >> analysis_report.md
        TOTAL_STRINGS=$(wc -l < binary_strings.txt)
        URL_COUNT=$(wc -l < urls.txt)
        SECRET_COUNT=$(wc -l < potential_secrets.txt)
        FILE_COUNT=$(wc -l < file_paths.txt)

        echo "- Total Strings: $TOTAL_STRINGS" >> analysis_report.md
        echo "- URLs: $URL_COUNT" >> analysis_report.md
        echo "- Potential Secrets: $SECRET_COUNT" >> analysis_report.md
        echo "- File Paths: $FILE_COUNT" >> analysis_report.md

        echo "## URLs" >> analysis_report.md
        echo "\`\`\`" >> analysis_report.md
        head -20 urls.txt >> analysis_report.md
        echo "\`\`\`" >> analysis_report.md

        if [ "$SECRET_COUNT" -gt 0 ]; then
          echo "## Potential Secrets" >> analysis_report.md
          echo "\`\`\`" >> analysis_report.md
          head -20 potential_secrets.txt >> analysis_report.md
          echo "\`\`\`" >> analysis_report.md
        fi

    - name: Check for Secrets
      run: |
        SECRET_COUNT=$(wc -l < potential_secrets.txt)
        if [ "$SECRET_COUNT" -gt 0 ]; then
          echo "[!] Found $SECRET_COUNT potential secrets"
          head -10 potential_secrets.txt
          exit 1
        fi

    - name: Upload Results
      uses: actions/upload-artifact@v4
      with:
        name: binary-strings-analysis
        path: |
          binary_strings.txt
          urls.txt
          potential_secrets.txt
          file_paths.txt
          objc_methods.txt
          binary_info.txt
          analysis_report.md
```

## 3. ATS Configuration Check

```yaml
# .github/workflows/ats-check.yml
name: iOS ATS Configuration Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  ats-check:
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Find Info.plist Files
      run: |
        find . -name "Info.plist" -type f > plists.txt

    - name: Check ATS Configuration
      run: |
        echo "# ATS Configuration Report" > ats_report.md
        echo "" >> ats_report.md

        CRITICAL_ISSUES=0
        WARNING_ISSUES=0

        while read plist; do
          echo "## Checking: $plist" >> ats_report.md
          echo "" >> ats_report.md

          # Check for NSAllowsArbitraryLoads
          if plutil -p "$plist" | grep -q "NSAllowsArbitraryLoads.*true"; then
            echo "[!] CRITICAL: NSAllowsArbitraryLoads is enabled" >> ats_report.md
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          fi

          # Check for NSExceptionDomains
          if plutil -p "$plist" | grep -q "NSExceptionDomains"; then
            echo "[*] Exception domains found:" >> ats_report.md

            plutil -p "$plist" | \
              grep -A20 "NSExceptionDomains" | \
              grep -E "NSExceptionAllowsInsecureHTTPLoads|NSThirdPartyExceptionAllowsInsecureHTTPLoads" >> ats_report.md

            # Check for insecure exceptions
            if plutil -p "$plist" | grep -q "NSExceptionAllowsInsecureHTTPLoads.*true"; then
              echo "[!] WARNING: Insecure HTTP loads allowed for exception domains" >> ats_report.md
              WARNING_ISSUES=$((WARNING_ISSUES + 1))
            fi
          fi

          # Check for minimum TLS version
          if plutil -p "$plist" | grep -q "NSExceptionMinimumTLSVersion"; then
            TLS_VERSION=$(plutil -p "$plist" | \
              grep "NSExceptionMinimumTLSVersion" | \
              head -1 | \
              sed 's/.*"\(TLSv[0-9.]\+\)".*/\1/')

            echo "[*] Minimum TLS version: $TLS_VERSION" >> ats_report.md

            if [ "$TLS_VERSION" = "TLSv1.0" ] || [ "$TLS_VERSION" = "TLSv1.1" ]; then
              echo "[!] WARNING: Insecure TLS version" >> ats_report.md
              WARNING_ISSUES=$((WARNING_ISSUES + 1))
            fi
          fi

          echo "" >> ats_report.md
        done < plists.txt

        # Summary
        echo "## Summary" >> ats_report.md
        echo "- Critical Issues: $CRITICAL_ISSUES" >> ats_report.md
        echo "- Warning Issues: $WARNING_ISSUES" >> ats_report.md

    - name: Fail on Critical Issues
      run: |
        CRITICAL=$(grep -c "CRITICAL:" ats_report.md || echo "0")
        if [ "$CRITICAL" -gt 0 ]; then
          echo "[!] Found $CRITICAL critical ATS issues"
          exit 1
        fi

    - name: Upload ATS Report
      uses: actions/upload-artifact@v4
      with:
        name: ats-configuration-report
        path: ats_report.md
```

## 4. Combined Security Workflow

> **Note**: This workflow calls `.github/scripts/security_analyzer.py`, `generate_sarif.py`, and `generate_summary.py`. Those paths live in **your own repository** — you must author those helper scripts there (the workflow shows the wiring, not the script bodies). They are not provided by this skill.

```yaml
# .github/workflows/ios-security.yml
name: iOS Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

env:
  PYTHON_VERSION: '3.10'

jobs:
  security-scan:
    name: Security Scan
    runs-on: macos-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Xcode
      uses: maxim-lobanov/setup-xcode@v1
      with:
        xcode-version: latest-stable

    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: ${{ env.PYTHON_VERSION }}

    - name: Install Python dependencies
      run: |
        pip3 install requests pyyaml

    - name: Build App
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

    - name: Run Security Scripts
      run: |
        # Extract binary
        APP_PATH=$(find build/MyApp.xcarchive/Products -name "*.app" -type d | head -1)
        BINARY=$(find "$APP_PATH" -type f -perm +111 | head -1)
        cp "$BINARY" main_binary

        # Extract strings
        strings main_binary > binary_strings.txt

        # Find URLs
        grep -oE "https?://[a-zA-Z0-9./?=_-]+" binary_strings.txt | \
          sort -u > urls.txt

        # Find potential secrets
        grep -iE "api[_-]?key|secret|token|password|credential" \
          binary_strings.txt > potential_secrets.txt

        # Analyze Info.plist
        cp "$APP_PATH/Info.plist" Info.plist
        plutil -p Info.plist > info.plist.parsed.txt

    - name: Analyze Security
      run: |
        python3 .github/scripts/security_analyzer.py \
          --binary main_binary \
          --strings binary_strings.txt \
          --urls urls.txt \
          --secrets potential_secrets.txt \
          --info-plist info.plist.parsed.txt \
          --output security_report.json

    - name: Generate SARIF
      run: |
        python3 .github/scripts/generate_sarif.py \
          --input security_report.json \
          --output security.sarif

    - name: Upload SARIF to GitHub
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security.sarif

    - name: Check for Critical Issues
      run: |
        CRITICAL=$(python3 -c "import json; data=json.load(open('security_report.json')); print(data.get('critical_count', 0))")

        if [ "$CRITICAL" -gt 0 ]; then
          echo "[!] Found $CRITICAL critical security issues"
          exit 1
        fi

    - name: Generate Summary
      run: |
        python3 .github/scripts/generate_summary.py \
          --input security_report.json \
          --output security_summary.md

    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const summary = fs.readFileSync('security_summary.md', 'utf8');

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: summary
          });

    - name: Upload Results
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-results
        path: |
          security_report.json
          security.sarif
          security_summary.md
          binary_strings.txt
          urls.txt
          potential_secrets.txt
```

## Testing Checklist

### Workflows
- [ ] Test plist analysis workflow
- [ ] Verify binary strings extraction
- [ ] Check ATS configuration workflow
- [ ] Test combined security workflow
- [ ] Verify artifact upload

### Security Checks
- [ ] Test ATS bypass detection
- [ ] Verify secret detection
- [ ] Check URL extraction
- [ ] Test plist parsing
- [ ] Verify SARIF generation

### Integration
- [ ] Test PR commenting
- [ ] Verify GitHub integration
- [ ] Check scheduled runs
- [ ] Test manual triggers
- [ ] Verify error handling

## OWASP MASTG References

- **MASTG-TEST-0001**: Information Gathering
- **MASTG-TEST-0050**: Testing Network Communication
- **MASTG-TEST-0051**: Testing Endpoint Transport Security

## Tools and Resources

### GitHub Actions
- **Official Actions**: github.com/features/actions
- **Marketplace**: github.com/marketplace?type=actions
- **Documentation**: docs.github.com/en/actions

### Security Tools
- **CodeQL**: GitHub's static analysis
- **MobSF**: Mobile Security Framework
- **ZAP**: Web application scanner

### Reference Materials
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [SARIF Format](https://sarifweb.azurewebsites.net/)
