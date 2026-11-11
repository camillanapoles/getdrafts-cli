# MobSF Integration Guide

Complete guide for Mobile Security Framework (MobSF) integration with iOS-Pentesting-Skill.

## Overview

MobSF is an automated mobile application security testing framework. When integrated with iOS-Pentesting-Skill, it provides:

- **Automated Static Analysis**: Binary analysis, permission checks, crypto detection
- **Malware Analysis**: Malicious behavior detection
- **Network Security**: ATS analysis, certificate pinning checks
- **File Analysis**: Data protection, keychain access patterns
- **Findings Correlation**: Merge with manual source-to-sink analysis

### Benefits

| Benefit | Description |
|---------|-------------|
| **Time Savings** | Automated checks reduce manual analysis time |
| **Coverage** | Scans for common patterns grep might miss |
| **Correlation** | Enhances manual findings with automated evidence |
| **Reporting** | Adds automated detection category to reports |

### Key Principles

- ✅ **OPTIONAL**: User choice, no hard dependency
- ✅ **NON-BLOCKING**: Works perfectly without MobSF
- ✅ **ENHANCEMENT**: Complements manual analysis
- ✅ **GRACEFUL**: Degrades gracefully when unavailable

## Installation

### Option 1: Docker (Recommended)

**Prerequisites**: Docker installed

```bash
# Install Docker (macOS)
brew install --cask docker

# Install Docker (Ubuntu)
curl -fsSL https://get.docker.com | sh
```

**Installation**:
```bash
# Run installation script
./scripts/install-mobsf-docker.sh

# Verify
curl http://127.0.0.1:8000
```

**Access**:
- Web UI: http://127.0.0.1:8000
- API: http://127.0.0.1:8000/api/v1

**Management**:
```bash
# Stop
docker stop mobsf-ios-pentest

# Start
docker start mobsf-ios-pentest

# Remove
docker rm -f mobsf-ios-pentest

# View logs
docker logs mobsf-ios-pentest
```

### Option 2: Local Installation (Advanced)

**Prerequisites**: Python 3.8+, Git

```bash
# Run installation script
./scripts/install-mobsf-local.sh

# Start server
./scripts/run-mobsf-local.sh
```

**Manual Installation**:
```bash
# Clone repository
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git ~/MobSF
cd ~/MobSF

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
> **Bind to 127.0.0.1, not 0.0.0.0**: MobSF has no authentication, so exposing it
> on every interface lets any host on the network upload binaries and read the
> scan results. Use 0.0.0.0 only behind a reverse proxy that adds auth.

python manage.py runserver 127.0.0.1:8000
```

## Configuration

### Interactive Setup

```bash
# Run interactive setup
python3 scripts/setup_mobsf.py
```

The script will:
1. Check for existing MobSF installation
2. Offer installation options if not found
3. Configure API access
4. Save configuration for future sessions

### Manual Configuration

```bash
# Set MobSF URL
python3 scripts/mobsf_config.py set-url http://127.0.0.1:8000

# Generate API key
python3 scripts/mobsf_config.py set-key generate

# Verify configuration
python3 scripts/mobsf_config.py status
```

### Configuration File

Location: `~/.ios-pentest-skill/mobsf-config.json`

```json
{
  "base_url": "http://127.0.0.1:8000",
  "api_key": "a1b2c3d4e5f6..."
}
```

### Environment Variables

```bash
# Override configuration
export MOBSF_BASE_URL="http://192.168.1.100:8000"
export MOBSF_API_KEY="your-api-key"
export MOBSF_ENABLED="true"
```

## Usage

### Basic Workflow

1. **Install and configure MobSF**
   ```bash
   python3 scripts/setup_mobsf.py
   ```

2. **Upload IPA for analysis**
   ```bash
   python3 scripts/mobsf_upload.py app.ipa --wait
   ```

3. **Export findings**
   ```bash
   python3 scripts/mobsf_export.py --scan-id <HASH> --format json
   ```

4. **Correlate with manual findings**
   ```python
   from mobsf_findings_correlator import FindingCorrelator

   manual = load_manual_findings('findings.json')
   mobsf = load_mobsf_findings('mobsf-findings.json')

   correlator = FindingCorrelator(manual, mobsf)
   merged = correlator.correlate()
   ```

5. **Generate report**
   ```bash
   python3 scripts/generate-report.py \
     --input merged-findings.json \
     --output report.html
   ```

### Integration with Skill Phases

**Phase 0**: MobSF setup is offered as optional enhancement

**Phase 3**: If configured, MobSF findings are automatically correlated:
```python
# In Phase 3 implementation
findings = perform_data_flow_analysis(ipa_path)
# Returns: Manual + MobSF findings (if configured)
```

**Phase 5**: Report includes merged findings from all sources

### Examples

**Upload and wait for scan**:
```bash
python3 scripts/mobsf_upload.py MyApp.ipa --wait --timeout 600
```

**Export as Markdown**:
```bash
python3 scripts/mobsf_export.py --scan-id abc123 --format markdown
```

**Custom timeout**:
```bash
python3 scripts/mobsf_upload.py MyApp.ipa --wait --timeout 1200
```

## API Reference

### MobSFClient Class

```python
from mobsf_client import MobSFClient

client = MobSFClient(
    base_url="http://127.0.0.1:8000",
    api_key="your-api-key"
)
```

#### Methods

**upload_ipa(ipa_path: str) -> Dict**
Upload IPA file for static analysis.

```python
result = client.upload_ipa('app.ipa')
scan_hash = result['hash']
```

**get_scan_status(scan_hash: str) -> Dict**
Get scan status.

```python
status = client.get_scan_status(scan_hash)
print(status['scan_status'])  # Completed, Running, Failed
```

**get_static_analysis(scan_hash: str) -> Dict**
Get full static analysis results.

```python
analysis = client.get_static_analysis(scan_hash)
print(analysis['security'])
print(analysis['ats_analysis'])
```

**get_findings(scan_hash: str) -> List[Dict]**
Extract security findings.

```python
findings = client.get_findings(scan_hash)
for finding in findings:
    print(f"{finding['id']}: {finding['title']}")
```

**delete_scan(scan_hash: str) -> Dict**
Delete scan from MobSF.

```python
client.delete_scan(scan_hash)
```

### Finding Structure

```python
{
    "id": "MOBSF-001",
    "title": "SQL Injection",
    "category": "Security",
    "severity": "High",
    "description": "SQL injection vulnerability found...",
    "evidence": "{...}",
    "source": "mobsf",
    "confidence": "Automated Detection",
    "needs_verification": true
}
```

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to MobSF API

**Solutions**:
1. Check MobSF is running:
   ```bash
   # Docker
   docker ps | grep mobsf

   # Local
   ps aux | grep manage.py
   ```

2. Verify URL:
   ```bash
   python3 scripts/mobsf_config.py status
   curl http://127.0.0.1:8000/api/v1/mobsf/health
   ```

3. Check firewall/network settings

### Authentication Issues

**Problem**: API key invalid or missing

**Solutions**:
1. Regenerate API key:
   ```bash
   python3 scripts/mobsf_config.py set-key generate
   ```

2. Verify key in MobSF Web UI

3. Check configuration file:
   ```bash
   cat ~/.ios-pentest-skill/mobsf-config.json
   ```

### Upload Failures

**Problem**: IPA upload fails

**Solutions**:
1. Verify IPA file exists and is valid:
   ```bash
   unzip -l app.ipa
   ```

2. Check disk space on MobSF server

3. Increase timeout:
   ```bash
   python3 scripts/mobsf_upload.py app.ipa --wait --timeout 1200
   ```

4. Check MobSF logs:
   ```bash
   # Docker
   docker logs mobsf-ios-pentest

   # Local
   # Logs in console output
   ```

### Scan Timeout

**Problem**: Scan takes too long

**Solutions**:
1. Increase timeout:
   ```bash
   python3 scripts/mobsf_upload.py app.ipa --wait --timeout 1200
   ```

2. Run without waiting:
   ```bash
   python3 scripts/mobsf_upload.py app.ipa
   # Then check manually in Web UI
   ```

### Graceful Degradation

**Problem**: MobSF configured but unavailable

**Expected Behavior**:
- Skill logs warning: "MobSF enhancement failed: ..."
- Analysis continues with manual tools only
- No crashes or blocking errors

**Verify**:
```bash
# Run Phase 3 with MobSF offline
# Should see warning and continue
```

## Advanced Topics

### Findings Correlation

Automatic correlation merges MobSF findings with manual analysis:

```python
from mobsf_findings_correlator import FindingCorrelator

# Load findings
manual = load_json('manual-findings.json')
mobsf = load_json('mobsf-findings.json')

# Correlate
correlator = FindingCorrelator(manual, mobsf)
merged = correlator.correlate()

# Result structure:
for finding in merged:
    if finding.get('mobsf_correlated'):
        print(f"Manual + MobSF: {finding['title']}")
    elif finding.get('source') == 'mobsf':
        print(f"MobSF only: {finding['title']} (Needs Verification)")
    else:
        print(f"Manual only: {finding['title']}")
```

### Custom Severity Mapping

Modify severity mapping in `mobsf_client.py`:

```python
def _map_severity(self, mobsf_severity: str) -> str:
    """Custom severity mapping."""
    mapping = {
        'critical': 'Critical',
        'high': 'High',
        'warning': 'Medium',
        'info': 'Low',
        'secure': 'Informational',
        # Add custom mappings
    }
    return mapping.get(mobsf_severity.lower(), 'Low')
```

## Summary

- ✅ **Optional**: User choice, no hard dependency
- ✅ **Non-blocking**: Works perfectly without MobSF
- ✅ **Enhancement**: Complements manual analysis
- ✅ **Flexible**: Docker or local installation
- ✅ **Secure**: API key management
- ✅ **Graceful**: Degrades gracefully when unavailable

For more information, see:
- MobSF Documentation: https://mobsf.github.io/docs/
- SKILL.md: Phase 0-5 integration points
- scripts/: Implementation code
