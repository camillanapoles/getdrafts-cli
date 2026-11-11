#!/usr/bin/env python3
"""
MobSF API Client for iOS-Pentesting-Skill

Provides Python API wrapper for MobSF REST API.
"""

import json
import sys
from typing import Dict, List
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover - environment dependent
    print(
        "❌ ERROR: the 'requests' package is required by this script.\n"
        "   Install it with:  pip3 install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


class MobSFClient:
    """MobSF REST API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {"X-Mobsf-Api-Key": api_key, "Accept": "application/json"}
        )

    def upload_ipa(self, ipa_path: str) -> Dict:
        """Upload IPA to MobSF for static analysis."""
        if not Path(ipa_path).exists():
            raise FileNotFoundError(f"IPA not found: {ipa_path}")

        with open(ipa_path, "rb") as f:
            files = {"file": f}
            data = {"scan_type": "ipa", "re_scan": 0}

            response = self.session.post(
                f"{self.base_url}/api/v1/upload", files=files, data=data
            )

            response.raise_for_status()
            return response.json()

    def get_scan_status(self, scan_hash: str) -> Dict:
        """Get scan status."""
        response = self.session.get(f"{self.base_url}/api/v1/scan")

        response.raise_for_status()
        scans = response.json()

        for scan in scans:
            if scan.get("hash") == scan_hash:
                return scan

        raise ValueError(f"Scan not found: {scan_hash}")

    def get_static_analysis(self, scan_hash: str) -> Dict:
        """Get static analysis results."""
        response = self.session.get(f"{self.base_url}/api/v1/report")

        response.raise_for_status()
        data = response.json()

        for scan in data.get("results", []):
            if scan.get("hash") == scan_hash:
                return scan

        raise ValueError(f"Scan not found: {scan_hash}")

    def get_findings(self, scan_hash: str) -> List[Dict]:
        """Extract security findings from static analysis."""
        analysis = self.get_static_analysis(scan_hash)
        findings = []

        security_tests = analysis.get("security", {})

        for test_name, test_results in security_tests.items():
            if not isinstance(test_results, dict):
                continue

            if test_results.get("status") == "insecure":
                findings.append(
                    {
                        "id": f"MOBSF-{test_name.upper()}",
                        "title": test_name.replace("_", " ").title(),
                        "category": "Security",
                        "severity": self._map_severity(test_results.get("severity")),
                        "description": test_results.get("description", ""),
                        "evidence": json.dumps(test_results, indent=2),
                    }
                )

        ats = analysis.get("ats_analysis", {})
        if ats.get("status") == "insecure":
            findings.append(
                {
                    "id": "MOBSF-ATS",
                    "title": "App Transport Security Disabled",
                    "category": "Network",
                    "severity": "High",
                    "description": "ATS is disabled allowing insecure connections",
                    "evidence": json.dumps(ats, indent=2),
                }
            )

        binary = analysis.get("binary_analysis", {})
        for test_name, test_results in binary.items():
            if (
                isinstance(test_results, dict)
                and test_results.get("status") == "insecure"
            ):
                findings.append(
                    {
                        "id": f"MOBSF-BINARY-{test_name.upper()}",
                        "title": f"Binary: {test_name.replace('_', ' ').title()}",
                        "category": "Binary",
                        "severity": self._map_severity(test_results.get("severity")),
                        "description": test_results.get("description", ""),
                        "evidence": json.dumps(test_results, indent=2),
                    }
                )

        return findings

    def _map_severity(self, mobsf_severity: str) -> str:
        """Map MobSF severity to standard severity levels."""
        mapping = {
            "critical": "Critical",
            "high": "High",
            "warning": "Medium",
            "info": "Low",
            "secure": "Informational",
        }
        if not mobsf_severity:
            return "Informational"
        return mapping.get(mobsf_severity.lower(), "Informational")

    def delete_scan(self, scan_hash: str) -> Dict:
        """Delete scan from MobSF."""
        data = {"hash": scan_hash}
        response = self.session.post(f"{self.base_url}/api/v1/delete_scan", json=data)

        response.raise_for_status()
        return response.json()


if __name__ == "__main__":
    import _scripts_path  # noqa: F401
    from mobsf_config import MobSFConfig

    config = MobSFConfig()

    if not config.is_configured():
        print(
            "MobSF not configured. Run: python3 scripts/mobsf_config.py set-url http://127.0.0.1:8000"
        )
        sys.exit(1)

    client = MobSFClient(base_url=config.get_base_url(), api_key=config.get_api_key())
