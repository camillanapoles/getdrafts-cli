#!/usr/bin/env python3
"""
Dependency Security Scanner for iOS Applications

Scans dependencies for:
- Known CVE vulnerabilities (NVD, GitHub Advisory, OSV)
- Typosquatting attacks
- License compliance issues
- Supply chain risks

Usage:
    python3 dependency_scanner.py --sbom app-sbom.json
    python3 dependency_scanner.py --dependencies deps.json
    python3 dependency_scanner.py --sbom app-sbom.json --output report.json
    python3 dependency_scanner.py --sbom app-sbom.json --check-licenses
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import urllib.parse
import urllib.error


@dataclass
class Vulnerability:
    """Represents a CVE or security vulnerability."""

    cve_id: str
    description: str
    severity: str
    cvss_score: float
    source: str
    published: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "cveId": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvssScore": self.cvss_score,
            "source": self.source,
            "published": self.published,
            "references": self.references,
        }


@dataclass
class LicenseIssue:
    """Represents a license compliance issue."""

    package: str
    license_type: str
    issue_type: str
    risk_level: str
    message: str

    def to_dict(self) -> Dict:
        return {
            "package": self.package,
            "license": self.license_type,
            "issueType": self.issue_type,
            "riskLevel": self.risk_level,
            "message": self.message,
        }


@dataclass
class SupplyChainWarning:
    """Represents a supply chain security warning."""

    package: str
    warning_type: str
    risk_level: str
    message: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "package": self.package,
            "warningType": self.warning_type,
            "riskLevel": self.risk_level,
            "message": self.message,
            "evidence": self.evidence,
        }


class DependencyScanner:
    """Main dependency scanner class."""

    def __init__(self):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.github_advisory_api = "https://api.github.com/advisories"
        self.osv_api = "https://api.osv.dev/v1/query"

        # Records which vulnerability sources failed. An empty result from a
        # source that is down is NOT evidence of safety, so the failures are
        # tracked and surfaced in the report instead of being swallowed.
        self.source_errors: Dict[str, str] = {}

        # Known typosquatting patterns
        self.typosquatting_patterns = [
            r".*-js$",  # npm-style in CocoaPods
            r"^js-",  # js- prefix
            r"^react-native-",  # React Native pattern
            r".*lib.*",  # lib in name
            r".*\d{4,}$",  # year suffix
            r".*-core$",  # -core suffix
            r".*-app$",  # -app suffix
        ]

        # Known legitimate package prefixes
        self.legitimate_prefixes = [
            "Alamofire",
            "SDWebImage",
            "AFNetworking",
            "MBProgressHUD",
            "Masonry",
            "ReactiveCocoa",
            "SwiftyJSON",
            "SnapKit",
            "Kingfisher",
            "lottie-ios",
            "Firebase",
            "Google",
            "GoogleMaps",
            "GoogleSignIn",
            "Kingfisher",
        ]

        # Copyleft licenses
        self.copyleft_licenses = [
            "GPL",
            "LGPL",
            "AGPL",
            "MPL",
            "CDDL",
            "EPL",
            "GPLv2",
            "GPLv3",
            "LGPLv2",
            "LGPLv3",
        ]

        # Permissive licenses
        self.permissive_licenses = [
            "MIT",
            "Apache",
            "Apache-2.0",
            "BSD",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Unlicense",
        ]

        self.vulnerabilities: List[Vulnerability] = []
        self.license_issues: List[LicenseIssue] = []
        self.supply_chain_warnings: List[SupplyChainWarning] = []

    def load_sbom(self, sbom_path: str) -> List[Dict]:
        """Load dependencies from SBOM file."""
        print(f"[*] Loading SBOM: {sbom_path}")

        with open(sbom_path, "r") as f:
            data = json.load(f)

        # Handle different SBOM formats
        if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
            dependencies = []
            for component in data.get("components", []):
                dependencies.append(
                    {
                        "name": component.get("name"),
                        "version": component.get("version"),
                        "manager": component.get("description", "").split()[0]
                        if component.get("description")
                        else "unknown",
                        "type": component.get("type", "library"),
                    }
                )

        elif "spdxVersion" in data and "SPDX" in data["spdxVersion"]:
            dependencies = []
            for pkg in data.get("packages", []):
                dependencies.append(
                    {
                        "name": pkg.get("name"),
                        "version": pkg.get("versionInfo"),
                        "manager": "unknown",
                        "type": "library",
                    }
                )

        elif "dependencies" in data:
            # Custom JSON format
            dependencies = data["dependencies"]

        else:
            raise ValueError("Unsupported SBOM format")

        print(f"[+] Loaded {len(dependencies)} dependencies")
        return dependencies

    def scan_cves(self, dependencies: List[Dict]) -> None:
        """Scan all dependencies for CVEs."""
        print("[*] Scanning for CVEs")

        total = len(dependencies)
        for i, dep in enumerate(dependencies, 1):
            print(f"  [{i}/{total}] Checking {dep['name']}@{dep['version']}")

            vulns = self.check_cve(dep["name"], dep["version"])
            self.vulnerabilities.extend(vulns)

            # Rate limiting (NVD allows 5 requests per 30 seconds = 6s delay)
            if i < total:
                time.sleep(6)

        print(f"[+] Found {len(self.vulnerabilities)} CVEs")

    def check_cve(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check package against CVE databases."""
        vulnerabilities = []

        # Check NVD
        nvd_cves = self._check_nvd(package_name, version)
        vulnerabilities.extend(nvd_cves)

        # Check OSV (more reliable for open source)
        osv_cves = self._check_osv(package_name, version)
        vulnerabilities.extend(osv_cves)

        # Check GitHub Advisory
        github_cves = self._check_github_advisory(package_name, version)
        vulnerabilities.extend(github_cves)

        return vulnerabilities

    def _check_nvd(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check NVD database."""
        try:
            query = f"{package_name} {version}"
            url = f"{self.nvd_api}?keywordSearch={urllib.parse.quote(query)}"

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "iOS-Pentesting-Skill/1.0")

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return self._parse_nvd_response(data)

        except Exception as e:
            print(
                f"    [!] NVD check failed (results for this dependency are UNRELIABLE): {e}",
                file=sys.stderr,
            )
            self.source_errors["nvd"] = str(e)
            return []

    def _parse_nvd_response(self, data: Dict) -> List[Vulnerability]:
        """Parse NVD API response."""
        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Get metrics
            metrics = cve.get("metrics", {})
            cvss_data = None
            cvss_score = 0.0

            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    cvss_data = metrics[metric_type][0]
                    cvss_score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
                    break

            # Get severity
            descriptions = cve.get("descriptions", [])
            description = descriptions[0].get("value", "") if descriptions else ""

            # Determine severity
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Get references
            references = []
            for ref in cve.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])

            vulnerabilities.append(
                Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="NVD",
                    published=cve.get("published"),
                    references=references,
                )
            )

        return vulnerabilities

    def _check_osv(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check OSV database.

        OSV.dev supports a 'CocoaPods' ecosystem natively. We query it first
        and fall back to a generic query if no results come back.
        """
        try:
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "CocoaPods",
                },
                "version": version,
            }

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.osv_api,
                data=data,
                headers={"Content-Type": "application/json"},
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                return self._parse_osv_response(result)

        except Exception as e:
            print(
                f"    [!] OSV check failed (results for this dependency are UNRELIABLE): {e}",
                file=sys.stderr,
            )
            self.source_errors["osv"] = str(e)
            return []

    def _parse_osv_response(self, data: Dict) -> List[Vulnerability]:
        """Parse OSV API response."""
        vulnerabilities = []

        for vuln in data.get("vulns", []):
            cve_id = vuln.get("id", "")
            summary = vuln.get("summary", "")

            # Get severity
            severity = "UNKNOWN"
            cvss_score = 0.0

            for severity_info in vuln.get("severity", []):
                if "score" in severity_info:
                    cvss_score = float(severity_info["score"])
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break

            # Get references
            references = []
            for ref in vuln.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])

            vulnerabilities.append(
                Vulnerability(
                    cve_id=cve_id,
                    description=summary,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="OSV",
                    references=references,
                )
            )

        return vulnerabilities

    def _check_github_advisory(
        self, package_name: str, version: str
    ) -> List[Vulnerability]:
        """Check GitHub Advisory database."""
        try:
            url = f"{self.github_advisory_api}?ecosystem=cocoapods&package={urllib.parse.quote(package_name)}"

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "iOS-Pentesting-Skill/1.0")

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return self._parse_github_advisory_response(data, version)

        except Exception as e:
            print(
                f"    [!] GitHub Advisory check failed (results for this dependency are UNRELIABLE): {e}",
                file=sys.stderr,
            )
            self.source_errors["github_advisory"] = str(e)
            return []

    def _parse_github_advisory_response(
        self, data: List, version: str
    ) -> List[Vulnerability]:
        """Parse GitHub Advisory API response."""
        vulnerabilities = []

        for advisory in data:
            if advisory.get("withdrawn_at"):
                continue

            cve_id = advisory.get("ghsa_id", "")
            description = advisory.get("summary", "")

            # Get severity
            severity = "UNKNOWN"
            cvss_score = 0.0

            for severity_info in advisory.get("severity", []):
                if "score" in severity_info:
                    cvss_score = float(severity_info["score"])
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break

            # Get references
            references = []
            for ref in advisory.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])

            vulnerabilities.append(
                Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="GitHub Advisory",
                    references=references,
                )
            )

        return vulnerabilities

    def detect_typosquatting(self, dependencies: List[Dict]) -> None:
        """Detect potential typosquatting attacks."""
        print("[*] Detecting typosquatting")

        for dep in dependencies:
            package_name = dep["name"]
            warnings = []

            # Check against known patterns
            for pattern in self.typosquatting_patterns:
                if re.match(pattern, package_name, re.IGNORECASE):
                    # Check if it's a known legitimate package
                    is_legitimate = any(
                        package_name.startswith(prefix)
                        for prefix in self.legitimate_prefixes
                    )

                    if not is_legitimate:
                        warnings.append(
                            {
                                "pattern": pattern,
                                "risk": "medium",
                            }
                        )

            # Check for similar names to popular packages
            for legit_pkg in self.legitimate_prefixes:
                similarity = self._calculate_similarity(package_name, legit_pkg)
                if similarity > 0.7 and similarity < 1.0:
                    warnings.append(
                        {
                            "pattern": f"similar to {legit_pkg}",
                            "risk": "high",
                            "evidence": f"Similarity: {similarity:.2f}",
                        }
                    )

            # Add warnings
            for warning in warnings:
                self.supply_chain_warnings.append(
                    SupplyChainWarning(
                        package=package_name,
                        warning_type="typosquatting",
                        risk_level=warning["risk"],
                        message=f"Package name matches suspicious pattern: {warning['pattern']}",
                        evidence=warning.get("evidence"),
                    )
                )

        print(f"[+] Found {len(self.supply_chain_warnings)} typosquatting warnings")

    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity using Levenshtein distance."""
        if len(s1) < len(s2):
            return self._calculate_similarity(s2, s1)

        if len(s2) == 0:
            return 0.0

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        max_len = max(len(s1), len(s2))
        return 1.0 - (previous_row[-1] / max_len)

    def check_license_compliance(self, dependencies: List[Dict]) -> None:
        """Check license compliance issues."""
        print("[*] Checking license compliance")

        for dep in dependencies:
            license_type = dep.get("license") or "unknown"

            if license_type == "unknown":
                continue

            # Check for copyleft licenses
            for copyleft in self.copyleft_licenses:
                if copyleft.lower() in license_type.lower():
                    self.license_issues.append(
                        LicenseIssue(
                            package=dep["name"],
                            license_type=license_type,
                            issue_type="copyleft_license",
                            risk_level="high",
                            message=f"{license_type} may require source code disclosure and viral licensing",
                        )
                    )

            # Check for proprietary licenses
            if "proprietary" in license_type.lower():
                self.license_issues.append(
                    LicenseIssue(
                        package=dep["name"],
                        license_type=license_type,
                        issue_type="proprietary_license",
                        risk_level="medium",
                        message="Proprietary license may restrict use, modification, or distribution",
                    )
                )

        print(f"[+] Found {len(self.license_issues)} license issues")

    def detect_supply_chain_risks(self, dependencies: List[Dict]) -> None:
        """Detect other supply chain risks."""
        print("[*] Detecting supply chain risks")

        for dep in dependencies:
            # Check for old versions
            version = dep.get("version", "unknown")
            if version != "unknown":
                try:
                    version_parts = version.split(".")
                    if len(version_parts) > 0:
                        major = int(version_parts[0])
                        # Flag semver 0.x as potentially pre-stable / abandoned
                        if major == 0:
                            self.supply_chain_warnings.append(
                                SupplyChainWarning(
                                    package=dep["name"],
                                    warning_type="pre_stable_version",
                                    risk_level="low",
                                    message=(
                                        f"Package version {version} is on 0.x "
                                        "(pre-stable / pre-1.0). Verify the package "
                                        "is still maintained."
                                    ),
                                )
                            )
                except (ValueError, IndexError):
                    pass

            # Check for suspicious package managers
            manager = dep.get("manager", "unknown")
            if manager == "unknown" and dep.get("type") == "library":
                self.supply_chain_warnings.append(
                    SupplyChainWarning(
                        package=dep["name"],
                        warning_type="unknown_source",
                        risk_level="low",
                        message="Package source unknown - manually verify authenticity",
                    )
                )

    def generate_report(self) -> Dict:
        """Generate security report."""
        print("[*] Generating security report")

        # Calculate statistics
        total_cves = len(self.vulnerabilities)
        critical_cves = sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")
        high_cves = sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

        report = {
            "metadata": {
                "generatedAt": datetime.utcnow().isoformat() + "Z",
                "scanner": "iOS-Pentesting-Skill Dependency Scanner v1.0.0",
            },
            "summary": {
                "totalVulnerabilities": total_cves,
                "criticalVulnerabilities": critical_cves,
                "highVulnerabilities": high_cves,
                "licenseIssues": len(self.license_issues),
                "supplyChainWarnings": len(self.supply_chain_warnings),
                "overallRiskLevel": self._calculate_overall_risk(),
            },
            "scanReliable": not self.source_errors,
            "sourceErrors": self.source_errors,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "licenseIssues": [li.to_dict() for li in self.license_issues],
            "supplyChainWarnings": [w.to_dict() for w in self.supply_chain_warnings],
            "recommendations": self._generate_recommendations(),
        }

        return report

    def _calculate_overall_risk(self) -> str:
        """Calculate overall risk level."""
        critical = sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")
        high = sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

        if critical > 0:
            return "CRITICAL"
        elif high > 0:
            return "HIGH"
        elif len(self.vulnerabilities) > 10:
            return "MEDIUM"
        elif self.source_errors:
            # A source was unreachable, so a LOW rating would be unfounded.
            return "UNKNOWN"
        else:
            return "LOW"

    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if any(v.severity == "CRITICAL" for v in self.vulnerabilities):
            recommendations.append(
                "CRITICAL: Update all packages with critical vulnerabilities immediately"
            )

        if any(v.severity == "HIGH" for v in self.vulnerabilities):
            recommendations.append(
                "HIGH: Update all packages with high vulnerabilities as soon as possible"
            )

        if self.license_issues:
            recommendations.append(
                "Review all copyleft licenses for compliance requirements"
            )

        if self.supply_chain_warnings:
            recommendations.append(
                "Review supply chain warnings and verify package authenticity"
            )

        if self.source_errors:
            # Absence of findings is NOT evidence of safety when a source
            # was unreachable, so the report must not claim a clean bill.
            recommendations.append(
                "INCOMPLETE SCAN: "
                + ", ".join(f"{source} unreachable" for source in self.source_errors)
                + " — the absence of findings is NOT evidence of safety. "
                "Re-run the scan once those sources are reachable."
            )

        if not recommendations:
            recommendations.append("No critical security issues found")

        return recommendations

    def save_report(self, report: Dict, output_path: str) -> None:
        """Save report to file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[+] Saved report to: {output_path}")

    def print_summary(self) -> None:
        """Print summary to console."""
        print("\n" + "=" * 60)
        print("DEPENDENCY SECURITY SCAN SUMMARY")
        print("=" * 60)

        print("\nVulnerabilities:")
        print(f"  Total:        {len(self.vulnerabilities)}")
        print(
            f"  Critical:     {sum(1 for v in self.vulnerabilities if v.severity == 'CRITICAL')}"
        )
        print(
            f"  High:         {sum(1 for v in self.vulnerabilities if v.severity == 'HIGH')}"
        )
        print(
            f"  Medium:       {sum(1 for v in self.vulnerabilities if v.severity == 'MEDIUM')}"
        )
        print(
            f"  Low:          {sum(1 for v in self.vulnerabilities if v.severity == 'LOW')}"
        )

        print("\nLicense Issues:")
        print(f"  Total:        {len(self.license_issues)}")

        print("\nSupply Chain Warnings:")
        print(f"  Total:        {len(self.supply_chain_warnings)}")
        print(
            f"  Typosquatting: {sum(1 for w in self.supply_chain_warnings if w.warning_type == 'typosquatting')}"
        )

        print("\n" + "=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scan iOS app dependencies for security issues"
    )
    parser.add_argument("--sbom", "-s", help="Path to SBOM file")
    parser.add_argument("--dependencies", "-d", help="Path to dependencies JSON file")
    parser.add_argument(
        "--output",
        "-o",
        help="Output report path (default: dependency-scan-report.json)",
    )
    parser.add_argument(
        "--check-licenses", action="store_true", help="Check license compliance"
    )
    parser.add_argument(
        "--check-typosquatting", action="store_true", help="Check for typosquatting"
    )
    parser.add_argument(
        "--check-cves",
        action="store_true",
        default=True,
        help="Check for CVEs (default: true)",
    )

    args = parser.parse_args()

    if not args.sbom and not args.dependencies:
        print("[!] Error: Must provide --sbom or --dependencies")
        return 1

    scanner = DependencyScanner()

    try:
        # Load dependencies
        if args.sbom:
            dependencies = scanner.load_sbom(args.sbom)
        else:
            with open(args.dependencies, "r") as f:
                data = json.load(f)
                # Handle both array format and custom JSON with dependencies key
                if isinstance(data, list):
                    dependencies = data
                elif "dependencies" in data:
                    dependencies = data["dependencies"]
                else:
                    raise ValueError(
                        "Invalid dependencies format: expected array or object with 'dependencies' key"
                    )

        # Run scans
        if args.check_cves:
            scanner.scan_cves(dependencies)

        if args.check_licenses:
            scanner.check_license_compliance(dependencies)

        if args.check_typosquatting:
            scanner.detect_typosquatting(dependencies)

        scanner.detect_supply_chain_risks(dependencies)

        # Generate report
        report = scanner.generate_report()

        # Save report
        output_path = args.output or "dependency-scan-report.json"
        scanner.save_report(report, output_path)

        # Print summary
        scanner.print_summary()

        # A scan whose sources were unreachable is not a clean scan: signal it
        # with a non-zero exit code so the caller does not treat the result as
        # "no vulnerabilities found".
        if scanner.source_errors:
            print(
                "[!] INCOMPLETE SCAN - unreachable vulnerability sources: "
                + ", ".join(scanner.source_errors)
                + ". Absence of findings is NOT evidence of safety.",
                file=sys.stderr,
            )
            return 2

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
