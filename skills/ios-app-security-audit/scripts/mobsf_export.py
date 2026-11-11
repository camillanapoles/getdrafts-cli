#!/usr/bin/env python3
"""
MobSF Findings Export Script

Exports MobSF scan findings in various formats.
"""

import sys
import argparse
import json
import _scripts_path  # noqa: F401  -- adds scripts/ to sys.path
from mobsf_client import MobSFClient
from mobsf_config import MobSFConfig


def export_findings(scan_hash: str, output_format: str = "json"):
    config = MobSFConfig()

    if not config.is_configured():
        print("❌ MobSF not configured")
        sys.exit(1)

    client = MobSFClient(base_url=config.get_base_url(), api_key=config.get_api_key())

    try:
        print(f"📊 Retrieving findings for scan: {scan_hash}")
        findings = client.get_findings(scan_hash)

        print(f"   Total findings: {len(findings)}")

        output_file = f"mobsf-findings-{scan_hash[:8]}.{output_format}"

        if output_format == "json":
            with open(output_file, "w") as f:
                json.dump(findings, f, indent=2)

        elif output_format == "markdown":
            with open(output_file, "w") as f:
                f.write("# MobSF Security Findings\n\n")
                f.write(f"Scan ID: {scan_hash}\n\n")

                for finding in findings:
                    f.write(f"## {finding['id']} - {finding['title']}\n\n")
                    f.write(f"**Severity**: {finding['severity']}\n")
                    f.write(f"**Category**: {finding['category']}\n\n")
                    f.write(f"### Description\n\n{finding['description']}\n\n")
                    f.write(f"### Evidence\n\n```\n{finding['evidence']}\n```\n\n")
                    f.write("---\n\n")

        print(f"✅ Exported to: {output_file}")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Export MobSF scan findings")
    parser.add_argument("--scan-id", required=True, help="Scan hash")
    parser.add_argument(
        "--format", choices=["json", "markdown"], default="json", help="Output format"
    )

    args = parser.parse_args()
    export_findings(args.scan_id, args.format)


if __name__ == "__main__":
    main()
