#!/usr/bin/env python3
"""
MobSF IPA Upload and Scan Script

Uploads IPA to MobSF and retrieves scan results.
"""

import sys
import argparse
import json
import time
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
import _scripts_path  # noqa: F401  -- adds scripts/ to sys.path
from mobsf_client import MobSFClient
from mobsf_config import MobSFConfig


def upload_and_scan(ipa_path: str, wait: bool = False, timeout: int = 300):
    config = MobSFConfig()

    if not config.is_configured():
        print("❌ MobSF not configured")
        print("   Run: python3 scripts/mobsf_config.py set-url http://127.0.0.1:8000")
        sys.exit(1)

    print(f"📱 Uploading {ipa_path} to MobSF...")
    print(f"   URL: {config.get_base_url()}")

    client = MobSFClient(base_url=config.get_base_url(), api_key=config.get_api_key())

    try:
        upload_result = client.upload_ipa(ipa_path)
        scan_hash = upload_result.get("hash")

        if not scan_hash:
            print("❌ Upload failed: No scan hash returned")
            sys.exit(1)

        print("✅ Upload successful")
        print(f"   Scan hash: {scan_hash}")

        if wait:
            print("⏳ Waiting for scan to complete...")

            start_time = time.time()
            while time.time() - start_time < timeout:
                status = client.get_scan_status(scan_hash)

                if status.get("scan_status") == "Completed":
                    print("✅ Scan completed!")

                    findings = client.get_findings(scan_hash)
                    print(f"\n   Total findings: {len(findings)}")

                    output_file = Path(ipa_path).stem + "-mobsf-findings.json"
                    with open(output_file, "w") as f:
                        json.dump(findings, f, indent=2)

                    print(f"   Saved to: {output_file}")
                    return

                elif status.get("scan_status") == "Failed":
                    print("❌ Scan failed")
                    sys.exit(1)

                time.sleep(5)

            print(f"⚠️  Scan timeout after {timeout}s")
            print(
                f"   Check manually: {config.get_base_url()}/scan_detail/{scan_hash}"
            )

        else:
            print(
                f"\n   View scan: {config.get_base_url()}/scan_detail/{scan_hash}"
            )
            print(
                f"   Retrieve findings: python3 scripts/mobsf_export.py --scan-id {scan_hash}"
            )

    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to MobSF")
        print("   Check: python3 scripts/mobsf_config.py status")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Upload IPA to MobSF for static analysis"
    )
    parser.add_argument("ipa", help="Path to IPA file")
    parser.add_argument("--wait", action="store_true", help="Wait for scan completion")
    parser.add_argument(
        "--timeout", type=int, default=300, help="Max wait time (seconds)"
    )

    args = parser.parse_args()

    if not Path(args.ipa).exists():
        print(f"❌ IPA not found: {args.ipa}")
        sys.exit(1)

    upload_and_scan(args.ipa, args.wait, args.timeout)


if __name__ == "__main__":
    main()
