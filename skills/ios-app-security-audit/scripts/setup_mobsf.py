#!/usr/bin/env python3
"""
MobSF Interactive Setup Script

Prompts user for MobSF installation and configuration.
Non-blocking - script exits cleanly if user declines.
"""

import sys
import _scripts_path  # noqa: F401  -- adds scripts/ to sys.path
from mobsf_detect import MobSFDetector
from mobsf_config import MobSFConfig


def main():
    print("\n" + "=" * 60)
    print("  MobSF Integration Setup (OPTIONAL)")
    print("=" * 60 + "\n")

    response = (
        input(
            "🤖 Do you want to install and configure MobSF for automated analysis? [y/N]: "
        )
        .strip()
        .lower()
    )

    if not response.startswith("y"):
        print(
            "\n⏭️  Skipping MobSF integration. The skill will work perfectly without it.\n"
        )
        return 0

    print("\n🔍 Checking for existing MobSF installation...")

    detector = MobSFDetector()
    result = detector.detect_all()

    if result["found"]:
        print(f"✅ MobSF detected: {result['details']}")
        print(f"   URL: {result['url']}\n")

        use_existing = input("   Use existing installation? [Y/n]: ").strip().lower()
        if not use_existing.startswith("n"):
            config = MobSFConfig()
            config.set_base_url(result["url"])

            api_key = detector.get_api_key(config.get_api_key())
            config.set_api_key(api_key)

            print(f"✅ Configured MobSF at {result['url']}")
            print(f"   API Key: {api_key}\n")
            return 0

    print("\n📦 Installation options:")
    print("   [1] Docker (recommended) - Quick setup, isolated")
    print("   [2] Local (advanced) - Requires Python dependencies")

    choice = input("   Choose installation method [1/2]: ").strip()

    if choice == "1":
        print("\n🐳 Installing MobSF via Docker...")
        print("   Run: ./scripts/install-mobsf-docker.sh")
    elif choice == "2":
        print("\n💻 Installing MobSF locally...")
        print("   Run: ./scripts/install-mobsf-local.sh")
    else:
        print("\n❌ Invalid choice. Skipping MobSF.\n")
        return 0

    print("\n⚠️  After installation, run:")
    print("   python3 scripts/setup_mobsf.py\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
