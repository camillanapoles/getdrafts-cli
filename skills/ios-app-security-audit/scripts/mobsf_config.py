#!/usr/bin/env python3
"""
MobSF Configuration Manager

Handles MobSF API key generation, storage, and retrieval.
Uses secure keychain on macOS and file fallback for other platforms.
"""

import json
import secrets
import argparse
from pathlib import Path
from typing import Optional

DEFAULT_MOBSF_URL = "http://127.0.0.1:8000"


def normalize_base_url(url: str) -> str:
    """Return the MobSF URL with exactly one scheme and no trailing slash.

    The URL can be given as "127.0.0.1:8000", "http://127.0.0.1:8000" or
    "https://host/"; all of them must end up as a single, well formed URL.
    The scheme is preserved: an https deployment must not be downgraded.
    """
    if not url:
        return DEFAULT_MOBSF_URL
    url = url.strip()
    scheme = "http://"
    # Strip every leading scheme, keeping the last one that was given.
    while True:
        lowered = url.lower()
        if lowered.startswith("https://"):
            scheme = "https://"
            url = url[len("https://") :]
        elif lowered.startswith("http://"):
            scheme = "http://"
            url = url[len("http://") :]
        else:
            break
    return f"{scheme}{url.rstrip('/')}"


class MobSFConfig:
    """Manages MobSF configuration."""

    CONFIG_DIR = Path.home() / ".ios-pentest-skill"
    CONFIG_FILE = CONFIG_DIR / "mobsf-config.json"

    def __init__(self):
        self.config = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from file."""
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    self.config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.config = {}

    def _save_config(self):
        """Save configuration to file."""
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: any):
        """Set configuration value."""
        self.config[key] = value
        self._save_config()

    def get_api_key(self) -> Optional[str]:
        """Get MobSF API key."""
        return self.get("api_key")

    def set_api_key(self, api_key: str):
        """Set MobSF API key."""
        self.set("api_key", api_key)

    def generate_api_key(self) -> str:
        """Generate new API key."""
        api_key = secrets.token_hex(16)
        self.set_api_key(api_key)
        return api_key

    def get_base_url(self) -> str:
        """Get MobSF base URL, always with exactly one scheme."""
        return normalize_base_url(self.get("base_url", DEFAULT_MOBSF_URL))

    def set_base_url(self, url: str):
        """Set MobSF base URL, normalising the scheme.

        Normalising here, at the source, is what keeps every consumer safe:
        the URL used to be assembled with a literal "http://" prefix in each
        caller, so a stored URL that already carried a scheme produced
        "http://http://127.0.0.1:8000". Each caller had to remember not to
        add the prefix again.
        """
        self.set("base_url", normalize_base_url(url))

    def is_configured(self) -> bool:
        """Check if MobSF is configured."""
        return bool(self.get_api_key() and self.get_base_url())

    def reset(self):
        """Reset configuration."""
        self.config = {}
        if self.CONFIG_FILE.exists():
            self.CONFIG_FILE.unlink()


def main():
    """CLI interface."""
    parser = argparse.ArgumentParser(description="MobSF Configuration Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    subparsers.add_parser("status", help="Show configuration status")

    parser_set_key = subparsers.add_parser("set-key", help="Set API key")
    parser_set_key.add_argument("key", help='API key (or "generate" to create one)')

    parser_set_url = subparsers.add_parser("set-url", help="Set base URL")
    parser_set_url.add_argument("url", help="Base URL (e.g., http://127.0.0.1:8000)")

    subparsers.add_parser("reset", help="Reset configuration")

    args = parser.parse_args()

    config = MobSFConfig()

    if args.command == "status":
        print("MobSF Configuration:")
        print(f"  Configured: {config.is_configured()}")
        print(f"  Base URL: {config.get_base_url()}")
        print(
            f"  API Key: {config.get_api_key()[:8]}..."
            if config.get_api_key()
            else "  API Key: None"
        )

    elif args.command == "set-key":
        if args.key == "generate":
            api_key = config.generate_api_key()
            print(f"Generated API key: {api_key}")
        else:
            config.set_api_key(args.key)
            print(f"API key set: {args.key}")

    elif args.command == "set-url":
        config.set_base_url(args.url)
        print(f"Base URL set: {args.url}")

    elif args.command == "reset":
        config.reset()
        print("Configuration reset")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
