#!/usr/bin/env python3
"""
MobSF Detection Module for iOS-Pentesting-Skill

Checks for existing MobSF installation in Docker or local.
Returns installation type and status.
"""

import subprocess
import sys
from typing import Dict, Optional

try:
    import requests
except ImportError:  # pragma: no cover - environment dependent
    print(
        "❌ ERROR: the 'requests' package is required by this script.\n"
        "   Install it with:  pip3 install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


class MobSFDetector:
    """Detects existing MobSF installation."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8000
    API_ENDPOINT = "/api/v1"
    HEALTH_ENDPOINT = "/api/v1/mobsf/health"

    def __init__(self, host: str = None, port: int = None):
        # The host may arrive with a scheme ("http://127.0.0.1"). Strip it
        # before rebuilding the URL, otherwise the result is
        # "http://http://127.0.0.1:8000".
        self.host = (host or self.DEFAULT_HOST).strip()
        for scheme in ("http://", "https://"):
            if self.host.lower().startswith(scheme):
                self.host = self.host[len(scheme) :]
                break
        self.port = port or self.DEFAULT_PORT
        self.base_url = f"http://{self.host}:{self.port}"

    def detect_all(self) -> Dict[str, any]:
        result = {
            "found": False,
            "type": None,
            "url": self.base_url,
            "version": None,
            "api_accessible": False,
            "details": "",
        }

        docker_result = self._detect_docker()
        if docker_result["found"]:
            result.update(docker_result)
            return result

        local_result = self._detect_local()
        if local_result["found"]:
            result.update(local_result)
            return result

        api_result = self._check_api_health()
        if api_result["found"]:
            result.update(api_result)
            return result

        return result

    def _detect_docker(self) -> Dict[str, any]:
        try:
            subprocess.run(
                ["docker", "--version"], capture_output=True, check=True, timeout=5
            )
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            return {"found": False, "details": "Docker not available"}

        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", "name=mobsf", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout.strip():
                container_name = result.stdout.strip().split("\n")[0]

                ports_result = subprocess.run(
                    ["docker", "port", container_name, "8000"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if ports_result.returncode == 0 and ports_result.stdout.strip():
                    port_mapping = ports_result.stdout.strip()
                    if "->" in port_mapping:
                        mapped_port = port_mapping.split(":")[1].split("-")[0]
                        self.base_url = f"http://{self.DEFAULT_HOST}:{mapped_port}"

                return {
                    "found": True,
                    "type": "docker",
                    "url": self.base_url,
                    "details": f"MobSF running in Docker container: {container_name}",
                }

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        return {"found": False, "details": "No MobSF Docker container found"}

    def _detect_local(self) -> Dict[str, any]:
        try:
            result = subprocess.run(
                ["python3", "-c", "import mobsf; print(mobsf.__version__)"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                return {
                    "found": True,
                    "type": "local",
                    "version": version,
                    "details": f"MobSF installed locally (v{version})",
                }
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            pass

        try:
            result = subprocess.run(
                ["mobsf", "--version"], capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                return {
                    "found": True,
                    "type": "local",
                    "version": version,
                    "details": f"MobSF CLI available (v{version})",
                }
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            pass

        return {"found": False, "details": "MobSF not installed locally"}

    def _check_api_health(self) -> Dict[str, any]:
        try:
            response = requests.get(f"{self.base_url}{self.HEALTH_ENDPOINT}", timeout=5)

            if response.status_code == 200:
                data = response.json()
                version = data.get("version", "unknown")
                return {
                    "found": True,
                    "type": "api",
                    "url": self.base_url,
                    "version": version,
                    "api_accessible": True,
                    "details": f"MobSF API accessible at {self.base_url}",
                }
        except requests.RequestException:
            pass

        return {"found": False, "details": f"API not accessible at {self.base_url}"}

    def get_api_key(self, stored_key: str = None) -> Optional[str]:
        if stored_key:
            return stored_key

        try:
            response = requests.post(
                f"{self.base_url}{self.API_ENDPOINT}/api_key", timeout=5
            )

            if response.status_code == 200:
                return response.json().get("api_key")
        except requests.RequestException:
            pass

        # MobSF is unreachable. Do NOT generate a fake key — it will
        # be saved to config and every subsequent request will fail.
        # Signal the failure to the caller so it can decide what to do.
        return None


if __name__ == "__main__":
    detector = MobSFDetector()
    result = detector.detect_all()

    print("MobSF Detection Results:")
    print(f"Found: {result['found']}")
    print(f"Type: {result.get('type', 'N/A')}")
    print(f"URL: {result['url']}")
    print(f"Version: {result.get('version', 'N/A')}")
    print(f"API Accessible: {result.get('api_accessible', False)}")
    print(f"Details: {result['details']}")
