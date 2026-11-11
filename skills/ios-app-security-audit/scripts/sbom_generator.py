#!/usr/bin/env python3
"""
SBOM Generator for iOS Applications

Generates Software Bill of Materials (SBOM) from IPA files in multiple formats:
- CycloneDX 1.4
- SPDX 2.3
- Custom JSON

Supports:
- CocoaPods (Podfile.lock)
- Swift Package Manager (Package.resolved)
- Carthage (Cartfile.resolved)
- Embedded frameworks detection

Usage:
    python3 sbom_generator.py --input app.ipa --format cyclonedx
    python3 sbom_generator.py --input app.ipa --format spdx
    python3 sbom_generator.py --input app.ipa --format all
    python3 sbom_generator.py --input app.ipa --analyze
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from zipfile import ZipFile, is_zipfile


class Dependency:
    """Represents a single dependency."""

    def __init__(
        self,
        name: str,
        version: Optional[str] = None,
        manager: str = "unknown",
        dep_type: str = "library",
        url: Optional[str] = None,
        license: Optional[str] = None,
    ):
        self.name = name
        self.version = version or "unknown"
        self.manager = manager
        self.type = dep_type
        self.url = url
        self.license = license

    def to_dict(self) -> Dict:
        """Convert dependency to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "manager": self.manager,
            "type": self.type,
            "url": self.url,
            "license": self.license,
        }


class SBOMGenerator:
    """Main SBOM generator class."""

    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        self.extracted_path: Optional[Path] = None
        self.app_bundle_path: Optional[Path] = None
        self.dependencies: List[Dependency] = []
        self.app_name: Optional[str] = None
        self.bundle_id: Optional[str] = None
        self.version: Optional[str] = None

    def validate_ipa(self) -> bool:
        """Validate the IPA file."""
        if not self.ipa_path.exists():
            raise FileNotFoundError(f"IPA file not found: {self.ipa_path}")

        if not is_zipfile(self.ipa_path):
            raise ValueError(f"File is not a valid IPA/ZIP: {self.ipa_path}")

        return True

    def extract_ipa(self) -> Path:
        """Extract IPA to temporary directory."""
        print(f"[*] Extracting IPA: {self.ipa_path}")

        self.extracted_path = Path(tempfile.mkdtemp(prefix="sbom_extract_"))

        try:
            with ZipFile(self.ipa_path, "r") as zip_ref:
                zip_ref.extractall(self.extracted_path)

            print(f"[+] Extracted to: {self.extracted_path}")
            return self.extracted_path

        except Exception as e:
            raise RuntimeError(f"Failed to extract IPA: {e}")

    def find_app_bundle(self) -> Path:
        """Find the .app bundle inside the extracted IPA."""
        if not self.extracted_path:
            raise RuntimeError("IPA not extracted")

        payload_dir = self.extracted_path / "Payload"
        if not payload_dir.exists():
            raise RuntimeError("Payload directory not found in IPA")

        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            raise RuntimeError("No .app bundle found in Payload")

        self.app_bundle_path = app_bundles[0]
        self.app_name = self.app_bundle_path.stem

        print(f"[+] Found app bundle: {self.app_name}")

        return self.app_bundle_path

    def parse_info_plist(self) -> Dict:
        """Parse Info.plist to get app metadata."""
        if not self.app_bundle_path:
            raise RuntimeError("App bundle not found")

        plist_path = self.app_bundle_path / "Info.plist"
        if not plist_path.exists():
            raise RuntimeError("Info.plist not found")

        print("[*] Parsing Info.plist")

        try:
            result = subprocess.run(
                ["plutil", "-convert", "json", "-o", "-", str(plist_path)],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                raise RuntimeError(f"Failed to parse Info.plist: {result.stderr}")

            info = json.loads(result.stdout)

            self.bundle_id = info.get("CFBundleIdentifier", "unknown")
            self.version = info.get("CFBundleShortVersionString", "unknown")

            print(f"[+] Bundle ID: {self.bundle_id}")
            print(f"[+] Version: {self.version}")

            return info

        except Exception as e:
            print(f"[!] Failed to parse Info.plist: {e}")
            return {}

    def detect_package_managers(self) -> List[str]:
        """Detect which package managers are used."""
        if not self.extracted_path:
            raise RuntimeError("IPA not extracted")

        managers = []

        # Check for CocoaPods
        if self._find_file("Podfile.lock"):
            managers.append("cocoapods")
            print("[+] Detected CocoaPods")

        # Check for Swift Package Manager
        if self._find_file("Package.resolved"):
            managers.append("spm")
            print("[+] Detected Swift Package Manager")

        # Check for Carthage
        if self._find_file("Cartfile.resolved"):
            managers.append("carthage")
            print("[+] Detected Carthage")

        return managers

    def _find_file(self, filename: str) -> Optional[Path]:
        """Search for a file in the extracted IPA."""
        if not self.extracted_path:
            return None

        for root, dirs, files in os.walk(self.extracted_path):
            if filename in files:
                return Path(root) / filename

        return None

    def parse_cocoapods(self, lockfile_path: Path) -> List[Dependency]:
        """Parse Podfile.lock for dependencies."""
        dependencies = []

        if not lockfile_path.exists():
            return dependencies

        print(f"[*] Parsing CocoaPods lockfile: {lockfile_path}")

        try:
            with open(lockfile_path, "r") as f:
                content = f.read()

            # Parse PODS section
            pods_section_match = re.search(r"PODS:\s*\n((?:[ \t].*\n)+)", content)
            if pods_section_match:
                pods_text = pods_section_match.group(1)
                pods = re.findall(r"- ([\w/-]+)\s+\(?([\d.]+)\)?", pods_text)

                for name, version in pods:
                    # Handle subspecs (e.g., AFNetworking/Serialization)
                    clean_name = name.split("/")[0]

                    dependencies.append(
                        Dependency(
                            name=clean_name,
                            version=version,
                            manager="cocoapods",
                            dep_type="library",
                        )
                    )

        except Exception as e:
            print(f"[!] Failed to parse Podfile.lock: {e}")

        return dependencies

    def parse_spm(self, resolved_path: Path) -> List[Dependency]:
        """Parse Package.resolved for dependencies."""
        dependencies = []

        if not resolved_path.exists():
            return dependencies

        print(f"[*] Parsing SPM resolved file: {resolved_path}")

        try:
            with open(resolved_path, "r") as f:
                data = json.load(f)

            for package in data.get("object", {}).get("pins", []):
                name = package.get("package")
                state = package.get("state", {})

                dependencies.append(
                    Dependency(
                        name=name,
                        version=state.get("version", "unknown"),
                        manager="spm",
                        dep_type="library",
                        url=state.get("url"),
                    )
                )

        except Exception as e:
            print(f"[!] Failed to parse Package.resolved: {e}")

        return dependencies

    def parse_carthage(self, resolved_path: Path) -> List[Dependency]:
        """Parse Cartfile.resolved for dependencies."""
        dependencies = []

        if not resolved_path.exists():
            return dependencies

        print(f"[*] Parsing Carthage resolved file: {resolved_path}")

        try:
            with open(resolved_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse: github "Alamofire/Alamofire" "5.6.2"
                    match = re.match(r'github\s+"([^"]+)"\s+"([^"]+)"', line)
                    if match:
                        repo, version = match.groups()
                        name = repo.split("/")[-1]

                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version,
                                manager="carthage",
                                dep_type="library",
                                url=f"https://github.com/{repo}",
                            )
                        )

        except Exception as e:
            print(f"[!] Failed to parse Cartfile.resolved: {e}")

        return dependencies

    def detect_embedded_frameworks(self) -> List[Dependency]:
        """Detect embedded frameworks in the app."""
        frameworks = []

        if not self.app_bundle_path:
            return frameworks

        print("[*] Detecting embedded frameworks")

        frameworks_dir = self.app_bundle_path / "Frameworks"
        if not frameworks_dir.exists():
            return frameworks

        for framework_path in frameworks_dir.glob("*.framework"):
            name = framework_path.stem

            frameworks.append(
                Dependency(
                    name=name,
                    version="unknown",
                    manager="embedded",
                    dep_type="framework",
                    url=str(framework_path),
                )
            )

        print(f"[+] Found {len(frameworks)} embedded frameworks")

        return frameworks

    def detect_libraries(self) -> List[Dependency]:
        """Detect dynamic libraries in the app."""
        libraries = []

        if not self.app_bundle_path:
            return libraries

        print("[*] Detecting dynamic libraries")

        for lib_path in self.app_bundle_path.glob("*.dylib"):
            name = lib_path.stem

            libraries.append(
                Dependency(
                    name=name,
                    version="unknown",
                    manager="embedded",
                    dep_type="library",
                    url=str(lib_path),
                )
            )

        print(f"[+] Found {len(libraries)} dynamic libraries")

        return libraries

    def analyze_dependencies(self) -> List[Dependency]:
        """Analyze all dependencies from all sources."""
        all_deps = []

        # Parse package managers
        managers = self.detect_package_managers()

        for manager in managers:
            if manager == "cocoapods":
                lockfile = self._find_file("Podfile.lock")
                if lockfile:
                    all_deps.extend(self.parse_cocoapods(lockfile))

            elif manager == "spm":
                resolved = self._find_file("Package.resolved")
                if resolved:
                    all_deps.extend(self.parse_spm(resolved))

            elif manager == "carthage":
                resolved = self._find_file("Cartfile.resolved")
                if resolved:
                    all_deps.extend(self.parse_carthage(resolved))

        # Detect embedded frameworks and libraries
        all_deps.extend(self.detect_embedded_frameworks())
        all_deps.extend(self.detect_libraries())

        # Deduplicate by name
        seen = {}
        unique_deps = []
        for dep in all_deps:
            if dep.name not in seen:
                seen[dep.name] = dep
                unique_deps.append(dep)
            else:
                # Prefer versioned dependency over unknown
                if dep.version != "unknown" and seen[dep.name].version == "unknown":
                    seen[dep.name] = dep

        self.dependencies = unique_deps
        print(f"[+] Total dependencies: {len(self.dependencies)}")

        return self.dependencies

    def generate_purl(self, dep: Dependency) -> str:
        """Generate a Package URL (purl) for a dependency."""
        if dep.manager == "cocoapods":
            return f"pkg:cocoapods/{dep.name.lower()}@{dep.version}"
        elif dep.manager == "spm":
            return f"pkg:swift/{dep.name.lower()}@{dep.version}"
        elif dep.manager == "carthage":
            return f"pkg:github/{dep.url.split('github.com/')[-1].split('@')[0]}@{dep.version}"
        elif dep.manager == "embedded":
            return f"pkg:generic/{dep.name.lower()}?type={dep.type}"
        else:
            return f"pkg:generic/{dep.name.lower()}@{dep.version}"

    def generate_cyclonedx(self) -> Dict:
        """Generate CycloneDX format SBOM."""
        print("[*] Generating CycloneDX SBOM")

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "iOS-Pentesting-Skill",
                        "name": "SBOM Generator",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.app_name or "unknown",
                    "version": self.version or "unknown",
                    "purl": f"pkg:ios/{self.bundle_id or 'unknown'}@{self.version or 'unknown'}",
                },
            },
            "components": [],
        }

        for dep in self.dependencies:
            component = {
                "type": dep.type,
                "name": dep.name,
                "version": dep.version,
                "purl": self.generate_purl(dep),
                "description": f"{dep.manager} {dep.type}",
            }

            if dep.url and dep.manager != "embedded":
                component["externalReferences"] = [
                    {
                        "type": "website",
                        "url": dep.url,
                    }
                ]

            sbom["components"].append(component)

        return sbom

    def generate_spdx(self) -> Dict:
        """Generate SPDX format SBOM."""
        print("[*] Generating SPDX SBOM")

        doc_uuid = str(uuid.uuid4())

        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{self.app_name or 'unknown'}-{self.version or 'unknown'}",
            "documentNamespace": f"https://sbom.example.com/{doc_uuid}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": [
                    "Tool: iOS-Pentesting-Skill SBOM Generator-1.0.0",
                ],
            },
            "packages": [],
            "relationships": [],
        }

        # Add document descriptor
        sbom["documentDescribes"] = [f"SPDXRef-{self.app_name or 'app'}"]

        # Add root package
        sbom["packages"].append(
            {
                "SPDXID": f"SPDXRef-{self.app_name or 'app'}",
                "name": self.app_name or "unknown",
                "versionInfo": self.version or "unknown",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": "NOASSERTION",
                },
            }
        )

        # Add dependencies
        for i, dep in enumerate(self.dependencies):
            pkg = {
                "SPDXID": f"SPDXRef-{dep.name.replace('-', '_')}-{i}",
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": dep.url or "NOASSERTION",
                "filesAnalyzed": False,
            }

            if dep.license:
                pkg["licenseConcluded"] = dep.license

            sbom["packages"].append(pkg)

            # Add relationship
            sbom["relationships"].append(
                {
                    "spdxElementId": f"SPDXRef-{self.app_name or 'app'}",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": f"SPDXRef-{dep.name.replace('-', '_')}-{i}",
                }
            )

        return sbom

    def generate_json(self) -> Dict:
        """Generate custom JSON format."""
        print("[*] Generating custom JSON SBOM")

        sbom = {
            "metadata": {
                "appName": self.app_name,
                "bundleId": self.bundle_id,
                "version": self.version,
                "generatedAt": datetime.utcnow().isoformat() + "Z",
                "generator": "iOS-Pentesting-Skill SBOM Generator v1.0.0",
            },
            "summary": {
                "totalDependencies": len(self.dependencies),
                "byManager": {},
                "byType": {},
            },
            "dependencies": [dep.to_dict() for dep in self.dependencies],
        }

        # Summary stats
        for dep in self.dependencies:
            # By manager
            manager = dep.manager
            sbom["summary"]["byManager"][manager] = (
                sbom["summary"]["byManager"].get(manager, 0) + 1
            )

            # By type
            dep_type = dep.type
            sbom["summary"]["byType"][dep_type] = (
                sbom["summary"]["byType"].get(dep_type, 0) + 1
            )

        return sbom

    def save_sbom(self, sbom: Dict, output_path: str) -> None:
        """Save SBOM to file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(sbom, f, indent=2)

        print(f"[+] Saved SBOM to: {output_path}")

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.extracted_path and self.extracted_path.exists():
            try:
                shutil.rmtree(self.extracted_path)
                print(f"[*] Cleaned up: {self.extracted_path}")
            except Exception as e:
                print(f"[!] Failed to cleanup: {e}")

    def analyze(self) -> Dict:
        """Run full analysis."""
        self.validate_ipa()
        self.extract_ipa()
        self.find_app_bundle()
        self.parse_info_plist()
        self.analyze_dependencies()

        return {
            "appName": self.app_name,
            "bundleId": self.bundle_id,
            "version": self.version,
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "managers": self.detect_package_managers(),
        }


def main():
    """Main entry point."""

    parser = argparse.ArgumentParser(description="Generate SBOM from iOS IPA")
    parser.add_argument("--input", "-i", required=True, help="Path to IPA file")
    parser.add_argument(
        "--format", "-f", choices=["cyclonedx", "spdx", "json", "all"], default="json"
    )
    parser.add_argument(
        "--output", "-o", help="Output directory (default: same as input)"
    )
    parser.add_argument(
        "--analyze", "-a", action="store_true", help="Analyze only, don't generate SBOM"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="Don't cleanup extracted files"
    )

    args = parser.parse_args()

    generator = SBOMGenerator(args.input)

    try:
        if args.analyze:
            result = generator.analyze()
            print("\n" + "=" * 50)
            print("ANALYSIS RESULT")
            print("=" * 50)
            print(json.dumps(result, indent=2))
        else:
            generator.analyze()

            # Determine output directory
            if args.output:
                output_dir = Path(args.output)
            else:
                output_dir = Path(args.input).parent

            # Generate SBOM
            formats = (
                ["cyclonedx", "spdx", "json"] if args.format == "all" else [args.format]
            )

            for fmt in formats:
                if fmt == "cyclonedx":
                    sbom = generator.generate_cyclonedx()
                    output_file = (
                        output_dir / f"{generator.app_name}-sbom-cyclonedx.json"
                    )
                elif fmt == "spdx":
                    sbom = generator.generate_spdx()
                    output_file = output_dir / f"{generator.app_name}-sbom-spdx.json"
                else:
                    sbom = generator.generate_json()
                    output_file = output_dir / f"{generator.app_name}-sbom.json"

                generator.save_sbom(sbom, output_file)

        if not args.no_cleanup:
            generator.cleanup()

        return 0

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        if not args.no_cleanup:
            generator.cleanup()
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
