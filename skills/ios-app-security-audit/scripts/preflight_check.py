#!/usr/bin/env python3
"""
Universal iOS App Security Audit - Preflight Check Script

A cross-platform tool availability checker that works on Windows, macOS, and Linux.
Detects required tools for iOS app security analysis and provides installation
instructions based on the detected operating system.

Usage:
    python3 preflight_check.py           # Full report
    python3 preflight_check.py --json    # JSON output for scripts
    python3 preflight_check.py --quiet   # Only show missing tools
    python3 preflight_check.py --install # Show install commands only

Bash and PowerShell equivalents ship alongside this file:
    ./preflight-check.sh
    ./preflight-check.ps1

Exit codes:
    0 - All critical tools found
    1 - Critical tools missing
    2 - Error during check
"""

import subprocess
import sys
import os
import platform
import json
import re
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ---------------------------------------------------------------------------
# Version requirements — single source of truth: references/tool-versions.md
# ---------------------------------------------------------------------------

VERSION_SPEC_FILE = Path(__file__).resolve().parent.parent / "references" / "tool-versions.md"

# Rows in the "Core Analysis Tools" table that describe a HOST tool we can
# actually probe. frida-tools is a pip package (version visible only via
# `pip show`) and dsdump exposes no version interface, so neither is enforced.
_VERSION_ROW_KEYS = {
    "frida": "frida_core",      # `frida --version` reports the frida CORE version
    "objection": "objection",   # `objection version` subcommand
}


def load_version_requirements() -> Dict[str, Tuple[str, str]]:
    """Parse required tool versions from references/tool-versions.md.

    That file declares itself the single source of truth for tool versions, so
    the checker reads it instead of hard-coding a second copy of the numbers.
    Returns {key: (version, "exact"|"min")}. Empty dict if the file is absent
    or unparsable — version checking is advisory and must never break preflight.
    """
    reqs: Dict[str, Tuple[str, str]] = {}
    try:
        text = VERSION_SPEC_FILE.read_text(encoding="utf-8")
    except OSError:
        return reqs

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        label = cells[0].replace("*", "").replace("`", "").strip()
        version = cells[1].replace("`", "").strip()
        status = cells[2].strip().lower()

        if status not in ("exact", "minimum"):
            continue

        # "**frida** (core)" -> "frida"; "**Objection**" -> "objection"
        name = label.split("(")[0].strip().split()[0].lower() if label.split() else ""
        key = _VERSION_ROW_KEYS.get(name)
        if not key:
            continue

        # "0.13+" -> "0.13"
        version = version.rstrip("+").strip()
        if not re.match(r"^\d+(\.\d+)*$", version):
            continue

        reqs[key] = (version, "exact" if status == "exact" else "min")

    return reqs


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Parse '17.11.0' -> (17, 11, 0) for numeric comparison."""
    try:
        return tuple(int(p) for p in version.split("."))
    except (ValueError, AttributeError):
        return ()


def check_version(actual: str, required: str, mode: str) -> Optional[str]:
    """Compare an extracted version string against a requirement.

    Returns None when the version is acceptable or cannot be compared,
    otherwise a human-readable reason describing the mismatch.
    """
    if not actual or not required:
        return None

    found = re.search(r"(\d+(?:\.\d+)*)", actual)
    if not found:
        return None

    a = _version_tuple(found.group(1))
    b = _version_tuple(required)
    if not a or not b:
        return None

    # Pad to equal length so 17.11 == 17.11.0
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))

    if mode == "exact":
        if a != b:
            return f"version {found.group(1)} != required {required} (exact match required)"
    else:  # min
        if a < b:
            return f"version {found.group(1)} is older than required minimum {required}"

    return None



# Platform-specific tool alternatives (macOS -> Linux substitutions)
TOOL_ALTERNATIVES = {
    "plutil": {
        "alternative": "plistutil",
        "install_command": "sudo apt install libplist-utils",
        "functionality": "plist convert/inspect",
        "limitations": "None - full compatibility",
    },
    "otool": {
        "alternative": "llvm-objdump",
        "install_command": "sudo apt install llvm",
        "functionality": "Mach-O analysis, load commands",
        "limitations": "Syntax differs, see linux-ios-analysis-workarounds.md",
    },
    "lipo": {
        "alternative": "llvm-lipo",
        "install_command": "sudo apt install llvm (version 12+)",
        "functionality": "Fat binary operations",
        "limitations": "None - full compatibility",
    },
    "codesign": {
        "alternative": "ldid",
        "install_command": "sudo apt install ldid",
        "functionality": "Code signing for jailbroken devices",
        "limitations": "ONLY for jailbroken devices, NOT for stock devices",
    },
    "security": {
        "alternative": "None - use device-based extraction",
        "install_command": "N/A",
        "functionality": "Keychain operations",
        "limitations": "Linux keychain different, see linux-ios-analysis-workarounds.md",
    },
    "jtool2": {
        "alternative": "llvm-objdump",
        "install_command": "sudo apt install llvm",
        "functionality": "Mach-O analysis",
        "limitations": "jtool2 is macOS-only, llvm-objdump has subset of features",
    },
    "dsdump": {
        "alternative": "Frida runtime dump",
        "install_command": "pip3 install frida-tools",
        "functionality": "Swift class introspection",
        "limitations": "dsdump has no Linux build, use Frida for runtime analysis",
    },
    "class-dump": {
        "alternative": "Frida runtime dump",
        "install_command": "pip3 install frida-tools",
        "functionality": "Objective-C class introspection",
        "limitations": "class-dump is macOS-only, use Frida or jtool2 equivalents",
    },
}


class ToolInfo:
    """Tool definition with metadata."""

    def __init__(
        self,
        name: str,
        description: str,
        critical: bool = False,
        version_flag: str = "--version",
        version_pattern: str = None,
        platform_specific: str = None,  # "macos", "linux", or None for universal
        version_checkable: bool = True,  # False when the tool has no version flag
    ):
        self.name = name
        self.description = description
        self.critical = critical
        self.version_flag = version_flag
        self.version_pattern = version_pattern
        self.platform_specific = platform_specific  # New field
        self.version_checkable = version_checkable
        self.found = False
        self.version = None


class SystemInfo:
    """System detection results."""

    def __init__(self):
        self.os = self._detect_os()
        self.arch = self._detect_arch()
        self.distro = self._detect_distro()
        self.wsl = self._detect_wsl()

    def _detect_os(self) -> str:
        """Detect operating system."""
        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        return system

    def _detect_arch(self) -> str:
        """Detect system architecture."""
        machine = platform.machine().lower()
        if machine in ("amd64", "x86_64"):
            return "x86_64"
        elif machine in ("arm64", "aarch64"):
            return "arm64"
        elif machine in ("i386", "i686"):
            return "x86"
        return machine

    def _detect_wsl(self) -> bool:
        """Detect if running in Windows Subsystem for Linux."""
        try:
            with open("/proc/version", "r") as f:
                return "microsoft" in f.read().lower()
        except (IOError, OSError):
            return False

    def _detect_distro(self) -> Optional[str]:
        """Detect Linux distribution."""
        if self.os != "linux":
            return None

        # Check /etc/os-release first
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro_id = line.strip().split("=", 1)[1].strip("\"'")
                        # Map to package manager
                        if distro_id in ("ubuntu", "debian", "linuxmint"):
                            return "debian"
                        elif distro_id in ("arch", "manjaro"):
                            return "arch"
                        elif distro_id in ("fedora", "rhel", "centos"):
                            return "fedora"
        except (IOError, OSError):
            pass

        # Fallback: check for package manager
        for cmd, distro in [
            ("apt-get", "debian"),
            ("pacman", "arch"),
            ("dnf", "fedora"),
            ("yum", "fedora"),
        ]:
            # shutil.which, not self._command_exists(): that helper belongs
            # to the checker, and SystemInfo is built before it exists. On a
            # Linux host whose /etc/os-release is not recognised this code
            # raised AttributeError and aborted the whole preflight.
            if shutil.which(cmd):
                return distro

        return "unknown"


class PreflightChecker:
    """Main preflight check engine."""

    def __init__(self):
        self.system = SystemInfo()
        self.results: List[Dict] = []
        self.xcode_info: Dict = {}
        # Advisory version requirements, loaded from references/tool-versions.md
        self.version_requirements: Dict[str, Tuple[str, str]] = load_version_requirements()
        self.version_issues: List[Tuple[str, str]] = []

        # Define all tools to check
        self.tools = [
            # Critical tools
            ToolInfo(
                "frida",
                "Dynamic instrumentation",
                critical=True,
                version_flag="--version",
                version_pattern="Frida",
            ),
            ToolInfo(
                "plutil",
                "Property list utility (macOS)",
                critical=True,
                version_flag="-version",
                version_pattern="plutil",
                platform_specific="macos",
            ),
            ToolInfo(
                "otool",
                "Object file display tool (macOS)",
                critical=True,
                version_flag="-v",
                version_pattern="otool",
                platform_specific="macos",
            ),
            # Important tools
            ToolInfo(
                "grep",
                "Text search",
                critical=True,
                version_flag="--version",
                version_pattern="grep",
            ),
            ToolInfo(
                "rg",
                "Ripgrep (faster)",
                critical=False,
                version_flag="--version",
                version_pattern="ripgrep",
            ),
            # Optional tools
            ToolInfo(
                "objection",
                "Runtime exploration",
                critical=False,
                version_flag="version",
                version_pattern="objection",
            ),
            ToolInfo(
                "dsdump",
                "Class dump utility",
                critical=False,
                version_flag="--version",
                version_pattern="dsdump",
                platform_specific="macos",
                # dsdump exposes no version flag; its version is only visible via
                # `pip show dsdump`, so version detection is skipped for it.
                version_checkable=False,
            ),
            ToolInfo(
                "jtool2",
                "Advanced Mach-O analysis",
                critical=False,
                version_flag="-v",
                version_pattern="jtool",
                platform_specific="macos",
            ),
            ToolInfo(
                "ipatool",
                "Download IPAs from the App Store",
                critical=False,
                version_flag="--version",
                version_pattern=r"^ipatool version",
            ),
            ToolInfo(
                "codesign",
                "Code signing (macOS)",
                critical=False,
                version_flag="-v",
                version_pattern="codesign",
                platform_specific="macos",
            ),
            ToolInfo(
                "security",
                "Keychain/Security (macOS)",
                critical=False,
                version_flag="-v",
                version_pattern="security",
                platform_specific="macos",
            ),
            ToolInfo(
                "lipo",
                "Universal binary tool (macOS)",
                critical=False,
                version_flag="-v",
                version_pattern="lipo",
                platform_specific="macos",
            ),
            ToolInfo(
                "nm",
                "Symbol table tool",
                critical=False,
                version_flag="",
                version_pattern=None,
            ),
            ToolInfo(
                "strings",
                "Extract strings",
                critical=False,
                version_flag="",
                version_pattern=None,
            ),
            ToolInfo(
                "python3",
                "Python 3",
                critical=False,
                version_flag="--version",
                version_pattern="Python",
            ),
            ToolInfo(
                "mobsf",
                "Mobile Security Framework",
                critical=False,
                version_flag="--version",
                version_pattern="MobSF",
            ),
            ToolInfo(
                "ideviceinfo",
                "libimobiledevice device info (UDID, iOS version)",
                critical=True,
                version_flag="-v",
                version_pattern="ideviceinfo",
            ),
            ToolInfo(
                "idevicepair",
                "libimobiledevice device pairing",
                critical=True,
                version_flag="-v",
                version_pattern="idevicepair",
            ),
            ToolInfo(
                "ideviceinstaller",
                "Install/uninstall IPA files",
                critical=False,
                version_flag="-v",
                version_pattern="ideviceinstaller",
            ),
            ToolInfo(
                "idevicesyslog",
                "Device syslog relay",
                critical=False,
                version_flag="-v",
                version_pattern="idevicesyslog",
            ),
            ToolInfo(
                "afcclient",
                "AFC filesystem access (per-app)",
                critical=False,
                version_flag="-v",
                version_pattern="afcclient",
            ),
        ]

    def _command_exists(self, cmd: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            devnull = open(os.devnull, "w")
            result = subprocess.call(
                ["which", cmd] if self.system.os != "windows" else ["where", cmd],
                stdout=devnull,
                stderr=devnull,
            )
            devnull.close()
            return result == 0
        except OSError:
            return False

    def _get_version(self, tool: ToolInfo) -> Optional[str]:
        """Extract version from tool output."""
        if not tool.version_checkable:
            return None
        try:
            result = subprocess.run(
                [tool.name, tool.version_flag],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # Some tools (e.g. objection) exit non-zero while still printing a
            # usable version, so do not bail out on the return code alone.
            combined = result.stdout + result.stderr
            if not combined.strip():
                return None

            # A tool that rejects the version flag (plutil, otool on some
            # toolchains) prints its usage text on stderr. Those lines mention
            # "version" but are not a version, so they must never be reported
            # as one.
            def is_error_line(line: str) -> bool:
                return bool(
                    re.search(
                        r"(unrecognized option|illegal option|invalid option|"
                        r"error:|usage:|no such file|command not found|"
                        r"must be specified)",
                        line,
                        re.IGNORECASE,
                    )
                )

            # Extract version from output
            if tool.name == "frida":
                # `frida --version` prints the bare core version, e.g. "17.11.0"
                for line in combined.splitlines():
                    line = line.strip()
                    if not line or is_error_line(line):
                        continue
                    version_match = re.search(r"(\d+\.\d+[\.\d]*)", line)
                    if version_match:
                        return version_match.group(1)
                    if "frida" in line.lower():
                        return line
                return None

            elif tool.name == "grep":
                for line in result.stdout.splitlines():
                    if is_error_line(line):
                        continue
                    if "grep" in line.lower() or "bsd" in line.lower():
                        version_match = re.search(r"(\d+\.\d+[\.\d]*)", line)
                        if version_match:
                            return version_match.group(1)
                        return line.strip()
                return None

            elif tool.name == "rg":
                for line in result.stdout.splitlines():
                    if "ripgrep" in line.lower():
                        return line.strip()
                return None

            else:
                # Generic extraction - first line containing a version number
                for line in combined.splitlines():
                    line = line.strip()
                    if not line or is_error_line(line):
                        continue
                    line_lower = line.lower()
                    if (
                        tool.version_pattern
                        and tool.version_pattern.lower() in line_lower
                    ):
                        version_match = re.search(r"(\d+\.\d+[\.\d]*)", line)
                        if version_match:
                            return version_match.group(1)
                        return line
                    if "version" in line_lower:
                        version_match = re.search(r"(\d+\.\d+[\.\d]*)", line)
                        if version_match:
                            return version_match.group(1)
                        return line

        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        return None

    def check_tool(self, tool: ToolInfo) -> Dict:
        """Check if a tool is available and get its version."""
        not_applicable = not self._tool_applies(tool)
        if not_applicable:
            # Not applicable on this platform: neither present nor missing.
            tool.found = False
            tool.version = f"N/A ({tool.platform_specific} only)"
        elif not self._command_exists(tool.name):
            tool.found = False
            tool.version = "MISSING"
        else:
            tool.found = True
            version = self._get_version(tool)
            # A version string always looks like "12.3" / "12.3.4". Anything
            # else is usage text that leaked out of the probe (e.g. otool's
            # help mentions "otool(1)" but is not a version).
            if version and not re.search(r"\d+\.\d+", version):
                version = None
            tool.version = version if version else "FOUND (no version)"

        result = {
            "name": tool.name,
            "description": tool.description,
            "critical": tool.critical,
            "found": tool.found,
            "version": tool.version,
            "version_issue": None,
            "not_applicable": not_applicable,
        }

        # Advisory version validation (see references/tool-versions.md).
        # Never blocks the run — it only surfaces a mismatch.
        key = {"frida": "frida_core", "objection": "objection"}.get(tool.name)
        req = self.version_requirements.get(key) if key else None
        if req and tool.found:
            required, mode = req
            issue = check_version(tool.version or "", required, mode)
            if issue:
                result["version_issue"] = issue
                result["required_version"] = required
                self.version_issues.append((tool.name, issue))

        self.results.append(result)
        return result

    def check_all_tools(self) -> None:
        """Check all defined tools."""
        for tool in self.tools:
            self.check_tool(tool)

    def _tool_applies(self, tool: ToolInfo) -> bool:
        """False when the tool belongs to another platform.

        A macOS-only tool such as `plutil` is not "missing" on Linux: it does
        not apply. Counting it as missing made the preflight fail on every
        Linux host and reported a toolchain problem where there is none.
        """
        if not tool.platform_specific:
            return True
        return tool.platform_specific == self.system.os

    def check_xcode(self) -> Dict:
        """Check Xcode CLI tools installation on macOS."""
        xcode_info = {
            "xcode_cli_found": False,
            "xcode_path": None,
            "developer_tools_found": False,
        }

        if self.system.os != "macos":
            return xcode_info

        try:
            # Check xcode-select path
            result = subprocess.run(
                ["xcode-select", "-p"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                xcode_info["xcode_cli_found"] = True
                xcode_info["xcode_path"] = result.stdout.strip()

            # Check for developer tools
            dev_tools_path = "/Library/Developer/CommandLineTools"
            xcode_info["developer_tools_found"] = os.path.exists(dev_tools_path)

        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        self.xcode_info = xcode_info
        return xcode_info

    def get_install_commands(self) -> Dict[str, List[str]]:
        """Get install commands for missing tools by OS."""
        commands = {}

        # Find missing tools
        missing_tools = [
            r["name"]
            for r in self.results
            if not r["found"] and not r.get("not_applicable")
        ]

        # Map tools to package names per OS
        package_map = {
            "macos": {
                "frida": "frida-tools (pip3)",
                "objection": "objection (pip3)",
                "dsdump": "dsdump (pip3)",
                "mobsf": "Mobile-Security-Framework-MobSF (git/pip3)",
                "jtool2": "jtool2 (manual download from https://newosxbook.com/tools/jtool.html)",
                "ipatool": "ipatool (brew)",
                "python3": "python@3",
                "ideviceinfo": "libimobiledevice",
                "idevicepair": "libimobiledevice",
                "idevicesyslog": "libimobiledevice",
                "afcclient": "libimobiledevice",
                "ideviceinstaller": "ideviceinstaller",
            },
            "cask": {
                "jtool2": "jtool2",
            },
            "debian": {
                "frida": "frida-tools (pip3)",
                "objection": "objection (pip3)",
                "dsdump": "dsdump (pip3)",
                "mobsf": "Mobile-Security-Framework-MobSF (git/pip3)",
                "ipatool": "ipatool (download binary from https://github.com/majd/ipatool/releases)",
                "python3": "python3",
                "ideviceinfo": "libimobiledevice-utils",
                "idevicepair": "libimobiledevice-utils",
                "idevicesyslog": "libimobiledevice-utils",
                "afcclient": "libimobiledevice-utils",
                "ideviceinstaller": "ideviceinstaller",
            },
            "arch": {
                "frida": "frida-tools (pip3)",
                "objection": "objection (pip3)",
                "dsdump": "dsdump (pip3)",
                "mobsf": "Mobile-Security-Framework-MobSF (git/pip3)",
                "ipatool": "ipatool (download binary from https://github.com/majd/ipatool/releases)",
                "python3": "python",
                "ideviceinfo": "libimobiledevice",
                "idevicepair": "libimobiledevice",
                "idevicesyslog": "libimobiledevice",
                "afcclient": "libimobiledevice",
                "ideviceinstaller": "ideviceinstaller",
            },
            "fedora": {
                "frida": "frida-tools (pip3)",
                "objection": "objection (pip3)",
                "dsdump": "dsdump (pip3)",
                "mobsf": "Mobile-Security-Framework-MobSF (git/pip3)",
                "ipatool": "ipatool (download binary from https://github.com/majd/ipatool/releases)",
                "python3": "python3",
                "ideviceinfo": "libimobiledevice",
                "idevicepair": "libimobiledevice",
                "idevicesyslog": "libimobiledevice",
                "afcclient": "libimobiledevice",
                "ideviceinstaller": "ideviceinstaller",
            },
            "windows": {
                "frida": "frida-tools (pip3)",
                "objection": "objection (pip3)",
                "mobsf": "Mobile-Security-Framework-MobSF (git/pip3)",
                "ipatool": "ipatool (download binary from https://github.com/majd/ipatool/releases)",
                "python3": "python",
                "ideviceinfo": "wsl + Ubuntu then follow Debian",
                "idevicepair": "wsl + Ubuntu then follow Debian",
                "idevicesyslog": "wsl + Ubuntu then follow Debian",
                "afcclient": "wsl + Ubuntu then follow Debian",
                "ideviceinstaller": "wsl + Ubuntu then follow Debian",
            },
        }

        # Python tools

        # Build commands
        if self.system.os == "macos":
            commands["brew"] = []
            commands["brew-cask"] = []
            commands["pip"] = []
            for tool in missing_tools:
                if tool in package_map["macos"]:
                    pkg = package_map["macos"][tool]
                    if "(pip3)" in pkg:
                        pip_pkg = pkg.replace(" (pip3)", "")
                        if pip_pkg not in commands["pip"]:
                            commands["pip"].append(pip_pkg)
                    elif "(cask)" in pkg:
                        cask_pkg = pkg.replace(" (cask)", "")
                        if cask_pkg not in commands["brew-cask"]:
                            commands["brew-cask"].append(cask_pkg)
                    elif "(brew)" in pkg:
                        brew_pkg = pkg.replace(" (brew)", "")
                        if brew_pkg not in commands["brew"]:
                            commands["brew"].append(brew_pkg)
                    elif pkg not in commands["brew"]:
                        commands["brew"].append(pkg)

        elif self.system.os == "linux":
            distro = self.system.distro or "debian"

            if distro == "debian":
                commands["apt"] = []
                commands["pip"] = []
                commands["manual"] = []
                for tool in missing_tools:
                    if tool in package_map["debian"]:
                        pkg = package_map["debian"][tool]
                        if "(pip3)" in pkg:
                            pip_pkg = pkg.replace(" (pip3)", "")
                            if pip_pkg not in commands["pip"]:
                                commands["pip"].append(pip_pkg)
                        elif "download binary" in pkg:
                            if pkg not in commands["manual"]:
                                commands["manual"].append(pkg)
                        elif pkg not in commands["apt"]:
                            commands["apt"].append(pkg)

            elif distro == "arch":
                commands["pacman"] = []
                commands["pip"] = []
                commands["manual"] = []
                for tool in missing_tools:
                    if tool in package_map["arch"]:
                        pkg = package_map["arch"][tool]
                        if "(pip3)" in pkg:
                            pip_pkg = pkg.replace(" (pip3)", "")
                            if pip_pkg not in commands["pip"]:
                                commands["pip"].append(pip_pkg)
                        elif "download binary" in pkg:
                            if pkg not in commands["manual"]:
                                commands["manual"].append(pkg)
                        elif pkg not in commands["pacman"]:
                            commands["pacman"].append(pkg)

            elif distro == "fedora":
                commands["dnf"] = []
                commands["pip"] = []
                commands["manual"] = []
                for tool in missing_tools:
                    if tool in package_map["fedora"]:
                        pkg = package_map["fedora"][tool]
                        if "(pip3)" in pkg:
                            pip_pkg = pkg.replace(" (pip3)", "")
                            if pip_pkg not in commands["pip"]:
                                commands["pip"].append(pip_pkg)
                        elif "download binary" in pkg:
                            if pkg not in commands["manual"]:
                                commands["manual"].append(pkg)
                        elif pkg not in commands["dnf"]:
                            commands["dnf"].append(pkg)

        elif self.system.os == "windows":
            commands["choco"] = []
            commands["scoop"] = []
            commands["pip"] = []
            commands["manual"] = []
            for tool in missing_tools:
                if tool in package_map["windows"]:
                    pkg = package_map["windows"][tool]
                    if "(pip3)" in pkg:
                        pip_pkg = pkg.replace(" (pip3)", "")
                        if pip_pkg not in commands["pip"]:
                            commands["pip"].append(pip_pkg)
                    elif "download binary" in pkg:
                        if pkg not in commands["manual"]:
                            commands["manual"].append(pkg)
                    elif pkg not in commands["choco"]:
                        commands["choco"].append(pkg)
                        commands["scoop"].append(pkg)

        return commands

    def print_output(
        self, json_mode: bool = False, quiet: bool = False, install_only: bool = False
    ) -> None:
        """Print formatted output."""
        if json_mode:
            self._print_json()
        elif install_only:
            self._print_install_only()
        elif quiet:
            self._print_quiet()
        else:
            self._print_full()

    def _print_full(self) -> None:
        """Print full report."""
        os_label = f"{self.system.os}"
        if self.system.os == "linux" and self.system.distro:
            os_label += f" ({self.system.distro})"
        if self.system.wsl:
            os_label += " [WSL]"
        os_label += f" {self.system.arch}"

        print("\n" + "=" * 40)
        print("  iOS App Security Audit - Preflight Check")
        print(f"  OS: {os_label}")
        print("=" * 40 + "\n")

        # Print tool results
        for result in self.results:
            status = "✅" if result["found"] else "❌"
            version = result["version"] if result["found"] else "MISSING"
            critical_marker = " [CRITICAL]" if result["critical"] else ""

            print(
                f"[{status}] {result['name']:<12} {version:<15} - {result['description']}{critical_marker}"
            )

            # Show Linux alternatives for macOS-only tools
            if (
                not result["found"]
                and self.system.os == "linux"
                and result["name"] in TOOL_ALTERNATIVES
            ):
                alt = TOOL_ALTERNATIVES[result["name"]]
                print(f"   └─→ Linux alternative: {alt['alternative']}")
                if alt["install_command"] != "N/A":
                    print(f"      Install: {alt['install_command']}")
                print(f"      Functionality: {alt['functionality']}")
                print(f"      Limitations: {alt['limitations']}")

        # Version mismatches (advisory — see references/tool-versions.md)
        if self.version_issues:
            print("\n" + "-" * 40)
            print("Version warnings:")
            for name, issue in self.version_issues:
                print(f"  ⚠️  {name}: {issue}")
            print("  → See references/tool-versions.md for required versions")

        # Xcode CLI tools (macOS only)
        if self.system.os == "macos":
            print("\n" + "-" * 40)
            print("Xcode Command Line Tools:")
            if self.xcode_info["xcode_cli_found"]:
                print(f"  ✅ Xcode CLI found at: {self.xcode_info['xcode_path']}")
            else:
                print("  ❌ Xcode CLI NOT FOUND - run: xcode-select --install")
            if self.xcode_info["developer_tools_found"]:
                print("  ✅ Developer Tools installed")
            else:
                print("  ⚠️  Developer Tools may not be installed")

        # Summary
        applicable = [r for r in self.results if not r.get("not_applicable")]
        total = len(applicable)
        found = sum(1 for r in applicable if r["found"])
        missing = total - found

        print("\n" + "-" * 40)
        print(f"  SUMMARY: {found}/{total} tools found")
        if missing > 0:
            missing_names = ", ".join(
                [r["name"] for r in self.results if not r["found"]]
            )
            print(f"  Missing: {missing_names}")
        print("-" * 40 + "\n")

        # Install commands
        if missing > 0:
            self._print_install_section()

    def _print_quiet(self) -> None:
        """Print only missing tools."""
        for result in self.results:
            if not result["found"]:
                critical_marker = " [CRITICAL]" if result["critical"] else ""
                print(
                    f"❌ {result['name']:<12} - {result['description']}{critical_marker}"
                )

                # Show Linux alternatives for macOS-only tools
                if (
                    self.system.os == "linux"
                    and result["name"] in TOOL_ALTERNATIVES
                ):
                    alt = TOOL_ALTERNATIVES[result["name"]]
                    print(f"   └─→ Linux alternative: {alt['alternative']}")
                    if alt["install_command"] != "N/A":
                        print(f"      Install: {alt['install_command']}")
                    print(f"      Limitations: {alt['limitations']}")

        if self.system.os == "macos" and not self.xcode_info["xcode_cli_found"]:
            print("❌ Xcode CLI tools")

        for name, issue in self.version_issues:
            print(f"⚠️  {name}: {issue}")

    def _print_install_only(self) -> None:
        """Print only install commands."""
        self._print_install_section()

    def _print_install_section(self) -> None:
        """Print installation commands."""
        commands = self.get_install_commands()

        # Install tools
        for manager, packages in commands.items():
            if packages:
                if manager == "brew":
                    print("\nInstall tools (macOS):")
                    print(f"  brew install {' '.join(packages)}")
                elif manager == "brew-cask":
                    print("\nInstall tools (macOS - Cask):")
                    print(f"  brew install --cask {' '.join(packages)}")
                elif manager == "apt":
                    print("\nInstall tools (Debian/Ubuntu):")
                    print(f"  sudo apt update && sudo apt install {' '.join(packages)}")
                elif manager == "pacman":
                    print("\nInstall tools (Arch/Manjaro):")
                    print(f"  sudo pacman -S {' '.join(packages)}")
                elif manager == "dnf":
                    print("\nInstall tools (Fedora/RHEL):")
                    print(f"  sudo dnf install {' '.join(packages)}")
                elif manager == "choco":
                    print("\nInstall tools (Windows - Chocolatey):")
                    print(f"  choco install {' '.join(packages)}")
                elif manager == "scoop":
                    print("\nInstall tools (Windows - Scoop):")
                    print(f"  scoop install {' '.join(packages)}")
                elif manager == "pip":
                    print("\nInstall Python tools:")
                    for pkg in packages:
                        if pkg.startswith("Mobile-Security-Framework-MobSF"):
                            print(
                                "  # Install MobSF (optional): ./scripts/install-mobsf-local.sh"
                            )
                            print(
                                "  # Or use Docker (recommended): ./scripts/install-mobsf-docker.sh"
                            )
                        else:
                            print(f"  pip install {pkg}")

        # Xcode CLI (macOS)
        if self.system.os == "macos" and not self.xcode_info["xcode_cli_found"]:
            print("\nInstall Xcode Command Line Tools (macOS):")
            print("  xcode-select --install")

        print("\nNOTE: Most iOS pentesting tools require macOS for full functionality.")

    def _print_json(self) -> None:
        """Print JSON output."""
        output = {
            "system": {
                "os": self.system.os,
                "arch": self.system.arch,
                "distro": self.system.distro,
                "wsl": self.system.wsl,
            },
            "tools": self.results,
            "xcode_cli": self.xcode_info,
            "version_requirements": {
                key: {"version": ver, "match": mode}
                for key, (ver, mode) in self.version_requirements.items()
            },
            "version_issues": [
                {"tool": name, "issue": issue} for name, issue in self.version_issues
            ],
            "summary": {
                "total": len([r for r in self.results if not r.get("not_applicable")]),
                "found": sum(
                    1 for r in self.results if r["found"] and not r.get("not_applicable")
                ),
                "missing": sum(
                    1
                    for r in self.results
                    if not r["found"] and not r.get("not_applicable")
                ),
                "not_applicable": sum(
                    1 for r in self.results if r.get("not_applicable")
                ),
                "missing_critical": self._missing_critical(),
            },
        }
        print(json.dumps(output, indent=2))

    def _missing_critical(self) -> List[str]:
        """Critical tools that apply here and are not installed.

        A critical tool that belongs to another platform (`plutil` and `otool`
        are macOS-only) does not apply on Linux: it must not be reported as
        missing. The JSON report and the exit code are built from this single
        source so they can never disagree about the verdict.
        """
        return [
            r["name"]
            for r in self.results
            if not r["found"] and r["critical"] and not r.get("not_applicable")
        ]

    def get_exit_code(self) -> int:
        """Calculate exit code based on results."""
        missing_critical = self._missing_critical()
        if self.system.os == "macos" and not self.xcode_info["xcode_cli_found"]:
            return 1
        if missing_critical:
            return 1
        return 0


def main():
    """Main entry point."""
    try:
        # Parse arguments
        args = sys.argv[1:]
        json_mode = "--json" in args
        quiet_mode = "--quiet" in args
        install_only = "--install" in args

        # Validate flags
        if len(args) > 3:
            print(
                "Usage: preflight_check.py [--json|--quiet|--install]", file=sys.stderr
            )
            return 2

        # Run checks
        checker = PreflightChecker()
        checker.check_all_tools()
        if checker.system.os == "macos":
            checker.check_xcode()

        # Print output
        checker.print_output(
            json_mode=json_mode, quiet=quiet_mode, install_only=install_only
        )

        # Exit
        return checker.get_exit_code()

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error during preflight check: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
