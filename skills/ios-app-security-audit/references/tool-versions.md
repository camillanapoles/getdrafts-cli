# Tool Versions Reference

Centralized version requirements for iOS security auditing tools. **This is the single source of truth** for tool versions referenced across the iOS-Pentesting-Skill.

## Version Policy

- **Exact versions** specified when critical (e.g., Frida for compatibility)
- **Minimum versions** specified when features depend on them
- **Latest stable** recommended unless otherwise noted

---

## Core Analysis Tools

| Tool | Version | Status | Notes |
|------|---------|--------|-------|
| **frida** (core) | 17.11.0 | Exact | Python core package; pulled in by `frida-tools`. `frida-server` on device MUST match this exact version |
| **frida-server** | 17.11.0 | Exact | Installed on device; must equal the host `frida` core version (`frida --version`) |
| **frida-tools** | 14.9.0 | Exact | CLI (`frida`, `frida-ps`, `frida-trace`); has its OWN version line — `pip3 install frida-tools` pulls the matching `frida` core |
| **Objection** | 1.12.4 | Minimum | In maintenance mode, use compatible version |
| **dsdump** | 0.13+ | Minimum | Swift class dump for modern iOS binaries. Upstream project is archived (Dec 2025) — the maintained fork is `dsdump_b2`; install with `pip3 install dsdump` |
| **class-dump** | latest | Optional | Objective-C class dump for legacy apps |

## Lint and CI Tooling

| Tool | Version | Status | Notes |
|------|---------|--------|-------|
| **ruff** | 0.17.1 | Exact | Linter for `scripts/`. Pinned in `.github/workflows/ci.yml` because ruff changed its **default** rule set between 0.15 (59 rules) and 0.17 (407 rules): an unpinned CI silently changed what it checked on every release. The rule set the project actually enforces is declared in `ruff.toml` (`E4`, `E7`, `E9`, `F`) |
| **shellcheck** | 0.11.0 | Exact | Shell linter; `shellcheck -S warning scripts/*.sh` must stay at 0 warnings |
| **node** | 20+ | Minimum | Only used to syntax-check the Frida scripts (`node --check`) |

## Python Dependencies

The scripts in `scripts/` need two third-party packages. Everything else runs on the standard library alone.

| Package | Version | Status | Needed by |
|------|---------|--------|-----------|
| **requests** | 2.32.5 | Exact | The MobSF integration (`mobsf_upload.py`, `mobsf_detect.py`, `mobsf_client.py`) |
| **lief** | 0.17.6 | Exact | The SimForge Mach-O scripts (`simforge_cleanup.py`, `simforge_apply.py`, `simforge_preflight.py`) |

Install both with:

```bash
pip3 install -r requirements.txt
```

A missing dependency is reported with an actionable message instead of a traceback: the affected script prints what to install and exits 1.

## System Tools (macOS)

| Tool | Version | Notes |
|------|---------|-------|
| **plutil** | System (preinstalled) | plist manipulation |
| **codesign** | System (preinstalled) | code signing |
| **security** | System (preinstalled) | keychain access |
| **lipo** | System (preinstalled) | fat binary manipulation |
| **nm** | System (preinstalled) | symbol extraction |
| **strings** | System (preinstalled) | string extraction |
| **otool** | System (preinstalled) | Mach-O analysis |
| **xcrun** | System (preinstalled) | Xcode developer tools |

## Optional Tools

| Tool | Version | Notes |
|------|---------|-------|
| **jtool2** | latest | Advanced Mach-O analysis |
| **SimForge** | latest | Apple Silicon only, no version pinning |
| **ipatool** | latest | App Store IPA download |
| **python3** | 3.10+ | Minimum for all Python scripts |
| **pymobiledevice3** | latest | Container extraction, device management (see libimobiledevice-guide.md) |
| **bagbak** | latest | Jailbreak-only dumper (see tool-installation-ios.md) |

## libimobiledevice Tools

| Tool | Version | Notes |
|------|---------|-------|
| **ideviceinstaller** | latest | IPA installation to device |
| **idevicesyslog** | latest | Device log streaming |
| **ideviceinfo** | latest | Device information |
| **idevicepair** | latest | Device pairing |
| **ideviceimagemounter** | latest | Image mounting |
| **afcclient** | latest | Filesystem access (interactive only) |
| **idevicecrashreport** | latest | Crash report retrieval |
| **ideviceprovision** | latest | Provisioning profile management |

## Frida Scripts Maturity

| Script | Maturity | Notes |
|--------|----------|-------|
| **ssl-pinning-bypass-ios.js** | STABLE | Production-ready |
| **jailbreak-detection-bypass.js** | STABLE | Production-ready |
| **biometric-bypass-ios.js** | STABLE | Production-ready |
| **network-interceptor-ios.js** | STABLE | Production-ready |
| **flutter-ssl-pinning-ios.js** | STABLE | Flutter-specific |
| **Others** | Various | See `references/frida-scripts-index.md` |

---

## Version Compatibility Notes

### Frida Version Matching

**Critical**: the `frida-server` on the device MUST match the host `frida` core version (`frida --version`) exactly. Note that `frida-tools` carries a different version number than the `frida` core — install the CLI with `pip3 install frida-tools` and it pulls the matching core.

**Check versions**:
```bash
# On host
frida --version

# On device (via SSH)
frida-server --version
```

**Mismatch symptoms**: Protocol mismatch, script load failures, attachment errors.

**Fix**:
```bash
# Reinstall matching versions (pulls frida core 17.11.0)
pip3 install "frida-tools==14.9.0"

# Reinstall frida-server on device
# See references/frida-server-ios-install.md
```

### iOS Version Compatibility

| iOS Version | Jailbreak | Frida | SimForge |
|-------------|-----------|-------|----------|
| **iOS 15.x** | checkra1n, unc0ver | ✅ | ✅ (SimRuntime 15.x) |
| **iOS 16.x** | checkra1n, palera1n | ✅ | ✅ (SimRuntime 16.x) |
| **iOS 17.x** | palera1n, Dopamine | ✅ | ✅ (SimRuntime 17.x - most permissive) |
| **iOS 18.x** | Dopamine (limited) | ⚠️ | ⚠️ (SimRuntime 18.x - stricter) |

**SimForge compatibility matrix**: See `references/simforge-compatibility.md`

**Jailbreak coverage**: See `references/jailbreak-setup-guide.md`

---

## Installation Quick Reference

### macOS
```bash
# Core tools
brew install ripgrep  # rg
pip install "frida-tools==14.9.0" objection dsdump

# Optional
# jtool2: NOT in Homebrew. Download manually from https://newosxbook.com/tools/jtool.html
brew install ipatool
git clone https://github.com/EthanArbuckle/simforge.git && cd simforge && xcodebuild -project simforge.xcodeproj -scheme simforge -configuration Release
# copy the resulting simforge binary to /usr/local/bin/
```

### Linux (Debian/Ubuntu)
```bash
# Core tools
sudo apt install ripgrep python3-pip
pip3 install "frida-tools==14.9.0" objection

# libimobiledevice
sudo apt install libimobiledevice-utils ideviceinstaller
```

### Verification
```bash
# Run preflight check
python3 scripts/preflight_check.py

# Or bash version
./scripts/preflight-check.sh
```

See `references/tool-installation-ios.md` for complete installation guides.

---

## Version History

| Date | Tool | Old Version | New Version | Reason |
|------|------|-------------|-------------|--------|
| 2026-06 | frida / frida-tools | 17.9.1 / mixed | 17.11.0 / 14.9.0 | Sync to latest; fixed `frida-tools` version (no 17.x release exists) and core/tools pairing |
| 2024-11 | Frida | 16.x | 17.9.1 | iOS 18 compatibility |
| 2024-08 | Objection | 1.12.3 | 1.12.4 | Bug fixes |
| 2024-06 | dsdump | 0.12 | 0.13+ | Swift 5.10 support |

---

## Updating This File

When tool versions change:
1. Update the version in this file — **this is the only place to change it**
2. Run `python3 scripts/preflight_check.py` to verify compatibility (it reads the "Core Analysis Tools" table below directly)
3. Update `SKILL.md` only if the tool's *role* changed (e.g., a new required tool) — not for version bumps
4. Add entry to Version History table

> The preflight check parses the **Core Analysis Tools** table below at runtime, so version bumps here propagate to the checker automatically. There is no second copy of the numbers in the code.
>
> Currently enforced (probed on the host): `frida` (core, exact) and `objection` (minimum).
> Not enforced: `frida-tools` and `dsdump` — their versions are only visible via `pip show`, so there is no binary interface to probe.

**This file is referenced by**:
- `SKILL.md` → Toolchain Requirements section
- `references/tool-installation-ios.md` → Installation commands
- `scripts/preflight_check.py` → Version validation (parsed at runtime)

---

**For complete installation instructions**, see `references/tool-installation-ios.md`.
