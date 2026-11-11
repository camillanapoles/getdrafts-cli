# Linux iOS Analysis Workarounds

Most of the iOS audit toolchain assumes macOS (`otool`, `codesign`, `lipo`, `plutil`,
`dsdump`, Xcode/Simulator are macOS-only). This guide maps **what you can do from a
Linux host**, the closest tool substitutions, and where you genuinely still need a Mac
or an Apple-Silicon machine.

> **Rule of thumb**: static analysis, device interaction, traffic interception, and
> dynamic instrumentation are fully doable from Linux. Re-signing and simulator-based
> work are where macOS is hard to avoid.

---

## 1. What works natively on Linux

| Task | Linux story |
|------|-------------|
| IPA extraction | `unzip app.ipa -d app/` — an IPA is just a zip. Fully cross-platform. |
| String/secret scanning | `rg`, `strings` (binutils) work everywhere. |
| Mach-O inspection | `llvm-objdump`, `objdump`, `jtool2` (cross-platform) replace `otool`. |
| Plist reading | `plistutil` / `libplist` replace `plutil`. |
| Symbol listing | `nm`, `llvm-nm` (binutils / LLVM). |
| Frida (host side) | `pip3 install frida-tools` runs on Linux; drives a jailbroken device over USB/Wi-Fi. |
| Device interaction | `libimobiledevice` suite is first-class on Linux. |
| Decrypting App Store binaries | `frida-ios-dump` from Linux against a jailbroken device. |
| MobSF | Run via Docker — identical on Linux/macOS/Windows. |
| Dependency / SBOM scan | `scripts/sbom_generator.py`, `scripts/dependency_scanner.py` (pure Python). |

---

## 2. macOS tool → Linux substitution

| macOS tool | Purpose | Linux substitute | Notes |
|------------|---------|------------------|-------|
| `plutil` | plist convert/inspect | `plistutil` (libplist) | `plistutil -i Info.plist -o -` to convert binary→XML |
| `otool -l` / `-L` | Mach-O load commands / dylibs | `llvm-objdump -p` / `jtool2 -l` | `LC_ENCRYPTION_INFO`, `LC_CODE_SIGNATURE` visible with `jtool2` |
| `lipo` | fat-binary arch ops | `llvm-lipo` | ships with LLVM ≥ 12 |
| `nm` / `strings` | symbols / strings | `llvm-nm` / `strings` (binutils) | identical usage |
| `codesign` | sign / inspect signature | `ldid` (Linux port) + `jtool2 --sign` | re-signing is limited — see §5 |
| `class-dump` | ObjC headers | `jtool2 -d objc` (partial) | best done at runtime via Frida `binary-class-dump.js` |
| `dsdump` | Swift class dump | *(no Linux build)* | use Frida runtime dump (`objc-api-explorer.js`) or a Mac |
| `swift-demangle` | demangle Swift symbols | `swift demangle` (Swift Linux toolchain) | install the Swift for Linux toolchain |
| `xcrun simctl` | Simulator control | *(macOS only)* | no substitute — see §6 |

Install the bulk on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y ripgrep binutils llvm libimobiledevice-utils \
  ideviceinstaller libplist-utils python3-pip unzip
pip3 install frida-tools objection
# ldid (re-signing helper)
sudo apt install -y ldid 2>/dev/null || brew install ldid  # or build from https://github.com/ProcursusTeam/ldid
```

---

## 3. Device interaction with libimobiledevice (Linux-native)

The `libimobiledevice` toolchain talks to a (jailbroken or normal) device over USB from
Linux — pairing, logs, install, file access:

```bash
idevice_id -l                       # list connected device UDIDs
ideviceinfo                         # device info
idevicepair pair                    # trust/pair
ideviceinstaller list               # list installed apps
ideviceinstaller install app.ipa    # install an IPA
idevicesyslog | rg "<bundle-id>"      # live syslog, filtered
idevicecrashreport -e ./crashes/    # pull crash reports
```

> See `references/libimobiledevice-guide.md` for the full command set (backup,
> screenshot, image mounting, AFC filesystem access).

---

## 4. Dynamic analysis from Linux (Frida + Objection)

`frida-tools` and `objection` are Python packages and run on Linux unchanged. You need a
**jailbroken device** with a matching `frida-server` (see `references/tool-versions.md`
for the pinned version and `references/frida-server-ios-install.md` for install):

```bash
# USB-attached jailbroken device
frida-ps -U
frida -U -f com.example.app -l assets/frida-scripts/ssl-pinning-bypass-ios.js  # removed in Frida 17; omit for auto-resume
objection -g com.example.app explore
```

Decrypt an App Store (FairPlay) binary from Linux against that device:

```bash
# https://github.com/AloneMonkey/frida-ios-dump  (Python, runs on Linux)
python3 dump.py com.example.app          # pulls a decrypted IPA over SSH/USB
```

---

## 5. Code signing & re-packaging on Linux (limited)

This is the weakest area on Linux. `ldid` can manipulate entitlements and apply a
pseudo-signature usable on a **jailbroken** device, but it cannot produce an
App-Store/ad-hoc signature accepted by a stock device.

```bash
# Inspect / set entitlements with ldid
ldid -e app/Payload/Example.app/Example > entitlements.plist
ldid -Sentitlements.plist app/Payload/Example.app/Example   # pseudo-sign (jailbroken only)

# Re-zip the modified bundle
cd app && zip -qr ../app-modified.ipa Payload/ && cd ..
```

For a signature that installs on a **non-jailbroken** device you still need macOS
`codesign` + a provisioning profile (see `references/repackaging-ios-guide.md`), a
cloud Mac, or a service like AltStore/Sideloadly run elsewhere.

---

## 6. What genuinely needs macOS / Apple Silicon

| Capability | Why | Alternative |
|------------|-----|-------------|
| iOS Simulator (`simctl`) | Apple private frameworks | Use a physical device, or a cloud Mac |
| **SimForge** (run iOS apps in Simulator) | Apple-Silicon macOS only | Physical jailbroken device + Frida |
| `codesign` for stock-device installs | Apple signing | Cloud Mac / AltStore / Sideloadly |
| `dsdump` (Swift static dump) | no Linux build | Runtime Swift introspection via Frida |
| Xcode build/instruments | macOS only | N/A |

**Cloud / remote options when you have no Mac:**
- **Corellium** — cloud-hosted virtual jailbroken iOS devices (full Frida/SSH access).
- **macOS CI runners** (GitHub Actions `macos-latest`, etc.) for signing/build steps —
  see `references/github-actions-ios-security.md`.
- A remote/rented Mac (MacStadium, Scaleway Mac mini) reachable over SSH.

---

## 7. Recommended Linux workflow

1. **Extract & static-scan** locally: `unzip` + `rg`/`strings` + `llvm-objdump`/`jtool2`
   + `plistutil` (Phases 0–2 of the skill work fine).
2. **Device dynamic analysis**: jailbroken device + `frida-server` driven from the Linux
   host (Phase 4); decrypt with `frida-ios-dump` if needed.
3. **MobSF via Docker** for automated coverage (`./scripts/install-mobsf-docker.sh`).
4. **Offload only the macOS-only steps** (re-signing for stock devices, Simulator,
   `dsdump`) to a cloud/remote Mac or Corellium.

---

## See also

- `references/tool-installation-ios.md` — per-tool install (notes Linux paths).
- `references/tool-versions.md` — pinned versions (single source of truth).
- `references/libimobiledevice-guide.md` — full device toolchain (Linux-native).
- `references/frida-server-ios-install.md` — frida-server setup on the device.
- `references/repackaging-ios-guide.md` — re-signing (the macOS path).
- `references/mobsf-integration-guide.md` — Docker-based automated analysis.

---

**Author**: DragonJAR iOS Pentesting Skill
