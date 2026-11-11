# libimobiledevice Guide for iOS Pentesting

**Complete reference for the libimobiledevice toolchain: device pairing, backup, filesystem access, syslog, screenshot, crash reports, and IPA installation.**

## Table of Contents

1. [Overview](#1-overview)
2. [Ecosystem & Dependencies](#2-ecosystem--dependencies)
3. [Command-Line Utilities Reference](#3-command-line-utilities-reference)
4. [Pentest Workflow](#4-pentest-workflow)
5. [Installation by OS](#5-installation-by-os)
6. [Troubleshooting](#6-troubleshooting)
7. [Security Notes](#7-security-notes)
8. [Cross-References](#8-cross-references)

---

## 1. Overview

**libimobiledevice** is a cross-platform FOSS C library that communicates with iOS devices using native Apple protocols over USB (and limited Wi-Fi). It does **not** require a jailbreak and works with stock iOS devices.

The library talks to several daemon-level services on the device:

- **lockdownd** — the handshake daemon (pairing, device info, service discovery)
- **usbmuxd** — the USB multiplexer that tunnels multiple service connections over one USB link
- **AFC** (Apple File Connection) — filesystem access in app sandboxes (via House Arrest)
- **installation_proxy** — install/uninstall/list apps
- **screenshotr**, **syslog_relay**, **debugserver**, **crash_report_copy_service** — utility services

The project ships **20 CLI utilities** plus the separately maintained `ideviceinstaller`. All are tested on macOS, Linux, and Windows (via MSYS2 or WSL2).

> **Key point**: pairing via `idevicepair` is always the first step. Without a trusted pairing, no other service is accessible.

---

## 2. Ecosystem & Dependencies

libimobiledevice is part of a family of five sibling libraries. Most package managers install them transitively:

| Library | Purpose | Required? |
|---------|---------|-----------|
| **libplist** | Parse/generate Apple Property List format | Yes (dependency) |
| **libusbmuxd** | Client library for usbmuxd communication | Yes (dependency) |
| **usbmuxd** | USB multiplexer daemon | Yes (service) |
| **libimobiledevice-glue** | Shared utility functions | Yes (dependency) |
| **libtatsu** | TSS signing (SHSH blobs, developer images) | Yes (dependency, newer versions) |
| **libimobiledevice** | Main library + 20 CLI tools | Yes (this guide) |
| **ideviceinstaller** | IPA install/uninstall (separate repo) | Recommended |

### ideviceinstaller (separate project)

`ideviceinstaller` is maintained in its own repository at https://github.com/libimobiledevice/ideviceinstaller and must be installed separately:

```bash
# macOS
brew install ideviceinstaller

# Debian/Ubuntu
sudo apt install ideviceinstaller

# Arch/Manjaro
sudo pacman -S ideviceinstaller

# Fedora/RHEL
sudo dnf install ideviceinstaller
```

---

## 3. Command-Line Utilities Reference

| Tool | Purpose | Requires Dev Disk Image | Used in Phase |
|------|---------|------------------------|---------------|
| `idevice_id` | List connected device UDIDs | No | Phase 0/4 |
| `idevicename` | Display/set device name | No | Phase 0/4 |
| `ideviceinfo` | Device info (UDID, iOS version, ProductType) | No | Phase 0/4/5 |
| `idevicepair` | Trust/pair with device (**must be first**) | No | Phase 0/4 |
| `idevicesyslog` | Real-time syslog relay with process filters | No | Phase 2/4 |
| `idevicebackup2` | Encrypted backup/restore (iOS 4+) | No | Phase 2/4 |
| `afcclient` | AFC filesystem access (per-app via House Arrest) | No | Phase 2/4 |
| `ideviceinstaller` (separate) | Install/uninstall/list apps | No | Phase 2/4/Mod |
| `ideviceimagemounter` | Mount Developer Disk Image | N/A (provider) | Phase 0/4 |
| `idevicescreenshot` | Take screenshot from device | Yes | Phase 4 |
| `idevicedebug` | Talk to debugserver service | Yes | Phase 4 |
| `idevicedebugserverproxy` | Proxy debugserver for remote debuggers (lldb) | Yes | Phase 4 |
| `idevicesetlocation` | Spoof GPS location (geofencing tests) | Yes | Phase 4 |
| `idevicecrashreport` | Extract crash reports (apps + system) | No | Phase 4/5 |
| `idevicediagnostics` | IORegistry, mobilegestalt, restart/shutdown/sleep | No | Phase 4/5 |
| `ideviceprovision` | Manage provisioning profiles | No | Phase 1 |
| `ideviceenterrecovery` | Force recovery mode (testing DFU) | No | Phase 4 |
| `idevicedate` | Read/set device date | No | Phase 4 |
| `idevicenotificationproxy` | Post/observe device notifications | No | Phase 4 |

### Key Flags

**ideviceinfo**
```bash
ideviceinfo -u "<UDID>"              # Target specific device
ideviceinfo -q com.apple.mobile.battery -k BatteryCurrentCapacity  # Query domain/key
ideviceinfo -x                      # XML output
ideviceinfo -n                      # Network (Wi-Fi) connected devices
```

**idevicesyslog**
```bash
idevicesyslog -u "<UDID>"                        # Filter by device
idevicesyslog -p com.example.app               # Filter by process name
idevicesyslog --pidlist                         # List active PIDs
```

**idevicebackup2**
```bash
idevicebackup2 backup -u "<UDID>" /path/to/backup            # Create backup
idevicebackup2 restore -u "<UDID>" /path/to/backup           # Restore backup
idevicebackup2 info /path/to/backup                         # Show backup info
idevicebackup2 list /path/to/backup                         # List backup contents
idevicebackup2 encryption on "<password>" -u "<UDID>"          # Enable encryption
idevicebackup2 encryption off "<password>" -u "<UDID>"         # Disable encryption
idevicebackup2 changepw "<old>" "<new>" -u "<UDID>"              # Change backup password
idevicebackup2 cloud -u "<UDID>"                              # Cloud backup status
```

**idevicepair**
```bash
idevicepair pair                 # Pair (user must tap "Trust" on device)
idevicepair validate             # Validate existing pairing
idevicepair unpair               # Remove pairing
idevicepair list                 # List paired devices
idevicepair systembuid           # Show system BUID
idevicepair hostid               # Show host ID
```

**ideviceimagemounter**
```bash
ideviceimagemounter list                                    # List mounted images
ideviceimagemounter mount /path/to/DeveloperDiskImage.dmg   # Mount dev image
ideviceimagemounter unmount                                 # Unmount
ideviceimagemounter devmodestatus                           # iOS 16+ developer mode status
```

**afcclient**
```bash
afcclient -u "<UDID>" --house-arrest com.example.app  # Access app sandbox
# Inside the afc shell:
#   ls, cd, cat, pull, push, rm, mkdir
```

**ideviceinstaller** (v1.2.0+ uses subcommands; replaces legacy `-i`/`-l`/`-U` flags)
```bash
ideviceinstaller list                          # list user apps (default)
ideviceinstaller list --system                 # system apps only
ideviceinstaller list --all                    # all apps (system + user)
ideviceinstaller list --xml                    # XML plist output
ideviceinstaller list -b com.example.app       # query single bundle
ideviceinstaller list -a CFBundleIdentifier -a Path -a SignerIdentity  # custom attributes
ideviceinstaller install app.ipa               # install IPA
ideviceinstaller uninstall com.example.app     # uninstall by bundle ID
ideviceinstaller upgrade app.ipa               # upgrade existing app
```

**idevicediagnostics**
```bash
idevicediagnostics diagnostics ioregistryentry "<class>"   # IORegistry lookup
idevicediagnostics diagnostics mobilegestalt "<key>"        # MobileGestalt query
idevicediagnostics restart                                 # Restart device
idevicediagnostics shutdown                                # Shutdown device
idevicediagnostics sleep                                   # Sleep device
```

---

## 4. Pentest Workflow

The following is the ordered "happy path" for device communication during an iOS pentest. Each step depends on the previous one succeeding.

### Step 1: Connect

```bash
# List connected device UDIDs
idevice_id -l
```

Expected output: one line per connected device with its 40-character UDID.

### Step 2: Pair

```bash
# Initiate pairing — user must tap "Trust" on the device and enter passcode
idevicepair pair
```

If pairing succeeds, you see `SUCCESS: Paired with device`. If the device is already paired, it returns success immediately.

### Step 3: Validate

```bash
# Confirm the pairing is still valid
idevicepair validate
```

Expected: `SUCCESS: Validated pairing with device`.

### Step 4: Identify

```bash
# Get device model (determines Frida server build)
ideviceinfo -u "<UDID>" -k ProductType
# e.g., iPhone14,2

# Get iOS version (determines developer disk image and Frida version)
ideviceinfo -u "<UDID>" -k ProductVersion
# e.g., 17.5.1

# Get UDID if not already known
ideviceinfo -k UniqueDeviceID
```

Use ProductType + ProductVersion to select the correct Frida server binary (see `references/frida-server-ios-install.md`).

### Step 5: Mount Developer Image (required for debug, screenshot, location spoof)

```bash
# Check if already mounted
ideviceimagemounter list

# Mount the developer disk image matching the iOS version
# Images come from Xcode's DeviceSupport directory or downloaded separately
ideviceimagemounter mount /path/to/DeveloperDiskImage.dmg

# For iOS 17+, you need a directory with .dmg + BuildManifest.plist + Firmware/
ideviceimagemounter mount /path/to/PersonalizedImage/
```

> **Note**: on iOS 16+, you must enable Developer Mode on the device first: **Settings → Privacy & Security → Developer Mode → toggle On**. The device will reboot. After reboot, confirm enabling Developer Mode. Then mount the developer image.

### Step 6: Syslog

```bash
# Stream device syslog, filtered to a specific app
idevicesyslog -u "<UDID>" -p com.example.app
```

Works without a developer disk image. Useful for monitoring app crashes, network errors, and debug output.

### Step 7: Backup

```bash
# Enable encrypted backup first (required to extract keychain data later)
idevicebackup2 encryption on "<password>" -u "<UDID>"

# Create the backup
idevicebackup2 backup -u "<UDID>" /path/to/backup

# List backup contents
idevicebackup2 list /path/to/backup
```

Encrypted backups include keychain items (passwords, tokens, certificates). Unencrypted backups do NOT include keychain data. See the **Security Notes** section below for password handling.

### Step 8: Install IPA

```bash
# Install IPA on device
ideviceinstaller install app.ipa -u "<UDID>"

# List installed apps
ideviceinstaller list                       # user apps only (default)
ideviceinstaller list --system              # system apps only
ideviceinstaller list --all                 # all apps (system + user)
ideviceinstaller list --xml                 # XML plist output (for scripting)

# Query specific bundle or attributes
ideviceinstaller list -b com.example.app    # single bundle query
ideviceinstaller list -a CFBundleIdentifier -a Path -a SignerIdentity

# Uninstall
ideviceinstaller uninstall com.example.app -u "<UDID>"

# Upgrade
ideviceinstaller upgrade app.ipa -u "<UDID>"
```

### Step 9: Screenshot

```bash
# Requires developer disk image mounted
idevicescreenshot -u "<UDID>" screenshot.tiff
```

### Step 10: Crash Reports

```bash
# Extract crash reports to local directory
idevicecrashreport -u "<UDID>" ./crashes/

# Also extract system crash reports
idevicecrashreport -u "<UDID>" -s ./crashes/
```

### Per-App Filesystem Access

```bash
# Access app sandbox via House Arrest (no jailbreak needed)
afcclient -u "<UDID>" --house-arrest com.example.app

# Inside afc shell, common operations:
#   ls Documents/
#   pull Documents/local_db.sqlite ./
#   push modified_file.plist Documents/
```

> **Recommended for automation**: `afcclient` is interactive-only and blocks scripts. Use `pymobiledevice3` for programmatic container extraction (no jailbreak needed, works via developer mode):

```bash
# Install
pipx install pymobiledevice3
# or: python3 -m pip install --user pymobiledevice3

# Open interactive AFC shell into app container
pymobiledevice3 apps afc com.example.app
# Inside: ls Documents/, cd Library/Preferences/, get "<file>", etc.

# Extract a specific file to local path (scriptable)
pymobiledevice3 apps pull com.example.app Documents/local_db.sqlite ./local_db.sqlite

# Bulk extract (pull the entire Documents/ directory)
pymobiledevice3 apps pull com.example.app Documents ./extracted_documents/

# List apps and metadata
pymobiledevice3 apps list
pymobiledevice3 apps info com.example.app
```

**When to use which**: `afcclient` for quick manual exploration, `pymobiledevice3` for any script or automation that touches more than 2-3 files.

### Location Spoofing

```bash
# Spoof GPS coordinates (requires developer image)
idevicesetlocation -u "<UDID>" 40.7128 -74.0060

# Reset to real location
idevicesetlocation -u "<UDID>" reset
```

---

## 5. Installation by OS

### macOS (recommended)

```bash
# Install the full libimobiledevice suite (all idevice* tools + afcclient)
brew install libimobiledevice

# Install ideviceinstaller separately (different repo)
brew install ideviceinstaller

# For the latest usbmuxd (optional — macOS ships one)
brew install --HEAD usbmuxd
```

> **IMPORTANT**: macOS ships its own `usbmuxd` via the OS. Replacing it with the Homebrew version is NOT recommended unless you have a specific reason. The macOS built-in `usbmuxd` is more stable for most users.

**Verify:**

```bash
ideviceinfo -v
ideviceinstaller -v
idevice_id -l   # Should list any connected devices
```

### Debian / Ubuntu

The `apt` packages are often outdated. For the latest versions, build from source.

**Option A: apt (quick, may be older)**

```bash
sudo apt update
sudo apt install libimobiledevice-utils ideviceinstaller usbmuxd
```

**Option B: Build from source (latest)**

```bash
# Install build dependencies
sudo apt install build-essential pkg-config checkinstall git \
    autoconf automake libtool-bin libplist-dev libusbmuxd-dev \
    libimobiledevice-glue-dev libssl-dev usbmuxd

# Build libtatsu first (new dependency)
git clone https://github.com/libimobiledevice/libtatsu
cd libtatsu && ./autogen.sh && make && sudo make install && cd ..

# Build libimobiledevice
git clone https://github.com/libimobiledevice/libimobiledevice
cd libimobiledevice && ./autogen.sh --without-cython && make && sudo make install && cd ..

# Update shared library cache
sudo ldconfig

# Build ideviceinstaller from source
git clone https://github.com/libimobiledevice/ideviceinstaller
cd ideviceinstaller && ./autogen.sh && make && sudo make install && cd ..
```

**Verify:**

```bash
ideviceinfo -v
ideviceinstaller -v
```

### Arch / Manjaro

```bash
sudo pacman -S libimobiledevice ideviceinstaller usbmuxd
```

The Arch community repositories are typically up-to-date.

**Verify:**

```bash
ideviceinfo -v
ideviceinstaller -v
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install libimobiledevice ideviceinstaller usbmuxd
```

**Verify:**

```bash
ideviceinfo -v
ideviceinstaller -v
```

### Windows

The recommended approach is **WSL2** with the Debian/Ubuntu instructions above.

```powershell
# Install WSL2 with Ubuntu
wsl --install -d Ubuntu

# Inside WSL2, follow the Debian/Ubuntu instructions
```

**Alternative: MSYS2 (native Windows, less stable)**

An MSYS2 build exists but is considered experimental. Prefer WSL2 for reliability.

**Alternative: Scoop (third-party bucket)**

```powershell
scoop bucket add extras
scoop install libimobiledevice
```

The Scoop package may lag behind the latest release.

### Verification (all platforms)

```bash
# Check library and tool versions
ideviceinfo -v
idevice_id -l

# List connected devices (should show UDID if a device is plugged in)
idevice_id -l

# Test pairing
idevicepair pair
```

---

## 6. Troubleshooting

### "Could not connect to lockdownd"

```bash
# Restart usbmuxd
# macOS:
sudo killall usbmuxd
sudo launchctl start com.apple.mobile.lockdown

# Linux:
sudo systemctl restart usbmuxd

# Try a different USB cable and port
# Disconnect and reconnect the device
```

### "Device is not paired"

```bash
# Re-pair the device
idevicepair unpair
idevicepair pair
# Then tap "Trust" on the device and enter passcode if prompted
```

### "ERROR: Could not start com.apple.mobile.lockdown" / Developer Mode

On iOS 16+, you must enable Developer Mode:

1. **Settings → Privacy & Security → Developer Mode**
2. Toggle **On**
3. Device will reboot
4. After reboot, tap **Enable** when prompted
5. Enter device passcode to confirm
6. Now retry the operation

### "no such file or directory" for Developer Disk Image

The developer disk image version must match the device iOS version exactly.

```bash
# Check device iOS version
ideviceinfo -k ProductVersion

# Download matching developer disk images from Xcode
# Located at: /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/

# For iOS 17+, use personalized developer images
# See: https://github.com/haikieu/xcode-developer-disk-image-all-platforms
```

### "Could not connect to lockdownd, error code -19"

This usually means the device needs to be re-trusted:

```bash
# Disconnect device
# On device: Settings → General → Transfer or Reset → Reset → Reset Location & Privacy
# Reconnect device
# Tap "Trust" when prompted
idevicepair pair
```

### Wireless pairing limitation

Wireless (network) pairing with `idevicepair` only works on **Apple TV** devices. On iPhones/iPads, you must use USB. This is a protocol limitation, not a bug.

### "Could not start service com.apple.mobile.screenshotr"

The developer disk image is not mounted:

```bash
ideviceimagemounter list    # Check current state
ideviceimagemounter mount /path/to/DeveloperDiskImage.dmg
```

---

## 7. Security Notes

### Backup Passwords

**NEVER pass backup passwords as CLI arguments.** They will appear in shell history and process listings.

```bash
# BAD — password visible in ps, history, and shell logs
idevicebackup2 backup -i  # interactive mode (acceptable)

# GOOD — use environment variable
export BACKUP_PASSWORD="your-password"
idevicebackup2 backup -u "<UDID>" /path/to/backup

# GOOD — use -i for interactive password entry
idevicebackup2 encryption on -i
```

### Encrypted Backup and Keychain

Encrypted backups are **required** to extract keychain items:

- `idevicebackup2 encryption on <password>` enables backup encryption
- Once enabled, all subsequent backups include keychain data
- The password cannot be recovered if lost
- Use tools like `keychaindump` or `iphone-dataprotection` scripts to extract keychain from encrypted backups

### PII in Device Info

`ideviceinfo` reveals serial numbers, UDIDs, IMEI, and other identifiers. Treat this output as **PII** when sharing screenshots or logs in reports:

```bash
# Before sharing, redact UDID
ideviceinfo -u "<UDID>" -k UniqueDeviceID | sed 's/[0-9a-f]\{8\}/XXXXXXXX/g'
```

### Syslog Privacy

`idevicesyslog` is unfiltered by default. It captures ALL device logs, including from other apps and system services. Your own tools and commands will leak into the log:

```bash
# Always filter by process name
idevicesyslog -p com.example.app

# Or by PID
idevicesyslog --pid 1234
```

---

## 8. Cross-References

- **`references/dynamic-analysis-setup-ios.md`** — device setup for Frida, debugserver, and runtime testing
- **`references/frida-server-ios-install.md`** — installing Frida server on the device (uses `ideviceinfo` to determine the correct build)
- **`references/jailbreak-setup-guide.md`** — jailbroken device workflows (some libimobiledevice tools work without jailbreak; this guide covers the jailbreak-specific paths)
- **`references/enterprise-app-testing.md`** — enterprise IPA installation and backup extraction workflows
- **`references/tool-installation-ios.md`** — the general tool installation guide (includes the libimobiledevice ecosystem summary)
- **`references/repackaging-ios-guide.md`** — IPA modification and re-signing (uses `ideviceinstaller` for deployment)
- **`references/environment-setup-ios.md`** — full environment setup including macOS system requirements
