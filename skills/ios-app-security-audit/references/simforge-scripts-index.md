# SimForge Scripts: End-to-End Usage

> This reference is the **"bridge"** between the 4 scripts in `scripts/` and the 4 references in `references/`. If you know what you want to do, this file tells you which script to run and which doc to read.

## Available Scripts

| Script | Type | What it does | When to use it |
|---|---|---|---|
| `scripts/simforge_preflight.py` | Python | Validates 5 things before patching | **ALWAYS first** |
| `scripts/simforge_apply.py` | Python | Applies the 5 patches of the canonical flow | After preflight passes |
| `scripts/simforge_install_launch.sh` | Bash | Boot + install + launch + verify crash | After apply, for quick test |
| `scripts/simforge_triage.py` | Python | Parses `.ips` and applies decision tree | When there's a crash |
| `scripts/simforge_iterate.sh` | Bash | Loop launch → triage → wait for fix → retry | When crashes need iteration |

## Typical Usage Flow

```bash
# 1. Extract the IPA
unzip /path/to/App.ipa -d /tmp/app-work/extracted
APP=/tmp/app-work/extracted/Payload/App.app

# 2. Backup (CRITICAL — scripts don't auto-backup)
cp -R "$APP" /tmp/app-work/App.app.original-backup

# 3. Pre-flight check
python3 scripts/simforge_preflight.py "$APP"
# → If exit code is 1 (FAIL), DO NOT continue. See references/simforge-compatibility.md.
# → If exit code is 2 (WARN), you can continue but with caution.
# → If exit code is 0 (OK), apply the patches.

# 4. Apply the patches
python3 scripts/simforge_apply.py "$APP"
# (Waits 3 seconds — scripts are DESTRUCTIVE, no going back)

# 5. Install and launch
./scripts/simforge_install_launch.sh com.example.app "$APP"
# → By default emulator opens visible (use --headless only if explicitly requested)
# → If app crashes, script tells you where .ips is and suggests running triage.

# 6. If crash, diagnose
python3 scripts/simforge_triage.py --latest
# or
python3 scripts/simforge_triage.py "<path-to-ips>"

# 7. If fix is iterative (framework by framework):
./scripts/simforge_iterate.sh com.example.app --iterations 5
# → Script launches, waits for crash, runs triage, and waits for you to fix and press Enter.
```

## Decision Tree: Which Script to Run?

```
Do you have an .app already extracted and want to know if it's worth patching?
└── → simforge_preflight.py

Did preflight pass (exit 0) and you want to apply the canonical flow?
└── → simforge_apply.py

Did you already apply patches and want to know if the app starts?
└── → simforge_install_launch.sh

Did the app crash and you have a .ips?
└── → simforge_triage.py

Do you want to iterate over several crashes without manually writing each step?
└── → simforge_iterate.sh
```

## Mapping to References

Each script has conceptual documentation in one of the 4 simforge references:

| Script | Conceptual Reference |
|---|---|
| `simforge_preflight.py` | `references/simforge-emulation-flow.md` §"Pre-flight check" |
| `simforge_apply.py` | `references/simforge-emulation-flow.md` §"The 10-Step Canonical Flow" (Steps 2-5) |
| `simforge_install_launch.sh` | `references/simforge-emulation-flow.md` §"Step 6-7" |
| `simforge_triage.py` | `references/simforge-crash-triage.md` (entire reference) |
| `simforge_iterate.sh` | `references/simforge-crash-triage.md` §"Iteration Pattern" |

## Script Requirements

- **macOS** (Apple Silicon ideally, required to run the binary in the simulator)
- **Xcode** with iOS Simulator runtime
- **simforge** compiled (in `~/.local/bin/simforge` or in `PATH`)
- **vtool** (included with Xcode, in `/usr/bin/vtool`)
- **Python 3.8+** (scripts use `pathlib`, `plistlib`, `argparse`, `subprocess`)
- **bash 4+** (shell scripts use `set -euo pipefail`)

## Script Limitations

- Scripts **do NOT make automatic backups** — always backup before (the doc says it, but it's your responsibility).
- Scripts **do NOT validate code signature** post-patch; for that use `codesign -v --strict <path>` manually.
- The `simforge_iterate.sh` script expects user input (press Enter) between iterations; it's not a fully automated loop.
- If your Xcode is in a non-standard path, `simforge_preflight.py` may not find the toolchain — scripts use hardcoded paths to `/Applications/Xcode.app`.

## Complete End-to-End Example

```bash
# Setup
mkdir -p /tmp/myapp && cd /tmp/myapp
unzip -q /path/to/MyApp.ipa -d extracted
APP="extracted/Payload/MyApp.app"
cp -R "$APP" MyApp.app.backup

# Validate
python3 /path/to/iOS-Pentesting-Skill/scripts/simforge_preflight.py "$APP"
# Expected output:
#   [OK]      arm64
#   [OK]      fairplay
#   [WARN]    platforms
#   [WARN]    legacy_lc
#   [OK]      swift_abi
#   RESULT: 2 warning(s). Patching will likely work but may need attention.
#   exit: 2

# Apply
python3 /path/to/iOS-Pentesting-Skill/scripts/simforge_apply.py "$APP"
# 3-second countdown, then applies Steps 2-5

# Install + Launch + Verify
/path/to/iOS-Pentesting-Skill/scripts/simforge_install_launch.sh com.example.app "$APP"
# If app crashes, script suggests:
#   python3 scripts/simforge_triage.py "/path/to/MyApp-2026-06-05.ips"

# Triage
python3 /path/to/iOS-Pentesting-Skill/scripts/simforge_triage.py --latest
# Prints decision tree recommendation

# Iterate
/path/to/iOS-Pentesting-Skill/scripts/simforge_iterate.sh com.example.app
# Loop: launch → wait → triage → "press Enter to fix" → relaunch
```

## When Scripts Are NOT Enough

There are scenarios that require manual intervention beyond the scripts:

- **Change the bundle ID** to avoid conflicts: use `plutil -replace CFBundleIdentifier` manually.
- **Inject custom entitlements** (e.g., `get-task-allow=true` for Frida Gadget): use `codesign --entitlements` with a custom entitlements plist.
- **Sign with a specific certificate** (not ad-hoc): scripts only do ad-hoc; for certificate-based, custom workflow.
- **Modify code** (not just metadata): requires a disassembler + recompiler (Hopper, Ghidra, etc.) beyond the scope of these scripts.

For those cases, the scripts are still useful as a starting point (preflight + apply + install + triage), but the manual modification phase is artisanal.
