# MITM Proxy Setup for iOS Simulator

> **Canonical reference** for installing a CA certificate and routing traffic through a MITM proxy (Burp Suite, Charles, mitmproxy, OWASP ZAP, Proxyman, etc.) on the **iOS Simulator** (Xcode).
>
> For **physical devices**, see the device-specific sections in `ssl-pinning-bypass-ios.md` and `dynamic-analysis-setup-ios.md`. The simulator flow is materially different and shorter.

---

## Why the Simulator Needs a Separate Flow

| Step | Physical Device | iOS Simulator |
|------|----------------|---------------|
| Install CA profile | Settings → VPN & Device Management → Install | **`xcrun simctl keychain booted add-root-cert <cert>`** |
| Enable full trust | Settings → About → Certificate Trust Settings → toggle | **Not required — `add-root-cert` auto-trusts** |
| Configure proxy host | Mac's LAN IP (e.g. `192.168.1.100`) | **`127.0.0.1`** (the simulator shares the host's loopback) |
| Configure proxy port | `8080` (or tool's default) | Same |
| Common mistake | Installing cert with `xcrun simctl addmedia` (it's for **photos/videos only**, not certificates — fails with `NSPOSIXErrorDomain 22: File type unsupported`) | |

> **Bottom line**: the simulator flow is **2 commands**, not the 6+ manual UI steps a physical device needs.

---

## Prerequisites

- macOS host with Xcode + iOS Simulator runtime installed
- At least one simulator booted (`xcrun simctl list devices booted`)
- MITM proxy tool running on the host (Burp Suite, Charles, mitmproxy, Proxyman, ZAP, etc.)
- The CA certificate of that tool exported to a file on disk (`.der`, `.pem`, or `.cer`)

Verify the simulator is reachable:

```bash
xcrun simctl list devices booted
# Expect: at least one device with "(Booted)" next to it
```

---

## Step 1 — Export the CA Certificate

The exact export steps differ per tool, but the goal is the same: get the tool's **root CA** into a single certificate file (not the private key) on disk.

| Tool | How to export | Default format |
|------|---------------|----------------|
| **Burp Suite** | Proxy → Proxy Listeners → import/export CA certificate → Export → **DER** | `.der` |
| **Charles** | Help → SSL Proxying → Save Charles Root Certificate… | `.pem` |
| **mitmproxy** | Already present at `~/.mitmproxy/mitmproxy-ca-cert.cer` after first run | `.cer` (DER) |
| **OWASP ZAP** | Tools → Options → Network → Save CA certificate | `.cer` |
| **Proxyman** | Certificate → Export Root Certificate as DER | `.der` |

If you need to convert formats:

```bash
# DER → PEM
openssl x509 -inform DER -in cert.der -out cert.pem

# PEM → DER
openssl x509 -inform PEM -outform DER -in cert.pem -out cert.der
```

> **Tip**: the simulator's `add-root-cert` command accepts both DER and PEM directly — you usually don't need to convert.

---

## Step 2 — Install the CA into the Simulator's Trust Store

> **One command. No UI. No restart.**

```bash
xcrun simctl keychain booted add-root-cert /absolute/path/to/cert.der
```

- Use the booted device's identifier instead of `booted` if you want to target a specific one: `xcrun simctl keychain <UDID> add-root-cert <cert>`.
- The command writes the certificate to the simulator's **System keychain** with full trust — equivalent to the user toggling "Enable full trust for root certificates" on a physical device, but done atomically.
- **No `simctl` reset is needed** before installing. Reset only if a prior cert is interfering and you want a clean slate: `xcrun simctl keychain booted reset` (⚠️ this wipes *all* user-installed certs).

### Why not `xcrun simctl addmedia`?

```bash
# WRONG — this is for photos/videos, not certificates:
xcrun simctl addmedia booted cert.der
# → Failed to import 'cert.der', error [NSPOSIXErrorDomain] 22: File type unsupported.
```

`addmedia` only accepts media types (PNG, JPG, MP4, MOV, …). For certificates, the right subcommand lives under `simctl keychain`.

### Verify the cert is installed (optional)

`xcrun simctl keychain` returns no output on success, which is silent-by-design. To confirm a cert was actually written, check the keychain database mtime on the host (this lives under the host's `$HOME`, not the simulator's internal HOME — `simctl getenv booted HOME` returns a sandbox path inside the simulator and is **not** what you want here):

```bash
# Get the booted device's UDID:
UDID=$(xcrun simctl list devices booted | rg -o '[0-9A-F-]{36}' | head -1)
# Then inspect the keychain db on the host's filesystem:
ls -la "$HOME/Library/Developer/CoreSimulator/Devices/$UDID/data/Library/Keychains/"
# mtime of keychain-2-debug.db-wal should be very recent (within seconds of your add-root-cert call)
```

A more direct verification is to launch Safari on the simulator and load a HTTPS site — if the cert is trusted, no SSL error is shown. (Don't trust a "site loaded" check alone if the app under test also pins; see the "Pin bypass" section in `ssl-pinning-bypass-ios.md`.)

---

## Step 3 — Configure the Proxy

> **Key difference from physical devices**: in the simulator, the host Mac is reachable on **loopback**, not on a LAN IP.

### 3a. Manual proxy (Settings UI)

1. Open **Settings** on the simulator.
2. Tap **Wi-Fi** (the only entry, even on cellular simulators).
3. Tap the **(i)** info button next to the active network.
4. Tap **Configure Proxy** → **Manual**.
5. Set **Server** = `127.0.0.1` and **Port** = the port your tool is listening on (commonly `8080`).
6. Leave Authentication off unless your tool requires it.
7. **Save**.

### 3b. Headless proxy (automation / CI)

`xcrun simctl` does **not** expose a direct command to set the Wi-Fi proxy on a simulator (Apple's `defaults` API for that is private). For automation, choose one of:

- **`.mobileconfig` profile (most reliable, headless-friendly)**: deploy a configuration profile with `com.apple.proxy.managed` (`ProxyType = Manual`, `ProxyServer`, `ProxyServerPort`, `ProxyPACURL`, etc.). Install it with `xcrun simctl install booted payload-profile.mobileconfig` or via the Apple Configurator `cfgutil` CLI (`cfgutil install-profile <profile.mobileconfig>`). This is the recommended headless path because it works system-wide for any app without touching the launch environment.
- **GUI automation**: drive Settings with AppleScript / `cliclick` / `xdotool` equivalents for macOS. Brittle — only use when no profile-based path is available.
- **Per-app env override (limited applicability)**: `xcrun simctl launch` does **not** accept an `--env` flag. To pass an env var to the launched app, export it in the calling shell with the `SIMCTL_CHILD_` prefix (e.g., `SIMCTL_CHILD_HTTP_PROXY=... xcrun simctl launch booted <bundle.id>`). **Important caveat**: iOS native networking stacks (`NSURLSession`, `CFNetwork`, `SecureTransport`) do **not** read `HTTP_PROXY` / `HTTPS_PROXY` — those are POSIX conventions respected only by some CLIs (curl, wget) and a few libraries (libcurl). For a typical iOS app built on `NSURLSession`, the env-var approach will **not** route its traffic. Use it only for apps/libraries that explicitly read these env vars. For native iOS apps, use the `.mobileconfig` path above or the transparent `pf` path below.

  ```bash
  # Syntax (note: vars go in the calling shell, NOT as a --env flag)
  SIMCTL_CHILD_HTTP_PROXY=http://127.0.0.1:8080 \
  SIMCTL_CHILD_HTTPS_PROXY=http://127.0.0.1:8080 \
    xcrun simctl launch --console-pty booted com.example.app
  ```

### 3c. Transparent VPN-style proxy (advanced)

For tests where you cannot touch the app's launch environment, do not want to deploy a profile, and the app ignores proxy env vars, layer `pf` (macOS packet filter) and a transparent redirector (e.g. `mitmproxy --mode transparent`). This is the same technique used for Flutter/Xamarin apps on physical devices (see the "Hotspot Method" section in `ssl-pinning-bypass-ios.md`). It is the most invasive but the most universally effective option.

---

## Step 4 — Verify the MITM Is Working

### 4a. Sanity check (Safari)

1. Boot the simulator and confirm the cert is installed (Step 2) and the proxy is set (Step 3).
2. Make sure Burp/Charles/mitmproxy is running and listening.
3. Open **Safari** on the simulator.
4. Load a HTTPS URL you have never visited (`https://example.com` works).
5. In your proxy tool's HTTP history, you should see the request and be able to inspect the response body.
6. If you see the request but the response body is empty or shows a TLS error, the app/server is doing something extra (HSTS preloading, pinned trust, client certificates). Move to Step 5.

### 4b. Programmatic check

```bash
# From the host, confirm the proxy is listening:
lsof -nP -iTCP:8080 -sTCP:LISTEN

# From the simulator, confirm it can reach loopback:
xcrun simctl openurl booted http://127.0.0.1:8080
# (or whatever your tool's landing page is — Burp: http://burp)
```

If `openurl` opens a page in Safari and the request shows up in the proxy, end-to-end is working.

---

## Step 5 — Combine with SSL Pinning Bypass (If Needed)

A trusted root cert is necessary but **not sufficient** when the app under test implements SSL pinning (`SecTrustEvaluateWithError`, `URLSession` delegate, TrustKit, AFNetworking, Alamofire, etc.). You will need to bypass the pinning in addition to installing the cert.

Order of escalation (see `references/ssl-pinning-bypass-ios.md` for full details):

1. **Burp mobile assistant / built-in bypass** — only some tools ship one.
2. **Objection** (jailbroken device or SimForge-injected app):
   ```bash
   objection -g com.example.app explore
   ios sslpinning disable
   ```
3. **Frida + generic script** (`assets/frida-scripts/ssl-pinning-bypass-ios.js`):
   ```bash
   frida -U -f com.example.app -l assets/frida-scripts/ssl-pinning-bypass-ios.js
   ```
4. **Framework-specific scripts** for Flutter (`flutter-ssl-pinning-ios.js`), Cordova, etc.

---

## End-to-End Automation Script

**Example automation script** — this is a **copy-paste template** you must author yourself: the skill does not ship a `scripts/simulator-mitm-setup.sh`. Copy the block below into your own working directory (for example `scripts/simulator-mitm-setup.sh`) and adapt the paths — note: the proxy portion of this script only does the *manual Wi-Fi proxy* instructions; for true headless proxying, deploy a `.mobileconfig` or use `pf` redirection, see Step 3b/3c):

```bash
#!/usr/bin/env bash
# Configure MITM proxy on the booted iOS simulator.
# Idempotent: safe to re-run.

set -euo pipefail

CERT_PATH="${1:?Usage: $0 <path-to-ca-cert.der>}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"

# 1. Simulator must be booted.
if ! xcrun simctl list devices booted | grep -q "(Booted)"; then
  echo "[!] No simulator booted. Boot one with: xcrun simctl boot <UDID>" >&2
  exit 1
fi

# 2. Install CA cert into the simulator's System keychain (auto-trusted).
xcrun simctl keychain booted add-root-cert "$CERT_PATH"
echo "[+] Cert installed: $CERT_PATH"

# 3. Tell the user how to set the proxy manually (we can't drive the Wi-Fi settings UI headlessly).
echo "[+] Now configure proxy manually in the simulator:"
echo "      Settings → Wi-Fi → (i) → Configure Proxy → Manual"
echo "      Server: $PROXY_HOST    Port: $PROXY_PORT"
echo
echo "[i] For headless/CI: deploy a .mobileconfig with com.apple.proxy.managed"
echo "    and install with: xcrun simctl install booted <profile.mobileconfig>"
echo
echo "[i] Per-app env-var override (only works for apps/libraries that read POSIX proxy env vars;"
echo "    NSURLSession-based iOS apps ignore these):"
echo "      SIMCTL_CHILD_HTTP_PROXY=http://$PROXY_HOST:$PROXY_PORT \\"
echo "      SIMCTL_CHILD_HTTPS_PROXY=http://$PROXY_HOST:$PROXY_PORT \\"
echo "        xcrun simctl launch --console-pty booted <bundle.id>"
```

---

## Tool-Specific Notes

### Burp Suite

- Default listener: `127.0.0.1:8080`. Good.
- CA export: Proxy → Proxy Listeners → your listener → **Import / Export CA Certificate** → **Export in DER format**.
- For invisible / non-proxy-aware clients, enable **"Support invisible proxying"** on the listener and pair it with `pf` redirection.

### Charles

- Default proxy: `127.0.0.1:8888` (remember to update `PROXY_PORT` if you keep the default).
- CA export: **Help → SSL Proxying → Save Charles Root Certificate…**
- macOS will trust Charles automatically on first install — that is *macOS*, not the simulator. The simulator still needs the explicit `add-root-cert` step.

### mitmproxy / mitmweb

- `~/.mitmproxy/mitmproxy-ca-cert.cer` is created on first run.
- For transparent mode, launch with `--mode transparent` and add the `pf` redirect rule from the Hotspot Method in `ssl-pinning-bypass-ios.md`.

### OWASP ZAP

- Save the CA, then enable **"Regenerate on address change"** off (otherwise the cert changes per network — annoying when you have a pinned cert and want to keep state).

### Proxyman

- macOS-only. Cert export is one click. Same `add-root-cert` flow.

---

## Common Pitfalls

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `addmedia` rejects `.der` | Wrong subcommand | Use `xcrun simctl keychain booted add-root-cert` |
| Cert "installed" but Safari still warns | Cert was installed in *user* keychain by Safari UI; not auto-trusted | Use `add-root-cert` (writes to System keychain) |
| Proxy never sees traffic | App is non-proxy-aware and ignores both Wi-Fi proxy and `HTTP_PROXY` env vars (common for native `NSURLSession` apps) | Deploy a `.mobileconfig` with `com.apple.proxy.managed`, or use transparent `pf` redirect (Step 3b/3c) |
| HTTPS requests show blank response in proxy | App uses SSL pinning | Move to Step 5 (pin bypass) |
| App works on real device but not simulator | Simulator lacks hardware-only APIs (Secure Enclave, biometric, Bluetooth) | Test the relevant code paths in a Frida script with stubs, or use a physical device for those features |
| `add-root-cert` returns nothing on stderr | **Success** — `simctl` is silent on success | Verify by re-running or by checking the keychain db mtime |
| After `xcrun simctl keychain booted reset` everything broke | That command wipes *all* user-installed certs | Re-run `add-root-cert`; only reset when you actually need a clean slate |

---

## Apple Silicon vs Intel

Same commands on both. The simulator runs natively on Apple Silicon and under Rosetta on Intel hosts; `simctl keychain` is arch-agnostic.

---

## See Also

- `references/ssl-pinning-bypass-ios.md` — full pin-bypass techniques (Frida, Objection, SSL Kill Switch 2, hotspot method, etc.)
- `references/dynamic-analysis-setup-ios.md` — overall dynamic analysis workflow
- `references/simforge-ios-testing.md` — running arm64 iOS apps in the simulator with dylib injection (pairs naturally with this guide: SimForge installs the app, `add-root-cert` trusts the CA, a `.mobileconfig` profile or `pf` redirect routes traffic)
- `references/frida-ios-guide.md` — Frida installation and runtime usage
- `references/environment-setup-ios.md` — Xcode and toolchain prerequisites
- OWASP MASTG-NETWORK-1 / MASTG-TEST-0060 — Network Communication Testing
