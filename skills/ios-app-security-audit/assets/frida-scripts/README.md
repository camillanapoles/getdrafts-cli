# Frida Scripts (iOS)

> **Canonical catalog**: See [`../../references/frida-scripts-index.md`](../../references/frida-scripts-index.md) for the complete, up-to-date catalog of all bundled Frida scripts.
>
> This folder is the **runtime location** for the scripts. The canonical catalog (script metadata, maturity classification, MASTG references, usage examples) lives in the `references/` directory to avoid duplication.

## Quick Usage

```bash
# Spawn app with a script
frida -U -f com.example.app -l ssl-pinning-bypass-ios.js

# Attach to running process
frida -U com.example.app -l jailbreak-detection-bypass.js

# Combine multiple scripts (see canonical catalog for combinations)
frida -U -f com.example.app \
  -l ssl-pinning-bypass-ios.js \
  -l jailbreak-detection-bypass.js \
  -l network-interceptor-ios.js
```

## File Inventory

This directory contains **73 Frida scripts** covering Network, Auth, Storage, IPC, Crypto, and Supply Chain categories. See the canonical catalog for descriptions, OWASP/MASTG mappings, and maturity labels (STABLE/BETA).

> If you find a script that isn't in the canonical catalog, please update `references/frida-scripts-index.md` — this folder and that file must stay in sync.
