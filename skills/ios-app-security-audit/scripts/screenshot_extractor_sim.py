#!/usr/bin/env python3
"""
iOS Simulator Screenshot Extractor (Core)

Description: Extract SplashBoard snapshots from iOS simulator
Author: iOS-Pentesting-Skill
Version: 1.0.0

Usage: python3 screenshot_extractor_sim.py <bundle_id> [output_dir]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys


def get_booted_simulator():
    """Get the UDID of the booted simulator."""
    result = subprocess.run(
        ["xcrun", "simctl", "list", "devices"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        if "Booted" in line:
            # A device line looks like:
            #   iPhone 16 Pro (4A6FA156-7205-4EAA-B2F5-CBDA7E809CCE) (Booted)
            # The UDID is the parenthesised token. Taking the first
            # alphanumeric token instead would return the device NAME
            # ("iPhone"), which no simctl command accepts.
            match = re.search(
                r"\(([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\)",
                line,
            )
            if match:
                return match.group(1)
    return None


def find_app_container(bundle_id, sim_udid):
    """Find the app container path for the given bundle ID."""
    result = subprocess.run(
        ["xcrun", "simctl", "get_app_container", sim_udid, bundle_id, "data"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def find_snapshots(app_container):
    """Find the Snapshots directory in the app container."""
    snapshots_dir = os.path.join(app_container, "Library", "Caches", "Snapshots")

    if os.path.exists(snapshots_dir):
        return snapshots_dir

    # Also check for app-specific snapshot directories
    library_caches = os.path.join(app_container, "Library", "Caches")
    if os.path.exists(library_caches):
        for item in os.listdir(library_caches):
            if "snapshot" in item.lower():
                return os.path.join(library_caches, item)

    return None


def extract_snapshots(snapshots_dir, output_dir):
    """Extract all snapshots from the snapshots directory to output_dir."""
    os.makedirs(output_dir, exist_ok=True)

    extracted_count = 0

    # Walk through snapshots directory
    for root, dirs, files in os.walk(snapshots_dir):
        for file in files:
            if file.endswith((".png", ".jpg", ".jpeg")):
                src_path = os.path.join(root, file)
                dst_path = os.path.join(output_dir, file)

                # Handle duplicate filenames
                counter = 1
                while os.path.exists(dst_path):
                    name, ext = os.path.splitext(file)
                    dst_path = os.path.join(output_dir, f"{name}_{counter}{ext}")
                    counter += 1

                shutil.copy2(src_path, dst_path)
                extracted_count += 1
                print(f"[+] Extracted: {file}")

    return extracted_count


def main():
    parser = argparse.ArgumentParser(
        description="Extract SplashBoard snapshots from iOS simulator"
    )
    parser.add_argument("bundle_id", help="Bundle ID of the app (e.g., com.example.app)")
    parser.add_argument("output_dir", nargs="?", default="./screenshots", help="Output directory")
    args = parser.parse_args()

    # Get booted simulator
    print("[*] Detecting booted simulator...")
    sim_udid = get_booted_simulator()

    if not sim_udid:
        print("[!] No booted simulator found")
        print("[*] Please boot a simulator using Xcode")
        sys.exit(1)

    print(f"[+] Found booted simulator: {sim_udid}")

    # Find app container
    print(f"[*] Finding app container for {args.bundle_id}...")
    app_container = find_app_container(args.bundle_id, sim_udid)

    if not app_container:
        print(f"[!] App container not found for bundle ID: {args.bundle_id}")
        print("[*] Verify the app is installed in the simulator")
        sys.exit(1)

    print(f"[+] App container: {app_container}")

    # Find snapshots directory
    print("[*] Looking for SplashBoard snapshots...")
    snapshots_dir = find_snapshots(app_container)

    if not snapshots_dir:
        print("[!] No snapshots directory found")
        print("[*] The app may not have been backgrounded yet")
        print("[*] Try using the app and then backgrounding it")
        sys.exit(1)

    print(f"[+] Snapshots directory: {snapshots_dir}")

    # Extract snapshots
    print(f"[*] Extracting snapshots to {args.output_dir}...")
    count = extract_snapshots(snapshots_dir, args.output_dir)

    if count > 0:
        print(f"[+] Successfully extracted {count} snapshot(s)")
        print(f"[+] Output directory: {os.path.abspath(args.output_dir)}")
    else:
        print("[!] No snapshots found")
        print("[*] The app may not have any snapshots yet")
        sys.exit(1)


if __name__ == "__main__":
    main()
