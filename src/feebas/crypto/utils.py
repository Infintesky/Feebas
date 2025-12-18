#!/usr/bin/env python3
"""Shared utilities for APK analysis."""
import os
import tempfile
from interfaces.adb_interface import run_command, get_package_path, pull_apk


def decompile_apk_with_jadx(apk_path, output_dir):
    """
    Decompile APK using jadx to get Java source code.

    Args:
        apk_path: Path to the APK file
        output_dir: Directory to output decompiled source code

    Returns:
        bool: True if successful, False otherwise
    """
    print(f"[+] Decompiling APK with jadx: {apk_path}")

    result = run_command(
        ["jadx", "-d", output_dir, apk_path],
        timeout=180
    )

    if not result:
        print(f"[-] Error: jadx command timed out or failed to execute")
        return False

    # jadx may return non-zero even on success, so check if output was created
    sources_dir = os.path.join(output_dir, "sources")
    if not os.path.exists(sources_dir):
        print(f"[-] Error: Failed to decompile APK with jadx (exit code: {result.returncode})")
        if result.stderr:
            print(f"[-] Error message: {result.stderr[:500]}")
        if result.stdout:
            print(f"[-] Output: {result.stdout[:500]}")
        return False

    print(f"[+] APK decompiled successfully with jadx")
    return True


def decompile_apk_with_apktool(apk_path, output_dir):
    """
    Decompile APK using apktool to get resources and manifest.

    Args:
        apk_path: Path to the APK file
        output_dir: Directory to output decompiled files

    Returns:
        bool: True if successful, False otherwise
    """
    print(f"[+] Decompiling APK with apktool: {apk_path}")

    result = run_command(
        ["apktool", "d", "-f", apk_path, "-o", output_dir],
        timeout=180
    )

    if not result or result.returncode != 0:
        print(f"[-] Error: apktool command failed")
        if result and result.stderr:
            print(f"[-] Error message: {result.stderr[:500]}")
        return False

    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print(f"[-] Error: AndroidManifest.xml not found after decompilation")
        return False

    print(f"[+] APK decompiled successfully with apktool")
    return True


def prepare_apk_for_analysis(package_name):
    """
    Pull APK from device and decompile it for analysis using both jadx and apktool.

    Args:
        package_name: The Android package name to analyze

    Returns:
        tuple: (temp_dir, sources_dir, apktool_dir) if successful, (None, None, None) if failed
               - temp_dir: Base temporary directory (caller must clean up when done)
               - sources_dir: Directory with jadx decompiled Java sources
               - apktool_dir: Directory with apktool decompiled resources/manifest
    """
    print("=" * 60)
    print("Preparing APK for Analysis")
    print("=" * 60)

    # Get package path from device
    apk_path = get_package_path(package_name)
    if not apk_path:
        return None, None, None

    # Create temporary directory for the APK and decompiled files
    temp_dir = tempfile.mkdtemp()

    try:
        local_apk = os.path.join(temp_dir, "base.apk")
        jadx_output_dir = os.path.join(temp_dir, "jadx")
        apktool_output_dir = os.path.join(temp_dir, "apktool")

        # Pull APK from device
        print(f"[+] Pulling APK from device")
        if not pull_apk(apk_path, local_apk):
            return None, None, None

        # Decompile APK with jadx (for source code analysis)
        if not decompile_apk_with_jadx(local_apk, jadx_output_dir):
            return None, None, None

        # Decompile APK with apktool (for resources and manifest)
        if not decompile_apk_with_apktool(local_apk, apktool_output_dir):
            return None, None, None

        # jadx puts decompiled source in 'sources' subdirectory
        sources_dir = os.path.join(jadx_output_dir, "sources")

        print("[+] APK preparation complete")
        print("=" * 60)
        print()

        return temp_dir, sources_dir, apktool_output_dir

    except Exception as e:
        print(f"[-] Error preparing APK for analysis: {e}")
        return None, None, None
