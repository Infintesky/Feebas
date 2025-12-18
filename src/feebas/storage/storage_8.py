#!/usr/bin/env python3
"""APK backup analysis module for checking allowBackup setting."""
import os
import tempfile
import re
from interfaces.adb_interface import run_command, get_package_path, pull_apk


def decompile_apk(apk_path, output_dir):
    """
    Decompile APK using apktool.

    Args:
        apk_path: Path to the APK file
        output_dir: Directory to output decompiled files

    Returns:
        bool: True if successful, False otherwise
    """
    print(f"[+] Decompiling APK with apktool: {apk_path}")

    result = run_command(
        ["apktool", "d", apk_path, "-o", output_dir, "-f"],
        timeout=120
    )

    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to decompile APK")
        if result:
            print(f"[-] Error message: {result.stderr}")
        return False

    print(f"[+] APK decompiled successfully to: {output_dir}")
    return True


def find_manifest(decompiled_dir):
    """
    Find AndroidManifest.xml in the decompiled APK directory.

    Args:
        decompiled_dir: Path to the decompiled APK directory

    Returns:
        str: Path to AndroidManifest.xml, or None if not found
    """
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")

    if os.path.exists(manifest_path):
        print(f"[+] Found AndroidManifest.xml at: {manifest_path}")
        return manifest_path
    else:
        print(f"[-] Error: AndroidManifest.xml not found in {decompiled_dir}")
        return None


def check_allow_backup(manifest_path):
    """
    Check the allowBackup setting in AndroidManifest.xml.

    Args:
        manifest_path: Path to AndroidManifest.xml

    Returns:
        dict: Results containing 'allow_backup' (True/False/None) and 'found' (bool)
    """
    print(f"[+] Checking allowBackup setting in: {manifest_path}")

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading manifest: {e}")
        return {'found': False, 'allow_backup': None}

    # Search for android:allowBackup attribute
    # Pattern matches: android:allowBackup="true" or android:allowBackup="false"
    pattern = r'android:allowBackup="(true|false)"'
    match = re.search(pattern, content)

    if match:
        allow_backup_value = match.group(1)
        allow_backup = (allow_backup_value == "true")
        print(f"[+] Found allowBackup setting: {allow_backup_value}")
        return {'found': True, 'allow_backup': allow_backup}
    else:
        print(f"[!] allowBackup attribute not found (defaults to true)")
        # If not explicitly set, Android defaults to true
        return {'found': False, 'allow_backup': True}


def print_backup_results(backup_info, test_id):
    """Print backup analysis results in a formatted way."""
    print("\n" + "=" * 60)
    print(f"[*] {test_id}")
    print("=" * 60)
    print(f"[+] Analyzing AndroidManifest.xml for backup settings")
    print()

    if backup_info['found']:
        backup_status = "enabled (true)" if backup_info['allow_backup'] else "disabled (false)"
        print(f"allowBackup setting: {backup_status}")
    else:
        print(f"allowBackup setting: not explicitly set (defaults to true)")

    print()

    # Security assessment
    if backup_info['allow_backup']:
        print("[!] FAIL: Backup is enabled")
        print("    - App data can be backed up via ADB or cloud backup")
        print("    - Sensitive data may be exposed through backups")
        print("    - Recommendation: Set android:allowBackup=\"false\" in <application> tag")
    else:
        print("[+] PASS: Backup is disabled")
        print("    - App data cannot be backed up")
        print("    - Sensitive data is protected from backup extraction")

    print("=" * 60)


def analyze_backup_setting(package_name, test_id="MASTG-STORAGE-8 - Testing Backups for Sensitive Data"):
    """
    Complete backup setting analysis workflow.

    Args:
        package_name: The Android package name to analyze
        test_id: Test identifier for reporting (default: MASTG-STORAGE-8)

    Returns:
        dict: Analysis results with 'passed' boolean and backup info, or None if failed
    """
    # Get package path from device
    apk_path = get_package_path(package_name)
    if not apk_path:
        return None

    # Create temporary directory for the APK and decompiled files
    with tempfile.TemporaryDirectory() as temp_dir:
        local_apk = os.path.join(temp_dir, "base.apk")
        decompiled_dir = os.path.join(temp_dir, "decompiled")

        # Pull APK from device
        if not pull_apk(apk_path, local_apk):
            return None

        # Decompile APK
        if not decompile_apk(local_apk, decompiled_dir):
            return None

        # Find AndroidManifest.xml
        manifest_path = find_manifest(decompiled_dir)
        if not manifest_path:
            return None

        # Check allowBackup setting
        backup_info = check_allow_backup(manifest_path)

        # Print results
        print_backup_results(backup_info, test_id)

        # Test passes if allowBackup is false
        passed = not backup_info['allow_backup']

        return {
            'passed': passed,
            'allow_backup': backup_info['allow_backup'],
            'explicitly_set': backup_info['found']
        }
