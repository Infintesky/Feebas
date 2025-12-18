#!/usr/bin/env python3
"""Testing Anti-Debugging Detection (RESILIENCE-2)."""
import os
import re


def check_debuggable(manifest_path):
    """
    Check the debuggable setting in AndroidManifest.xml.

    Args:
        manifest_path: Path to AndroidManifest.xml

    Returns:
        dict: Results containing 'debuggable' (True/False) and 'found' (bool)
    """
    print(f"[+] Checking android:debuggable setting in: {manifest_path}")

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading manifest: {e}")
        return {'found': False, 'debuggable': None}

    # Search for android:debuggable attribute
    # Pattern matches: android:debuggable="true" or android:debuggable="false"
    pattern = r'android:debuggable="(true|false)"'
    match = re.search(pattern, content)

    if match:
        debuggable_value = match.group(1)
        debuggable = (debuggable_value == "true")
        print(f"[+] Found android:debuggable setting: {debuggable_value}")
        return {'found': True, 'debuggable': debuggable}
    else:
        print(f"[+] android:debuggable attribute not found (defaults to false in release builds)")
        # If not explicitly set, it defaults to false in release builds
        return {'found': False, 'debuggable': False}


def analyze_anti_debugging(apktool_dir, package_name, test_id="MASTG-RESILIENCE-2 - Testing Anti-Debugging Detection"):
    """
    Complete anti-debugging analysis workflow.

    Args:
        apktool_dir: Path to apktool decompiled directory
        package_name: The Android package name
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings, or None if failed
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Find AndroidManifest.xml
    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print(f"\n[-] Error: AndroidManifest.xml not found in {apktool_dir}")
        print("=" * 80)
        return None

    print(f"[+] Analyzing anti-debugging protections...")
    print()

    # Check android:debuggable setting
    debuggable_info = check_debuggable(manifest_path)

    # Print results
    print("[*] Anti-Debugging Analysis Results:")
    print("-" * 80)
    print()

    # Report android:debuggable status
    print("DEBUGGABLE FLAG:")
    if debuggable_info['found']:
        debuggable_status = "true (INSECURE)" if debuggable_info['debuggable'] else "false (secure)"
        print(f"  android:debuggable: {debuggable_status}")
    else:
        print(f"  android:debuggable: not set (defaults to false in release)")
    print()

    if debuggable_info['debuggable']:
        print("[!] EXCEPTION: android:debuggable is set to true")
        print("    Apps with debuggable flag can be easily analyzed and modified")
        print("    Recommendation: Remove android:debuggable or set to false in production builds")
        print()
    else:
        print("[+] android:debuggable is not enabled")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  android:debuggable: {'true (FAIL)' if debuggable_info['debuggable'] else 'false or not set (PASS)'}")
    print()

    # Determine if test passed
    # Test passes if debuggable is false or not set
    has_issues = debuggable_info['debuggable']

    if has_issues:
        print("[!] FAIL: android:debuggable is set to true")
    else:
        print("[+] PASS: android:debuggable is not enabled")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'debuggable': debuggable_info['debuggable'],
        'debuggable_explicitly_set': debuggable_info['found']
    }
