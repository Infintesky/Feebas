#!/usr/bin/env python3
"""Android WebView JavaScript Interface Analysis (PLATFORM-7)."""
import os
import re
import xml.etree.ElementTree as ET


def check_webview_usage(sources_dir):
    """
    Check if WebView is used in the application.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources

    Returns:
        dict: {'webview_files': [str], 'uses_webview': bool, 'success': bool}
    """
    print(f"[+] Checking for WebView usage...")

    if not os.path.exists(sources_dir):
        print(f"[-] Error: Sources directory not found: {sources_dir}")
        return {'webview_files': [], 'uses_webview': False, 'success': False}

    webview_files = []

    try:
        # Walk through all Java files
        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, sources_dir)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        # Check for WebView usage
                        if 'WebView' in content:
                            webview_files.append(relative_path)

                except Exception as e:
                    # Skip files that can't be read
                    continue

        return {
            'webview_files': webview_files,
            'uses_webview': len(webview_files) > 0,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error checking for WebView usage: {e}")
        return {'webview_files': [], 'uses_webview': False, 'success': False}


def check_javascript_interface(sources_dir):
    """
    Check for addJavascriptInterface usage in decompiled source code.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources

    Returns:
        dict: {
            'javascript_interfaces': [{'file': str, 'line': int, 'code': str}],
            'success': bool
        }
    """
    print(f"[+] Checking for addJavascriptInterface usage...")

    if not os.path.exists(sources_dir):
        print(f"[-] Error: Sources directory not found: {sources_dir}")
        return {'javascript_interfaces': [], 'success': False}

    javascript_interfaces = []

    try:
        # Walk through all Java files
        for root, dirs, files in os.walk(sources_dir):
            for file in files:
                if not file.endswith('.java'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, sources_dir)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                        for line_num, line in enumerate(lines, start=1):
                            # Check if line contains addJavascriptInterface
                            if 'addJavascriptInterface' in line:
                                javascript_interfaces.append({
                                    'file': relative_path,
                                    'line': line_num,
                                    'code': line.strip()
                                })

                except Exception as e:
                    # Skip files that can't be read
                    continue

        return {
            'javascript_interfaces': javascript_interfaces,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error checking for addJavascriptInterface: {e}")
        return {'javascript_interfaces': [], 'success': False}


def check_min_sdk_version(apktool_dir):
    """
    Check minSdkVersion in AndroidManifest.xml.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        dict: {'min_sdk': int, 'success': bool}
    """
    print(f"[+] Checking minSdkVersion in AndroidManifest.xml...")

    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print(f"[-] Error: AndroidManifest.xml not found at {manifest_path}")
        return {'min_sdk': None, 'success': False}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Android namespace
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        # Find uses-sdk element
        uses_sdk = root.find('.//uses-sdk', ns)

        if uses_sdk is not None:
            min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')

            if min_sdk:
                try:
                    min_sdk_int = int(min_sdk)
                    return {'min_sdk': min_sdk_int, 'success': True}
                except ValueError:
                    # minSdkVersion might be a string like "P" or "Q"
                    return {'min_sdk': min_sdk, 'success': True}

        # If not found in uses-sdk, might be in manifest root
        min_sdk = root.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
        if min_sdk:
            try:
                min_sdk_int = int(min_sdk)
                return {'min_sdk': min_sdk_int, 'success': True}
            except ValueError:
                return {'min_sdk': min_sdk, 'success': True}

        # minSdkVersion not found, defaults to 1
        return {'min_sdk': 1, 'success': True}

    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return {'min_sdk': None, 'success': False}


def analyze_javascript_interface(sources_dir, apktool_dir, test_id="MASTG-PLATFORM-7 - Testing for Java Objects Exposed Through WebViews"):
    """
    Analyze JavaScript interface exposure in WebViews.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources
        apktool_dir: Directory containing apktool decompiled files
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Check if WebView is used
    webview_results = check_webview_usage(sources_dir)

    if not webview_results['success']:
        print("\n[!] FAIL: Failed to check WebView usage")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check WebView usage'
        }

    # Check for addJavascriptInterface
    js_interface_results = check_javascript_interface(sources_dir)

    if not js_interface_results['success']:
        print("\n[!] FAIL: Failed to check addJavascriptInterface usage")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check JavaScript interface'
        }

    # Check minSdkVersion
    min_sdk_results = check_min_sdk_version(apktool_dir)

    if not min_sdk_results['success']:
        print("\n[!] FAIL: Failed to check minSdkVersion")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check minSdkVersion'
        }

    # Print results
    print()
    print("[*] JavaScript Interface Analysis Results:")
    print("-" * 80)

    uses_webview = webview_results['uses_webview']
    javascript_interfaces = js_interface_results['javascript_interfaces']
    min_sdk = min_sdk_results['min_sdk']

    # WebView usage
    if uses_webview:
        print(f"\n[*] WebView Usage: Found in {len(webview_results['webview_files'])} file(s)")
    else:
        print("\n[+] WebView Usage: Not detected")

    # JavaScript Interface
    if javascript_interfaces:
        print(f"\n[!] JavaScript Interface Exposed: {len(javascript_interfaces)} instance(s) found")
        print()
        for js_interface in javascript_interfaces:
            print(f"  File: {js_interface['file']}:{js_interface['line']}")
            print(f"  Code: {js_interface['code']}")
            print()
    else:
        print("\n[+] JavaScript Interface: Not detected")

    # minSdkVersion
    if min_sdk is not None:
        if isinstance(min_sdk, int):
            print(f"\n[*] minSdkVersion: {min_sdk}")
            if min_sdk >= 17:
                print("    [+] API level 17 or higher (Protected by @JavascriptInterface annotation)")
            else:
                print("    [!] API level below 17 (Vulnerable to JavaScript reflection attacks)")
        else:
            print(f"\n[*] minSdkVersion: {min_sdk} (non-numeric)")

    print("-" * 80)
    print()

    # Determine if test passed
    has_issues = False

    # If addJavascriptInterface is used
    if javascript_interfaces:
        # Check if minSdkVersion < 17
        if isinstance(min_sdk, int) and min_sdk < 17:
            has_issues = True
            print("[!] FAIL: addJavascriptInterface used with minSdkVersion < 17")
            print("[!] This allows JavaScript to invoke any public method via reflection")
            print("[!] Recommendation: Set minSdkVersion to 17 or higher")
        else:
            print("[+] PASS: addJavascriptInterface used with minSdkVersion >= 17")
            print("[+] Protected by @JavascriptInterface annotation requirement")
    else:
        print("[+] PASS: No JavaScript interface exposed through WebViews")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'uses_webview': uses_webview,
        'javascript_interfaces': javascript_interfaces,
        'min_sdk': min_sdk
    }
