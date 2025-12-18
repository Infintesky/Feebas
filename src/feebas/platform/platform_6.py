#!/usr/bin/env python3
"""Android WebView Security Configuration Analysis (PLATFORM-6)."""
import os
import re


def check_webview_security_settings(sources_dir):
    """
    Check for insecure WebView security settings in decompiled source code.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources

    Returns:
        dict: {
            'insecure_settings': [{'file': str, 'line': int, 'method': str, 'code': str, 'value': str}],
            'success': bool
        }
    """
    print(f"[+] Checking for insecure WebView security settings...")

    if not os.path.exists(sources_dir):
        print(f"[-] Error: Sources directory not found: {sources_dir}")
        return {'insecure_settings': [], 'success': False}

    # Methods to search for (these should all be set to false)
    target_methods = [
        'setAllowContentAccess',
        'setAllowFileAccess',
        'setAllowFileAccessFromFileURLs',
        'setAllowUniversalAccessFromFileURLs'
    ]

    insecure_settings = []

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
                            # Check if line contains any of the target methods
                            for method in target_methods:
                                if method in line:
                                    # Check if the method is being called
                                    # Look for patterns like: .setAllowContentAccess(true) or .setAllowContentAccess(false)

                                    # Extract the value being set
                                    # Pattern: method_name(value)
                                    pattern = rf'{method}\s*\(\s*(\w+)\s*\)'
                                    match = re.search(pattern, line)

                                    if match:
                                        value = match.group(1)

                                        # Flag as insecure if set to true or any non-false value
                                        if value.lower() != 'false':
                                            insecure_settings.append({
                                                'file': relative_path,
                                                'line': line_num,
                                                'method': method,
                                                'code': line.strip(),
                                                'value': value
                                            })

                except Exception as e:
                    # Skip files that can't be read
                    continue

        return {
            'insecure_settings': insecure_settings,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error checking for insecure WebView settings: {e}")
        return {'insecure_settings': [], 'success': False}


def analyze_webview_security(sources_dir, test_id="MASTG-PLATFORM-6 - Testing WebView Security Configuration"):
    """
    Analyze WebView security configuration for security issues.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Check WebView security settings
    settings_results = check_webview_security_settings(sources_dir)

    if not settings_results['success']:
        print("\n[!] FAIL: Failed to check WebView security settings")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check WebView settings'
        }

    # Print results
    print()
    print("[*] WebView Security Configuration Analysis Results:")
    print("-" * 80)

    insecure_settings = settings_results['insecure_settings']

    if insecure_settings:
        print(f"\n[*] Insecure WebView Settings Found ({len(insecure_settings)}):")
        print()

        # Group by method for better readability
        grouped = {}
        for setting in insecure_settings:
            method = setting['method']
            if method not in grouped:
                grouped[method] = []
            grouped[method].append(setting)

        for method, settings in grouped.items():
            print(f"  [!] {method} - {len(settings)} instance(s)")
            for setting in settings:
                print(f"      File: {setting['file']}:{setting['line']}")
                print(f"      Value: {setting['value']}")
                print(f"      Code: {setting['code']}")
                print()
    else:
        print("\n[+] No insecure WebView settings found")
        print("    All WebView security settings are properly configured")

    print("-" * 80)
    print()

    # Determine if test passed
    has_issues = len(insecure_settings) > 0

    if has_issues:
        print(f"[!] FAIL: Found {len(insecure_settings)} insecure WebView setting(s)")
        print("[!] All WebView settings should be set to 'false' for security:")
        print("    - setAllowContentAccess(false)")
        print("    - setAllowFileAccess(false)")
        print("    - setAllowFileAccessFromFileURLs(false)")
        print("    - setAllowUniversalAccessFromFileURLs(false)")
    else:
        print("[+] PASS: WebView security settings are properly configured")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'insecure_settings': insecure_settings
    }
