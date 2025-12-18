#!/usr/bin/env python3
"""Testing for Debugging Flags and WebView Debugging (CODE-2)."""
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
    print(f"[+] Checking android:debuggable setting in manifest")

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading manifest: {e}")
        return {'found': False, 'debuggable': None}

    # Search for android:debuggable attribute
    pattern = r'android:debuggable="(true|false)"'
    match = re.search(pattern, content)

    if match:
        debuggable_value = match.group(1)
        debuggable = (debuggable_value == "true")
        print(f"[+] Found android:debuggable: {debuggable_value}")
        return {'found': True, 'debuggable': debuggable}
    else:
        print(f"[+] android:debuggable not found (defaults to false in release)")
        return {'found': False, 'debuggable': False}


def search_webview_debugging(sources_dir):
    """
    Search for WebView debugging being enabled in source code.

    Args:
        sources_dir: Path to jadx decompiled sources

    Returns:
        dict: Results with lists of files containing debugging code
    """
    print(f"[+] Searching for WebView debugging settings in source code")

    webview_debug_files = []
    flag_debuggable_files = []

    # Search for setWebContentsDebuggingEnabled
    for root, dirs, files in os.walk(sources_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    # Check for setWebContentsDebuggingEnabled(true)
                    if 'setWebContentsDebuggingEnabled' in content:
                        # Get relative path from sources_dir
                        rel_path = os.path.relpath(file_path, sources_dir)

                        # Extract the lines with this method call
                        lines = content.split('\n')
                        for line_num, line in enumerate(lines, start=1):
                            if 'setWebContentsDebuggingEnabled' in line:
                                webview_debug_files.append({
                                    'file': rel_path,
                                    'line_num': line_num,
                                    'line_content': line.strip()
                                })

                    # Check for FLAG_DEBUGGABLE references
                    if 'FLAG_DEBUGGABLE' in content:
                        rel_path = os.path.relpath(file_path, sources_dir)
                        flag_debuggable_files.append(rel_path)

                except Exception:
                    # Skip files that can't be read
                    pass

    print(f"[+] Found {len(webview_debug_files)} occurrence(s) of setWebContentsDebuggingEnabled")
    print(f"[+] Found {len(flag_debuggable_files)} file(s) referencing FLAG_DEBUGGABLE")

    return {
        'webview_debug_occurrences': webview_debug_files,
        'flag_debuggable_files': flag_debuggable_files
    }


def analyze_webview_debug_context(sources_dir, webview_debug_files):
    """
    Analyze if WebView debugging is properly conditional on FLAG_DEBUGGABLE.

    Args:
        sources_dir: Path to jadx decompiled sources
        webview_debug_files: List of files with WebView debugging calls

    Returns:
        list: Files with unconditional or improperly conditional WebView debugging
    """
    print(f"[+] Analyzing WebView debugging context")

    insecure_files = []

    for occurrence in webview_debug_files:
        file_path = os.path.join(sources_dir, occurrence['file'])

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # Get the method/class context around the setWebContentsDebuggingEnabled call
            lines = content.split('\n')
            line_num = occurrence['line_num']

            # Look at surrounding lines (20 lines before and after)
            start_line = max(0, line_num - 20)
            end_line = min(len(lines), line_num + 20)
            context = '\n'.join(lines[start_line:end_line])

            # Check if FLAG_DEBUGGABLE is checked in the context
            # Common patterns:
            # - (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0
            # - BuildConfig.DEBUG
            # - if (debuggable)

            has_flag_check = 'FLAG_DEBUGGABLE' in context
            has_build_config_check = 'BuildConfig.DEBUG' in context or 'BuildConfig.debug' in context

            # Check if it's setWebContentsDebuggingEnabled(true) - explicitly true
            line_content = occurrence['line_content']
            is_explicit_true = 'setWebContentsDebuggingEnabled(true)' in line_content or \
                              'setWebContentsDebuggingEnabled (true)' in line_content

            # If it's explicitly set to true without proper checks, it's insecure
            if is_explicit_true and not (has_flag_check or has_build_config_check):
                insecure_files.append({
                    'file': occurrence['file'],
                    'line_num': line_num,
                    'line_content': line_content,
                    'reason': 'setWebContentsDebuggingEnabled(true) without FLAG_DEBUGGABLE or BuildConfig.DEBUG check'
                })

        except Exception:
            # Skip files that can't be analyzed
            pass

    return insecure_files


def analyze_debugging_detection(apktool_dir, sources_dir, test_id="MASTG-CODE-2 - Testing for Debugging Flags and WebView Debugging"):
    """
    Complete debugging detection analysis workflow.

    Args:
        apktool_dir: Path to apktool decompiled directory
        sources_dir: Path to jadx decompiled sources
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
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

    print(f"[+] Analyzing debugging flags and WebView debugging...")
    print()

    # Check android:debuggable flag
    debuggable_info = check_debuggable(manifest_path)

    # Search for WebView debugging
    webview_search = search_webview_debugging(sources_dir)

    # Analyze WebView debugging context
    insecure_webview = []
    if webview_search['webview_debug_occurrences']:
        insecure_webview = analyze_webview_debug_context(
            sources_dir,
            webview_search['webview_debug_occurrences']
        )

    # Print results
    print()
    print("[*] Debugging Detection Analysis Results:")
    print("-" * 80)
    print()

    # Report android:debuggable status
    print("DEBUGGABLE FLAG IN MANIFEST:")
    if debuggable_info['found']:
        debuggable_status = "true (INSECURE)" if debuggable_info['debuggable'] else "false (secure)"
        print(f"  android:debuggable: {debuggable_status}")
    else:
        print(f"  android:debuggable: not set (defaults to false)")
    print()

    if debuggable_info['debuggable']:
        print("[!] EXCEPTION: android:debuggable is set to true")
        print()
    else:
        print("[+] android:debuggable is not enabled")
        print()

    # Report WebView debugging status
    print("WEBVIEW DEBUGGING:")
    print(f"  setWebContentsDebuggingEnabled calls: {len(webview_search['webview_debug_occurrences'])}")
    print(f"  FLAG_DEBUGGABLE references:           {len(webview_search['flag_debuggable_files'])}")
    print(f"  Insecure WebView debugging:           {len(insecure_webview)}")
    print()

    if insecure_webview:
        print(f"[!] EXCEPTION: Found {len(insecure_webview)} insecure WebView debugging configuration(s):")
        print()
        for item in insecure_webview[:5]:  # Show first 5
            print(f"  File: {item['file']}:{item['line_num']}")
            print(f"    {item['line_content']}")
            print(f"    Issue: {item['reason']}")
            print()

        if len(insecure_webview) > 5:
            print(f"  ... and {len(insecure_webview) - 5} more occurrence(s)")
            print()
    elif webview_search['webview_debug_occurrences']:
        print("[+] All WebView debugging calls are properly conditional")
        print()
    else:
        print("[+] No WebView debugging enabled")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  android:debuggable:           {'true (FAIL)' if debuggable_info['debuggable'] else 'false or not set (PASS)'}")
    print(f"  Insecure WebView debugging:   {len(insecure_webview)} occurrence(s)")
    print()

    # Determine if test passed
    has_issues = debuggable_info['debuggable'] or len(insecure_webview) > 0

    if has_issues:
        issues = []
        if debuggable_info['debuggable']:
            issues.append("android:debuggable enabled")
        if insecure_webview:
            issues.append(f"{len(insecure_webview)} insecure WebView debugging")
        print(f"[!] FAIL: {', '.join(issues)}")
    else:
        print("[+] PASS: No debugging flags or insecure WebView debugging detected")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'debuggable': debuggable_info['debuggable'],
        'debuggable_explicitly_set': debuggable_info['found'],
        'webview_debug_count': len(webview_search['webview_debug_occurrences']),
        'flag_debuggable_refs': len(webview_search['flag_debuggable_files']),
        'insecure_webview_count': len(insecure_webview),
        'insecure_webview': insecure_webview
    }
