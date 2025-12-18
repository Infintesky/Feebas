#!/usr/bin/env python3
"""Android Implicit Intents and WebView SafeBrowsing Analysis (PLATFORM-2)."""
import os
import xml.etree.ElementTree as ET

# Potentially dangerous system actions that could be exploited via implicit intents
DANGEROUS_SYSTEM_ACTIONS = [
    'android.intent.action.VIEW',
    'android.intent.action.SEND',
    'android.intent.action.SENDTO',
    'android.intent.action.SEND_MULTIPLE',
    'android.intent.action.MAIN',
    'android.intent.action.EDIT',
    'android.intent.action.PICK',
    'android.intent.action.GET_CONTENT',
    'android.intent.action.DIAL',
    'android.intent.action.CALL',
    'android.intent.action.WEB_SEARCH',
    'android.intent.action.PROCESS_TEXT'
]


def check_implicit_intents(apktool_dir):
    """
    Check for implicit intents with dangerous system actions in AndroidManifest.xml.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        dict: {
            'implicit_intents': [{'component': str, 'type': str, 'actions': [str]}],
            'success': bool
        }
    """
    print(f"[+] Checking for implicit intents with dangerous actions...")

    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print(f"[-] Error: AndroidManifest.xml not found at {manifest_path}")
        return {'implicit_intents': [], 'success': False}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Android namespace
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        implicit_intents = []

        # Check activities, services, and receivers for intent filters
        for component_type in ['activity', 'service', 'receiver']:
            for component in root.findall(f'.//{component_type}', ns):
                component_name = component.get('{http://schemas.android.com/apk/res/android}name')

                # Find intent filters
                intent_filters = component.findall('.//intent-filter', ns)

                for intent_filter in intent_filters:
                    # Find all actions in this intent filter
                    actions = intent_filter.findall('.//action', ns)

                    dangerous_actions = []
                    for action in actions:
                        action_name = action.get('{http://schemas.android.com/apk/res/android}name')

                        if action_name in DANGEROUS_SYSTEM_ACTIONS:
                            dangerous_actions.append(action_name)

                    # If dangerous actions found, record this intent filter
                    if dangerous_actions:
                        implicit_intents.append({
                            'component': component_name,
                            'type': component_type,
                            'actions': dangerous_actions
                        })

        return {
            'implicit_intents': implicit_intents,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return {'implicit_intents': [], 'success': False}


def check_safebrowsing_disabled(apktool_dir):
    """
    Check if WebView SafeBrowsing is disabled in AndroidManifest.xml.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        dict: {
            'safebrowsing_disabled': bool,
            'success': bool
        }
    """
    print(f"[+] Checking WebView SafeBrowsing configuration...")

    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print(f"[-] Error: AndroidManifest.xml not found at {manifest_path}")
        return {'safebrowsing_disabled': False, 'success': False}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Android namespace
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        # Find application element
        application = root.find('.//application', ns)

        if application is not None:
            # Find all meta-data elements
            meta_data_elements = application.findall('.//meta-data', ns)

            for meta_data in meta_data_elements:
                name = meta_data.get('{http://schemas.android.com/apk/res/android}name')
                value = meta_data.get('{http://schemas.android.com/apk/res/android}value')

                # Check if SafeBrowsing is explicitly disabled
                if name == 'android.webkit.WebView.EnableSafeBrowsing':
                    if value and value.lower() == 'false':
                        return {
                            'safebrowsing_disabled': True,
                            'success': True
                        }

        # SafeBrowsing not disabled (either not present or set to true)
        return {
            'safebrowsing_disabled': False,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return {'safebrowsing_disabled': False, 'success': False}


def analyze_implicit_intents_and_webview(apktool_dir, test_id="MASTG-PLATFORM-2 - Testing Implicit Intents and WebView Configuration"):
    """
    Analyze implicit intents and WebView SafeBrowsing configuration.

    Args:
        apktool_dir: Directory containing apktool decompiled files
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Check implicit intents
    intent_results = check_implicit_intents(apktool_dir)

    if not intent_results['success']:
        print("\n[!] FAIL: Failed to check implicit intents")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check implicit intents'
        }

    # Check SafeBrowsing configuration
    safebrowsing_results = check_safebrowsing_disabled(apktool_dir)

    if not safebrowsing_results['success']:
        print("\n[!] FAIL: Failed to check SafeBrowsing configuration")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to check SafeBrowsing'
        }

    # Print results
    print()
    print("[*] Implicit Intents and WebView Configuration Analysis Results:")
    print("-" * 80)

    implicit_intents = intent_results['implicit_intents']
    safebrowsing_disabled = safebrowsing_results['safebrowsing_disabled']

    # Implicit Intents
    if implicit_intents:
        print(f"\n[!] Implicit Intents with Dangerous System Actions ({len(implicit_intents)}):")
        print()

        # Group by component type
        grouped = {}
        for intent in implicit_intents:
            comp_type = intent['type']
            if comp_type not in grouped:
                grouped[comp_type] = []
            grouped[comp_type].append(intent)

        for comp_type, intents in grouped.items():
            print(f"  [{comp_type.upper()}] - {len(intents)} component(s):")
            for intent in intents:
                print(f"    [!] {intent['component']}")
                for action in intent['actions']:
                    print(f"        Action: {action}")
            print()
    else:
        print("\n[+] No implicit intents with dangerous system actions found")

    # SafeBrowsing
    if safebrowsing_disabled:
        print("[!] WebView SafeBrowsing: DISABLED")
        print("    android.webkit.WebView.EnableSafeBrowsing is set to false")
    else:
        print("[+] WebView SafeBrowsing: ENABLED (default)")

    print("-" * 80)
    print()

    # Determine if test passed
    has_issues = len(implicit_intents) > 0 or safebrowsing_disabled

    if has_issues:
        issues = []
        if implicit_intents:
            issues.append(f"{len(implicit_intents)} implicit intent(s) with dangerous actions")
        if safebrowsing_disabled:
            issues.append("SafeBrowsing disabled")
        print(f"[!] FAIL: Found {', '.join(issues)}")

        if implicit_intents:
            print("[!] Implicit intents with dangerous actions can be exploited by malicious apps")
            print("[!] Recommendation: Validate all intent data and use explicit intents when possible")
        if safebrowsing_disabled:
            print("[!] Disabling SafeBrowsing exposes users to phishing and malware sites")
            print("[!] Recommendation: Remove or set android.webkit.WebView.EnableSafeBrowsing to true")
    else:
        print("[+] PASS: No implicit intent or WebView configuration issues detected")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'implicit_intents': implicit_intents,
        'safebrowsing_disabled': safebrowsing_disabled
    }
