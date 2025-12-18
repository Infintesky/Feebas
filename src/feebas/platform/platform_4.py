#!/usr/bin/env python3
"""Android Exported Components Analysis (PLATFORM-4)."""
import os
import re
import xml.etree.ElementTree as ET
from utils.adb import run_command


def parse_manifest_for_exported_components(apktool_dir):
    """
    Parse AndroidManifest.xml to find exported components.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        dict: {
            'activities': [{'name': str, 'has_permission': bool, 'permission': str}],
            'services': [...],
            'receivers': [...],
            'success': bool
        }
    """
    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print(f"[-] Error: AndroidManifest.xml not found at {manifest_path}")
        return {'success': False}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Android namespace
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        exported_activities = []
        exported_services = []
        exported_receivers = []

        # Find all activities with android:exported="true"
        for activity in root.findall('.//activity', ns):
            exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
            if exported == 'true':
                name = activity.get('{http://schemas.android.com/apk/res/android}name')
                permission = activity.get('{http://schemas.android.com/apk/res/android}permission')
                exported_activities.append({
                    'name': name,
                    'has_permission': permission is not None,
                    'permission': permission if permission else None
                })

        # Find all services with android:exported="true"
        for service in root.findall('.//service', ns):
            exported = service.get('{http://schemas.android.com/apk/res/android}exported')
            if exported == 'true':
                name = service.get('{http://schemas.android.com/apk/res/android}name')
                permission = service.get('{http://schemas.android.com/apk/res/android}permission')
                exported_services.append({
                    'name': name,
                    'has_permission': permission is not None,
                    'permission': permission if permission else None
                })

        # Find all receivers with android:exported="true"
        for receiver in root.findall('.//receiver', ns):
            exported = receiver.get('{http://schemas.android.com/apk/res/android}exported')
            if exported == 'true':
                name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                permission = receiver.get('{http://schemas.android.com/apk/res/android}permission')
                exported_receivers.append({
                    'name': name,
                    'has_permission': permission is not None,
                    'permission': permission if permission else None
                })

        return {
            'activities': exported_activities,
            'services': exported_services,
            'receivers': exported_receivers,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return {'success': False}


def check_exported_content_providers(package_name):
    """
    Check for exported ContentProviders using adb.

    Args:
        package_name: Android package name

    Returns:
        dict: {'providers': [str], 'success': bool}
    """
    print(f"[+] Checking for exported ContentProviders...")

    # Run: adb shell dumpsys package <package name> | grep -o "Provider{[\w\d\s\./]+}" | sort -u
    result = run_command(
        ['adb', 'shell', 'dumpsys', 'package', package_name],
        timeout=30
    )

    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to run dumpsys command")
        return {'providers': [], 'success': False}

    output = result.stdout if result.stdout else ""

    # Parse the output to find Provider{...} patterns
    provider_pattern = r'Provider\{[\w\d\s\./]+\}'
    providers = re.findall(provider_pattern, output)

    # Remove duplicates and sort
    unique_providers = sorted(set(providers))

    return {
        'providers': unique_providers,
        'success': True
    }


def check_mutable_pending_intents(sources_dir):
    """
    Check for mutable PendingIntent usage in decompiled source code.

    Args:
        sources_dir: Directory containing jadx decompiled Java sources

    Returns:
        dict: {
            'mutable_intents': [{'file': str, 'line': int, 'method': str, 'code': str}],
            'success': bool
        }
    """
    print(f"[+] Checking for mutable PendingIntent usage...")

    if not os.path.exists(sources_dir):
        print(f"[-] Error: Sources directory not found: {sources_dir}")
        return {'mutable_intents': [], 'success': False}

    # Methods to search for
    target_methods = [
        'getActivity',
        'getActivities',
        'getForegroundService',
        'getService'
    ]

    mutable_intents = []

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
                                if f'PendingIntent.{method}' in line or f'PendingIntent .{method}' in line:
                                    # Check if this line or surrounding context indicates mutability
                                    # Look for FLAG_MUTABLE or absence of FLAG_IMMUTABLE

                                    # Get surrounding context (5 lines before and after)
                                    start = max(0, line_num - 6)
                                    end = min(len(lines), line_num + 5)
                                    context = '\n'.join(lines[start:end])

                                    # Check for mutability flags
                                    has_flag_mutable = 'FLAG_MUTABLE' in context
                                    has_flag_immutable = 'FLAG_IMMUTABLE' in context

                                    # Flag as issue if:
                                    # 1. Explicitly uses FLAG_MUTABLE, OR
                                    # 2. Doesn't use FLAG_IMMUTABLE (missing protection)
                                    if has_flag_mutable or not has_flag_immutable:
                                        mutable_intents.append({
                                            'file': relative_path,
                                            'line': line_num,
                                            'method': method,
                                            'code': line.strip(),
                                            'has_flag_mutable': has_flag_mutable,
                                            'has_flag_immutable': has_flag_immutable
                                        })

                except Exception as e:
                    # Skip files that can't be read
                    continue

        return {
            'mutable_intents': mutable_intents,
            'success': True
        }

    except Exception as e:
        print(f"[-] Error checking for mutable PendingIntents: {e}")
        return {'mutable_intents': [], 'success': False}


def analyze_exported_components(package_name, apktool_dir, sources_dir, test_id="MASTG-PLATFORM-4 - Testing Exported Components"):
    """
    Analyze exported components for security issues.

    Args:
        package_name: Android package name
        apktool_dir: Directory containing apktool decompiled files
        sources_dir: Directory containing jadx decompiled Java sources
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Parse AndroidManifest.xml for exported components
    print(f"[+] Parsing AndroidManifest.xml for exported components...")
    manifest_results = parse_manifest_for_exported_components(apktool_dir)

    if not manifest_results['success']:
        print("\n[!] FAIL: Failed to parse AndroidManifest.xml")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'Failed to parse manifest'
        }

    # Check for exported ContentProviders
    provider_results = check_exported_content_providers(package_name)

    # Check for mutable PendingIntent usage
    pending_intent_results = check_mutable_pending_intents(sources_dir)

    # Print results
    print()
    print("[*] Exported Components Analysis Results:")
    print("-" * 80)

    # Activities
    activities = manifest_results['activities']
    if activities:
        print(f"\n[*] Exported Activities ({len(activities)}):")
        for activity in activities:
            if activity['has_permission']:
                print(f"  [+] {activity['name']}")
                print(f"      Permission: {activity['permission']}")
            else:
                print(f"  [!] {activity['name']} (NO PERMISSION REQUIRED)")
    else:
        print("\n[+] No exported activities found")

    # Services
    services = manifest_results['services']
    if services:
        print(f"\n[*] Exported Services ({len(services)}):")
        for service in services:
            if service['has_permission']:
                print(f"  [+] {service['name']}")
                print(f"      Permission: {service['permission']}")
            else:
                print(f"  [!] {service['name']} (NO PERMISSION REQUIRED)")
    else:
        print("\n[+] No exported services found")

    # Receivers
    receivers = manifest_results['receivers']
    if receivers:
        print(f"\n[*] Exported Receivers ({len(receivers)}):")
        for receiver in receivers:
            if receiver['has_permission']:
                print(f"  [+] {receiver['name']}")
                print(f"      Permission: {receiver['permission']}")
            else:
                print(f"  [!] {receiver['name']} (NO PERMISSION REQUIRED)")
    else:
        print("\n[+] No exported receivers found")

    # ContentProviders
    if provider_results['success']:
        providers = provider_results['providers']
        if providers:
            print(f"\n[*] Exported ContentProviders ({len(providers)}):")
            for provider in providers:
                print(f"  [!] {provider}")
        else:
            print("\n[+] No exported ContentProviders found")
    else:
        print("\n[!] Failed to check for exported ContentProviders")

    # Mutable PendingIntents
    if pending_intent_results['success']:
        mutable_intents = pending_intent_results['mutable_intents']
        if mutable_intents:
            print(f"\n[*] Mutable PendingIntent Usage ({len(mutable_intents)}):")
            for intent in mutable_intents:
                print(f"  [!] {intent['file']}:{intent['line']}")
                print(f"      Method: PendingIntent.{intent['method']}")
                if intent['has_flag_mutable']:
                    print(f"      Issue: Explicitly uses FLAG_MUTABLE")
                else:
                    print(f"      Issue: Missing FLAG_IMMUTABLE")
                print(f"      Code: {intent['code']}")
        else:
            print("\n[+] No mutable PendingIntent usage found")
    else:
        print("\n[!] Failed to check for mutable PendingIntent usage")

    print("-" * 80)
    print()

    # Determine if test passed
    # Test fails if there are exported components without permissions or mutable PendingIntents
    unprotected_activities = [a for a in activities if not a['has_permission']]
    unprotected_services = [s for s in services if not s['has_permission']]
    unprotected_receivers = [r for r in receivers if not r['has_permission']]
    has_exported_providers = len(provider_results.get('providers', [])) > 0
    has_mutable_intents = len(pending_intent_results.get('mutable_intents', [])) > 0

    has_issues = (
        len(unprotected_activities) > 0 or
        len(unprotected_services) > 0 or
        len(unprotected_receivers) > 0 or
        has_exported_providers or
        has_mutable_intents
    )

    if has_issues:
        issues = []
        if unprotected_activities:
            issues.append(f"{len(unprotected_activities)} unprotected exported activity(ies)")
        if unprotected_services:
            issues.append(f"{len(unprotected_services)} unprotected exported service(s)")
        if unprotected_receivers:
            issues.append(f"{len(unprotected_receivers)} unprotected exported receiver(s)")
        if has_exported_providers:
            issues.append(f"{len(provider_results['providers'])} exported ContentProvider(s)")
        if has_mutable_intents:
            issues.append(f"{len(pending_intent_results['mutable_intents'])} mutable PendingIntent(s)")
        print(f"[!] FAIL: Found {', '.join(issues)}")
    else:
        print("[+] PASS: All exported components are properly protected")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'activities': activities,
        'services': services,
        'receivers': receivers,
        'providers': provider_results.get('providers', []),
        'mutable_intents': pending_intent_results.get('mutable_intents', []),
        'unprotected_activities': unprotected_activities,
        'unprotected_services': unprotected_services,
        'unprotected_receivers': unprotected_receivers
    }
