#!/usr/bin/env python3
"""Network security analysis module (NETWORK-1)."""
import os
import re
import xml.etree.ElementTree as ET

# HTTP URL Whitelist - Safe URLs that should not trigger security warnings
HTTP_URL_WHITELIST = [
    "http://schemas.android.com/apk/res/android",
    "http://schemas.android.com/apk/res-auto",
    "http://ns.adobe.com/xap/1.0/",
    "http://www.w3.org/2000/svg",
    "http://localhost/",
]


def search_hardcoded_http_urls(sources_dir):
    """
    Search for hardcoded HTTP URLs in decompiled source code.
    Excludes URLs in HTTP_URL_WHITELIST (defined in config.py).

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, url) for HTTP URLs found
    """
    print(f"[+] Searching for hardcoded HTTP URLs (excluding whitelisted URLs)")

    matches = []

    # Pattern for HTTP URLs (not HTTPS)
    http_pattern = r'http://[a-zA-Z0-9./?=_\-&%#]+'
    pattern = re.compile(http_pattern)

    for root, _, files in os.walk(sources_dir):
        for file in files:
            # Skip non-Java files
            if not file.endswith('.java'):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, start=1):
                        for match in pattern.finditer(line):
                            url = match.group(0)

                            # Check if URL is in whitelist
                            is_whitelisted = False
                            for whitelist_url in HTTP_URL_WHITELIST:
                                if url.startswith(whitelist_url):
                                    is_whitelisted = True
                                    break

                            # Only add if not whitelisted
                            if not is_whitelisted:
                                matches.append((file_path, line_num, url))
            except Exception:
                continue

    print(f"[+] Found {len(matches)} hardcoded HTTP URLs (excluding whitelisted)")
    return matches


def check_cleartext_traffic(apktool_dir):
    """
    Check if cleartext traffic is allowed in AndroidManifest.xml.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        dict: {'cleartext_allowed': bool, 'manifest_path': str} or None on error
    """
    print(f"[+] Checking cleartext traffic configuration")

    try:
        # Parse AndroidManifest.xml
        manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

        if not os.path.exists(manifest_path):
            print(f"[-] Error: AndroidManifest.xml not found in apktool directory")
            return None

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Look for android:usesCleartextTraffic attribute in <application> tag
        # Default is true for API < 28, false for API >= 28
        # If not specified, we'll assume it could be true (depends on targetSdkVersion)

        cleartext_allowed = None  # None means not specified

        for application in root.findall('application'):
            # Check for usesCleartextTraffic attribute
            # The attribute might be in android namespace
            for key, value in application.attrib.items():
                if 'usesCleartextTraffic' in key:
                    cleartext_allowed = value.lower() == 'true'
                    break

        print(f"[+] Cleartext traffic setting: {cleartext_allowed if cleartext_allowed is not None else 'not specified (depends on targetSdkVersion)'}")

        return {
            'cleartext_allowed': cleartext_allowed,
            'manifest_path': manifest_path
        }

    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return None


def search_custom_http_sockets(sources_dir):
    """
    Search for socket classes that might be used for custom HTTP connections.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, class_name) for socket usage
    """
    print(f"[+] Searching for custom HTTP socket connections")

    matches = []

    # Socket classes that might indicate custom HTTP implementation
    socket_classes = [
        'java.net.Socket',
        'javax.net.ssl.SSLSocket',
        'java.net.ServerSocket',
        'java.net.SocketFactory',
        'javax.net.ssl.SSLSocketFactory'
    ]

    for root, _, files in os.walk(sources_dir):
        for file in files:
            # Skip non-Java files
            if not file.endswith('.java'):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for socket_class in socket_classes:
                        # Escape dots for regex
                        escaped_class = socket_class.replace('.', r'\.')
                        pattern = re.compile(rf'\b{escaped_class}\b')

                        for match in pattern.finditer(content):
                            line_num = content[:match.start()].count('\n') + 1
                            matches.append((file_path, line_num, socket_class))
            except Exception:
                continue

    print(f"[+] Found {len(matches)} instances of socket class usage")
    return matches


def print_network_results(http_urls, cleartext_info, custom_sockets):
    """Print network security analysis results."""
    print()

    has_issues = False

    # Report hardcoded HTTP URLs (CRITICAL)
    if http_urls:
        has_issues = True
        print(f"[!] CRITICAL: Hardcoded HTTP URLs detected ({len(http_urls)} instances):")
        print("    (Whitelisted URLs excluded from this report)")
        print("-" * 60)
        for file_path, line_num, url in http_urls:
            print(f"  {file_path}:{line_num} - {url}")
        print("-" * 60)
        print()

    # Report cleartext traffic configuration
    if cleartext_info:
        cleartext_allowed = cleartext_info.get('cleartext_allowed')

        if cleartext_allowed is True:
            has_issues = True
            print("[!] CRITICAL: Cleartext traffic is explicitly ALLOWED")
            print("    (android:usesCleartextTraffic=\"true\" in AndroidManifest.xml)")
            print()

            # If cleartext is allowed, report custom socket usage
            if custom_sockets:
                print(f"[!] WARNING: Custom socket connections detected ({len(custom_sockets)} instances):")
                print("    (May be used for custom HTTP connections)")
                print("-" * 60)
                socket_count = {}
                for file_path, line_num, socket_class in custom_sockets:
                    print(f"  {file_path}:{line_num} - {socket_class}")
                    socket_count[socket_class] = socket_count.get(socket_class, 0) + 1
                print()
                print("  Socket classes found:")
                for socket_class, count in socket_count.items():
                    print(f"    - {socket_class}: {count} instance(s)")
                print("-" * 60)
                print()

        elif cleartext_allowed is False:
            print("[+] PASS: Cleartext traffic is explicitly DISABLED")
            print("    (android:usesCleartextTraffic=\"false\" in AndroidManifest.xml)")
            print()
        else:
            print("[*] INFO: Cleartext traffic setting not specified in manifest")
            print("    (Default behavior depends on targetSdkVersion)")
            print("    (API < 28: allowed by default, API >= 28: blocked by default)")
            print()
    else:
        print("[!] WARNING: Could not determine cleartext traffic configuration")
        print()

    # Final assessment
    if has_issues:
        issues = []
        if http_urls:
            issues.append("hardcoded HTTP URLs detected")
        if cleartext_info and cleartext_info.get('cleartext_allowed') is True:
            issues.append("cleartext traffic enabled")
        print(f"\n[!] FAIL: {', '.join(issues)}")
    else:
        print("\n[+] PASS: No critical network security issues detected")

    print("=" * 80)


def analyze_network_security(sources_dir, apktool_dir, test_id="MASTG-NETWORK-1 - Testing Data Encryption on the Network"):
    """
    Analyze network security in decompiled source code and manifest.

    Args:
        sources_dir: Path to decompiled sources directory (from jadx)
        apktool_dir: Path to apktool decompiled directory
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Search for hardcoded HTTP URLs
    http_urls = search_hardcoded_http_urls(sources_dir)

    # Check cleartext traffic configuration
    cleartext_info = check_cleartext_traffic(apktool_dir)

    # Search for custom HTTP sockets (only if cleartext is allowed)
    custom_sockets = []
    if cleartext_info and cleartext_info.get('cleartext_allowed') is True:
        custom_sockets = search_custom_http_sockets(sources_dir)

    # Print results
    print_network_results(http_urls, cleartext_info, custom_sockets)

    # Test passes if no HTTP URLs and cleartext traffic is disabled
    cleartext_allowed = cleartext_info.get('cleartext_allowed') if cleartext_info else None
    passed = len(http_urls) == 0 and cleartext_allowed is not True

    return {
        'passed': passed,
        'http_urls_count': len(http_urls),
        'cleartext_allowed': cleartext_allowed,
        'custom_sockets_count': len(custom_sockets),
        'http_urls': http_urls,
        'custom_sockets': custom_sockets
    }
