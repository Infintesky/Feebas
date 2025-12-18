#!/usr/bin/env python3
"""Network security configuration analysis module (NETWORK-3)."""
import os
import xml.etree.ElementTree as ET


def find_network_security_config(apktool_dir):
    """
    Find network_security_config.xml in apktool decompiled APK.

    Args:
        apktool_dir: Directory containing apktool decompiled files

    Returns:
        str: Path to network_security_config.xml or None if not found
    """
    print(f"[+] Searching for network_security_config.xml")

    # Common locations for network security config
    possible_paths = [
        os.path.join(apktool_dir, "res", "xml", "network_security_config.xml"),
        os.path.join(apktool_dir, "res", "xml", "network_security_configuration.xml"),
    ]

    for path in possible_paths:
        if os.path.exists(path):
            print(f"[+] Found network_security_config.xml at: {path}")
            return path

    # Search recursively in res folder
    res_dir = os.path.join(apktool_dir, "res")
    if os.path.exists(res_dir):
        for root, _, files in os.walk(res_dir):
            for file in files:
                if "network_security" in file and file.endswith(".xml"):
                    path = os.path.join(root, file)
                    print(f"[+] Found network security config at: {path}")
                    return path

    print(f"[-] network_security_config.xml not found")
    return None


def check_certificate_pinning(config_path):
    """
    Check if certificate pinning (pin-set) is configured.

    Args:
        config_path: Path to network_security_config.xml

    Returns:
        dict: {
            'has_pin_set': bool,
            'pin_sets': list of tuples (domain, pin_count),
            'base_config_pins': int
        }
    """
    print(f"[+] Checking certificate pinning configuration")

    try:
        tree = ET.parse(config_path)
        root = tree.getroot()

        pin_sets = []
        base_config_pins = 0

        # Look for <pin-set> elements
        # Can be in <domain-config> or <base-config>

        # Check domain-config elements
        for domain_config in root.findall('.//domain-config'):
            domain_names = []
            for domain in domain_config.findall('domain'):
                if domain.text:
                    domain_names.append(domain.text.strip())

            # Check for pin-set in this domain-config
            pin_set = domain_config.find('pin-set')
            if pin_set is not None:
                pins = pin_set.findall('pin')
                pin_count = len(pins)
                if pin_count > 0:
                    domains_str = ', '.join(domain_names) if domain_names else 'unspecified'
                    pin_sets.append((domains_str, pin_count))
                    print(f"[+] Found pin-set for domain(s): {domains_str} ({pin_count} pin(s))")

        # Check base-config
        base_config = root.find('base-config')
        if base_config is not None:
            pin_set = base_config.find('pin-set')
            if pin_set is not None:
                pins = pin_set.findall('pin')
                base_config_pins = len(pins)
                if base_config_pins > 0:
                    print(f"[+] Found pin-set in base-config ({base_config_pins} pin(s))")

        has_pin_set = len(pin_sets) > 0 or base_config_pins > 0

        if not has_pin_set:
            print(f"[-] No certificate pinning (pin-set) configured")

        return {
            'has_pin_set': has_pin_set,
            'pin_sets': pin_sets,
            'base_config_pins': base_config_pins
        }

    except Exception as e:
        print(f"[-] Error parsing network_security_config.xml: {e}")
        return {
            'has_pin_set': False,
            'pin_sets': [],
            'base_config_pins': 0,
            'error': str(e)
        }


def print_network_config_results(config_found, config_path, pinning_info):
    """Print network security configuration analysis results."""
    print()

    has_issues = False

    # Report network security config file
    if not config_found:
        has_issues = True
        print("[!] CRITICAL: network_security_config.xml NOT FOUND")
        print("    (App does not define custom network security configuration)")
        print("    (Using system defaults - may allow user-installed certificates)")
        print()
    else:
        print(f"[+] network_security_config.xml found")
        print(f"    Location: {config_path}")
        print()

        # Report certificate pinning
        if pinning_info:
            if 'error' in pinning_info:
                has_issues = True
                print(f"[!] ERROR: Failed to parse network_security_config.xml")
                print(f"    {pinning_info['error']}")
                print()
            elif not pinning_info.get('has_pin_set'):
                has_issues = True
                print("[!] CRITICAL: Certificate pinning (pin-set) NOT CONFIGURED")
                print("    (App is vulnerable to MitM attacks via rogue certificates)")
                print()
            else:
                # Certificate pinning is configured
                print("[+] Certificate pinning (pin-set) is CONFIGURED")
                print()

                # Show base-config pins
                if pinning_info.get('base_config_pins', 0) > 0:
                    print(f"[+] Base configuration pins: {pinning_info['base_config_pins']} pin(s)")
                    print("    (Applies to all domains by default)")
                    print()

                # Show domain-specific pins
                if pinning_info.get('pin_sets'):
                    print(f"[+] Domain-specific pinning:")
                    print("-" * 60)
                    for domain, pin_count in pinning_info['pin_sets']:
                        print(f"  Domain(s): {domain}")
                        print(f"  Pins: {pin_count}")
                    print("-" * 60)
                    print()

    # Final assessment
    if has_issues:
        if not config_found:
            print("\n[!] FAIL: network_security_config.xml does not exist")
        elif pinning_info and not pinning_info.get('has_pin_set'):
            print("\n[!] FAIL: certificate pinning is not properly configured")
        else:
            print("\n[!] FAIL: network security configuration issues detected")
    else:
        print("\n[+] PASS: Network security configuration and certificate pinning properly configured")

    print("=" * 80)


def analyze_network_security_config(apktool_dir, test_id="MASTG-NETWORK-3 - Testing the Security Provider"):
    """
    Analyze network security configuration and certificate pinning.

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

    try:
        # Find network_security_config.xml
        config_path = find_network_security_config(apktool_dir)
        config_found = config_path is not None

        # Check certificate pinning
        pinning_info = None
        if config_found:
            pinning_info = check_certificate_pinning(config_path)

        # Print results
        print_network_config_results(config_found, config_path, pinning_info)

        # Test passes if config is found AND pinning is configured
        has_pinning = pinning_info and pinning_info.get('has_pin_set', False) if pinning_info else False
        passed = config_found and has_pinning

        return {
            'passed': passed,
            'config_found': config_found,
            'has_pinning': has_pinning,
            'pin_sets_count': len(pinning_info.get('pin_sets', [])) if pinning_info else 0,
            'base_config_pins': pinning_info.get('base_config_pins', 0) if pinning_info else 0,
            'pinning_info': pinning_info
        }

    except Exception as e:
        print(f"[!] ERROR: {e}")
        return None
