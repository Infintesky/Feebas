#!/usr/bin/env python3
"""Cryptographic API usage analysis module (CRYPTO-2, CRYPTO-3, CRYPTO-4)."""
import os
import re


def search_crypto_api_usage(sources_dir):
    """
    Search for cryptographic API usage in decompiled source code.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        dict: Dictionary with API types as keys and lists of (file_path, line_num) tuples as values
    """
    print(f"[+] Searching for cryptographic API usage")

    # Pattern for cryptographic APIs
    crypto_api_pattern = r'\b(Cipher|Mac|MessageDigest|Signature|Key|PrivateKey|PublicKey|SecretKey|getInstance|generateKey|KeyStoreException|CertificateException|NoSuchAlgorithmException)\b'
    pattern = re.compile(crypto_api_pattern)

    api_usage = {}

    for root, _, files in os.walk(sources_dir):
        for file in files:
            # Skip non-Java files
            if not file.endswith('.java'):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, start=1):
                        matches = pattern.findall(line)
                        for api_name in matches:
                            if api_name not in api_usage:
                                api_usage[api_name] = []
                            api_usage[api_name].append((file_path, line_num))
            except Exception:
                continue

    print(f"[+] Found {sum(len(v) for v in api_usage.values())} cryptographic API usages across {len(api_usage)} different APIs")
    return api_usage


def detect_weak_primitives(sources_dir):
    """
    Detect usage of weak cryptographic primitives.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, primitive_type, description)
    """
    print(f"[+] Detecting weak cryptographic primitives")

    weak_primitives = []

    # Patterns for weak primitives
    weak_patterns = [
        (r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1|SHA1)"\s*\)', "Weak hash algorithm"),
        (r'Mac\.getInstance\s*\(\s*"(HmacMD5|HmacSHA1)"\s*\)', "Weak MAC algorithm"),
        (r'Signature\.getInstance\s*\(\s*"(MD5withRSA|SHA1withRSA)"\s*\)', "Weak signature algorithm"),
        (r'(ECB|Electronic Codebook)', "Insecure cipher mode (ECB)"),
        (r'NoPadding', "No padding (potential security risk)"),
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
                    for pattern_str, description in weak_patterns:
                        pattern = re.compile(pattern_str)
                        for match in pattern.finditer(content):
                            line_num = content[:match.start()].count('\n') + 1
                            primitive_type = match.group(1) if match.groups() else "Unknown"
                            weak_primitives.append((file_path, line_num, primitive_type, description))
            except Exception:
                continue

    print(f"[+] Found {len(weak_primitives)} instances of weak cryptographic primitives")
    return weak_primitives


def print_crypto_api_results(api_usage, weak_primitives):
    """Print cryptographic API usage analysis results."""
    print()

    has_issues = False

    # Report weak primitives (critical)
    if weak_primitives:
        has_issues = True
        print("[!] CRITICAL: Weak cryptographic primitives detected:")
        print("-" * 60)
        primitive_count = {}
        for file_path, line_num, primitive_type, description in weak_primitives:
            print(f"  {file_path}:{line_num} - {primitive_type} ({description})")
            key = f"{primitive_type} ({description})"
            primitive_count[key] = primitive_count.get(key, 0) + 1
        print()
        print("  Weak primitives found:")
        for primitive, count in primitive_count.items():
            print(f"    - {primitive}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report API usage summary
    if api_usage:
        print("[*] Cryptographic API usage detected:")
        print("-" * 60)
        print("  API types found:")
        for api_name, usages in sorted(api_usage.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"    - {api_name}: {len(usages)} instance(s)")
        print("-" * 60)
        print()

    # Final assessment
    if has_issues:
        print("\n[!] FAIL: weak cryptographic primitives detected")
    else:
        print("\n[+] PASS: No weak cryptographic primitives detected")

    print("=" * 80)


def analyze_crypto_api_usage(sources_dir, test_id="MASTG-CRYPTO-2/3/4 - Cryptographic API Usage Analysis"):
    """
    Analyze cryptographic API usage in decompiled source code.

    Args:
        sources_dir: Path to decompiled sources directory
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Search for crypto API usage
    api_usage = search_crypto_api_usage(sources_dir)

    # Detect weak primitives
    weak_primitives = detect_weak_primitives(sources_dir)

    # Print results
    print_crypto_api_results(api_usage, weak_primitives)

    # Test passes if no weak primitives are found
    passed = len(weak_primitives) == 0

    return {
        'passed': passed,
        'api_usage_count': sum(len(v) for v in api_usage.values()),
        'weak_primitives_count': len(weak_primitives),
        'weak_primitives': weak_primitives,
        'api_usage': api_usage
    }
