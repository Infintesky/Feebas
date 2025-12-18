#!/usr/bin/env python3
"""Cryptographic implementation analysis module."""
import os
import re


def search_crypto_keywords(decompiled_dir, keywords):
    """
    Search for cryptographic keywords in decompiled source code.

    Args:
        decompiled_dir: Directory containing decompiled source
        keywords: Regex pattern to search for (e.g., "SecretKeySpec")

    Returns:
        list: List of tuples (file_path, line_number, line_content) for matches
    """
    print(f"[+] Searching for crypto keywords: {keywords}")

    matches = []
    pattern = re.compile(keywords, re.IGNORECASE)

    # Search recursively through all .java files
    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, start=1):
                            if pattern.search(line):
                                matches.append((file_path, line_num, line.strip()))
                except Exception:
                    # Skip files that can't be read
                    continue

    print(f"[+] Found {len(matches)} matches for crypto keywords")
    return matches


def search_hardcoded_keys(decompiled_dir):
    """
    Search for potential hardcoded cryptographic keys in source code.

    Args:
        decompiled_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_number, line_content) for potential keys
    """
    print(f"[+] Searching for hardcoded cryptographic keys")

    matches = []

    # Patterns that might indicate hardcoded keys:
    # - Byte arrays with many elements
    # - Long hex strings
    # - Base64-like strings assigned to key-related variables
    patterns = [
        # Byte arrays like: new byte[]{0x1a, 0x2b, ...} with 16+ elements
        (r'new\s+byte\s*\[\s*\]\s*\{(?:[^}]*,){15,}[^}]*\}', "Byte array (16+ elements)"),
        # Hex strings like: "0a1b2c3d..." (32+ hex chars)
        (r'["\']([0-9a-fA-F]{32,})["\']', "Hex string (32+ chars)"),
        # Variables with 'key' in name assigned to strings
        (r'(?:secret|Secret|KEY|Key|key|PASSWORD|Password|password)\s*=\s*["\']([A-Za-z0-9+/=]{16,})["\']', "Key variable assignment"),
    ]

    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, start=1):
                            for pattern_str, pattern_desc in patterns:
                                pattern = re.compile(pattern_str)
                                if pattern.search(line):
                                    matches.append((file_path, line_num, line.strip(), pattern_desc))
                                    break  # Only match once per line
                except Exception:
                    continue

    print(f"[+] Found {len(matches)} potential hardcoded keys")
    return matches


def search_insecure_algorithms(decompiled_dir):
    """
    Search for usage of insecure cryptographic algorithms.

    Args:
        decompiled_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_number, line_content, algorithm) for insecure usage
    """
    print(f"[+] Searching for insecure cryptographic algorithms")

    matches = []

    # Patterns for insecure algorithms
    insecure_patterns = [
        (r'Cipher\.getInstance\s*\(\s*"(DES|DESede|TripleDES|3DES|RC4|Blowfish)[^"]*"\s*\)', "Cipher.getInstance"),
        (r'SecretKeyFactory\.getInstance\s*\(\s*"(DES|DESede|TripleDES|3DES|RC4|Blowfish)"\s*\)', "SecretKeyFactory.getInstance"),
        (r'KeyGenerator\.getInstance\s*\(\s*"(DES|DESede|TripleDES|3DES|RC4|Blowfish)"\s*\)', "KeyGenerator.getInstance"),
    ]

    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_str, method_name in insecure_patterns:
                            pattern = re.compile(pattern_str)
                            for match in pattern.finditer(content):
                                # Find line number
                                line_num = content[:match.start()].count('\n') + 1
                                # Get the line content
                                lines = content.split('\n')
                                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                                # Get the algorithm name from the match
                                algorithm = match.group(1)

                                matches.append((file_path, line_num, line_content, algorithm, method_name))
                except Exception:
                    continue

    print(f"[+] Found {len(matches)} instances of insecure algorithms")
    return matches


def search_secure_algorithms(decompiled_dir):
    """
    Search for usage of secure cryptographic algorithms.

    Args:
        decompiled_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_number, algorithm) for secure usage
    """
    print(f"[+] Searching for secure cryptographic algorithms")

    matches = []

    # Patterns for secure algorithms (AES, RSA, etc.)
    secure_patterns = [
        (r'Cipher\.getInstance\s*\(\s*"(AES|RSA)[^"]*"\s*\)', "Cipher.getInstance"),
        (r'SecretKeyFactory\.getInstance\s*\(\s*"(PBKDF2|AES)"\s*\)', "SecretKeyFactory.getInstance"),
        (r'KeyGenerator\.getInstance\s*\(\s*"(AES|HmacSHA256|HmacSHA512)"\s*\)', "KeyGenerator.getInstance"),
    ]

    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_str, method_name in secure_patterns:
                            pattern = re.compile(pattern_str)
                            for match in pattern.finditer(content):
                                # Find line number
                                line_num = content[:match.start()].count('\n') + 1
                                # Get the algorithm name from the match
                                algorithm = match.group(1)

                                matches.append((file_path, line_num, algorithm, method_name))
                except Exception:
                    continue

    print(f"[+] Found {len(matches)} instances of secure algorithms")
    return matches


def print_crypto_results(crypto_matches, hardcoded_keys, insecure_algos, secure_algos):
    """Print cryptographic analysis results in a formatted way."""
    print()

    has_issues = False

    # Report secure algorithms first
    if secure_algos:
        print("[+] Secure cryptographic algorithms detected:")
        print("-" * 60)
        algo_count = {}
        for file_path, line_num, algorithm, method in secure_algos:
            algo_count[algorithm] = algo_count.get(algorithm, 0) + 1

        print("  Secure algorithms found:")
        for algo, count in algo_count.items():
            print(f"    - {algo}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report insecure algorithms (most critical)
    if insecure_algos:
        has_issues = True
        print("[!] CRITICAL: Insecure cryptographic algorithms detected:")
        print("-" * 60)
        algo_count = {}
        for file_path, line_num, _, algorithm, method in insecure_algos:
            print(f"  {file_path}:{line_num} - {algorithm} (via {method})")
            algo_count[algorithm] = algo_count.get(algorithm, 0) + 1
        print()
        print("  Insecure algorithms found:")
        for algo, count in algo_count.items():
            print(f"    - {algo}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report hardcoded keys
    if hardcoded_keys:
        has_issues = True
        print("[!] WARNING: Potential hardcoded cryptographic keys detected:")
        print("-" * 60)
        pattern_count = {}
        for file_path, line_num, _, pattern_desc in hardcoded_keys:
            print(f"  {file_path}:{line_num} - {pattern_desc}")
            pattern_count[pattern_desc] = pattern_count.get(pattern_desc, 0) + 1
        print()
        print("  Potential key types found:")
        for pattern_type, count in pattern_count.items():
            print(f"    - {pattern_type}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report crypto usage summary
    if crypto_matches:
        print(f"[*] Cryptographic API usage found: {len(crypto_matches)} instances")
        print(f"    (Review source code for proper implementation)")
        print()

    # Final assessment
    if has_issues:
        issues = []
        if insecure_algos:
            issues.append("insecure algorithms detected")
        if hardcoded_keys:
            issues.append("hardcoded keys detected")
        print(f"\n[!] FAIL: {', '.join(issues)}")
    else:
        print("\n[+] PASS: No obvious cryptographic issues detected")

    print("=" * 80)


def analyze_crypto_implementation(sources_dir, test_id="MASTG-CRYPTO-1 - Testing for Insecure Cryptographic Algorithms"):
    """
    Analyze cryptographic implementation in decompiled source code.

    Args:
        sources_dir: Path to decompiled sources directory
        test_id: Test identifier for reporting (default: MASTG-CRYPTO-1)

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Search for cryptographic keywords
    crypto_matches = search_crypto_keywords(sources_dir, r"SecretKeySpec")

    # Search for hardcoded keys
    hardcoded_keys = search_hardcoded_keys(sources_dir)

    # Search for insecure algorithms
    insecure_algos = search_insecure_algorithms(sources_dir)

    # Search for secure algorithms
    secure_algos = search_secure_algorithms(sources_dir)

    # Print results
    print_crypto_results(crypto_matches, hardcoded_keys, insecure_algos, secure_algos)

    # Test passes if no insecure algorithms or hardcoded keys are found
    passed = len(insecure_algos) == 0 and len(hardcoded_keys) == 0

    return {
        'passed': passed,
        'crypto_usage_count': len(crypto_matches),
        'hardcoded_keys_count': len(hardcoded_keys),
        'insecure_algos_count': len(insecure_algos),
        'insecure_algos': insecure_algos,
        'hardcoded_keys': hardcoded_keys
    }