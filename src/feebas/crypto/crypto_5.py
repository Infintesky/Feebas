#!/usr/bin/env python3
"""Cryptographic key security analysis module (CRYPTO-5)."""
import os
import re


def search_crypto_key_usage(sources_dir):
    """
    Search for cryptographic key usage in decompiled source code.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        dict: Dictionary with file paths as keys and list of (line_num, line_content, api_type) tuples
    """
    print(f"[+] Searching for cryptographic key usage")

    # Pattern for cryptographic APIs related to keys
    crypto_api_pattern = r'\b(Cipher|Mac|MessageDigest|Signature|Key|PrivateKey|PublicKey|SecretKey|getInstance|generateKey|KeyStoreException|CertificateException|NoSuchAlgorithmException)\b'
    pattern = re.compile(crypto_api_pattern)

    key_usage = {}

    for root, _, files in os.walk(sources_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, start=1):
                            matches = pattern.findall(line)
                            if matches:
                                if file_path not in key_usage:
                                    key_usage[file_path] = []
                                for api_name in matches:
                                    key_usage[file_path].append((line_num, line.strip(), api_name))
                except Exception:
                    continue

    total_usages = sum(len(v) for v in key_usage.values())
    print(f"[+] Found cryptographic API usage in {len(key_usage)} files ({total_usages} instances)")
    return key_usage


def search_hardcoded_keys(sources_dir):
    """
    Search for hardcoded cryptographic keys in source code.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_number, line_content, pattern_desc) for hardcoded keys
    """
    print(f"[+] Searching for hardcoded cryptographic keys")

    matches = []

    # Patterns that might indicate hardcoded keys
    patterns = [
        # Byte arrays like: new byte[]{0x1a, 0x2b, ...} with 16+ elements
        (r'new\s+byte\s*\[\s*\]\s*\{(?:[^}]*,){15,}[^}]*\}', "Byte array (16+ elements)"),
        # Hex strings like: "0a1b2c3d..." (32+ hex chars)
        (r'["\']([0-9a-fA-F]{32,})["\']', "Hex string (32+ chars)"),
        # Variables with 'key' in name assigned to strings
        (r'(?:secret|Secret|KEY|Key|key|PASSWORD|Password|password)\s*=\s*["\']([A-Za-z0-9+/=]{16,})["\']', "Key variable assignment"),
        # SecretKeySpec with hardcoded values
        (r'SecretKeySpec\s*\(\s*["\']', "SecretKeySpec with string literal"),
        (r'SecretKeySpec\s*\(\s*new\s+byte\s*\[', "SecretKeySpec with byte array"),
    ]

    for root, _, files in os.walk(sources_dir):
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


def search_insecure_key_storage(sources_dir):
    """
    Search for keys stored in insecure locations.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, line_content, storage_type) for insecure storage
    """
    print(f"[+] Searching for insecure key storage")

    matches = []

    # Patterns for insecure key storage
    insecure_storage_patterns = [
        # SharedPreferences usage with key-related variables
        (r'SharedPreferences.*(?:put|get).*(?:key|Key|KEY|secret|Secret|password|Password)', "SharedPreferences"),
        # Keys stored in files
        (r'(?:FileOutputStream|FileWriter).*(?:key|Key|KEY|secret|Secret)', "File storage"),
        # Keys in external storage
        (r'(?:getExternalStorageDirectory|EXTERNAL_STORAGE).*(?:key|Key|KEY|secret|Secret)', "External storage"),
        # Keys in database without encryption
        (r'(?:SQLiteDatabase|ContentValues).*(?:put|insert).*(?:key|Key|KEY|secret|Secret)', "Database storage"),
    ]

    for root, _, files in os.walk(sources_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_str, storage_type in insecure_storage_patterns:
                            pattern = re.compile(pattern_str)
                            for match in pattern.finditer(content):
                                line_num = content[:match.start()].count('\n') + 1
                                lines = content.split('\n')
                                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                                matches.append((file_path, line_num, line_content, storage_type))
                except Exception:
                    continue

    print(f"[+] Found {len(matches)} instances of potentially insecure key storage")
    return matches


def search_keystore_usage(sources_dir):
    """
    Search for proper KeyStore usage (secure key storage).

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num) for KeyStore usage
    """
    print(f"[+] Searching for KeyStore usage (secure key storage)")

    matches = []

    keystore_pattern = r'KeyStore\.getInstance'
    pattern = re.compile(keystore_pattern)

    for root, _, files in os.walk(sources_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in pattern.finditer(content):
                            line_num = content[:match.start()].count('\n') + 1
                            matches.append((file_path, line_num))
                except Exception:
                    continue

    print(f"[+] Found {len(matches)} instances of KeyStore usage")
    return matches


def print_key_security_results(key_usage, hardcoded_keys, insecure_storage, keystore_usage):
    """Print cryptographic key security analysis results."""
    print()

    has_issues = False

    # Report files using cryptographic keys
    if key_usage:
        print(f"[*] Cryptographic key APIs detected in {len(key_usage)} file(s)")
        print()

    # Report hardcoded keys (CRITICAL)
    if hardcoded_keys:
        has_issues = True
        print(f"[!] CRITICAL: Hardcoded cryptographic keys detected ({len(hardcoded_keys)} instances):")
        print("-" * 60)
        key_type_count = {}
        for file_path, line_num, line_content, pattern_desc in hardcoded_keys:
            print(f"  {file_path}:{line_num} - {pattern_desc}")
            key_type_count[pattern_desc] = key_type_count.get(pattern_desc, 0) + 1
        print()
        print("  Key types found:")
        for key_type, count in key_type_count.items():
            print(f"    - {key_type}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report insecure key storage (WARNING)
    if insecure_storage:
        has_issues = True
        print(f"[!] WARNING: Potentially insecure key storage detected ({len(insecure_storage)} instances):")
        print("-" * 60)
        storage_type_count = {}
        for file_path, line_num, line_content, storage_type in insecure_storage:
            print(f"  {file_path}:{line_num} - {storage_type}")
            storage_type_count[storage_type] = storage_type_count.get(storage_type, 0) + 1
        print()
        print("  Storage types found:")
        for storage_type, count in storage_type_count.items():
            print(f"    - {storage_type}: {count} instance(s)")
        print("-" * 60)
        print()

    # Report secure KeyStore usage (POSITIVE)
    if keystore_usage:
        print(f"[+] Secure KeyStore usage detected ({len(keystore_usage)} instances)")
        print("    (Good practice: keys should be stored in Android KeyStore)")
        print()

    # Final assessment
    if has_issues:
        issues = []
        if hardcoded_keys:
            issues.append("hardcoded keys detected")
        if insecure_storage:
            issues.append("insecure key storage detected")
        print(f"\n[!] FAIL: {', '.join(issues)}")
    else:
        if key_usage:
            print("\n[+] PASS: Cryptographic keys appear to be properly secured")
        else:
            print("\n[*] INFO: No cryptographic key usage detected")

    print("=" * 80)


def analyze_key_security(sources_dir, test_id="MASTG-CRYPTO-5 - Testing Key Management"):
    """
    Analyze cryptographic key security in decompiled source code.

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

    # Search for cryptographic key usage
    key_usage = search_crypto_key_usage(sources_dir)

    # Search for hardcoded keys
    hardcoded_keys = search_hardcoded_keys(sources_dir)

    # Search for insecure key storage
    insecure_storage = search_insecure_key_storage(sources_dir)

    # Search for secure KeyStore usage
    keystore_usage = search_keystore_usage(sources_dir)

    # Print results
    print_key_security_results(key_usage, hardcoded_keys, insecure_storage, keystore_usage)

    # Test passes if no hardcoded keys or insecure storage detected
    passed = len(hardcoded_keys) == 0 and len(insecure_storage) == 0

    return {
        'passed': passed,
        'key_usage_count': sum(len(v) for v in key_usage.values()),
        'hardcoded_keys_count': len(hardcoded_keys),
        'insecure_storage_count': len(insecure_storage),
        'keystore_usage_count': len(keystore_usage),
        'hardcoded_keys': hardcoded_keys,
        'insecure_storage': insecure_storage,
        'key_usage': key_usage
    }
