#!/usr/bin/env python3
"""Random number generation security analysis module (CRYPTO-6)."""
import os
import re


def search_insecure_random(sources_dir):
    """
    Search for usage of insecure Random() in source code.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, line_content, random_type) for insecure Random usage
    """
    print(f"[+] Searching for insecure Random() usage")

    matches = []

    # Patterns for insecure random usage
    # Looking for java.util.Random (insecure) vs java.security.SecureRandom (secure)
    insecure_patterns = [
        (r'new\s+Random\s*\(', "java.util.Random"),
        (r'java\.util\.Random\s*\(', "java.util.Random"),
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

                    # Check if file has cryptographic or sensitive operations
                    # This helps identify if Random is being used in sensitive context
                    is_sensitive = is_sensitive_context(content)

                    for pattern_str, random_type in insecure_patterns:
                        pattern = re.compile(pattern_str)
                        for match in pattern.finditer(content):
                            line_num = content[:match.start()].count('\n') + 1
                            lines = content.split('\n')
                            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                            matches.append((file_path, line_num, line_content, random_type, is_sensitive))
            except Exception:
                continue

    print(f"[+] Found {len(matches)} instances of insecure Random() usage")
    return matches


def search_non_random_sources(sources_dir):
    """
    Search for non-random sources being used for randomization.

    Args:
        sources_dir: Directory containing decompiled source

    Returns:
        list: List of tuples (file_path, line_num, line_content, source_type) for non-random sources
    """
    print(f"[+] Searching for non-random sources")

    matches = []

    # Patterns for non-random sources (time-based, predictable)
    non_random_patterns = [
        (r'System\.currentTimeMillis\s*\(\s*\)', "System.currentTimeMillis()"),
        (r'new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\)', "Date.getTime()"),
        (r'Calendar\.getInstance\s*\(\s*\)\.getTimeInMillis\s*\(\s*\)', "Calendar.getTimeInMillis()"),
        (r'System\.nanoTime\s*\(\s*\)', "System.nanoTime()"),
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

                    # Check if file has cryptographic or sensitive operations
                    is_sensitive = is_sensitive_context(content)

                    for pattern_str, source_type in non_random_patterns:
                        pattern = re.compile(pattern_str)
                        for match in pattern.finditer(content):
                            line_num = content[:match.start()].count('\n') + 1
                            lines = content.split('\n')
                            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                            # Check if this is used as a seed or in crypto context
                            if is_used_for_seeding(content, match.start(), match.end()):
                                matches.append((file_path, line_num, line_content, source_type, is_sensitive))
            except Exception:
                continue

    print(f"[+] Found {len(matches)} instances of non-random sources")
    return matches


def is_sensitive_context(file_content):
    """
    Determine if file contains cryptographic or sensitive operations.

    Args:
        file_content: Content of the file

    Returns:
        bool: True if file contains sensitive operations
    """
    sensitive_keywords = [
        r'\bCipher\b',
        r'\bKey\b',
        r'\bSecretKey\b',
        r'\bPrivateKey\b',
        r'\bPublicKey\b',
        r'\bKeyGenerator\b',
        r'\bSecretKeySpec\b',
        r'\bSignature\b',
        r'\bMessageDigest\b',
        r'\bMac\b',
        r'\bIvParameterSpec\b',
        r'\btoken\b',
        r'\bsession\b',
        r'\bnonce\b',
        r'\bsalt\b',
    ]

    for keyword in sensitive_keywords:
        if re.search(keyword, file_content, re.IGNORECASE):
            return True
    return False


def is_used_for_seeding(content, match_start, match_end):
    """
    Check if a non-random source is used for seeding or initialization.

    Args:
        content: File content
        match_start: Start position of match
        match_end: End position of match

    Returns:
        bool: True if used for seeding
    """
    # Get context around the match (200 chars before and after)
    context_start = max(0, match_start - 200)
    context_end = min(len(content), match_end + 200)
    context = content[context_start:context_end]

    # Check for seeding patterns
    seeding_patterns = [
        r'setSeed',
        r'seed',
        r'Random\s*\(',
        r'SecureRandom\s*\(',
        r'init',
        r'generate',
    ]

    for pattern in seeding_patterns:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    return False


def print_random_results(insecure_random, non_random_sources):
    """Print random number generation analysis results."""
    print()

    has_issues = False

    # Report insecure Random() usage
    if insecure_random:
        sensitive_count = sum(1 for _, _, _, _, is_sensitive in insecure_random if is_sensitive)

        if sensitive_count > 0:
            has_issues = True
            print(f"[!] CRITICAL: Insecure Random() used in sensitive contexts ({sensitive_count} instances):")
            print("-" * 60)
            for file_path, line_num, line_content, random_type, is_sensitive in insecure_random:
                if is_sensitive:
                    print(f"  {file_path}:{line_num} - {random_type}")
            print("-" * 60)
            print()

        non_sensitive_count = len(insecure_random) - sensitive_count
        if non_sensitive_count > 0:
            print(f"[*] INFO: Insecure Random() found in non-sensitive contexts ({non_sensitive_count} instances)")
            print("    (Review if these could be used for security purposes)")
            print()

    # Report non-random sources
    if non_random_sources:
        sensitive_count = sum(1 for _, _, _, _, is_sensitive in non_random_sources if is_sensitive)

        if sensitive_count > 0:
            has_issues = True
            print(f"[!] CRITICAL: Non-random sources used in sensitive contexts ({sensitive_count} instances):")
            print("-" * 60)
            for file_path, line_num, line_content, source_type, is_sensitive in non_random_sources:
                if is_sensitive:
                    print(f"  {file_path}:{line_num} - {source_type}")
            print("-" * 60)
            print()

        non_sensitive_count = len(non_random_sources) - sensitive_count
        if non_sensitive_count > 0:
            print(f"[*] INFO: Non-random sources found in potentially sensitive contexts ({non_sensitive_count} instances)")
            print("    (Review if these are used for seeding or randomization)")
            print()

    # Final assessment
    if has_issues:
        print("\n[!] FAIL: insecure random number generation detected in sensitive contexts")
    else:
        print("\n[+] PASS: No insecure random number generation detected in sensitive contexts")

    print("=" * 80)


def analyze_random_number_generation(sources_dir, test_id="MASTG-CRYPTO-6 - Testing Random Number Generation"):
    """
    Analyze random number generation security in decompiled source code.

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

    # Search for insecure Random() usage
    insecure_random = search_insecure_random(sources_dir)

    # Search for non-random sources
    non_random_sources = search_non_random_sources(sources_dir)

    # Print results
    print_random_results(insecure_random, non_random_sources)

    # Count only sensitive context issues
    insecure_random_sensitive = sum(1 for _, _, _, _, is_sensitive in insecure_random if is_sensitive)
    non_random_sources_sensitive = sum(1 for _, _, _, _, is_sensitive in non_random_sources if is_sensitive)

    # Test passes if no insecure random or non-random sources in sensitive contexts
    passed = insecure_random_sensitive == 0 and non_random_sources_sensitive == 0

    return {
        'passed': passed,
        'insecure_random_count': len(insecure_random),
        'insecure_random_sensitive_count': insecure_random_sensitive,
        'non_random_sources_count': len(non_random_sources),
        'non_random_sources_sensitive_count': non_random_sources_sensitive,
        'insecure_random': insecure_random,
        'non_random_sources': non_random_sources
    }