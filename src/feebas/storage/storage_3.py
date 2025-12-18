#!/usr/bin/env python3
"""Logcat analysis module for detecting sensitive data in logs."""
from interfaces.adb_interface import run_command


def capture_logcat():
    """Capture current logcat buffer with threadtime format."""
    print(f"[+] Capturing logcat with threadtime format")

    # Use -d to dump logs and exit (non-blocking)
    # Use 'replace' to handle non-UTF-8 characters in logcat output
    result = run_command(
        ["adb", "logcat", "-d", "-v", "threadtime"],
        timeout=60,
        encoding_errors='replace'
    )

    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to capture logcat")
        if result:
            print(f"[-] Error message: {result.stderr}")
        return None

    return result.stdout


def search_logcat(logcat_output, search_term):
    """
    Search for a term in logcat output and return matching lines with line numbers.

    Args:
        logcat_output: The logcat output to search through
        search_term: The term to search for

    Returns:
        list: List of tuples (line_number, line_content) for matching lines
    """
    print(f"[+] Searching for '{search_term}' in logcat output")

    matches = []
    lines = logcat_output.split('\n')

    for line_num, line in enumerate(lines, start=1):
        if search_term in line:
            matches.append((line_num, line))

    if matches:
        print(f"[!] Found {len(matches)} occurrence(s) of '{search_term}'")
    else:
        print(f"[+] No occurrences of '{search_term}' found")

    return matches


def print_logcat_results(matches, search_term, test_id):
    """Print logcat analysis results in a formatted way."""
    print("\n" + "=" * 60)
    print(f"[*] {test_id}")
    print("=" * 60)
    print(f"[+] Running: adb logcat -d -v threadtime | grep \"{search_term}\"")

    if matches:
        print(f"\n[!] FAIL: Found sensitive data in logcat at {len(matches)} location(s):")
        print("-" * 60)
        for line_num, line_content in matches:
            print(f"Line {line_num}: {line_content.strip()}")
        print("-" * 60)
    else:
        print(f"\n[+] PASS: No sensitive data found in logcat")

    print("=" * 60)


def analyze_logcat(search_term, test_id="MASTG-STORAGE-3 - Testing Logs for Sensitive Data"):
    """
    Complete logcat analysis workflow.

    Args:
        search_term: The term to search for in logcat (typically last 5 chars of NRIC)
        test_id: Test identifier for reporting (default: MASTG-STORAGE-3)

    Returns:
        dict: Analysis results with 'passed' boolean and 'matches' list, or None if failed to capture logcat
    """
    # Capture logcat
    logcat_output = capture_logcat()
    if logcat_output is None:
        return None

    # Search for sensitive data
    matches = search_logcat(logcat_output, search_term)

    # Print results
    print_logcat_results(matches, search_term, test_id)

    # Test passes if no matches found
    passed = len(matches) == 0

    return {
        'passed': passed,
        'matches': matches,
        'search_term': search_term
    }