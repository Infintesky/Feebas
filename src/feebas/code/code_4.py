#!/usr/bin/env python3
"""Testing for Debugging Code and Verbose Error Logging (CODE-4)."""
from utils.adb import run_command


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


def search_strictmode(logcat_output):
    """
    Search for StrictMode in logcat output and return matching lines with line numbers.

    Args:
        logcat_output: The logcat output to search through

    Returns:
        list: List of tuples (line_number, line_content) for matching lines
    """
    print(f"[+] Searching for 'StrictMode' in logcat output")

    matches = []
    lines = logcat_output.split('\n')

    for line_num, line in enumerate(lines, start=1):
        if 'StrictMode' in line:
            matches.append((line_num, line))

    if matches:
        print(f"[!] Found {len(matches)} occurrence(s) of 'StrictMode'")
    else:
        print(f"[+] No occurrences of 'StrictMode' found")

    return matches


def analyze_debug_logging(test_id="MASTG-CODE-4 - Testing for Debugging Code and Verbose Error Logging"):
    """
    Complete logcat analysis workflow for StrictMode detection.

    Args:
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and 'matches' list, or None if failed to capture logcat
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Capture logcat
    logcat_output = capture_logcat()
    if logcat_output is None:
        print("\n[!] FAIL: Failed to capture logcat")
        print("=" * 80)
        return None

    # Search for StrictMode
    matches = search_strictmode(logcat_output)

    # Print results
    print()
    print("[*] Debugging Code Analysis Results:")
    print("-" * 80)
    print()

    if matches:
        print(f"[!] Found StrictMode in logcat at {len(matches)} location(s):")
        print()
        for line_num, line_content in matches[:10]:  # Show first 10 matches
            print(f"  Line {line_num}: {line_content.strip()}")

        if len(matches) > 10:
            print(f"  ... and {len(matches) - 10} more occurrence(s)")
        print()
    else:
        print("[+] No StrictMode debugging code found in logcat")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  StrictMode occurrences: {len(matches)}")
    print()

    # Test passes if no matches found
    passed = len(matches) == 0

    if passed:
        print("[+] PASS: No debugging code detected in logcat")
    else:
        print(f"[!] FAIL: Found {len(matches)} StrictMode occurrence(s) in logcat")

    print("=" * 80)

    return {
        'passed': passed,
        'matches': matches,
        'strictmode_count': len(matches)
    }
