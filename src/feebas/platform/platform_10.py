#!/usr/bin/env python3
"""Android Cache Data Analysis (PLATFORM-10)."""
from interfaces.adb_interface import run_command


def check_cache_for_sensitive_data(package_name, search_term):
    """
    Check if sensitive data is stored in app cache directory.

    Args:
        package_name: Android package name
        search_term: Sensitive data to search for (e.g., NRIC)

    Returns:
        dict: {
            'files_found': [str],
            'has_sensitive_data': bool,
            'success': bool,
            'error': str
        }
    """
    print(f"[+] Checking cache directory for sensitive data...")
    print(f"[+] Searching for: {search_term}")

    cache_dir = f"/data/data/{package_name}/cache"

    # Try to access the cache directory and search for sensitive data
    # Command: su -c 'grep -lr "<search_term>" /data/data/<package>/cache'
    print(f"[+] Checking directory: {cache_dir}")

    result = run_command(
        ['adb', 'shell', 'su', '-c', f'grep -lr "{search_term}" {cache_dir}'],
        timeout=30
    )

    if not result:
        print(f"[-] Error: ADB command timed out or failed to execute")
        return {
            'files_found': [],
            'has_sensitive_data': False,
            'success': False,
            'error': 'Command execution failed'
        }

    # Check for permission errors
    if result.returncode != 0:
        stderr = result.stderr if result.stderr else ""

        # Check if it's a "not found" or "no such file" error (which is actually OK)
        if "No such file or directory" in stderr or "not found" in stderr.lower():
            print(f"[+] Cache directory does not exist or is empty")
            return {
                'files_found': [],
                'has_sensitive_data': False,
                'success': True,
                'error': None
            }

        # Check for permission errors
        if "Permission denied" in stderr or "not permitted" in stderr:
            print(f"[-] Error: Permission denied - root access required")
            return {
                'files_found': [],
                'has_sensitive_data': False,
                'success': False,
                'error': 'Permission denied - root access required'
            }

        # grep returns non-zero when no matches found (which is good)
        if result.returncode == 1:
            print(f"[+] No sensitive data found in cache")
            return {
                'files_found': [],
                'has_sensitive_data': False,
                'success': True,
                'error': None
            }

        print(f"[-] Warning: Command returned non-zero exit code: {result.returncode}")

    output = result.stdout if result.stdout else ""

    # Parse output to get list of files
    files_found = []
    if output.strip():
        files_found = [line.strip() for line in output.strip().split('\n') if line.strip()]

    has_sensitive_data = len(files_found) > 0

    return {
        'files_found': files_found,
        'has_sensitive_data': has_sensitive_data,
        'success': True,
        'error': None
    }


def analyze_cache_data(package_name, search_term, test_id="MASTG-PLATFORM-10 - Testing Cached Sensitive Data"):
    """
    Analyze app cache for sensitive data.

    Args:
        package_name: Android package name
        search_term: Sensitive data to search for
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    # Check cache for sensitive data
    cache_results = check_cache_for_sensitive_data(package_name, search_term)

    if not cache_results['success']:
        print("\n[!] FAIL: Failed to check cache directory")
        if cache_results['error']:
            print(f"[!] Error: {cache_results['error']}")
        print("=" * 80)
        return {
            'passed': False,
            'error': cache_results['error']
        }

    # Print results
    print()
    print("[*] Cache Data Analysis Results:")
    print("-" * 80)

    files_found = cache_results['files_found']
    has_sensitive_data = cache_results['has_sensitive_data']

    if has_sensitive_data:
        print(f"\n[!] Sensitive Data Found in Cache ({len(files_found)} file(s)):")
        print()
        for file_path in files_found:
            print(f"  [!] {file_path}")
        print()
    else:
        print("\n[+] No sensitive data found in cache directory")

    print("-" * 80)
    print()

    # Determine if test passed
    if has_sensitive_data:
        print(f"[!] FAIL: Found sensitive data in {len(files_found)} cache file(s)")
        print("[!] Sensitive data should not be stored in cache")
        print("[!] Cache files can be accessed by other apps with READ_EXTERNAL_STORAGE permission")
    else:
        print("[+] PASS: No sensitive data found in app cache")

    print("=" * 80)

    return {
        'passed': not has_sensitive_data,
        'files_found': files_found,
        'has_sensitive_data': has_sensitive_data
    }
