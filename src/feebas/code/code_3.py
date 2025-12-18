#!/usr/bin/env python3
"""Android Debugging Symbols Analysis (CODE-3)."""


def analyze_debug_symbols(mobsf_report, test_id="MASTG-CODE-3 - Testing for Debugging Symbols"):
    """
    Analyze debugging symbols (symbols stripped) from MobSF report.

    Args:
        mobsf_report: MobSF JSON report dictionary
        test_id: Test identifier for reporting

    Returns:
        dict: Analysis results with 'passed' boolean and findings
    """
    # Print test header
    print("\n" + "=" * 80)
    print(f"{test_id}")
    print("=" * 80)

    if not mobsf_report:
        print("\n[!] FAIL: MobSF report not provided")
        print("=" * 80)
        return {
            'passed': False,
            'error': 'MobSF report not provided'
        }

    # Get binary analysis from report
    binary_analysis = mobsf_report.get('binary_analysis', [])

    if not binary_analysis:
        print("\n[*] INFO: No binary analysis found in MobSF report")
        print("=" * 80)
        return {
            'passed': True,
            'symbols_not_stripped': []
        }

    print(f"[+] Analyzing {len(binary_analysis)} shared libraries...")
    print()

    # Track libraries with issues
    symbols_not_stripped = []
    symbols_stripped_count = 0

    for binary in binary_analysis:
        lib_name = binary.get('name', 'Unknown')

        # Get Symbols Stripped flag - handle both string and dict values
        symbols_stripped = binary.get('symbol', 'unknown')
        if isinstance(symbols_stripped, dict):
            symbols_stripped = symbols_stripped.get('is_stripped', 'unknown')
        if isinstance(symbols_stripped, str):
            symbols_stripped = symbols_stripped.lower()
        else:
            symbols_stripped = str(symbols_stripped).lower()

        # Check symbols stripped status
        if symbols_stripped == 'true' or symbols_stripped == 'yes':
            symbols_stripped_count += 1
        elif symbols_stripped == 'false' or symbols_stripped == 'no':
            symbols_not_stripped.append(lib_name)

    # Print results
    print("[*] Debugging Symbols Analysis Results:")
    print("-" * 80)
    print()

    # Report symbols stripped status
    print(f"SYMBOLS STRIPPED:")
    print(f"  Stripped:     {symbols_stripped_count}/{len(binary_analysis)}")
    print(f"  Not Stripped: {len(symbols_not_stripped)}/{len(binary_analysis)}")
    print()

    if symbols_not_stripped:
        print(f"[!] Libraries with SYMBOLS NOT STRIPPED ({len(symbols_not_stripped)}):")
        for lib in symbols_not_stripped:
            print(f"  [!] {lib}")
        print()
    else:
        print("[+] All libraries have symbols stripped")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  Total libraries analyzed: {len(binary_analysis)}")
    print(f"  Symbols not stripped:     {len(symbols_not_stripped)}")
    print()

    # Determine if test passed
    has_issues = len(symbols_not_stripped) > 0

    if has_issues:
        print(f"[!] FAIL: Found {len(symbols_not_stripped)} library(ies) with symbols not stripped")
    else:
        print("[+] PASS: All libraries have symbols stripped")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'total_libraries': len(binary_analysis),
        'symbols_not_stripped_count': len(symbols_not_stripped),
        'symbols_not_stripped': symbols_not_stripped,
        'symbols_stripped_count': symbols_stripped_count
    }
