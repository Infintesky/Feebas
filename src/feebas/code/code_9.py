#!/usr/bin/env python3
"""Android Binary Protection Mechanisms Analysis (PLATFORM-9)."""


def analyze_binary_protections(mobsf_report, test_id="MASTG-PLATFORM-9 - Testing Binary Protection Mechanisms"):
    """
    Analyze binary protection mechanisms (PIE and Stack Canary) from MobSF report.

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
            'pie_disabled': [],
            'stack_canary_disabled': []
        }

    print(f"[+] Analyzing {len(binary_analysis)} shared libraries...")
    print()

    # Track libraries with issues
    pie_disabled = []
    stack_canary_disabled = []
    pie_enabled_count = 0
    stack_canary_enabled_count = 0

    for binary in binary_analysis:
        lib_name = binary.get('name', 'Unknown')

        # Get PIE flag - handle both string and dict values
        pie_flag = binary.get('nx', 'unknown')
        if isinstance(pie_flag, dict):
            pie_flag = pie_flag.get('is_nx', 'unknown')
        if isinstance(pie_flag, str):
            pie_flag = pie_flag.lower()
        else:
            pie_flag = str(pie_flag).lower()

        # Get Stack Canary - handle both string and dict values
        stack_canary = binary.get('stack_canary', 'unknown')
        if isinstance(stack_canary, dict):
            stack_canary = stack_canary.get('has_canary', 'unknown')
        if isinstance(stack_canary, str):
            stack_canary = stack_canary.lower()
        else:
            stack_canary = str(stack_canary).lower()

        # Check PIE status
        if pie_flag == 'true' or pie_flag == 'yes':
            pie_enabled_count += 1
        elif pie_flag == 'false' or pie_flag == 'no':
            pie_disabled.append(lib_name)

        # Check Stack Canary status
        if stack_canary == 'true' or stack_canary == 'yes':
            stack_canary_enabled_count += 1
        elif stack_canary == 'false' or stack_canary == 'no':
            stack_canary_disabled.append(lib_name)

    # Print results
    print("[*] Binary Protection Analysis Results:")
    print("-" * 80)
    print()

    # Report PIE status
    print(f"POSITION INDEPENDENT EXECUTABLE (PIE):")
    print(f"  Enabled:  {pie_enabled_count}/{len(binary_analysis)}")
    print(f"  Disabled: {len(pie_disabled)}/{len(binary_analysis)}")
    print()

    if pie_disabled:
        print(f"[!] Libraries with PIE DISABLED ({len(pie_disabled)}):")
        for lib in pie_disabled:
            print(f"  [!] {lib}")
        print()
    else:
        print("[+] All libraries have PIE enabled")
        print()

    # Report Stack Canary status
    print(f"STACK CANARY:")
    print(f"  Enabled:  {stack_canary_enabled_count}/{len(binary_analysis)}")
    print(f"  Disabled: {len(stack_canary_disabled)}/{len(binary_analysis)}")
    print()

    if stack_canary_disabled:
        print(f"[!] Libraries with STACK CANARY DISABLED ({len(stack_canary_disabled)}):")
        for lib in stack_canary_disabled:
            print(f"  [!] {lib}")
        print()
    else:
        print("[+] All libraries have Stack Canary enabled")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  Total libraries analyzed: {len(binary_analysis)}")
    print(f"  PIE issues:               {len(pie_disabled)}")
    print(f"  Stack Canary issues:      {len(stack_canary_disabled)}")
    print()

    # Determine if test passed
    has_issues = len(pie_disabled) > 0 or len(stack_canary_disabled) > 0

    if has_issues:
        issues = []
        if pie_disabled:
            issues.append(f"{len(pie_disabled)} library(ies) without PIE")
        if stack_canary_disabled:
            issues.append(f"{len(stack_canary_disabled)} library(ies) without Stack Canary")

        print(f"[!] FAIL: Found {', '.join(issues)}")
    else:
        print("[+] PASS: All libraries have PIE and Stack Canary enabled")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'total_libraries': len(binary_analysis),
        'pie_disabled_count': len(pie_disabled),
        'stack_canary_disabled_count': len(stack_canary_disabled),
        'pie_disabled': pie_disabled,
        'stack_canary_disabled': stack_canary_disabled,
        'pie_enabled_count': pie_enabled_count,
        'stack_canary_enabled_count': stack_canary_enabled_count
    }
