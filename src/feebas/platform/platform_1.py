#!/usr/bin/env python3
"""Android Application Permissions Analysis (PLATFORM-1)."""


def analyze_permissions(mobsf_report, test_id="MASTG-PLATFORM-1 - Testing App Permissions"):
    """
    Analyze application permissions from MobSF report.

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

    # Get permissions from report
    permissions = mobsf_report.get('permissions', {})

    if not permissions:
        print("\n[*] INFO: No permissions found in MobSF report")
        print("=" * 80)
        return {
            'passed': True,
            'dangerous_permissions': [],
            'unknown_permissions': []
        }

    print(f"[+] Analyzing {len(permissions)} permissions...")
    print()

    # Categorize permissions
    dangerous_permissions = []
    unknown_permissions = []
    normal_permissions = []

    for permission, details in permissions.items():
        status = details.get('status', 'unknown').lower()
        info = details.get('info', 'No description available')
        description = details.get('description', info)

        permission_data = {
            'name': permission,
            'status': status,
            'description': description,
            'info': info
        }

        if status == 'dangerous':
            dangerous_permissions.append(permission_data)
        elif status == 'unknown':
            unknown_permissions.append(permission_data)
        else:
            normal_permissions.append(permission_data)

    # Print results
    print("[*] Application Permissions Analysis Results:")
    print("-" * 80)
    print()

    # Report dangerous permissions
    if dangerous_permissions:
        print(f"[!] DANGEROUS PERMISSIONS ({len(dangerous_permissions)}):")
        print()
        for perm in sorted(dangerous_permissions, key=lambda x: x['name']):
            print(f"  [!] {perm['name']}")
            print(f"      Status: {perm['status'].upper()}")
            if perm['description']:
                # Wrap long descriptions
                desc_lines = perm['description'].split('\n')
                for line in desc_lines:
                    if len(line) > 70:
                        # Simple word wrapping
                        words = line.split()
                        current_line = "      "
                        for word in words:
                            if len(current_line) + len(word) + 1 > 76:
                                print(current_line)
                                current_line = "      " + word
                            else:
                                if current_line == "      ":
                                    current_line += word
                                else:
                                    current_line += " " + word
                        if current_line != "      ":
                            print(current_line)
                    else:
                        print(f"      {line}")
            print()
    else:
        print("[+] No dangerous permissions found")
        print()

    # Report unknown permissions
    if unknown_permissions:
        print(f"[!] UNKNOWN PERMISSIONS ({len(unknown_permissions)}):")
        print()
        for perm in sorted(unknown_permissions, key=lambda x: x['name']):
            print(f"  [?] {perm['name']}")
            print(f"      Status: {perm['status'].upper()}")
            if perm['description']:
                # Wrap long descriptions
                desc_lines = perm['description'].split('\n')
                for line in desc_lines:
                    if len(line) > 70:
                        # Simple word wrapping
                        words = line.split()
                        current_line = "      "
                        for word in words:
                            if len(current_line) + len(word) + 1 > 76:
                                print(current_line)
                                current_line = "      " + word
                            else:
                                if current_line == "      ":
                                    current_line += word
                                else:
                                    current_line += " " + word
                        if current_line != "      ":
                            print(current_line)
                    else:
                        print(f"      {line}")
            print()
    else:
        print("[+] No unknown permissions found")
        print()

    # Report summary
    if normal_permissions:
        print(f"[*] Normal/Safe permissions: {len(normal_permissions)}")
        print()

    print("-" * 80)
    print()

    # Summary statistics
    print("PERMISSION SUMMARY:")
    print(f"  Total permissions:     {len(permissions)}")
    print(f"  Dangerous permissions: {len(dangerous_permissions)}")
    print(f"  Unknown permissions:   {len(unknown_permissions)}")
    print(f"  Normal permissions:    {len(normal_permissions)}")
    print()

    # Determine if test passed
    has_issues = len(dangerous_permissions) > 0 or len(unknown_permissions) > 0

    if has_issues:
        issues = []
        if dangerous_permissions:
            issues.append(f"{len(dangerous_permissions)} dangerous permission(s)")
        if unknown_permissions:
            issues.append(f"{len(unknown_permissions)} unknown permission(s)")

        print(f"[!] WARNING: Found {', '.join(issues)}")
    else:
        print("[+] PASS: No dangerous or unknown permissions detected")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'total_permissions': len(permissions),
        'dangerous_permissions_count': len(dangerous_permissions),
        'unknown_permissions_count': len(unknown_permissions),
        'normal_permissions_count': len(normal_permissions),
        'dangerous_permissions': dangerous_permissions,
        'unknown_permissions': unknown_permissions,
        'normal_permissions': normal_permissions
    }
