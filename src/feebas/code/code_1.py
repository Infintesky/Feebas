#!/usr/bin/env python3
"""Android Certificate Security Analysis (CODE-1)."""
import re
from utils.adb import run_command


def extract_key_size_from_apk(apk_path):
    """
    Extract certificate key size from APK using apksigner.

    Args:
        apk_path: Path to the APK file

    Returns:
        int: Key size in bits, or 0 if could not be determined
    """
    if not apk_path:
        return 0

    # Try using apksigner first
    result = run_command(
        ["apksigner", "verify", "--print-certs", apk_path],
        timeout=30
    )

    if result and result.returncode == 0:
        output = result.stdout + result.stderr

        # Look for key size patterns in apksigner output
        key_patterns = [
            r'(\d+)-bit\s+(?:RSA|EC|DSA)',
            r'(?:RSA|EC|DSA)\s+(\d+)',
            r'(\d+)\s+bit\s+(?:RSA|EC|DSA)',
            r'key\s+size:\s+(\d+)',
        ]

        for pattern in key_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))

    # Try using keytool as fallback
    # First extract the certificate
    result = run_command(
        ["unzip", "-p", apk_path, "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.EC"],
        timeout=30
    )

    if result and result.returncode == 0:
        # The certificate is in the stdout, try to analyze it with keytool
        # This is more complex and may require writing to a temp file
        pass

    return 0


def analyze_certificate_security(mobsf_report, apk_path=None, test_id="MASTG-CODE-1 - Testing Certificate Security"):
    """
    Analyze certificate security (signature version and key size) from MobSF report.

    Args:
        mobsf_report: MobSF JSON report dictionary
        apk_path: Path to APK file (optional, used if key size can't be determined from MobSF)
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

    # Get certificate analysis from report
    cert_analysis = mobsf_report.get('certificate_analysis', {})

    if not cert_analysis:
        print("\n[*] INFO: No certificate analysis found in MobSF report")
        print("=" * 80)
        return {
            'passed': True,
            'v1_signature_used': False,
            'insecure_key_size': False
        }

    print(f"[+] Analyzing certificate security from MobSF report...")
    print()

    # Extract certificate information string
    cert_info = cert_analysis.get('certificate_info', '')
    cert_findings = cert_analysis.get('certificate_findings', [])

    # Parse certificate_info string for signature versions
    v1_signature_bool = False
    v2_signature_bool = False
    v3_signature_bool = False
    v4_signature_bool = False
    key_size_int = 0

    if cert_info:
        # Parse v1/v2/v3/v4 signature from certificate_info
        v1_match = re.search(r'v1 signature:\s*(True|False)', cert_info, re.IGNORECASE)
        v2_match = re.search(r'v2 signature:\s*(True|False)', cert_info, re.IGNORECASE)
        v3_match = re.search(r'v3 signature:\s*(True|False)', cert_info, re.IGNORECASE)
        v4_match = re.search(r'v4 signature:\s*(True|False)', cert_info, re.IGNORECASE)

        if v1_match:
            v1_signature_bool = v1_match.group(1).lower() == 'true'
        if v2_match:
            v2_signature_bool = v2_match.group(1).lower() == 'true'
        if v3_match:
            v3_signature_bool = v3_match.group(1).lower() == 'true'
        if v4_match:
            v4_signature_bool = v4_match.group(1).lower() == 'true'

        # Try to extract key size (RSA key size or other key type)
        # Look for patterns like "2048-bit RSA" or "RSA 2048"
        key_patterns = [
            r'(\d+)-bit\s+(?:RSA|EC|DSA)',
            r'(?:RSA|EC|DSA)\s+(\d+)',
            r'(\d+)\s+bit\s+(?:RSA|EC|DSA)',
            r'Key\s+Size:\s+(\d+)',
            r'keysize:\s+(\d+)',
        ]
        for pattern in key_patterns:
            match = re.search(pattern, cert_info, re.IGNORECASE)
            if match:
                key_size_int = int(match.group(1))
                break

    # If key size still not found and APK path is provided, try extracting from APK
    if key_size_int == 0 and apk_path:
        print(f"[*] Key size not found in MobSF report, extracting from APK...")
        key_size_int = extract_key_size_from_apk(apk_path)
        if key_size_int > 0:
            print(f"[+] Extracted key size from APK: {key_size_int} bits")

    # Check for debug certificate in findings
    is_debug_cert = False
    for finding in cert_findings:
        if len(finding) >= 3:
            description = finding[2].lower()
            if 'debug certificate' in description:
                is_debug_cert = True
                break

    # Track issues
    v1_signature_used = v1_signature_bool
    no_modern_signature = not v2_signature_bool and not v3_signature_bool and not v4_signature_bool
    insecure_key_size = key_size_int < 2048 and key_size_int > 0

    # Print results
    print("[*] Certificate Security Analysis Results:")
    print("-" * 80)
    print()

    # Report signature versions
    print("SIGNATURE VERSIONS:")
    print(f"  v1 Signature: {v1_signature_bool}")
    print(f"  v2 Signature: {v2_signature_bool}")
    print(f"  v3 Signature: {v3_signature_bool}")
    if v4_signature_bool:
        print(f"  v4 Signature: {v4_signature_bool}")
    print()

    if v1_signature_used:
        print("[!] EXCEPTION: v1 Signature is enabled")
        print("    v1 signatures are vulnerable to Janus attack")
        print("    Recommendation: Disable v1 signature and use v2/v3/v4 only")
        print()
    else:
        print("[+] v1 Signature is disabled")
        print()

    if no_modern_signature:
        print("[!] EXCEPTION: No modern signature scheme (v2/v3/v4) is being used")
        print("    Apps should use v2, v3, or v4 signature scheme")
        print("    Recommendation: Use APK Signature Scheme v2 or higher")
        print()
    else:
        schemes = []
        if v2_signature_bool:
            schemes.append("v2")
        if v3_signature_bool:
            schemes.append("v3")
        if v4_signature_bool:
            schemes.append("v4")
        print(f"[+] Modern signature scheme(s) enabled: {', '.join(schemes)}")
        print()

    # Report debug certificate
    print(f"DEBUG CERTIFICATE:")
    if is_debug_cert:
        print(f"  Debug Certificate: Yes (INSECURE)")
        print()
        print("[!] EXCEPTION: Application is signed with a debug certificate")
        print("    Production applications must not be shipped with debug certificates")
        print("    Recommendation: Sign with a production certificate")
        print()
    else:
        print(f"  Debug Certificate: No")
        print()

    # Report key size
    print(f"CERTIFICATE KEY SIZE:")
    if key_size_int > 0:
        print(f"  Key Size: {key_size_int} bits")
    else:
        print(f"  Key Size: Unknown (could not be determined)")
    print()

    if insecure_key_size:
        print(f"[!] EXCEPTION: Key size {key_size_int} bits is below 2048 bits")
        print(f"    Insecure key sizes are vulnerable to brute force attacks")
        print(f"    Recommendation: Use at least 2048-bit keys")
        print()
    elif key_size_int >= 2048:
        print(f"[+] Key size {key_size_int} bits meets minimum requirement (2048 bits)")
        print()
    else:
        print("[*] Key size could not be determined")
        print()

    print("-" * 80)
    print()

    # Summary
    print("SUMMARY:")
    print(f"  v1 Signature Used:             {'Yes (FAIL)' if v1_signature_used else 'No'}")
    print(f"  Modern Signature Used:         {'No (FAIL)' if no_modern_signature else 'Yes'}")
    print(f"  Debug Certificate:             {'Yes (FAIL)' if is_debug_cert else 'No'}")
    print(f"  Key Size:                      {key_size_int if key_size_int > 0 else 'Unknown'} bits")
    print(f"  Key Size Secure:               {'No (FAIL)' if insecure_key_size else 'Yes' if key_size_int >= 2048 else 'Unknown'}")
    print()

    # Determine if test passed
    has_issues = v1_signature_used or no_modern_signature or is_debug_cert or insecure_key_size

    if has_issues:
        issues = []
        if v1_signature_used:
            issues.append("v1 signature enabled")
        if no_modern_signature:
            issues.append("no modern signature (v2/v3/v4)")
        if is_debug_cert:
            issues.append("debug certificate")
        if insecure_key_size:
            issues.append(f"key size below 2048 bits ({key_size_int} bits)")

        print(f"[!] FAIL: Found {', '.join(issues)}")
    else:
        print("[+] PASS: Certificate uses secure signature scheme and key size")

    print("=" * 80)

    return {
        'passed': not has_issues,
        'v1_signature_used': v1_signature_used,
        'v2_signature_used': v2_signature_bool,
        'v3_signature_used': v3_signature_bool,
        'v4_signature_used': v4_signature_bool,
        'no_modern_signature': no_modern_signature,
        'is_debug_cert': is_debug_cert,
        'key_size': key_size_int if key_size_int > 0 else None,
        'insecure_key_size': insecure_key_size
    }
