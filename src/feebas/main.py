#!/usr/bin/env python3
"""Main script to run APK analysis tests."""
import shutil
from storage.storage_11 import analyze_apk_from_device
from storage.storage_1 import analyze_storage
from storage.storage_3 import analyze_logcat
from storage.storage_8 import analyze_backup_setting
from crypto.crypto_1 import analyze_crypto_implementation
from crypto.crypto_234 import analyze_crypto_api_usage
from crypto.crypto_5 import analyze_key_security
from crypto.crypto_6 import analyze_random_number_generation
from utils.apk import prepare_apk_for_analysis
from network.network_1 import analyze_network_security
from network.network_3 import analyze_network_security_config
from platform.platform_2 import analyze_implicit_intents_and_webview
from platform.platform_4 import analyze_exported_components
from platform.platform_6 import analyze_webview_security
from platform.platform_7 import analyze_javascript_interface
from platform.platform_10 import analyze_cache_data
from config import PACKAGE_NAME, TEST_NRIC


def main():
    """Main function to run all test cases."""

    failed_tests = []

    # Prepare APK for all tests (pull and decompile once with both jadx and apktool)
    temp_dir, sources_dir, apktool_dir = prepare_apk_for_analysis(PACKAGE_NAME)
    if not sources_dir or not apktool_dir:
        print("\n[!] CRITICAL ERROR: Failed to prepare APK for analysis")
        print("[!] Cannot run any tests without decompiled APK")
        return

    try:
        print("=" * 60)
        print("MASVS-STORAGE Tests")
        print("=" * 60)
        print()

        # MASTG-STORAGE-11 - Testing the Device-Access-Security Policy
        result = analyze_apk_from_device(
            package_name=PACKAGE_NAME,
            test_id="MASTG-STORAGE-11 - Testing the Device-Access-Sadecurity Policy"
        )

        if not result:
            print("\n[-] Test failed: MASTG-STORAGE-11")
            failed_tests.append("MASTG-STORAGE-11")


        # STORAGE-1 - Data Stored in the App Sandbox at Runtime
        result = analyze_storage(
            package_name=PACKAGE_NAME,
            search_term=TEST_NRIC,
            test_id="MASTG-STORAGE-1 - Data Stored in the App Sandbox at Runtime"
        )

        if not result:
            print("\n[-] Test failed: STORAGE-1")
            failed_tests.append("STORAGE-1")


        # STORAGE-3 - Testing Logs for Sensitive Data
        # Extract last 5 characters of NRIC for logcat search
        search_term = TEST_NRIC[-5:]
        result = analyze_logcat(
            search_term=search_term,
            test_id="MASTG-STORAGE-3 - Testing Logs for Sensitive Data"
        )

        if not result:
            print("\n[-] Test failed: STORAGE-3 (error capturing logcat)")
            failed_tests.append("STORAGE-3")
        elif not result['passed']:
            print(f"\n[-] Test failed: STORAGE-3 (found sensitive data in logcat)")
            failed_tests.append("STORAGE-3")


        # STORAGE-8 - Testing Backups for Sensitive Data
        result = analyze_backup_setting(
            package_name=PACKAGE_NAME,
            test_id="MASTG-STORAGE-8 - Testing Backups for Sensitive Data"
        )

        if not result:
            print("\n[-] Test failed: STORAGE-8 (error analyzing backup settings)")
            failed_tests.append("STORAGE-8")
        elif not result['passed']:
            print(f"\n[-] Test failed: STORAGE-8 (backup is enabled)")
            failed_tests.append("STORAGE-8")


        # MASVS-CRYPTO Tests - Use jadx decompiled sources
        print("\n" + "=" * 60)
        print("MASVS-CRYPTO Tests")
        print("=" * 60)
        print()

        # CRYPTO-1 - Testing for Insecure Cryptographic Algorithms
        result = analyze_crypto_implementation(
            sources_dir=sources_dir,
            test_id="MASTG-CRYPTO-1 - Testing for Insecure Cryptographic Algorithms"
        )

        if not result:
            print("\n[-] Test failed: CRYPTO-1 (error analyzing cryptographic implementation)")
            failed_tests.append("CRYPTO-1")
        elif not result['passed']:
            print(f"\n[-] Test failed: CRYPTO-1 (insecure cryptographic implementation detected)")
            failed_tests.append("CRYPTO-1")

        # CRYPTO-2/3/4 - Cryptographic API Usage Analysis
        result = analyze_crypto_api_usage(
            sources_dir=sources_dir,
            test_id="MASTG-CRYPTO-2/3/4 - Cryptographic API Usage Analysis"
        )

        if not result:
            print("\n[-] Test failed: CRYPTO-2/3/4 (error analyzing crypto API usage)")
            failed_tests.append("CRYPTO-2/3/4")
        elif not result['passed']:
            print(f"\n[-] Test failed: CRYPTO-2/3/4 (weak cryptographic primitives detected)")
            failed_tests.append("CRYPTO-2/3/4")

        # CRYPTO-5 - Testing Key Management
        result = analyze_key_security(
            sources_dir=sources_dir,
            test_id="MASTG-CRYPTO-5 - Testing Key Management"
        )

        if not result:
            print("\n[-] Test failed: CRYPTO-5 (error analyzing key security)")
            failed_tests.append("CRYPTO-5")
        elif not result['passed']:
            print(f"\n[-] Test failed: CRYPTO-5 (insecure key management detected)")
            failed_tests.append("CRYPTO-5")

        # CRYPTO-6 - Testing Random Number Generation
        result = analyze_random_number_generation(
            sources_dir=sources_dir,
            test_id="MASTG-CRYPTO-6 - Testing Random Number Generation"
        )

        if not result:
            print("\n[-] Test failed: CRYPTO-6 (error analyzing random number generation)")
            failed_tests.append("CRYPTO-6")
        elif not result['passed']:
            print(f"\n[-] Test failed: CRYPTO-6 (insecure random number generation detected)")
            failed_tests.append("CRYPTO-6")

        # MASVS-NETWORK Tests - Use both jadx and apktool decompiled sources
        print("\n" + "=" * 60)
        print("MASVS-NETWORK Tests")
        print("=" * 60)
        print()

        # NETWORK-1 - Testing Data Encryption on the Network
        result = analyze_network_security(
            sources_dir=sources_dir,
            apktool_dir=apktool_dir,
            test_id="MASTG-NETWORK-1 - Testing Data Encryption on the Network"
        )

        if not result:
            print("\n[-] Test failed: NETWORK-1 (error analyzing network security)")
            failed_tests.append("NETWORK-1")
        elif not result['passed']:
            print(f"\n[-] Test failed: NETWORK-1 (insecure network configuration detected)")
            failed_tests.append("NETWORK-1")

        # NETWORK-3 - Testing the Security Provider (Certificate Pinning)
        result = analyze_network_security_config(
            apktool_dir=apktool_dir,
            test_id="MASTG-NETWORK-3 - Testing the Security Provider"
        )

        if not result:
            print("\n[-] Test failed: NETWORK-3 (error analyzing network security config)")
            failed_tests.append("NETWORK-3")
        elif not result['passed']:
            # Determine specific issue
            if not result.get('config_found'):
                print(f"\n[-] Test failed: NETWORK-3 (network_security_config.xml does not exist)")
            elif not result.get('has_pinning'):
                print(f"\n[-] Test failed: NETWORK-3 (certificate pinning is not properly configured)")
            else:
                print(f"\n[-] Test failed: NETWORK-3 (network security configuration issues detected)")
            failed_tests.append("NETWORK-3")

        # MASVS-PLATFORM Tests
        print("\n" + "=" * 80)
        print("MASVS-PLATFORM Tests")
        print("=" * 80)
        print()

        # PLATFORM-2 - Testing Implicit Intents and WebView Configuration
        result = analyze_implicit_intents_and_webview(
            apktool_dir=apktool_dir,
            test_id="MASTG-PLATFORM-2 - Testing Implicit Intents and WebView Configuration"
        )

        if not result:
            print("\n[-] Test failed: PLATFORM-2 (error analyzing implicit intents)")
            failed_tests.append("PLATFORM-2")
        elif not result['passed']:
            print(f"\n[-] Test failed: PLATFORM-2 (implicit intent or WebView configuration issues detected)")
            failed_tests.append("PLATFORM-2")

        # PLATFORM-4 - Testing Exported Components
        result = analyze_exported_components(
            package_name=PACKAGE_NAME,
            apktool_dir=apktool_dir,
            sources_dir=sources_dir,
            test_id="MASTG-PLATFORM-4 - Testing Exported Components"
        )

        if not result:
            print("\n[-] Test failed: PLATFORM-4 (error analyzing exported components)")
            failed_tests.append("PLATFORM-4")
        elif not result['passed']:
            print(f"\n[-] Test failed: PLATFORM-4 (insecure exported components detected)")
            failed_tests.append("PLATFORM-4")

        # PLATFORM-6 - Testing WebView Security Configuration
        result = analyze_webview_security(
            sources_dir=sources_dir,
            test_id="MASTG-PLATFORM-6 - Testing WebView Security Configuration"
        )

        if not result:
            print("\n[-] Test failed: PLATFORM-6 (error analyzing WebView security)")
            failed_tests.append("PLATFORM-6")
        elif not result['passed']:
            print(f"\n[-] Test failed: PLATFORM-6 (insecure WebView configuration detected)")
            failed_tests.append("PLATFORM-6")

        # PLATFORM-7 - Testing for Java Objects Exposed Through WebViews
        result = analyze_javascript_interface(
            sources_dir=sources_dir,
            apktool_dir=apktool_dir,
            test_id="MASTG-PLATFORM-7 - Testing for Java Objects Exposed Through WebViews"
        )

        if not result:
            print("\n[-] Test failed: PLATFORM-7 (error analyzing JavaScript interface)")
            failed_tests.append("PLATFORM-7")
        elif not result['passed']:
            print(f"\n[-] Test failed: PLATFORM-7 (JavaScript interface exposed with minSdkVersion < 17)")
            failed_tests.append("PLATFORM-7")

        # PLATFORM-10 - Testing Cached Sensitive Data
        result = analyze_cache_data(
            package_name=PACKAGE_NAME,
            search_term=TEST_NRIC,
            test_id="MASTG-PLATFORM-10 - Testing Cached Sensitive Data"
        )

        if not result:
            print("\n[-] Test failed: PLATFORM-10 (error analyzing cache data)")
            failed_tests.append("PLATFORM-10")
        elif not result['passed']:
            print(f"\n[-] Test failed: PLATFORM-10 (sensitive data found in cache)")
            failed_tests.append("PLATFORM-10")

    finally:
        # Clean up temporary decompiled files at the very end
        if temp_dir:
            print(f"\n[+] Cleaning up temporary files")
            shutil.rmtree(temp_dir, ignore_errors=True)


    # Future test cases can be added here easily:
    #
    # # Test Case 2: MASTG-STORAGE-12 - Storage Analysis
    # result2 = analyze_storage(package_name=PACKAGE_NAME)
    #
    # # Test Case 3: MASTG-STORAGE-13 - Permission Check
    # result3 = analyze_permissions(package_name=PACKAGE_NAME)

    print("\n" + "=" * 60)
    if failed_tests:
        print(f"[-] {len(failed_tests)} test(s) failed: {', '.join(failed_tests)}")
    else:
        print("[+] All tests completed successfully")
    print("=" * 60)


if __name__ == "__main__":
    main()
