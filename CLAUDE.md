# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Feebas is an automated Android security testing framework that implements tests based on the Mobile Application Security Verification Standard (MASVS) and Mobile Application Security Testing Guide (MASTG).

**Important:** This framework is designed exclusively for Android applications. All tests target Android APK files and require an Android device or emulator.

The tool connects to Android devices via ADB, extracts and decompiles APK files, analyzes source code and resources, and examines runtime storage for security vulnerabilities.

## Development Commands

**Run the security tests:**
```bash
python src/feebas/main.py
```

This project has no external Python dependencies - it only requires Python 3.9+ and the system tools listed in the External Dependencies section.

## Project Structure

```
src/feebas/
├── main.py              # Test orchestrator
├── config.py            # Configuration (PACKAGE_NAME, TEST_NRIC)
├── utils/               # Shared utilities
│   ├── adb.py           # ADB command wrapper
│   ├── apk.py           # APK decompilation utilities (jadx, apktool)
│   └── mobsf.py         # MobSF Docker integration
├── storage/             # MASVS-STORAGE test modules
│   ├── storage_1.py     # Runtime storage analysis
│   ├── storage_3.py     # Logcat analysis
│   ├── storage_8.py     # Backup settings analysis
│   └── storage_11.py    # APK metadata analysis
├── crypto/              # MASVS-CRYPTO test modules
│   ├── crypto_1.py      # Insecure cryptographic algorithms
│   ├── crypto_234.py    # Cryptographic API usage analysis
│   ├── crypto_5.py      # Key management analysis
│   └── crypto_6.py      # Random number generation analysis
├── network/             # MASVS-NETWORK test modules
│   ├── network_1.py     # Network encryption analysis
│   └── network_3.py     # Certificate pinning analysis
├── code/                # MASVS-CODE test modules
│   ├── code_1.py        # Certificate security analysis (MobSF)
│   ├── code_2.py        # Debugging flags and WebView debugging
│   ├── code_3.py        # Debugging symbols analysis (MobSF)
│   ├── code_4.py        # Debugging code and verbose error logging
│   └── code_9.py        # Binary protection mechanisms (MobSF)
├── platform/            # MASVS-PLATFORM test modules
│   ├── platform_1.py    # Application permissions analysis (MobSF)
│   ├── platform_2.py    # Implicit intents and WebView SafeBrowsing
│   ├── platform_4.py    # Exported components and PendingIntent analysis
│   ├── platform_6.py    # WebView security configuration
│   ├── platform_7.py    # JavaScript interface exposure
│   └── platform_10.py   # Cache data analysis
└── resilience/          # MASVS-RESILIENCE test modules
    └── resilience_2.py  # Anti-debugging detection
```

## Architecture

### Core Components

1. **main.py** - Test orchestrator that runs MASVS test suites
   - Prepares APK once at start (pulls and decompiles with jadx + apktool)
   - Executes all implemented MASTG test cases sequentially
   - Tracks failed tests and reports summary at end
   - Does NOT exit on test failures (continues running all tests)
   - Cleans up temporary files in finally block

2. **config.py** - Central configuration
   - `PACKAGE_NAME`: Target Android package to test
   - `TEST_NRIC`: Test data to search for in storage/cache analysis
   - `HTTP_URL_WHITELIST`: List of safe HTTP URLs to exclude from network checks
   - `DANGEROUS_SYSTEM_ACTIONS`: List of dangerous intent actions for implicit intent checks

3. **utils/apk.py** - APK preparation utilities
   - `prepare_apk_for_analysis()`: Pulls APK and decompiles once with both jadx and apktool
   - `decompile_apk_with_jadx()`: Decompiles to Java source (sources/)
   - `decompile_apk_with_apktool()`: Decompiles to resources/manifest
   - Returns: (temp_dir, sources_dir, apktool_dir)

4. **utils/adb.py** - Low-level ADB command wrapper
   - `run_command()`: Executes subprocess commands with timeout and encoding error handling
   - `get_package_path()`: Locates APK file path on device
   - `pull_apk()`: Downloads APK from device to local filesystem

5. **utils/mobsf.py** - MobSF Docker integration
   - `start_mobsf_container()`: Starts MobSF Docker container with persistent volume
   - `get_mobsf_api_key()`: Retrieves API key from container logs
   - `upload_apk()`: Uploads APK file to MobSF
   - `scan_apk()`: Triggers static analysis scan (up to 10 min timeout)
   - `get_json_report()`: Retrieves JSON report with security findings
   - `download_pdf_report()`: Downloads PDF report to specified path
   - `stop_mobsf_container()`: Stops and removes container
   - `analyze_apk_with_mobsf()`: Complete workflow (start → upload → scan → report)

### Test Categories

#### MASTG-STORAGE Tests

- **storage_11.py** - Device-Access-Security Policy
  - Uses `aapt dump badging` to extract app information
  - Parses package name, version, SDK versions, activities

- **storage_1.py** - Runtime storage analysis
  - Examines `/data/data/{package}` directories on rooted devices
  - Lists databases, shared preferences
  - Searches for TEST_NRIC using grep
  - Requires root access via `adb shell su -c`

- **storage_3.py** - Logcat analysis
  - Captures device logs using `adb logcat`
  - Searches for TEST_NRIC (last 5 chars) in logs

- **storage_8.py** - Backup settings analysis
  - Uses apktool decompiled AndroidManifest.xml
  - Checks `android:allowBackup` setting

#### MASTG-CRYPTO Tests

- **crypto_1.py** - Insecure cryptographic algorithms
  - Uses jadx decompiled source code
  - Searches for cryptographic keywords
  - Detects hardcoded keys (byte arrays, hex strings)
  - Identifies insecure algorithms (DES, 3DES, RC4, Blowfish)

- **crypto_234.py** - Cryptographic API usage
  - Searches for weak cryptographic primitives
  - Detects ECB mode, weak hash algorithms (MD5, SHA-1)
  - Identifies small key sizes

- **crypto_5.py** - Key management
  - Detects hardcoded encryption keys
  - Identifies insecure key storage (SharedPreferences, files)
  - Checks for proper KeyStore usage

- **crypto_6.py** - Random number generation
  - Detects insecure Random() vs SecureRandom usage
  - Identifies non-random sources (timestamps, dates)

#### MASTG-NETWORK Tests

- **network_1.py** - Network encryption
  - Searches for hardcoded HTTP URLs in source code
  - Checks for cleartext traffic allowed in manifest
  - Uses HTTP_URL_WHITELIST to filter safe URLs

- **network_3.py** - Certificate pinning
  - Checks for network_security_config.xml
  - Verifies pin-set configuration

#### MASTG-CODE Tests

- **code_1.py** - Certificate security analysis (MobSF-based)
  - Parses MobSF `certificate_analysis.certificate_info` string
  - Checks which signature schemes are used (v1, v2, v3, v4)
  - Validates certificate key size (minimum 2048 bits)
  - Falls back to `apksigner verify --print-certs` if key size not in MobSF report
  - Fails if v1 signature is enabled (vulnerable to Janus attack)
  - Fails if no modern signature (v2/v3/v4) is being used
  - Fails if signed with debug certificate

- **code_2.py** - Debugging flags and WebView debugging
  - Checks android:debuggable flag in AndroidManifest.xml
  - Searches for WebView.setWebContentsDebuggingEnabled(true) in source code
  - Searches for ApplicationInfo.FLAG_DEBUGGABLE references
  - Fails if WebView debugging is enabled unconditionally (without FLAG_DEBUGGABLE or BuildConfig.DEBUG check)

- **code_3.py** - Debugging symbols analysis (MobSF-based)
  - Uses MobSF JSON report to analyze shared library debugging symbols
  - Checks if symbols are stripped for all libraries
  - Reports libraries with symbols not stripped

- **code_4.py** - Debugging code and verbose error logging
  - Captures device logs using `adb logcat`
  - Searches for StrictMode occurrences in logcat output
  - Fails if StrictMode is detected in logcat

- **code_9.py** - Binary protection mechanisms (MobSF-based)
  - Uses MobSF JSON report to analyze shared library binary protections
  - Checks PIE (Position Independent Executable) enabled for all libraries
  - Checks Stack Canary enabled for all libraries
  - Reports libraries missing security protections

#### MASTG-PLATFORM Tests

- **platform_1.py** - Application permissions analysis (MobSF-based)
  - Uses MobSF JSON report to analyze permissions
  - Lists dangerous permissions (status: "dangerous")
  - Lists unknown permissions (status: "unknown")
  - Provides permission descriptions and recommendations

- **platform_2.py** - Implicit intents and WebView SafeBrowsing
  - Detects dangerous system actions in intent filters
  - Checks if SafeBrowsing is disabled

- **platform_4.py** - Exported components and PendingIntent
  - Finds exported activities/services/receivers without permissions
  - Checks for exported ContentProviders via dumpsys
  - Detects mutable PendingIntent usage (FLAG_MUTABLE or missing FLAG_IMMUTABLE)

- **platform_6.py** - WebView security configuration
  - Searches for setAllowContentAccess, setAllowFileAccess, etc.
  - Ensures all settings are set to false

- **platform_7.py** - JavaScript interface exposure
  - Checks if WebView is used
  - Detects addJavascriptInterface usage
  - Verifies minSdkVersion >= 17 for @JavascriptInterface protection

- **platform_10.py** - Cache data analysis
  - Searches for TEST_NRIC in `/data/data/{package}/cache`
  - Uses `adb shell su -c grep` with root access

#### MASTG-RESILIENCE Tests

- **resilience_2.py** - Anti-debugging detection
  - Checks android:debuggable flag in AndroidManifest.xml
  - Verifies debuggable is false or not set

### Test Design Pattern

Each MASTG test module follows this structure:
- Analysis function that performs the test (e.g., `analyze_*()`)
- Returns dict with `{'passed': bool, ...}` on success, `{'passed': False, 'error': str}` on failure
- Test header printed with "=" * 80 delimiter
- Detailed findings printed with appropriate formatting
- Pass/fail determination at end

### Decompilation Strategy

The framework uses **two decompilers** to get different views of the APK:
1. **jadx** - Produces Java source code for analysis (crypto, platform tests)
2. **apktool** - Produces resources and readable AndroidManifest.xml (network, platform tests)

Both are run once at the start via `prepare_apk_for_analysis()` and the results are passed to individual tests.

### External Dependencies

**Required tools (must be in PATH):**
- `adb` - Android Debug Bridge for device communication
- `aapt` - Android Asset Packaging Tool for APK metadata analysis
- `apktool` - APK decompilation tool for manifest and resources
- `jadx` - Dex to Java decompiler for source code analysis
- `apksigner` - Android APK Signing Tool for certificate analysis (fallback for CODE-1)
- `docker` - Container platform for MobSF integration

**Device requirements:**
- Connected Android device or emulator
- USB debugging enabled
- Root access for storage/cache analysis tests

## MobSF Integration

The framework includes integration with [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) for comprehensive static analysis.

### MobSF Setup

**Requirements:**
- Docker installed and running
- Python `requests` library: `pip install requests`

**Docker image:**
- `opensecurity/mobile-security-framework-mobsf:latest`
- ~2GB download on first run (automatically pulled by the framework)

**First-time setup:**
The framework automatically checks if the MobSF Docker image exists locally. On first run, it will pull the image automatically (this may take several minutes depending on internet connection). Subsequent runs will use the cached image.

**Persistent storage:**
MobSF data is stored in a Docker volume named `mobsf_data`, which persists scan results across container restarts. To remove all MobSF data:
```bash
docker volume rm mobsf_data
```

### Using MobSF

**Complete workflow (recommended):**
```python
from utils.mobsf import analyze_apk_with_mobsf

result = analyze_apk_with_mobsf(
    apk_path='base.apk',
    container_name='mobsf',
    port=8000,
    cleanup=False  # Set to True to remove container after analysis
)

if result['success']:
    report = result['report']
    print(f"Security Score: {report['security_score']}")
    print(f"App Name: {report['app_name']}")
    # Access findings: report['android_api'], report['manifest_analysis'], etc.
else:
    print(f"Error: {result['error']}")
```

**Individual steps:**
```python
from utils.mobsf import (
    start_mobsf_container,
    get_mobsf_api_key,
    upload_apk,
    scan_apk,
    get_json_report,
    download_pdf_report,
    stop_mobsf_container
)

# 1. Start container
start_mobsf_container(container_name='mobsf', port=8000)

# 2. Get API key
api_key = get_mobsf_api_key(container_name='mobsf')

# 3. Upload APK
upload_result = upload_apk('base.apk', api_key)
file_hash = upload_result['hash']

# 4. Scan APK
scan_apk(file_hash, api_key)

# 5. Get JSON report
report = get_json_report(file_hash, api_key)

# 6. Download PDF report (optional)
download_pdf_report(file_hash, api_key, 'report.pdf')

# 7. Cleanup (optional)
stop_mobsf_container(container_name='mobsf')
```

### MobSF Report Structure

The JSON report contains comprehensive security analysis:
- `app_name`, `package_name`, `version_name`
- `security_score` - Overall security score (0-100)
- `android_api` - Android API usage findings
- `manifest_analysis` - Manifest security issues
- `certificate_analysis` - Certificate information
- `code_analysis` - Source code security findings
- `network_security` - Network security configuration
- `permissions` - Permission analysis
- And many more categories...

### API Reference

The MobSF utility supports all MobSF REST API endpoints:

**Static Analysis:**
- `api/v1/upload` - Upload APK file
- `api/v1/scan` - Trigger static analysis
- `api/v1/report_json` - Get JSON report
- `api/v1/download_pdf` - Download PDF report
- `api/v1/delete_scan` - Delete scan results

**Dynamic Analysis:**
- `api/v1/dynamic/start_analysis` - Start dynamic analysis
- `api/v1/dynamic/stop_analysis` - Stop dynamic analysis
- `api/v1/dynamic/report_json` - Get dynamic analysis report

See [MobSF API Documentation](https://mobsf.github.io/docs/#/rest_api) for complete API reference.

## Test Summary

The framework currently implements **21 MASTG test cases** across 6 categories:
- **MASTG-STORAGE** (4 tests): Data storage, logs, backups
- **MASTG-CRYPTO** (4 tests): Cryptographic implementation, keys, random number generation
- **MASTG-NETWORK** (2 tests): Network encryption, certificate pinning
- **MASTG-CODE** (5 tests): Certificate security, debugging detection, binary protections
- **MASTG-PLATFORM** (5 tests): Permissions, intents, WebView security, exported components
- **MASTG-RESILIENCE** (1 test): Anti-debugging detection

**MobSF-dependent tests** (require Docker):
- MASTG-PLATFORM-1 (permissions)
- MASTG-CODE-1 (certificate security - with apksigner fallback)
- MASTG-CODE-3 (debugging symbols)
- MASTG-CODE-9 (binary protections)

**Root-required tests**:
- MASTG-STORAGE-1 (app sandbox access)
- MASTG-PLATFORM-10 (cache access)

## Adding New Tests

To add a new MASTG test case:

1. Create a new module in the appropriate category folder:
   - Storage: `src/feebas/storage/storage_X.py`
   - Crypto: `src/feebas/crypto/crypto_X.py`
   - Network: `src/feebas/network/network_X.py`
   - Code: `src/feebas/code/code_X.py`
   - Platform: `src/feebas/platform/platform_X.py`
   - Resilience: `src/feebas/resilience/resilience_X.py`

2. Import required utilities:
   ```python
   from utils.adb import run_command
   # For jadx source analysis:
   # sources_dir parameter from prepare_apk_for_analysis()
   # For manifest/resource analysis:
   # apktool_dir parameter from prepare_apk_for_analysis()
   ```

3. Implement an `analyze_*()` function:
   ```python
   def analyze_feature(sources_dir, apktool_dir, test_id="MASTG-X-Y - Test Name"):
       print("\n" + "=" * 80)
       print(f"{test_id}")
       print("=" * 80)

       # Perform analysis

       print("-" * 80)
       print()

       # Determine pass/fail
       if has_issues:
           print("[!] FAIL: ...")
       else:
           print("[+] PASS: ...")

       print("=" * 80)

       return {'passed': not has_issues, ...}
   ```

4. Import and call the test in `main.py`:
   - Add import at top
   - Add test execution in appropriate MASVS section
   - Handle result and track failures
   - For MobSF-based tests, check if `mobsf_report` is available before running

5. Update README.md implemented tests list

6. Consider test ordering: tests are run in the order they appear in main.py

**IMPORTANT:** Do NOT create example scripts or example files. The test modules themselves should be self-documenting with clear function signatures and docstrings.

## Key Implementation Details

- **No sys.exit() on failures**: Tests continue even if some fail
- **Single APK decompilation**: APK is pulled and decompiled once at start, not per-test
- **MobSF integration**: MobSF Docker container started at beginning, report used for permission analysis
- **Cleanup in finally block**: Temporary files and MobSF container cleaned up even on errors
- **Root access**: Some tests require `adb shell su -c` for device access
- **Encoding handling**: ADB outputs use errors='replace' for non-UTF-8 content
- **MobSF-based tests**: Tests requiring MobSF report are skipped if MobSF analysis fails
- **No example files**: Test modules are self-documenting; no separate example scripts are created
