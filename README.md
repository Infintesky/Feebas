# Feebas - Android Security Testing Framework

<p align="center">
  <img src="https://img.pokemondb.net/artwork/large/feebas.jpg" alt="Feebas" width="300"/>
</p>

Automated MASVS/MASTG test cases for Android security analysis.

**Note:** This framework is designed exclusively for Android applications. All tests target Android APK files and require an Android device or emulator.

## Implemented Tests

### MASTG-STORAGE Tests
- **MASTG-STORAGE-11** - Testing the Device-Access-Security Policy
  - Extracts APK metadata using `aapt dump badging`
- **MASTG-STORAGE-1** - Data Stored in the App Sandbox at Runtime
  - Searches app sandbox for sensitive data (requires root)
- **MASTG-STORAGE-3** - Testing Logs for Sensitive Data
  - Scans logcat output for sensitive information
- **MASTG-STORAGE-8** - Testing Backups for Sensitive Data
  - Checks if `android:allowBackup` is disabled

### MASTG-CRYPTO Tests
- **MASTG-CRYPTO-1** - Testing for Insecure Cryptographic Algorithms
  - Detects hardcoded keys and weak algorithms (DES, 3DES, RC4, Blowfish)
- **MASTG-CRYPTO-2/3/4** - Cryptographic API Usage Analysis
  - Identifies weak primitives (ECB mode, MD5, SHA-1, small key sizes)
- **MASTG-CRYPTO-5** - Testing Key Management
  - Detects insecure key storage and hardcoded encryption keys
- **MASTG-CRYPTO-6** - Testing Random Number Generation
  - Identifies insecure Random() vs SecureRandom usage

### MASTG-NETWORK Tests
- **MASTG-NETWORK-1** - Testing Data Encryption on the Network
  - Detects hardcoded HTTP URLs and cleartext traffic configuration
- **MASTG-NETWORK-3** - Testing the Security Provider (Certificate Pinning)
  - Verifies network_security_config.xml with certificate pinning

### MASTG-CODE Tests
- **MASTG-CODE-1** - Testing Certificate Security (MobSF)
  - Checks signature schemes (v1/v2/v3/v4) from MobSF report
  - Validates key size ≥ 2048 bits (fallback to apksigner if needed)
  - Detects debug certificates and v1 signature vulnerabilities
- **MASTG-CODE-2** - Testing for Debugging Flags and WebView Debugging
  - Verifies `android:debuggable` is false or not set
  - Detects unconditional `WebView.setWebContentsDebuggingEnabled(true)`
- **MASTG-CODE-3** - Testing for Debugging Symbols (MobSF)
  - Ensures symbols are stripped from all shared libraries
- **MASTG-CODE-4** - Testing for Debugging Code and Verbose Error Logging
  - Searches logcat for StrictMode occurrences
- **MASTG-CODE-9** - Testing Binary Protection Mechanisms (MobSF)
  - Verifies PIE and Stack Canary enabled for all libraries

### MASTG-PLATFORM Tests
- **MASTG-PLATFORM-1** - Testing App Permissions (MobSF)
  - Lists dangerous and unknown permissions
- **MASTG-PLATFORM-2** - Testing Implicit Intents and WebView Configuration
  - Detects dangerous intent filters and disabled SafeBrowsing
- **MASTG-PLATFORM-4** - Testing Exported Components
  - Finds unprotected exported components and mutable PendingIntents
- **MASTG-PLATFORM-6** - Testing WebView Security Configuration
  - Checks WebView security settings (file access, content access, etc.)
- **MASTG-PLATFORM-7** - Testing for Java Objects Exposed Through WebViews
  - Detects JavaScript interface exposure with minSdkVersion < 17
- **MASTG-PLATFORM-10** - Testing Cached Sensitive Data
  - Searches app cache for sensitive information (requires root)

### MASTG-RESILIENCE Tests
- **MASTG-RESILIENCE-2** - Testing Anti-Debugging Detection
  - Verifies `android:debuggable` is false or not set in manifest

## Dependencies

### System Tools
- adb (Android Debug Bridge)
- aapt (Android Asset Packaging Tool)
- apktool (APK decompilation tool)
- jadx (Dex to Java decompiler)
- apksigner (Android APK Signing Tool) - for certificate key size extraction
- Docker (for MobSF integration)

### Python Libraries
- Python 3.9 or higher
- requests (`pip install requests`) - for MobSF API integration

## Installation

### Prerequisites
- Python 3.9 or higher
- Android device or emulator connected via ADB
- Docker installed and running (for MobSF tests)

### Setup

1. Install Python dependencies:
```bash
pip install requests
```

2. Configure `src/feebas/config.py` with your package name and test data

3. Connect your Android device via ADB

4. (Optional) Pre-pull MobSF Docker image to save time on first run:
```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
```

## Usage

Run all tests:

```bash
python src/feebas/main.py
```

The framework will:
1. Pull and decompile the APK from the connected device
2. Start MobSF Docker container and perform static analysis
3. Run all MASVS test cases sequentially
4. Display results and summary

## Configuration

Edit `src/feebas/config.py`:
- `PACKAGE_NAME`: Android package name to test
- `TEST_NRIC`: Test data for sensitive data detection

## MobSF Integration

Tests marked with **(MobSF)** require MobSF Docker container:
- MASTG-PLATFORM-1 - App Permissions analysis
- MASTG-CODE-1 - Certificate security analysis (signature schemes, key size)
- MASTG-CODE-3 - Debugging symbols analysis (symbols stripped)
- MASTG-CODE-9 - Binary protection mechanisms (PIE, Stack Canary)

MobSF provides comprehensive static analysis including:
- Permission analysis with risk classification
- Certificate security analysis (signature versions, key sizes)
- Binary security analysis (PIE, Stack Canary, symbols stripped, etc.)
- Security scoring and detailed findings

The framework automatically:
- Starts MobSF container on first run
- Pulls Docker image if not cached (~2GB download)
- Stores scan results in persistent Docker volume
- Cleans up container after tests complete
