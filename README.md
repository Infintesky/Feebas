# Feebas - Android Security Testing Framework

<p align="center">
  <img src="https://img.pokemondb.net/artwork/large/feebas.jpg" alt="Feebas" width="300"/>
</p>

Automated MASVS/MASTG test cases for Android security analysis.

**Note:** This framework is designed exclusively for Android applications. All tests target Android APK files and require an Android device or emulator.

## Implemented Tests

- MSTG-STORAGE-11 - Testing the Device-Access-Security Policy
- MSTG-STORAGE-1 - Data Stored in the App Sandbox at Runtime
- MSTG-STORAGE-3 - Testing Logs for Sensitive Data
- MSTG-STORAGE-8 - Testing Backups for Sensitive Data
- MSTG-CRYPTO-1 - Testing for Insecure Cryptographic Algorithms
- MSTG-CRYPTO-2/3/4 - Cryptographic API Usage Analysis
- MSTG-CRYPTO-5 - Testing Key Management
- MSTG-CRYPTO-6 - Testing Random Number Generation
- MSTG-NETWORK-1 - Testing Data Encryption on the Network
- MSTG-NETWORK-3 - Testing the Security Provider (Certificate Pinning)
- MSTG-PLATFORM-2 - Testing Implicit Intents and WebView Configuration
- MSTG-PLATFORM-4 - Testing Exported Components
- MSTG-PLATFORM-6 - Testing WebView Security Configuration
- MSTG-PLATFORM-7 - Testing for Java Objects Exposed Through WebViews
- MSTG-PLATFORM-10 - Testing Cached Sensitive Data

## Dependencies

- adb (Android Debug Bridge)
- aapt (Android Asset Packaging Tool)
- apktool (APK decompilation tool)
- jadx (Dex to Java decompiler)

## Installation

### Prerequisites
- Python 3.9 or higher
- Android device or emulator connected via ADB

### Setup

1. Configure `src/feebas/config.py` with your package name and test data

2. Connect your Android device via ADB

## Usage

Run the tests:

```bash
python src/feebas/main.py
```

## Configuration

Edit `src/feebas/config.py`:
- `PACKAGE_NAME`: Android package name to test
- `TEST_NRIC`: Test data for sensitive data detection
- `HTTP_URL_WHITELIST`: List of safe HTTP URLs to exclude from network security checks (e.g., Android schemas, localhost)
