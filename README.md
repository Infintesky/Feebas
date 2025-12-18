# Feebas - Android Security Testing Framework

<p align="center">
  <img src="https://img.pokemondb.net/artwork/large/feebas.jpg" alt="Feebas" width="300"/>
</p>

Automated MASVS/MASTG test cases for Android security analysis.

**Note:** This framework is designed exclusively for Android applications. All tests target Android APK files and require an Android device or emulator.

## Implemented Tests

### MASVS-STORAGE Tests
- MSTG-STORAGE-11 - Testing the Device-Access-Security Policy
- MSTG-STORAGE-1 - Data Stored in the App Sandbox at Runtime
- MSTG-STORAGE-3 - Testing Logs for Sensitive Data
- MSTG-STORAGE-8 - Testing Backups for Sensitive Data

### MASVS-CRYPTO Tests
- MSTG-CRYPTO-1 - Testing for Insecure Cryptographic Algorithms
- MSTG-CRYPTO-2/3/4 - Cryptographic API Usage Analysis
- MSTG-CRYPTO-5 - Testing Key Management
- MSTG-CRYPTO-6 - Testing Random Number Generation

### MASVS-NETWORK Tests
- MSTG-NETWORK-1 - Testing Data Encryption on the Network
- MSTG-NETWORK-3 - Testing the Security Provider (Certificate Pinning)

### MASVS-CODE Tests
- MSTG-CODE-1 - Testing Certificate Security (MobSF)
- MSTG-CODE-2 - Testing for Debugging Flags and WebView Debugging
- MSTG-CODE-3 - Testing for Debugging Symbols (MobSF)
- MSTG-CODE-4 - Testing for Debugging Code and Verbose Error Logging
- MSTG-CODE-9 - Testing Binary Protection Mechanisms (MobSF)

### MASVS-PLATFORM Tests
- MSTG-PLATFORM-1 - Testing App Permissions (MobSF)
- MSTG-PLATFORM-2 - Testing Implicit Intents and WebView Configuration
- MSTG-PLATFORM-4 - Testing Exported Components
- MSTG-PLATFORM-6 - Testing WebView Security Configuration
- MSTG-PLATFORM-7 - Testing for Java Objects Exposed Through WebViews
- MSTG-PLATFORM-10 - Testing Cached Sensitive Data

### MASVS-RESILIENCE Tests
- MSTG-RESILIENCE-2 - Testing Anti-Debugging Detection

## Dependencies

### System Tools
- adb (Android Debug Bridge)
- aapt (Android Asset Packaging Tool)
- apktool (APK decompilation tool)
- jadx (Dex to Java decompiler)
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
- PLATFORM-1 - App Permissions analysis
- CODE-1 - Certificate security analysis (signature schemes, key size)
- CODE-3 - Debugging symbols analysis (symbols stripped)
- CODE-9 - Binary protection mechanisms (PIE, Stack Canary)

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
