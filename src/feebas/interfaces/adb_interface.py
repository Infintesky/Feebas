#!/usr/bin/env python3
"""ADB interface module for device communication."""
import subprocess
import os


def run_command(cmd, timeout=30, encoding_errors='strict'):
    """
    Run a shell command and return the result.

    Args:
        cmd: Command to run as a list
        timeout: Timeout in seconds
        encoding_errors: How to handle encoding errors ('strict', 'replace', 'ignore')
                        Use 'replace' for commands that may output non-UTF-8 data
    """
    try:
        # Capture as bytes first
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=timeout,
            shell=False
        )

        # Decode with error handling
        try:
            result.stdout = result.stdout.decode('utf-8', errors=encoding_errors)
            result.stderr = result.stderr.decode('utf-8', errors=encoding_errors)
        except Exception as e:
            print(f"[-] Error decoding output: {e}")
            return None

        return result
    except subprocess.TimeoutExpired:
        print(f"[-] Error: Command timed out: {' '.join(cmd)}")
        return None
    except Exception as e:
        print(f"[-] Error running command: {e}")
        return None


def get_package_path(package_name):
    """Get the APK path for a given package name on the device."""
    print(f"[+] Finding APK path for package: {package_name}")
    
    result = run_command(["adb", "shell", "pm", "path", package_name])
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to find package '{package_name}'")
        return None
    
    # Output format: package:/data/app/package.name/base.apk
    output = result.stdout.strip()
    
    if not output.startswith("package:"):
        print(f"[-] Error: Unexpected output format: {output}")
        return None
    
    apk_path = output.replace("package:", "")
    print(f"[+] Found APK at: {apk_path}")
    
    return apk_path


def pull_apk(apk_path, local_path):
    """Pull the APK from the device to local storage."""
    print(f"[+] Pulling APK to: {local_path}")
    
    result = run_command(["adb", "pull", apk_path, local_path], timeout=60)
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to pull APK")
        return False
    
    if not os.path.exists(local_path):
        print(f"[-] Error: APK file not found at {local_path} after pull")
        return False
    
    print("[+] APK pulled successfully")
    return True
