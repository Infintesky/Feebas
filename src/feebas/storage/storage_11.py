#!/usr/bin/env python3
"""APK analysis module for extracting application information."""
import re
import os
import tempfile
from utils.adb import run_command, get_package_path, pull_apk


def parse_aapt_output(aapt_output):
    """Parse aapt dump badging output and extract required fields."""
    info = {
        'application-label': None,
        'package_name': None,
        'launchable-activity': None,
        'compileSdkVersion': None,
        'sdkVersion': None,
        'versionName': None,
        'versionCode': None
    }
    
    lines = aapt_output.split('\n')
    
    for line in lines:
        # Extract package name
        if line.startswith('package:') and info['package_name'] is None:
            match = re.search(r"name='([^']+)'", line)
            if match:
                info['package_name'] = match.group(1)
            
            # Extract versionCode
            match = re.search(r"versionCode='([^']+)'", line)
            if match:
                info['versionCode'] = match.group(1)
            
            # Extract versionName
            match = re.search(r"versionName='([^']+)'", line)
            if match:
                info['versionName'] = match.group(1)
            
            # Extract compileSdkVersion
            match = re.search(r"compileSdkVersion='([^']+)'", line)
            if match:
                info['compileSdkVersion'] = match.group(1)
        
        # Extract application-label (first occurrence without locale suffix)
        if line.startswith('application-label:') and info['application-label'] is None:
            match = re.search(r"application-label:'([^']+)'", line)
            if match:
                info['application-label'] = match.group(1)
        
        # Extract sdkVersion
        if line.startswith('sdkVersion:') and info['sdkVersion'] is None:
            match = re.search(r"sdkVersion:'([^']+)'", line)
            if match:
                info['sdkVersion'] = match.group(1)
        
        # Extract launchable-activity name
        if line.startswith('launchable-activity:') and info['launchable-activity'] is None:
            match = re.search(r"name='([^']+)'", line)
            if match:
                info['launchable-activity'] = match.group(1)
    
    return info


def dump_apk_info(apk_path):
    """Run aapt dump badging on the APK and return the output."""
    print(f"[+] Running aapt dump badging on: {apk_path}")
    
    result = run_command(["aapt", "dump", "badging", apk_path], timeout=30)
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to run aapt dump badging")
        return None
    
    return result.stdout


def print_info(info, test_id):
    """Print extracted information in a formatted way."""
    print("\n" + "=" * 60)
    print(f"[*] {test_id}")
    print("=" * 60)
    
    fields = [
        ('Application Label', 'application-label'),
        ('Package Name', 'package_name'),
        ('Main Activity', 'launchable-activity'),
        ('Target SDK', 'compileSdkVersion'),
        ('Min SDK Version', 'sdkVersion'),
        ('Version Name', 'versionName'),
        ('Version Code', 'versionCode'),
    ]
    
    for label, key in fields:
        value = info.get(key, 'Not found')
        print(f"{label:25s}: {value}")
    
    print("=" * 60)


def analyze_apk_from_device(package_name, test_id="MASTG-STORAGE-11 - Testing the Device-Access-Security Policy"):
    """
    Complete workflow: Get APK from device, analyze it, and print results.
    
    Args:
        package_name: The Android package name to analyze
        test_id: Test identifier for reporting (default: MASTG-STORAGE-11)
    
    Returns:
        dict: Extracted APK information, or None if failed
    """
    # Get package path from device
    apk_path = get_package_path(package_name)
    if not apk_path:
        return None
    
    # Create temporary directory for the APK
    with tempfile.TemporaryDirectory() as temp_dir:
        local_apk = os.path.join(temp_dir, "base.apk")
        
        # Pull APK from device
        if not pull_apk(apk_path, local_apk):
            return None
        
        # Run aapt dump badging
        aapt_output = dump_apk_info(local_apk)
        if not aapt_output:
            return None
        
        # Parse and extract information
        info = parse_aapt_output(aapt_output)
        
        # Print results
        print_info(info, test_id)
        
        return info
