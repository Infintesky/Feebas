#!/usr/bin/env python3
"""Storage analysis module for examining app data directories."""
from utils.adb import run_command


def list_app_data_directory(package_name):
    """List contents of app's data directory."""
    data_path = f"/data/data/{package_name}"
    print(f"[+] Listing contents of: {data_path}")
    
    result = run_command(["adb", "shell", "su", "-c", f"ls -ltr {data_path}"])
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to list directory")
        if result:
            print(f"[-] Error message: {result.stderr}")
        return None
    
    return result.stdout


def search_data_directory(package_name, search_term):
    """Search for a term in the app's data directory."""
    data_path = f"/data/data/{package_name}"
    print(f"[+] Searching for '{search_term}' in: {data_path}")
    
    # Using grep with 2>/dev/null to suppress errors
    result = run_command([
        "adb", "shell", "su", "-c",
        f"grep -Ri '{search_term}' {data_path} 2>/dev/null"
    ])
    
    # grep returns 1 when no matches found, which is not an error for our purposes
    if not result:
        print(f"[-] Error: Failed to search directory")
        return None
    
    if result.returncode == 1:
        print(f"[+] No matches found for '{search_term}'")
        return ""
    
    return result.stdout


def list_databases(package_name):
    """List database files in the app's databases directory."""
    databases_path = f"/data/data/{package_name}/databases"
    print(f"[+] Listing databases in: {databases_path}")
    
    result = run_command(["adb", "shell", "su", "-c", f"ls -ltr {databases_path}"])
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to list databases directory")
        if result:
            print(f"[-] Error message: {result.stderr}")
        return None
    
    return result.stdout


def list_shared_prefs(package_name):
    """List shared preferences files."""
    shared_prefs_path = f"/data/data/{package_name}/shared_prefs"
    print(f"[+] Listing shared preferences in: {shared_prefs_path}")
    
    result = run_command(["adb", "shell", "su", "-c", f"ls -ltr {shared_prefs_path}"])
    
    if not result or result.returncode != 0:
        print(f"[-] Error: Failed to list shared_prefs directory")
        if result:
            print(f"[-] Error message: {result.stderr}")
        return None
    
    return result.stdout


def print_storage_info(data_listing, search_result, databases_listing, shared_prefs_listing, package_name, search_term=None, test_id="STORAGE-1"):
    """Print storage analysis results in a formatted way."""
    print("\n" + "=" * 60)
    print(f"[*] {test_id}")
    print("=" * 60)
    
    if data_listing:
        print(f"\n[+] Running adb shell su -c 'ls -ltr /data/data/{package_name}'")
        print(data_listing)
    
    if search_result is not None:
        print(f"\n[+] Running adb shell su -c 'grep -Ri \"{search_term}\" /data/data/{package_name} 2>/dev/null'")
        if search_result:
            print(search_result)
        else:
            print("No matches found")
    
    if databases_listing:
        print(f"\n[+] Running adb shell su -c 'ls -ltr /data/data/{package_name}/databases'")
        print(databases_listing)
    
    if shared_prefs_listing:
        print(f"\n[+] Running adb shell su -c 'ls -ltr /data/data/{package_name}/shared_prefs'")
        print(shared_prefs_listing)
    
    print("=" * 60)


def analyze_storage(package_name, search_term=None, test_id="STORAGE-1"):
    """
    Complete storage analysis workflow.
    
    Args:
        package_name: The Android package name to analyze
        search_term: Optional term to search for in data directory
        test_id: Test identifier for reporting (default: STORAGE-1)
    
    Returns:
        dict: Storage analysis results, or None if failed
    """
    results = {
        'data_listing': None,
        'search_result': None,
        'databases_listing': None,
        'shared_prefs_listing': None
    }
    
    # List main data directory
    results['data_listing'] = list_app_data_directory(package_name)
    if not results['data_listing']:
        print(f"[-] Failed to access app data directory")
        return None
    
    # Search for specific term if provided
    if search_term:
        results['search_result'] = search_data_directory(package_name, search_term)
    
    # List databases
    results['databases_listing'] = list_databases(package_name)
    
    # List shared preferences
    results['shared_prefs_listing'] = list_shared_prefs(package_name)
    
    # Print formatted results
    print_storage_info(
        results['data_listing'],
        results['search_result'],
        results['databases_listing'],
        results['shared_prefs_listing'],
        package_name,
        search_term,
        test_id
    )
    
    return results
