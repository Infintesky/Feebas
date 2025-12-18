#!/usr/bin/env python3
"""MobSF Docker interface for static analysis."""
import subprocess
import time
import re
import requests
import os


def strip_ansi_codes(text):
    """
    Remove ANSI escape codes from text.

    Args:
        text: Text containing ANSI codes

    Returns:
        str: Text with ANSI codes removed
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def start_mobsf_container(container_name='mobsf', port=8000, image='opensecurity/mobile-security-framework-mobsf:latest'):
    """
    Start MobSF Docker container.

    Args:
        container_name: Name for the Docker container
        port: Port to expose MobSF on (default: 8000)
        image: Docker image to use

    Returns:
        bool: True if started successfully, False otherwise
    """
    print(f"[+] Starting MobSF Docker container '{container_name}'...")

    # Check if Docker image exists locally
    print(f"[+] Checking if Docker image '{image}' exists locally...")
    result = subprocess.run(
        ['docker', 'images', '-q', image],
        capture_output=True,
        text=True
    )

    if not result.stdout.strip():
        print(f"[!] Docker image '{image}' not found locally")
        print(f"[!] Pulling image (this may take several minutes - ~2GB download)...")
        print(f"[+] Running: docker pull {image}")

        # Pull the image with output streaming
        pull_result = subprocess.run(
            ['docker', 'pull', image],
            capture_output=True,
            text=True
        )

        if pull_result.returncode != 0:
            print(f"[-] Error: Failed to pull Docker image")

            # Check for credential helper error
            if 'docker-credential-desktop' in pull_result.stderr or 'docker-credential-desktop' in pull_result.stdout:
                print(f"[-] Docker credential helper error detected")
                print(f"")
                print(f"[!] To fix this issue, please run:")
                print(f"    1. Edit your Docker config:")
                print(f"       nano ~/.docker/config.json")
                print(f"")
                print(f"    2. Remove or comment out the 'credsStore' line:")
                print(f"       {{")
                print(f"         // \"credsStore\": \"desktop\",")
                print(f"         ...")
                print(f"       }}")
                print(f"")
                print(f"    3. Or manually pull the image:")
                print(f"       docker pull {image}")
                print(f"")
            else:
                print(f"[-] Error details: {pull_result.stderr}")

            return False

        print(f"[+] Docker image pulled successfully")
    else:
        print(f"[+] Docker image found locally")

    # Check if container already exists
    result = subprocess.run(
        ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
        capture_output=True,
        text=True
    )

    if container_name in result.stdout:
        print(f"[+] Container '{container_name}' already exists, removing it...")
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)

    # Start new container with volume mount for persistence
    print(f"[+] Starting container on port {port}...")
    result = subprocess.run(
        [
            'docker', 'run', '-d',
            '-v', 'mobsf_data:/root/.MobSF',
            '--name', container_name,
            '-p', f'{port}:8000',
            image
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[-] Error: Failed to start MobSF container")
        print(f"[-] {result.stderr}")
        return False

    print(f"[+] MobSF container started successfully")
    print(f"[+] Waiting for MobSF to be ready (this may take up to 60 seconds)...")

    # Wait for MobSF to be ready - give it more time on first start
    max_retries = 60  # 60 seconds total
    for i in range(max_retries):
        try:
            response = requests.get(f'http://localhost:{port}/', timeout=2)
            if response.status_code == 200:
                print(f"[+] MobSF is ready! (took {i+1} seconds)")
                # Wait an additional 5 seconds to ensure all services are fully initialized
                time.sleep(5)
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)

        # Print progress every 10 seconds
        if (i + 1) % 10 == 0:
            print(f"[+] Still waiting... ({i+1}/{max_retries} seconds)")

    print(f"[-] Warning: MobSF might not be fully ready yet")
    return True


def get_mobsf_api_key(container_name='mobsf', retries=15, delay=4):
    """
    Get the MobSF REST API key from container logs.

    Args:
        container_name: Name of the Docker container
        retries: Number of retry attempts
        delay: Delay between retries in seconds

    Returns:
        str: API key if found, None otherwise
    """
    print(f"[+] Retrieving MobSF API key from container logs...")

    for i in range(retries):
        result = subprocess.run(
            ['docker', 'logs', container_name],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[-] Error: Failed to get container logs")
            return None

        clean_log = strip_ansi_codes(result.stdout)
        match = re.search(r'REST API Key:\s*([a-fA-F0-9]+)', clean_log)

        if match:
            api_key = match.group(1)
            print(f"[+] API key retrieved: {api_key}")
            return api_key

        print(f"[+] API key not found yet, retrying... ({i+1}/{retries})")
        time.sleep(delay)

    print(f"[-] Error: Could not find API key in container logs")
    return None


def upload_apk(apk_path, api_key, mobsf_url='http://localhost:8000'):
    """
    Upload APK to MobSF for analysis.

    Args:
        apk_path: Path to the APK file
        api_key: MobSF REST API key
        mobsf_url: MobSF server URL

    Returns:
        dict: Upload response with 'hash', 'scan_type', etc., or None on error
    """
    print(f"[+] Uploading APK to MobSF: {apk_path}")

    if not os.path.exists(apk_path):
        print(f"[-] Error: APK file not found: {apk_path}")
        return None

    url = f"{mobsf_url}/api/v1/upload"
    headers = {'Authorization': api_key}

    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f, 'application/octet-stream')}
            response = requests.post(url, headers=headers, files=files, timeout=120)

        if response.status_code != 200:
            print(f"[-] Error: Upload failed with status {response.status_code}")
            print(f"[-] Response: {response.text}")
            return None

        result = response.json()
        print(f"[+] Upload successful!")
        print(f"[+] Hash: {result.get('hash')}")
        print(f"[+] Scan Type: {result.get('scan_type')}")
        print(f"[+] File Name: {result.get('file_name')}")

        return result

    except Exception as e:
        print(f"[-] Error uploading APK: {e}")
        return None


def scan_apk(file_hash, api_key, mobsf_url='http://localhost:8000'):
    """
    Trigger static analysis scan on uploaded APK.

    Args:
        file_hash: Hash of the uploaded file (from upload response)
        api_key: MobSF REST API key
        mobsf_url: MobSF server URL

    Returns:
        dict: Scan response, or None on error
    """
    print(f"[+] Starting static analysis scan...")

    url = f"{mobsf_url}/api/v1/scan"
    headers = {'Authorization': api_key}
    data = {
        'hash': file_hash
    }

    try:
        response = requests.post(url, headers=headers, data=data, timeout=600)

        if response.status_code != 200:
            print(f"[-] Error: Scan failed with status {response.status_code}")
            print(f"[-] Response: {response.text}")
            return None

        result = response.json()
        print(f"[+] Scan completed successfully for {file_hash}")
        return result

    except requests.exceptions.Timeout:
        print(f"[-] Error: Scan timed out after 600 seconds")
        print(f"[-] The APK file might be too large or complex")
        return None
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        return None


def get_json_report(file_hash, api_key, mobsf_url='http://localhost:8000'):
    """
    Get JSON report for a scanned APK.

    Args:
        file_hash: Hash of the scanned file
        api_key: MobSF REST API key
        mobsf_url: MobSF server URL

    Returns:
        dict: JSON report data, or None on error
    """
    print(f"[+] Retrieving JSON report...")

    url = f"{mobsf_url}/api/v1/report_json"
    headers = {'Authorization': api_key}
    data = {'hash': file_hash}

    try:
        response = requests.post(url, headers=headers, data=data, timeout=120)

        if response.status_code != 200:
            print(f"[-] Error: Failed to get report with status {response.status_code}")
            print(f"[-] Response: {response.text}")
            return None

        report = response.json()
        print(f"[+] JSON report retrieved successfully!")
        print(f"[+] App Name: {report.get('app_name', 'N/A')}")
        print(f"[+] Package Name: {report.get('package_name', 'N/A')}")

        return report

    except Exception as e:
        print(f"[-] Error retrieving report: {e}")
        return None


def download_pdf_report(file_hash, api_key, output_path, mobsf_url='http://localhost:8000'):
    """
    Download PDF report for a scanned APK.

    Args:
        file_hash: Hash of the scanned file
        api_key: MobSF REST API key
        output_path: Path where to save the PDF report
        mobsf_url: MobSF server URL

    Returns:
        bool: True if successful, False otherwise
    """
    print(f"[+] Downloading PDF report...")

    url = f"{mobsf_url}/api/v1/download_pdf"
    headers = {'Authorization': api_key}
    data = {'hash': file_hash}

    try:
        response = requests.post(url, headers=headers, data=data, timeout=120)

        if response.status_code != 200:
            print(f"[-] Error: Failed to download PDF with status {response.status_code}")
            return False

        with open(output_path, 'wb') as f:
            f.write(response.content)

        print(f"[+] PDF report saved to: {output_path}")
        return True

    except Exception as e:
        print(f"[-] Error downloading PDF report: {e}")
        return False


def stop_mobsf_container(container_name='mobsf'):
    """
    Stop and remove MobSF Docker container.

    Args:
        container_name: Name of the Docker container

    Returns:
        bool: True if stopped successfully, False otherwise
    """
    print(f"[+] Stopping MobSF container '{container_name}'...")

    result = subprocess.run(
        ['docker', 'stop', container_name],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[-] Warning: Failed to stop container (it may not be running)")
    else:
        print(f"[+] Container stopped")

    result = subprocess.run(
        ['docker', 'rm', container_name],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[-] Warning: Failed to remove container")
        return False

    print(f"[+] Container removed successfully")
    return True


def analyze_apk_with_mobsf(apk_path, container_name='mobsf', port=8000, cleanup=False):
    """
    Complete workflow: Start MobSF, upload APK, scan, and get report.

    Args:
        apk_path: Path to the APK file to analyze
        container_name: Name for the Docker container
        port: Port to expose MobSF on
        cleanup: Whether to stop and remove container after analysis

    Returns:
        dict: {
            'success': bool,
            'api_key': str,
            'hash': str,
            'report': dict,
            'error': str
        }
    """
    print("=" * 80)
    print("MobSF Static Analysis")
    print("=" * 80)

    result = {
        'success': False,
        'api_key': None,
        'hash': None,
        'report': None,
        'error': None
    }

    try:
        # Start MobSF container
        if not start_mobsf_container(container_name, port):
            result['error'] = 'Failed to start MobSF container'
            return result

        # Get API key
        api_key = get_mobsf_api_key(container_name)
        if not api_key:
            result['error'] = 'Failed to retrieve API key'
            return result

        result['api_key'] = api_key
        mobsf_url = f'http://localhost:{port}'

        # Upload APK
        upload_result = upload_apk(apk_path, api_key, mobsf_url)
        if not upload_result:
            result['error'] = 'Failed to upload APK'
            return result

        file_hash = upload_result.get('hash')
        result['hash'] = file_hash

        # Scan APK
        scan_result = scan_apk(file_hash, api_key, mobsf_url)
        if not scan_result:
            result['error'] = 'Failed to scan APK'
            return result

        # Get JSON report
        report = get_json_report(file_hash, api_key, mobsf_url)
        if not report:
            result['error'] = 'Failed to retrieve report'
            return result

        result['report'] = report
        result['success'] = True

        print("=" * 80)
        print("[+] MobSF analysis completed successfully!")
        print("=" * 80)

        return result

    except Exception as e:
        result['error'] = f'Unexpected error: {str(e)}'
        print(f"[-] Error: {e}")
        return result

    finally:
        if cleanup:
            stop_mobsf_container(container_name)
