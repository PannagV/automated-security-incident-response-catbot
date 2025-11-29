#!/usr/bin/env python3
"""
Automated Attack Script for Testing Snort IDS
This script performs various attacks against the vulnerable test site
to trigger Snort alerts and test the IDS functionality.
"""

import requests
import time
import sys
import subprocess

TARGET_URL = "http://localhost:8080"

def test_sql_injection():
    """Test SQL injection vulnerabilities"""
    print("🔍 Testing SQL Injection...")

    payloads = [
        "admin'--",
        "' OR '1'='1",
        "admin' UNION SELECT * FROM users--",
        "' OR username LIKE '%admin%'"
    ]

    for payload in payloads:
        try:
            url = f"{TARGET_URL}/login?username={payload}&password=test"
            response = requests.get(url, timeout=5)
            print(f"  ✓ SQL Injection: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)  # Rate limiting
        except Exception as e:
            print(f"  ✗ SQL Injection failed: {e}")

def test_xss():
    """Test XSS vulnerabilities"""
    print("🔍 Testing XSS...")

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    for payload in payloads:
        try:
            url = f"{TARGET_URL}/comment?comment={payload}"
            response = requests.get(url, timeout=5)
            print(f"  ✓ XSS: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ XSS failed: {e}")

def test_directory_traversal():
    """Test directory traversal vulnerabilities"""
    print("🔍 Testing Directory Traversal...")

    payloads = [
        "../../../etc/passwd",
        "../../../Windows/System32/drivers/etc/hosts",
        "....//....//....//etc/passwd",
        "..\\..\\..\\Windows\\System32\\config\\sam"
    ]

    for payload in payloads:
        try:
            url = f"{TARGET_URL}/file?path={payload}"
            response = requests.get(url, timeout=5)
            print(f"  ✓ Directory Traversal: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ Directory Traversal failed: {e}")

def test_command_injection():
    """Test command injection vulnerabilities"""
    print("🔍 Testing Command Injection...")

    payloads = [
        "whoami",
        "cat /etc/passwd",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& whoami"
    ]

    for payload in payloads:
        try:
            url = f"{TARGET_URL}/exec?cmd={payload}"
            response = requests.get(url, timeout=10)
            print(f"  ✓ Command Injection: {payload} (Status: {response.status_code})")
            time.sleep(1)  # Longer delay for commands
        except Exception as e:
            print(f"  ✗ Command Injection failed: {e}")

def test_nmap_scans():
    """Test network scanning (requires nmap)"""
    print("🔍 Testing Network Scans...")

    target_ip = "127.0.0.1"  # Localhost

    scans = [
        ["nmap", "-sS", "-p", "1-100", target_ip],  # SYN scan
        ["nmap", "-sX", "-p", "1-50", target_ip],   # XMAS scan
        ["nmap", "-sN", "-p", "1-50", target_ip],   # NULL scan
        ["nmap", "-sF", "-p", "1-50", target_ip],   # FIN scan
    ]

    for scan_cmd in scans:
        try:
            print(f"  Running: {' '.join(scan_cmd)}")
            result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=30)
            print(f"  ✓ Scan completed (Return code: {result.returncode})")
            time.sleep(2)
        except subprocess.TimeoutExpired:
            print("  ! Scan timed out")
        except FileNotFoundError:
            print("  ✗ Nmap not found. Install nmap for network scanning tests.")
            break
        except Exception as e:
            print(f"  ✗ Scan failed: {e}")

def check_snort_alerts():
    """Check for Snort alerts"""
    print("🔍 Checking Snort Alerts...")

    try:
        response = requests.get("http://localhost:5000/get_alerts", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            alert_count = len(alerts)
            print(f"  ✓ Found {alert_count} alerts")

            # Show recent alerts
            for alert in alerts[-5:]:  # Last 5 alerts
                severity = alert.get('severity', 'Unknown')
                message = alert.get('message', '')[:50]
                print(f"    - {severity}: {message}...")
        else:
            print(f"  ✗ Failed to get alerts (Status: {response.status_code})")
    except Exception as e:
        print(f"  ✗ Could not check alerts: {e}")

def main():
    print("🚨 Snort IDS Testing Script")
    print("=" * 50)
    print("This script will perform various attacks against the vulnerable test site")
    print("Make sure Snort and the vulnerable site are running before proceeding!")
    print()

    if len(sys.argv) > 1 and sys.argv[1] == "--yes":
        proceed = True
    else:
        response = input("Do you want to proceed with the attacks? (yes/no): ")
        proceed = response.lower() in ['yes', 'y']

    if not proceed:
        print("Aborting...")
        return

    print("\nStarting attack simulation...")
    print("This may take several minutes...\n")

    # Run tests
    test_sql_injection()
    print()

    test_xss()
    print()

    test_directory_traversal()
    print()

    test_command_injection()
    print()

    test_nmap_scans()
    print()

    # Wait a bit for alerts to be processed
    print("Waiting for alerts to be processed...")
    time.sleep(5)

    check_snort_alerts()

    print("\n" + "=" * 50)
    print("Testing completed!")
    print("Check your Snort logs and web interface for detected alerts.")

if __name__ == "__main__":
    main()