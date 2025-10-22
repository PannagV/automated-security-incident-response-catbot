#!/usr/bin/env python3
"""
Network Interface Diagnostic Tool for Snort
This script helps diagnose network interface issues that prevent Snort from capturing packets.
"""

import subprocess
import psutil
import socket
import os
import sys
from datetime import datetime

def check_npcap_winpcap():
    """Check if Npcap or WinPcap is installed and working"""
    print("=== Checking Packet Capture Drivers ===")
    
    # Check for Npcap
    npcap_paths = [
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
        r"C:\Windows\System32\Npcap"
    ]
    
    npcap_found = False
    for path in npcap_paths:
        if os.path.exists(path):
            print(f"✓ Npcap found at: {path}")
            npcap_found = True
            break
    
    if not npcap_found:
        print("✗ Npcap not found - this is required for Snort packet capture")
        print("  Download from: https://npcap.com/")
    
    # Check for WinPcap (legacy)
    winpcap_path = r"C:\Program Files\WinPcap"
    if os.path.exists(winpcap_path):
        print(f"✓ WinPcap found at: {winpcap_path} (legacy)")
    
    return npcap_found

def check_snort_interfaces():
    """Check Snort's view of network interfaces"""
    print("\n=== Checking Snort Interface Detection ===")
    
    snort_exe = r"C:\Snort\bin\snort.exe"
    if not os.path.exists(snort_exe):
        print(f"✗ Snort executable not found at: {snort_exe}")
        return False
    
    try:
        # Run snort with interface list command
        result = subprocess.run(
            [snort_exe, "-W"], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        if result.returncode == 0:
            print("✓ Snort interface listing:")
            print(result.stdout)
        else:
            print("✗ Snort interface listing failed:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        print("✗ Snort interface listing timed out")
    except Exception as e:
        print(f"✗ Error running Snort interface check: {e}")
    
    return True

def test_packet_capture():
    """Test if we can capture packets on the primary interface"""
    print("\n=== Testing Packet Capture ===")
    
    try:
        # Get primary interface
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        # Find the Wi-Fi interface (Interface 5)
        interface_names = list(interfaces.keys())
        if len(interface_names) >= 5:
            wifi_interface = interface_names[4]  # Index 4 = Interface 5
            print(f"Testing packet capture on: {wifi_interface}")
            
            # Try a simple ping to generate traffic
            print("Generating test traffic with ping...")
            ping_process = subprocess.Popen(
                ["ping", "-n", "3", "8.8.8.8"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for ping to complete
            ping_process.wait()
            print("✓ Test traffic generated")
            
        else:
            print("✗ Could not identify Wi-Fi interface for testing")
            
    except Exception as e:
        print(f"✗ Error in packet capture test: {e}")

def check_firewall_antivirus():
    """Check for potential firewall/antivirus interference"""
    print("\n=== Checking for Interference ===")
    
    print("Common causes of packet capture issues:")
    print("1. Windows Firewall blocking Snort")
    print("2. Antivirus software interfering with packet capture")
    print("3. VPN software modifying network stack")
    print("4. Network adapter in power saving mode")
    print("5. Hyper-V or VMware virtual switches")
    
    # Check for Hyper-V
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"],
            capture_output=True,
            text=True
        )
        if "Enabled" in result.stdout:
            print("⚠ Hyper-V is enabled - this can interfere with packet capture")
    except:
        pass

def suggest_fixes():
    """Suggest potential fixes for packet capture issues"""
    print("\n=== Suggested Fixes ===")
    print("1. Run as Administrator:")
    print("   - Right-click Command Prompt/PowerShell")
    print("   - Select 'Run as Administrator'")
    print("   - Snort requires admin rights for packet capture")
    print()
    print("2. Install/Reinstall Npcap:")
    print("   - Download from: https://npcap.com/")
    print("   - Install with 'WinPcap API-compatible Mode' checked")
    print("   - Install in 'WinPcap API-compatible Mode'")
    print()
    print("3. Windows Firewall Exception:")
    print("   - Add C:\\Snort\\bin\\snort.exe to firewall exceptions")
    print("   - Or temporarily disable Windows Firewall for testing")
    print()
    print("4. Network Adapter Settings:")
    print("   - Open Device Manager")
    print("   - Find your Wi-Fi adapter")
    print("   - Properties > Power Management")
    print("   - Uncheck 'Allow computer to turn off this device'")
    print()
    print("5. Try different interface:")
    print("   - Use 'Ethernet 2' (Interface 2) if available")
    print("   - Some adapters work better than others")

def main():
    print("Network Interface Diagnostic Tool for Snort")
    print("=" * 50)
    print(f"Timestamp: {datetime.now()}")
    print()
    
    # Check if running as admin
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    if not is_admin:
        print("⚠ WARNING: Not running as Administrator!")
        print("  Packet capture usually requires administrator privileges.")
        print()
    
    # Run diagnostics
    check_npcap_winpcap()
    check_snort_interfaces()
    test_packet_capture()
    check_firewall_antivirus()
    suggest_fixes()
    
    print("\n" + "=" * 50)
    print("Diagnostic complete!")

if __name__ == "__main__":
    main()
