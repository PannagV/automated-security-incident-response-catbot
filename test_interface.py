#!/usr/bin/env python3
"""
Test script to verify interface detection is working correctly
"""

import subprocess
import socket

def test_snort_interface_detection():
    """Test the Snort interface detection"""
    print("=== Testing Snort Interface Detection ===")
    
    # Get our primary IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        print(f"Primary IP: {local_ip}")
    except Exception as e:
        print(f"Error getting primary IP: {e}")
        return
    
    # Query Snort interfaces
    try:
        result = subprocess.run(
            [r"C:\Snort\bin\snort.exe", "-W"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("\nSnort interfaces:")
            lines = result.stdout.split('\n')
            for line in lines:
                if local_ip in line and 'Index' not in line and '-----' not in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        interface_num = parts[0]
                        interface_ip = parts[2]
                        print(f">>> FOUND: Interface {interface_num} has IP {interface_ip}")
                        print(f">>> This is the correct interface to use!")
                        return interface_num
                elif line.strip() and not line.startswith('Index') and not line.startswith('-----'):
                    print(line)
        else:
            print("Error running Snort -W command")
            print(result.stderr)
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_snort_interface_detection()
