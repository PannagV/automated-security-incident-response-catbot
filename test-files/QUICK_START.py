#!/usr/bin/env python3
"""
QUICK START: Test End-to-End Alert Generation with Snort Simulation

This script provides a simple step-by-step setup and test of the complete
alert processing pipeline.
"""

import os
import sys
import subprocess
import time

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def check_port(port):
    """Check if a port is accessible"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def main():
    print_section("🚨 ALERT GENERATION TEST - QUICK START GUIDE")
    
    print("""
This guide will help you:
1. Start the vulnerable test site
2. Start the Flask alert processing app
3. Run the attack simulation
4. Verify alerts are created and classified

Prerequisites:
- Python 3.7+
- Flask and dependencies installed
- PostgreSQL running (or SQLite fallback)
""")
    
    input("Press Enter to continue...")
    
    # Step 1: Vulnerable Site
    print_section("Step 1️⃣: Starting Vulnerable Test Site")
    
    print("📍 Location: test-files/test_site.py")
    print("🌐 URL: http://localhost:3000")
    print("\nCommand to run (in a new terminal):")
    print("  cd test-files && python test_site.py")
    print("\n⏳ Waiting for you to start it...")
    
    if not check_port(3000):
        print("\n❌ Port 3000 is not responding yet.")
        print("Please run the command above in a new PowerShell terminal.")
        print("Press Enter when you've started it...")
        input()
    
    # Verify
    time.sleep(1)
    if check_port(3000):
        print("✅ Vulnerable test site is running!")
    else:
        print("⚠️  Still can't reach port 3000. Check for errors in the terminal.")
    
    # Step 2: Flask App
    print_section("Step 2️⃣: Starting Flask Alert Processing App")
    
    print("📍 Location: app.py")
    print("🌐 URL: http://localhost:5000")
    print("\nCommand to run (in another new terminal):")
    print("  python app.py")
    print("\n⏳ Waiting for you to start it...")
    
    if not check_port(5000):
        print("\n❌ Port 5000 is not responding yet.")
        print("Please run the command above in a new PowerShell terminal.")
        print("Press Enter when you've started it...")
        input()
    
    # Verify
    time.sleep(1)
    if check_port(5000):
        print("✅ Flask app is running!")
    else:
        print("⚠️  Still can't reach port 5000. Check for errors in the terminal.")
    
    # Step 3: Run Attacks
    print_section("Step 3️⃣: Running Attack Simulation")
    
    print("📍 Location: test-files/test_attacks_with_alerts.py")
    print("\nThis script will:")
    print("  1. Perform actual attacks on the vulnerable site")
    print("  2. Create Snort-like alerts in the Flask app")
    print("  3. Display all generated alerts")
    print("\nCommand to run:")
    print("  cd test-files && python test_attacks_with_alerts.py --yes")
    
    ready = input("\nReady to run? (yes/no): ").lower() in ['yes', 'y']
    
    if ready:
        try:
            os.chdir('test-files')
            subprocess.run([sys.executable, 'test_attacks_with_alerts.py', '--yes'], check=False)
        except Exception as e:
            print(f"❌ Error running script: {e}")
    else:
        print("Skipped attack simulation.")
    
    # Step 4: Verify Results
    print_section("Step 4️⃣: Verifying Alert Generation")
    
    print("To check alerts, use one of these methods:")
    print("\n1️⃣  Command Line:")
    print("   curl http://localhost:5000/get_alerts")
    
    print("\n2️⃣  Python Script:")
    print("""
   import requests
   response = requests.get('http://localhost:5000/get_alerts')
   alerts = response.json()
   print(f'Total alerts: {len(alerts)}')
   for alert in alerts[-5:]:
       print(f\"- [{alert['severity']}] {alert['message']}\")
    """)
    
    print("\n3️⃣  Web Browser:")
    print("   http://localhost:5000/get_alerts")
    
    print("\n4️⃣  Check Specific Alerts by Severity:")
    print("   curl http://localhost:5000/get_alerts/critical")
    print("   curl http://localhost:5000/get_alerts/high")
    
    input("\nPress Enter to continue...")
    
    # Step 5: Understanding Results
    print_section("Understanding Alert Results")
    
    print("""
Each alert includes:
  - ID: Unique identifier
  - Message: Description of the attack detected
  - Severity: Classification (Low, Medium, High, Critical)
  - Source: 'snort_ids' for simulated Snort detections
  - Timestamp: When the alert was created
  - Jira Ticket: Associated ticket ID (if created)
  - Slack Notification: Whether notification was sent
  - Impact: Potential impact of the detected threat
  - Recommendations: Suggested response actions

Alert Classification:
  - The ML model analyzes the alert message and predicts severity
  - Uses TF-IDF vectorization and Random Forest classifier
  - Falls back to 'Medium' if model not available
  - Alternative: Use Gemini API for classification (requires API key)
    """)
    
    # Step 6: Troubleshooting
    print_section("Troubleshooting")
    
    print("""
If no alerts are created:

1. Check if app is running:
   curl http://localhost:5000/api/status

2. Check if vulnerable site is running:
   curl http://localhost:3000/

3. Check database connection:
   curl http://localhost:5000/api/db-check

4. Test alert creation manually:
   curl -X POST http://localhost:5000/process_alert \\
     -H "Content-Type: application/json" \\
     -d '{"message": "Test alert for debugging"}'

5. Check app logs for errors (look at terminal where you ran app.py)

If alerts are created but not classified correctly:

1. Check if ML model loaded:
   - Look for "Model loaded successfully" in app logs
   - If not found, model may not be available

2. Try with Gemini API:
   - Set GEMINI_API_KEY in .env file
   - Run test again with classification_method='gemini'
    """)
    
    print_section("✅ Quick Start Complete!")
    
    print("""
Next Steps:
  1. Verify alerts are being created in the app
  2. Check Jira ticket creation (if configured)
  3. Verify Slack notifications (if configured)
  4. Test the complete alert workflow
  5. Review ML model classifications for accuracy

For more details, see:
  - LOCALHOST_SNORT_ISSUE.md - Why Snort can't capture localhost
  - test_attacks_with_alerts.py - Alert injection implementation
  - app.py - Alert processing and classification

Happy testing! 🎉
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user.")
        sys.exit(1)
