#!/usr/bin/env python3
"""
Example: Manual Alert Testing Without Attack Script

This shows how to directly create alerts in the app for testing
the alert processing pipeline.
"""

import requests
import json

# Configuration
APP_URL = "http://localhost:5000"

def test_alerts():
    """Create test alerts directly"""
    
    # Test data: Different attack types
    test_cases = [
        {
            "name": "SQL Injection Detection",
            "payload": {
                "message": "SQL Injection attack detected in user login parameters. Pattern: ' OR '1'='1 detected in database query",
                "source": "snort_ids"
            }
        },
        {
            "name": "Unauthorized Admin Access",
            "payload": {
                "message": "Unauthorized root access detected from suspicious IP address 192.168.1.100. Multiple failed authentication attempts followed by successful login",
                "source": "snort_ids"
            }
        },
        {
            "name": "Data Exfiltration Attempt",
            "payload": {
                "message": "Suspicious data transfer detected. Large volume of sensitive data being transferred to external IP 10.0.0.50. Data includes customer records and payment information",
                "source": "snort_ids"
            }
        },
        {
            "name": "Malware Detection",
            "payload": {
                "message": "Malware detected on system. File: C:\\Windows\\System32\\suspicious.exe matches known malware signature. Executing detected ransomware behavior",
                "source": "snort_ids"
            }
        },
        {
            "name": "Brute Force Attack",
            "payload": {
                "message": "Brute force attack detected on SSH port 22. 1000+ failed authentication attempts in 5 minutes from IP 203.0.113.45",
                "source": "snort_ids"
            }
        }
    ]
    
    print("\n" + "="*70)
    print("📊 MANUAL ALERT TEST - Direct API Testing")
    print("="*70)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: {test_case['name']}")
        print("-" * 70)
        
        try:
            # Create alert
            response = requests.post(
                f"{APP_URL}/process_alert",
                json=test_case['payload'],
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                print(f"✅ Alert Created Successfully")
                print(f"   ID: {result.get('alert_id', 'N/A')}")
                print(f"   Severity: {result.get('severity', 'Unknown')}")
                print(f"   Jira Ticket: {result.get('jira_ticket', 'N/A')}")
                print(f"   Slack Sent: {result.get('slack_notification_sent', False)}")
                
                # Show impact if available
                if 'impact' in result:
                    print(f"   Impact: {result['impact'][:100]}...")
                
                # Show recommendations
                if 'recommendations' in result:
                    recs = result['recommendations']
                    if isinstance(recs, dict):
                        immediate = recs.get('immediate', [])
                        if immediate:
                            print(f"   Recommendations:")
                            for rec in immediate[:2]:
                                print(f"     • {rec}")
                        
            else:
                print(f"❌ Failed to create alert (Status: {response.status_code})")
                print(f"   Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Now retrieve and display all alerts
    print("\n" + "="*70)
    print("📋 RETRIEVING ALL ALERTS")
    print("="*70)
    
    try:
        response = requests.get(f"{APP_URL}/get_alerts", timeout=5)
        
        if response.status_code == 200:
            alerts = response.json()
            
            print(f"\n✅ Total Alerts: {len(alerts)}\n")
            
            # Group by severity
            by_severity = {}
            for alert in alerts:
                severity = alert.get('severity', 'Unknown')
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(alert)
            
            # Display grouped alerts
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if severity in by_severity:
                    print(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])} alerts)")
                    print("-" * 70)
                    
                    for alert in by_severity[severity][:3]:  # Show first 3 of each severity
                        print(f"\n  Alert ID: {alert.get('id', 'N/A')}")
                        print(f"  Message: {alert.get('message', 'N/A')[:60]}...")
                        print(f"  Source: {alert.get('source', 'unknown')}")
                        print(f"  Created: {alert.get('timestamp', 'N/A')}")
                        
                        # Show additional data if present
                        additional = alert.get('additional_data', {})
                        if additional:
                            if 'impact' in additional:
                                print(f"  Impact: {additional['impact'][:60]}...")
                            if 'reasoning' in additional:
                                print(f"  Reasoning: {additional['reasoning'][:60]}...")
        else:
            print(f"❌ Failed to retrieve alerts (Status: {response.status_code})")
            
    except Exception as e:
        print(f"❌ Error retrieving alerts: {e}")

def test_severity_classification():
    """Test the ML model's severity classification"""
    
    print("\n" + "="*70)
    print("🧠 SEVERITY CLASSIFICATION TEST - ML Model Behavior")
    print("="*70)
    
    # Different messages that should be classified at different severity levels
    test_messages = [
        ("Connection timeout from 192.168.1.50", "Low"),
        ("Multiple failed login attempts detected from external IP", "Medium"),
        ("Unauthorized admin access detected, root shell spawned", "High"),
        ("Ransomware encryption spreading to all network shares. Data loss imminent", "Critical"),
    ]
    
    for message, expected in test_messages:
        print(f"\n📝 Message: {message}")
        print(f"   Expected Severity: {expected}")
        
        try:
            response = requests.post(
                f"{APP_URL}/process_alert",
                json={"message": message, "source": "test_model"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                predicted = result.get('severity', 'Unknown')
                match = "✅" if predicted == expected else "⚠️"
                print(f"   {match} Predicted: {predicted}")
                
                if 'impact' in result:
                    print(f"   Impact: {result['impact'][:80]}...")
                    
            else:
                print(f"   ❌ Failed: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")

def test_gemini_classification():
    """Test classification using Gemini API"""
    
    print("\n" + "="*70)
    print("🤖 GEMINI API CLASSIFICATION TEST")
    print("="*70)
    
    test_message = "Suspicious process started: mimikatz.exe detected running with SYSTEM privileges attempting to dump credentials"
    
    print(f"\n📝 Message: {test_message}")
    
    try:
        response = requests.post(
            f"{APP_URL}/process_alert",
            json={
                "message": test_message,
                "classification_method": "gemini",  # Use Gemini instead of model
                "source": "test_gemini"
            },
            timeout=30  # Gemini may take longer
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Gemini Classification Results:")
            print(f"   Severity: {result.get('severity', 'Unknown')}")
            print(f"   Impact: {result.get('impact', 'N/A')}")
            print(f"   Reasoning: {result.get('reasoning', 'N/A')}")
            
            if 'recommendations' in result:
                recs = result['recommendations']
                if isinstance(recs, dict):
                    print(f"\n   Recommendations:")
                    for i, rec in enumerate(recs.get('immediate', []), 1):
                        print(f"     {i}. {rec}")
        else:
            print(f"❌ Failed: {response.status_code}")
            print(f"   Note: Gemini API may require configuration")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("\n🚀 Alert Testing Suite - Testing Local Alert Processing\n")
    
    # Check if app is running
    try:
        response = requests.get(f"{APP_URL}/api/status", timeout=2)
        print(f"✅ App is running at {APP_URL}")
    except:
        print(f"❌ App not running at {APP_URL}")
        print(f"   Start it with: python app.py")
        return
    
    # Run tests
    print("\n1️⃣  Testing basic alert creation and classification...")
    test_alerts()
    
    print("\n\n2️⃣  Testing ML model severity classification...")
    test_severity_classification()
    
    print("\n\n3️⃣  Testing Gemini API classification (if configured)...")
    test_gemini_classification()
    
    print("\n" + "="*70)
    print("✅ TESTING COMPLETE")
    print("="*70)
    print("\nYou can now:")
    print("  1. View alerts: curl http://localhost:5000/get_alerts")
    print("  2. Filter by severity: curl http://localhost:5000/get_alerts/critical")
    print("  3. Check database: curl http://localhost:5000/api/db-check")
    print("\n")

if __name__ == "__main__":
    main()
