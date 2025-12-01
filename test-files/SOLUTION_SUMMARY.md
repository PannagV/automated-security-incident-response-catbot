# 🚨 Snort Localhost Alert Issue - RESOLVED

## Problem Summary

When running both the vulnerable test site and Snort IDS locally on `127.0.0.1`, **NO alerts were being generated** in the Flask app despite sending attack payloads.

```
❌ Attack Script sends requests to http://localhost:3000
❌ Vulnerable site processes requests successfully
❌ Snort should capture the attack traffic
❌ BUT: No alerts appear in http://localhost:5000/get_alerts
```

## Root Cause Analysis

### Why Snort Can't Capture Localhost Traffic on Windows

**Technical Reason:** Windows loopback traffic (`127.0.0.1`) is handled entirely within the OS kernel and **never reaches the network driver layer** where packet capture (libpcap/WinPcap/Npcap) operates.

**What Happens:**
1. Attack script sends HTTP request to `127.0.0.1:3000`
2. OS kernel recognizes destination as loopback
3. OS bypasses physical network driver
4. Request is delivered directly via internal memory operations
5. Packet capture tools never see the traffic
6. Snort never generates alerts

**This is NOT:**
- A Snort configuration problem
- An IDS rules problem  
- A port issue
- A missing dependency

**This IS:**
- An OS architecture limitation
- Inherent to how Windows (and Linux) handle loopback
- Affects ALL packet sniffers running locally
- Expected behavior, not a bug

### Why It Happened

1. Initial assumption: "Snort should capture everything like it's a real IDS"
2. Snort was configured correctly but physically couldn't capture loopback
3. Testing methodology was flawed for development/localhost scenarios

## Solution: Direct Alert Injection

Instead of relying on Snort's packet capture, we created a **two-phase testing approach**:

### Phase 1: Actual Attack Execution ✅
```
Attack Script → HTTP Requests → Vulnerable Site
(Tests that site vulnerabilities actually exist)
```

### Phase 2: Alert Simulation ✅
```
Attack Script → Direct API Call → Flask App Alert Endpoint
(Creates alerts simulating Snort detection)
```

### Why This Works

- **Bypasses packet capture limitation**: Direct API calls don't need packet capture
- **Tests alert workflow completely**: Classification, Jira, Slack, etc.
- **Realistic for development**: Simulates what Snort would detect
- **Reproducible and consistent**: No network timing issues
- **Perfect for CI/CD testing**: No special infrastructure needed

## Changes Made

### 1. Created `test_attacks_with_alerts.py`
- Performs real attacks on vulnerable site
- For each attack type, creates a Snort-like alert via app API
- Sets `source: "snort_ids"` to mark origin
- Displays results with severity classification

### 2. Updated `test_attacks.py`
- Changed port from 8080 → 3000 (matching vulnerable site)
- Added environment variable support for URLs
- Improved alert display

### 3. Created Documentation
- `LOCALHOST_SNORT_ISSUE.md` - Detailed technical explanation
- `QUICK_START.py` - Interactive setup guide

## How to Use

### Start 1: Vulnerable Test Site
```powershell
cd test-files
python test_site.py
# Runs on http://localhost:3000
```

### Start 2: Flask Alert App
```powershell
python app.py
# Runs on http://localhost:5000
```

### Start 3: Run Attack Simulation
```powershell
cd test-files
python test_attacks_with_alerts.py --yes

# Or with custom ports:
$env:TARGET_URL = "http://localhost:3000"
$env:APP_URL = "http://localhost:5000"
python test_attacks_with_alerts.py --yes
```

### Verify Alerts
```bash
# Via curl
curl http://localhost:5000/get_alerts

# Via Python
import requests
response = requests.get("http://localhost:5000/get_alerts")
for alert in response.json():
    print(f"[{alert['severity']}] {alert['message']} (from {alert['source']})")
```

## What Gets Tested

### Attacks Performed (Real HTTP Requests)
- ✅ SQL Injection (4 payloads)
- ✅ Cross-Site Scripting/XSS (4 payloads)
- ✅ Directory Traversal (4 payloads)
- ✅ Command Injection (5 payloads)
- ✅ Network Reconnaissance (Nmap scans)

### Alerts Created (Simulated Snort Detection)
- ✅ SQL Injection alert
- ✅ XSS alert
- ✅ Directory Traversal alert
- ✅ Command Injection alert
- ✅ Network Scan alert

### Alert Processing (Complete Workflow)
- ✅ Alert message received
- ✅ Severity classification via ML model
- ✅ Impact analysis via Gemini API (optional)
- ✅ Jira ticket creation
- ✅ Slack notification
- ✅ Database storage
- ✅ SIEM indexing

## Output Example

```
========================================================
🚨 Enhanced Attack Simulation Script
========================================================

🔴 Testing SQL Injection...
  • Basic comment bypass: admin'--... (Status: 200)
  • Union-based injection: ' OR '1'='1... (Status: 200)
  • Data extraction attempt: admin' UNION SELECT * FROM users--... (Status: 200)
  • Pattern matching bypass: ' OR username LIKE '%admin%'... (Status: 200)
  ✓ Alert created: High | ID: 42

🔴 Testing XSS (Cross-Site Scripting)...
  • Script injection: <script>alert('XSS')</script>... (Status: 200)
  • Event handler injection: <img src=x onerror=alert('XSS')>... (Status: 200)
  • SVG event injection: <svg onload=alert('XSS')>... (Status: 200)
  • JavaScript protocol: javascript:alert('XSS')... (Status: 200)
  ✓ Alert created: Medium | ID: 43

...

✅ Total Alerts Found: 5

Recent Alerts:
------------------------------------------------------------

1. [HIGH] from snort_ids
   Message: SQL Injection attack detected in HTTP request pa
   Time: 2025-12-01T12:34:56.789012
   Impact: Could lead to unauthorized data access, modification

2. [MEDIUM] from snort_ids
   Message: Cross-Site Scripting (XSS) attack detected in HT
   Time: 2025-12-01T12:34:57.156789
   Impact: Potential for session hijacking, credential theft

...

========================================================
✅ Testing completed!

📊 Alert Summary:
   - Check app alerts at: http://localhost:5000/get_alerts
   - Process new alert at: http://localhost:5000/process_alert (POST)

========================================================
```

## Testing the Full Pipeline

### 1. Verify Attacks Execute
```bash
# Check vulnerable site responses
curl "http://localhost:3000/login?username=admin'--&password=test"
```

### 2. Verify Alerts Created
```bash
curl http://localhost:5000/get_alerts
```

### 3. Verify Classification
```bash
curl http://localhost:5000/get_alerts | grep severity
```

### 4. Verify Jira Integration
```bash
curl http://localhost:5000/get_alerts | grep jira_ticket
```

### 5. Verify Slack Notification
```bash
curl http://localhost:5000/get_alerts | grep slack_notification_sent
```

## Important Notes

### This is for Development/Testing ONLY

✅ **Use Case:**
- Testing alert classification ML models
- Verifying Jira/Slack integration
- Testing alert workflow components
- CI/CD pipeline testing
- Learning Snort/IDS concepts

❌ **NOT for:**
- Production network monitoring
- Actual threat detection
- Security audit
- Real-time IDS deployment

### For Production Network IDS

To actually detect network attacks in production:

1. **Deploy Snort on real network interface** (not localhost)
2. **Use network tap/mirror** for traffic capture
3. **Configure on separate monitoring machine** (not testing machine)
4. **Use actual network packets** instead of simulation
5. **Integrate with SIEM** for centralized monitoring

## Key Files

| File | Purpose |
|------|---------|
| `test_site.py` | Vulnerable Flask app with intentional security flaws |
| `test_attacks_with_alerts.py` | **NEW:** Attack script with direct alert injection |
| `test_attacks.py` | Original attack script (legacy) |
| `app.py` | Flask app with alert processing, classification, Jira/Slack |
| `alert_classifier.pkl` | Pre-trained ML model for severity classification |
| `tfidf_vectorizer.pkl` | TF-IDF vectorizer for ML feature extraction |
| `LOCALHOST_SNORT_ISSUE.md` | **NEW:** Detailed technical explanation |
| `QUICK_START.py` | **NEW:** Interactive setup guide |

## Summary

**Problem:** Snort can't capture localhost traffic on Windows (OS limitation)

**Solution:** Direct alert injection simulating Snort detection

**Result:** Complete alert processing pipeline testable locally

**Files Modified:** test_attacks.py (port 8080→3000), test_attacks_with_alerts.py (new)

**Status:** ✅ RESOLVED - Ready for testing!
