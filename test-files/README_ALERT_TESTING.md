# 📚 Localhost Snort Alert Testing - Complete Guide Index

## 🎯 Quick Navigation

### For the Impatient (30 minutes)
1. Read: `SOLUTION_SUMMARY.md` (2 min)
2. Run: `QUICK_START.py` (15 min)
3. Check: Results at `http://localhost:5000/get_alerts`

### For the Curious (1-2 hours)
1. Read: `LOCALHOST_SNORT_ISSUE.md` - Deep technical explanation
2. Run: `test_attacks_with_alerts.py` - See real attacks + alerts
3. Run: `example_manual_testing.py` - Test classification directly
4. Verify: Complete alert workflow

### For Integration/Production
- See section "For Production Network IDS" in `LOCALHOST_SNORT_ISSUE.md`

---

## 📖 Documentation Files

### `SOLUTION_SUMMARY.md` ⭐ START HERE
**What:** High-level overview of the problem and solution
**Why:** Quick understanding of why Snort can't capture localhost
**Length:** 5 min read
**Contains:**
- Problem summary
- Root cause analysis
- Solution explanation
- Quick usage examples

### `LOCALHOST_SNORT_ISSUE.md` ⭐ FOR DEEP DIVE
**What:** Detailed technical explanation of the limitation
**Why:** Understand OS-level constraints and alternative approaches
**Length:** 15 min read
**Contains:**
- Technical deep dive
- Why loopback traffic is special
- Four different solutions explained
- Troubleshooting guide
- Alternative approaches (Suricata, WinDivert, etc.)

---

## 🛠️ Executable Files

### `test_attacks_with_alerts.py` ⭐ MAIN TEST SCRIPT
**What:** Attack simulation + direct alert injection
**How:** `python test_attacks_with_alerts.py --yes`
**Does:**
1. Executes real attacks on vulnerable site
2. For each attack, creates alert in app
3. Displays all generated alerts
4. Shows severity classification
**Required:** Both `test_site.py` and `app.py` running

### `test_attacks.py` 
**What:** Original attack script (updated for port 3000)
**How:** `python test_attacks.py`
**Status:** Legacy - use `test_attacks_with_alerts.py` instead
**Note:** Updated to use port 3000 and configurable URLs

### `test_site.py`
**What:** Vulnerable Flask app with intentional security flaws
**How:** `python test_site.py` 
**Runs:** `http://localhost:3000`
**Vulnerabilities:**
- SQL Injection (login, search)
- XSS (comments)
- Directory Traversal (file access)
- Command Injection (exec)
- File Upload (unrestricted)

### `QUICK_START.py` ⭐ GUIDED SETUP
**What:** Interactive step-by-step guide
**How:** `python QUICK_START.py`
**Guides:** Complete setup from zero to verified alerts
**Features:**
- Checks if services are running
- Provides copy-paste commands
- Explains each step
- Troubleshooting tips

### `example_manual_testing.py` ⭐ DIRECT API TESTING
**What:** Examples of creating alerts directly via API
**How:** `python example_manual_testing.py`
**Tests:**
1. Basic alert creation
2. Severity classification
3. Gemini API classification
4. Alert retrieval and grouping
**Great for:** Understanding the alert workflow

---

## 🚀 Getting Started in 3 Steps

### Step 1: Start Services
```powershell
# Terminal 1: Vulnerable Site
cd test-files
python test_site.py
# Opens on http://localhost:3000

# Terminal 2: Flask Alert App
python app.py
# Opens on http://localhost:5000
```

### Step 2: Run Attack Simulation
```powershell
# Terminal 3: Attack Script
cd test-files
python test_attacks_with_alerts.py --yes
```

### Step 3: View Results
```bash
# Check alerts
curl http://localhost:5000/get_alerts

# Or visit in browser
http://localhost:5000/get_alerts

# Or run manual testing
python example_manual_testing.py
```

---

## 📊 Understanding the Alert Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Attack Script (test_attacks_with_alerts.py)                      │
│                                                                   │
│ Phase 1: Perform Actual Attacks                                  │
│  • SQL Injection attempts          → http://localhost:3000       │
│  • XSS payloads                    → Vulnerable Site             │
│  • Directory traversal requests    ↓                             │
│  • Command injection commands                                     │
│  • Nmap port scans                                                │
│                                                                   │
│ Phase 2: Create Simulated Alerts                                 │
│  • For each attack, call:                                         │
│  • POST /process_alert                                            │
│  • source: "snort_ids" (mark as Snort detection)                 │
│  ↓                                                                │
└──────────────────────────────────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────┐
        │ Flask App (app.py)               │
        │                                  │
        │ Alert Processing Pipeline:       │
        │ 1. Receive alert message         │
        │ 2. Classify severity (ML model)  │
        │ 3. Create Jira ticket            │
        │ 4. Send Slack notification       │
        │ 5. Store in PostgreSQL/SQLite    │
        │ 6. Index in SIEM                 │
        │                                  │
        │ Return: Classified alert         │
        └──────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────┐
        │ Results Available at:             │
        │ • GET /get_alerts                │
        │ • GET /get_alerts/critical       │
        │ • GET /get_alerts?severity=High  │
        │ • Database (PostgreSQL/SQLite)   │
        └──────────────────────────────────┘
```

---

## 🔍 Troubleshooting Quick Reference

### Problem: No alerts created
**Solutions:**
1. Verify app is running: `curl http://localhost:5000/api/status`
2. Verify site is running: `curl http://localhost:3000/`
3. Check database: `curl http://localhost:5000/api/db-check`
4. Create test alert: `python example_manual_testing.py`

### Problem: Alerts created but severity always "Medium"
**Solutions:**
1. Check if ML model loaded: Look for "Model loaded successfully" in app logs
2. Verify model files exist: `alert_classifier.pkl`, `tfidf_vectorizer.pkl`
3. Try Gemini classification: Set `GEMINI_API_KEY` in `.env`
4. Check for errors: `curl http://localhost:5000/api/debug`

### Problem: Jira tickets not created
**Solutions:**
1. Verify config: Check `.env` for JIRA_SERVER, JIRA_USERNAME, JIRA_API_TOKEN
2. Test connection: Use Jira API directly
3. Check permissions: Ensure user has permission to create issues
4. Check project exists: `curl http://localhost:5000/api/db-check`

### Problem: Slack notifications not sent
**Solutions:**
1. Verify token: Check SLACK_BOT_TOKEN in `.env`
2. Verify channel: Check SLACK_CHANNEL_ID in `.env`
3. Test connection: `curl http://localhost:5000/api/test-slack`
4. Check permissions: Bot must have channel access

---

## 📋 File Manifest

```
test-files/
├── 📄 SOLUTION_SUMMARY.md (NEW)          ← START: High-level overview
├── 📄 LOCALHOST_SNORT_ISSUE.md (NEW)     ← Deep technical details
├── 📄 README.md or INDEX.md (THIS FILE)  ← Navigation guide
├── 🐍 QUICK_START.py (NEW)               ← Interactive setup
├── 🐍 test_attacks_with_alerts.py (NEW)  ← Main test script
├── 🐍 example_manual_testing.py (NEW)    ← API testing examples
├── 🐍 test_site.py                       ← Vulnerable Flask app
├── 🐍 test_attacks.py (UPDATED)          ← Original attack script
└── 📄 VULNERABLE_SITE_README.md          ← Site documentation
```

---

## 🎓 Learning Outcomes

After working through this guide, you'll understand:

1. **Why localhost IDS testing is special**
   - OS-level packet capture limitations
   - Loopback traffic handling
   - Windows vs Linux differences

2. **How to test alert workflows locally**
   - Direct API alert injection
   - Bypassing packet capture limitations
   - Simulating IDS detection

3. **Complete alert processing pipeline**
   - Alert reception and parsing
   - ML-based severity classification
   - Jira ticket creation
   - Slack notifications
   - SIEM integration

4. **Python for security testing**
   - Crafting attack payloads
   - HTTP requests and APIs
   - Alert processing
   - Result verification

---

## 🔗 Related Files (Not in test-files/)

### In Repository Root:
- `app.py` - Main Flask alert processing app
- `alert_classifier.pkl` - Pre-trained severity classifier
- `tfidf_vectorizer.pkl` - ML feature extractor
- `.env` - Configuration (Jira, Slack, Gemini API keys)

### Frontend:
- `alert-frontend/` - React dashboard (future)
- `src/components/SnortIDS.jsx` - Snort monitoring UI

---

## 📞 Support & Questions

### For Questions About:

**OS/Packet Capture Limitations:**
- Read: `LOCALHOST_SNORT_ISSUE.md` - Technical explanation
- See: "Root Cause Analysis" section

**How to Use the Scripts:**
- Read: `SOLUTION_SUMMARY.md` - Quick start
- Run: `QUICK_START.py` - Interactive guide

**Alert Classification:**
- Run: `example_manual_testing.py` - See real classifications
- Check: `app.py` - `process_alert()` function

**Jira/Slack Integration:**
- Check: `.env` - Configuration
- Test: `curl http://localhost:5000/api/test-slack`

**Database Issues:**
- Test: `curl http://localhost:5000/api/db-check`
- Migrate: `curl http://localhost:5000/migrate-database`

---

## ✅ Verification Checklist

- [ ] Read SOLUTION_SUMMARY.md (2 min)
- [ ] Read LOCALHOST_SNORT_ISSUE.md (15 min)
- [ ] Start test_site.py on port 3000
- [ ] Start app.py on port 5000
- [ ] Run test_attacks_with_alerts.py
- [ ] See alerts created: `curl http://localhost:5000/get_alerts`
- [ ] Verify severity classification
- [ ] Run example_manual_testing.py
- [ ] Test Jira ticket creation (if configured)
- [ ] Test Slack notifications (if configured)

---

## 🎉 You're All Set!

The localhost Snort alert limitation is now resolved through direct API alert injection. You can fully test the alert processing, classification, and integration workflows locally.

**Next Steps:**
1. Verify alerts are being created correctly
2. Test your ML model's classification accuracy
3. Configure Jira and Slack integration
4. Extend the alert workflow as needed
5. Deploy to production with real network interfaces

Happy testing! 🚀
