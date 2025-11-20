# Snort IDS Auto-Ticketing Feature

## Overview
Automatic Jira ticket creation and Slack notifications for High and Critical severity alerts detected by Snort IDS.

## What Was Implemented

### 1. **Automatic Ticket Generation**
When Snort IDS detects a **High** or **Critical** severity alert, the system now automatically:
- ✅ Creates a Jira ticket with full alert details
- ✅ Sends a Slack notification to the security team
- ✅ Stores the alert in the database with source tracking
- ✅ Links the Jira ticket to the Snort alert

### 2. **Enhanced Alert Tracking**
- **Source Field**: All alerts now track their origin (manual, snort_ids, api, etc.)
- **Deduplication**: Prevents duplicate tickets for the same alert
- **Auto-Processing Counter**: Tracks how many alerts have been auto-processed

### 3. **Integration Architecture**

```
Snort IDS → Parse Alert → Check Severity → If High/Critical:
                                           ├─→ Create Jira Ticket
                                           ├─→ Send Slack Notification  
                                           └─→ Store in Database
```

## Technical Implementation

### Modified Files

#### 1. **snort_backend.py**
- Added `requests` library import for HTTP calls
- Added `main_app_url` configuration
- Added `processed_alert_ids` set to track processed alerts
- **New Method**: `create_ticket_for_alert(alert)` - Handles ticket creation
- **Updated**: `monitor_log_file()` - Auto-creates tickets for High/Critical alerts
- **Updated**: `monitor_console_output()` - Auto-creates tickets for High/Critical alerts
- **Updated**: `clear_alerts()` - Clears processed alerts tracking
- **New Endpoint**: `/snort/auto-ticket/status` - Get auto-ticketing statistics

#### 2. **app.py**
- **Updated Alert Model**: Added `source` field to track alert origin
- **Updated**: `/process_alert` endpoint to accept and store source field
- Enhanced logging to show alert source

### How It Works

#### Step 1: Alert Detection
When Snort detects network activity matching its rules, it writes to the log file:
```
01/28-17:30:45.123456 [**] [1:1000001:0] Suspicious Activity Detected [**] {TCP} 192.168.1.100 -> 10.0.0.1
```

#### Step 2: Alert Parsing & Classification
The Snort backend parses the alert and classifies severity based on:
- Alert message content
- Protocol type
- Nmap scan detection
- Attack patterns

#### Step 3: Automatic Ticket Creation (High/Critical Only)
For High or Critical alerts:
```python
alert_message = f"Snort IDS Alert: {alert['message']}\n" \
              f"Source: {alert['source']} → Destination: {alert['destination']}\n" \
              f"Protocol: {alert['protocol']}\n" \
              f"Severity: {alert['severity']}"

# Send to main app
POST /process_alert
{
    "message": alert_message,
    "classification_method": "model",
    "source": "snort_ids"
}
```

#### Step 4: Jira & Slack Integration
The main app (`app.py`) then:
1. Uses ML model to confirm/adjust severity
2. Creates Jira ticket with priority mapping
3. Sends formatted Slack notification
4. Stores in PostgreSQL database

## Usage

### Starting Snort with Auto-Ticketing
```powershell
# Terminal 1: Start main app
python app.py

# Terminal 2: Start Snort backend (with auto-ticketing enabled)
python snort_backend.py
```

You'll see confirmation:
```
Starting Snort Backend Server...
============================================================
🎫 AUTO-TICKETING ENABLED
High and Critical Snort alerts will automatically create:
  ✓ Jira tickets
  ✓ Slack notifications
============================================================
```

### Monitoring Auto-Ticketing
Check the status via API:
```bash
GET http://localhost:5001/snort/auto-ticket/status
```

Response:
```json
{
    "status": "enabled",
    "total_processed": 5,
    "main_app_url": "http://localhost:5000",
    "message": "Auto-ticketing is enabled for High and Critical alerts"
}
```

### Console Output
When a High/Critical alert is detected:
```
RAW ALERT LINE: 01/28-17:30:45.123456 [**] [1:1000001:0] Suspicious Activity...
PARSED ALERT: Suspicious Activity Detected | Severity: High
🎫 Auto-creating ticket for High severity alert...
Creating ticket for High alert: Suspicious Activity Detected...
✓ Ticket created successfully: SEC-123
```

## Severity Classification

### Critical Alerts
Automatically ticketed. Examples:
- Ransomware activity
- Data exfiltration attempts
- Command & Control traffic
- Authentication bypass
- Critical vulnerability exploits

### High Alerts  
Automatically ticketed. Examples:
- Malware detected
- Brute force attacks
- Suspicious port scans (Nmap SYN scans)
- Privilege escalation attempts
- Unauthorized access attempts

### Medium Alerts
**NOT** automatically ticketed. Examples:
- Failed login attempts
- Port scans (basic)
- Minor policy violations

### Low Alerts
**NOT** automatically ticketed. Examples:
- Routine traffic
- Informational alerts
- Normal network activity

## Configuration

### Environment Variables Required
Ensure these are set in your `.env` file:
```env
# Jira Configuration
JIRA_SERVER=https://your-domain.atlassian.net
JIRA_USERNAME=your-email@example.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=SEC

# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_CHANNEL_ID=C01234567890

# Database
DB_USERNAME=postgres
DB_PASSWORD=your-password
DB_HOST=localhost
DB_NAME=alerts
```

### Database Migration
The Alert model now includes a `source` field. If you have existing alerts, run:
```python
# In Python console or migration script
from app import db, Alert

# Add source column (if not exists)
with db.engine.connect() as conn:
    conn.execute("ALTER TABLE alert ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'manual'")
    conn.commit()
```

## Benefits

### 1. **Faster Response Time**
- Tickets created instantly upon detection
- No manual alert review needed for critical threats
- Security team notified immediately via Slack

### 2. **Reduced Manual Work**
- Eliminates manual ticket creation for Snort alerts
- Automatic severity classification
- Audit trail maintained automatically

### 3. **Consistent Handling**
- Every High/Critical alert gets a ticket
- Standard format for all Snort alerts
- No alerts slip through the cracks

### 4. **Traceability**
- Source tracking shows alert origin
- Jira ticket linked to original alert
- Full context preserved (IPs, protocol, timestamp)

## Troubleshooting

### Issue: Tickets Not Being Created
**Check:**
1. Main app (port 5000) is running
2. Jira and Slack credentials are configured
3. Alert severity is High or Critical
4. Check console for error messages

### Issue: Duplicate Tickets
**Solution**: The system automatically prevents duplicates using alert ID tracking. If you see duplicates:
- Clear alerts: `DELETE http://localhost:5001/snort/alerts/clear`
- This resets the processed alerts tracker

### Issue: Connectivity Errors
**Error**: `✗ Error connecting to main app: Connection refused`
**Solution**: Ensure main app is running on port 5000

### Debug Mode
View detailed logging:
```python
# In snort_backend.py, alerts print to console:
print(f"🎫 Auto-creating ticket for {alert['severity']} severity alert...")
print(f"✓ Ticket created successfully: {result.get('jira_ticket_id')}")
```

## API Endpoints

### Get Auto-Ticket Status
```http
GET /snort/auto-ticket/status
```

### Get Snort Alerts (including ticket info)
```http
GET /snort/alerts
```

Response includes ticket information:
```json
[
    {
        "id": 1,
        "message": "Suspicious Activity Detected",
        "severity": "High",
        "jira_ticket_id": "SEC-123",
        "slack_sent": true,
        "auto_ticketed": true,
        "source": "192.168.1.100",
        "destination": "10.0.0.1"
    }
]
```

## Future Enhancements

### Potential Improvements
1. **Configurable Severity Threshold**: Allow customization of which severities trigger tickets
2. **Rate Limiting**: Prevent ticket spam for repeated alerts
3. **Alert Correlation**: Group related alerts into single ticket
4. **Custom Rules**: User-defined ticket creation rules
5. **Email Integration**: Send email notifications in addition to Slack
6. **Webhook Support**: Trigger custom webhooks for alerts

## Testing

### Manual Test
1. Start both apps (main + Snort backend)
2. Generate test traffic that triggers Snort rules
3. Use Nmap scan: `nmap -sS <target-ip>` (requires Snort rules for port scans)
4. Check console output for ticket creation
5. Verify in Jira and Slack

### Verify Auto-Ticketing
```bash
# Check status
curl http://localhost:5001/snort/auto-ticket/status

# View alerts
curl http://localhost:5001/snort/alerts

# Check main app alerts
curl http://localhost:5000/get_alerts
```

## Security Considerations

### Best Practices
1. **Secure Credentials**: Never commit `.env` file to version control
2. **API Rate Limits**: Be aware of Jira/Slack API rate limits
3. **Alert Validation**: ML model validates severity before ticket creation
4. **Access Control**: Ensure Snort backend can only be accessed locally
5. **Log Monitoring**: Regularly review auto-ticketing logs

## Summary

This feature transforms Snort IDS from a passive detection tool into an active incident response system. High and Critical alerts now trigger immediate action:

- 🎫 **Jira Ticket** - Trackable incident with all details
- 💬 **Slack Alert** - Instant team notification
- 📊 **Database Record** - Permanent audit trail
- 🔗 **Full Context** - IPs, protocol, timestamp preserved

**Result**: Faster response, reduced manual work, zero missed critical alerts.

---

**Author**: Security Automation System  
**Version**: 1.0  
**Last Updated**: November 2025
