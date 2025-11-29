# Vulnerable Test Site for Snort IDS Testing

This is a deliberately vulnerable web application designed to test Snort IDS rules in a controlled environment.

## ⚠️ SECURITY WARNING

**This application contains intentional security vulnerabilities!**
- **DO NOT deploy on production systems**
- **DO NOT expose to the internet**
- **Only run in isolated test environments**
- **Use at your own risk**

## Setup

### Option 1: Direct Python Execution (Recommended)

1. Install dependencies:
```bash
pip install flask
```

2. Run the vulnerable site:
```bash
python vulnerable_test_site.py
```

### Option 2: Docker Deployment

1. Build and run with Docker Compose:
```bash
docker-compose up --build
```

Or manually:
```bash
docker build -t vulnerable-site .
docker run -p 8080:8080 vulnerable-site
```

The site will be available at `http://localhost:8080`

## Vulnerabilities Included

### 1. SQL Injection
- **Endpoint**: `/login` and `/search`
- **Vulnerability**: Unsanitized user input in SQL queries
- **Snort Rules Triggered**: `WEB-ATTACK SQL Injection` rules

**Test Commands:**
```bash
# Login bypass
curl "http://localhost:8080/login?username=admin'--&password=anything"

# Union-based injection
curl "http://localhost:8080/search?q=%' UNION SELECT * FROM users--"
```

### 2. Cross-Site Scripting (XSS)
- **Endpoint**: `/comment`
- **Vulnerability**: User input reflected without sanitization
- **Snort Rules Triggered**: `WEB-ATTACK XSS` rules

**Test Commands:**
```bash
# Basic XSS
curl "http://localhost:8080/comment?comment=<script>alert('XSS')</script>"

# Event handler XSS
curl "http://localhost:8080/comment?comment=<img src=x onerror=alert('XSS')>"
```

### 3. Directory Traversal
- **Endpoint**: `/file`
- **Vulnerability**: Path manipulation allows accessing any file
- **Snort Rules Triggered**: `WEB-ATTACK Directory Traversal` rules

**Test Commands:**
```bash
# Access system files
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Windows hosts file
curl "http://localhost:8080/file?path=../../../Windows/System32/drivers/etc/hosts"
```

### 4. Command Injection / RCE
- **Endpoint**: `/exec`
- **Vulnerability**: User input passed directly to shell
- **Snort Rules Triggered**: `WEB-ATTACK OS Command Injection` and `Log4Shell` rules

**Test Commands:**
```bash
# Basic command execution
curl "http://localhost:8080/exec?cmd=whoami"

# Command chaining
curl "http://localhost:8080/exec?cmd=cat /etc/passwd"
```

### 5. File Upload Vulnerabilities
- **Endpoint**: `/upload`
- **Vulnerability**: Unrestricted file upload
- **Snort Rules Triggered**: Potential malware upload detection

## Automated Testing

Use the included test script to automatically perform attacks:

```bash
python test_attacks.py
```

Or run non-interactively:
```bash
python test_attacks.py --yes
```

The script will:
1. Test SQL injection vulnerabilities
2. Test XSS vulnerabilities  
3. Test directory traversal
4. Test command injection
5. Perform network scans with nmap
6. Check for generated Snort alerts

## Manual Testing Steps

1. **Start Snort Backend:**
```bash
python snort_backend.py
```

2. **Start Main Application:**
```bash
python app.py
```

3. **Start Vulnerable Site:**
```bash
python vulnerable_test_site.py
```

4. **Run Attacks from Another Terminal:**
```bash
# Example attack sequence
curl "http://localhost:8080/login?username=admin'--&password=test"
curl "http://localhost:8080/comment?comment=<script>alert(1)</script>"
curl "http://localhost:8080/file?path=../../../etc/passwd"
```

5. **Check Alerts:**
```bash
curl http://localhost:5000/get_alerts
```

Or visit the web interface at `http://localhost:3000`

## Expected Snort Alerts

When attacking the vulnerable site, you should see alerts like:
- `WEB-ATTACK SQL Injection UNION SELECT Attempt`
- `WEB-ATTACK XSS Script Tag Injection`
- `WEB-ATTACK Directory Traversal Attempt`
- `WEB-ATTACK OS Command Injection`

## Cleanup

After testing, remove the vulnerable site:
```bash
rm vulnerable_test_site.py
rm -rf uploads/
rm vulnerable.db
```

## Alternative Testing Methods

If you prefer not to run vulnerable code locally:

1. **Use existing vulnerable applications:**
   - DVWA (Damn Vulnerable Web Application)
   - OWASP Juice Shop
   - WebGoat

2. **Network scanning:**
   - `nmap -sS -p1-1000 localhost`
   - `nmap -sX -p1-100 localhost` (XMAS scan)

3. **API testing:**
   - Use the `/process_alert` endpoint with test messages

## Troubleshooting

- **No alerts detected**: Check Snort interface configuration
- **App won't start**: Install missing dependencies
- **Database errors**: The app creates its own SQLite database

## Legal Notice

This tool is provided for educational and testing purposes only. The author is not responsible for any misuse or damage caused by this software.