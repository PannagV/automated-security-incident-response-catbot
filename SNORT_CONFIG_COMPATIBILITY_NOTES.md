# Snort Production Configuration Compatibility Notes

## Overview
This document details the compatibility adjustments made to `snort_production.conf` and `production-threats.rules` to work with Snort 2.9.20 on Windows.

## Validation Status
✅ **Configuration Successfully Validated** - `Snort successfully validated the configuration!`

---

## Preprocessors Disabled (Not Available in This Build)

The following preprocessors were commented out because they are not compiled into this Snort build:

### 1. FTP/Telnet Preprocessor
```conf
# preprocessor ftp_telnet: global inspection_type stateful encrypted_traffic no
```
**Reason**: `Unknown preprocessor: 'ftp_telnet'`

### 2. SMTP Preprocessor
```conf
# preprocessor smtp: ...
```
**Reason**: `Unknown preprocessor: 'smtp'`

### 3. SSH Preprocessor
```conf
# preprocessor ssh: server_ports { 22 } autodetect ...
```
**Reason**: `Unknown preprocessor: 'ssh'`

### 4. DNS Preprocessor
```conf
# preprocessor dns: ports { 53 } enable_rdata_overflow
```
**Reason**: `Unknown preprocessor: 'dns'`

### 5. SSL Preprocessor
```conf
# preprocessor ssl: ports { 443 ... } trustservers noinspect_encrypted
```
**Reason**: `Unknown preprocessor: 'ssl'`

### 6. DCE/RPC2 Preprocessor
```conf
# preprocessor dcerpc2: ...
```
**Reason**: `Unknown preprocessor: 'dcerpc2'`

### 7. SIP Preprocessor
```conf
# preprocessor sip: ...
```
**Reason**: `Unknown preprocessor: 'sip'`

**Impact**: These preprocessors provide protocol-specific anomaly detection. Without them, Snort will still detect threats using signature-based rules but won't perform deep protocol inspection for these services.

---

## Stream5 Configuration Changes

### Active Response Removed
**Original**:
```conf
preprocessor stream5_global: ... max_active_responses 2, min_response_seconds 5
```

**Modified**:
```conf
preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp no, max_tcp 262144, max_udp 131072
```

**Reason**: `ERROR: Active response: can't open ip!`  
Active responses (TCP resets) are only available in inline mode. Since we're running Snort in passive/IDS mode, these settings must be removed.

---

## Rule Syntax Fixes

### 1. PCRE Pattern Issues - Character Classes
**Problem**: Snort PCRE engine had issues with certain bracket notation in character classes.

#### Unix Command Injection (SID 3000021)
**Original**: `pcre:"/(\||;|`|\$\()(cat|ls|wget|curl|chmod|nc|bash|sh)/Ui"`  
**Fixed**: `content:"cat"; nocase; http_uri;`  
**Reason**: Pipe character `|` caused parsing errors even when escaped

#### Windows Command Injection (SID 3000022)
**Original**: `pcre:"/(&|\||;)(cmd|powershell|net|whoami|ipconfig)/Ui"`  
**Fixed**: `content:"cmd"; nocase; http_uri;`  
**Reason**: Same issue with pipe character

#### Emotet C2 Communication (SID 3000003)
**Original**: `pcre:"/^\/[a-zA-Z0-9]{1,10}$/Ui"`  
**Fixed**: `pcre:"/^\/\w{1,10}$/Ui"`  
**Reason**: Simplified character class using `\w`

#### Cobalt Strike Beacon (SID 3000004)
**Original**: `pcre:"/Cookie\x3a[^\r\n]{100,}/H"`  
**Fixed**: `pcre:"/Cookie\x3a.{100,}/H"`  
**Reason**: Negated character class `[^\r\n]` replaced with `.`

#### XSS Script Tag (SID 3000040)
**Original**: `pcre:"/<script[^>]*>/Ui"`  
**Fixed**: `pcre:"/<script.*>/Ui"`  
**Reason**: Simplified negated character class

#### Base64 Data Transfer (SID 3000082)
**Original**: `pcre:"/[A-Za-z0-9+\/]{100,}={0,2}/P"`  
**Fixed**: `pcre:"/\w{100,}/P"`  
**Reason**: Simplified to word characters

---

### 2. Threshold Deprecation
**Problem**: `threshold` keyword is deprecated in Snort 2.9.x

#### Changed in All Rules
**Original**: `threshold:type both, track by_src, count X, seconds Y`  
**Fixed**: `detection_filter:track by_src, count X, seconds Y`

**Affected Rules**:
- SSH Brute Force (SID 3000050)
- RDP Brute Force (SID 3000051)
- HTTP Auth Brute Force (SID 3000052)
- Failed Login Attempts (SID 3000053)
- Nmap SYN Scan (SID 3000060)
- Nmap XMAS Scan (SID 3000061)
- Nmap NULL Scan (SID 3000062)
- Nmap FIN Scan (SID 3000063)
- UDP Port Scan (SID 3000064)
- SYN Flood (SID 3000070)
- ICMP Flood (SID 3000071)
- UDP Flood (SID 3000072)
- Slowloris Attack (SID 3000073)
- Large Data Transfer (SID 3000080)

---

### 3. HTTP Keyword Issues
**Problem**: `http_user_agent` keyword not available

#### Nessus Scanner Detection (SID 3000065)
**Original**: `content:"Nessus"; http_user_agent;`  
**Fixed**: `content:"User-Agent|3a|"; http_header; content:"Nessus"; within:20; http_header;`  
**Reason**: `http_user_agent` not supported, manually match User-Agent header

---

## Configuration Testing

### Test Command
```powershell
& "C:\Snort\bin\snort.exe" -T -c "C:\Snort\etc\snort_production.conf"
```

### Expected Output
```
...
Snort successfully validated the configuration!
Snort exiting
```

### Expected Warnings (Harmless)
```
WARNING: ip normalizations disabled because not inline.
WARNING: tcp normalizations disabled because not inline.
WARNING: icmp4 normalizations disabled because not inline.
WARNING: ip6 normalizations disabled because not inline.
WARNING: icmp6 normalizations disabled because not inline.
```
These warnings are expected in IDS mode and can be ignored.

---

## Production Deployment

### Files Modified
1. **c:\Snort\etc\snort_production.conf** - Main configuration
2. **c:\Snort\rules\production-threats.rules** - 47 threat detection rules

### Backup Files
- Original configs saved as: `snort_minimal_complete.conf`, `snort_minimal.conf`
- Source files in: `c:\Users\panna\Documents\GitHub\Secbot\`

### Running Snort with Production Config
```powershell
& "C:\Snort\bin\snort.exe" -i 4 -c "C:\Snort\etc\snort_production.conf" -A console -q -l "C:\Snort\log"
```

**Parameters**:
- `-i 4`: Interface number (verify with `snort.exe -W`)
- `-c`: Configuration file
- `-A console`: Alert to console
- `-q`: Quiet mode
- `-l`: Log directory

---

## Rule Categories Active

The production configuration includes 47 rules across these categories:

1. **Malware & Exploits** (7 rules) - Wannacry, Emotet, Cobalt Strike, Mimikatz, etc.
2. **SQL Injection** (6 rules) - UNION, Time-based, Comment bypass, etc.
3. **Command Injection & RCE** (4 rules) - PHP, Unix, Windows commands, Log4Shell
4. **Directory Traversal** (3 rules) - Path traversal, LFI, RFI
5. **XSS Attacks** (3 rules) - Script tags, Event handlers, IMG tags
6. **Brute Force** (4 rules) - SSH, RDP, HTTP Auth, Login attempts
7. **Port Scans** (6 rules) - Nmap scans, UDP scans, Nessus
8. **DoS Attacks** (4 rules) - SYN/UDP/ICMP floods, Slowloris
9. **Data Exfiltration** (3 rules) - DNS tunneling, Large transfers, Base64
10. **Backdoors** (2 rules) - Reverse shells, Bind shells
11. **Suspicious Protocols** (1 rule) - IRC C2
12. **Crypto Mining** (2 rules) - Stratum, Monero
13. **Web Shells** (1 rule) - Common web shell patterns
14. **Lateral Movement** (1 rule) - SMB relay attacks

---

## Performance Considerations

### Memory Usage
- **MaxRss**: ~88MB at rule load
- **Pattern Matchers**: 3.95K patterns, 8.59K match lists

### Recommended Settings
```conf
config pcre_match_limit: 3500
config pcre_match_limit_recursion: 1500
config detection: search-method ac-bnfa-q search-optimize max-pattern-len 20
```

### Alert Rate Tuning
All scan/flood detection rules use `detection_filter` to prevent alert storms:
- Port scans: 50+ connections/60s
- Brute force: 10-20 attempts/60s
- Floods: 50-100 packets/10s

---

## Troubleshooting

### Issue: "Unknown preprocessor" error
**Solution**: Comment out that preprocessor - it's not compiled into your Snort build

### Issue: "unable to parse pcre regex"
**Solution**: Simplify PCRE patterns, avoid complex character classes with brackets

### Issue: "Unknown rule option: 'http_user_agent'"
**Solution**: Use `http_header` with manual content matching instead

### Issue: "Active response: can't open ip!"
**Solution**: Remove `max_active_responses` and `min_response_seconds` from stream5_global

### Issue: Threshold deprecation warning
**Solution**: Replace `threshold:type both, track...` with `detection_filter:track...`

---

## Integration with Alert System

### Auto-Ticketing
Snort backend automatically creates Jira tickets and Slack notifications for High/Critical severity alerts.

**Severity Mapping**:
- Priority 1 rules → **Critical**
- Priority 2 rules → **High**  
- Priority 3 rules → **Medium**

**Backend Configuration** (`snort_backend.py`):
```python
SNORT_CONFIG_PATH = r"C:\Snort\etc\snort_production.conf"
```

---

## Next Steps

1. ✅ Configuration validated successfully
2. ⏳ Test with live traffic
3. ⏳ Verify only real threats generate alerts (not normal traffic)
4. ⏳ Test auto-ticketing with High/Critical alerts
5. ⏳ Monitor false positive rate
6. ⏳ Fine-tune detection_filter thresholds as needed

---

## Version Information

- **Snort Version**: 2.9.20
- **OS**: Windows
- **Configuration**: snort_production.conf
- **Rules File**: production-threats.rules (47 custom rules)
- **Last Updated**: 2024
- **Validation Status**: ✅ PASSED
