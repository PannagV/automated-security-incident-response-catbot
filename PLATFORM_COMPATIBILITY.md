# Platform Compatibility Summary

## Overview

The Secbot application has been updated to support both **Windows** and **Linux** platforms. The codebase automatically detects the operating system and uses appropriate paths, commands, and configurations.

## Key Changes Made

### 1. Core Application (`snort_backend.py`)

#### Platform Detection
- Added `import platform` for OS detection
- All file paths now use platform-specific defaults

#### Path Configuration
**Windows:**
- Snort executable: `C:\Snort\bin\snort.exe`
- Config: `C:\Snort\etc\snort_production.conf`
- Logs: `C:\Snort\log\`
- Rules: `C:\Snort\rules\`

**Linux:**
- Snort executable: `/usr/sbin/snort`
- Config: `/etc/snort/snort.conf`
- Logs: `/var/log/snort/`
- Rules: `/etc/snort/rules/`

#### Interface Detection
- **Windows**: Uses numeric interface IDs (1, 2, 3...) via `snort.exe -W`
- **Linux**: Uses interface names (eth0, ens33, wlan0...) via `ip route` command
- New method: `_get_linux_primary_interface()` for Linux-specific detection

#### Privilege Checking
- **Windows**: Checks for Administrator via `ctypes.windll.shell32.IsUserAnAdmin()`
- **Linux**: Checks for root via `os.geteuid() == 0`
- Error messages now dynamically mention "Administrator" or "root"

#### Terminal/Debug Mode
- **Windows**: Uses batch files and `cmd.exe`
- **Linux**: Attempts to use `gnome-terminal`, `xterm`, or `konsole`
- Falls back to background mode if no terminal emulator found

### 2. Utility Files

#### `platform_utils.py` (NEW)
Centralized platform configuration module:
- `PlatformConfig` class with automatic OS detection
- Platform-specific path management
- Privilege checking utilities
- Interface format detection (numeric vs name)
- Terminal command helpers

#### `network_diagnostic.py`
- Updated to check for libpcap on Linux (instead of Npcap/WinPcap only)
- Platform-specific Snort path detection
- Linux-specific installation instructions

### 3. Test Files

#### `test_attacks.py`
- Removed Windows-specific paths (e.g., `C:\Windows\System32\...`)
- Uses universal paths like `/etc/passwd` for directory traversal tests

#### `test_attacks_with_alerts.py`
- Updated payload examples to be platform-neutral
- Removed references to Windows-specific files

### 4. Documentation

#### `LINUX_SETUP.md` (NEW)
Comprehensive Linux installation and setup guide including:
- System dependencies (apt packages)
- Snort installation and configuration
- PostgreSQL setup
- systemd service files for auto-start
- Firewall configuration
- Network interface configuration
- Troubleshooting common Linux issues

## Platform-Specific Features

### Windows
- Uses WinPcap/Npcap for packet capture
- Requires "Run as Administrator"
- Batch file support for debug terminals
- Windows-specific route command parsing
- Interface numbering system

### Linux
- Uses libpcap for packet capture
- Requires root or CAP_NET_RAW capability
- Shell script support
- systemd service integration
- Interface naming system (eth0, ens33, etc.)
- Can use setcap to avoid running as root

## What Stays the Same

### Application Logic
- Flask web server (port 5000 for main app, 5001 for Snort backend)
- PostgreSQL database (platform-independent)
- Jira integration
- Slack notifications
- Gemini AI classification
- React frontend (port 3001)
- Alert processing and ML classification
- REST API endpoints

### Configuration
- `.env` file format identical on both platforms
- Database connection strings work on both
- API keys and tokens are platform-independent

### Snort Rules
- Rule files (`.rules`) are identical
- Rule syntax is the same
- Configuration directives compatible with both

## Testing Both Platforms

### Windows Testing
```powershell
# Run as Administrator
python snort_backend.py
python app.py
cd alert-frontend && npm run dev
```

### Linux Testing
```bash
# Run with sudo
sudo python3 snort_backend.py
sudo python3 app.py
cd alert-frontend && npm run dev
```

## Migration Checklist

### From Windows to Linux

- [ ] Install Snort via apt: `sudo apt install snort`
- [ ] Copy production rules to `/etc/snort/rules/`
- [ ] Update snort.conf with correct HOME_NET and HTTP_PORTS
- [ ] Create log directory: `sudo mkdir -p /var/log/snort`
- [ ] Install Python dependencies in venv
- [ ] Set up PostgreSQL database
- [ ] Copy .env file (same format)
- [ ] Test Snort: `sudo snort -T -c /etc/snort/snort.conf`
- [ ] Run application with sudo
- [ ] Configure firewall rules if needed

### From Linux to Windows

- [ ] Install Snort for Windows
- [ ] Install Npcap
- [ ] Copy rules to `C:\Snort\rules\`
- [ ] Update snort.conf with Windows paths
- [ ] Create log directory structure
- [ ] Install Python dependencies
- [ ] Set up PostgreSQL on Windows
- [ ] Copy .env file (same format)
- [ ] Test Snort: `C:\Snort\bin\snort.exe -T -c C:\Snort\etc\snort.conf`
- [ ] Run as Administrator

## Known Platform Differences

### 1. Loopback Traffic
Both Windows and Linux cannot capture loopback (127.0.0.1) traffic with Snort. This is an OS-level limitation, not platform-specific.

### 2. Process Management
- **Windows**: Uses `psutil` with Windows-specific process iteration
- **Linux**: Uses same `psutil` but with Linux process tree

### 3. File Permissions
- **Windows**: Relies on Administrator rights
- **Linux**: Uses file permissions (chmod/chown) and capabilities

### 4. Network Interface Identification
- **Windows**: Snort assigns numeric IDs to interfaces
- **Linux**: Uses kernel-assigned interface names

## Code Structure

### Platform-Independent Code
- Database models (`app.py`)
- API endpoints
- ML training (`trainmodel.py`)
- Frontend (React)

### Platform-Specific Code
- File paths (now auto-detected)
- Interface detection methods
- Privilege checking
- Terminal command generation

### Abstracted Platform Logic
All platform-specific logic is contained in:
1. `SnortManager.__init__()` - path initialization
2. `is_admin()` - privilege checking
3. `get_default_interface()` - interface detection
4. `_start_snort_with_terminal()` - debug mode terminals
5. `platform_utils.py` - centralized configuration

## Future Improvements

### Suggested Enhancements
1. Support for macOS
2. Docker containerization for easier deployment
3. Automated platform-specific installer scripts
4. Configuration wizard for first-time setup
5. Better handling of alternative Snort installations
6. Support for Suricata (alternative to Snort)

### Testing Needs
1. Automated tests on both platforms
2. CI/CD pipeline for multi-platform testing
3. Performance benchmarking on different OSes
4. Interface detection edge cases

## Troubleshooting

### Issue: Import platform fails
**Solution**: Should be in Python standard library. Check Python version (3.7+).

### Issue: libpcap not found (Linux)
**Solution**: `sudo apt install libpcap-dev`

### Issue: Permission denied on Linux
**Solution**: Run with `sudo` or use `setcap` on snort executable

### Issue: Interface detection fails
**Solution**: Manually set interface in UI or check `platform_utils.py`

### Issue: Paths not found
**Solution**: Verify Snort installation location, may need to customize paths in code

## Support

For platform-specific issues:
- **Windows**: Check Windows Event Viewer, verify Npcap installation
- **Linux**: Check syslog (`/var/log/syslog`), verify libpcap installation

For general issues:
- Check application logs
- Verify database connection
- Test Snort configuration manually
- Review `.env` file configuration
