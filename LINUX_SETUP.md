# Linux Setup Guide for Secbot

This guide will help you set up the Security Incident Response Bot on Linux (Ubuntu/Debian).

## Prerequisites

### 1. System Requirements
- Ubuntu 20.04+ / Debian 11+ (or similar Linux distribution)
- Python 3.8+
- PostgreSQL 12+
- Root/sudo access for Snort

### 2. Install System Dependencies

```bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    postgresql \
    postgresql-contrib \
    snort \
    git \
    build-essential
```

## Snort Installation and Configuration

### 1. Install Snort

```bash
# Install Snort IDS
sudo apt install -y snort

# Verify installation
snort --version
```

### 2. Configure Snort

The application expects Snort configuration at specific paths:
- Config file: `/etc/snort/snort.conf`
- Log directory: `/var/log/snort/`
- Rules directory: `/etc/snort/rules/`

```bash
# Create log directory
sudo mkdir -p /var/log/snort
sudo chmod 755 /var/log/snort

# Copy production rules
sudo cp production-threats.rules /etc/snort/rules/

# Update snort.conf
sudo nano /etc/snort/snort.conf
```

Update these lines in `/etc/snort/snort.conf`:

```conf
# Set your network
ipvar HOME_NET [YOUR_IP_ADDRESS]
ipvar EXTERNAL_NET !$HOME_NET

# Include production rules
include /etc/snort/rules/production-threats.rules

# HTTP ports - ensure port 3000 is included
portvar HTTP_PORTS [80,443,3000,8000,8080,8443]

# Stream reassembly - ensure ports are included
preprocessor stream5_tcp: policy linux, ports both 21 22 23 25 53 80 110 111 135 139 143 443 445 1433 3000 3306 3389 8000 8080 8443
```

### 3. Set Snort Permissions

```bash
# Allow Snort to capture packets (optional, instead of running as root)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/snort

# Or run the application as root (required for packet capture)
```

## Database Setup

### 1. Install and Configure PostgreSQL

```bash
# PostgreSQL should be installed from prerequisites
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE alerts;
CREATE USER secbot_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE alerts TO secbot_user;
\q
EOF
```

### 2. Configure Database Connection

Create/edit `.env` file:

```bash
DB_USERNAME=secbot_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_NAME=alerts
```

## Application Setup

### 1. Clone Repository

```bash
cd ~
git clone https://github.com/YourUsername/Secbot.git
cd Secbot
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create `.env` file in the project root:

```bash
# Database
DB_USERNAME=secbot_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_NAME=alerts

# Jira Configuration
JIRA_SERVER=https://your-domain.atlassian.net
JIRA_USERNAME=your-email@example.com
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT_KEY=SEC

# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
SLACK_CHANNEL_ID=C1234567890

# Gemini AI (optional)
GEMINI_API_KEY=your_gemini_api_key
```

### 5. Initialize Database

```bash
# Run database migrations
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"

# Or use Flask-Migrate
flask db upgrade
```

### 6. Train ML Model (if not using Gemini)

```bash
python3 trainmodel.py
```

## Running the Application

### Option 1: Run with sudo (Recommended for Snort)

```bash
# Run main Flask app
sudo -E venv/bin/python3 app.py

# In another terminal, run Snort backend
sudo -E venv/bin/python3 snort_backend.py

# In another terminal, run frontend
cd alert-frontend
npm install
npm run dev
```

### Option 2: Using systemd Services

Create service files for automatic startup:

#### Main Application Service

Create `/etc/systemd/system/secbot-app.service`:

```ini
[Unit]
Description=Secbot Main Application
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/youruser/Secbot
Environment="PATH=/home/youruser/Secbot/venv/bin"
EnvironmentFile=/home/youruser/Secbot/.env
ExecStart=/home/youruser/Secbot/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

#### Snort Backend Service

Create `/etc/systemd/system/secbot-snort.service`:

```ini
[Unit]
Description=Secbot Snort Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/youruser/Secbot
Environment="PATH=/home/youruser/Secbot/venv/bin"
EnvironmentFile=/home/youruser/Secbot/.env
ExecStart=/home/youruser/Secbot/venv/bin/python3 snort_backend.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable secbot-app secbot-snort
sudo systemctl start secbot-app secbot-snort

# Check status
sudo systemctl status secbot-app
sudo systemctl status secbot-snort
```

## Network Interface Configuration

### Find Your Network Interface

```bash
# List all network interfaces
ip link show

# Common interface names:
# - eth0, eth1 (Ethernet)
# - ens33, ens192 (VMware/VirtualBox)
# - enp0s3, enp0s8 (PCI based naming)
# - wlan0, wlp2s0 (Wireless)
```

### Set Interface in Application

1. Access Snort dashboard: http://localhost:3001
2. Select your active network interface
3. Start Snort monitoring

## Firewall Configuration

### Allow Required Ports

```bash
# UFW (Ubuntu Firewall)
sudo ufw allow 5000/tcp  # Main Flask app
sudo ufw allow 5001/tcp  # Snort backend
sudo ufw allow 3000/tcp  # Vulnerable test site
sudo ufw allow 3001/tcp  # Frontend
sudo ufw enable

# iptables (alternative)
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5001 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3001 -j ACCEPT
```

## Testing the Setup

### 1. Test Database Connection

```bash
python3 -c "from app import db; print('Database connected!' if db else 'Connection failed')"
```

### 2. Test Snort

```bash
# Test Snort configuration
sudo snort -T -c /etc/snort/snort.conf

# Run Snort in test mode
sudo snort -A console -i eth0 -c /etc/snort/snort.conf -l /var/log/snort
```

### 3. Run Test Attacks

```bash
# Start vulnerable test site
python3 test-files/test_site.py

# In another terminal, run attacks
python3 test-files/test_attacks.py

# Or with alert injection
python3 test-files/test_attacks_with_alerts.py
```

## Troubleshooting

### Snort Not Detecting Traffic

```bash
# Check if Snort has permission to capture packets
sudo getcap /usr/sbin/snort

# Check interface is up
ip link show eth0

# Check Snort is running
ps aux | grep snort

# Check logs
sudo tail -f /var/log/snort/alert.ids
```

### Permission Errors

```bash
# Run application as root
sudo -E venv/bin/python3 app.py

# Or set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/snort
```

### Database Connection Issues

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U secbot_user -d alerts -h localhost
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :5000

# Kill process if needed
sudo kill -9 <PID>
```

## Differences from Windows

### Path Differences

| Purpose | Windows | Linux |
|---------|---------|-------|
| Snort executable | `C:\Snort\bin\snort.exe` | `/usr/sbin/snort` |
| Snort config | `C:\Snort\etc\snort.conf` | `/etc/snort/snort.conf` |
| Log directory | `C:\Snort\log\` | `/var/log/snort/` |
| Rules directory | `C:\Snort\rules\` | `/etc/snort/rules/` |

### Interface Naming

- **Windows**: Uses numeric interface IDs (1, 2, 3, etc.)
- **Linux**: Uses interface names (eth0, ens33, wlan0, etc.)

### Privilege Requirements

- **Windows**: Requires "Run as Administrator"
- **Linux**: Requires root or capabilities (`cap_net_raw`, `cap_net_admin`)

### Terminal Commands

- **Windows**: Uses `cmd.exe` and batch files
- **Linux**: Uses `bash` and shell scripts

## Production Deployment Recommendations

1. **Use systemd services** for automatic startup and monitoring
2. **Configure log rotation** for Snort logs
3. **Set up HTTPS** using nginx/Apache reverse proxy
4. **Use strong database passwords** and limit access
5. **Monitor system resources** (CPU, memory, disk I/O)
6. **Set up regular backups** of database
7. **Configure SELinux/AppArmor** for additional security
8. **Use firewall rules** to restrict access

## Performance Tuning

### Snort Optimization

```bash
# Edit /etc/snort/snort.conf
# Increase memory limits
config pcre_match_limit: 5000
config pcre_match_limit_recursion: 2000

# Tune preprocessors
preprocessor stream5_tcp: max_tcp 524288
```

### System Limits

```bash
# Increase file descriptors
sudo nano /etc/security/limits.conf

# Add:
* soft nofile 65535
* hard nofile 65535
```

## Support

For issues specific to Linux deployment:
- Check system logs: `sudo journalctl -u secbot-app -f`
- Check application logs in the working directory
- Verify all dependencies are installed
- Ensure correct file permissions

## Additional Resources

- Snort Documentation: https://www.snort.org/documents
- PostgreSQL Docs: https://www.postgresql.org/docs/
- Flask Deployment: https://flask.palletsprojects.com/en/latest/deploying/
