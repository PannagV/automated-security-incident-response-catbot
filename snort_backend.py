import subprocess
import threading
import time
import json
import os
import re
from datetime import datetime
from flask import Flask, jsonify
from flask_cors import CORS
import psutil

app = Flask(__name__)
CORS(app)

class SnortManager:
    def __init__(self):
        self.snort_process = None
        self.is_running = False
        self.log_file_path = r"C:\Snort\log\alert.ids"
        self.snort_config_path = r"C:\Snort\etc\snort_minimal.conf"
        self.snort_executable = r"C:\Snort\bin\snort.exe"
        self.interface = self.get_default_interface()
        self.alerts = []
        self.max_alerts = 1000
        self.snort_errors = []
        self.debug_mode = False
    def get_default_interface(self):
        """Get the primary active network interface for Snort on Windows"""
        try:
            import socket
            
            # Method 1: Get the interface used for default route
            primary_interface = self._get_primary_interface()
            if primary_interface:
                return primary_interface
            
            # Method 2: Find active non-loopback interfaces
            active_interfaces = self._get_active_interfaces()
            if active_interfaces:
                return active_interfaces[0]
            
            # Fallback to interface 1
            return "1"
            
        except Exception as e:
            print(f"Error detecting interface: {e}")
            return "1"
    def _get_windows_primary_interface(self):
        """Use Windows route command to find primary interface"""
        try:
            import subprocess
            
            # Get default route on Windows
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'Gateway' not in line:
                        # Parse the interface from route output
                        parts = line.split()
                        if len(parts) >= 4:
                            interface_ip = parts[3]  # Interface IP
                            
                            # Find corresponding Snort interface number
                            interfaces = psutil.net_if_addrs()
                            for i, (name, addresses) in enumerate(interfaces.items(), 1):
                                for addr in addresses:
                                    if (addr.family.name == 'AF_INET' and 
                                        addr.address == interface_ip):
                                        return str(i)
            
            return None
            
        except Exception as e:
            print(f"Error using Windows route command: {e}")
            return None

    def _get_primary_interface(self):
        """Get the primary interface by checking Snort's interface list"""
        try:
            import socket
            
            # Get our primary IP address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            print(f"Primary IP address: {local_ip}")
            
            # Get Snort's interface list to find the correct interface number
            snort_interface = self._get_snort_interface_by_ip(local_ip)
            if snort_interface:
                print(f"Found Snort interface {snort_interface} for IP {local_ip}")
                return snort_interface
            
            # Fallback to old method
            interfaces = psutil.net_if_addrs()
            for interface_name, addresses in interfaces.items():
                for addr in addresses:
                    if addr.family.name == 'AF_INET' and addr.address == local_ip:
                        return self._get_snort_interface_number(interface_name)
            
            return None
            
        except Exception as e:
            print(f"Error getting primary interface: {e}")
            return None

    def _get_active_interfaces(self):
        """Get list of active network interfaces with their Snort numbers"""
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            active_interfaces = []
            
            for interface_name, addresses in interfaces.items():
                # Skip loopback interfaces
                if 'loopback' in interface_name.lower() or 'lo' in interface_name.lower():
                    continue
                
                # Check if interface is up and has an IP address
                if interface_name in stats and stats[interface_name].isup:
                    for addr in addresses:
                        if (addr.family.name == 'AF_INET' and 
                            not addr.address.startswith('127.') and
                            not addr.address.startswith('169.254.')):  # Skip APIPA addresses
                            
                            snort_interface = self._get_snort_interface_number(interface_name)
                            active_interfaces.append(snort_interface)
                            print(f"Found active interface: {interface_name} -> Snort interface {snort_interface} (IP: {addr.address})")
                            break
            
            return active_interfaces
            
        except Exception as e:
            print(f"Error getting active interfaces: {e}")
            return []

    def _get_snort_interface_by_ip(self, target_ip):
        """Get Snort interface number by querying Snort directly for interface with specific IP"""
        try:
            result = subprocess.run(
                [self.snort_executable, "-W"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if target_ip in line and 'Index' not in line and '-----' not in line:
                        # Parse line format: "    4   94:BB:43:C1:AC:42       192.168.31.12   \Device\NPF_..."
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            interface_num = parts[0]
                            interface_ip = parts[2]
                            if interface_ip == target_ip:
                                print(f"Found interface {interface_num} with IP {interface_ip}")
                                return interface_num
            
            return None
            
        except Exception as e:
            print(f"Error querying Snort interfaces: {e}")
            return None

    def _get_snort_interface_number(self, interface_name):
        """Convert Windows interface name to Snort interface number"""
        try:
            # Get list of all interfaces
            interfaces = list(psutil.net_if_addrs().keys())
            
            # Find the index of our interface
            if interface_name in interfaces:
                # Snort interface numbers start at 1
                interface_index = interfaces.index(interface_name) + 1
                return str(interface_index)
            
            return "1"  # Default fallback
            
        except Exception as e:
            print(f"Error converting interface name: {e}")
            return "1"

    def list_all_interfaces(self):
        """List all available network interfaces for debugging"""
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            interface_list = []
            
            for i, (interface_name, addresses) in enumerate(interfaces.items(), 1):
                interface_info = {
                    "snort_number": str(i),
                    "name": interface_name,
                    "is_up": stats.get(interface_name, {}).isup if interface_name in stats else False,
                    "addresses": []
                }
                
                for addr in addresses:
                    if addr.family.name == 'AF_INET':
                        interface_info["addresses"].append({
                            "ip": addr.address,
                            "netmask": addr.netmask
                        })
                
                interface_list.append(interface_info)
            
            return interface_list
            
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            return []

    
    def is_admin(self):
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def ensure_log_directory(self):
        """Ensure log directory exists"""
        log_dir = os.path.dirname(self.log_file_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def test_snort_config(self):
        """Test Snort configuration before starting"""
        try:
            cmd = [
                self.snort_executable,
                "-T",  # Test configuration
                "-c", self.snort_config_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {"status": "success", "message": "Configuration test passed"}
            else:
                return {
                    "status": "error", 
                    "message": f"Configuration test failed: {result.stderr}",
                    "stdout": result.stdout
                }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Configuration test timed out"}
        except Exception as e:
            return {"status": "error", "message": f"Configuration test error: {str(e)}"}
    
    def start_snort(self, debug_mode=False):
        """Start Snort IDS process with optional terminal window for debugging"""
        if self.is_running:
            return {"status": "already_running", "message": "Snort is already running"}
        
        # Check administrator privileges
        if not self.is_admin():
            return {
                "status": "error", 
                "message": "Snort requires Administrator privileges for packet capture. Please run as Administrator."
            }
        
        try:
            # Ensure log directory exists
            self.ensure_log_directory()
            
            # Re-detect the correct interface
            correct_interface = self._get_primary_interface()
            if correct_interface:
                self.interface = correct_interface
                print(f"Using interface: {self.interface}")
            else:
                print(f"Warning: Could not detect interface, using default: {self.interface}")
            
            # Remove any existing log files
            if os.path.exists(self.log_file_path):
                os.remove(self.log_file_path)
            
            if debug_mode:
                # Debug mode - open terminal window
                return self._start_snort_with_terminal()
            else:
                # Regular mode - background process
                return self._start_snort_background()
                
        except Exception as e:
            return {"status": "error", "message": f"Failed to start Snort: {str(e)}"}

    def _start_snort_with_terminal(self):
        """Start Snort with a visible terminal window for debugging"""
        try:
            # Create a batch file to run Snort with proper parameters
            batch_file_path = r"C:\Snort\log\run_snort_debug.bat"
            
            # Snort command for debugging
            snort_cmd = f'''@echo off
    echo Starting Snort IDS in Debug Mode...
    echo Configuration: {self.snort_config_path}
    echo Interface: {self.interface}
    echo Log Directory: C:\\Snort\\log
    echo.
    cd /d "C:\\Snort\\bin"
    echo Running: snort -A fast -v -i {self.interface} -c "{self.snort_config_path}" -l "C:\\Snort\\log" -N
    echo.
    snort -A fast -v -i {self.interface} -c "{self.snort_config_path}" -l "C:\\Snort\\log" -N
    echo.
    echo Snort has stopped. Press any key to close this window...
    pause'''
            
            # Write the batch file
            with open(batch_file_path, 'w') as f:
                f.write(snort_cmd)
            
            print(f"Created debug batch file: {batch_file_path}")
            
            # Start the batch file in a new terminal window
            self.snort_process = subprocess.Popen(
                ['cmd', '/c', 'start', 'cmd', '/k', batch_file_path],
                shell=True,
                cwd=r"C:\Snort\bin"
            )
            
            # Wait a moment
            time.sleep(2)
            
            # Find the Snort process by name (since we started it via cmd)
            snort_pid = self._find_snort_process()
            
            self.is_running = True
            self.debug_mode = True
            
            # Start monitoring threads
            log_thread = threading.Thread(target=self.monitor_log_file, daemon=True)
            log_thread.start()
            
            monitor_thread = threading.Thread(target=self.monitor_snort_process, daemon=True)
            monitor_thread.start()
            
            return {
                "status": "started_debug", 
                "message": f"Snort started in DEBUG mode with terminal window on interface {self.interface}",
                "pid": snort_pid,
                "debug_mode": True,
                "batch_file": batch_file_path
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Failed to start Snort in debug mode: {str(e)}"}

    def _start_snort_background(self):
        """Start Snort in background mode (original method)"""
        try:
            cmd = [
                self.snort_executable,
                "-A", "fast",
                "-N",
                "-c", self.snort_config_path,
                "-i", self.interface,
                "-l", r"C:\Snort\log",
                "-k", "none",
                "-q"
            ]
            
            print(f"Starting Snort in background with command: {' '.join(cmd)}")
            
            original_dir = os.getcwd()
            os.chdir(r"C:\Snort\bin")
            
            try:
                self.snort_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                    cwd=r"C:\Snort\bin"
                )
            finally:
                os.chdir(original_dir)
            
            time.sleep(3)
            
            if self.snort_process.poll() is not None:
                stdout, stderr = self.snort_process.communicate()
                return {
                    "status": "error",
                    "message": f"Snort failed to start. Error: {stderr.decode() if stderr else 'Unknown error'}",
                    "stdout": stdout.decode() if stdout else "",
                    "stderr": stderr.decode() if stderr else ""
                }
            
            self.is_running = True
            self.debug_mode = False
            
            # Start monitoring threads
            log_thread = threading.Thread(target=self.monitor_log_file, daemon=True)
            log_thread.start()
            
            monitor_thread = threading.Thread(target=self.monitor_process, daemon=True)
            monitor_thread.start()
            
            return {
                "status": "started", 
                "message": f"Snort started in background mode on interface {self.interface}",
                "pid": self.snort_process.pid,
                "debug_mode": False
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Failed to start Snort: {str(e)}"}

    def _find_snort_process(self):
        """Find running Snort process PID"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'snort' in proc.info['name'].lower():
                    return proc.info['pid']
            return None
        except:
            return None

    def monitor_snort_process(self):
        """Monitor Snort process specifically for debug mode"""
        while self.is_running:
            try:
                # Look for snort.exe process
                snort_found = False
                for proc in psutil.process_iter(['pid', 'name']):
                    if 'snort' in proc.info['name'].lower():
                        snort_found = True
                        break
                
                if not snort_found:
                    print("Snort process no longer found")
                    self.is_running = False
                    break
                    
                time.sleep(5)
            except Exception as e:
                print(f"Error monitoring Snort process: {e}")
                break
    
    def monitor_process(self):
        """Monitor Snort process for unexpected termination"""
        while self.is_running and self.snort_process:
            try:
                # Check if process is still alive
                if self.snort_process.poll() is not None:
                    # Process has terminated
                    stdout, stderr = self.snort_process.communicate()
                    error_info = {
                        "timestamp": datetime.now().isoformat(),
                        "message": "Snort process terminated unexpectedly",
                        "stdout": stdout.decode() if stdout else "",
                        "stderr": stderr.decode() if stderr else "",
                        "return_code": self.snort_process.returncode
                    }
                    self.snort_errors.append(error_info)
                    self.is_running = False
                    break
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"Error monitoring process: {e}")
                break
    
    def stop_snort(self):
        """Stop Snort IDS process"""
        if not self.is_running or not self.snort_process:
            return {"status": "not_running", "message": "Snort is not running"}
        
        try:
            self.snort_process.terminate()
            self.snort_process.wait(timeout=10)
            self.is_running = False
            self.snort_process = None
            return {"status": "stopped", "message": "Snort stopped successfully"}
        except subprocess.TimeoutExpired:
            self.snort_process.kill()
            self.is_running = False
            self.snort_process = None
            return {"status": "killed", "message": "Snort force stopped"}
        except Exception as e:
            return {"status": "error", "message": f"Error stopping Snort: {str(e)}"}
    
    def get_status(self):
        """Get current Snort status with error information"""
        status_info = {
            "status": "stopped",
            "alerts_count": len(self.alerts),
            "errors": self.snort_errors[-5:] if self.snort_errors else []  # Last 5 errors
        }
        
        if self.is_running and self.snort_process:
            try:
                if self.snort_process.poll() is None:
                    status_info.update({
                        "status": "running",
                        "pid": self.snort_process.pid,
                        "interface": self.interface
                    })
                else:
                    self.is_running = False
                    self.snort_process = None
                    status_info["status"] = "stopped"
                    status_info["message"] = "Snort process terminated"
            except:
                self.is_running = False
                self.snort_process = None
                status_info["status"] = "error"
                status_info["message"] = "Error checking Snort status"
        
        return status_info
    
    def determine_nmap_severity(self, message, priority):
        """Determine severity based on message content and priority"""
        message_lower = message.lower()
        
        if any(keyword in message_lower for keyword in ['xmas', 'null', 'stealth', 'aggressive', 'os fingerprinting']):
            return "High"
        elif any(keyword in message_lower for keyword in ['syn scan', 'connect scan', 'version detection']):
            return "Medium"
        elif 'ping sweep' in message_lower or 'udp scan' in message_lower:
            return "Low"
        elif 'aggressive' in message_lower or 'rapid' in message_lower:
            return "Critical"
        
        if priority and priority.isdigit():
            priority_num = int(priority)
            if priority_num <= 1:
                return "Critical"
            elif priority_num <= 2:
                return "High"
            elif priority_num <= 3:
                return "Medium"
        
        return "Low"

    def is_nmap_related(self, message):
        """Check if the alert is related to Nmap scanning"""
        nmap_keywords = [
            'nmap', 'scan', 'sweep', 'probe', 'reconnaissance', 'recon',
            'syn scan', 'fin scan', 'xmas', 'null scan', 'ack scan',
            'ping sweep', 'port scan', 'stealth scan', 'connect scan',
            'version detection', 'os fingerprinting', 'udp scan'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in nmap_keywords)

    def identify_scan_type(self, message):
        """Identify the type of Nmap scan based on the message"""
        message_lower = message.lower()
        
        scan_types = {
            'syn': ['syn scan', 'syn probe'],
            'connect': ['connect scan', 'tcp connect'],
            'fin': ['fin scan'],
            'xmas': ['xmas', 'christmas'],
            'null': ['null scan'],
            'ack': ['ack scan'],
            'window': ['window scan'],
            'maimon': ['maimon scan'],
            'udp': ['udp scan'],
            'ping_sweep': ['ping sweep', 'icmp sweep'],
            'version': ['version detection', 'version scan'],
            'os_detection': ['os fingerprint', 'os detection'],
            'aggressive': ['aggressive scan'],
            'stealth': ['stealth scan']
        }
        
        for scan_type, keywords in scan_types.items():
            if any(keyword in message_lower for keyword in keywords):
                return scan_type
        
        return 'unknown'
    
    def parse_alert_line(self, line):
        """Parse Snort alert log line"""
        try:
            # Standard fast alert format
            pattern = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]\s+.*?\{([^}]+)\}\s+(\S+)\s*->\s*(\S+)'
            
            match = re.match(pattern, line.strip())
            if match:
                timestamp_str, gid_sid_rev, message, protocol, src, dst = match.groups()
                
                # Parse timestamp
                current_year = datetime.now().year
                timestamp = datetime.strptime(f"{current_year}/{timestamp_str}", "%Y/%m/%d-%H:%M:%S.%f")
                
                # Enhanced severity determination
                severity = self.determine_nmap_severity(message, None)
                is_nmap_scan = self.is_nmap_related(message)
                
                return {
                    "id": len(self.alerts) + 1,
                    "timestamp": timestamp.isoformat(),
                    "message": message.strip(),
                    "severity": severity,
                    "priority": "Unknown",
                    "classification": "attempted-recon",
                    "protocol": protocol,
                    "source": src,
                    "destination": dst,
                    "gid_sid_rev": gid_sid_rev,
                    "is_nmap_scan": is_nmap_scan,
                    "scan_type": self.identify_scan_type(message) if is_nmap_scan else None,
                    "raw_log": line.strip()
                }
        except Exception as e:
            print(f"Error parsing alert line: {e}")
            return None
    
    def monitor_log_file(self):
        """Enhanced log file monitoring with debugging"""
        print(f"Starting to monitor log file: {self.log_file_path}")
        
        # Create the log file if it doesn't exist
        if not os.path.exists(self.log_file_path):
            try:
                # Create empty file
                with open(self.log_file_path, 'w') as f:
                    f.write("")
                print(f"Created empty log file: {self.log_file_path}")
            except Exception as e:
                print(f"Error creating log file: {e}")
        
        # Check file permissions
        try:
            with open(self.log_file_path, 'a') as f:
                f.write("")  # Test write access
            print("Log file is writable")
        except Exception as e:
            print(f"Log file write test failed: {e}")
            return
        
        # Wait for log file to have content or timeout
        wait_count = 0
        while self.is_running and wait_count < 60:
            if os.path.exists(self.log_file_path) and os.path.getsize(self.log_file_path) > 0:
                print("Log file has content!")
                break
            print(f"Waiting for log content... {wait_count}/60")
            time.sleep(1)
            wait_count += 1
        
        if wait_count >= 60:
            print("WARNING: No alerts written to log file after 60 seconds")
        
        # Monitor the file
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Go to end if file already has content
                f.seek(0, 2)
                
                while self.is_running:
                    line = f.readline()
                    if line:
                        print(f"RAW ALERT LINE: {line.strip()}")
                        alert = self.parse_alert_line(line)
                        if alert:
                            self.alerts.append(alert)
                            if len(self.alerts) > self.max_alerts:
                                self.alerts = self.alerts[-self.max_alerts:]
                            print(f"PARSED ALERT: {alert['message']}")
                        else:
                            print("FAILED TO PARSE ALERT LINE")
                    else:
                        time.sleep(0.1)
        except Exception as e:
            print(f"Error monitoring log file: {e}")

    
    def get_alerts(self):
        """Get all alerts"""
        return self.alerts
    
    def clear_alerts(self):
        """Clear all stored alerts"""
        self.alerts = []
        self.snort_errors = []
        return {"status": "success", "message": "Alerts and errors cleared"}
    def debug_snort_traffic(self):
        """Debug method to check if Snort is seeing traffic"""
        try:
            # Run Snort in verbose mode to see traffic
            debug_cmd = [
                self.snort_executable,
                "-v",  # Verbose
                "-i", self.interface,
                "-c", self.snort_config_path
            ]
            
            print("Running Snort in debug mode...")
            print(f"Command: {' '.join(debug_cmd)}")
            
            # Run for 30 seconds then stop
            debug_process = subprocess.Popen(
                debug_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=r"C:\Snort\bin"
            )
            
            # Wait 30 seconds
            time.sleep(30)
            debug_process.terminate()
            
            stdout, stderr = debug_process.communicate()
            
            return {
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "message": "Debug run completed"
            }
            
        except Exception as e:
            return {"error": str(e)}
    def monitor_console_output(self):
        """Monitor Snort console output directly"""
        if not self.snort_process or not self.snort_process.stdout:
            return
        
        try:
            for line in iter(self.snort_process.stdout.readline, b''):
                if not self.is_running:
                    break
                
                line_str = line.decode('utf-8', errors='ignore').strip()
                print(f"CONSOLE OUTPUT: {line_str}")
                
                if '[**]' in line_str:  # This is an alert
                    alert = self.parse_alert_line(line_str)
                    if alert:
                        self.alerts.append(alert)
                        if len(self.alerts) > self.max_alerts:
                            self.alerts = self.alerts[-self.max_alerts:]
                        print(f"CAPTURED ALERT: {alert['message']}")
        except Exception as e:
            print(f"Error monitoring console output: {e}")


# Global Snort manager instance
snort_manager = SnortManager()

# API Routes
@app.route('/snort/admin/check', methods=['GET'])
def check_admin_status():
    """Check if running with administrator privileges"""
    is_admin = snort_manager.is_admin()
    return jsonify({
        "is_admin": is_admin,
        "message": "Running as Administrator" if is_admin else "Not running as Administrator - packet capture may fail"
    })

@app.route('/snort/start', methods=['POST'])
def start_snort():
    result = snort_manager.start_snort()
    return jsonify(result)

@app.route('/snort/stop', methods=['POST'])
def stop_snort():
    result = snort_manager.stop_snort()
    return jsonify(result)

@app.route('/snort/status', methods=['GET'])
def get_snort_status():
    result = snort_manager.get_status()
    return jsonify(result)

@app.route('/snort/alerts', methods=['GET'])
def get_snort_alerts():
    alerts = snort_manager.get_alerts()
    return jsonify(alerts)

@app.route('/snort/alerts/clear', methods=['DELETE'])
def clear_snort_alerts():
    result = snort_manager.clear_alerts()
    return jsonify(result)

@app.route('/snort/config/test', methods=['GET'])
def test_snort_config():
    result = snort_manager.test_snort_config()
    return jsonify(result)

@app.route('/snort/interfaces', methods=['GET'])
def list_network_interfaces():
    """List all available network interfaces"""
    interfaces = snort_manager.list_all_interfaces()
    return jsonify({
        "interfaces": interfaces,
        "selected_interface": snort_manager.interface,
        "primary_interface": snort_manager._get_primary_interface()
    })

@app.route('/snort/interface/set/<interface_id>', methods=['POST'])
def set_snort_interface(interface_id):
    """Set the Snort interface manually"""
    snort_manager.interface = interface_id
    return jsonify({
        "status": "success",
        "message": f"Interface set to {interface_id}",
        "interface": interface_id
    })

@app.route('/snort/debug', methods=['POST'])
def debug_snort():
    result = snort_manager.debug_snort_traffic()
    return jsonify(result)

#debug routes
@app.route('/snort/start/debug', methods=['POST'])
def start_snort_debug():
    """Start Snort in debug mode with terminal window"""
    result = snort_manager.start_snort(debug_mode=True)
    return jsonify(result)

@app.route('/snort/start/background', methods=['POST'])
def start_snort_background():
    """Start Snort in background mode (no terminal)"""
    result = snort_manager.start_snort(debug_mode=False)
    return jsonify(result)


if __name__ == '__main__':
    print("Starting Snort Backend Server...")
    print(f"Snort executable: {snort_manager.snort_executable}")
    print(f"Config file: {snort_manager.snort_config_path}")
    print(f"Log file: {snort_manager.log_file_path}")
    print(f"Interface: {snort_manager.interface}")
    
    app.run(host='127.0.0.1', port=5001, debug=True, threaded=True)
