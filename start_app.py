#!/usr/bin/env python3
"""
Secbot Application Launcher
Starts all required components: Flask app, Snort backend, and React frontend
Supports both Windows and Linux platforms
"""

import subprocess
import sys
import os
import platform
import time
import signal
import atexit
from pathlib import Path
import psutil

class AppLauncher:
    def __init__(self):
        self.processes = []
        self.system = platform.system()
        self.is_windows = self.system == 'Windows'
        self.is_linux = self.system == 'Linux'
        
        # Get the project root directory
        self.project_root = Path(__file__).parent.absolute()
        self.frontend_dir = self.project_root / "alert-frontend"
        self.venv_dir = self.project_root / "venv"
        
        # Set Python executable path (use venv if available)
        if self.is_windows:
            self.python_exe = self.venv_dir / "Scripts" / "python.exe"
        else:
            self.python_exe = self.venv_dir / "bin" / "python"
        
        # Fallback to system Python if venv doesn't exist
        if not self.python_exe.exists():
            self.python_exe = 'python' if self.is_windows else 'python3'
        else:
            self.python_exe = str(self.python_exe)
        
        # Register cleanup handler
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self.signal_handler)
        if not self.is_windows:
            signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C and other signals"""
        print("\n\n[SHUTDOWN] Shutting down all services...")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Terminate all child processes"""
        print("\n[CLEANUP] Cleaning up processes...")
        for process_info in self.processes:
            try:
                process = process_info['process']
                name = process_info['name']
                
                if process.poll() is None:  # Process is still running
                    print(f"  Stopping {name}...")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print(f"  Force killing {name}...")
                        process.kill()
            except Exception as e:
                print(f"  Error stopping {name}: {e}")
        
        self.processes.clear()
        print("[SUCCESS] All processes stopped")
    
    def check_privileges(self):
        """Check if running with required privileges"""
        try:
            if self.is_windows:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def find_process_by_port(self, port):
        """Find a process listening on a specific port"""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid)
                        return proc
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except (psutil.AccessDenied, Exception):
            pass
        return None
    
    def is_service_running(self, port):
        """Check if a service is running on a specific port"""
        return self.find_process_by_port(port) is not None
    
    def check_dependencies(self):
        """Check if all dependencies are available"""
        print("[CHECK] Checking dependencies...\n")
        
        issues = []
        
        # Check virtual environment
        if self.venv_dir.exists():
            print(f"  [OK] Found virtual environment at venv/")
            print(f"  [OK] Using Python: {self.python_exe}")
        else:
            print(f"  [WARNING] No virtual environment found at venv/")
            print(f"  [WARNING] Using system Python: {self.python_exe}")
            print(f"     Consider creating a venv: python -m venv venv")
        
        # Check Python files exist
        required_files = ['app.py', 'snort_backend.py']
        for file in required_files:
            file_path = self.project_root / file
            if not file_path.exists():
                issues.append(f"Missing required file: {file}")
            else:
                print(f"  [OK] Found {file}")
        
        # Check frontend directory
        if not self.frontend_dir.exists():
            issues.append(f"Missing frontend directory: {self.frontend_dir}")
        else:
            print(f"  [OK] Found alert-frontend/")
            
            # Check if node_modules exists
            node_modules = self.frontend_dir / "node_modules"
            if not node_modules.exists():
                print(f"  [WARNING] node_modules not found. Run 'npm install' in alert-frontend/")
                issues.append("Frontend dependencies not installed")
            else:
                print(f"  [OK] Frontend dependencies installed")
        
        # Check if npm is available
        try:
            npm_version = subprocess.run(['npm', '--version'], 
                                        capture_output=True, text=True, timeout=5, shell=True)
            if npm_version.returncode == 0:
                print(f"  [OK] npm v{npm_version.stdout.strip()}")
            else:
                issues.append("npm command failed")
        except Exception as e:
            issues.append(f"npm not found: {e}")
        
        # Check Python dependencies
        try:
            import flask
            import psutil
            import sqlalchemy
            print(f"  [OK] Python dependencies available")
        except ImportError as e:
            issues.append(f"Missing Python dependency: {e}")
        
        # Check privileges for Snort
        if not self.check_privileges():
            priv_name = "Administrator" if self.is_windows else "root"
            print(f"\n  [WARNING] Not running as {priv_name}")
            print(f"     Snort packet capture will fail without {priv_name} privileges")
            print(f"     {'Run as Administrator' if self.is_windows else 'Use sudo'} to enable packet capture\n")
        else:
            priv_name = "Administrator" if self.is_windows else "root"
            print(f"  [OK] Running with {priv_name} privileges")
        
        if issues:
            print(f"\n[ERROR] Found {len(issues)} issue(s):")
            for issue in issues:
                print(f"   - {issue}")
            return False
        
        print(f"\n[SUCCESS] All dependencies checked\n")
        return True
    
    def start_process(self, command, name, cwd=None, shell=False):
        """Start a subprocess and track it"""
        try:
            print(f"[START] Starting {name}...")
            
            if self.is_windows:
                # Windows: Start in new console window
                if isinstance(command, list):
                    cmd_str = ' '.join(command)
                else:
                    cmd_str = command
                
                process = subprocess.Popen(
                    ['cmd', '/c', 'start', 'cmd', '/k', cmd_str],
                    cwd=cwd or self.project_root,
                    shell=True
                )
            else:
                # Linux: Start in background
                process = subprocess.Popen(
                    command,
                    cwd=cwd or self.project_root,
                    shell=shell,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            self.processes.append({
                'process': process,
                'name': name,
                'command': command
            })
            
            print(f"   [OK] {name} started (PID: {process.pid})")
            return True
            
        except Exception as e:
            print(f"   [FAILED] Failed to start {name}: {e}")
            return False
    
    def start_flask_app(self):
        """Start the main Flask application"""
        command = [self.python_exe, 'app.py']
        return self.start_process(command, "Flask App (port 5000)")
    
    def start_snort_backend(self):
        """Start the Snort backend"""
        command = [self.python_exe, 'snort_backend.py']
        return self.start_process(command, "Snort Backend (port 5001)")
    
    def start_frontend(self):
        """Start the React frontend"""
        # Use npm run dev directly - cwd parameter handles directory change
        command = 'npm run dev' if self.is_windows else ['npm', 'run', 'dev']
        
        return self.start_process(
            command, 
            "React Frontend (port 3001)", 
            cwd=self.frontend_dir,
            shell=self.is_windows
        )
    
    def wait_for_startup(self):
        """Wait a moment for services to start"""
        print("\n[WAIT] Waiting for services to initialize...")
        for i in range(5, 0, -1):
            print(f"   {i}...", end='\r')
            time.sleep(1)
        print("   [READY] Startup complete!\n")
    
    def display_info(self):
        """Display information about running services"""
        print("=" * 70)
        print("Secbot is now running!")
        print("=" * 70)
        print("\nService URLs:")
        print("   * Main Application:  http://localhost:5000")
        print("   * Snort Backend:     http://localhost:5001")
        print("   * Frontend Dashboard: http://localhost:3001")
        print("\nLaunched Services:")
        print(f"   * Flask App (port 5000)")
        print(f"   * Snort Backend (port 5001)")
        print(f"   * React Frontend (port 3001)")
        print("\n   Note: Services are running in separate windows.")
        print("   Status will be monitored via port availability.")
        
        print("\nTips:")
        print("   * Access the dashboard at http://localhost:3001")
        print("   * Use Snort IDS tab to start network monitoring")
        print("   * Check logs in each terminal window for details")
        
        if not self.check_privileges():
            priv_name = "Administrator" if self.is_windows else "root"
            print(f"\n[WARNING] Not running as {priv_name}")
            print(f"   Snort will NOT be able to capture packets!")
            print(f"   {'Restart as Administrator' if self.is_windows else 'Run with sudo'} to enable IDS")
        
        print("\nPress Ctrl+C to stop all services")
        print("=" * 70)
    
    def monitor_processes(self):
        """Monitor running processes by checking service ports"""
        print("\n[MONITOR] Monitoring services...\n")
        print("Services are running. Press Ctrl+C to stop all services.\n")
        
        # Service ports to monitor
        services = [
            {'name': 'Flask App', 'port': 5000},
            {'name': 'Snort Backend', 'port': 5001},
            {'name': 'React Frontend', 'port': 3001}
        ]
        
        # Give services time to start
        time.sleep(3)
        
        try:
            while True:
                # Check each service
                status_changed = False
                for service in services:
                    is_running = self.is_service_running(service['port'])
                    
                    # Track status changes
                    if 'was_running' not in service:
                        service['was_running'] = is_running
                        if is_running:
                            print(f"[OK] {service['name']} detected on port {service['port']}")
                    elif service['was_running'] != is_running:
                        status_changed = True
                        service['was_running'] = is_running
                        if is_running:
                            print(f"[OK] {service['name']} started on port {service['port']}")
                        else:
                            print(f"[WARNING] {service['name']} stopped (port {service['port']} not listening)")
                
                if status_changed:
                    print()
                
                time.sleep(5)  # Check every 5 seconds
                
        except KeyboardInterrupt:
            print("\n\n[INTERRUPT] Received interrupt signal...")
        finally:
            self.cleanup()
    
    def run(self):
        """Main entry point"""
        print("\n" + "=" * 70)
        print("Secbot Application Launcher")
        print("=" * 70)
        print(f"Platform: {self.system}")
        print(f"Project: {self.project_root}")
        print()
        
        # Check dependencies
        if not self.check_dependencies():
            print("\n[ERROR] Dependency check failed. Please resolve issues and try again.")
            return 1
        
        # Start services
        print("[LAUNCH] Starting all services...\n")
        
        success = True
        success &= self.start_flask_app()
        time.sleep(2)  # Small delay between starts
        
        success &= self.start_snort_backend()
        time.sleep(2)
        
        success &= self.start_frontend()
        
        if not success:
            print("\n[ERROR] Failed to start one or more services")
            self.cleanup()
            return 1
        
        # Wait for startup
        self.wait_for_startup()
        
        # Display info
        self.display_info()
        
        # Monitor processes
        self.monitor_processes()
        
        return 0

def main():
    """Main function"""
    launcher = AppLauncher()
    return launcher.run()

if __name__ == "__main__":
    sys.exit(main())
