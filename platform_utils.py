#!/usr/bin/env python3
"""
Platform Utilities for Secbot
Provides platform-independent paths and configurations for Windows and Linux
"""

import platform
import os

class PlatformConfig:
    """Platform-specific configuration"""
    
    def __init__(self):
        self.system = platform.system()
        self.is_windows = self.system == 'Windows'
        self.is_linux = self.system == 'Linux'
        
        # Configure paths based on platform
        if self.is_windows:
            self._setup_windows_paths()
        else:
            self._setup_linux_paths()
    
    def _setup_windows_paths(self):
        """Configure Windows-specific paths"""
        self.snort_executable = r"C:\Snort\bin\snort.exe"
        self.snort_config = r"C:\Snort\etc\snort_production.conf"
        self.snort_log_dir = r"C:\Snort\log"
        self.snort_rules_dir = r"C:\Snort\rules"
        self.snort_bin_dir = r"C:\Snort\bin"
        self.alert_log_file = r"C:\Snort\log\alert.ids"
        
        # Admin/privilege info
        self.priv_name = "Administrator"
        self.priv_command_prefix = []  # No prefix needed on Windows
        
    def _setup_linux_paths(self):
        """Configure Linux-specific paths"""
        self.snort_executable = "/usr/sbin/snort"
        self.snort_config = "/etc/snort/snort.conf"
        self.snort_log_dir = "/var/log/snort"
        self.snort_rules_dir = "/etc/snort/rules"
        self.snort_bin_dir = "/usr/sbin"
        self.alert_log_file = "/var/log/snort/alert.ids"
        
        # Admin/privilege info
        self.priv_name = "root"
        self.priv_command_prefix = ['sudo']  # May need sudo
    
    def get_interface_format(self):
        """Return expected interface format (number for Windows, name for Linux)"""
        if self.is_windows:
            return "numeric"  # e.g., "1", "2", "3"
        else:
            return "name"  # e.g., "eth0", "ens33", "wlan0"
    
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
    
    def get_privilege_message(self):
        """Get message about required privileges"""
        if self.check_privileges():
            return f"Running with {self.priv_name} privileges"
        else:
            return f"Not running as {self.priv_name}. Packet capture may fail."
    
    def format_path(self, *parts):
        """Create a platform-appropriate path from components"""
        return os.path.join(*parts)
    
    def get_terminal_command(self, command_list):
        """
        Get platform-appropriate terminal command
        On Windows: opens cmd window
        On Linux: opens gnome-terminal/xterm/konsole
        """
        if self.is_windows:
            # Windows: use cmd with start
            batch_content = "\n".join([
                "@echo off",
                "echo Starting application...",
                " ".join(command_list),
                "echo.",
                "echo Application stopped. Press any key to close...",
                "pause"
            ])
            return ['cmd', '/c', 'start', 'cmd', '/k'], batch_content
        else:
            # Linux: try different terminal emulators
            terminals = [
                (['gnome-terminal', '--'], 'gnome-terminal'),
                (['xterm', '-hold', '-e'], 'xterm'),
                (['konsole', '--hold', '-e'], 'konsole'),
            ]
            
            for term_cmd, term_name in terminals:
                term_path = term_cmd[0]
                if os.path.exists(f"/usr/bin/{term_path}"):
                    return term_cmd, None
            
            # No terminal found, return None
            return None, None
    
    def __repr__(self):
        return f"PlatformConfig(system={self.system}, snort_exe={self.snort_executable})"

# Global instance
platform_config = PlatformConfig()

# Convenience functions
def is_windows():
    """Check if running on Windows"""
    return platform_config.is_windows

def is_linux():
    """Check if running on Linux"""
    return platform_config.is_linux

def get_snort_paths():
    """Get all Snort-related paths for current platform"""
    return {
        'executable': platform_config.snort_executable,
        'config': platform_config.snort_config,
        'log_dir': platform_config.snort_log_dir,
        'rules_dir': platform_config.snort_rules_dir,
        'bin_dir': platform_config.snort_bin_dir,
        'alert_log': platform_config.alert_log_file
    }

def requires_sudo():
    """Check if current operation requires sudo (Linux) or Run as Admin (Windows)"""
    return not platform_config.check_privileges()

def get_priv_command(command_list):
    """Prepend sudo if on Linux and not root"""
    if platform_config.is_linux and not platform_config.check_privileges():
        return ['sudo'] + command_list
    return command_list

if __name__ == "__main__":
    # Test the platform configuration
    print("Platform Configuration Test")
    print("=" * 50)
    print(f"Operating System: {platform_config.system}")
    print(f"Is Windows: {platform_config.is_windows}")
    print(f"Is Linux: {platform_config.is_linux}")
    print(f"\nSnort Paths:")
    for key, value in get_snort_paths().items():
        print(f"  {key:15}: {value}")
    print(f"\nPrivileges:")
    print(f"  Required: {platform_config.priv_name}")
    print(f"  Status: {platform_config.get_privilege_message()}")
    print(f"  Interface Format: {platform_config.get_interface_format()}")
