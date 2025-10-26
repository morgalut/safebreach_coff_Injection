# process_analyzer.py

import os
from ui.display import Display

class ProcessAnalyzer:
    def __init__(self):
        self.display = Display()
    
    def get_running_processes(self):
        """Get list of running processes (Windows)"""
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    processes.append((proc.info['pid'], proc.info['name'], proc.info['exe']))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            return sorted(processes, key=lambda x: x[1].lower())
        except ImportError:
            # Fallback without psutil
            print("Note: Install 'psutil' for better process listing: pip install psutil")
            return []

    def list_common_targets(self):
        """List common injection targets with descriptions"""
        common_targets = [
            ("notepad.exe", "Windows Notepad - Common benign target"),
            ("calc.exe", "Windows Calculator - Safe testing target"), 
            ("explorer.exe", "Windows Explorer - High impact, visible"),
            ("svchost.exe", "Service Host - Multiple instances"),
            ("winlogon.exe", "Windows Logon - System process"),
            ("csrss.exe", "Client Server Runtime - Critical system"),
            ("services.exe", "Services Controller - Manages services"),
            ("lsass.exe", "Local Security Authority - Sensitive credentials")
        ]
        return common_targets

    def list_running_processes(self):
        """Display running processes"""
        self.display.print_banner("RUNNING PROCESSES")
        processes = self.get_running_processes()
        for pid, name, exe in processes[:20]:  # Show first 20
            exe_display = exe if exe else "N/A"
            print(f"  PID {pid:6} : {name:20} - {exe_display}")
        if len(processes) > 20:
            print(f"  ... and {len(processes) - 20} more processes")

    def list_common_targets(self):
        """Display common injection targets"""
        self.display.print_banner("COMMON INJECTION TARGETS")
        targets = [
            ("notepad.exe", "Windows Notepad - Common benign target"),
            ("calc.exe", "Windows Calculator - Safe testing target"), 
            ("explorer.exe", "Windows Explorer - High impact, visible"),
            ("svchost.exe", "Service Host - Multiple instances"),
            ("winlogon.exe", "Windows Logon - System process"),
            ("csrss.exe", "Client Server Runtime - Critical system"),
            ("services.exe", "Services Controller - Manages services"),
            ("lsass.exe", "Local Security Authority - Sensitive credentials")
        ]
        for name, desc in targets:
            print(f"  {name:20} - {desc}")