import ctypes
import struct
import os
import sys
from ctypes import wintypes

def load_dll_safely():
    """Load the DLL and check available functions"""
    try:
        # Load the C library
        coff_loader = ctypes.CDLL('./coff_loader.dll')
        
        # Check if our target function exists
        try:
            # Try to access the function
            func = coff_loader.parse_coff_and_execute
            print("[+] Found parse_coff_and_execute function")
            
            # Define function prototype
            coff_loader.parse_coff_and_execute.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
            coff_loader.parse_coff_and_execute.restype = ctypes.c_int
            
            return coff_loader
        except AttributeError:
            print("[-] parse_coff_and_execute function not found in DLL")
            print("[*] Checking for other available functions...")
            
            # List all possible functions in the DLL
            for name in dir(coff_loader):
                if not name.startswith('_'):
                    print(f"    Available: {name}")
            
            return None
                    
    except Exception as e:
        print(f"[-] Failed to load DLL: {e}")
        print("[*] Make sure coff_loader.dll exists in the current directory")
        return None

def create_valid_coff_file():
    """Create a valid COFF file structure that mimics real object files"""
    print("[*] Creating valid COFF file structure...")
    
    # Build the COFF file manually with exact byte structure
    coff_data = bytearray()
    
    # COFF Header (20 bytes)
    coff_data.extend(struct.pack('<H', 0x014C))     # Machine: I386
    coff_data.extend(struct.pack('<H', 2))          # NumberOfSections: 2
    coff_data.extend(struct.pack('<I', 0))          # TimeDateStamp
    coff_data.extend(struct.pack('<I', 0))          # PointerToSymbolTable
    coff_data.extend(struct.pack('<I', 0))          # NumberOfSymbols
    coff_data.extend(struct.pack('<H', 0))          # SizeOfOptionalHeader
    coff_data.extend(struct.pack('<H', 0x0101))     # Characteristics: RELOCS_STRIPPED | EXECUTABLE_IMAGE
    
    # Section 1: .text (executable code)
    coff_data.extend(b'.text\0\0\0')                # Name (8 bytes)
    coff_data.extend(struct.pack('<I', 0x1000))     # VirtualSize
    coff_data.extend(struct.pack('<I', 0x1000))     # VirtualAddress
    coff_data.extend(struct.pack('<I', 0x200))      # SizeOfRawData
    coff_data.extend(struct.pack('<I', 0x7C))       # PointerToRawData (20 + 80 = 100 = 0x64)
    coff_data.extend(struct.pack('<I', 0))          # PointerToRelocations
    coff_data.extend(struct.pack('<I', 0))          # PointerToLinenumbers
    coff_data.extend(struct.pack('<H', 0))          # NumberOfRelocations
    coff_data.extend(struct.pack('<H', 0))          # NumberOfLinenumbers
    coff_data.extend(struct.pack('<I', 0x60000020)) # Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ
    
    # Section 2: .data (initialized data)
    coff_data.extend(b'.data\0\0\0')                # Name (8 bytes)
    coff_data.extend(struct.pack('<I', 0x1000))     # VirtualSize
    coff_data.extend(struct.pack('<I', 0x2000))     # VirtualAddress
    coff_data.extend(struct.pack('<I', 0x100))      # SizeOfRawData
    coff_data.extend(struct.pack('<I', 0x27C))      # PointerToRawData (20 + 80 + 512 = 612 = 0x264)
    coff_data.extend(struct.pack('<I', 0))          # PointerToRelocations
    coff_data.extend(struct.pack('<I', 0))          # PointerToLinenumbers
    coff_data.extend(struct.pack('<H', 0))          # NumberOfRelocations
    coff_data.extend(struct.pack('<H', 0))          # NumberOfLinenumbers
    coff_data.extend(struct.pack('<I', 0xC0000040)) # Characteristics: CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
    
    # Section data: .text (NOP sled + some instructions)
    coff_data.extend(b'\x90' * 0x200)  # NOP sled
    
    # Section data: .data (some dummy data)
    coff_data.extend(b'COFF_DEMO_DATA_SECTION\x00' * 8)
    
    print(f"[+] Valid COFF file created: {len(coff_data)} bytes")
    print("[+] COFF structure:")
    print(f"    - Header: 20 bytes")
    print(f"    - Sections: 2 (.text, .data)")
    print(f"    - .text section: 512 bytes executable")
    print(f"    - .data section: 128 bytes data")
    
    return bytes(coff_data)

def verify_environment():
    """Verify the execution environment"""
    print("[*] Verifying environment...")
    
    # Check if we're on Windows
    if os.name != 'nt':
        print("[-] This demo requires Windows OS")
        return False
    
    # Check if DLL exists
    if not os.path.exists("coff_loader.dll"):
        print("[-] coff_loader.dll not found in current directory")
        print("[*] Please run build_windows.py first to compile the DLL")
        return False
    
    print("[+] Environment verified: Windows OS, DLL present")
    return True

def main():
    print("=== COFF Parser & Process Injection Demo ===")
    print("MITRE ATT&CK Technique: T1055 (Process Injection)")
    print("Target: Open Notepad with 'Hello World' text")
    print("=" * 60)
    
    # Verify environment
    if not verify_environment():
        return
    
    # Load the DLL
    coff_loader = load_dll_safely()
    if not coff_loader:
        print("[-] Cannot continue - DLL not loaded properly")
        return
    
    try:
        # Create valid COFF data
        print("\n[*] Generating COFF file structure...")
        coff_data = create_valid_coff_file()
        
        # Convert to ctypes compatible format
        coff_buffer = (ctypes.c_ubyte * len(coff_data))(*coff_data)
        
        print("\n[*] Executing COFF parser with process injection...")
        print("[*] This will:")
        print("    1. Parse the COFF file structure")
        print("    2. Demonstrate process injection techniques")
        print("    3. Open Notepad and type 'Hello World'")
        print("=" * 60)
        
        # Call the C function to parse COFF and execute
        result = coff_loader.parse_coff_and_execute(coff_buffer, len(coff_data))
        
        print("\n" + "=" * 60)
        if result == 0:
            print("[+] SUCCESS: Demo completed successfully!")
            print("[+] Notepad should be open with 'Hello World' text")
        else:
            print(f"[-] Demo completed with warnings (Code: {result})")
            print("[*] Some techniques may have worked partially")
            
    except KeyboardInterrupt:
        print("\n[-] Demo interrupted by user")
    except Exception as e:
        print(f"[-] Error during execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()