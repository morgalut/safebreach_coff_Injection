# payload_creator.py

import time
import struct
from pathlib import Path
from .shellcode_generator import ShellcodeGenerator


class PayloadCreator:
    def __init__(self):
        self.shellcode_generator = ShellcodeGenerator()
    
    def create_realistic_coff_payload(self, payload_type="demo", architecture="x86"):
        """
        Create a realistic COFF object file with proper sections.
        Automatically uses real_injection=True for 'message_box' payloads.
        """
        payload_path = f"coff_payload_{payload_type}.obj"

        # --- Select the correct shellcode type ---
        if payload_type == "message_box":
            # Use real Windows shellcode (shows a MessageBox)
            shellcode = self.shellcode_generator.create_shellcode_payload(
                payload_type="message_box", real_injection=True
            )
        else:
            # Use simulated payloads for safe testing (demo/meterpreter/beacon)
            shellcode = self.shellcode_generator.create_shellcode_payload(
                payload_type=payload_type, real_injection=False
            )

        # --- Build COFF File Header ---
        coff_data = b""
        if architecture == "x86":
            machine = 0x014C  # IMAGE_FILE_MACHINE_I386
        else:
            machine = 0x8664  # IMAGE_FILE_MACHINE_AMD64
        
        number_of_sections = 3  # .text, .data, .rdata
        time_date_stamp = int(time.time())
        pointer_to_symbol_table = 0
        number_of_symbols = 0
        size_of_optional_header = 0
        characteristics = 0x0100 | 0x0002  # 32BIT_MACHINE + EXECUTABLE_IMAGE
        
        coff_data += struct.pack(
            '<HHIIIHH', 
            machine, number_of_sections, time_date_stamp,
            pointer_to_symbol_table, number_of_symbols,
            size_of_optional_header, characteristics
        )

        # --- Calculate section offsets ---
        text_raw_data_offset = 20 + (40 * number_of_sections)  # after headers
        data_raw_data_offset = text_raw_data_offset + len(shellcode)
        rdata_raw_data_offset = data_raw_data_offset + 64  # .data section size

        # --- .text section (executable code) ---
        coff_data += b".text\0\0\0"
        coff_data += struct.pack(
            '<IIIIIIHHI',
            len(shellcode),        # Virtual size
            0x1000,               # Virtual address
            len(shellcode),        # Size of raw data
            text_raw_data_offset,  # Pointer to raw data
            0,                    # Pointer to relocations
            0,                    # Pointer to line numbers
            0,                    # Number of relocations
            0,                    # Number of line numbers
            0x60000020            # CODE|EXECUTE|READ
        )

        # --- .data section (initialized data) ---
        data_section = b"INITIALIZED_DATA" + b"\x00" * 48
        coff_data += b".data\0\0\0"
        coff_data += struct.pack(
            '<IIIIIIHHI',
            len(data_section),
            0x2000,
            len(data_section),
            data_raw_data_offset,
            0, 0, 0, 0,
            0xC0000040            # INITIALIZED_DATA|READ|WRITE
        )

        # --- .rdata section (read-only data) ---
        rdata_section = b"ReadOnlyData\x00" + b"API_NAMES\x00" * 4
        coff_data += b".rdata\0\0"
        coff_data += struct.pack(
            '<IIIIIIHHI',
            len(rdata_section),
            0x3000,
            len(rdata_section),
            rdata_raw_data_offset,
            0, 0, 0, 0,
            0x40000040            # INITIALIZED_DATA|READ
        )

        # --- Append actual section data ---
        coff_data += shellcode
        coff_data += data_section
        coff_data += rdata_section

        # --- Write final COFF file ---
        with open(payload_path, "wb") as f:
            f.write(coff_data)

        print(f"[+] Created COFF payload: {payload_path}")
        print(f"    -> Type: {payload_type}")
        print(f"    -> Architecture: {architecture}")
        print(f"    -> Shellcode size: {len(shellcode)} bytes")
        if payload_type == "message_box":
            print("    -> [INFO] Using real Windows MessageBox shellcode (safe demo)")
        else:
            print("    -> [INFO] Using simulated payload")

        return payload_path
