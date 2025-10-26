# coff_analyzer.py

import struct

class COFFAnalyzer:
    def validate_coff_file(self, file_path):
        """Validate COFF file structure and return detailed results"""
        results = {
            "valid": False,
            "sections": [],
            "issues": [],
            "file_size": 0
        }
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            results["file_size"] = len(data)
            
            # Validate COFF header
            if len(data) < 20:
                results["issues"].append("File too small for COFF header")
                return results
                
            machine, num_sections, timestamp, sym_table, num_symbols, opt_size, chars = \
                struct.unpack('<HHIIIHH', data[:20])
            
            # Validate section count
            if num_sections != 3:
                results["issues"].append(f"Expected 3 sections, got {num_sections}")
            
            # Validate each section
            offset = 20
            for i in range(num_sections):
                if offset + 40 > len(data):
                    results["issues"].append(f"Section {i} header out of bounds")
                    break
                    
                section_data = data[offset:offset+40]
                name = section_data[:8].rstrip(b'\x00')
                
                try:
                    section_fields = struct.unpack('<IIIIIIHHI', section_data[8:40])
                    virt_size, virt_addr, raw_size, raw_ptr, relocs, lines, num_relocs, num_lines, section_chars = section_fields
                    
                    results["sections"].append({
                        "name": name.decode('ascii', errors='ignore'),
                        "virtual_size": virt_size,
                        "raw_size": raw_size,
                        "characteristics": hex(section_chars)
                    })
                    
                except struct.error as e:
                    results["issues"].append(f"Section {i} header corrupt: {e}")
                
                offset += 40
            
            results["valid"] = len(results["issues"]) == 0
            
        except Exception as e:
            results["issues"].append(f"Validation error: {e}")
        
        return results

    def analyze_coff_structure(self, payload_path):
        """Analyze and display COFF structure details"""
        try:
            with open(payload_path, "rb") as f:
                data = f.read()
            
            print("\n[COFF STRUCTURE ANALYSIS]")
            print("-" * 40)
            
            # Parse COFF header
            if len(data) >= 20:
                machine, num_sections, timestamp, sym_table, num_symbols, opt_size, chars = \
                    struct.unpack('<HHIIIHH', data[:20])
                
                print(f"Machine:           0x{machine:04X}")
                print(f"Sections:          {num_sections}")
                print(f"Timestamp:         {timestamp} (0x{timestamp:08X})")
                print(f"Symbols:           {num_symbols}")
                print(f"Optional Header:   {opt_size} bytes")
                print(f"Characteristics:   0x{chars:04X}")
                
                # Parse section headers
                offset = 20
                for i in range(num_sections):
                    if offset + 40 <= len(data):
                        section_data = data[offset:offset+40]
                        name = section_data[:8].rstrip(b'\x00')
                        
                        # Correct section header unpacking (9 fields)
                        section_fields = struct.unpack('<IIIIIIHHI', section_data[8:40])
                        virt_size, virt_addr, raw_size, raw_ptr, relocs, lines, num_relocs, num_lines, section_chars = section_fields
                        
                        print(f"\nSection {i+1}: {name.decode('ascii', errors='ignore')}")
                        print(f"  Virtual Size:    {virt_size} bytes")
                        print(f"  Virtual Address: 0x{virt_addr:08X}")
                        print(f"  Raw Data Size:   {raw_size} bytes")
                        print(f"  Raw Data Ptr:    0x{raw_ptr:08X}")
                        print(f"  Characteristics: 0x{section_chars:08X}")
                        
                        offset += 40
                        
                # Show section data sizes
                print(f"\nTotal COFF file size: {len(data)} bytes")
                
        except Exception as e:
            print(f"COFF analysis error: {e}")
            import traceback
            traceback.print_exc()