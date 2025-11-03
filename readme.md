## Compilation Instructions

### For C Implementation:

1. **Using Visual Studio Developer Command Prompt:**
 After installation, **open the Developer Command Prompt**:

   * Click *Start → Visual Studio 2022 → x64 Native Tools Command Prompt for VS 2022*.
   * This sets the PATH automatically for `cl.exe`.

 Verify it works:

   ```sh
   where cl
   cl /?
   ```

   You should now see:

```sh
   C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<version>\bin\Hostx64\x64\cl.exe
```

   and compiler help output.

 Finally:

```sh

   cd C:\Users\user\Desktop\safebreach_coff_ijc\coff_parser
compile_fixed.bat
  ```

   


### For Python Implementation:

1. **No compilation needed:**
 ```sh
   python coff_parser.py shellcode.obj 12736
 ```
## 🎯 **USAGE INSTRUCTIONS**

### **1. Build Everything:**
```sh
compile_fixed.bat
```

### **2. Run Test Target:**
```sh
test_target.exe
```
**Note the PID shown!**

### **3. Perform Injection:**
```sh
# Using C version
coff_parser_enhanced.exe minimal_shellcode.obj 12736

# Using Python version  
python coff_parser_enhanced.py minimal_shellcode.obj 12736
```

### **4. Expected Output:**
```
=== COFF Parser Enhanced - MITRE ATT&CK T1055 ===
Target PID: 1234

[1/3] Parsing COFF file: minimal_shellcode.obj
COFF Header Info:
  Machine: 0x014C (x86)
  Sections: 4
  Characteristics: 0x0000

[2/3] Extracting shellcode from .text section
Found .text section: 8 bytes

[3/3] Attempting process injection
[1/4] Opening process PID: 1234... SUCCESS
[2/4] Allocating memory (8 bytes)... SUCCESS at 0x00A40000
[3/4] Writing shellcode... SUCCESS (8/8 bytes)
[4/4] Creating remote thread... SUCCESS (Thread ID: 5678)
Waiting for thread completion... Thread exited with code: 0x00000000

✅ SUCCESS: Process injection completed!
MITRE ATT&CK T1055 demonstrated successfully!
```
