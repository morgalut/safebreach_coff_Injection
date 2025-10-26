# COFF Process Injection Demo

An advanced demonstration of COFF (Common Object File Format) process injection techniques for educational and research purposes. This project showcases how COFF object files can be used for memory-only execution and process injection, bypassing traditional security controls.

## 🚨 Important Disclaimer

**This tool is for educational and authorized security research purposes only.**

- All actions are simulated and safe
- Intended for red team training, penetration testing, and security research
- Use only in controlled environments with proper authorization
- The authors are not responsible for misuse

## 📋 Features

- **COFF Object Creation**: Generate realistic COFF files with multiple sections (.text, .data, .rdata)
- **Memory Injection**: Simulate process hollowing and memory-only execution
- **Multiple Payload Types**: Demo, Meterpreter-like, and Cobalt Strike Beacon-like payloads
- **MITRE ATT&CK Mapping**: Demonstrates 8 distinct attack techniques
- **Defensive Evasion**: Shows techniques that bypass traditional AV and EDR
- **Comprehensive Analysis**: COFF structure analysis and validation

## 🛠 Prerequisites

### System Requirements
- Windows 10/11 or Windows Server 2016+
- Python 3.8 or higher
- Mingw-w64 compiler (for compiling C components)

### Python Dependencies
```bash
pip install -r requirements.txt
```

## ⚙️ Installation

1. **Clone the repository**
```bash
git clone https://github.com/morgalut/safebreach_coff_Injection.git
cd coff_injection_demo
```

2. **Compile C components**
```bash
cd coff_injection_demo/src
chmod +x compile_enhanced.sh
./compile_enhanced.sh
```

3. **Verify installation**
```bash
python -m main --list-targets
```

## 🎯 Usage Examples

### Basic Demonstration
```bash
# List available injection targets
python -m main --list-targets

# Run demo with default settings
python -m main --target notepad.exe --payload-type demo
```

### Advanced Usage
```bash
# Use different payload types
python -m main --target notepad.exe --payload-type meterpreter
python -m main --target notepad.exe --payload-type beacon

# Specify custom payload file
python -m main --target explorer.exe --payload custom_payload.obj

# List running processes
python -m main --list-processes

# Register custom application paths
python -m main --register-path loader_enhanced.exe C:\custom\path\loader_enhanced.exe --target notepad.exe
```

### Command Line Options
```
--target, -t          Target process name or PID for injection
--list-processes, -l  List running processes
--list-targets        List common injection targets
--payload, -p         Custom COFF payload file
--payload-type        Payload type: demo, meterpreter, beacon (default: demo)
--architecture        Target architecture: x86, x64 (default: x86)
--register-path       Register custom application path
--no-cleanup          Keep generated payload files
--skip-env-check      Skip environment verification
```

## 🔬 Technical Details

### COFF Structure
The demo creates COFF objects with three sections:
- **.text**: Executable code section
- **.data**: Initialized data section  
- **.rdata**: Read-only data section

### MITRE ATT&CK Techniques
- **T1055.002**: Process Injection: Portable Executable Injection
- **T1027**: Obfuscated Files or Information
- **T1620**: Reflective Code Loading
- **T1106**: Native API
- **T1497.001**: Virtualization/Sandbox Evasion
- **T1134**: Access Token Manipulation
- **T1057**: Process Discovery
- **T1564.003**: Hide Artifacts: Process Hollowing

### Security Controls Evaded
- Traditional File Scanning
- Signature-based Detection
- Static Analysis
- Disk-based Forensics
- Process Whitelisting

## 🏗 Project Structure

```
coff_injection_demo/
├── main.py                 # Main demo orchestrator
├── bin/                    # Compiled executables
├── src/                    # C source code
├── launcher/              # Application launcher module
├── payloads/              # Payload creation modules
├── analysis/              # COFF and process analysis
├── simulation/            # Injection simulation
├── ui/                    # Display and metrics
└── utils/                 # Utility functions
```

## 🛡 Defensive Considerations

This demo highlights the importance of monitoring for:
- Unusual process memory allocations (RWX)
- Remote thread creation in system processes
- Process behavior anomalies
- API calls like VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- EDR solutions with behavioral detection

## 🔍 Detection Tips

Security teams should look for:
- COFF object files in memory
- Uncommon image formats being executed
- Process hollowing patterns
- Anomalous section permissions in loaded images

## 📝 Notes

- The "Unknown opcode" messages are expected and indicate the safety measures
- Real x86 shellcode cannot execute in the Python demo environment
- In real scenarios, this would execute native machine code
- All safety measures prevent actual code execution in the demo

