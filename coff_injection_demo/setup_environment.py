# setup_environment.py

import os
import sys
from pathlib import Path

def check_required_files():
    """Check if all required executables are available"""
    project_root = Path(__file__).parent
    required_files = [
        "bin/loader_enhanced.exe",
        "bin/coff_parser_enhanced.exe", 
        "bin/coff_loader_dll.dll"
    ]
    
    missing_files = []
    available_files = []
    
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            available_files.append(file_path)
        else:
            missing_files.append(file_path)
    
    return available_files, missing_files

def setup_environment():
    """Setup the environment for the demo"""
    project_root = Path(__file__).parent
    
    # Add bin directory to PATH temporarily
    bin_path = str(project_root / "bin")
    if bin_path not in os.environ['PATH']:
        os.environ['PATH'] = bin_path + os.pathsep + os.environ['PATH']
    
    # Check for required files
    available, missing = check_required_files()
    
    print("Environment Setup:")
    print("=" * 50)
    print("Available executables:")
    for file in available:
        print(f"  ✓ {file}")
    
    if missing:
        print("\nMissing executables:")
        for file in missing:
            print(f"  ✗ {file}")
        
        print("\nTo fix this:")
        print("1. Compile the C source files using compile_enhanced.sh")
        print("2. Place the compiled executables in the bin/ directory")
        print("3. Or register custom paths using --register-path")
        
        src_dir = project_root / "src"
        if src_dir.exists():
            print(f"\nSource files are available in: {src_dir}")
            print("Run the compile script from that directory.")
        
        return False
    
    return True

if __name__ == "__main__":
    setup_environment()