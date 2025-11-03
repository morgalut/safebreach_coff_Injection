import subprocess
import sys
import os
import platform
import tempfile
import shutil

def find_msvc_compiler():
    """Find MSVC compiler on Windows system"""
    print("[*] Searching for MSVC compiler...")
    
    # Common Visual Studio installation paths
    vs_paths = [
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build",
    ]
    
    for vs_path in vs_paths:
        vcvars64 = os.path.join(vs_path, "vcvars64.bat")
        if os.path.exists(vcvars64):
            print(f"[+] Found MSVC at: {vs_path}")
            return vcvars64
    
    # Try using vswhere to find Visual Studio
    try:
        vswhere_path = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
        if os.path.exists(vswhere_path):
            result = subprocess.run([
                vswhere_path, 
                "-latest", 
                "-property", "installationPath"
            ], capture_output=True, text=True, check=True)
            
            if result.returncode == 0:
                install_path = result.stdout.strip()
                vcvars64 = os.path.join(install_path, "VC\\Auxiliary\\Build\\vcvars64.bat")
                if os.path.exists(vcvars64):
                    print(f"[+] Found MSVC via vswhere: {install_path}")
                    return vcvars64
    except:
        pass
    
    # Check for standalone compiler
    standalone_paths = [
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
    ]
    
    for standalone_path in standalone_paths:
        if os.path.exists(standalone_path):
            # Find the latest version
            versions = []
            for item in os.listdir(standalone_path):
                if os.path.isdir(os.path.join(standalone_path, item)):
                    try:
                        versions.append(item)
                    except:
                        pass
            
            if versions:
                latest_version = sorted(versions)[-1]
                bin_path = os.path.join(standalone_path, latest_version, "bin", "Hostx64", "x64")
                if os.path.exists(bin_path):
                    print(f"[+] Found standalone MSVC: {bin_path}")
                    # We'll use the system cl.exe if available
                    if shutil.which("cl.exe"):
                        return "system"
    
    print("[-] MSVC compiler not found automatically")
    print("[*] Checking if cl.exe is in PATH...")
    
    # Check if cl.exe is already in PATH
    if shutil.which("cl.exe"):
        print("[+] Found cl.exe in PATH")
        return "system"
    
    print("[-] Please install Visual Studio Build Tools with C++ support")
    return None

def compile_coff_loader(vcvars_path):
    """Compile the actual coff_loader.c file"""
    print("\n[*] Compiling coff_loader.c...")
    
    # Check if source file exists
    if not os.path.exists("coff_loader.c"):
        print("[-] coff_loader.c not found!")
        return False
    
    compile_cmd = []
    
    if vcvars_path == "system":
        # Use cl.exe directly from PATH
        compile_cmd = [
            "cl", "/nologo", "/D_WINDOWS", "/D_USRDLL", "/DCOFF_LOADER_EXPORTS", 
            "/LD", "coff_loader.c", "/link", "/OUT:coff_loader.dll", 
            "kernel32.lib", "user32.lib", "shell32.lib"
        ]
    else:
        # Create batch file to set up environment and compile
        batch_content = f'''@echo off
call "{vcvars_path}"
cl /nologo /D_WINDOWS /D_USRDLL /DCOFF_LOADER_EXPORTS /LD coff_loader.c /link /OUT:coff_loader.dll kernel32.lib user32.lib shell32.lib
echo COMPILE_RESULT: %errorlevel%
'''
        
        # Write batch file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False, encoding='utf-8') as bat_file:
            bat_file.write(batch_content)
            bat_file_path = bat_file.name
        
        compile_cmd = [bat_file_path]
    
    try:
        # Run the compilation
        print("[*] Running compilation command...")
        result = subprocess.run(
            compile_cmd, 
            capture_output=True, 
            text=True, 
            shell=True,
            cwd=os.getcwd()
        )
        
        # Print compilation output
        if result.stdout:
            print("[*] Compilation output:")
            for line in result.stdout.split('\n'):
                if line.strip():
                    print(f"    {line}")
        
        if result.stderr:
            print("[*] Compilation warnings/errors:")
            for line in result.stderr.split('\n'):
                if line.strip() and not line.startswith('   Creating library'):
                    print(f"    {line}")
        
        # Check for success
        success = os.path.exists("coff_loader.dll")
        
        if success:
            print("[+] coff_loader.c compiled successfully!")
            
            # Verify the function is exported
            if verify_dll_exports():
                return True
            else:
                print("[-] DLL compiled but function not found!")
                return False
        else:
            print(f"[-] Compilation failed with return code: {result.returncode}")
            return False
        
    except Exception as e:
        print(f"[-] Compilation error: {e}")
        return False
    finally:
        # Clean up batch file if we created one
        if vcvars_path != "system" and 'bat_file_path' in locals():
            if os.path.exists(bat_file_path):
                os.remove(bat_file_path)

def verify_dll_exports():
    """Verify that the DLL has the expected function"""
    print("[*] Verifying DLL exports...")
    
    try:
        # Try to load the DLL and check for the function
        import ctypes
        dll = ctypes.CDLL('./coff_loader.dll')
        
        # Check if our target function exists
        try:
            func = dll.parse_coff_and_execute
            print("[+] Verified: parse_coff_and_execute function found in DLL")
            
            # Test function prototype
            dll.parse_coff_and_execute.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
            dll.parse_coff_and_execute.restype = ctypes.c_int
            print("[+] Function prototype configured successfully")
            return True
        except AttributeError:
            print("[-] parse_coff_and_execute function NOT found in DLL")
            
            # List available functions
            print("[*] Available functions in DLL:")
            for name in dir(dll):
                if not name.startswith('_') and not name.startswith('Dll'):
                    print(f"    - {name}")
            
            return False
    except Exception as e:
        print(f"[-] Failed to verify DLL: {e}")
        return False

def cleanup_old_files():
    """Clean up old build files"""
    print("[*] Cleaning up old build files...")
    
    build_files = [
        "coff_loader.dll", "coff_loader.exp", "coff_loader.lib", "coff_loader.obj",
        "simple_coff_loader.c", "simple_coff_loader.exp", "simple_coff_loader.lib", "simple_coff_loader.obj",
        "vc140.pdb", "*.pdb"
    ]
    
    for pattern in build_files:
        if '*' in pattern:
            # Handle wildcard patterns
            import glob
            for file in glob.glob(pattern):
                if os.path.exists(file):
                    os.remove(file)
                    print(f"    Removed: {file}")
        else:
            if os.path.exists(pattern):
                os.remove(pattern)
                print(f"    Removed: {pattern}")

def main():
    print("=== COFF Loader Build System ===")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print()
    
    # Verify we're on Windows
    if platform.system() != "Windows":
        print("[-] This script is designed for Windows systems only!")
        return
    
    # Clean up old files
    cleanup_old_files()
    
    # Find compiler and compile
    vcvars_path = find_msvc_compiler()
    if not vcvars_path:
        print("[-] No compiler found!")
        print("[*] Please install Visual Studio Build Tools with C++ support")
        return
    
    # Compile the actual coff_loader.c file
    if compile_coff_loader(vcvars_path):
        print("\n" + "=" * 50)
        print("[+] BUILD COMPLETED SUCCESSFULLY!")
        print("[+] coff_loader.dll created with parse_coff_and_execute function")
        print("\n[*] Next steps:")
        print("    1. Run: python coff_controller.py")
        print("    2. Watch Notepad open with 'Hello World' text")
        print("    3. Observe the process injection technique in action")
        print("\n[!] Note: Windows Defender might show warnings")
        print("    This is expected for process injection demonstrations")
    else:
        print("\n[-] BUILD FAILED!")
        print("[*] Troubleshooting tips:")
        print("    - Ensure Visual Studio Build Tools are installed")
        print("    - Check that C++ development tools are included")
        print("    - Run as Administrator if there are permission issues")

if __name__ == "__main__":
    main()