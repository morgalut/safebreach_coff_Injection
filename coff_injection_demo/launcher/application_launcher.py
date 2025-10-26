# application_launcher.py

import subprocess
import sys
import os
import shutil
from pathlib import Path

class ApplicationLauncher:
    def __init__(self):
        self.app_paths = {}
        self.setup_default_paths()
    
    def setup_default_paths(self):
        """Setup default application names and their expected locations"""
        self.default_apps = {
            "loader_enhanced.exe": "loader_enhanced.exe",
            "coff_parser_enhanced.exe": "coff_parser_enhanced.exe", 
            "coff_loader_dll.dll": "coff_loader_dll.dll"
        }
    
    def register_app_path(self, app_name, full_path):
        """Register a custom path for an application"""
        self.app_paths[app_name] = str(Path(full_path).resolve())
        print(f"[PATH REGISTERED] {app_name} -> {self.app_paths[app_name]}")
    
    def find_application(self, app_name):
        """Find application using registered paths, current dir, bin directory, or PATH env"""
        # Check registered custom paths first
        if app_name in self.app_paths:
            path = Path(self.app_paths[app_name])
            if path.exists():
                return path
        
        # Check current directory
        current_dir = Path(app_name)
        if current_dir.exists():
            return current_dir
        
        # Check in bin directory (preferred location)
        project_root = Path(__file__).parent.parent
        bin_dir = project_root / "bin" / app_name
        if bin_dir.exists():
            return bin_dir
        
        # Check in src directory (for development)
        src_dir = project_root / "src" / app_name
        if src_dir.exists():
            return src_dir
        
        # Check in script directory
        script_dir = Path(__file__).parent / app_name
        if script_dir.exists():
            return script_dir
        
        # Check in project root
        project_dir = project_root / app_name
        if project_dir.exists():
            return project_dir
        
        # Check in PATH environment variable
        for path_dir in os.environ.get('PATH', '').split(os.pathsep):
            potential_path = Path(path_dir) / app_name
            if potential_path.exists():
                return potential_path
        
        return None
    
    def ensure_file_accessible(self, file_path):
        """Ensure a file is accessible to external executables by making a copy in the bin directory"""
        path = Path(file_path)
        
        if not path.exists():
            return None
            
        # Use the bin directory as target
        target_dir = Path(__file__).parent.parent / "bin"
        
        # Create target directory if it doesn't exist
        target_dir.mkdir(exist_ok=True)
            
        # Copy file to target directory
        target_path = target_dir / path.name
        try:
            shutil.copy2(path, target_path)
            print(f"[FILE COPIED] {path.name} -> {target_path}")
            return str(target_path)
        except Exception as e:
            print(f"[WARNING] Could not copy {path.name} to {target_dir}: {e}")
            # Fallback to absolute path
            return str(path.resolve())
    
    def launch_app(self, app_name, args="", capture=False, ensure_files=None):
        """Launch application with arguments"""
        app_path = self.find_application(app_name)
        
        if not app_path:
            print(f"[ERROR] Application not found: {app_name}")
            print("Available search locations:")
            project_root = Path(__file__).parent.parent
            bin_path = project_root / "bin" / app_name
            src_path = project_root / "src" / app_name
            print(f"   - {bin_path}")
            print(f"   - {src_path}")
            print(f"   - {project_root / app_name}")
            return 1, f"Application {app_name} not found", ""
        
        # Ensure files are accessible (copy to bin directory if needed)
        file_replacements = {}
        if ensure_files:
            for file_path in ensure_files:
                accessible_path = self.ensure_file_accessible(file_path)
                if accessible_path:
                    # Store the replacement mapping
                    file_replacements[file_path] = accessible_path
        
        # Build the command with proper path handling
        resolved_args = args
        for original_path, accessible_path in file_replacements.items():
            # Replace the file path in arguments - handle both quoted and unquoted
            original_quoted = f'"{original_path}"'
            accessible_quoted = f'"{accessible_path}"'
            
            # Replace quoted paths first
            if original_quoted in resolved_args:
                resolved_args = resolved_args.replace(original_quoted, accessible_quoted)
            else:
                # Replace unquoted paths
                resolved_args = resolved_args.replace(original_path, accessible_path)
        
        cmd = f'"{app_path}" {resolved_args}'
        print(f"[EXECUTING] {cmd}")
        sys.stdout.flush()
        
        try:
            # Store original directory
            original_dir = os.getcwd()
            
            # Set current directory to the bin directory where files are accessible
            bin_dir = Path(__file__).parent.parent / "bin"
            os.chdir(bin_dir)
            
            p = subprocess.Popen(cmd, shell=True, 
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None,
                                universal_newlines=False)
        
            if capture:
                out, err = p.communicate()
                # Decode with error handling for binary data
                try:
                    out = out.decode('utf-8', errors='replace') if out else ""
                except UnicodeDecodeError:
                    out = out.decode('latin-1', errors='replace') if out else ""
                try:
                    err = err.decode('utf-8', errors='replace') if err else ""
                except UnicodeDecodeError:
                    err = err.decode('latin-1', errors='replace') if err else ""
                
                # Restore original directory
                os.chdir(original_dir)
                return p.returncode, out, err
            else:
                p.wait()
                # Restore original directory
                os.chdir(original_dir)
                return p.returncode, "", ""
        except Exception as e:
            # Restore original directory on error
            try:
                os.chdir(original_dir)
            except:
                pass
            return 1, "", f"Failed to launch {app_name}: {str(e)}"
    
    def get_expected_locations(self, app_name):
        """Return all expected locations for an application for debugging"""
        locations = []
        
        # Registered paths
        if app_name in self.app_paths:
            locations.append(("Registered", self.app_paths[app_name]))
        
        # Current directory
        current_dir = Path(app_name)
        locations.append(("Current Directory", str(current_dir)))
        
        # Project directories
        project_root = Path(__file__).parent.parent
        locations.extend([
            ("Project Bin", str(project_root / "bin" / app_name)),
            ("Project Src", str(project_root / "src" / app_name)),
            ("Project Root", str(project_root / app_name)),
            ("Launcher Dir", str(Path(__file__).parent / app_name))
        ])
        
        return locations