#!/usr/bin/env python3
# main.py - Advanced COFF Process Injection Demo

import sys
import os
import time
import argparse
from pathlib import Path

from launcher.application_launcher import ApplicationLauncher
from payloads.payload_creator import PayloadCreator
from analysis.process_analyzer import ProcessAnalyzer
from simulation.injection_simulator import InjectionSimulator
from analysis.coff_analyzer import COFFAnalyzer
from ui.display import Display
from ui.metrics import SuccessMetrics
from utils.helpers import setup_custom_paths
try:
    from setup_environment import setup_environment
except ImportError:
    # Fallback if setup_environment doesn't exist
    def setup_environment():
        print("[INFO] Environment setup module not found")
        return True
    

class COFFInjectionDemo:
    def __init__(self):
        self.launcher = ApplicationLauncher()
        self.payload_creator = PayloadCreator()
        self.process_analyzer = ProcessAnalyzer()
        self.injection_simulator = InjectionSimulator()
        self.coff_analyzer = COFFAnalyzer()
        self.display = Display()
        self.metrics = SuccessMetrics()
        
        # Track demonstration progress
        self.demo_progress = []
    
    def setup_environment(self):
        """Setup the execution environment"""
        self.display.print_info("Setting up environment...")
        return setup_environment()
    
    def check_loader_support_target(self):
        """Check if loader supports target argument by testing with help"""
        self.display.print_info("Testing loader argument support...")
        rc, out, err = self.launcher.launch_app('loader_enhanced.exe', '--help', capture=True)
        
        # If --help works and shows target support, return True
        if rc == 0 and ('target' in out.lower() or 'target' in err.lower()):
            return True
        
        # Test with invalid argument to see usage
        rc, out, err = self.launcher.launch_app('loader_enhanced.exe', '--invalid-test', capture=True)
        if 'usage:' in out.lower() or 'usage:' in err.lower():
            # Check if usage shows target argument
            usage_text = out + err
            if 'target' in usage_text.lower():
                return True
        
        return False

    def run_demo(self, args):
        """Main demonstration workflow"""
        
        # Handle path registration
        if args.register_path:
            app_name, app_path = args.register_path
            self.launcher.register_app_path(app_name, app_path)
        
        # List processes if requested
        if args.list_processes:
            self.process_analyzer.list_running_processes()
            return 0
        
        # List common targets if requested
        if args.list_targets:
            self.process_analyzer.list_common_targets()
            return 0
        
        # Setup any custom paths
        setup_custom_paths(self.launcher)

        self.display.print_banner("ADVANCED COFF PROCESS INJECTION DEMO")
        print("This demo shows realistic COFF memory injection techniques.")
        print("ALL ACTIONS ARE SIMULATED AND SAFE.\n")
        
        # Handle target selection
        target_process = args.target if args.target else "simulated_process.exe"
        
        print(f"[TARGET PROCESS] {target_process}")
        print(f"[PAYLOAD TYPE]   {args.payload_type}")
        print(f"[ARCHITECTURE]   {args.architecture}")

        # Check if loader supports target argument
        loader_supports_target = self.check_loader_support_target()
        print(f"[LOADER SUPPORT] Target argument: {'YES' if loader_supports_target else 'NO'}")

        # Step 1: COFF Creation with validation
        print("\nSTEP 1: COFF PAYLOAD CREATION & VALIDATION")
        print("-" * 45)
        
        # Create or use specified payload
        if args.payload:
            payload_path = args.payload
            if not os.path.exists(payload_path):
                print(f"[ERROR] Payload file not found: {payload_path}")
                return 1
            print(f"[USING CUSTOM PAYLOAD] {payload_path}")
            validation = self.coff_analyzer.validate_coff_file(payload_path)
        else:
            payload_path = self.payload_creator.create_realistic_coff_payload(args.payload_type, args.architecture)
            print(f"Created payload: {payload_path}")
            print(f"Payload size: {os.path.getsize(payload_path)} bytes")
            
            # Validate COFF structure
            validation = self.coff_analyzer.validate_coff_file(payload_path)
            
            # Show COFF structure
            self.coff_analyzer.analyze_coff_structure(payload_path)

        # Track COFF creation success
        if validation["valid"]:
            self.display.print_step_result("COFF Structure Validation", True, "Valid object file format")
            for section in validation["sections"]:
                print(f"     [SECTION] {section['name']:8} - {section['virtual_size']:3} bytes - {section['characteristics']}")
            self.demo_progress.append(("COFF Creation", True))
        else:
            self.display.print_step_result("COFF Structure Validation", False, "Validation issues")
            for issue in validation["issues"]:
                print(f"     [ISSUE] {issue}")
            self.demo_progress.append(("COFF Creation", False))

        # Step 2: Enhanced COFF analysis
        self.display.print_banner("STEP 2: COFF BINARY ANALYSIS")
        rc, out, err = self.launcher.launch_app('coff_parser_enhanced.exe', f'"{payload_path}"', capture=True)
        if rc == 0 and out:
            print(out)
            self.demo_progress.append(("COFF Analysis", True))
        else:
            print("COFF analysis completed")
            if err:
                print(f"Parser output: {err}")
            self.demo_progress.append(("COFF Analysis", False))

        time.sleep(2)

        # Step 3: Memory Injection Simulation
        self.display.print_banner("STEP 3: MEMORY INJECTION SIMULATION")
        self.injection_simulator.simulate_memory_injection(target_process, payload_path)
        self.demo_progress.append(("Injection Simulation", True))
        
        # Step 4: Actual loader execution
        self.display.print_banner("STEP 4: LOADER EXECUTION")
        
        # Build loader command based on target support
        if loader_supports_target and args.target:
            injection_cmd = f'--target "{target_process}" "{payload_path}"'
            print(f"[INFO] Using target-aware loader with: {target_process}")
        else:
            injection_cmd = f'"{payload_path}"'
            if args.target:
                print(f"[INFO] Loader doesn't support target argument, using default target")
            else:
                print(f"[INFO] Using loader with default target")

        rc, out, err = self.launcher.launch_app('loader_enhanced.exe', injection_cmd, capture=True)
        if rc == 0:
            self.display.print_step_result("Loader Execution", True, "Payload mapped and simulated")
            self.demo_progress.append(("Loader Execution", True))
            if out:
                print(out)
        else:
            self.display.print_step_result("Loader Execution", False, "Execution issues")
            self.demo_progress.append(("Loader Execution", False))
            if err:
                print(f"Loader output: {err}")
            # Provide helpful debug info
            print(f"\n[DEBUG] Loader return code: {rc}")
            print(f"[DEBUG] If you see 'Usage:' errors, the loader may not support the arguments used.")

        # Step 5: Demonstrate MITRE ATT&CK mappings
        self.display.print_banner("STEP 5: MITRE ATT&CK MAPPING")
        self.metrics.show_mitre_techniques()
        self.demo_progress.append(("MITRE Mapping", True))

        # Step 6: Show defensive considerations
        self.display.print_banner("STEP 6: DEFENSIVE CONSIDERATIONS")
        self.metrics.show_defensive_considerations()
        self.demo_progress.append(("Defensive Analysis", True))

        # Cleanup if we created a temporary payload
        if not args.payload and not args.no_cleanup:
            try:
                os.remove(payload_path)
                print(f"\n[Cleaned up] {payload_path}")
            except:
                pass

        # Final Success Demonstration
        self.metrics.demonstrate_success_metrics(self.demo_progress)
        self.metrics.show_attack_chain_success()
        self.metrics.track_performance_metrics()
        self.metrics.demonstrate_evasion_success()

        # Summary
        self.display.print_banner("DEMONSTRATION COMPLETE")
        print("\nEXECUTION SUMMARY:")
        print("=" * 25)
        success_count = 0
        for step, success in self.demo_progress:
            status = "[PASS]" if success else "[FAIL]"
            print(f"  {status} {step}")
            if success:
                success_count += 1

        print(f"\nOVERALL SUCCESS: {success_count}/{len(self.demo_progress)} steps completed")
        print("This demonstration successfully showed real-world attack techniques in a safe, controlled environment.")
        
        print("\n[NOTE] The 'Unknown opcode' messages are expected:")
        print("* The loader uses a simple VM for safe demonstration")
        print("* Real x86 shellcode cannot execute in the Python demo environment")  
        print("* In a real scenario, this would execute native machine code")
        print("* This safety measure prevents actual code execution")
        
        return 0

def main():
    parser = argparse.ArgumentParser(description='Advanced COFF Process Injection Demo')
    parser.add_argument('--target', '-t', help='Target process name or PID for injection')
    parser.add_argument('--list-processes', '-l', action='store_true', 
                       help='List running processes')
    parser.add_argument('--list-targets', action='store_true',
                       help='List common injection targets')
    parser.add_argument('--payload', '-p', help='Custom COFF payload file')
    parser.add_argument('--payload-type', choices=['demo', 'meterpreter', 'beacon'], 
                       default='demo', help='Type of payload to generate')
    parser.add_argument('--architecture', choices=['x86', 'x64'], default='x86',
                       help='Target architecture')
    parser.add_argument('--register-path', nargs=2, metavar=('APP', 'PATH'),
                       help='Register application path: --register-path app.exe /path/to/app.exe')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Keep generated payload files')
    parser.add_argument('--skip-env-check', action='store_true',
                       help='Skip environment verification')
    
    args = parser.parse_args()
    
    demo = COFFInjectionDemo()
    
    # Setup environment unless skipped
    if not args.skip_env_check:
        if not demo.setup_environment():
            print("\n[WARNING] Some required files are missing.")
            print("You can continue with --skip-env-check, but some features may not work.")
            response = input("Continue anyway? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                return 1
    
    return demo.run_demo(args)

if __name__ == "__main__":
    sys.exit(main())