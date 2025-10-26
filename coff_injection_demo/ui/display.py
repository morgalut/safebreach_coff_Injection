# display.py

class Display:
    def print_banner(self, title):
        print(f"\n{'='*60}")
        print(f" {title}")
        print(f"{'='*60}")

    def print_success(self, message):
        """Print clear success messages"""
        print(f"  [SUCCESS] {message}")

    def print_failure(self, message):
        """Print clear failure messages"""
        print(f"  [FAILED] {message}")

    def print_step_result(self, step_name, success, details=""):
        """Print step results with clear indicators"""
        if success:
            print(f"  [PASS] {step_name}: SUCCESS {details}")
        else:
            print(f"  [FAIL] {step_name}: FAILED {details}")

    def print_info(self, message):
        """Print informational messages"""
        print(f"  [INFO] {message}")