#!/bin/bash
# compile_enhanced.sh - Compile all C components for the COFF injection demo
# Combined version with both simulation and real injection capabilities

echo "========================================================"
echo "    COFF Injection Demo - Component Compilation"
echo "    Combined Simulation & Real Injection Build"
echo "========================================================"
echo ""

# Configuration
COMPILER="x86_64-w64-mingw32-gcc"
BIN_DIR="../bin"
SRC_DIR="."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored status
print_status() {
    echo -e "${BLUE}[STATUS]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if compiler is available
check_compiler() {
    if ! command -v $COMPILER &> /dev/null; then
        print_error "Compiler $COMPILER not found!"
        echo "Please install mingw-w64:"
        echo "  Ubuntu/Debian: sudo apt-get install mingw-w64"
        echo "  CentOS/RHEL:   sudo yum install mingw64-gcc"
        echo "  macOS:         brew install mingw-w64"
        exit 1
    fi
    print_success "Compiler $COMPILER is available"
}

# Create bin directory
create_bin_directory() {
    if [ ! -d "$BIN_DIR" ]; then
        print_status "Creating bin directory: $BIN_DIR"
        mkdir -p "$BIN_DIR"
    else
        print_status "Bin directory already exists: $BIN_DIR"
    fi
}

# Compile COFF Loader DLL
compile_coff_loader_dll() {
    print_status "Compiling COFF Loader DLL..."
    local output="$BIN_DIR/coff_loader_dll.dll"
    local source="$SRC_DIR/coff_loader_dll.c"
    
    if [ ! -f "$source" ]; then
        print_warning "Source file not found: $source"
        return 1
    fi
    
    $COMPILER -shared -o "$output" "$source" -lntdll -s
    
    if [ $? -eq 0 ] && [ -f "$output" ]; then
        print_success "COFF Loader DLL compiled: $(basename $output)"
        return 0
    else
        print_error "Failed to compile COFF Loader DLL"
        return 1
    fi
}

# Compile Enhanced COFF Parser
compile_coff_parser() {
    print_status "Compiling Enhanced COFF Parser..."
    local output="$BIN_DIR/coff_parser_enhanced.exe"
    local source="$SRC_DIR/coff_parser_enhanced.c"
    
    if [ ! -f "$source" ]; then
        print_warning "Source file not found: $source"
        return 1
    fi
    
    $COMPILER -o "$output" "$source" -s
    
    if [ $? -eq 0 ] && [ -f "$output" ]; then
        print_success "COFF Parser compiled: $(basename $output)"
        return 0
    else
        print_error "Failed to compile COFF Parser"
        return 1
    fi
}

# Compile Enhanced Loader (with real injection capabilities)
compile_enhanced_loader() {
    print_status "Compiling Enhanced Loader with real injection capabilities..."
    local output="$BIN_DIR/loader_enhanced.exe"
    local source="$SRC_DIR/loader_enhanced.c"
    
    if [ ! -f "$source" ]; then
        print_warning "Source file not found: $source"
        return 1
    fi
    
    # Compile with both simulation and real injection features
    $COMPILER -o "$output" "$source" -lpsapi -s
    
    if [ $? -eq 0 ] && [ -f "$output" ]; then
        print_success "Enhanced Loader compiled: $(basename $output)"
        return 0
    else
        print_error "Failed to compile Enhanced Loader"
        return 1
    fi
}

# Compile any additional utilities
compile_utilities() {
    print_status "Checking for additional utilities to compile..."
    
    # Check if there are any utility C files to compile
    for util_source in "$SRC_DIR"/*_util.c "$SRC_DIR"/util_*.c; do
        if [ -f "$util_source" ]; then
            local base_name=$(basename "$util_source" .c)
            local output="$BIN_DIR/$base_name.exe"
            
            print_status "Compiling utility: $base_name"
            $COMPILER -o "$output" "$util_source" -s
            
            if [ $? -eq 0 ] && [ -f "$output" ]; then
                print_success "Utility compiled: $(basename $output)"
            else
                print_warning "Failed to compile utility: $base_name"
            fi
        fi
    done
}

# Verify all compiled files
verify_compilation() {
    echo ""
    print_status "Verifying compiled files..."
    
    local success_count=0
    local total_count=0
    
    # Expected files
    local expected_files=(
        "loader_enhanced.exe"
        "coff_parser_enhanced.exe" 
        "coff_loader_dll.dll"
    )
    
    for file in "${expected_files[@]}"; do
        local full_path="$BIN_DIR/$file"
        total_count=$((total_count + 1))
        
        if [ -f "$full_path" ]; then
            # Get file size
            local size=$(stat -f%z "$full_path" 2>/dev/null || stat -c%s "$full_path" 2>/dev/null || echo "0")
            
            # Check if file has reasonable size (not empty)
            if [ "$size" -gt 1024 ]; then
                echo -e "  ${GREEN}✓${NC} $file (${size} bytes)"
                success_count=$((success_count + 1))
            else
                echo -e "  ${YELLOW}⚠${NC} $file (WARNING: file may be too small - ${size} bytes)"
            fi
        else
            echo -e "  ${RED}✗${NC} $file - MISSING"
        fi
    done
    
    echo ""
    if [ $success_count -eq $total_count ]; then
        print_success "All $total_count components compiled successfully!"
        return 0
    else
        print_warning "Only $success_count out of $total_count components compiled successfully"
        return 1
    fi
}

# Display usage information
display_usage() {
    echo "Compilation completed components:"
    echo ""
    echo "  📦 loader_enhanced.exe"
    echo "     - Dual-mode: Simulation & Real Injection"
    echo "     - Usage:"
    echo "         Simulation:   loader_enhanced.exe payload.obj"
    echo "         Real Inject:  loader_enhanced.exe --target notepad.exe payload.obj"
    echo ""
    echo "  📊 coff_parser_enhanced.exe" 
    echo "     - Dual-mode: Enhanced Analysis & Real Windows API Analysis"
    echo "     - Usage:"
    echo "         Enhanced:     coff_parser_enhanced.exe payload.obj"
    echo "         Real Analysis: coff_parser_enhanced.exe --real payload.obj"
    echo ""
    echo "  🔧 coff_loader_dll.dll"
    echo "     - Support DLL for COFF loading operations"
    echo ""
}

# Display security warning
display_security_warning() {
    echo ""
    echo "========================================================"
    echo "                    SECURITY NOTICE"
    echo "========================================================"
    echo ""
    echo "⚠️   THESE TOOLS CAN PERFORM ACTUAL CODE INJECTION"
    echo ""
    echo "Authorized Use Only:"
    echo "  ✓ Penetration testing with explicit permission"
    echo "  ✓ Security research in controlled environments"
    echo "  ✓ Educational purposes in academic settings"
    echo ""
    echo "Prohibited Use:"
    echo "  ✗ Unauthorized penetration testing"
    echo "  ✗ Malicious activities"
    echo "  ✗ Testing systems without explicit permission"
    echo ""
    echo "By using these tools, you agree to:"
    echo "  1. Use only in environments you own or have explicit permission to test"
    echo "  2. Comply with all applicable laws and regulations"
    echo "  3. Accept full responsibility for your actions"
    echo ""
    echo "========================================================"
}

# Clean previous builds (optional)
clean_previous_build() {
    if [ "$1" = "--clean" ]; then
        print_status "Cleaning previous build..."
        rm -f "$BIN_DIR"/*.exe "$BIN_DIR"/*.dll
    fi
}

# Main compilation process
main() {
    echo "Starting compilation process..."
    echo ""
    
    # Check compiler
    check_compiler
    
    # Clean if requested
    clean_previous_build "$1"
    
    # Create bin directory
    create_bin_directory
    
    echo ""
    echo "Compiling components..."
    echo "----------------------"
    
    # Compile all components
    compile_coff_loader_dll
    compile_coff_parser
    compile_enhanced_loader
    compile_utilities
    
    # Verify compilation
    if verify_compilation; then
        echo ""
        echo "========================================================"
        print_success "COMPILATION COMPLETED SUCCESSFULLY!"
        echo "========================================================"
        echo ""
        
        display_usage
        display_security_warning
        
        # Show where files are located
        echo ""
        print_status "Compiled files are located in: $(readlink -f $BIN_DIR)"
        
    else
        echo ""
        echo "========================================================"
        print_warning "COMPILATION COMPLETED WITH WARNINGS"
        echo "========================================================"
        echo ""
        
        print_status "Some components may not have compiled correctly."
        print_status "Check the errors above and ensure all source files exist."
        
        display_security_warning
    fi
}

# Run main function with all arguments
main "$@"