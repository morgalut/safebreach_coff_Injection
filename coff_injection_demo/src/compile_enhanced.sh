#!/bin/bash
# compile_enhanced.sh - Compile all C components for the COFF injection demo

echo "Compiling COFF Injection Demo Components..."
echo "==========================================="

# Create bin directory if it doesn't exist
mkdir -p ../bin

# Compile COFF Loader DLL
echo "Compiling coff_loader_dll.dll..."
x86_64-w64-mingw32-gcc -shared -o ../bin/coff_loader_dll.dll coff_loader_dll.c -lntdll

# Compile Enhanced COFF Parser
echo "Compiling coff_parser_enhanced.exe..."
x86_64-w64-mingw32-gcc -o ../bin/coff_parser_enhanced.exe coff_parser_enhanced.c

# Compile Enhanced Loader
echo "Compiling loader_enhanced.exe..."
x86_64-w64-mingw32-gcc -o ../bin/loader_enhanced.exe loader_enhanced.c

echo "==========================================="
echo "Compilation complete!"
echo "Executables are in ../bin/ directory"

# Check if files were created
echo ""
echo "Verifying compiled files:"
for file in ../bin/loader_enhanced.exe ../bin/coff_parser_enhanced.exe ../bin/coff_loader_dll.dll; do
    if [ -f "$file" ]; then
        echo "  ✓ $(basename $file)"
    else
        echo "  ✗ $(basename $file) - MISSING"
    fi
done