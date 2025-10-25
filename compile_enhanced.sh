#!/bin/bash
echo "Building Enhanced COFF Injection Demo..."

# Build enhanced COFF parser
x86_64-w64-mingw32-gcc -O2 -o coff_parser_enhanced.exe coff_parser_enhanced.c

# Build enhanced loader  
x86_64-w64-mingw32-gcc -O2 -o loader_enhanced.exe loader_enhanced.c -ladvapi32

# Build the DLL (unchanged)
x86_64-w64-mingw32-gcc -shared -o coff_loader_dll.dll coff_loader_dll.c -ladvapi32

echo
echo "Build complete. Files created:"
echo "  - coff_parser_enhanced.exe"
echo "  - loader_enhanced.exe"  
echo "  - coff_loader_dll.dll"
echo
echo "Run: python run_enhanced_demo.py "