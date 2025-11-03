@echo off
title COFF Parser Enhanced - Build System
echo ===============================================
echo    COFF Parser Enhanced - MITRE ATT&CK T1055
echo ===============================================
echo.

echo [1/4] Building minimal test shellcode...
cl /c /GS- /Gs- minimal_shellcode.c
if %errorlevel% neq 0 (
    echo  Failed to compile minimal_shellcode.c
    pause
    exit /b 1
)

echo [2/4] Building position-independent shellcode...
cl /c /GS- /Gs- position_independent_shellcode.c
if %errorlevel% neq 0 (
    echo  Failed to compile position_independent_shellcode.c
    pause
    exit /b 1
)

echo [3/4] Building enhanced COFF parser...
cl coff_parser_enhanced.c
if %errorlevel% neq 0 (
    echo  Failed to compile coff_parser_enhanced.c
    pause
    exit /b 1
)

echo [4/4] Building test target application...
cl test_target.c
if %errorlevel% neq 0 (
    echo   Test target compilation failed (optional)
)

echo.
echo ===============================================
echo  BUILD COMPLETED SUCCESSFULLY!
echo ===============================================
echo.
echo Generated Files:
echo   - minimal_shellcode.obj          (Safe test shellcode)
echo   - position_independent_shellcode.obj (Advanced shellcode)  
echo   - coff_parser_enhanced.exe       (Main parser/injector)
echo   - test_target.exe                (Test application)
echo.
echo Usage Examples:
echo   coff_parser_enhanced.exe minimal_shellcode.obj 1234
echo.
echo Test Commands:
echo   test_target.exe                  (Run test target, note PID)
echo   tasklist ^| findstr "notepad"      (Find notepad PID)
echo   tasklist ^| findstr "test_target"  (Find test target PID)
echo.
echo ===============================================
echo \  RUN AS ADMINISTRATOR FOR PROCESS INJECTION
echo ===============================================
pause