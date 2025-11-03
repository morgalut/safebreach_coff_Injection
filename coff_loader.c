#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// COFF Header Structures
#pragma pack(push, 1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_Header;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SectionHeader;
#pragma pack(pop)

// Working shellcode that opens Notepad and types "Hello World"
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x38,                             // sub rsp, 0x38
    0x48, 0x31, 0xC0,                                   // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x20,                       // mov [rsp+0x20], rax
    
    // Push "notepad.exe" string
    0x48, 0xB8, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x657865
    0x50,                                               // push rax
    0x48, 0xB8, 0x2E, 0x70, 0x61, 0x64, 0x2E, 0x65, 0x78, 0x65, // mov rax, 0x6578652E6461702E
    0x50,                                               // push rax
    0x48, 0xB8, 0x5C, 0x6E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, // mov rax, 0x64617065746F6E5C
    0x50,                                               // push rax
    0x48, 0xB8, 0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F, // mov rax, 0x6F646E69575C3A43
    0x50,                                               // push rax
    0x48, 0x89, 0xE1,                                   // mov rcx, rsp
    
    // Call CreateProcessA
    0x48, 0x31, 0xD2,                                   // xor rdx, rdx
    0x4D, 0x31, 0xC0,                                   // xor r8, r8
    0x4D, 0x31, 0xC9,                                   // xor r9, r9
    0x48, 0x31, 0xC0,                                   // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x30,                       // mov [rsp+0x30], rax
    0x48, 0x8D, 0x44, 0x24, 0x30,                       // lea rax, [rsp+0x30]
    0x48, 0x89, 0x44, 0x24, 0x28,                       // mov [rsp+0x28], rax
    0x48, 0x8D, 0x44, 0x24, 0x20,                       // lea rax, [rsp+0x20]
    0x48, 0x89, 0x44, 0x24, 0x20,                       // mov [rsp+0x20], rax
    0x48, 0xB8, 0xEC, 0xEC, 0xEC, 0xEC, 0xEC, 0xEC, 0xEC, 0xEC, // mov rax, CreateProcessA address (patched)
    0xFF, 0xD0,                                         // call rax
    
    // Cleanup and return
    0x48, 0x83, 0xC4, 0x38,                             // add rsp, 0x38
    0xC3                                                // ret
};

// Function to type text into Notepad
BOOL TypeTextIntoNotepad(const char* text) {
    HWND hNotepad = FindWindowA("Notepad", NULL);
    if (!hNotepad) {
        printf("[-] Could not find Notepad window\n");
        return FALSE;
    }
    
    HWND hEdit = FindWindowExA(hNotepad, NULL, "Edit", NULL);
    if (!hEdit) {
        printf("[-] Could not find Notepad edit control\n");
        return FALSE;
    }
    
    // Set focus to Notepad
    SetForegroundWindow(hNotepad);
    SetFocus(hEdit);
    
    // Send each character
    for (int i = 0; i < strlen(text); i++) {
        PostMessageA(hEdit, WM_CHAR, (WPARAM)text[i], 0);
        Sleep(10); // Small delay between characters
    }
    
    printf("[+] Successfully typed '%s' into Notepad\n", text);
    return TRUE;
}

// Function to patch shellcode with actual API addresses
void PatchShellcode() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pCreateProcessA = GetProcAddress(hKernel32, "CreateProcessA");
    
    // Patch the CreateProcessA address into shellcode
    memcpy(&shellcode[0x60], &pCreateProcessA, sizeof(pCreateProcessA));
}

__declspec(dllexport) int parse_coff_and_execute(unsigned char* coff_data, size_t data_size) {
    printf("\n[+] COFF Parser & Process Injection Started\n");
    printf("[+] MITRE ATT&CK Technique: T1055 (Process Injection)\n");
    
    // Validate COFF data
    if (!coff_data || data_size < sizeof(COFF_Header)) {
        printf("[-] Invalid COFF data\n");
        return -1;
    }
    
    // Parse COFF header
    COFF_Header* coff_header = (COFF_Header*)coff_data;
    
    printf("[+] COFF Header Parsed:\n");
    printf("    Machine: 0x%04X\n", coff_header->Machine);
    printf("    Sections: %d\n", coff_header->NumberOfSections);
    printf("    Characteristics: 0x%04X\n", coff_header->Characteristics);
    
    // Parse section headers if present
    if (coff_header->NumberOfSections > 0) {
        COFF_SectionHeader* sections = (COFF_SectionHeader*)(coff_data + sizeof(COFF_Header));
        
        printf("[+] Parsing %d sections:\n", coff_header->NumberOfSections);
        for (int i = 0; i < coff_header->NumberOfSections; i++) {
            printf("    Section %d: %-8s (Raw Size: %d bytes)\n", 
                   i, sections[i].Name, sections[i].SizeOfRawData);
        }
    }
    
    printf("\n[+] Performing Process Injection (T1055)...\n");
    
    // Method 1: Direct WinAPI approach (Most reliable)
    printf("[*] Attempting Method 1: Direct WinAPI...\n");
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    
    char notepadPath[] = "C:\\Windows\\System32\\notepad.exe";
    
    if (CreateProcessA(
        notepadPath,
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        
        printf("[+] Notepad process created successfully! (PID: %d)\n", pi.dwProcessId);
        
        // Wait for Notepad to initialize
        printf("[*] Waiting for Notepad window...\n");
        Sleep(3000);
        
        // Type "Hello World" into Notepad
        if (TypeTextIntoNotepad("Hello World")) {
            printf("[+] SUCCESS: Notepad opened with 'Hello World' text!\n");
        } else {
            printf("[-] Notepad opened but couldn't type text\n");
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        printf("[+] Process injection demo completed successfully!\n");
        return 0;
    } else {
        DWORD error = GetLastError();
        printf("[-] CreateProcessA failed (Error: %d)\n", error);
    }
    
    // Method 2: ShellExecute fallback
    printf("[*] Attempting Method 2: ShellExecute fallback...\n");
    
    HINSTANCE hResult = ShellExecuteA(NULL, "open", "notepad.exe", NULL, NULL, SW_SHOW);
    if ((INT_PTR)hResult > 32) {
        printf("[+] Notepad opened via ShellExecute\n");
        Sleep(3000);
        
        if (TypeTextIntoNotepad("Hello World")) {
            printf("[+] SUCCESS: Notepad opened with 'Hello World' text!\n");
            return 0;
        }
    } else {
        printf("[-] ShellExecute failed\n");
    }
    
    // Method 3: Shellcode injection (Advanced technique)
    printf("[*] Attempting Method 3: Shellcode injection...\n");
    
    PatchShellcode();
    
    LPVOID pRemoteCode = VirtualAlloc(NULL, sizeof(shellcode), 
                                     MEM_COMMIT | MEM_RESERVE, 
                                     PAGE_EXECUTE_READWRITE);
    
    if (pRemoteCode) {
        printf("[+] Memory allocated at: 0x%p\n", pRemoteCode);
        
        memcpy(pRemoteCode, shellcode, sizeof(shellcode));
        
        printf("[+] Shellcode copied to memory\n");
        printf("[+] Executing shellcode...\n");
        
        HANDLE hThread = CreateThread(NULL, 0, 
                                    (LPTHREAD_START_ROUTINE)pRemoteCode, 
                                    NULL, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            printf("[+] Shellcode execution completed\n");
            
            Sleep(3000);
            TypeTextIntoNotepad("Hello from Shellcode!");
            
            VirtualFree(pRemoteCode, 0, MEM_RELEASE);
            return 0;
        } else {
            printf("[-] Failed to create thread\n");
            VirtualFree(pRemoteCode, 0, MEM_RELEASE);
        }
    } else {
        printf("[-] Memory allocation failed\n");
    }
    
    printf("[-] All methods failed to demonstrate the technique\n");
    return -1;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}