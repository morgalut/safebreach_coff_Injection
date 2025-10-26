// loader_enhanced.c
// Enhanced loader with process injection simulation and advanced VM
// FIXED: Removed C++ lambdas, fixed string operations

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

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

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.obj>\n", argv[0]);
        return 2;
    }
    
    printf("[+] Enhanced COFF Loader - Process Injection Simulation\n");
    printf("[+] Target: %s\n\n", argv[1]);
    
    // Simulate process hollowing
    HANDLE hProcess = simulate_process_hollowing("notepad.exe");
    if (hProcess != INVALID_HANDLE_VALUE) {
        printf("[INJECTION] Process created in suspended state\n");
        printf("[INJECTION] Simulating memory unmapping and COFF injection\n");
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
    
    FILE *f = fopen(argv[1], "rb");
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