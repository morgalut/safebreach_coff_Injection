// coff_parser_enhanced.c
// Enhanced COFF analysis with section characteristics, relocation parsing, threat assessment, and real COFF analysis
// Combines both simulation and real analysis capabilities

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} Relocation;
#pragma pack(pop)

// Section characteristic flags - use different names to avoid conflicts
#define COFF_SCN_CNT_CODE              0x00000020
#define COFF_SCN_CNT_INITIALIZED_DATA  0x00000040
#define COFF_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define COFF_SCN_MEM_EXECUTE           0x20000000
#define COFF_SCN_MEM_READ              0x40000000
#define COFF_SCN_MEM_WRITE             0x80000000

// Enhanced COFF analysis for real files using Windows API
void AnalyzeRealCOFF(const char* filename) {
    printf("=== REAL COFF ANALYSIS (Windows API) ===\n");
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file: %d\n", GetLastError());
        return;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Error getting file size: %d\n", GetLastError());
        CloseHandle(hFile);
        return;
    }
    
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("Error creating file mapping: %d\n", GetLastError());
        CloseHandle(hFile);
        return;
    }
    
    LPVOID pFileData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, fileSize);
    if (!pFileData) {
        printf("Error mapping file: %d\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }
    
    PIMAGE_FILE_HEADER pCoffHeader = (PIMAGE_FILE_HEADER)pFileData;
    
    printf("File Size: %lu bytes\n", fileSize);
    printf("Machine: 0x%04X", pCoffHeader->Machine);
    
    // Decode machine type using Windows constants
    switch (pCoffHeader->Machine) {
        case IMAGE_FILE_MACHINE_I386:
            printf(" (x86)");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf(" (x64)");
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            printf(" (ARM64)");
            break;
        default:
            printf(" (Unknown)");
            break;
    }
    printf("\n");
    
    printf("Sections: %d\n", pCoffHeader->NumberOfSections);
    printf("Timestamp: 0x%08X\n", pCoffHeader->TimeDateStamp);
    printf("Symbols: %d\n", pCoffHeader->NumberOfSymbols);
    printf("Characteristics: 0x%04X\n", pCoffHeader->Characteristics);
    
    // Analyze sections in detail
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pFileData + 
                                 sizeof(IMAGE_FILE_HEADER));
    
    printf("\n[SECTION DETAILS]\n");
    for (int i = 0; i < pCoffHeader->NumberOfSections; i++) {
        printf("\nSection %d: %s\n", i + 1, pSection[i].Name);
        printf("  Virtual Size: %lu bytes\n", pSection[i].Misc.VirtualSize);
        printf("  Virtual Address: 0x%08X\n", pSection[i].VirtualAddress);
        printf("  Raw Data Size: %lu bytes\n", pSection[i].SizeOfRawData);
        printf("  Raw Data Ptr: 0x%08X\n", pSection[i].PointerToRawData);
        printf("  Characteristics: 0x%08X\n", pSection[i].Characteristics);
        
        // Check if section contains executable code
        if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            printf("  [EXECUTABLE CODE DETECTED]\n");
            
            // Optional: Show first few bytes
            BYTE* codeStart = (BYTE*)pFileData + pSection[i].PointerToRawData;
            printf("  First 16 bytes: ");
            for (int j = 0; j < 16 && j < pSection[i].SizeOfRawData; j++) {
                printf("%02X ", codeStart[j]);
            }
            printf("\n");
        }
        
        // Check for suspicious characteristics
        if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
            (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            printf("  [WARNING: Writeable & Executable Section]\n");
        }
    }
    
    UnmapViewOfFile(pFileData);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

void analyze_section_threat(SectionHeader *sh) {
    char name[9]; 
    memcpy(name, sh->Name, 8); 
    name[8] = 0;
    
    printf("    [THREAT ASSESSMENT] Section '%s':\n", name);
    
    // Check for executable sections using our custom constants
    if (sh->Characteristics & COFF_SCN_MEM_EXECUTE) {
        printf("      ⚠️  EXECUTABLE section detected\n");
        if (sh->Characteristics & COFF_SCN_MEM_WRITE) {
            printf("      🔥 CRITICAL: Writeable & Executable (W+X) - Common exploit technique\n");
        }
    }
    
    // Check for suspicious section names
    if (strstr(name, ".text") || strstr(name, "CODE")) {
        printf("      📝 Contains executable code\n");
    }
    if (strstr(name, ".data") || strstr(name, "DATA")) {
        printf("      💾 Contains data\n");
    }
    if (strstr(name, ".rdata") || strstr(name, ".rodata")) {
        printf("      📖 Contains read-only data\n");
    }
    
    // Suspicious characteristics
    if (sh->SizeOfRawData == 0 && sh->VirtualSize > 0) {
        printf("      🚩 Zero raw size but non-zero virtual size - potential hollowing\n");
    }
    
    // Check for packed or encrypted sections
    if (sh->SizeOfRawData > 0 && sh->VirtualSize > sh->SizeOfRawData * 2) {
        printf("      🚩 Large virtual size compared to raw size - potential packing\n");
    }
    
    printf("      Characteristics: 0x%08X\n", sh->Characteristics);
}

void parse_relocations(FILE *f, SectionHeader *sh) {
    if (sh->NumberOfRelocations == 0 || sh->PointerToRelocations == 0) return;
    
    if (fseek(f, sh->PointerToRelocations, SEEK_SET) != 0) return;
    
    printf("      Relocations (%d):\n", sh->NumberOfRelocations);
    for (int i = 0; i < sh->NumberOfRelocations; i++) {
        Relocation reloc;
        if (fread(&reloc, sizeof(Relocation), 1, f) != 1) break;
        printf("        VA: 0x%08X, Type: 0x%04X, SymIdx: %u\n", 
               reloc.VirtualAddress, reloc.Type, reloc.SymbolTableIndex);
    }
}

void dump_section_hex(FILE *f, SectionHeader *sh, int max_bytes) {
    if (sh->SizeOfRawData == 0 || sh->PointerToRawData == 0) return;
    
    if (fseek(f, sh->PointerToRawData, SEEK_SET) != 0) return;
    
    uint8_t *buffer = malloc(sh->SizeOfRawData > max_bytes ? max_bytes : sh->SizeOfRawData);
    if (!buffer) return;
    
    size_t bytes_to_read = sh->SizeOfRawData > max_bytes ? max_bytes : sh->SizeOfRawData;
    if (fread(buffer, 1, bytes_to_read, f) == bytes_to_read) {
        printf("      First %zu bytes (hex):\n        ", bytes_to_read);
        for (size_t i = 0; i < bytes_to_read; i++) {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n        ");
        }
        printf("\n");
        
        // Show ASCII representation for non-zero bytes
        printf("      ASCII preview:\n        ");
        for (size_t i = 0; i < bytes_to_read; i++) {
            if (isprint(buffer[i])) printf("%c", buffer[i]);
            else printf(".");
            if ((i + 1) % 64 == 0) printf("\n        ");
        }
        printf("\n");
        
        // Analyze byte patterns for common shellcode signatures
        int consecutive_nops = 0;
        int int3_count = 0;
        for (size_t i = 0; i < bytes_to_read; i++) {
            if (buffer[i] == 0x90) consecutive_nops++; // NOP
            else consecutive_nops = 0;
            
            if (buffer[i] == 0xCC) int3_count++; // INT3 (breakpoint)
        }
        
        if (consecutive_nops >= 8) {
            printf("      🚩 Suspicious: Long NOP sled detected (%d consecutive NOPs)\n", consecutive_nops);
        }
        if (int3_count >= 3) {
            printf("      🚩 Suspicious: Multiple INT3 instructions (%d found) - possible anti-debug\n", int3_count);
        }
    }
    
    free(buffer);
}

void print_machine_type(uint16_t machine) {
    printf("  Machine: 0x%04X", machine);
    
    // Use Windows constants for comparison
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:
            printf(" (x86 32-bit)");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf(" (x64 64-bit)");
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            printf(" (ARM64)");
            break;
        case 0x0162:
            printf(" (R3000)");
            break;
        case 0x0166:
            printf(" (R4000)");
            break;
        case 0x0168:
            printf(" (R10000)");
            break;
        case 0x0184:
            printf(" (Alpha AXP)");
            break;
        case 0x01A2:
            printf(" (Hitachi SH3)");
            break;
        case 0x01B2:
            printf(" (Hitachi SH4)");
            break;
        default:
            printf(" (Unknown)");
            break;
    }
    printf("\n");
}

void print_characteristics(uint16_t characteristics) {
    printf("  Characteristics: 0x%04X\n", characteristics);
    if (characteristics & 0x0001) printf("    - RELOCS_STRIPPED\n");
    if (characteristics & 0x0002) printf("    - EXECUTABLE_IMAGE\n");
    if (characteristics & 0x0004) printf("    - LINE_NUMS_STRIPPED\n");
    if (characteristics & 0x0008) printf("    - LOCAL_SYMS_STRIPPED\n");
    if (characteristics & 0x0010) printf("    - AGGRESSIVE_WS_TRIM\n");
    if (characteristics & 0x0020) printf("    - LARGE_ADDRESS_AWARE\n");
    if (characteristics & 0x0080) printf("    - BYTES_REVERSED_LO\n");
    if (characteristics & 0x0100) printf("    - 32BIT_MACHINE\n");
    if (characteristics & 0x0200) printf("    - DEBUG_STRIPPED\n");
    if (characteristics & 0x0400) printf("    - REMOVABLE_RUN_FROM_SWAP\n");
    if (characteristics & 0x0800) printf("    - NET_RUN_FROM_SWAP\n");
    if (characteristics & 0x1000) printf("    - SYSTEM\n");
    if (characteristics & 0x2000) printf("    - DLL\n");
    if (characteristics & 0x4000) printf("    - UP_SYSTEM_ONLY\n");
    if (characteristics & 0x8000) printf("    - BYTES_REVERSED_HI\n");
}

// Parse command line arguments
typedef struct {
    int real_analysis;
    const char* filename;
} CommandLineArgs;

CommandLineArgs parse_arguments(int argc, char** argv) {
    CommandLineArgs args = {0};
    
    if (argc == 3 && strcmp(argv[1], "--real") == 0) {
        // Real analysis mode: coff_parser_enhanced.exe --real filename.obj
        args.real_analysis = 1;
        args.filename = argv[2];
    } else if (argc == 2) {
        // Enhanced analysis mode: coff_parser_enhanced.exe filename.obj
        args.real_analysis = 0;
        args.filename = argv[1];
    }
    
    return args;
}

// Enhanced analysis mode
int perform_enhanced_analysis(const char* filename) {
    printf("[+] COFF File Analyzer - Enhanced Threat Assessment\n");
    printf("[+] Target: %s\n\n", filename);
    
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    COFFHeader hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        fprintf(stderr, "Failed to read COFF header\n");
        fclose(f);
        return 1;
    }

    printf("[HEADER ANALYSIS]\n");
    print_machine_type(hdr.Machine);
    printf("  Sections: %u\n", hdr.NumberOfSections);
    printf("  Timestamp: 0x%08X\n", hdr.TimeDateStamp);
    printf("  Symbols: %u\n", hdr.NumberOfSymbols);
    print_characteristics(hdr.Characteristics);

    long sect_offset = sizeof(COFFHeader) + hdr.SizeOfOptionalHeader;
    if (fseek(f, sect_offset, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    printf("\n[SECTION ANALYSIS]\n");
    SectionHeader *sections = malloc(sizeof(SectionHeader) * hdr.NumberOfSections);
    
    for (int i = 0; i < hdr.NumberOfSections; i++) {
        if (fread(&sections[i], sizeof(SectionHeader), 1, f) != 1) {
            fprintf(stderr, "Failed to read section %d\n", i);
            break;
        }
        
        char name[9]; 
        memcpy(name, sections[i].Name, 8); 
        name[8] = 0;
        
        printf("  [Section %d] %s\n", i, name);
        printf("    VirtualSize: 0x%08X\n", sections[i].VirtualSize);
        printf("    VirtualAddress: 0x%08X\n", sections[i].VirtualAddress);
        printf("    RawDataSize: 0x%08X\n", sections[i].SizeOfRawData);
        printf("    RawDataPtr:  0x%08X\n", sections[i].PointerToRawData);
        
        analyze_section_threat(&sections[i]);
        parse_relocations(f, &sections[i]);
        
        // Only dump first 64 bytes of each section
        if (sections[i].SizeOfRawData > 0) {
            dump_section_hex(f, &sections[i], 64);
        }
        printf("\n");
    }

    free(sections);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    printf("[+] Enhanced COFF Parser - Comprehensive Analysis Tool\n");
    printf("[+] Educational Purpose Only - Authorized Analysis Only\n");
    printf("==================================================\n");
    
    // Parse command line arguments
    CommandLineArgs args = parse_arguments(argc, argv);
    
    if (args.real_analysis) {
        // Real analysis using Windows API
        AnalyzeRealCOFF(args.filename);
    } else if (args.filename) {
        // Enhanced analysis mode
        return perform_enhanced_analysis(args.filename);
    } else {
        // Usage information
        printf("Usage:\n");
        printf("  Enhanced Analysis: %s <coff_file.obj>\n", argv[0]);
        printf("  Real Analysis:     %s --real <coff_file.obj>\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s payload.obj\n", argv[0]);
        printf("  %s --real payload.obj\n", argv[0]);
        printf("\nModes:\n");
        printf("  Enhanced Analysis: Cross-platform analysis with threat assessment\n");
        printf("  Real Analysis:     Windows API-based analysis with memory mapping\n");
        return 2;
    }
    
    return 0;
}