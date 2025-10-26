// coff_parser_enhanced.c
// Enhanced COFF analysis with section characteristics, relocation parsing, and threat assessment

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

// Section characteristic flags
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

void analyze_section_threat(SectionHeader *sh) {
    char name[9]; 
    memcpy(name, sh->Name, 8); 
    name[8] = 0;
    
    printf("    [THREAT ASSESSMENT] Section '%s':\n", name);
    
    // Check for executable sections
    if (sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
        printf("      ⚠️  EXECUTABLE section detected\n");
        if (sh->Characteristics & IMAGE_SCN_MEM_WRITE) {
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
    
    // Suspicious characteristics
    if (sh->SizeOfRawData == 0 && sh->VirtualSize > 0) {
        printf("      🚩 Zero raw size but non-zero virtual size - potential hollowing\n");
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
    }
    
    free(buffer);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.obj>\n", argv[0]);
        return 2;
    }
    
    printf("[+] COFF File Analyzer - Enhanced Threat Assessment\n");
    printf("[+] Target: %s\n\n", argv[1]);
    
    FILE *f = fopen(argv[1], "rb");
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
    printf("  Machine: 0x%04X\n", hdr.Machine);
    printf("  Sections: %u\n", hdr.NumberOfSections);
    printf("  Timestamp: 0x%08X\n", hdr.TimeDateStamp);
    printf("  Symbols: %u\n", hdr.NumberOfSymbols);
    printf("  Characteristics: 0x%04X\n", hdr.Characteristics);

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