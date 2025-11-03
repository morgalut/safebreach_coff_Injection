#include <windows.h>

// Minimal position-independent shellcode that actually works
// This shellcode simply returns 0 - safe and reliable
__declspec(naked) void shellcode() {
    __asm {
        // Safe minimal shellcode - just return 0
        xor eax, eax    // Set return value to 0 (success)
        ret             // Return from thread
    }
}

// Alternative: Shellcode that calls OutputDebugString (more useful but still safe)
__declspec(naked) void debug_shellcode() {
    __asm {
        // This would need proper API resolution in real scenarios
        // For now, just return safely
        xor eax, eax
        ret
    }
}

// Export the functions
#pragma comment(linker, "/EXPORT:shellcode")
#pragma comment(linker, "/EXPORT:debug_shellcode")