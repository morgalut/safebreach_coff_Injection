#include <windows.h>

// Position-independent shellcode with basic functionality
// This is a more complete example but still safe
__declspec(naked) void advanced_shellcode() {
    __asm {
        push ebp
        mov ebp, esp
        
        // Simple position-independent code pattern
        call get_self
        get_self:
        pop ebx
        
        // Safe operations - no hardcoded addresses
        xor eax, eax    // Success code
        mov esp, ebp
        pop ebp
        ret
    }
}

// Safe message box shellcode (conceptual - would need API resolution)
__declspec(naked) void message_shellcode() {
    __asm {
        // In real shellcode, you would:
        // 1. Find kernel32.dll base
        // 2. Resolve LoadLibrary and GetProcAddress  
        // 3. Load user32.dll
        // 4. Call MessageBoxA
        // For now, just return safely
        
        xor eax, eax    // Return 0
        ret
    }
}

#pragma comment(linker, "/EXPORT:advanced_shellcode")
#pragma comment(linker, "/EXPORT:message_shellcode")