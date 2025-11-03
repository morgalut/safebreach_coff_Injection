#include <windows.h>

// Simple shellcode for demonstration
__declspec(naked) void shellcode() {
    __asm {
        // XOR register for null termination
        xor ebx, ebx
        
        // Push "Hello from injected shellcode!" string
        push ebx                // Null terminator
        push 0x21656e6f         // "!eno"
        push 0x63206564         // "c ed"
        push 0x6f6a6e65         // "ojne"
        push 0x74206672         // "t fr"
        push 0x6f6d2065         // "om e"
        push 0x6c6c6548         // "lleH"
        mov eax, esp            // Store string pointer in EAX
        
        // Call MessageBoxA parameters
        push ebx                // MB_OK
        push eax                // Message string
        push eax                // Title string  
        push ebx                // hWnd = NULL
        
        // Call MessageBoxA - note: in real shellcode you'd need to resolve this dynamically
        mov eax, 0x757a4500     // This would normally be resolved dynamically
        call eax
        
        // Exit thread
        push ebx                // Exit code 0
        mov eax, 0x757a4000     // This would normally be resolved dynamically  
        call eax
        
        ret
    }
}

// Export the function
#pragma comment(linker, "/EXPORT:shellcode")