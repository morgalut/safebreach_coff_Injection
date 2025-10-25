// coff_loader_dll.c
// A small DLL that would be used by the demo to represent host APIs.
// Build as a DLL and load locally only. Does not perform injection.

#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void host_emit(const char *msg) {
    // benign helper - prints to stdout
    printf("[DLL host_emit] %s\n", msg ? msg : "(null)");
}

__declspec(dllexport) void host_whoami(void) {
    // benign helper - print local user name
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        printf("[DLL host_whoami] Local user: %s\n", username);
    } else {
        printf("[DLL host_whoami] Could not get username\n");
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // no harmful action
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
