#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== Test Target Application ===\n");
    printf("PID: %d\n", GetCurrentProcessId());
    printf("This is a 32-bit test process for injection testing.\n");
    printf("The process will wait for 60 seconds...\n\n");
    
    for (int i = 60; i > 0; i--) {
        printf("\rWaiting %d seconds... (Press Ctrl+C to exit)", i);
        fflush(stdout);
        Sleep(1000);
    }
    
    printf("\n\nTest completed. Exiting...\n");
    return 0;
}