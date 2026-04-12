#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "veh.h"

int main(int argc, char** argv)
{
    const char* path = (argc > 1) ? argv[1] : "windows-x86_64-nosyscall.bin";

    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Allocate RW memory (no execute). Shellcode lives here but the page is
       NOT marked executable -- VEH catches the access violation and emulates. */
    void* buf = VirtualAlloc(NULL, (size_t)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { fprintf(stderr, "VirtualAlloc failed\n"); fclose(f); return 1; }

    fread(buf, 1, (size_t)size, f);
    fclose(f);

    printf("Loaded %s: %ld bytes at %p (PAGE_READWRITE, no execute)\n", path, size, buf);

    /* Allocate a zero-initialized stack for the emulated shellcode. */
    g_emu_stack_size = 256 * 1024;
    g_emu_stack = VirtualAlloc(NULL, g_emu_stack_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_emu_stack) { fprintf(stderr, "Stack alloc failed\n"); return 1; }

    if (!veh_init(buf, (size_t)size)) {
        fprintf(stderr, "veh_init failed\n");
        return 1;
    }

    printf("Jumping into buffer (expecting fault)...\n");
    fflush(stdout);

    /* Call the buffer as a function. The CPU will fault (not executable),
       VEH catches it, and the emulator takes over. */
    typedef void (*shellcode_fn)(void);
    ((shellcode_fn)buf)();

    printf("Execution finished.\n");
    veh_uninit();
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
