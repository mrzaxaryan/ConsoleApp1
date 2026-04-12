#ifndef NORWX_VEH_H
#define NORWX_VEH_H

#include <windows.h>
#include <stdint.h>

extern void*  g_code_base;
extern size_t g_code_size;
extern void*  g_emu_stack;
extern size_t g_emu_stack_size;

int  veh_init(void* code_base, size_t code_size);
void veh_uninit(void);

static inline int veh_in_region(uint64_t addr) {
    return (uintptr_t)addr >= (uintptr_t)g_code_base
        && (uintptr_t)addr <  (uintptr_t)g_code_base + g_code_size;
}

#endif /* NORWX_VEH_H */
