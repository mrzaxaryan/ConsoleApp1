#ifndef HANDLERS_TWO_BYTE_H
#define HANDLERS_TWO_BYTE_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_xadd(CONTEXT *ctx, uint8_t *ip);
int handle_cmpxchg(CONTEXT *ctx, uint8_t *ip);
int handle_shld(CONTEXT *ctx, uint8_t *ip);
int handle_shrd(CONTEXT *ctx, uint8_t *ip);
int handle_ud2(CONTEXT *ctx, uint8_t *ip);
int handle_cpuid(CONTEXT *ctx, uint8_t *ip);
int handle_rdtsc(CONTEXT *ctx, uint8_t *ip);
int handle_syscall(CONTEXT *ctx, uint8_t *ip);
int handle_popcnt(CONTEXT *ctx, uint8_t *ip);
int handle_lzcnt(CONTEXT *ctx, uint8_t *ip);
int handle_tzcnt(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_TWO_BYTE_H */
