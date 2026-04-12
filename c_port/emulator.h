#ifndef NORWX_EMULATOR_H
#define NORWX_EMULATOR_H

#include <windows.h>
#include <stdint.h>

/* Emulate one instruction at ctx->Rip. Updates ctx in place.
   Returns 1 on success, 0 on unsupported instruction. */
int emulate_one(CONTEXT* ctx);

/* REX-prefixed dispatch (called internally by emulate_one). */
int emulate_one_rex(CONTEXT* ctx, uint8_t* ip);

#endif /* NORWX_EMULATOR_H */
