#ifndef HANDLERS_CONTROL_H
#define HANDLERS_CONTROL_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_call_rel32(CONTEXT *ctx, uint8_t *ip);
int handle_ret(CONTEXT *ctx, uint8_t *ip);
int handle_leave(CONTEXT *ctx, uint8_t *ip);
int handle_enter(CONTEXT *ctx, uint8_t *ip);
int handle_jmp(CONTEXT *ctx, uint8_t *ip);
int handle_jcc_short(CONTEXT *ctx, uint8_t *ip);
int handle_jcc_near(CONTEXT *ctx, uint8_t *ip);
int handle_group5(CONTEXT *ctx, uint8_t *ip);
int handle_loop(CONTEXT *ctx, uint8_t *ip);
int handle_int3(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_CONTROL_H */
