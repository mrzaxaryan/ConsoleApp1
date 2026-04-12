#ifndef HANDLERS_STACK_H
#define HANDLERS_STACK_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_push_reg(CONTEXT *ctx, uint8_t *ip);
int handle_pop_reg(CONTEXT *ctx, uint8_t *ip);
int handle_push_imm8(CONTEXT *ctx, uint8_t *ip);
int handle_push_imm32(CONTEXT *ctx, uint8_t *ip);
int handle_pop_rm64(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_STACK_H */
