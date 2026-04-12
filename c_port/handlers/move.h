#ifndef HANDLERS_MOVE_H
#define HANDLERS_MOVE_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_mov_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_mov_r_rm(CONTEXT *ctx, uint8_t *ip);
int handle_mov_rm_imm(CONTEXT *ctx, uint8_t *ip);
int handle_mov_reg_imm(CONTEXT *ctx, uint8_t *ip);
int handle_lea(CONTEXT *ctx, uint8_t *ip);
int handle_xchg(CONTEXT *ctx, uint8_t *ip);
int handle_xchg_acc_reg(CONTEXT *ctx, uint8_t *ip);
int handle_movzx(CONTEXT *ctx, uint8_t *ip);
int handle_movsx(CONTEXT *ctx, uint8_t *ip);
int handle_movsxd(CONTEXT *ctx, uint8_t *ip);
int handle_cmovcc(CONTEXT *ctx, uint8_t *ip);
int handle_setcc(CONTEXT *ctx, uint8_t *ip);
int handle_bswap(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_MOVE_H */
