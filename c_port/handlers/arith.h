#ifndef HANDLERS_ARITH_H
#define HANDLERS_ARITH_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_add_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_add_r_rm(CONTEXT *ctx, uint8_t *ip);
int handle_add_acc_imm(CONTEXT *ctx, uint8_t *ip);
int handle_sub_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_sub_r_rm(CONTEXT *ctx, uint8_t *ip);
int handle_sub_acc_imm(CONTEXT *ctx, uint8_t *ip);
int handle_cmp_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_cmp_r_rm(CONTEXT *ctx, uint8_t *ip);
int handle_cmp_acc_imm(CONTEXT *ctx, uint8_t *ip);
int handle_group1(CONTEXT *ctx, uint8_t *ip);
int handle_group3(CONTEXT *ctx, uint8_t *ip);
int handle_inc_dec(CONTEXT *ctx, uint8_t *ip);
int handle_group2_shift(CONTEXT *ctx, uint8_t *ip);
int handle_imul2(CONTEXT *ctx, uint8_t *ip);
int handle_imul3(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_ARITH_H */
