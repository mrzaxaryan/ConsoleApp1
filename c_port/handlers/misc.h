#ifndef HANDLERS_MISC_H
#define HANDLERS_MISC_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_nop(CONTEXT *ctx, uint8_t *ip);
int handle_multi_byte_nop(CONTEXT *ctx, uint8_t *ip);
int handle_cbw_cwde_cdqe(CONTEXT *ctx, uint8_t *ip);
int handle_cwd_cdq_cqo(CONTEXT *ctx, uint8_t *ip);
int handle_clear_set_carry(CONTEXT *ctx, uint8_t *ip);
int handle_clear_set_direction(CONTEXT *ctx, uint8_t *ip);
int handle_lahf(CONTEXT *ctx, uint8_t *ip);
int handle_sahf(CONTEXT *ctx, uint8_t *ip);
int handle_gs_prefix(CONTEXT *ctx, uint8_t *ip);
int handle_bit_test(CONTEXT *ctx, uint8_t *ip);
int handle_bit_test_imm(CONTEXT *ctx, uint8_t *ip);
int handle_bsf_bsr(CONTEXT *ctx, uint8_t *ip);
int handle_string_op(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_MISC_H */
