#ifndef HANDLERS_SSE_H
#define HANDLERS_SSE_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

/* 16 XMM registers, each 128-bit (16 bytes) */
uint8_t *get_xmm(int index);

int handle_mov_xmm_load(CONTEXT *ctx, uint8_t *ip);
int handle_mov_xmm_store(CONTEXT *ctx, uint8_t *ip);
int handle_movdq_load(CONTEXT *ctx, uint8_t *ip);
int handle_movdq_store(CONTEXT *ctx, uint8_t *ip);
int handle_movd_to_xmm(CONTEXT *ctx, uint8_t *ip);
int handle_movd_from_xmm(CONTEXT *ctx, uint8_t *ip);
int handle_xor_xmm(CONTEXT *ctx, uint8_t *ip);
int handle_mov_scalar(CONTEXT *ctx, uint8_t *ip);
int handle_mov_low_high(CONTEXT *ctx, uint8_t *ip);
int handle_fxsave_ldmxcsr(CONTEXT *ctx, uint8_t *ip);
int handle_movnt(CONTEXT *ctx, uint8_t *ip);
int handle_sse_arith(CONTEXT *ctx, uint8_t *ip);
int handle_sse_logic(CONTEXT *ctx, uint8_t *ip);
int handle_cvt_int_to_float(CONTEXT *ctx, uint8_t *ip);
int handle_cvt_float_to_int(CONTEXT *ctx, uint8_t *ip);
int handle_ucomisd(CONTEXT *ctx, uint8_t *ip);
int handle_shufps(CONTEXT *ctx, uint8_t *ip);
int handle_cmpps(CONTEXT *ctx, uint8_t *ip);
int handle_unpack(CONTEXT *ctx, uint8_t *ip);
int handle_pshufd(CONTEXT *ctx, uint8_t *ip);
int handle_movmskps(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_SSE_H */
