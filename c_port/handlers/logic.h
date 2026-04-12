#ifndef HANDLERS_LOGIC_H
#define HANDLERS_LOGIC_H

#include <windows.h>
#include <stdint.h>
#include "../decoder.h"
#include "../regs.h"
#include "../flags.h"

int handle_logic_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_logic_r_rm(CONTEXT *ctx, uint8_t *ip);
int handle_logic_acc_imm(CONTEXT *ctx, uint8_t *ip);
int handle_test_rm_r(CONTEXT *ctx, uint8_t *ip);
int handle_test_acc_imm(CONTEXT *ctx, uint8_t *ip);

#endif /* HANDLERS_LOGIC_H */
