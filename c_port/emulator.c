/* Full x64 instruction emulator dispatch -- C port of EmulatorX64.cs */
#include "emulator.h"
#include "decoder.h"
#include "regs.h"
#include "flags.h"
#include "handlers/move.h"
#include "handlers/arith.h"
#include "handlers/logic.h"
#include "handlers/control.h"
#include "handlers/stack.h"
#include "handlers/misc.h"
#include "handlers/two_byte.h"
#include "handlers/sse.h"
#include <stdio.h>

static int handle_two_byte(CONTEXT* ctx, uint8_t* ip);

int emulate_one(CONTEXT* ctx)
{
    uint8_t* ip = (uint8_t*)(uintptr_t)ctx->Rip;
    uint8_t opcode = *ip;

    switch (opcode)
    {
    /* NOP */
    case 0x90: return handle_nop(ctx, ip);

    /* PUSH r64 (50-57), POP r64 (58-5F) */
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        return handle_push_reg(ctx, ip);
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        return handle_pop_reg(ctx, ip);

    /* PUSH imm / POP r/m */
    case 0x6A: return handle_push_imm8(ctx, ip);
    case 0x68: return handle_push_imm32(ctx, ip);
    case 0x8F: return handle_pop_rm64(ctx, ip);

    /* MOV */
    case 0x88: case 0x89: return handle_mov_rm_r(ctx, ip);
    case 0x8A: case 0x8B: return handle_mov_r_rm(ctx, ip);
    case 0xC6: case 0xC7: return handle_mov_rm_imm(ctx, ip);
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        return handle_mov_reg_imm(ctx, ip);

    /* LEA */
    case 0x8D: return handle_lea(ctx, ip);

    /* MOVSXD */
    case 0x63: return handle_movsxd(ctx, ip);

    /* ADD */
    case 0x00: case 0x01: return handle_add_rm_r(ctx, ip);
    case 0x02: case 0x03: return handle_add_r_rm(ctx, ip);
    case 0x04: case 0x05: return handle_add_acc_imm(ctx, ip);

    /* ADC (10-15) */
    case 0x10: case 0x11: return handle_add_rm_r(ctx, ip);
    case 0x12: case 0x13: return handle_add_r_rm(ctx, ip);
    case 0x14: case 0x15: return handle_add_acc_imm(ctx, ip);

    /* SBB (18-1D) */
    case 0x18: case 0x19: return handle_sub_rm_r(ctx, ip);
    case 0x1A: case 0x1B: return handle_sub_r_rm(ctx, ip);
    case 0x1C: case 0x1D: return handle_sub_acc_imm(ctx, ip);

    /* OR */
    case 0x08: case 0x09: return handle_logic_rm_r(ctx, ip);
    case 0x0A: case 0x0B: return handle_logic_r_rm(ctx, ip);
    case 0x0C: case 0x0D: return handle_logic_acc_imm(ctx, ip);

    /* AND */
    case 0x20: case 0x21: return handle_logic_rm_r(ctx, ip);
    case 0x22: case 0x23: return handle_logic_r_rm(ctx, ip);
    case 0x24: case 0x25: return handle_logic_acc_imm(ctx, ip);

    /* SUB */
    case 0x28: case 0x29: return handle_sub_rm_r(ctx, ip);
    case 0x2A: case 0x2B: return handle_sub_r_rm(ctx, ip);
    case 0x2C: case 0x2D: return handle_sub_acc_imm(ctx, ip);

    /* XOR */
    case 0x30: case 0x31: return handle_logic_rm_r(ctx, ip);
    case 0x32: case 0x33: return handle_logic_r_rm(ctx, ip);
    case 0x34: case 0x35: return handle_logic_acc_imm(ctx, ip);

    /* CMP */
    case 0x38: case 0x39: return handle_cmp_rm_r(ctx, ip);
    case 0x3A: case 0x3B: return handle_cmp_r_rm(ctx, ip);
    case 0x3C: case 0x3D: return handle_cmp_acc_imm(ctx, ip);

    /* Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm */
    case 0x80: case 0x81: case 0x83: return handle_group1(ctx, ip);

    /* TEST */
    case 0x84: case 0x85: return handle_test_rm_r(ctx, ip);
    case 0xA8: case 0xA9: return handle_test_acc_imm(ctx, ip);

    /* XCHG */
    case 0x86: case 0x87: return handle_xchg(ctx, ip);
    case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x96: case 0x97:
        return handle_xchg_acc_reg(ctx, ip);

    /* CBW/CWDE/CDQE and CWD/CDQ/CQO */
    case 0x98: return handle_cbw_cwde_cdqe(ctx, ip);
    case 0x99: return handle_cwd_cdq_cqo(ctx, ip);

    /* SAHF/LAHF */
    case 0x9E: return handle_sahf(ctx, ip);
    case 0x9F: return handle_lahf(ctx, ip);

    /* String operations */
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
        return handle_string_op(ctx, ip);

    /* Group 2: Shift/rotate */
    case 0xC0: case 0xC1: case 0xD0: case 0xD1:
    case 0xD2: case 0xD3:
        return handle_group2_shift(ctx, ip);

    /* Control flow */
    case 0xE8: return handle_call_rel32(ctx, ip);
    case 0xC3: case 0xC2: return handle_ret(ctx, ip);
    case 0xC9: return handle_leave(ctx, ip);
    case 0xC8: return handle_enter(ctx, ip);
    case 0xE9: case 0xEB: return handle_jmp(ctx, ip);
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        return handle_jcc_short(ctx, ip);
    case 0xE0: case 0xE1: case 0xE2: return handle_loop(ctx, ip);
    case 0xCC: return handle_int3(ctx, ip);

    /* INC/DEC r/m8 */
    case 0xFE: return handle_inc_dec(ctx, ip);

    /* Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV */
    case 0xF6: case 0xF7: return handle_group3(ctx, ip);

    /* Group 5: INC/DEC/CALL/JMP/PUSH r/m */
    case 0xFF: return handle_group5(ctx, ip);

    /* IMUL r, r/m, imm */
    case 0x69: case 0x6B: return handle_imul3(ctx, ip);

    /* Flag manipulation */
    case 0xF5: case 0xF8: case 0xF9: return handle_clear_set_carry(ctx, ip);
    case 0xFC: case 0xFD: return handle_clear_set_direction(ctx, ip);

    /* PUSHF/POPF */
    case 0x9C:
        ctx->Rsp -= 8;
        *(uint64_t*)(uintptr_t)ctx->Rsp = ctx->EFlags;
        ctx->Rip += 1;
        return 1;
    case 0x9D:
        ctx->EFlags = (uint32_t)(*(uint64_t*)(uintptr_t)ctx->Rsp);
        ctx->Rsp += 8;
        ctx->Rip += 1;
        return 1;

    /* MOV moffs (A0-A3) */
    case 0xA0: {
        uint64_t moffs = *(uint64_t*)(ip + 1);
        uint8_t val = *(uint8_t*)(uintptr_t)moffs;
        ctx->Rax = (ctx->Rax & ~0xFFULL) | val;
        ctx->Rip += 9;
        return 1;
    }
    case 0xA1: {
        uint64_t moffs = *(uint64_t*)(ip + 1);
        ctx->Rax = *(uint64_t*)(uintptr_t)moffs;
        ctx->Rip += 9;
        return 1;
    }
    case 0xA2: {
        uint64_t moffs = *(uint64_t*)(ip + 1);
        *(uint8_t*)(uintptr_t)moffs = (uint8_t)ctx->Rax;
        ctx->Rip += 9;
        return 1;
    }
    case 0xA3: {
        uint64_t moffs = *(uint64_t*)(ip + 1);
        *(uint64_t*)(uintptr_t)moffs = ctx->Rax;
        ctx->Rip += 9;
        return 1;
    }

    /* JRCXZ (E3) */
    case 0xE3: {
        int8_t rel8 = *(int8_t*)(ip + 1);
        uint64_t next = ctx->Rip + 2;
        uint64_t target = (uint64_t)((int64_t)next + rel8);
        ctx->Rip = (ctx->Rcx == 0) ? target : next;
        return 1;
    }

    /* INT imm8 (CD) */
    case 0xCD:
        ctx->Rip += 2;
        return 1;

    /* HLT (F4) */
    case 0xF4:
        return 0;

    /* GS prefix (65) */
    case 0x65: return handle_gs_prefix(ctx, ip);

    /* FS prefix (64) -- skip */
    case 0x64:
        ctx->Rip += 1;
        return 1;

    /* LOCK prefix (F0) -- transparent, re-dispatch on next byte */
    case 0xF0: {
        uint8_t next = ip[1];
        if ((next & 0xF0) == 0x40) return emulate_one_rex(ctx, ip);
        if (next == 0x0F) return handle_two_byte(ctx, ip);
        switch (next) {
        case 0x00: case 0x01: return handle_add_rm_r(ctx, ip);
        case 0x08: case 0x09: return handle_logic_rm_r(ctx, ip);
        case 0x20: case 0x21: return handle_logic_rm_r(ctx, ip);
        case 0x28: case 0x29: return handle_sub_rm_r(ctx, ip);
        case 0x30: case 0x31: return handle_logic_rm_r(ctx, ip);
        case 0x80: case 0x81: case 0x83: return handle_group1(ctx, ip);
        case 0x86: case 0x87: return handle_xchg(ctx, ip);
        case 0xFE: return handle_inc_dec(ctx, ip);
        case 0xFF: return handle_group5(ctx, ip);
        case 0xF6: case 0xF7: return handle_group3(ctx, ip);
        default: return 0;
        }
    }

    /* Operand-size prefix (0x66) */
    case 0x66: {
        int o = 1;
        uint8_t n = ip[o];
        if ((n & 0xF0) == 0x40) o++;
        n = ip[o];
        switch (n) {
        case 0x88: case 0x89: return handle_mov_rm_r(ctx, ip);
        case 0x8A: case 0x8B: return handle_mov_r_rm(ctx, ip);
        case 0xC6: case 0xC7: return handle_mov_rm_imm(ctx, ip);
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            return handle_mov_reg_imm(ctx, ip);
        case 0x80: case 0x81: case 0x83: return handle_group1(ctx, ip);
        case 0x84: case 0x85: return handle_test_rm_r(ctx, ip);
        case 0xA8: case 0xA9: return handle_test_acc_imm(ctx, ip);
        case 0x00: case 0x01: return handle_add_rm_r(ctx, ip);
        case 0x02: case 0x03: return handle_add_r_rm(ctx, ip);
        case 0x28: case 0x29: return handle_sub_rm_r(ctx, ip);
        case 0x2A: case 0x2B: return handle_sub_r_rm(ctx, ip);
        case 0x38: case 0x39: return handle_cmp_rm_r(ctx, ip);
        case 0x3A: case 0x3B: return handle_cmp_r_rm(ctx, ip);
        case 0x08: case 0x09: case 0x20: case 0x21:
        case 0x30: case 0x31:
            return handle_logic_rm_r(ctx, ip);
        case 0x0A: case 0x0B: case 0x22: case 0x23:
        case 0x32: case 0x33:
            return handle_logic_r_rm(ctx, ip);
        case 0xC0: case 0xC1: case 0xD0: case 0xD1:
        case 0xD2: case 0xD3:
            return handle_group2_shift(ctx, ip);
        case 0xF6: case 0xF7: return handle_group3(ctx, ip);
        case 0xFE: return handle_inc_dec(ctx, ip);
        case 0xFF: return handle_group5(ctx, ip);
        case 0x86: case 0x87: return handle_xchg(ctx, ip);
        case 0x8D: return handle_lea(ctx, ip);
        case 0x0F: return handle_two_byte(ctx, ip);
        case 0x90: return handle_nop(ctx, ip);
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            return handle_push_reg(ctx, ip);
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return handle_pop_reg(ctx, ip);
        default:
            fprintf(stderr, "UNSUPPORTED 66+0x%02X at RIP=0x%llx\n", n, (unsigned long long)ctx->Rip);
            return 0;
        }
    }

    /* Address-size prefix (0x67) */
    case 0x67: {
        uint8_t n = ip[1];
        if ((n & 0xF0) == 0x40) return emulate_one_rex(ctx, ip);
        if (n == 0x0F) return handle_two_byte(ctx, ip);
        switch (n) {
        case 0x89: return handle_mov_rm_r(ctx, ip);
        case 0x8B: return handle_mov_r_rm(ctx, ip);
        case 0x8D: return handle_lea(ctx, ip);
        case 0xA4: case 0xA5: case 0xAA: case 0xAB:
            return handle_string_op(ctx, ip);
        default: return 0;
        }
    }

    /* REP/REPNE prefixes (F2/F3) */
    case 0xF2: case 0xF3: {
        int o = 1;
        if ((ip[o] & 0xF0) == 0x40) o++;
        uint8_t n = ip[o];
        switch (n) {
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD:
        case 0xAE: case 0xAF:
            return handle_string_op(ctx, ip);
        case 0x0F: return handle_two_byte(ctx, ip);
        default: return 0;
        }
    }

    /* REX prefixes (0x40-0x4F) */
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        return emulate_one_rex(ctx, ip);

    /* Two-byte opcode escape (0F) */
    case 0x0F: return handle_two_byte(ctx, ip);

    default:
        fprintf(stderr, "UNSUPPORTED: 0x%02X at RIP=0x%llx\n", opcode, (unsigned long long)ctx->Rip);
        return 0;
    }
}

/* REX-prefixed dispatch */
int emulate_one_rex(CONTEXT* ctx, uint8_t* ip)
{
    uint8_t op2 = ip[1];
    switch (op2) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        return handle_push_reg(ctx, ip);
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        return handle_pop_reg(ctx, ip);
    case 0x88: case 0x89: return handle_mov_rm_r(ctx, ip);
    case 0x8A: case 0x8B: return handle_mov_r_rm(ctx, ip);
    case 0xC6: case 0xC7: return handle_mov_rm_imm(ctx, ip);
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        return handle_mov_reg_imm(ctx, ip);
    case 0x8D: return handle_lea(ctx, ip);
    case 0x63: return handle_movsxd(ctx, ip);
    case 0x00: case 0x01: return handle_add_rm_r(ctx, ip);
    case 0x02: case 0x03: return handle_add_r_rm(ctx, ip);
    case 0x04: case 0x05: return handle_add_acc_imm(ctx, ip);
    case 0x08: case 0x09: return handle_logic_rm_r(ctx, ip);
    case 0x0A: case 0x0B: return handle_logic_r_rm(ctx, ip);
    case 0x10: case 0x11: return handle_add_rm_r(ctx, ip);   /* ADC */
    case 0x12: case 0x13: return handle_add_r_rm(ctx, ip);
    case 0x14: case 0x15: return handle_add_acc_imm(ctx, ip);
    case 0x18: case 0x19: return handle_sub_rm_r(ctx, ip);   /* SBB */
    case 0x1A: case 0x1B: return handle_sub_r_rm(ctx, ip);
    case 0x1C: case 0x1D: return handle_sub_acc_imm(ctx, ip);
    case 0x20: case 0x21: return handle_logic_rm_r(ctx, ip);
    case 0x22: case 0x23: return handle_logic_r_rm(ctx, ip);
    case 0x28: case 0x29: return handle_sub_rm_r(ctx, ip);
    case 0x2A: case 0x2B: return handle_sub_r_rm(ctx, ip);
    case 0x2C: case 0x2D: return handle_sub_acc_imm(ctx, ip);
    case 0x30: case 0x31: return handle_logic_rm_r(ctx, ip);
    case 0x32: case 0x33: return handle_logic_r_rm(ctx, ip);
    case 0x38: case 0x39: return handle_cmp_rm_r(ctx, ip);
    case 0x3A: case 0x3B: return handle_cmp_r_rm(ctx, ip);
    case 0x3C: case 0x3D: return handle_cmp_acc_imm(ctx, ip);
    case 0x80: case 0x81: case 0x83: return handle_group1(ctx, ip);
    case 0x84: case 0x85: return handle_test_rm_r(ctx, ip);
    case 0x86: case 0x87: return handle_xchg(ctx, ip);
    case 0x98: return handle_cbw_cwde_cdqe(ctx, ip);
    case 0x99: return handle_cwd_cdq_cqo(ctx, ip);
    case 0xC0: case 0xC1: case 0xD0: case 0xD1:
    case 0xD2: case 0xD3:
        return handle_group2_shift(ctx, ip);
    case 0xFE: return handle_inc_dec(ctx, ip);
    case 0xF6: case 0xF7: return handle_group3(ctx, ip);
    case 0xFF: return handle_group5(ctx, ip);
    case 0x69: case 0x6B: return handle_imul3(ctx, ip);
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
        return handle_string_op(ctx, ip);
    case 0x0F: return handle_two_byte(ctx, ip);
    default:
        fprintf(stderr, "UNSUPPORTED REX+0x%02X at RIP=0x%llx\n", op2, (unsigned long long)ctx->Rip);
        return 0;
    }
}

/* Two-byte opcode dispatch (0F xx) */
static int handle_two_byte(CONTEXT* ctx, uint8_t* ip)
{
    int p = 0;
    while (ip[p] != 0x0F) { if (p > 5) return 0; p++; }
    uint8_t op2 = ip[p + 1];

    switch (op2) {
    /* Jcc near (0F 80-8F) */
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        return handle_jcc_near(ctx, ip);

    /* SETcc (0F 90-9F) */
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        return handle_setcc(ctx, ip);

    /* CMOVcc (0F 40-4F) */
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        return handle_cmovcc(ctx, ip);

    /* MOVZX (0F B6/B7) */
    case 0xB6: case 0xB7: return handle_movzx(ctx, ip);
    /* MOVSX (0F BE/BF) */
    case 0xBE: case 0xBF: return handle_movsx(ctx, ip);
    /* IMUL (0F AF) */
    case 0xAF: return handle_imul2(ctx, ip);
    /* BSWAP (0F C8-CF) */
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
        return handle_bswap(ctx, ip);
    /* BT/BTS/BTR/BTC r/m, r */
    case 0xA3: case 0xAB: case 0xB3: case 0xBB:
        return handle_bit_test(ctx, ip);
    /* BT/BTS/BTR/BTC imm */
    case 0xBA: return handle_bit_test_imm(ctx, ip);
    /* BSF/BSR */
    case 0xBC: case 0xBD: return handle_bsf_bsr(ctx, ip);
    /* Multi-byte NOP (0F 18-1F) */
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:
        return handle_multi_byte_nop(ctx, ip);

    /* SSE moves */
    case 0x10: case 0x28: return handle_mov_xmm_load(ctx, ip);
    case 0x11: case 0x29: return handle_mov_xmm_store(ctx, ip);
    case 0x12: case 0x13: case 0x16: case 0x17:
        return handle_mov_low_high(ctx, ip);
    case 0x14: case 0x15: return handle_unpack(ctx, ip);
    case 0x2B: return handle_movnt(ctx, ip);
    case 0x50: return handle_movmskps(ctx, ip);
    case 0x6E: return handle_movd_to_xmm(ctx, ip);
    case 0x6F: return handle_movdq_load(ctx, ip);
    case 0x70: return handle_pshufd(ctx, ip);
    case 0x7E: return handle_movd_from_xmm(ctx, ip);
    case 0x7F: return handle_movdq_store(ctx, ip);

    /* SSE arithmetic (0F 51-5F) */
    case 0x51: case 0x52: case 0x53: case 0x58: case 0x59:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        return handle_sse_arith(ctx, ip);
    case 0x54: case 0x55: case 0x56: case 0x57:
        return handle_sse_logic(ctx, ip);
    case 0x5A: case 0x5B:
        return handle_mov_xmm_load(ctx, ip);

    /* SSE compare */
    case 0x2E: case 0x2F: return handle_ucomisd(ctx, ip);
    case 0x2A: return handle_cvt_int_to_float(ctx, ip);
    case 0x2C: case 0x2D: return handle_cvt_float_to_int(ctx, ip);
    case 0xC2: return handle_cmpps(ctx, ip);
    case 0xC3: return handle_movnt(ctx, ip);
    case 0xC6: return handle_shufps(ctx, ip);
    case 0xAE: return handle_fxsave_ldmxcsr(ctx, ip);
    case 0xE7: return handle_movnt(ctx, ip);
    case 0xEF: return handle_xor_xmm(ctx, ip);

    /* SSE2 packed integer ops (parse and skip) */
    case 0x60: case 0x61: case 0x62: case 0x63:
    case 0x64: case 0x65: case 0x66: case 0x67:
    case 0x68: case 0x69: case 0x6A: case 0x6B:
    case 0x6C: case 0x6D:
    case 0x74: case 0x75: case 0x76:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xE4: case 0xE5: case 0xE6: case 0xE8:
    case 0xE9: case 0xEA: case 0xEB: case 0xEC:
    case 0xED: case 0xEE:
    case 0xF0: case 0xF1: case 0xF2: case 0xF3:
    case 0xF4: case 0xF5: case 0xF6: case 0xF7:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
    {
        int ofs = 0;
        prefix_t pfx = parse_prefixes(ip, &ofs);
        ofs += 2; /* 0F xx */
        modrm_t m = parse_modrm(ip, &ofs, pfx.R, pfx.B);
        if (m.mod != 3)
            resolve_addr(ctx, ip, &ofs, m.mod, m.rm, pfx.X, pfx.B);
        ctx->Rip += ofs;
        return 1;
    }

    /* Non-SSE two-byte */
    case 0xC0: case 0xC1: return handle_xadd(ctx, ip);
    case 0xB0: case 0xB1: return handle_cmpxchg(ctx, ip);
    case 0xA4: case 0xA5: return handle_shld(ctx, ip);
    case 0xAC: case 0xAD: return handle_shrd(ctx, ip);
    case 0xA2: return handle_cpuid(ctx, ip);
    case 0x31: return handle_rdtsc(ctx, ip);
    case 0x05: return handle_syscall(ctx, ip);
    case 0x0B: return handle_ud2(ctx, ip);

    /* POPCNT (F3 0F B8) */
    case 0xB8: {
        int ofs = 0;
        prefix_t pfx = parse_prefixes(ip, &ofs);
        if (pfx.has_rep) return handle_popcnt(ctx, ip);
        return 0;
    }

    /* PUSH/POP FS/GS */
    case 0xA0:
        ctx->Rsp -= 8;
        *(uint64_t*)(uintptr_t)ctx->Rsp = ctx->SegFs;
        ctx->Rip += 2;
        return 1;
    case 0xA1:
        ctx->SegFs = (uint16_t)(*(uint64_t*)(uintptr_t)ctx->Rsp);
        ctx->Rsp += 8;
        ctx->Rip += 2;
        return 1;
    case 0xA8:
        ctx->Rsp -= 8;
        *(uint64_t*)(uintptr_t)ctx->Rsp = ctx->SegGs;
        ctx->Rip += 2;
        return 1;
    case 0xA9:
        ctx->SegGs = (uint16_t)(*(uint64_t*)(uintptr_t)ctx->Rsp);
        ctx->Rsp += 8;
        ctx->Rip += 2;
        return 1;

    /* Prefetch NOP (0F 0D) */
    case 0x0D: return handle_multi_byte_nop(ctx, ip);

    default:
        fprintf(stderr, "UNSUPPORTED 0F %02X at RIP=0x%llx\n", op2, (unsigned long long)ctx->Rip);
        return 0;
    }
}
