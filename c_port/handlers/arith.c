#include "arith.h"
#include <string.h>

/* --- Internal helpers for MUL/IMUL1/DIV/IDIV --- */

static void do_mul(CONTEXT *ctx, uint64_t operand, int op_size)
{
    switch (op_size) {
    case 8: {
        uint16_t r = (uint16_t)((uint8_t)ctx->Rax * (uint8_t)operand);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | r;
        ctx->EFlags = (r >> 8) != 0
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 16: {
        uint32_t r = (uint32_t)((uint16_t)ctx->Rax * (uint16_t)operand);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (r & 0xFFFF);
        ctx->Rdx = (ctx->Rdx & ~0xFFFFULL) | (r >> 16);
        ctx->EFlags = (r >> 16) != 0
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 32: {
        uint64_t r = (uint64_t)(uint32_t)ctx->Rax * (uint32_t)operand;
        ctx->Rax = (uint32_t)r;
        ctx->Rdx = (uint32_t)(r >> 32);
        ctx->EFlags = (r >> 32) != 0
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 64: {
        /* 64x64 -> 128 bit multiply */
        unsigned __int128 r = (unsigned __int128)ctx->Rax * operand;
        ctx->Rax = (uint64_t)r;
        ctx->Rdx = (uint64_t)(r >> 64);
        ctx->EFlags = ctx->Rdx != 0
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    }
}

static void do_imul1(CONTEXT *ctx, uint64_t operand, int op_size)
{
    switch (op_size) {
    case 8: {
        int16_t r = (int16_t)((int8_t)(uint8_t)ctx->Rax * (int8_t)(uint8_t)operand);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (uint16_t)r;
        ctx->EFlags = (r != (int8_t)r)
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 16: {
        int32_t r = (int32_t)(int16_t)(uint16_t)ctx->Rax * (int16_t)(uint16_t)operand;
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (uint16_t)r;
        ctx->Rdx = (ctx->Rdx & ~0xFFFFULL) | (uint16_t)(r >> 16);
        ctx->EFlags = (r != (int16_t)r)
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 32: {
        int64_t r = (int64_t)(int32_t)(uint32_t)ctx->Rax * (int32_t)(uint32_t)operand;
        ctx->Rax = (uint32_t)r;
        ctx->Rdx = (uint32_t)((uint64_t)(r >> 32));
        ctx->EFlags = (r != (int32_t)r)
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    case 64: {
        __int128 r = (__int128)(int64_t)ctx->Rax * (int64_t)operand;
        ctx->Rax = (uint64_t)(int64_t)r;
        ctx->Rdx = (uint64_t)(int64_t)(r >> 64);
        ctx->EFlags = (r != (int64_t)r)
            ? ctx->EFlags | FLAG_CF | FLAG_OF
            : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);
        break;
    }
    }
}

static int do_div(CONTEXT *ctx, uint64_t divisor, int op_size)
{
    if (divisor == 0) return 0;
    switch (op_size) {
    case 8: {
        uint16_t d = (uint16_t)(ctx->Rax & 0xFFFF);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) |
                   (uint16_t)((uint8_t)(d / (uint8_t)divisor) |
                              ((uint8_t)(d % (uint8_t)divisor) << 8));
        break;
    }
    case 16: {
        uint32_t d = (uint32_t)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF));
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (uint16_t)(d / (uint16_t)divisor);
        ctx->Rdx = (ctx->Rdx & ~0xFFFFULL) | (uint16_t)(d % (uint16_t)divisor);
        break;
    }
    case 32: {
        uint64_t d = ((ctx->Rdx & 0xFFFFFFFF) << 32) | (ctx->Rax & 0xFFFFFFFF);
        ctx->Rax = (uint32_t)(d / (uint32_t)divisor);
        ctx->Rdx = (uint32_t)(d % (uint32_t)divisor);
        break;
    }
    case 64: {
        // 128-bit / 64-bit unsigned division.
        // Simplified: if RDX == 0, just do 64-bit division.
        // Full 128-bit division is rare in shellcode.
        if (ctx->Rdx == 0) {
            ctx->Rdx = ctx->Rax % divisor;
            ctx->Rax = ctx->Rax / divisor;
        } else {
            // Fallback: iterative shift-subtract (correct but slow)
            unsigned __int128 d = ((unsigned __int128)ctx->Rdx << 64) | ctx->Rax;
            unsigned __int128 dv = divisor;
            unsigned __int128 q = 0, r = 0;
            for (int i = 127; i >= 0; i--) {
                r = (r << 1) | ((d >> i) & 1);
                if (r >= dv) { r -= dv; q |= ((unsigned __int128)1 << i); }
            }
            ctx->Rax = (uint64_t)q;
            ctx->Rdx = (uint64_t)r;
        }
        break;
    }
    }
    return 1;
}

static int do_idiv(CONTEXT *ctx, uint64_t divisor, int op_size)
{
    if (divisor == 0) return 0;
    switch (op_size) {
    case 8: {
        int16_t d = (int16_t)(uint16_t)(ctx->Rax & 0xFFFF);
        int8_t q = (int8_t)(d / (int8_t)(uint8_t)divisor);
        int8_t r = (int8_t)(d % (int8_t)(uint8_t)divisor);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) |
                   (uint64_t)(uint16_t)(uint8_t)q |
                   ((uint64_t)(uint16_t)(uint8_t)r << 8);
        break;
    }
    case 16: {
        int32_t d = (int32_t)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF));
        int16_t q = (int16_t)(d / (int16_t)(uint16_t)divisor);
        int16_t r = (int16_t)(d % (int16_t)(uint16_t)divisor);
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (uint16_t)q;
        ctx->Rdx = (ctx->Rdx & ~0xFFFFULL) | (uint16_t)r;
        break;
    }
    case 32: {
        int64_t d = (int64_t)(((ctx->Rdx & 0xFFFFFFFF) << 32) | (ctx->Rax & 0xFFFFFFFF));
        int32_t q = (int32_t)(d / (int32_t)(uint32_t)divisor);
        int32_t r = (int32_t)(d % (int32_t)(uint32_t)divisor);
        ctx->Rax = (uint32_t)q;
        ctx->Rdx = (uint32_t)r;
        break;
    }
    case 64: {
        // 128-bit / 64-bit signed division.
        if ((int64_t)ctx->Rdx == ((int64_t)ctx->Rax >> 63)) {
            // Simple: RDX is just sign extension of RAX
            int64_t q = (int64_t)ctx->Rax / (int64_t)divisor;
            int64_t r = (int64_t)ctx->Rax % (int64_t)divisor;
            ctx->Rax = (uint64_t)q;
            ctx->Rdx = (uint64_t)r;
        } else {
            // Full 128-bit signed: convert to unsigned, divide, fix sign
            int neg_d = (int64_t)ctx->Rdx < 0;
            int neg_v = (int64_t)divisor < 0;
            unsigned __int128 ud, uv;
            if (neg_d) {
                unsigned __int128 d128 = ((unsigned __int128)ctx->Rdx << 64) | ctx->Rax;
                ud = ~d128 + 1;
            } else {
                ud = ((unsigned __int128)ctx->Rdx << 64) | ctx->Rax;
            }
            uv = neg_v ? (uint64_t)(-(int64_t)divisor) : divisor;
            // Iterative division
            unsigned __int128 q = 0, r = 0;
            for (int i = 127; i >= 0; i--) {
                r = (r << 1) | ((ud >> i) & 1);
                if (r >= uv) { r -= uv; q |= ((unsigned __int128)1 << i); }
            }
            if (neg_d ^ neg_v) ctx->Rax = (uint64_t)(-(int64_t)(uint64_t)q);
            else ctx->Rax = (uint64_t)q;
            if (neg_d) ctx->Rdx = (uint64_t)(-(int64_t)(uint64_t)r);
            else ctx->Rdx = (uint64_t)r;
        }
        break;
    }
    }
    return 1;
}

/* ADD r/m, r (00=8bit, 01=32/64bit) */
int handle_add_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x00 || opcode == 0x10) ? 8 : operand_size(&prefix);
    int is_adc = (opcode == 0x10 || opcode == 0x11);
    int cf = is_adc ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t result = dst + src + (uint64_t)cf;

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->EFlags = set_add_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* ADD r, r/m (02=8bit, 03=32/64bit) */
int handle_add_r_rm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x02 || opcode == 0x12) ? 8 : operand_size(&prefix);
    int is_adc = (opcode == 0x12 || opcode == 0x13);
    int cf = is_adc ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    uint64_t result = dst + src + (uint64_t)cf;
    write_sized(ctx, modrm.reg, result, op_size, prefix.has_rex);

    ctx->EFlags = set_add_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* ADD/ADC AL/AX/EAX/RAX, imm */
int handle_add_acc_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x04 || opcode == 0x14) ? 8 : operand_size(&prefix);
    int is_adc = (opcode == 0x14 || opcode == 0x15);
    int cf = is_adc ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;
    int imm_sz = (op_size == 64) ? 32 : op_size;

    uint64_t dst = read_sized(ctx, 0, op_size, false);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    uint64_t result = dst + src + (uint64_t)cf;
    write_sized(ctx, 0, result, op_size, false);

    ctx->EFlags = set_add_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SUB/SBB r/m, r (28/29=SUB, 18/19=SBB) */
int handle_sub_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x28 || opcode == 0x18) ? 8 : operand_size(&prefix);
    int is_sbb = (opcode == 0x18 || opcode == 0x19);
    int cf = is_sbb ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t result = dst - src - (uint64_t)cf;

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SUB/SBB r, r/m (2A/2B=SUB, 1A/1B=SBB) */
int handle_sub_r_rm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x2A || opcode == 0x1A) ? 8 : operand_size(&prefix);
    int is_sbb = (opcode == 0x1A || opcode == 0x1B);
    int cf = is_sbb ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    uint64_t result = dst - src - (uint64_t)cf;
    write_sized(ctx, modrm.reg, result, op_size, prefix.has_rex);

    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SUB/SBB AL/AX/EAX/RAX, imm (2C/2D=SUB, 1C/1D=SBB) */
int handle_sub_acc_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x2C || opcode == 0x1C) ? 8 : operand_size(&prefix);
    int is_sbb = (opcode == 0x1C || opcode == 0x1D);
    int cf = is_sbb ? ((ctx->EFlags & FLAG_CF) ? 1 : 0) : 0;
    int imm_sz = (op_size == 64) ? 32 : op_size;

    uint64_t dst = read_sized(ctx, 0, op_size, false);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    uint64_t result = dst - src - (uint64_t)cf;
    write_sized(ctx, 0, result, op_size, false);

    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, cf);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMP r/m, r (38=8bit, 39=32/64bit) */
int handle_cmp_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x38) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t result = dst - src;
    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, 0);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMP r, r/m (3A=8bit, 3B=32/64bit) */
int handle_cmp_r_rm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x3A) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    uint64_t result = dst - src;
    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, 0);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMP AL/AX/EAX/RAX, imm (3C=8bit, 3D=32/64bit) */
int handle_cmp_acc_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x3C) ? 8 : operand_size(&prefix);
    int imm_sz = (op_size == 64) ? 32 : op_size;

    uint64_t dst = read_sized(ctx, 0, op_size, false);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    uint64_t result = dst - src;
    ctx->EFlags = set_sub_flags(ctx->EFlags, dst, src, result, op_size, 0);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* Group 1: 80/81/83 /digit r/m, imm */
int handle_group1(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int op_size, imm_sz;
    switch (opcode) {
    case 0x80: op_size = 8; imm_sz = 8; break;
    case 0x81: op_size = operand_size(&prefix); imm_sz = (op_size == 64) ? 32 : op_size; break;
    case 0x83: op_size = operand_size(&prefix); imm_sz = 8; break;
    default: return 0;
    }

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);

    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src;
    if (op_size == 64)
        src = (uint64_t)imm_signed;
    else
        src = (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    uint64_t result;
    uint32_t eflags = ctx->EFlags;
    int cf = (eflags & FLAG_CF) ? 1 : 0;

    switch (grp) {
    case 0: /* ADD */
        result = dst + src;
        eflags = set_add_flags(eflags, dst, src, result, op_size, 0);
        break;
    case 1: /* OR */
        result = dst | src;
        eflags = set_logic_flags(eflags, result, op_size);
        break;
    case 2: /* ADC */
        result = dst + src + (uint64_t)cf;
        eflags = set_add_flags(eflags, dst, src, result, op_size, cf);
        break;
    case 3: /* SBB */
        result = dst - src - (uint64_t)cf;
        eflags = set_sub_flags(eflags, dst, src, result, op_size, cf);
        break;
    case 4: /* AND */
        result = dst & src;
        eflags = set_logic_flags(eflags, result, op_size);
        break;
    case 5: /* SUB */
        result = dst - src;
        eflags = set_sub_flags(eflags, dst, src, result, op_size, 0);
        break;
    case 6: /* XOR */
        result = dst ^ src;
        eflags = set_logic_flags(eflags, result, op_size);
        break;
    case 7: /* CMP - no writeback */
        result = dst - src;
        eflags = set_sub_flags(eflags, dst, src, result, op_size, 0);
        ctx->EFlags = eflags;
        ctx->Rip += (uint64_t)ofs;
        return 1;
    default:
        return 0;
    }

    ctx->EFlags = eflags;

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* Group 3: F6 (8-bit) / F7 (16/32/64-bit) */
int handle_group3(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0xF6) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t operand = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);

    switch (grp) {
    case 0: case 1: { /* TEST r/m, imm */
        int isz = (op_size == 64) ? 32 : op_size;
        int64_t imm_signed = read_imm_signed(ip, &ofs, isz);
        uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);
        uint64_t result = operand & src;
        ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    case 2: { /* NOT r/m */
        uint64_t result = ~operand;
        if (is_mem) write_mem(addr, result, op_size);
        else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    case 3: { /* NEG r/m */
        uint64_t result = 0 - operand;
        if (is_mem) write_mem(addr, result, op_size);
        else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);
        ctx->EFlags = set_sub_flags(ctx->EFlags, 0, operand, result, op_size, 0);
        if (operand != 0) ctx->EFlags |= FLAG_CF;
        else ctx->EFlags &= ~(uint32_t)FLAG_CF;
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    case 4: /* MUL */
        do_mul(ctx, operand, op_size);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    case 5: /* IMUL (1-operand) */
        do_imul1(ctx, operand, op_size);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    case 6: /* DIV */
        if (!do_div(ctx, operand, op_size)) return 0;
        ctx->Rip += (uint64_t)ofs;
        return 1;
    case 7: /* IDIV */
        if (!do_idiv(ctx, operand, op_size)) return 0;
        ctx->Rip += (uint64_t)ofs;
        return 1;
    default:
        return 0;
    }
}

/* INC/DEC: FE (8-bit), FF /0 and /1 (32/64-bit) */
int handle_inc_dec(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0xFE) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;
    if (grp != 0 && grp != 1) return 0;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t operand = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);

    uint64_t result;
    if (grp == 0) {
        result = operand + 1;
        ctx->EFlags = set_inc_flags(ctx->EFlags, operand, result, op_size);
    } else {
        result = operand - 1;
        ctx->EFlags = set_dec_flags(ctx->EFlags, operand, result, op_size);
    }

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* Group 2: C0/C1/D0/D1/D2/D3 - Shift/rotate operations */
int handle_group2_shift(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int op_size;
    int by_cl = 0, by_1 = 0;
    switch (opcode) {
    case 0xC0: op_size = 8; break;
    case 0xC1: op_size = operand_size(&prefix); break;
    case 0xD0: op_size = 8; by_1 = 1; break;
    case 0xD1: op_size = operand_size(&prefix); by_1 = 1; break;
    case 0xD2: op_size = 8; by_cl = 1; break;
    case 0xD3: op_size = operand_size(&prefix); by_cl = 1; break;
    default: return 0;
    }

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int sub = (modrm.raw >> 3) & 7;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t value = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);

    uint8_t count;
    if (by_1) count = 1;
    else if (by_cl) count = (uint8_t)(ctx->Rcx & (op_size == 64 ? 0x3FULL : 0x1FULL));
    else { count = ip[ofs++]; count &= (uint8_t)(op_size == 64 ? 0x3F : 0x1F); }

    uint64_t result;
    int bits = op_size;

    switch (sub) {
    case 0: /* ROL */
        result = count ? ((value << count) | (value >> (bits - count))) : value;
        break;
    case 1: /* ROR */
        result = count ? ((value >> count) | (value << (bits - count))) : value;
        break;
    case 2: /* RCL */
        result = value;
        break;
    case 3: /* RCR */
        result = value;
        break;
    case 4: case 6: /* SHL */
        result = value << count;
        break;
    case 5: /* SHR */
        result = value >> count;
        break;
    case 7: /* SAR */
        switch (op_size) {
        case 8:  result = (uint64_t)((int64_t)(int8_t)(uint8_t)value >> count); break;
        case 16: result = (uint64_t)((int64_t)(int16_t)(uint16_t)value >> count); break;
        case 32: result = (uint64_t)((int64_t)(int32_t)(uint32_t)value >> count); break;
        case 64: result = (uint64_t)((int64_t)value >> count); break;
        default: result = value; break;
        }
        break;
    default:
        return 0;
    }

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    if (count > 0 && sub >= 4) {
        ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);
        if (sub == 4 || sub == 6) {
            int shift_amt = bits - count;
            uint64_t mask = (shift_amt >= 0 && shift_amt < 64) ? (1ULL << shift_amt) : 0;
            ctx->EFlags = (value & mask) != 0
                ? ctx->EFlags | FLAG_CF
                : ctx->EFlags & ~(uint32_t)FLAG_CF;
        } else if (sub == 5) {
            int shift_amt = count - 1;
            uint64_t mask = (shift_amt >= 0 && shift_amt < 64) ? (1ULL << shift_amt) : 0;
            ctx->EFlags = (value & mask) != 0
                ? ctx->EFlags | FLAG_CF
                : ctx->EFlags & ~(uint32_t)FLAG_CF;
        } else if (sub == 7) {
            int shift_amt = count - 1;
            uint64_t mask = (shift_amt >= 0 && shift_amt < 64) ? (1ULL << shift_amt) : 0;
            ctx->EFlags = (value & mask) != 0
                ? ctx->EFlags | FLAG_CF
                : ctx->EFlags & ~(uint32_t)FLAG_CF;
        }
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* IMUL r, r/m (0F AF) - two-operand form */
int handle_imul2(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* skip 0F AF */
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int64_t dst = (int64_t)sign_extend(read_sized(ctx, modrm.reg, op_size, false), op_size);
    int64_t src = (int64_t)sign_extend(read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex), op_size);

    int64_t result = dst * src;
    write_sized(ctx, modrm.reg, (uint64_t)result, op_size, false);

    int overflow = 0;
    switch (op_size) {
    case 16: overflow = (result != (int16_t)result); break;
    case 32: overflow = (result != (int32_t)result); break;
    default: overflow = 0; break;
    }
    ctx->EFlags = overflow
        ? ctx->EFlags | FLAG_CF | FLAG_OF
        : ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_OF);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* IMUL r, r/m, imm8 (6B) or IMUL r, r/m, imm32 (69) */
int handle_imul3(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = operand_size(&prefix);
    int imm_sz = (opcode == 0x6B) ? 8 : (op_size == 64 ? 32 : op_size);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int64_t src = (int64_t)sign_extend(
        read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex),
        op_size);
    int64_t imm = read_imm_signed(ip, &ofs, imm_sz);

    int64_t result = src * imm;
    write_sized(ctx, modrm.reg, (uint64_t)result, op_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
