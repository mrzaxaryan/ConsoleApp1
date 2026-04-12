#include "move.h"
#include <string.h>

/* MOV r/m, r (88=8bit, 89=32/64bit) */
int handle_mov_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x88) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    if (modrm.mod == 3) {
        write_sized(ctx, modrm.rm, src, op_size, prefix.has_rex);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        write_mem(addr, src, op_size);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOV r, r/m (8A=8bit, 8B=32/64bit) */
int handle_mov_r_rm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x8A) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    write_sized(ctx, modrm.reg, src, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOV r/m, imm (C6 /0=8bit, C7 /0=32/64bit) */
int handle_mov_rm_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0xC6) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (((modrm.raw >> 3) & 7) != 0) return 0; /* must be /0 */

    uint64_t addr = 0;
    int is_mem = (modrm.mod != 3);
    if (is_mem)
        addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

    int imm_size = (op_size == 8) ? 8 : (op_size == 64 ? 32 : op_size);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_size);
    uint64_t value;
    if (prefix.W)
        value = (uint64_t)imm_signed;
    else
        value = (uint64_t)imm_signed & ((1ULL << (op_size > 32 ? 32 : op_size)) - 1);

    if (is_mem)
        write_mem(addr, value, (op_size == 64 && prefix.W) ? 64 : op_size);
    else
        write_sized(ctx, modrm.rm, value, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOV r, imm (B0-B7=8bit, B8-BF=32/64bit) */
int handle_mov_reg_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int op_size;
    int reg;
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        op_size = 8;
        reg = (opcode - 0xB0) | (prefix.B ? 8 : 0);
    } else { /* B8-BF */
        op_size = prefix.W ? 64 : (prefix.has_operand_size ? 16 : 32);
        reg = (opcode - 0xB8) | (prefix.B ? 8 : 0);
    }

    int imm_size = op_size;
    if (op_size == 32) imm_size = 32;
    /* For MOV r64, imm64 the immediate is full 64-bit */

    uint64_t value = read_imm_unsigned(ip, &ofs, imm_size);
    write_sized(ctx, reg, value, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* LEA r, m (8D /r) */
int handle_lea(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode 0x8D */

    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

    write_sized(ctx, modrm.reg, addr, op_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* XCHG r, r/m (86=8bit, 87=32/64bit) */
int handle_xchg(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x86) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t reg_val = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t rm_val = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);

    write_sized(ctx, modrm.reg, rm_val, op_size, prefix.has_rex);
    if (is_mem)
        write_mem(addr, reg_val, op_size);
    else
        write_sized(ctx, modrm.rm, reg_val, op_size, prefix.has_rex);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* XCHG rAX, r (90+r, except 90=NOP) */
int handle_xchg_acc_reg(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int reg = (opcode - 0x90) | (prefix.B ? 8 : 0);

    /* 90 without REX.B is NOP */
    if (reg == 0 && !prefix.has_rex) {
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }

    int op_size = operand_size(&prefix);
    uint64_t rax = read_sized(ctx, 0, op_size, false);
    uint64_t other = read_sized(ctx, reg, op_size, false);

    write_sized(ctx, 0, other, op_size, false);
    write_sized(ctx, reg, rax, op_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVZX r, r/m8 (0F B6) or MOVZX r, r/m16 (0F B7) */
int handle_movzx(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* skip 0F B6 or 0F B7 */
    uint8_t opcode2 = ip[ofs - 1];
    int src_size = (opcode2 == 0xB6) ? 8 : 16;
    int dst_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, src_size, prefix.has_rex);

    write_sized(ctx, modrm.reg, src, dst_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVSX r, r/m8 (0F BE) or MOVSX r, r/m16 (0F BF) */
int handle_movsx(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* skip 0F BE or 0F BF */
    uint8_t opcode2 = ip[ofs - 1];
    int src_size = (opcode2 == 0xBE) ? 8 : 16;
    int dst_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, src_size, prefix.has_rex);

    uint64_t result = sign_extend(src, src_size);
    if (dst_size == 32)
        result &= 0xFFFFFFFF;

    write_sized(ctx, modrm.reg, result, dst_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVSXD r64, r/m32 (63 with REX.W) */
int handle_movsxd(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode 0x63 */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint32_t src = (uint32_t)read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, 32, prefix.has_rex);

    uint64_t result = prefix.W ? (uint64_t)(int64_t)(int32_t)src : (uint64_t)src;
    write_sized(ctx, modrm.reg, result, prefix.W ? 64 : 32, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMOVcc r, r/m (0F 40-4F) */
int handle_cmovcc(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t cc = ip[ofs++] & 0xF;
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    if (eval_condition(ctx->EFlags, cc))
        write_sized(ctx, modrm.reg, src, op_size, false);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SETcc r/m8 (0F 90-9F) */
int handle_setcc(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t cc = ip[ofs++] & 0xF;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint8_t result = eval_condition(ctx->EFlags, cc) ? 1 : 0;

    if (modrm.mod == 3) {
        write8(ctx, modrm.rm, result, prefix.has_rex);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        *(uint8_t *)(uintptr_t)addr = result;
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* BSWAP r32/r64 (0F C8+r) */
int handle_bswap(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t opcode2 = ip[ofs++];
    int reg = (opcode2 - 0xC8) | (prefix.B ? 8 : 0);

    if (prefix.W) {
        uint64_t val = read64(ctx, reg);
        val = ((val & 0xFF) << 56) | ((val & 0xFF00) << 40) |
              ((val & 0xFF0000) << 24) | ((val & 0xFF000000ULL) << 8) |
              ((val >> 8) & 0xFF000000ULL) | ((val >> 24) & 0xFF0000) |
              ((val >> 40) & 0xFF00) | ((val >> 56) & 0xFF);
        write64(ctx, reg, val);
    } else {
        uint32_t val = read32(ctx, reg);
        val = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
              ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
        write32(ctx, reg, val);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
