#include "logic.h"

static uint64_t do_logic_op(int op_field, uint64_t dst, uint64_t src)
{
    switch (op_field) {
    case 1: return dst | src;  /* OR */
    case 4: return dst & src;  /* AND */
    case 6: return dst ^ src;  /* XOR */
    default: return dst;
    }
}

/* AND/OR/XOR r/m, r (opcode 08/09=OR, 20/21=AND, 30/31=XOR) */
int handle_logic_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode & 1) == 0 ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    int op_field = (opcode >> 3) & 0x7;
    uint64_t result = do_logic_op(op_field, dst, src);

    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* AND/OR/XOR r, r/m (opcode 0A/0B=OR, 22/23=AND, 32/33=XOR) */
int handle_logic_r_rm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode & 1) == 0 ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    int op_field = (opcode >> 3) & 0x7;
    uint64_t result = do_logic_op(op_field, dst, src);

    write_sized(ctx, modrm.reg, result, op_size, prefix.has_rex);
    ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* AND/OR/XOR AL/AX/EAX/RAX, imm (0C/0D=OR, 24/25=AND, 34/35=XOR) */
int handle_logic_acc_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode & 1) == 0 ? 8 : operand_size(&prefix);
    int imm_sz = (op_size == 64) ? 32 : op_size;

    uint64_t dst = read_sized(ctx, 0, op_size, false);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    int op_field = (opcode >> 3) & 0x7;
    uint64_t result = do_logic_op(op_field, dst, src);

    write_sized(ctx, 0, result, op_size, false);
    ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* TEST r/m, r (84=8bit, 85=32/64bit) */
int handle_test_rm_r(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0x84) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    uint64_t dst = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t result = dst & src;
    ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* TEST AL/AX/EAX/RAX, imm (A8=8bit, A9=32/64bit) */
int handle_test_acc_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int op_size = (opcode == 0xA8) ? 8 : operand_size(&prefix);
    int imm_sz = (op_size == 64) ? 32 : op_size;

    uint64_t dst = read_sized(ctx, 0, op_size, false);
    int64_t imm_signed = read_imm_signed(ip, &ofs, imm_sz);
    uint64_t src = (op_size == 64) ? (uint64_t)imm_signed : (uint64_t)imm_signed & ((1ULL << op_size) - 1);

    uint64_t result = dst & src;
    ctx->EFlags = set_logic_flags(ctx->EFlags, result, op_size);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
