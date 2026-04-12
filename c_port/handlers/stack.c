#include "stack.h"

/* PUSH r64 (50-57) */
int handle_push_reg(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int reg = (opcode - 0x50) | (prefix.B ? 8 : 0);
    uint64_t value = read64(ctx, reg);

    ctx->Rsp -= 8;
    *(uint64_t *)(uintptr_t)ctx->Rsp = value;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* POP r64 (58-5F) */
int handle_pop_reg(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int reg = (opcode - 0x58) | (prefix.B ? 8 : 0);
    uint64_t value = *(uint64_t *)(uintptr_t)ctx->Rsp;
    ctx->Rsp += 8;

    write64(ctx, reg, value);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* PUSH imm8 (6A) */
int handle_push_imm8(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    int8_t imm8 = *(int8_t *)(ip + ofs);
    ofs++;
    uint64_t value = (uint64_t)(int64_t)imm8; /* sign-extend to 64 */

    ctx->Rsp -= 8;
    *(uint64_t *)(uintptr_t)ctx->Rsp = value;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* PUSH imm32 (68) */
int handle_push_imm32(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    int32_t imm32 = *(int32_t *)(ip + ofs);
    ofs += 4;
    uint64_t value = (uint64_t)(int64_t)imm32; /* sign-extend to 64 */

    ctx->Rsp -= 8;
    *(uint64_t *)(uintptr_t)ctx->Rsp = value;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* POP r/m64 (8F /0) */
int handle_pop_rm64(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (((modrm.raw >> 3) & 7) != 0) return 0; /* must be /0 */

    uint64_t value = *(uint64_t *)(uintptr_t)ctx->Rsp;
    ctx->Rsp += 8;

    if (modrm.mod == 3) {
        write64(ctx, modrm.rm, value);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        *(uint64_t *)(uintptr_t)addr = value;
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
