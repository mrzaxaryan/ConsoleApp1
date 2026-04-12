#include "control.h"

/* CALL rel32 (E8) */
int handle_call_rel32(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    int32_t rel32 = *(int32_t *)(ip + ofs);
    ofs += 4;

    uint64_t return_addr = ctx->Rip + (uint64_t)ofs;
    uint64_t target = (uint64_t)((int64_t)ctx->Rip + ofs + rel32);

    ctx->Rsp -= 8;
    *(uint64_t *)(uintptr_t)ctx->Rsp = return_addr;
    ctx->Rip = target;

    return 1;
}

/* RET (C3) / RET imm16 (C2) */
int handle_ret(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    uint64_t return_addr = *(uint64_t *)(uintptr_t)ctx->Rsp;
    ctx->Rsp += 8;

    if (opcode == 0xC2) {
        uint16_t stack_adj = *(uint16_t *)(ip + ofs);
        ofs += 2;
        ctx->Rsp += stack_adj;
    }

    ctx->Rip = return_addr;
    return 1;
}

/* LEAVE (C9) */
int handle_leave(CONTEXT *ctx, uint8_t *ip)
{
    ctx->Rsp = ctx->Rbp;
    ctx->Rbp = *(uint64_t *)(uintptr_t)ctx->Rsp;
    ctx->Rsp += 8;

    ctx->Rip += 1;
    return 1;
}

/* ENTER imm16, imm8 (C8) */
int handle_enter(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    uint16_t alloc_size = *(uint16_t *)(ip + ofs); ofs += 2;
    uint8_t nesting_level = ip[ofs++];

    /* Push RBP */
    ctx->Rsp -= 8;
    *(uint64_t *)(uintptr_t)ctx->Rsp = ctx->Rbp;

    uint64_t frame_temp = ctx->Rsp;

    if (nesting_level > 0) {
        int i;
        for (i = 1; i < nesting_level; i++) {
            ctx->Rbp -= 8;
            ctx->Rsp -= 8;
            *(uint64_t *)(uintptr_t)ctx->Rsp = *(uint64_t *)(uintptr_t)ctx->Rbp;
        }
        ctx->Rsp -= 8;
        *(uint64_t *)(uintptr_t)ctx->Rsp = frame_temp;
    }

    ctx->Rbp = frame_temp;
    ctx->Rsp -= alloc_size;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* JMP rel8 (EB) / JMP rel32 (E9) */
int handle_jmp(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    uint64_t target;
    if (opcode == 0xEB) {
        int8_t rel8 = *(int8_t *)(ip + ofs);
        ofs++;
        target = (uint64_t)((int64_t)(ctx->Rip + (uint64_t)ofs) + rel8);
    } else { /* E9 */
        int32_t rel32 = *(int32_t *)(ip + ofs);
        ofs += 4;
        target = (uint64_t)((int64_t)(ctx->Rip + (uint64_t)ofs) + rel32);
    }

    ctx->Rip = target;
    return 1;
}

/* Jcc short rel8 (70-7F) */
int handle_jcc_short(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];
    int cc = opcode & 0xF;

    int8_t rel8 = *(int8_t *)(ip + ofs);
    ofs++;
    uint64_t next_rip = ctx->Rip + (uint64_t)ofs;
    uint64_t target = (uint64_t)((int64_t)next_rip + rel8);

    int taken = eval_condition(ctx->EFlags, cc);

    ctx->Rip = taken ? target : next_rip;
    return 1;
}

/* Jcc near rel32 (0F 80-8F) */
int handle_jcc_near(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t opcode2 = ip[ofs++];
    int cc = opcode2 & 0xF;

    int32_t rel32 = *(int32_t *)(ip + ofs);
    ofs += 4;
    uint64_t next_rip = ctx->Rip + (uint64_t)ofs;
    uint64_t target = (uint64_t)((int64_t)next_rip + rel32);

    int taken = eval_condition(ctx->EFlags, cc);

    ctx->Rip = taken ? target : next_rip;
    return 1;
}

/* FF /2 = CALL r/m64, FF /4 = JMP r/m64, FF /6 = PUSH r/m64,
   FF /0 = INC r/m64, FF /1 = DEC r/m64 */
int handle_group5(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip FF */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t operand = is_mem ? read_mem(addr, 64) : read64(ctx, modrm.rm);

    switch (grp) {
    case 0: { /* INC r/m64 */
        uint64_t result = operand + 1;
        if (is_mem) write_mem(addr, result, 64);
        else write64(ctx, modrm.rm, result);
        ctx->EFlags = set_inc_flags(ctx->EFlags, operand, result, 64);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    case 1: { /* DEC r/m64 */
        uint64_t result = operand - 1;
        if (is_mem) write_mem(addr, result, 64);
        else write64(ctx, modrm.rm, result);
        ctx->EFlags = set_dec_flags(ctx->EFlags, operand, result, 64);
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    case 2: { /* CALL r/m64 */
        uint64_t return_addr = ctx->Rip + (uint64_t)ofs;
        ctx->Rsp -= 8;
        *(uint64_t *)(uintptr_t)ctx->Rsp = return_addr;
        ctx->Rip = operand;
        return 1;
    }
    case 4: { /* JMP r/m64 */
        ctx->Rip = operand;
        return 1;
    }
    case 6: { /* PUSH r/m64 */
        ctx->Rsp -= 8;
        *(uint64_t *)(uintptr_t)ctx->Rsp = operand;
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }
    default:
        return 0;
    }
}

/* LOOP/LOOPE/LOOPNE (E0/E1/E2) */
int handle_loop(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int8_t rel8 = *(int8_t *)(ip + ofs);
    ofs++;
    uint64_t next_rip = ctx->Rip + (uint64_t)ofs;
    uint64_t target = (uint64_t)((int64_t)next_rip + rel8);

    ctx->Rcx--;
    int zf = (ctx->EFlags & FLAG_ZF) != 0;

    int taken = 0;
    switch (opcode) {
    case 0xE0: taken = (ctx->Rcx != 0 && !zf); break;  /* LOOPNE */
    case 0xE1: taken = (ctx->Rcx != 0 && zf); break;    /* LOOPE */
    case 0xE2: taken = (ctx->Rcx != 0); break;           /* LOOP */
    }

    ctx->Rip = taken ? target : next_rip;
    return 1;
}

/* INT3 (CC) */
int handle_int3(CONTEXT *ctx, uint8_t *ip)
{
    ctx->Rip += 1;
    return 1;
}
