#include "misc.h"
#include <string.h>

/* Platform-specific helpers for bit scanning */
#ifdef _MSC_VER
#include <intrin.h>
static int count_trailing_zeros_64(uint64_t val) {
    unsigned long idx;
    if (_BitScanForward64(&idx, val)) return (int)idx;
    return 64;
}
static int count_leading_zeros_64(uint64_t val) {
    unsigned long idx;
    if (_BitScanReverse64(&idx, val)) return 63 - (int)idx;
    return 64;
}
static int count_trailing_zeros_32(uint32_t val) {
    unsigned long idx;
    if (_BitScanForward(&idx, val)) return (int)idx;
    return 32;
}
static int count_leading_zeros_32(uint32_t val) {
    unsigned long idx;
    if (_BitScanReverse(&idx, val)) return 31 - (int)idx;
    return 32;
}
#else
static int count_trailing_zeros_64(uint64_t val) { return val ? __builtin_ctzll(val) : 64; }
static int count_leading_zeros_64(uint64_t val) { return val ? __builtin_clzll(val) : 64; }
static int count_trailing_zeros_32(uint32_t val) { return val ? __builtin_ctz(val) : 32; }
static int count_leading_zeros_32(uint32_t val) { return val ? __builtin_clz(val) : 32; }
#endif

/* NOP (90) */
int handle_nop(CONTEXT *ctx, uint8_t *ip)
{
    ctx->Rip += 1;
    return 1;
}

/* Multi-byte NOP: 0F 1F /0 (with various lengths) */
int handle_multi_byte_nop(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* skip 0F 1F */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (modrm.mod != 3)
        resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CBW/CWDE/CDQE (98): sign-extend AL->AX / AX->EAX / EAX->RAX */
int handle_cbw_cwde_cdqe(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    if (prefix.W) {
        /* CDQE: sign-extend EAX to RAX */
        ctx->Rax = (uint64_t)(int64_t)(int32_t)(uint32_t)ctx->Rax;
    } else if (prefix.has_operand_size) {
        /* CBW: sign-extend AL to AX */
        ctx->Rax = (ctx->Rax & ~0xFFFFULL) | (uint16_t)(int16_t)(int8_t)(uint8_t)ctx->Rax;
    } else {
        /* CWDE: sign-extend AX to EAX */
        ctx->Rax = (uint32_t)(int32_t)(int16_t)(uint16_t)ctx->Rax;
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CWD/CDQ/CQO (99): sign-extend AX->DX:AX / EAX->EDX:EAX / RAX->RDX:RAX */
int handle_cwd_cdq_cqo(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip opcode */

    if (prefix.W) {
        /* CQO */
        ctx->Rdx = ((int64_t)ctx->Rax < 0) ? 0xFFFFFFFFFFFFFFFFULL : 0;
    } else if (prefix.has_operand_size) {
        /* CWD */
        ctx->Rdx = (ctx->Rdx & ~0xFFFFULL) |
                   (((int16_t)(uint16_t)ctx->Rax < 0) ? 0xFFFFULL : 0ULL);
    } else {
        /* CDQ */
        ctx->Rdx = ((int32_t)(uint32_t)ctx->Rax < 0) ? 0xFFFFFFFFULL : 0;
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CLC (F8), STC (F9), CMC (F5) */
int handle_clear_set_carry(CONTEXT *ctx, uint8_t *ip)
{
    uint8_t opcode = *ip;
    switch (opcode) {
    case 0xF8: ctx->EFlags &= ~(uint32_t)FLAG_CF; break;
    case 0xF9: ctx->EFlags |= FLAG_CF; break;
    case 0xF5: ctx->EFlags ^= FLAG_CF; break;
    default: return 0;
    }
    ctx->Rip += 1;
    return 1;
}

/* CLD (FC), STD (FD) */
int handle_clear_set_direction(CONTEXT *ctx, uint8_t *ip)
{
    uint8_t opcode = *ip;
    switch (opcode) {
    case 0xFC: ctx->EFlags &= ~(uint32_t)FLAG_DF; break;
    case 0xFD: ctx->EFlags |= FLAG_DF; break;
    default: return 0;
    }
    ctx->Rip += 1;
    return 1;
}

/* LAHF (9F): Load AH from Flags */
int handle_lahf(CONTEXT *ctx, uint8_t *ip)
{
    uint8_t flags = (uint8_t)(ctx->EFlags & 0xFF);
    write8(ctx, 4, flags, false); /* AH = flags[7:0] */
    ctx->Rip += 1;
    return 1;
}

/* SAHF (9E): Store AH into Flags */
int handle_sahf(CONTEXT *ctx, uint8_t *ip)
{
    uint8_t ah = read8(ctx, 4, false); /* AH */
    ctx->EFlags = (ctx->EFlags & ~0xFFu) | ah;
    ctx->Rip += 1;
    return 1;
}

/* GS segment override prefix (65) - resolve GS:[...] accesses */
int handle_gs_prefix(CONTEXT *ctx, uint8_t *ip)
{
    /* Get GS base via Windows API */
    uint64_t gs_base = (uint64_t)__readgsqword(0x30); /* TEB pointer */
    /* Actually, __readgsqword reads GS-relative; we need the TEB base.
       On x64 Windows, GS:[0x30] = TEB self-pointer, so GS base = TEB. */
    /* For a more correct approach, use NtQueryInformationThread, but
       for emulation purposes we approximate GS base from the TEB. */
    gs_base = (uint64_t)NtCurrentTeb();

    uint8_t next_opcode = *(ip + 1);

    /* Common patterns: 65 48 8B xx xx => MOV r64, GS:[...] */
    if (next_opcode >= 0x40 && next_opcode <= 0x4F) {
        uint8_t rex = next_opcode;
        bool W = (rex & 0x08) != 0;
        bool R = (rex & 0x04) != 0;
        bool X = (rex & 0x02) != 0;
        bool B = (rex & 0x01) != 0;

        uint8_t op = *(ip + 2);
        if (op == 0x8B) { /* MOV r, GS:[r/m] */
            int ofs = 3;
            modrm_t modrm = parse_modrm(ip, &ofs, R, B);
            int op_size = W ? 64 : 32;

            if (modrm.mod == 3) return 0;

            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, X, B);
            uint64_t effective_addr = gs_base + addr;

            /* Special case: mod=00, rm=101: RIP-rel becomes GS:[disp32] */
            if (modrm.mod == 0x00 && (modrm.raw & 7) == 0x05) {
                int d32ofs = 3;
                parse_modrm(ip, &d32ofs, R, B);
                int32_t disp32 = *(int32_t *)(ip + d32ofs);
                effective_addr = gs_base + (uint64_t)(uint32_t)disp32;
                ofs = d32ofs + 4;
            }

            uint64_t value;
            if (op_size == 64)
                value = *(uint64_t *)(uintptr_t)effective_addr;
            else
                value = *(uint32_t *)(uintptr_t)effective_addr;

            write_sized(ctx, modrm.reg, value, op_size, false);

            ctx->Rip += (uint64_t)ofs;
            return 1;
        }
    }

    /* Simple 65 8B ... (no REX) */
    if (next_opcode == 0x8B) {
        int ofs = 2;
        modrm_t modrm = parse_modrm(ip, &ofs, false, false);
        if (modrm.mod == 3) return 0;

        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, false, false);
        uint64_t effective_addr = gs_base + addr;
        uint32_t value = *(uint32_t *)(uintptr_t)effective_addr;
        write32(ctx, modrm.reg, value);

        ctx->Rip += (uint64_t)ofs;
        return 1;
    }

    return 0;
}

/* BT r/m, r (0F A3), BTS r/m, r (0F AB), BTR r/m, r (0F B3), BTC r/m, r (0F BB) */
int handle_bit_test(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t opcode2 = ip[ofs++];
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, false);
    int bit_index = (int)(read_sized(ctx, modrm.reg, op_size, false) % (uint64_t)op_size);

    int bit_value = (dst & (1ULL << bit_index)) != 0;
    ctx->EFlags = bit_value
        ? ctx->EFlags | FLAG_CF
        : ctx->EFlags & ~(uint32_t)FLAG_CF;

    switch (opcode2) {
    case 0xA3: /* BT - no modification */ break;
    case 0xAB: dst |= (1ULL << bit_index); break;  /* BTS */
    case 0xB3: dst &= ~(1ULL << bit_index); break;  /* BTR */
    case 0xBB: dst ^= (1ULL << bit_index); break;   /* BTC */
    default: return 0;
    }

    if (opcode2 != 0xA3) {
        if (is_mem) write_mem(addr, dst, op_size);
        else write_sized(ctx, modrm.rm, dst, op_size, false);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* BT/BTS/BTR/BTC r/m, imm8 (0F BA /4, /5, /6, /7) */
int handle_bit_test_imm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* skip 0F BA */
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;
    if (grp < 4) return 0;

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, false);
    uint8_t imm8 = ip[ofs++];
    int bit_index = imm8 % op_size;

    int bit_value = (dst & (1ULL << bit_index)) != 0;
    ctx->EFlags = bit_value
        ? ctx->EFlags | FLAG_CF
        : ctx->EFlags & ~(uint32_t)FLAG_CF;

    if (grp >= 5) {
        switch (grp) {
        case 5: dst |= (1ULL << bit_index); break;  /* BTS */
        case 6: dst &= ~(1ULL << bit_index); break;  /* BTR */
        case 7: dst ^= (1ULL << bit_index); break;   /* BTC */
        }
        if (is_mem) write_mem(addr, dst, op_size);
        else write_sized(ctx, modrm.rm, dst, op_size, false);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* BSF r, r/m (0F BC) / BSR r, r/m (0F BD) */
int handle_bsf_bsr(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* skip 0F */
    uint8_t opcode2 = ip[ofs++];
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    uint64_t masked = src & ((op_size == 64) ? UINT64_MAX : ((1ULL << op_size) - 1));
    int is_zero = (masked == 0);
    ctx->EFlags = is_zero
        ? ctx->EFlags | FLAG_ZF
        : ctx->EFlags & ~(uint32_t)FLAG_ZF;

    if (!is_zero) {
        int result;
        if (opcode2 == 0xBC) { /* BSF */
            result = count_trailing_zeros_64(masked);
        } else { /* BSR */
            if (op_size == 64)
                result = 63 - count_leading_zeros_64(masked);
            else
                result = 31 - count_leading_zeros_32((uint32_t)masked);
        }
        write_sized(ctx, modrm.reg, (uint64_t)result, op_size, false);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* String operations with REP/REPNE prefix handling */
int handle_string_op(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    uint8_t opcode = ip[ofs++];

    int op_size = (opcode & 1) == 0 ? 8 : operand_size(&prefix);
    int step = op_size / 8;
    int forward = (ctx->EFlags & FLAG_DF) == 0;
    int64_t delta = forward ? step : -step;

    int has_rep = prefix.has_rep;
    int has_repne = prefix.has_repne;
    int is_rep_prefixed = has_rep || has_repne;

    /* REP with RCX=0: skip entirely */
    if (is_rep_prefixed && ctx->Rcx == 0) {
        ctx->Rip += (uint64_t)ofs;
        return 1;
    }

    do {
        switch (opcode) {
        case 0xA4: case 0xA5: { /* MOVS */
            uint64_t val = read_mem(ctx->Rsi, op_size);
            write_mem(ctx->Rdi, val, op_size);
            ctx->Rsi = (uint64_t)((int64_t)ctx->Rsi + delta);
            ctx->Rdi = (uint64_t)((int64_t)ctx->Rdi + delta);
            break;
        }
        case 0xAA: case 0xAB: { /* STOS */
            uint64_t val = read_sized(ctx, 0, op_size, false);
            write_mem(ctx->Rdi, val, op_size);
            ctx->Rdi = (uint64_t)((int64_t)ctx->Rdi + delta);
            break;
        }
        case 0xAC: case 0xAD: { /* LODS */
            uint64_t val = read_mem(ctx->Rsi, op_size);
            write_sized(ctx, 0, val, op_size, false);
            ctx->Rsi = (uint64_t)((int64_t)ctx->Rsi + delta);
            break;
        }
        case 0xA6: case 0xA7: { /* CMPS */
            uint64_t s = read_mem(ctx->Rsi, op_size);
            uint64_t d = read_mem(ctx->Rdi, op_size);
            uint64_t result = s - d;
            ctx->EFlags = set_sub_flags(ctx->EFlags, s, d, result, op_size, 0);
            ctx->Rsi = (uint64_t)((int64_t)ctx->Rsi + delta);
            ctx->Rdi = (uint64_t)((int64_t)ctx->Rdi + delta);
            break;
        }
        case 0xAE: case 0xAF: { /* SCAS */
            uint64_t val = read_mem(ctx->Rdi, op_size);
            uint64_t acc = read_sized(ctx, 0, op_size, false);
            uint64_t result = acc - val;
            ctx->EFlags = set_sub_flags(ctx->EFlags, acc, val, result, op_size, 0);
            ctx->Rdi = (uint64_t)((int64_t)ctx->Rdi + delta);
            break;
        }
        default:
            return 0;
        }

        if (is_rep_prefixed) {
            ctx->Rcx--;
            if (ctx->Rcx == 0) break;

            /* For CMPS/SCAS: check ZF condition */
            if (opcode == 0xA6 || opcode == 0xA7 ||
                opcode == 0xAE || opcode == 0xAF) {
                int zf = (ctx->EFlags & FLAG_ZF) != 0;
                if (has_rep && !zf) break;     /* REPE: stop if not equal */
                if (has_repne && zf) break;     /* REPNE: stop if equal */
            }
        }
    } while (is_rep_prefixed && ctx->Rcx > 0);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
