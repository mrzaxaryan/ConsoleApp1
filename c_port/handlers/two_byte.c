#include "two_byte.h"
#include <string.h>

/* Platform-specific bit operation helpers */
#ifdef _MSC_VER
#include <intrin.h>
static int tb_popcount64(uint64_t val) {
    return (int)__popcnt64(val);
}
static int tb_clz64(uint64_t val) {
    unsigned long idx;
    if (_BitScanReverse64(&idx, val)) return 63 - (int)idx;
    return 64;
}
static int tb_clz32(uint32_t val) {
    unsigned long idx;
    if (_BitScanReverse(&idx, val)) return 31 - (int)idx;
    return 32;
}
static int tb_ctz64(uint64_t val) {
    unsigned long idx;
    if (_BitScanForward64(&idx, val)) return (int)idx;
    return 64;
}
#else
static int tb_popcount64(uint64_t val) { return __builtin_popcountll(val); }
static int tb_clz64(uint64_t val) { return val ? __builtin_clzll(val) : 64; }
static int tb_clz32(uint32_t val) { return val ? __builtin_clz(val) : 32; }
static int tb_ctz64(uint64_t val) { return val ? __builtin_ctzll(val) : 64; }
#endif

/* XADD r/m, r (0F C0=8bit, 0F C1=32/64bit) */
int handle_xadd(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int op_size = (op2 == 0xC0) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t result = dst + src;
    /* XADD: TEMP=SRC+DEST; SRC=DEST; DEST=TEMP */
    write_sized(ctx, modrm.reg, dst, op_size, prefix.has_rex);
    if (is_mem) write_mem(addr, result, op_size);
    else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);

    ctx->EFlags = set_add_flags(ctx->EFlags, dst, src, result, op_size, 0);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMPXCHG r/m, r (0F B0=8bit, 0F B1=32/64bit) */
int handle_cmpxchg(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int op_size = (op2 == 0xB0) ? 8 : operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t acc = read_sized(ctx, 0, op_size, false); /* AL/AX/EAX/RAX */
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint64_t cmp_result = acc - dst;
    ctx->EFlags = set_sub_flags(ctx->EFlags, acc, dst, cmp_result, op_size, 0);

    if (acc == dst) {
        /* ZF=1, dest <- src */
        if (is_mem) write_mem(addr, src, op_size);
        else write_sized(ctx, modrm.rm, src, op_size, prefix.has_rex);
    } else {
        /* ZF=0, accumulator <- dest */
        write_sized(ctx, 0, dst, op_size, false);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SHLD r/m, r, imm8 (0F A4) / SHLD r/m, r, CL (0F A5) */
int handle_shld(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int op_size = operand_size(&prefix);
    int by_cl = (op2 == 0xA5);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint8_t count = by_cl ? (uint8_t)(ctx->Rcx & 0x3F) : ip[ofs++];
    count &= (uint8_t)(op_size == 64 ? 0x3F : 0x1F);

    if (count > 0) {
        uint64_t result = (dst << count) | (src >> (op_size - count));
        if (is_mem) write_mem(addr, result, op_size);
        else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SHRD r/m, r, imm8 (0F AC) / SHRD r/m, r, CL (0F AD) */
int handle_shrd(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int op_size = operand_size(&prefix);
    int by_cl = (op2 == 0xAD);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    int is_mem = (modrm.mod != 3);
    uint64_t addr = is_mem ? resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B) : 0;
    uint64_t dst = is_mem ? read_mem(addr, op_size) : read_sized(ctx, modrm.rm, op_size, prefix.has_rex);
    uint64_t src = read_sized(ctx, modrm.reg, op_size, prefix.has_rex);

    uint8_t count = by_cl ? (uint8_t)(ctx->Rcx & 0x3F) : ip[ofs++];
    count &= (uint8_t)(op_size == 64 ? 0x3F : 0x1F);

    if (count > 0) {
        uint64_t result = (dst >> count) | (src << (op_size - count));
        if (is_mem) write_mem(addr, result, op_size);
        else write_sized(ctx, modrm.rm, result, op_size, prefix.has_rex);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* UD2 (0F 0B) */
int handle_ud2(CONTEXT *ctx, uint8_t *ip)
{
    return 0; /* intentional undefined instruction */
}

/* CPUID (0F A2) */
int handle_cpuid(CONTEXT *ctx, uint8_t *ip)
{
    uint32_t leaf = (uint32_t)ctx->Rax;
    switch (leaf) {
    case 0: /* Max leaf + vendor */
        ctx->Rax = 0x16;
        ctx->Rbx = 0x756E6547; /* "Genu" */
        ctx->Rdx = 0x49656E69; /* "ineI" */
        ctx->Rcx = 0x6C65746E; /* "ntel" */
        break;
    case 1: /* Feature bits */
        ctx->Rax = 0x000806E9;
        ctx->Rbx = 0;
        ctx->Rcx = 0x7FFAFBBF; /* SSE4.2, POPCNT, etc. */
        ctx->Rdx = 0xBFEBFBFF;
        break;
    default:
        ctx->Rax = 0;
        ctx->Rbx = 0;
        ctx->Rcx = 0;
        ctx->Rdx = 0;
        break;
    }

    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F A2 */
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* RDTSC (0F 31) */
int handle_rdtsc(CONTEXT *ctx, uint8_t *ip)
{
    uint64_t tsc = (uint64_t)GetTickCount64() * 3000; /* approximate TSC */
    ctx->Rax = tsc & 0xFFFFFFFF;
    ctx->Rdx = tsc >> 32;

    int ofs = 0;
    parse_prefixes(ip, &ofs);
    ofs += 2;
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SYSCALL (0F 05) - not truly emulatable */
int handle_syscall(CONTEXT *ctx, uint8_t *ip)
{
    return 0;
}

/* POPCNT r, r/m (F3 0F B8) */
int handle_popcnt(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F B8 */
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    int count = tb_popcount64(src);
    write_sized(ctx, modrm.reg, (uint64_t)count, op_size, false);

    ctx->EFlags = ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_ZF | FLAG_SF | FLAG_OF | FLAG_PF | FLAG_AF);
    if (count == 0) ctx->EFlags |= FLAG_ZF;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* LZCNT r, r/m (F3 0F BD) */
int handle_lzcnt(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F BD */
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    int count = (op_size == 64)
        ? tb_clz64(src)
        : tb_clz32((uint32_t)src);
    write_sized(ctx, modrm.reg, (uint64_t)count, op_size, false);

    ctx->EFlags = ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_ZF);
    if (src == 0) ctx->EFlags |= FLAG_CF;
    if (count == 0) ctx->EFlags |= FLAG_ZF;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* TZCNT r, r/m (F3 0F BC) */
int handle_tzcnt(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F BC */
    int op_size = operand_size(&prefix);

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint64_t src = read_rm_operand(ctx, ip, &ofs, modrm, prefix.X, prefix.B, op_size, prefix.has_rex);

    int count = tb_ctz64(src);
    if (op_size == 32 && src == 0) count = 32;
    write_sized(ctx, modrm.reg, (uint64_t)count, op_size, false);

    ctx->EFlags = ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_ZF);
    if (src == 0) ctx->EFlags |= FLAG_CF;
    if (count == 0) ctx->EFlags |= FLAG_ZF;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
