#include "sse.h"
#include <string.h>
#include <math.h>
#include <float.h>

/* 16 XMM registers, each 128-bit (16 bytes) */
static uint8_t xmm_regs[16][16];

uint8_t *get_xmm(int index)
{
    return xmm_regs[index & 15];
}

/* MOVAPS/MOVUPS xmm, xmm/m128 (0F 28 / 0F 10)
   MOVAPD/MOVUPD xmm, xmm/m128 (66 0F 28 / 66 0F 10) */
int handle_mov_xmm_load(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    (void)op2;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;

    if (modrm.mod == 3) {
        memcpy(get_xmm(dst_xmm), get_xmm(modrm.rm), 16);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        memcpy(get_xmm(dst_xmm), (void *)(uintptr_t)addr, 16);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVAPS/MOVUPS xmm/m128, xmm (0F 29 / 0F 11)
   MOVAPD/MOVUPD xmm/m128, xmm (66 0F 29 / 66 0F 11) */
int handle_mov_xmm_store(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    (void)op2;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int src_xmm = modrm.reg;

    if (modrm.mod == 3) {
        memcpy(get_xmm(modrm.rm), get_xmm(src_xmm), 16);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        memcpy((void *)(uintptr_t)addr, get_xmm(src_xmm), 16);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVDQA/MOVDQU xmm, xmm/m128 (66 0F 6F / F3 0F 6F) */
int handle_movdq_load(CONTEXT *ctx, uint8_t *ip)
{
    return handle_mov_xmm_load(ctx, ip);
}

/* MOVDQA/MOVDQU xmm/m128, xmm (66 0F 7F / F3 0F 7F) */
int handle_movdq_store(CONTEXT *ctx, uint8_t *ip)
{
    return handle_mov_xmm_store(ctx, ip);
}

/* MOVD xmm, r/m32 (66 0F 6E) / MOVQ xmm, r/m64 (66 REX.W 0F 6E) */
int handle_movd_to_xmm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F 6E */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;
    int op_sz = prefix.W ? 64 : 32;

    uint64_t val;
    if (modrm.mod == 3)
        val = read_sized(ctx, modrm.rm, op_sz, false);
    else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        val = (op_sz == 64) ? *(uint64_t *)(uintptr_t)addr : *(uint32_t *)(uintptr_t)addr;
    }

    /* Zero-extend into XMM */
    uint8_t *xmm = get_xmm(dst_xmm);
    *(uint64_t *)xmm = val;
    *(uint64_t *)(xmm + 8) = 0;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVD r/m32, xmm (66 0F 7E) / MOVQ r/m64, xmm (66 REX.W 0F 7E)
   Also: MOVQ xmm, xmm/m64 (F3 0F 7E) */
int handle_movd_from_xmm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F 7E */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    if (prefix.has_rep) { /* F3 0F 7E = MOVQ xmm, xmm/m64 */
        int dst_xmm = modrm.reg;
        uint64_t val;
        if (modrm.mod == 3)
            val = *(uint64_t *)get_xmm(modrm.rm);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            val = *(uint64_t *)(uintptr_t)addr;
        }
        uint8_t *xmm = get_xmm(dst_xmm);
        *(uint64_t *)xmm = val;
        *(uint64_t *)(xmm + 8) = 0;
    } else { /* 66 0F 7E = MOVD/Q r/m, xmm */
        int src_xmm = modrm.reg;
        int op_sz = prefix.W ? 64 : 32;
        uint64_t val = (op_sz == 64)
            ? *(uint64_t *)get_xmm(src_xmm)
            : *(uint32_t *)get_xmm(src_xmm);

        if (modrm.mod == 3)
            write_sized(ctx, modrm.rm, val, op_sz, false);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            if (op_sz == 64)
                *(uint64_t *)(uintptr_t)addr = val;
            else
                *(uint32_t *)(uintptr_t)addr = (uint32_t)val;
        }
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* XORPS xmm, xmm/m128 (0F 57)
   XORPD xmm, xmm/m128 (66 0F 57)
   PXOR xmm, xmm/m128 (66 0F EF) */
int handle_xor_xmm(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    (void)op2;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;

    uint64_t lo, hi;
    if (modrm.mod == 3) {
        lo = *(uint64_t *)get_xmm(modrm.rm);
        hi = *(uint64_t *)(get_xmm(modrm.rm) + 8);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        lo = *(uint64_t *)(uintptr_t)addr;
        hi = *(uint64_t *)(uintptr_t)(addr + 8);
    }

    uint8_t *dst = get_xmm(dst_xmm);
    *(uint64_t *)dst ^= lo;
    *(uint64_t *)(dst + 8) ^= hi;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVSS xmm, xmm/m32 (F3 0F 10) / MOVSS xmm/m32, xmm (F3 0F 11)
   MOVSD xmm, xmm/m64 (F2 0F 10) / MOVSD xmm/m64, xmm (F2 0F 11) */
int handle_mov_scalar(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int is_load = (op2 & 1) == 0; /* 10=load, 11=store */
    int is_double = prefix.has_repne; /* F2=double, F3=single */
    int scalar_size = is_double ? 8 : 4;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    if (is_load) {
        int dst_xmm = modrm.reg;
        if (modrm.mod == 3) {
            /* xmm <- xmm: only low scalar, rest preserved */
            if (scalar_size == 4)
                *(uint32_t *)get_xmm(dst_xmm) = *(uint32_t *)get_xmm(modrm.rm);
            else
                *(uint64_t *)get_xmm(dst_xmm) = *(uint64_t *)get_xmm(modrm.rm);
        } else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            uint8_t *xmm = get_xmm(dst_xmm);
            /* From memory: zero-extend */
            *(uint64_t *)xmm = 0;
            *(uint64_t *)(xmm + 8) = 0;
            if (scalar_size == 4)
                *(uint32_t *)xmm = *(uint32_t *)(uintptr_t)addr;
            else
                *(uint64_t *)xmm = *(uint64_t *)(uintptr_t)addr;
        }
    } else {
        int src_xmm = modrm.reg;
        if (modrm.mod == 3) {
            if (scalar_size == 4)
                *(uint32_t *)get_xmm(modrm.rm) = *(uint32_t *)get_xmm(src_xmm);
            else
                *(uint64_t *)get_xmm(modrm.rm) = *(uint64_t *)get_xmm(src_xmm);
        } else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            if (scalar_size == 4)
                *(uint32_t *)(uintptr_t)addr = *(uint32_t *)get_xmm(src_xmm);
            else
                *(uint64_t *)(uintptr_t)addr = *(uint64_t *)get_xmm(src_xmm);
        }
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVLPS/MOVHPS load/store (0F 12/13/16/17)
   MOVLPD/MOVHPD (66 0F 12/13/16/17) */
int handle_mov_low_high(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int xmm_reg = modrm.reg;

    int is_high = (op2 == 0x16 || op2 == 0x17);
    int is_store = (op2 == 0x13 || op2 == 0x17);
    int qword_off = is_high ? 8 : 0;

    if (modrm.mod == 3 && !is_store) {
        /* MOVLHPS (0F 16 mod=11) or MOVHLPS (0F 12 mod=11) */
        if (op2 == 0x16) /* MOVLHPS: dst.high = src.low */
            *(uint64_t *)(get_xmm(xmm_reg) + 8) = *(uint64_t *)get_xmm(modrm.rm);
        else /* MOVHLPS: dst.low = src.high */
            *(uint64_t *)get_xmm(xmm_reg) = *(uint64_t *)(get_xmm(modrm.rm) + 8);
    } else if (modrm.mod != 3) {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        if (is_store)
            *(uint64_t *)(uintptr_t)addr = *(uint64_t *)(get_xmm(xmm_reg) + qword_off);
        else
            *(uint64_t *)(get_xmm(xmm_reg) + qword_off) = *(uint64_t *)(uintptr_t)addr;
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* LDMXCSR m32 (0F AE /2) / STMXCSR m32 (0F AE /3)
   FXSAVE/FXRSTOR (0F AE /0, /1) - skip
   CLFLUSH (0F AE /7) - NOP
   LFENCE/MFENCE/SFENCE (mod=11) */
int handle_fxsave_ldmxcsr(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F AE */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int grp = (modrm.raw >> 3) & 7;

    if (modrm.mod != 3) {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

        switch (grp) {
        case 2: /* LDMXCSR */
            ctx->MxCsr = *(uint32_t *)(uintptr_t)addr;
            break;
        case 3: /* STMXCSR */
            *(uint32_t *)(uintptr_t)addr = ctx->MxCsr;
            break;
        default: /* FXSAVE, FXRSTOR, CLFLUSH, etc. - skip */
            break;
        }
    }
    /* mod=11 forms: LFENCE, MFENCE, SFENCE - no-op */

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVNTPS/MOVNTPD/MOVNTI/MOVNTDQ (0F 2B, 66 0F 2B, 0F C3, 66 0F E7) */
int handle_movnt(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    if (modrm.mod == 3) {
        ctx->Rip += (uint64_t)ofs;
        return 1; /* shouldn't happen */
    }

    uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

    if (op2 == 0xC3) { /* MOVNTI m32/m64, r32/r64 */
        int op_sz = prefix.W ? 64 : 32;
        uint64_t val = read_sized(ctx, modrm.reg, op_sz, false);
        if (op_sz == 64)
            *(uint64_t *)(uintptr_t)addr = val;
        else
            *(uint32_t *)(uintptr_t)addr = (uint32_t)val;
    } else { /* MOVNTPS/MOVNTPD/MOVNTDQ: store 128-bit from XMM */
        memcpy((void *)(uintptr_t)addr, get_xmm(modrm.reg), 16);
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* Generic SSE arithmetic: ADDPS/SUBPS/MULPS/DIVPS/etc. */
int handle_sse_arith(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;

    /* Load source into temp buffer */
    uint8_t src_buf[16];
    if (modrm.mod == 3)
        memcpy(src_buf, get_xmm(modrm.rm), 16);
    else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        memcpy(src_buf, (void *)(uintptr_t)addr, 16);
    }

    uint8_t *dst = get_xmm(dst_xmm);

    /* Determine operation width */
    int packed = !prefix.has_rep && !prefix.has_repne;
    int is_double = prefix.has_operand_size || prefix.has_repne;
    int elem_size = is_double ? 8 : 4;
    int count = packed ? (16 / elem_size) : 1;

    int i;
    for (i = 0; i < count; i++) {
        int off = i * elem_size;
        if (elem_size == 4) {
            float a = *(float *)(dst + off);
            float b = *(float *)(src_buf + off);
            float r;
            switch (op2) {
            case 0x58: r = a + b; break;           /* ADDPS/ADDSS */
            case 0x59: r = a * b; break;           /* MULPS/MULSS */
            case 0x5C: r = a - b; break;           /* SUBPS/SUBSS */
            case 0x5E: r = (b != 0) ? a / b : 0; break; /* DIVPS/DIVSS */
            case 0x5D: r = (a < b) ? a : b; break; /* MINPS */
            case 0x5F: r = (a > b) ? a : b; break; /* MAXPS */
            case 0x51: r = sqrtf(b); break;        /* SQRTPS (unary) */
            default: r = a; break;
            }
            *(float *)(dst + off) = r;
        } else {
            double a = *(double *)(dst + off);
            double b = *(double *)(src_buf + off);
            double r;
            switch (op2) {
            case 0x58: r = a + b; break;
            case 0x59: r = a * b; break;
            case 0x5C: r = a - b; break;
            case 0x5E: r = (b != 0) ? a / b : 0; break;
            case 0x5D: r = (a < b) ? a : b; break;
            case 0x5F: r = (a > b) ? a : b; break;
            case 0x51: r = sqrt(b); break;
            default: r = a; break;
            }
            *(double *)(dst + off) = r;
        }
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* ANDPS/ANDNPS/ORPS (0F 54/55/56) and packed double variants */
int handle_sse_logic(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;

    uint64_t s_lo, s_hi;
    if (modrm.mod == 3) {
        s_lo = *(uint64_t *)get_xmm(modrm.rm);
        s_hi = *(uint64_t *)(get_xmm(modrm.rm) + 8);
    } else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        s_lo = *(uint64_t *)(uintptr_t)addr;
        s_hi = *(uint64_t *)(uintptr_t)(addr + 8);
    }

    uint8_t *dst = get_xmm(dst_xmm);
    uint64_t *d_lo = (uint64_t *)dst;
    uint64_t *d_hi = (uint64_t *)(dst + 8);

    switch (op2) {
    case 0x54: *d_lo &= s_lo; *d_hi &= s_hi; break;                     /* ANDPS */
    case 0x55: *d_lo = ~*d_lo & s_lo; *d_hi = ~*d_hi & s_hi; break;     /* ANDNPS */
    case 0x56: *d_lo |= s_lo; *d_hi |= s_hi; break;                     /* ORPS */
    case 0x57: *d_lo ^= s_lo; *d_hi ^= s_hi; break;                     /* XORPS */
    }

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CVTSI2SS (F3 0F 2A), CVTSI2SD (F2 0F 2A) */
int handle_cvt_int_to_float(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F 2A */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_xmm = modrm.reg;
    int op_sz = prefix.W ? 64 : 32;

    int64_t val;
    if (modrm.mod == 3)
        val = (int64_t)sign_extend(read_sized(ctx, modrm.rm, op_sz, false), op_sz);
    else {
        uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
        val = (op_sz == 64) ? *(int64_t *)(uintptr_t)addr : *(int32_t *)(uintptr_t)addr;
    }

    uint8_t *xmm = get_xmm(dst_xmm);
    if (prefix.has_repne) /* F2 = CVTSI2SD */
        *(double *)xmm = (double)val;
    else /* F3 = CVTSI2SS */
        *(float *)xmm = (float)val;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CVTSS2SI/CVTSD2SI (F3/F2 0F 2D), CVTTSS2SI/CVTTSD2SI (F3/F2 0F 2C) */
int handle_cvt_float_to_int(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    int truncate = (op2 == 0x2C);
    int dst_size = prefix.W ? 64 : 32;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    int dst_reg = modrm.reg;

    int64_t result;
    if (prefix.has_repne) { /* F2 = SD */
        double val;
        if (modrm.mod == 3)
            val = *(double *)get_xmm(modrm.rm);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            val = *(double *)(uintptr_t)addr;
        }
        result = truncate ? (int64_t)val : (int64_t)round(val);
    } else { /* F3 = SS */
        float val;
        if (modrm.mod == 3)
            val = *(float *)get_xmm(modrm.rm);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            val = *(float *)(uintptr_t)addr;
        }
        result = truncate ? (int64_t)val : (int64_t)roundf(val);
    }

    write_sized(ctx, dst_reg, (uint64_t)result, dst_size, false);
    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* UCOMISS (0F 2E) / UCOMISD (66 0F 2E) / COMISS (0F 2F) / COMISD (66 0F 2F) */
int handle_ucomisd(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    (void)op2;
    int is_double = prefix.has_operand_size;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);

    double a, b;
    if (is_double) {
        a = *(double *)get_xmm(modrm.reg);
        if (modrm.mod == 3)
            b = *(double *)get_xmm(modrm.rm);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            b = *(double *)(uintptr_t)addr;
        }
    } else {
        a = *(float *)get_xmm(modrm.reg);
        if (modrm.mod == 3)
            b = *(float *)get_xmm(modrm.rm);
        else {
            uint64_t addr = resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
            b = *(float *)(uintptr_t)addr;
        }
    }

    uint32_t f = ctx->EFlags & ~(uint32_t)(FLAG_CF | FLAG_ZF | FLAG_PF | FLAG_OF | FLAG_SF | FLAG_AF);
    if (isnan(a) || isnan(b))
        f |= FLAG_CF | FLAG_ZF | FLAG_PF; /* unordered */
    else if (a < b)
        f |= FLAG_CF;
    else if (a == b)
        f |= FLAG_ZF;
    /* else a > b: all clear */
    ctx->EFlags = f;

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* SHUFPS/SHUFPD (0F C6 / 66 0F C6) */
int handle_shufps(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F C6 */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (modrm.mod != 3)
        resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
    ofs++; /* imm8 */

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* CMPPS/CMPPD/CMPSS/CMPSD (0F C2) */
int handle_cmpps(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F C2 */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (modrm.mod != 3)
        resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
    ofs++; /* imm8 */

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* UNPCKLPS/UNPCKHPS (0F 14/15) */
int handle_unpack(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs++; /* 0F */
    uint8_t op2 = ip[ofs++];
    (void)op2;

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (modrm.mod != 3)
        resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* PSHUFD/PSHUFHW/PSHUFLW (66 0F 70 / F3 0F 70 / F2 0F 70) */
int handle_pshufd(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F 70 */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    if (modrm.mod != 3)
        resolve_addr(ctx, ip, &ofs, modrm.mod, modrm.rm, prefix.X, prefix.B);
    ofs++; /* imm8 */

    ctx->Rip += (uint64_t)ofs;
    return 1;
}

/* MOVMSKPS/MOVMSKPD (0F 50 / 66 0F 50) */
int handle_movmskps(CONTEXT *ctx, uint8_t *ip)
{
    int ofs = 0;
    prefix_t prefix = parse_prefixes(ip, &ofs);
    ofs += 2; /* 0F 50 */

    modrm_t modrm = parse_modrm(ip, &ofs, prefix.R, prefix.B);
    uint8_t *xmm = get_xmm(modrm.rm);
    int result;
    if (prefix.has_operand_size) { /* MOVMSKPD */
        result = ((*(uint64_t *)(xmm + 8) >> 63) != 0 ? 2 : 0) |
                 ((*(uint64_t *)xmm >> 63) != 0 ? 1 : 0);
    } else { /* MOVMSKPS */
        int i;
        result = 0;
        for (i = 0; i < 4; i++)
            if ((*(uint32_t *)(xmm + i * 4) >> 31) != 0)
                result |= 1 << i;
    }
    write32(ctx, modrm.reg, (uint32_t)result);

    ctx->Rip += (uint64_t)ofs;
    return 1;
}
