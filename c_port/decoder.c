#include "decoder.h"
#include "regs.h"
#include "flags.h"
#include <string.h>

/* --- Internal: Resolve SIB-based effective address --- */
static uint64_t resolve_sib(CONTEXT *ctx, const uint8_t *ip, int *offs,
                            uint8_t mod, bool rex_x, bool rex_b)
{
    uint8_t sib = ip[*offs];
    (*offs)++;
    int scale_bits = sib >> 6;
    int index_low = (sib >> 3) & 7;
    int base_low = sib & 7;

    int index_reg = index_low | (rex_x ? 8 : 0);
    int base_reg = base_low | (rex_b ? 8 : 0);

    /* Index: suppressed when indexLow==0b100 and !REX.X */
    bool no_index = (index_low == 4) && !rex_x;
    uint64_t index_val = no_index ? 0ULL : (read64(ctx, index_reg) << scale_bits);

    /* Base: special case when mod==00 and baseLow==101 -> disp32 only (no base register) */
    if (base_low == 5 && mod == 0) {
        int32_t disp32;
        memcpy(&disp32, ip + *offs, 4);
        *offs += 4;
        return (uint64_t)(int64_t)disp32 + index_val;
    }

    uint64_t base_val = read64(ctx, base_reg);
    uint64_t ea = base_val + index_val;

    if (mod == 1) {
        int8_t disp8 = *(const int8_t *)(ip + *offs);
        *offs += 1;
        ea += (uint64_t)(int64_t)disp8;
    } else if (mod == 2) {
        int32_t disp32;
        memcpy(&disp32, ip + *offs, 4);
        *offs += 4;
        ea += (uint64_t)(int64_t)disp32;
    }

    return ea;
}

/* --- Public functions --- */

prefix_t parse_prefixes(const uint8_t *ip, int *offs)
{
    prefix_t state;
    memset(&state, 0, sizeof(state));

    /* Parse legacy prefixes */
    bool parsing = true;
    while (parsing) {
        uint8_t b = ip[*offs];
        switch (b) {
            case 0x66: state.has_operand_size = true; (*offs)++; break;
            case 0x67: state.has_address_size = true; (*offs)++; break;
            case 0xF2: state.has_repne = true; (*offs)++; break;
            case 0xF3: state.has_rep = true; (*offs)++; break;
            case 0x26: case 0x2E: case 0x36: case 0x3E:
            case 0x64: case 0x65:
                state.segment_override = b; (*offs)++; break;
            default:
                parsing = false; break;
        }
    }

    /* Parse REX prefix (0x40-0x4F) */
    if ((ip[*offs] & 0xF0) == 0x40) {
        state.rex = ip[*offs];
        (*offs)++;
        state.has_rex = true;
        state.W = (state.rex & 0x08) != 0;
        state.R = (state.rex & 0x04) != 0;
        state.X = (state.rex & 0x02) != 0;
        state.B = (state.rex & 0x01) != 0;
    }

    return state;
}

modrm_t parse_modrm(const uint8_t *ip, int *offs, bool rex_r, bool rex_b)
{
    modrm_t m;
    m.raw = ip[*offs];
    (*offs)++;
    m.mod = (m.raw >> 6) & 3;
    m.reg = ((m.raw >> 3) & 7) | (rex_r ? 8 : 0);
    m.rm  = (m.raw & 7) | (rex_b ? 8 : 0);
    return m;
}

uint64_t resolve_addr(CONTEXT *ctx, const uint8_t *ip, int *offs,
                      uint8_t mod, int rm, bool rex_x, bool rex_b)
{
    int rm_low = rm & 7;

    /* SIB byte present (rmLow == 0b100) */
    if (rm_low == 4) {
        return resolve_sib(ctx, ip, offs, mod, rex_x, rex_b);
    }

    /* RIP-relative (mod=00, rm=101, no REX.B) */
    if (mod == 0 && rm_low == 5 && !rex_b) {
        int32_t disp32;
        memcpy(&disp32, ip + *offs, 4);
        *offs += 4;
        return ctx->Rip + *offs + (int64_t)disp32;
    }

    /* Simple base + displacement */
    uint64_t base_val = read64(ctx, rm);

    if (mod == 1) {
        int8_t disp8 = *(const int8_t *)(ip + *offs);
        *offs += 1;
        return base_val + (uint64_t)(int64_t)disp8;
    }
    if (mod == 2) {
        int32_t disp32;
        memcpy(&disp32, ip + *offs, 4);
        *offs += 4;
        return base_val + (uint64_t)(int64_t)disp32;
    }

    return base_val; /* mod == 0b00 */
}

uint64_t read_rm_operand(CONTEXT *ctx, const uint8_t *ip, int *offs,
                         modrm_t modrm, bool rex_x, bool rex_b,
                         int operand_sz, bool has_rex)
{
    if (modrm.mod == 3) {
        return read_sized(ctx, modrm.rm, operand_sz, has_rex);
    }

    uint64_t addr = resolve_addr(ctx, ip, offs, modrm.mod, modrm.rm, rex_x, rex_b);
    return read_mem(addr, operand_sz);
}

void write_rm_operand(CONTEXT *ctx, const uint8_t *ip, int *offs,
                      modrm_t modrm, bool rex_x, bool rex_b,
                      int operand_sz, uint64_t value, bool has_rex)
{
    if (modrm.mod == 3) {
        write_sized(ctx, modrm.rm, value, operand_sz, has_rex);
        return;
    }

    uint64_t addr = resolve_addr(ctx, ip, offs, modrm.mod, modrm.rm, rex_x, rex_b);
    write_mem(addr, value, operand_sz);
}

uint64_t resolve_rm_addr(CONTEXT *ctx, const uint8_t *ip, int *offs,
                         modrm_t modrm, bool rex_x, bool rex_b)
{
    if (modrm.mod == 3) return 0; /* register mode, no address */
    return resolve_addr(ctx, ip, offs, modrm.mod, modrm.rm, rex_x, rex_b);
}

// Lightweight bad-pointer guard: NULL page (first 64 KB) is always unmapped on Windows.
// No syscall — just a comparison. Catches NULL derefs and failed API return values.
static inline int is_bad_addr(uint64_t addr) {
    return addr < 0x10000ULL;
}

uint64_t read_mem(uint64_t addr, int operand_sz)
{
    if (is_bad_addr(addr)) return 0;
    switch (operand_sz) {
        case 8:  return *(const uint8_t *)(uintptr_t)addr;
        case 16: return *(const uint16_t *)(uintptr_t)addr;
        case 32: return *(const uint32_t *)(uintptr_t)addr;
        case 64: return *(const uint64_t *)(uintptr_t)addr;
        default: return *(const uint32_t *)(uintptr_t)addr;
    }
}

void write_mem(uint64_t addr, uint64_t value, int operand_sz)
{
    if (is_bad_addr(addr)) return;
    switch (operand_sz) {
        case 8:  *(uint8_t *)(uintptr_t)addr = (uint8_t)value; break;
        case 16: *(uint16_t *)(uintptr_t)addr = (uint16_t)value; break;
        case 32: *(uint32_t *)(uintptr_t)addr = (uint32_t)value; break;
        case 64: *(uint64_t *)(uintptr_t)addr = value; break;
    }
}

int64_t read_imm_signed(const uint8_t *ip, int *offs, int imm_size)
{
    switch (imm_size) {
        case 8: {
            int8_t v = *(const int8_t *)(ip + *offs);
            *offs += 1;
            return (int64_t)v;
        }
        case 16: {
            int16_t v;
            memcpy(&v, ip + *offs, 2);
            *offs += 2;
            return (int64_t)v;
        }
        case 32: {
            int32_t v;
            memcpy(&v, ip + *offs, 4);
            *offs += 4;
            return (int64_t)v;
        }
        case 64: {
            int64_t v;
            memcpy(&v, ip + *offs, 8);
            *offs += 8;
            return v;
        }
        default:
            return 0;
    }
}

uint64_t read_imm_unsigned(const uint8_t *ip, int *offs, int imm_size)
{
    switch (imm_size) {
        case 8: {
            uint8_t v = ip[*offs];
            (*offs)++;
            return (uint64_t)v;
        }
        case 16: {
            uint16_t v;
            memcpy(&v, ip + *offs, 2);
            *offs += 2;
            return (uint64_t)v;
        }
        case 32: {
            uint32_t v;
            memcpy(&v, ip + *offs, 4);
            *offs += 4;
            return (uint64_t)v;
        }
        case 64: {
            uint64_t v;
            memcpy(&v, ip + *offs, 8);
            *offs += 8;
            return v;
        }
        default:
            return 0;
    }
}

bool eval_condition(uint32_t eflags, int cc)
{
    bool cf = (eflags & FLAG_CF) != 0;
    bool pf = (eflags & FLAG_PF) != 0;
    bool zf = (eflags & FLAG_ZF) != 0;
    bool sf = (eflags & FLAG_SF) != 0;
    bool of = (eflags & FLAG_OF) != 0;

    switch (cc & 0xF) {
        case 0x0: return of;                    /* O */
        case 0x1: return !of;                   /* NO */
        case 0x2: return cf;                    /* B/C/NAE */
        case 0x3: return !cf;                   /* NB/AE/NC */
        case 0x4: return zf;                    /* E/Z */
        case 0x5: return !zf;                   /* NE/NZ */
        case 0x6: return cf || zf;              /* BE/NA */
        case 0x7: return !cf && !zf;            /* A/NBE */
        case 0x8: return sf;                    /* S */
        case 0x9: return !sf;                   /* NS */
        case 0xA: return pf;                    /* P/PE */
        case 0xB: return !pf;                   /* NP/PO */
        case 0xC: return sf != of;              /* L/NGE */
        case 0xD: return sf == of;              /* GE/NL */
        case 0xE: return zf || (sf != of);      /* LE/NG */
        case 0xF: return !zf && (sf == of);     /* G/NLE */
        default:  return false;
    }
}

uint64_t sign_extend(uint64_t value, int from_size)
{
    switch (from_size) {
        case 8:  return (uint64_t)(int64_t)(int8_t)(uint8_t)value;
        case 16: return (uint64_t)(int64_t)(int16_t)(uint16_t)value;
        case 32: return (uint64_t)(int64_t)(int32_t)(uint32_t)value;
        case 64: return value;
        default: return value;
    }
}

uint64_t zero_extend(uint64_t value, int from_size)
{
    switch (from_size) {
        case 8:  return value & 0xFF;
        case 16: return value & 0xFFFF;
        case 32: return value & 0xFFFFFFFF;
        case 64: return value;
        default: return value;
    }
}

int operand_size(const prefix_t *p)
{
    if (p->W) return 64;
    if (p->has_operand_size) return 16;
    return 32; /* default in 64-bit long mode */
}
