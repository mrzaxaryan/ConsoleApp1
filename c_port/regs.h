#ifndef REGS_H
#define REGS_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/* Get pointer to a 64-bit register by index (0=RAX, 1=RCX, ..., 15=R15). */
static inline uint64_t *reg64_ptr(CONTEXT *ctx, int idx)
{
    return &ctx->Rax + (idx & 15);
}

/* Read a 64-bit register by index. */
static inline uint64_t read64(CONTEXT *ctx, int index)
{
    return *(&ctx->Rax + (index & 15));
}

/* Read a 32-bit register by index (zero-extended). */
static inline uint32_t read32(CONTEXT *ctx, int index)
{
    return (uint32_t)(*(&ctx->Rax + (index & 15)));
}

/* Read a 16-bit register by index. */
static inline uint16_t read16(CONTEXT *ctx, int index)
{
    return (uint16_t)(*(&ctx->Rax + (index & 15)));
}

/* Read an 8-bit register by index. Without REX, indices 4-7 map to AH/CH/DH/BH. */
static inline uint8_t read8(CONTEXT *ctx, int index, bool has_rex)
{
    if (!has_rex && index >= 4 && index <= 7) {
        /* AH=4, CH=5, DH=6, BH=7 -> high byte of AX/CX/DX/BX */
        int base_idx = index - 4; /* 0=RAX, 1=RCX, 2=RDX, 3=RBX */
        return *((uint8_t *)(&ctx->Rax + base_idx) + 1);
    }
    return (uint8_t)(*(&ctx->Rax + (index & 15)));
}

/* Write a 64-bit value to a register. */
static inline void write64(CONTEXT *ctx, int index, uint64_t value)
{
    *(&ctx->Rax + (index & 15)) = value;
}

/* Write a 32-bit value to a register (zero-extends to 64-bit). */
static inline void write32(CONTEXT *ctx, int index, uint32_t value)
{
    *(&ctx->Rax + (index & 15)) = (uint64_t)value;
}

/* Write a 16-bit value to a register (preserves upper bits). */
static inline void write16(CONTEXT *ctx, int index, uint16_t value)
{
    uint64_t *reg = &ctx->Rax + (index & 15);
    *reg = (*reg & ~(uint64_t)0xFFFF) | value;
}

/* Write an 8-bit value to a register (preserves upper bits).
   Without REX, indices 4-7 map to AH/CH/DH/BH. */
static inline void write8(CONTEXT *ctx, int index, uint8_t value, bool has_rex)
{
    if (!has_rex && index >= 4 && index <= 7) {
        int base_idx = index - 4;
        *((uint8_t *)(&ctx->Rax + base_idx) + 1) = value;
        return;
    }
    uint64_t *reg = &ctx->Rax + (index & 15);
    *reg = (*reg & ~(uint64_t)0xFF) | value;
}

/* Read a register value with the specified operand size. */
static inline uint64_t read_sized(CONTEXT *ctx, int index, int operand_size, bool has_rex)
{
    switch (operand_size) {
        case 8:  return read8(ctx, index, has_rex);
        case 16: return read16(ctx, index);
        case 32: return read32(ctx, index);
        case 64: return read64(ctx, index);
        default: return read64(ctx, index);
    }
}

/* Write a value to a register with the specified operand size. */
static inline void write_sized(CONTEXT *ctx, int index, uint64_t value, int operand_size, bool has_rex)
{
    switch (operand_size) {
        case 8:  write8(ctx, index, (uint8_t)value, has_rex); break;
        case 16: write16(ctx, index, (uint16_t)value); break;
        case 32: write32(ctx, index, (uint32_t)value); break;
        case 64: write64(ctx, index, value); break;
    }
}

#endif /* REGS_H */
