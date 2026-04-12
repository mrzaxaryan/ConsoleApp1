#include "flags.h"

#define ARITHMETIC_FLAGS (FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF)
#define LOGIC_FLAGS      (FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF | FLAG_OF)

bool parity(uint64_t value)
{
    /* Count bits in low byte; even parity = true */
    unsigned int v = (unsigned int)(value & 0xFF);
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (v & 1) == 0;
}

uint64_t sign_bit(int operand_size)
{
    switch (operand_size) {
        case 8:  return 0x80ULL;
        case 16: return 0x8000ULL;
        case 32: return 0x80000000ULL;
        case 64: return 0x8000000000000000ULL;
        default: return 0x80000000ULL;
    }
}

uint64_t size_mask(int operand_size)
{
    switch (operand_size) {
        case 8:  return 0xFFULL;
        case 16: return 0xFFFFULL;
        case 32: return 0xFFFFFFFFULL;
        case 64: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0xFFFFFFFFULL;
    }
}

uint32_t set_add_flags(uint32_t eflags, uint64_t a, uint64_t b,
                       uint64_t result, int operand_size, int carry)
{
    uint32_t f = eflags & ~ARITHMETIC_FLAGS;
    uint64_t sb = sign_bit(operand_size);
    uint64_t mask = size_mask(operand_size);

    uint64_t masked_result = result & mask;
    uint64_t masked_a = a & mask;
    uint64_t masked_b = b & mask;

    /* CF: unsigned overflow */
    if (result > mask || masked_result < masked_a)
        f |= FLAG_CF;

    /* OF: signed overflow - both operands same sign, result different sign */
    if (((masked_a ^ masked_result) & (masked_b ^ masked_result) & sb) != 0)
        f |= FLAG_OF;

    /* AF: carry from bit 3 to bit 4 */
    if ((((uint32_t)a & 0xF) + ((uint32_t)b & 0xF) + (uint32_t)carry & 0x10) != 0)
        f |= FLAG_AF;

    /* ZF */
    if (masked_result == 0) f |= FLAG_ZF;

    /* SF */
    if ((masked_result & sb) != 0) f |= FLAG_SF;

    /* PF */
    if (parity(masked_result)) f |= FLAG_PF;

    return f;
}

uint32_t set_sub_flags(uint32_t eflags, uint64_t a, uint64_t b,
                       uint64_t result, int operand_size, int borrow)
{
    uint32_t f = eflags & ~ARITHMETIC_FLAGS;
    uint64_t sb = sign_bit(operand_size);
    uint64_t mask = size_mask(operand_size);

    uint64_t masked_result = result & mask;
    uint64_t masked_a = a & mask;
    uint64_t masked_b = b & mask;

    /* CF: unsigned borrow */
    if (masked_a < masked_b + (uint64_t)borrow)
        f |= FLAG_CF;

    /* OF: signed overflow */
    if (((masked_a ^ masked_b) & (masked_a ^ masked_result) & sb) != 0)
        f |= FLAG_OF;

    /* AF */
    if (((masked_a ^ masked_b ^ masked_result) & 0x10) != 0)
        f |= FLAG_AF;

    /* ZF */
    if (masked_result == 0) f |= FLAG_ZF;

    /* SF */
    if ((masked_result & sb) != 0) f |= FLAG_SF;

    /* PF */
    if (parity(masked_result)) f |= FLAG_PF;

    return f;
}

uint32_t set_logic_flags(uint32_t eflags, uint64_t result, int operand_size)
{
    uint32_t f = eflags & ~LOGIC_FLAGS;
    uint64_t sb = sign_bit(operand_size);
    uint64_t mask = size_mask(operand_size);
    uint64_t masked_result = result & mask;

    /* CF = 0, OF = 0 (already cleared) */
    if (masked_result == 0) f |= FLAG_ZF;
    if ((masked_result & sb) != 0) f |= FLAG_SF;
    if (parity(masked_result)) f |= FLAG_PF;

    return f;
}

uint32_t set_inc_flags(uint32_t eflags, uint64_t a, uint64_t result, int operand_size)
{
    uint32_t f = eflags & ~(FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF); /* CF preserved */
    uint64_t sb = sign_bit(operand_size);
    uint64_t mask = size_mask(operand_size);
    uint64_t masked_result = result & mask;
    uint64_t masked_a = a & mask;

    /* OF: signed overflow (a was max positive) */
    if (((masked_a ^ masked_result) & (~(uint64_t)0 ^ masked_result) & sb) != 0)
        f |= FLAG_OF;

    if (((masked_a ^ 1 ^ masked_result) & 0x10) != 0) f |= FLAG_AF;
    if (masked_result == 0) f |= FLAG_ZF;
    if ((masked_result & sb) != 0) f |= FLAG_SF;
    if (parity(masked_result)) f |= FLAG_PF;

    return f;
}

uint32_t set_dec_flags(uint32_t eflags, uint64_t a, uint64_t result, int operand_size)
{
    uint32_t f = eflags & ~(FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF); /* CF preserved */
    uint64_t sb = sign_bit(operand_size);
    uint64_t mask = size_mask(operand_size);
    uint64_t masked_result = result & mask;
    uint64_t masked_a = a & mask;

    /* OF: signed overflow (a was min negative) */
    if (((masked_a ^ 1) & (masked_a ^ masked_result) & sb) != 0)
        f |= FLAG_OF;

    if (((masked_a ^ 1 ^ masked_result) & 0x10) != 0) f |= FLAG_AF;
    if (masked_result == 0) f |= FLAG_ZF;
    if ((masked_result & sb) != 0) f |= FLAG_SF;
    if (parity(masked_result)) f |= FLAG_PF;

    return f;
}
