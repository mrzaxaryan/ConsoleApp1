#ifndef FLAGS_H
#define FLAGS_H

#include <stdint.h>
#include <stdbool.h>

/* EFLAGS bit positions */
#define FLAG_CF  (1u << 0)   /* Carry Flag */
#define FLAG_PF  (1u << 2)   /* Parity Flag */
#define FLAG_AF  (1u << 4)   /* Auxiliary Carry Flag */
#define FLAG_ZF  (1u << 6)   /* Zero Flag */
#define FLAG_SF  (1u << 7)   /* Sign Flag */
#define FLAG_DF  (1u << 10)  /* Direction Flag */
#define FLAG_OF  (1u << 11)  /* Overflow Flag */

/* Compute parity of the low byte (true = even parity). */
bool parity(uint64_t value);

/* Get the sign bit for a given operand size. */
uint64_t sign_bit(int operand_size);

/* Get the size mask for a given operand size. */
uint64_t size_mask(int operand_size);

/* Update flags after an ADD/ADC operation. */
uint32_t set_add_flags(uint32_t eflags, uint64_t a, uint64_t b,
                       uint64_t result, int operand_size, int carry);

/* Update flags after a SUB/SBB/CMP operation. */
uint32_t set_sub_flags(uint32_t eflags, uint64_t a, uint64_t b,
                       uint64_t result, int operand_size, int borrow);

/* Update flags after a logic operation (AND/OR/XOR/TEST). CF=0, OF=0. */
uint32_t set_logic_flags(uint32_t eflags, uint64_t result, int operand_size);

/* Update flags after INC. CF is not affected. */
uint32_t set_inc_flags(uint32_t eflags, uint64_t a, uint64_t result, int operand_size);

/* Update flags after DEC. CF is not affected. */
uint32_t set_dec_flags(uint32_t eflags, uint64_t a, uint64_t result, int operand_size);

#endif /* FLAGS_H */
