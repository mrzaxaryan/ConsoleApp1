#ifndef DECODER_H
#define DECODER_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/* Parsed instruction prefixes and state. */
typedef struct prefix_t {
    uint8_t rex;
    bool has_rex;
    bool W, R, X, B;
    bool has_operand_size;  /* 0x66 */
    bool has_address_size;  /* 0x67 */
    bool has_repne;         /* F2 */
    bool has_rep;           /* F3 */
    uint8_t segment_override; /* 0x26/2E/36/3E/64/65 */
} prefix_t;

/* Parsed ModRM byte with REX extensions applied. */
typedef struct modrm_t {
    uint8_t raw;
    uint8_t mod;
    int reg;  /* with REX.R applied */
    int rm;   /* with REX.B applied */
} modrm_t;

/* Parse all legacy prefixes and REX prefix from instruction stream. */
prefix_t parse_prefixes(const uint8_t *ip, int *offs);

/* Parse ModRM byte with REX extensions. */
modrm_t parse_modrm(const uint8_t *ip, int *offs, bool rex_r, bool rex_b);

/* Resolve effective address from ModRM (and optional SIB) bytes. */
uint64_t resolve_addr(CONTEXT *ctx, const uint8_t *ip, int *offs,
                      uint8_t mod, int rm, bool rex_x, bool rex_b);

/* Read an operand value (register or memory) based on ModRM decoding. */
uint64_t read_rm_operand(CONTEXT *ctx, const uint8_t *ip, int *offs,
                         modrm_t modrm, bool rex_x, bool rex_b,
                         int operand_size, bool has_rex);

/* Write a value to an operand (register or memory) based on ModRM decoding. */
void write_rm_operand(CONTEXT *ctx, const uint8_t *ip, int *offs,
                      modrm_t modrm, bool rex_x, bool rex_b,
                      int operand_size, uint64_t value, bool has_rex);

/* Resolve the effective address of an r/m operand without reading the value. */
uint64_t resolve_rm_addr(CONTEXT *ctx, const uint8_t *ip, int *offs,
                         modrm_t modrm, bool rex_x, bool rex_b);

/* Read a value from memory with the specified size. */
uint64_t read_mem(uint64_t addr, int operand_size);

/* Write a value to memory with the specified size. */
void write_mem(uint64_t addr, uint64_t value, int operand_size);

/* Read a sign-extended immediate value. */
int64_t read_imm_signed(const uint8_t *ip, int *offs, int imm_size);

/* Read an unsigned immediate value. */
uint64_t read_imm_unsigned(const uint8_t *ip, int *offs, int imm_size);

/* Evaluate a condition code (0x0-0xF) against EFLAGS. */
bool eval_condition(uint32_t eflags, int cc);

/* Sign-extend a value from the given source size to 64 bits. */
uint64_t sign_extend(uint64_t value, int from_size);

/* Zero-extend a value from the given source size to 64 bits. */
uint64_t zero_extend(uint64_t value, int from_size);

/* Determine operand size based on prefixes. */
int operand_size(const prefix_t *p);

#endif /* DECODER_H */
