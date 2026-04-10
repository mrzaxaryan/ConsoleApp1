using NoRWX.Core;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;

namespace NoRWX;

/// <summary>
/// AArch64 (ARM64) instruction emulator. Runs ARM64 PIC code by decoding
/// fixed-width 32-bit instructions and updating the register context.
///
/// ARM64 ISA key points:
/// - All instructions are 4 bytes (fixed width)
/// - 31 general-purpose registers: X0-X30 (64-bit) / W0-W30 (32-bit view)
/// - SP (stack pointer) is separate from X31 in some encodings
/// - PC is not a GP register — updated implicitly
/// - NZCV condition flags (Negative, Zero, Carry, oVerflow)
/// - Load/store architecture: no memory operands in ALU instructions
/// - Instruction groups determined by bits [28:25]
/// </summary>
public static unsafe class EmulatorARM64
{
    [StructLayout(LayoutKind.Explicit, Size = 272)]
    public struct CONTEXT_ARM64
    {
        [FieldOffset(0)] public uint Cpsr;
        [FieldOffset(8)] public ulong Pc;
        [FieldOffset(16)] public ulong Sp;

        // X0-X30: 31 registers at explicit offsets
        [FieldOffset(24)] public ulong X0;  [FieldOffset(32)] public ulong X1;
        [FieldOffset(40)] public ulong X2;  [FieldOffset(48)] public ulong X3;
        [FieldOffset(56)] public ulong X4;  [FieldOffset(64)] public ulong X5;
        [FieldOffset(72)] public ulong X6;  [FieldOffset(80)] public ulong X7;
        [FieldOffset(88)] public ulong X8;  [FieldOffset(96)] public ulong X9;
        [FieldOffset(104)] public ulong X10; [FieldOffset(112)] public ulong X11;
        [FieldOffset(120)] public ulong X12; [FieldOffset(128)] public ulong X13;
        [FieldOffset(136)] public ulong X14; [FieldOffset(144)] public ulong X15;
        [FieldOffset(152)] public ulong X16; [FieldOffset(160)] public ulong X17;
        [FieldOffset(168)] public ulong X18; [FieldOffset(176)] public ulong X19;
        [FieldOffset(184)] public ulong X20; [FieldOffset(192)] public ulong X21;
        [FieldOffset(200)] public ulong X22; [FieldOffset(208)] public ulong X23;
        [FieldOffset(216)] public ulong X24; [FieldOffset(224)] public ulong X25;
        [FieldOffset(232)] public ulong X26; [FieldOffset(240)] public ulong X27;
        [FieldOffset(248)] public ulong X28; [FieldOffset(256)] public ulong X29;
        [FieldOffset(264)] public ulong X30;
    }

    // NZCV flag positions in CPSR
    public const uint N_FLAG = 1u << 31;
    public const uint Z_FLAG = 1u << 30;
    public const uint C_FLAG = 1u << 29;
    public const uint V_FLAG = 1u << 28;
    public const uint NZCV_MASK = N_FLAG | Z_FLAG | C_FLAG | V_FLAG;

    private static readonly Action<string, int> _noopLog = static (_, _) => { };
    // Logging controlled by EmulatorLogger.Target

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong* Xn(CONTEXT_ARM64* ctx, int n) => &ctx->X0 + n;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ReadX(CONTEXT_ARM64* ctx, int n)
    {
        if (n == 31) return 0; // XZR
        return Xn(ctx, n)[0];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ReadXSp(CONTEXT_ARM64* ctx, int n)
    {
        if (n == 31) return ctx->Sp;
        return Xn(ctx, n)[0];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadW(CONTEXT_ARM64* ctx, int n)
    {
        if (n == 31) return 0;
        return (uint)Xn(ctx, n)[0];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadWSp(CONTEXT_ARM64* ctx, int n)
    {
        if (n == 31) return (uint)ctx->Sp;
        return (uint)Xn(ctx, n)[0];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteX(CONTEXT_ARM64* ctx, int n, ulong val)
    {
        if (n == 31) return;
        Xn(ctx, n)[0] = val;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteXSp(CONTEXT_ARM64* ctx, int n, ulong val)
    {
        if (n == 31) { ctx->Sp = val; return; }
        Xn(ctx, n)[0] = val;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteW(CONTEXT_ARM64* ctx, int n, uint val)
    {
        if (n == 31) return;
        Xn(ctx, n)[0] = val; // zero-extend
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteWSp(CONTEXT_ARM64* ctx, int n, uint val)
    {
        if (n == 31) { ctx->Sp = (ctx->Sp & 0xFFFFFFFF00000000) | val; return; }
        Xn(ctx, n)[0] = val;
    }

    // ========== NZCV Flag helpers ==========

    private static void SetNZCV_Add64(CONTEXT_ARM64* ctx, ulong a, ulong b, ulong result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 63) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        if (result < a) f |= C_FLAG; // unsigned carry
        if (((a ^ result) & (b ^ result) & (1UL << 63)) != 0) f |= V_FLAG;
        ctx->Cpsr = f;
    }

    private static void SetNZCV_Add32(CONTEXT_ARM64* ctx, uint a, uint b, uint result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 31) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        if ((ulong)a + b > 0xFFFFFFFF) f |= C_FLAG;
        if (((a ^ result) & (b ^ result) & 0x80000000) != 0) f |= V_FLAG;
        ctx->Cpsr = f;
    }

    private static void SetNZCV_Sub64(CONTEXT_ARM64* ctx, ulong a, ulong b, ulong result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 63) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        if (a >= b) f |= C_FLAG; // no borrow = carry set
        if (((a ^ b) & (a ^ result) & (1UL << 63)) != 0) f |= V_FLAG;
        ctx->Cpsr = f;
    }

    private static void SetNZCV_Sub32(CONTEXT_ARM64* ctx, uint a, uint b, uint result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 31) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        if (a >= b) f |= C_FLAG;
        if (((a ^ b) & (a ^ result) & 0x80000000) != 0) f |= V_FLAG;
        ctx->Cpsr = f;
    }

    private static void SetNZ64(CONTEXT_ARM64* ctx, ulong result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 63) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        // C and V cleared for logic ops
        ctx->Cpsr = f;
    }

    private static void SetNZ32(CONTEXT_ARM64* ctx, uint result)
    {
        uint f = ctx->Cpsr & ~NZCV_MASK;
        if ((result >> 31) != 0) f |= N_FLAG;
        if (result == 0) f |= Z_FLAG;
        ctx->Cpsr = f;
    }

    private static bool EvalCond(CONTEXT_ARM64* ctx, int cond)
    {
        uint f = ctx->Cpsr;
        bool n = (f & N_FLAG) != 0, z = (f & Z_FLAG) != 0;
        bool c = (f & C_FLAG) != 0, v = (f & V_FLAG) != 0;

        bool result = (cond >> 1) switch
        {
            0 => z,           // EQ/NE
            1 => c,           // CS/CC (HS/LO)
            2 => n,           // MI/PL
            3 => v,           // VS/VC
            4 => c && !z,     // HI/LS
            5 => n == v,      // GE/LT
            6 => n == v && !z,// GT/LE
            7 => true,        // AL
            _ => true
        };

        // Odd condition codes invert
        if ((cond & 1) != 0 && cond != 0xF)
            result = !result;

        return result;
    }

    // ========== Barrel shifter ==========

    private static ulong ShiftReg64(ulong val, int shiftType, int amount)
    {
        if (amount == 0) return val;
        return shiftType switch
        {
            0 => val << amount,                           // LSL
            1 => val >> amount,                           // LSR
            2 => (ulong)((long)val >> amount),            // ASR
            3 => (val >> amount) | (val << (64 - amount)),// ROR
            _ => val
        };
    }

    private static uint ShiftReg32(uint val, int shiftType, int amount)
    {
        if (amount == 0) return val;
        return shiftType switch
        {
            0 => val << amount,
            1 => val >> amount,
            2 => (uint)((int)val >> amount),
            3 => (val >> amount) | (val << (32 - amount)),
            _ => val
        };
    }

    // ========== Sign/zero extend ==========

    private static ulong ExtendReg(ulong val, int extType, int shift)
    {
        ulong extended = extType switch
        {
            0 => val & 0xFF,                           // UXTB
            1 => val & 0xFFFF,                         // UXTH
            2 => val & 0xFFFFFFFF,                     // UXTW
            3 => val,                                   // UXTX
            4 => (ulong)(long)(sbyte)(byte)val,        // SXTB
            5 => (ulong)(long)(short)(ushort)val,      // SXTH
            6 => (ulong)(long)(int)(uint)val,          // SXTW
            7 => val,                                   // SXTX
            _ => val
        };
        return extended << shift;
    }

    /// <summary>
    /// Emulate using x64 CONTEXT directly (no CONTEXT_ARM64 allocation).
    /// Maps: Rax→X0, Rcx→X1, Rdx→X2, Rbx→X3, Rsp→X4/SP, Rbp→X5,
    ///       Rsi→X6, Rdi→X7, R8-R15→X8-X15, Rip→PC, EFlags→CPSR.
    /// Only X0-X15 are mapped; X16-X30 use a static backing store.
    /// </summary>
    // Static backing for X16-X30 (not mapped to x64 registers)
    private static ulong _x16, _x17, _x18, _x19, _x20, _x21, _x22, _x23;
    private static ulong _x24, _x25, _x26, _x27, _x28, _x29, _x30;

    public static bool EmulateRaw(EmulatorX64.CONTEXT* ctx64, byte* address)
    {
        // Build ARM64 context on stack from x64 registers — no managed alloc
        CONTEXT_ARM64 arm;
        arm.Pc = ctx64->Rip;
        arm.Sp = ctx64->Rsp;
        arm.Cpsr = ctx64->EFlags;

        // Map x64 GPRs → ARM64 X0-X15
        arm.X0 = ctx64->Rax; arm.X1 = ctx64->Rcx;
        arm.X2 = ctx64->Rdx; arm.X3 = ctx64->Rbx;
        arm.X4 = ctx64->Rsp; arm.X5 = ctx64->Rbp;
        arm.X6 = ctx64->Rsi; arm.X7 = ctx64->Rdi;
        arm.X8 = ctx64->R8;  arm.X9 = ctx64->R9;
        arm.X10 = ctx64->R10; arm.X11 = ctx64->R11;
        arm.X12 = ctx64->R12; arm.X13 = ctx64->R13;
        arm.X14 = ctx64->R14; arm.X15 = ctx64->R15;

        // X16-X30 from static fields
        arm.X16 = _x16; arm.X17 = _x17; arm.X18 = _x18; arm.X19 = _x19;
        arm.X20 = _x20; arm.X21 = _x21; arm.X22 = _x22; arm.X23 = _x23;
        arm.X24 = _x24; arm.X25 = _x25; arm.X26 = _x26; arm.X27 = _x27;
        arm.X28 = _x28; arm.X29 = _x29; arm.X30 = _x30;

        bool ok = Emulate(&arm, address);

        if (ok)
        {
            ctx64->Rip = arm.Pc; ctx64->Rsp = arm.Sp; ctx64->EFlags = arm.Cpsr;
            ctx64->Rax = arm.X0; ctx64->Rcx = arm.X1;
            ctx64->Rdx = arm.X2; ctx64->Rbx = arm.X3;
            ctx64->Rbp = arm.X5; ctx64->Rsi = arm.X6;
            ctx64->Rdi = arm.X7;
            ctx64->R8 = arm.X8;  ctx64->R9 = arm.X9;
            ctx64->R10 = arm.X10; ctx64->R11 = arm.X11;
            ctx64->R12 = arm.X12; ctx64->R13 = arm.X13;
            ctx64->R14 = arm.X14; ctx64->R15 = arm.X15;
            _x16 = arm.X16; _x17 = arm.X17; _x18 = arm.X18; _x19 = arm.X19;
            _x20 = arm.X20; _x21 = arm.X21; _x22 = arm.X22; _x23 = arm.X23;
            _x24 = arm.X24; _x25 = arm.X25; _x26 = arm.X26; _x27 = arm.X27;
            _x28 = arm.X28; _x29 = arm.X29; _x30 = arm.X30;
        }

        return ok;
    }

    // ========== Main dispatch ==========

    public static bool Emulate(CONTEXT_ARM64* ctx, byte* address)
    {
        uint instr = *(uint*)address;

        // ARM64 instruction groups by bits [28:25]
        int op0 = (int)(instr >> 25) & 0xF;
        if (Core.EmulatorLogger.IsEnabled)
            Core.EmulatorLogger.Log($"ARM64: instr=0x{instr:X8} op0={op0} PC=0x{ctx->Pc:X}");

        switch (op0)
        {
            case 0b0000: // Reserved / UDF
                return false;

            case 0b1000: case 0b1001: // Data processing (immediate)
                return HandleDataProcImm(ctx, instr);

            case 0b1010: case 0b1011: // Branch, exception, system
                return HandleBranchSys(ctx, instr, address);

            case 0b0100: case 0b0110: case 0b1100: case 0b1110: // Load/store
                return HandleLoadStore(ctx, instr);

            case 0b0101: case 0b1101: // Data processing (register)
                return HandleDataProcReg(ctx, instr);

            case 0b0111: case 0b1111: // SIMD/FP
                return HandleSimdFp(ctx, instr);

            default:
                return false;
        }
    }

    // ========== Data Processing (Immediate) ==========

    private static bool HandleDataProcImm(CONTEXT_ARM64* ctx, uint instr)
    {
        // Discriminate by the fixed opcode bits within the encoding.
        // Use bits[28:23] to determine the specific DP-immediate sub-group.
        int fixed6 = (int)(instr >> 23) & 0x3F;

        // PC-rel addressing: bits[28:24] = 10000 → fixed6[5:1] matches x0000x
        // ADR: bit31=0, ADRP: bit31=1. Check: bits[28:24] of instr = 10000
        if (((instr >> 24) & 0x1F) == 0b10000)
        {
            bool isAdrp = (instr >> 31) != 0;
            int immlo = (int)(instr >> 29) & 3;
            int immhi = (int)(instr >> 5) & 0x7FFFF;
            long imm = ((long)((immhi << 2) | immlo) << 43) >> 43;
            int rd = (int)(instr & 0x1F);
            if (isAdrp)
                WriteX(ctx, rd, (ctx->Pc & ~0xFFFUL) + ((ulong)imm << 12));
            else
                WriteX(ctx, rd, ctx->Pc + (ulong)imm);
            ctx->Pc += 4;
            return true;
        }

        // Add/subtract immediate: bits[28:24] = 10001
        if ((fixed6 >> 1 & 0x1F) == 0b10001)
        {
            bool sf = (instr >> 31) != 0;
            bool op = ((instr >> 30) & 1) != 0;
            bool S = ((instr >> 29) & 1) != 0;
            int shift = (int)(instr >> 22) & 3;
            uint imm12 = (instr >> 10) & 0xFFF;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);
            ulong immVal = shift == 1 ? (ulong)imm12 << 12 : imm12;

            if (sf)
            {
                ulong a = ReadXSp(ctx, rn);
                ulong result = op ? a - immVal : a + immVal;
                if (S) { if (op) SetNZCV_Sub64(ctx, a, immVal, result); else SetNZCV_Add64(ctx, a, immVal, result); WriteX(ctx, rd, result); }
                else WriteXSp(ctx, rd, result);
            }
            else
            {
                uint a = ReadWSp(ctx, rn);
                uint result = op ? a - (uint)immVal : a + (uint)immVal;
                if (S) { if (op) SetNZCV_Sub32(ctx, a, (uint)immVal, result); else SetNZCV_Add32(ctx, a, (uint)immVal, result); WriteW(ctx, rd, result); }
                else WriteWSp(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Logical immediate: bits[28:23] = 100100
        if (fixed6 == 0b100100)
        {
            bool sf = (instr >> 31) != 0;
            int opc = (int)(instr >> 29) & 3;
            int rd = (int)(instr & 0x1F);
            int rn = (int)(instr >> 5) & 0x1F;
            ulong imm = DecodeBitmaskImm(instr, sf);

            if (sf)
            {
                ulong a = ReadX(ctx, rn);
                ulong result = opc switch { 0 => a & imm, 1 => a | imm, 2 => a ^ imm, 3 => a & imm, _ => a };
                if (opc == 3) { SetNZ64(ctx, result); WriteX(ctx, rd, result); }
                else WriteXSp(ctx, rd, result);
            }
            else
            {
                uint a = ReadW(ctx, rn);
                uint result = opc switch { 0 => a & (uint)imm, 1 => a | (uint)imm, 2 => a ^ (uint)imm, 3 => a & (uint)imm, _ => a };
                if (opc == 3) { SetNZ32(ctx, result); WriteW(ctx, rd, result); }
                else WriteWSp(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Move wide immediate: bits[28:23] = 100101
        if (fixed6 == 0b100101)
        {
            bool sf = (instr >> 31) != 0;
            int opc = (int)(instr >> 29) & 3;
            int hw = (int)(instr >> 21) & 3;
            uint imm16 = (instr >> 5) & 0xFFFF;
            int rd = (int)(instr & 0x1F);
            int shift = hw * 16;

            if (opc == 0) // MOVN
            {
                ulong val = ~((ulong)imm16 << shift);
                if (!sf) val &= 0xFFFFFFFF;
                WriteX(ctx, rd, val);
            }
            else if (opc == 2) // MOVZ
            {
                WriteX(ctx, rd, (ulong)imm16 << shift);
            }
            else if (opc == 3) // MOVK
            {
                ulong old = ReadX(ctx, rd);
                ulong mask = ~(0xFFFFUL << shift);
                WriteX(ctx, rd, (old & mask) | ((ulong)imm16 << shift));
            }
            ctx->Pc += 4;
            return true;
        }

        // Bitfield: bits[28:23] = 100110
        if (fixed6 == 0b100110)
        {
            bool sf = (instr >> 31) != 0;
            int opc = (int)(instr >> 29) & 3;
            int immr = (int)(instr >> 16) & 0x3F;
            int imms = (int)(instr >> 10) & 0x3F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);
            int regSize = sf ? 64 : 32;
            ulong src = ReadX(ctx, rn);
            ulong dst = ReadX(ctx, rd);

            if (opc == 2)
            { ulong rot = sf ? ShiftReg64(src, 3, immr) : ShiftReg32((uint)src, 3, immr); ulong mask = imms < regSize - 1 ? (1UL << (imms + 1)) - 1 : ulong.MaxValue; WriteX(ctx, rd, rot & mask); }
            else if (opc == 0)
            { ulong rot = sf ? ShiftReg64(src, 3, immr) : ShiftReg32((uint)src, 3, immr); ulong mask = (1UL << (imms + 1)) - 1; ulong result = rot & mask; if (imms < regSize - 1 && ((result >> imms) & 1) != 0) result |= ~mask; if (!sf) result &= 0xFFFFFFFF; WriteX(ctx, rd, result); }
            else if (opc == 1)
            { ulong rot = sf ? ShiftReg64(src, 3, immr) : ShiftReg32((uint)src, 3, immr); ulong mask = (1UL << (imms + 1)) - 1; WriteX(ctx, rd, (dst & ~mask) | (rot & mask)); }

            ctx->Pc += 4;
            return true;
        }

        // Extract: bits[28:23] = 100111
        if (fixed6 == 0b100111)
        {
            bool sf = (instr >> 31) != 0;
            int rm = (int)(instr >> 16) & 0x1F;
            int imms = (int)(instr >> 10) & 0x3F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);
            if (sf) { UInt128 c = ((UInt128)ReadX(ctx, rn) << 64) | ReadX(ctx, rm); WriteX(ctx, rd, (ulong)(c >> imms)); }
            else { ulong c = ((ulong)ReadW(ctx, rn) << 32) | ReadW(ctx, rm); WriteW(ctx, rd, (uint)(c >> imms)); }
            ctx->Pc += 4;
            return true;
        }

        return false;
    }

    // ========== Branch, Exception, System ==========

    private static bool HandleBranchSys(CONTEXT_ARM64* ctx, uint instr, byte* address)
    {
        int op0 = (int)(instr >> 29) & 0x7;

        if ((instr >> 26 & 0x1F) == 0b00101) // B / BL (unconditional immediate)
        {
            bool isLink = ((instr >> 31) & 1) != 0;
            int imm26 = (int)(instr & 0x3FFFFFF);
            long offset = (((long)imm26 << 38) >> 36); // sign-extend and *4

            if (isLink) ctx->X30 = ctx->Pc + 4;
            ctx->Pc = (ulong)((long)ctx->Pc + offset);
            return true;
        }

        if ((instr & 0xFF000010) == 0x54000000) // B.cond
        {
            int cond = (int)(instr & 0xF);
            int imm19 = (int)(instr >> 5) & 0x7FFFF;
            long offset = (((long)imm19 << 45) >> 43); // sign-extend and *4

            ctx->Pc = EvalCond(ctx, cond) ? (ulong)((long)ctx->Pc + offset) : ctx->Pc + 4;
            return true;
        }

        if ((instr & 0x7E000000) == 0x34000000) // CBZ/CBNZ
        {
            bool sf = (instr >> 31) != 0;
            bool isNZ = ((instr >> 24) & 1) != 0;
            int imm19 = (int)(instr >> 5) & 0x7FFFF;
            long offset = (((long)imm19 << 45) >> 43);
            int rt = (int)(instr & 0x1F);

            ulong val = sf ? ReadX(ctx, rt) : ReadW(ctx, rt);
            bool taken = isNZ ? val != 0 : val == 0;
            ctx->Pc = taken ? (ulong)((long)ctx->Pc + offset) : ctx->Pc + 4;
            return true;
        }

        if ((instr & 0x7E000000) == 0x36000000) // TBZ/TBNZ
        {
            bool isNZ = ((instr >> 24) & 1) != 0;
            int b5 = (int)(instr >> 31) & 1;
            int b40 = (int)(instr >> 19) & 0x1F;
            int bit = (b5 << 5) | b40;
            int imm14 = (int)(instr >> 5) & 0x3FFF;
            long offset = (((long)imm14 << 50) >> 48); // sign-extend and multiply by 4
            int rt = (int)(instr & 0x1F);

            bool bitSet = ((ReadX(ctx, rt) >> bit) & 1) != 0;
            bool taken = isNZ ? bitSet : !bitSet;
            ctx->Pc = taken ? (ulong)((long)ctx->Pc + offset) : ctx->Pc + 4;
            return true;
        }

        if ((instr & 0xFE000000) == 0xD6000000) // Unconditional branch (register)
        {
            int opc = (int)(instr >> 21) & 0xF;
            int rn = (int)(instr >> 5) & 0x1F;

            switch (opc)
            {
                case 0b0000: // BR
                    ctx->Pc = ReadX(ctx, rn);
                    return true;
                case 0b0001: // BLR
                    ctx->X30 = ctx->Pc + 4;
                    ctx->Pc = ReadX(ctx, rn);
                    return true;
                case 0b0010: // RET
                    ctx->Pc = ReadX(ctx, rn);
                    return true;
            }
        }

        if ((instr & 0xFFE0001F) == 0xD4000001) // SVC
        {
            // Supervisor call — cannot truly emulate, skip
            ctx->Pc += 4;
            return true;
        }

        // NOP / HINT / DMB / DSB / ISB / MSR / MRS
        if ((instr & 0xFFF00000) == 0xD5000000)
        {
            // System instructions
            int op1 = (int)(instr >> 16) & 0x7;
            int crn = (int)(instr >> 12) & 0xF;

            if ((instr & 0xFFFFF01F) == 0xD503201F) // NOP
            {
                ctx->Pc += 4;
                return true;
            }

            // MRS Xt, sysreg / MSR sysreg, Xt
            bool isRead = ((instr >> 21) & 1) != 0; // MRS = read
            int rt = (int)(instr & 0x1F);

            if (isRead) // MRS
            {
                // Common: NZCV, FPCR, FPSR, TPIDR_EL0
                int sysreg = (int)((instr >> 5) & 0x7FFF);
                if (sysreg == 0x5A10) // NZCV
                    WriteX(ctx, rt, ctx->Cpsr & NZCV_MASK);
                else
                    WriteX(ctx, rt, 0); // stub for other sysregs
            }
            else // MSR
            {
                int sysreg = (int)((instr >> 5) & 0x7FFF);
                if (sysreg == 0x5A10) // NZCV
                    ctx->Cpsr = (ctx->Cpsr & ~NZCV_MASK) | (uint)(ReadX(ctx, rt) & NZCV_MASK);
            }
            ctx->Pc += 4;
            return true;
        }

        return false;
    }

    // ========== Load/Store ==========

    private static bool HandleLoadStore(CONTEXT_ARM64* ctx, uint instr)
    {
        int op0 = (int)(instr >> 28) & 0xF;

        // LDP/STP (load/store pair)
        if ((instr & 0x3A000000) == 0x28000000)
        {
            bool sf = ((instr >> 31) & 1) != 0;
            bool isLoad = ((instr >> 22) & 1) != 0;
            int opc = (int)(instr >> 23) & 0x7; // includes pre/post/signed offset
            int imm7 = (int)(instr >> 15) & 0x7F;
            int rt2 = (int)(instr >> 10) & 0x1F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rt1 = (int)(instr & 0x1F);
            int scale = sf ? 3 : 2;
            long offset = ((long)(imm7 << 25)) >> (25 - scale);

            ulong baseAddr = ReadXSp(ctx, rn);
            bool preIndex = (opc & 3) == 3;
            bool postIndex = (opc & 3) == 1;
            bool signedOff = (opc & 3) == 2;

            ulong addr = preIndex || signedOff ? baseAddr + (ulong)offset : baseAddr;

            if (isLoad)
            {
                if (sf) { WriteX(ctx, rt1, *(ulong*)addr); WriteX(ctx, rt2, *(ulong*)(addr + 8)); }
                else { WriteW(ctx, rt1, *(uint*)addr); WriteW(ctx, rt2, *(uint*)(addr + 4)); }
            }
            else
            {
                if (sf) { *(ulong*)addr = ReadX(ctx, rt1); *(ulong*)(addr + 8) = ReadX(ctx, rt2); }
                else { *(uint*)addr = ReadW(ctx, rt1); *(uint*)(addr + 4) = ReadW(ctx, rt2); }
            }

            if (preIndex || postIndex)
            {
                ulong wb = postIndex ? baseAddr + (ulong)offset : addr;
                WriteXSp(ctx, rn, wb);
            }

            ctx->Pc += 4;
            return true;
        }

        // LDR/STR (immediate, register, literal)
        {
            int size = (int)(instr >> 30) & 3;
            int opc = (int)(instr >> 22) & 3;
            bool isLoad = (opc & 1) != 0;
            bool isSigned = (opc & 2) != 0;
            int rt = (int)(instr & 0x1F);
            int rn = (int)(instr >> 5) & 0x1F;

            int dataSize = 8 << size; // 8, 16, 32, 64 bits
            int accessBytes = dataSize / 8;

            // Unsigned offset (bit 24 set, bits 21 not register)
            if (((instr >> 24) & 3) == 1) // unsigned immediate
            {
                uint imm12 = (instr >> 10) & 0xFFF;
                ulong offset = (ulong)imm12 << size;
                ulong baseVal = ReadXSp(ctx, rn);
                ulong addr = baseVal + offset;

                if (EmulatorLogger.IsEnabled)
                    EmulatorLogger.Log($"  LDR/STR: base=X{rn}=0x{baseVal:X} + 0x{offset:X} = 0x{addr:X} size={accessBytes} load={isLoad} rt=X{rt}");

                if (isLoad || isSigned)
                {
                    ulong val = accessBytes switch
                    {
                        1 => *(byte*)addr, 2 => *(ushort*)addr,
                        4 => *(uint*)addr, 8 => *(ulong*)addr, _ => 0
                    };
                    if (isSigned && !isLoad) // e.g., LDRSW (size=2, opc=2)
                    {
                        val = size switch
                        {
                            0 => (ulong)(long)(sbyte)(byte)val,
                            1 => (ulong)(long)(short)(ushort)val,
                            2 => (ulong)(long)(int)(uint)val,
                            _ => val
                        };
                    }
                    if (isSigned && isLoad) // LDRSB/LDRSH/LDRSW
                    {
                        val = size switch
                        {
                            0 => (ulong)(long)(sbyte)(byte)val,
                            1 => (ulong)(long)(short)(ushort)val,
                            2 => (ulong)(long)(int)(uint)val,
                            _ => val
                        };
                    }
                    WriteX(ctx, rt, val);
                    if (EmulatorLogger.IsEnabled)
                        EmulatorLogger.Log($"    loaded 0x{val:X} into X{rt}");
                }
                else // store
                {
                    ulong val = ReadX(ctx, rt);
                    switch (accessBytes)
                    {
                        case 1: *(byte*)addr = (byte)val; break;
                        case 2: *(ushort*)addr = (ushort)val; break;
                        case 4: *(uint*)addr = (uint)val; break;
                        case 8: *(ulong*)addr = val; break;
                    }
                    if (EmulatorLogger.IsEnabled)
                        EmulatorLogger.Log($"    stored 0x{val:X} from X{rt}");
                }
                ctx->Pc += 4;
                return true;
            }

            // Pre/post-index
            if (((instr >> 24) & 3) == 0 && ((instr >> 10) & 3) != 0)
            {
                int imm9 = (int)(instr >> 12) & 0x1FF;
                long offset = ((long)(imm9 << 23)) >> 23; // sign-extend
                bool preIndex = ((instr >> 11) & 1) != 0;
                ulong baseAddr = ReadXSp(ctx, rn);
                ulong addr = preIndex ? baseAddr + (ulong)offset : baseAddr;

                if (isLoad || isSigned)
                {
                    ulong val = accessBytes switch
                    {
                        1 => *(byte*)addr, 2 => *(ushort*)addr,
                        4 => *(uint*)addr, 8 => *(ulong*)addr, _ => 0
                    };
                    if (isSigned)
                    {
                        val = size switch
                        {
                            0 => (ulong)(long)(sbyte)(byte)val,
                            1 => (ulong)(long)(short)(ushort)val,
                            2 => (ulong)(long)(int)(uint)val,
                            _ => val
                        };
                    }
                    WriteX(ctx, rt, val);
                }
                else
                {
                    ulong val = ReadX(ctx, rt);
                    switch (accessBytes) { case 1: *(byte*)addr = (byte)val; break; case 2: *(ushort*)addr = (ushort)val; break; case 4: *(uint*)addr = (uint)val; break; case 8: *(ulong*)addr = val; break; }
                }

                ulong wb = preIndex ? addr : baseAddr + (ulong)offset;
                WriteXSp(ctx, rn, wb);
                ctx->Pc += 4;
                return true;
            }

            // LDR (literal) - PC-relative
            if ((instr & 0x3B000000) == 0x18000000)
            {
                int imm19 = (int)(instr >> 5) & 0x7FFFF;
                long offset = (((long)imm19 << 45) >> 43);
                ulong addr = (ulong)((long)ctx->Pc + offset);

                if (size == 0) WriteW(ctx, rt, *(uint*)addr);
                else WriteX(ctx, rt, *(ulong*)addr);
                ctx->Pc += 4;
                return true;
            }

            // Register offset
            if (((instr >> 21) & 1) != 0 && ((instr >> 10) & 3) == 2)
            {
                int rm = (int)(instr >> 16) & 0x1F;
                int opt = (int)(instr >> 13) & 7;
                int S = (int)(instr >> 12) & 1;
                ulong baseAddr = ReadXSp(ctx, rn);
                ulong offset = ExtendReg(ReadX(ctx, rm), opt, S != 0 ? size : 0);
                ulong addr = baseAddr + offset;

                if (isLoad || isSigned)
                {
                    ulong val = accessBytes switch { 1 => *(byte*)addr, 2 => *(ushort*)addr, 4 => *(uint*)addr, 8 => *(ulong*)addr, _ => 0 };
                    if (isSigned) val = size switch { 0 => (ulong)(long)(sbyte)(byte)val, 1 => (ulong)(long)(short)(ushort)val, 2 => (ulong)(long)(int)(uint)val, _ => val };
                    WriteX(ctx, rt, val);
                }
                else
                {
                    ulong val = ReadX(ctx, rt);
                    switch (accessBytes) { case 1: *(byte*)addr = (byte)val; break; case 2: *(ushort*)addr = (ushort)val; break; case 4: *(uint*)addr = (uint)val; break; case 8: *(ulong*)addr = val; break; }
                }
                ctx->Pc += 4;
                return true;
            }
        }

        // Unimplemented load/store variant — skip (4 bytes)
        ctx->Pc += 4;
        return true;
    }

    // ========== Data Processing (Register) ==========

    private static bool HandleDataProcReg(CONTEXT_ARM64* ctx, uint instr)
    {
        bool sf = (instr >> 31) != 0;
        int op1 = (int)(instr >> 28) & 1;
        int op2 = (int)(instr >> 21) & 0xF;

        // Logical (shifted register): AND/ORR/EOR/ANDS
        if (op1 == 0 && (op2 & 0x8) == 0)
        {
            int opc = (int)(instr >> 29) & 3;
            bool N = ((instr >> 21) & 1) != 0;
            int shift = (int)(instr >> 22) & 3;
            int rm = (int)(instr >> 16) & 0x1F;
            int imm6 = (int)(instr >> 10) & 0x3F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);

            if (sf)
            {
                ulong a = ReadX(ctx, rn);
                ulong b = ShiftReg64(ReadX(ctx, rm), shift, imm6);
                if (N) b = ~b;
                ulong result = opc switch { 0 => a & b, 1 => a | b, 2 => a ^ b, 3 => a & b, _ => 0 };
                if (opc == 3) SetNZ64(ctx, result); // ANDS
                WriteX(ctx, rd, result);
            }
            else
            {
                uint a = ReadW(ctx, rn);
                uint b = ShiftReg32(ReadW(ctx, rm), shift, imm6);
                if (N) b = ~b;
                uint result = opc switch { 0 => a & b, 1 => a | b, 2 => a ^ b, 3 => a & b, _ => 0 };
                if (opc == 3) SetNZ32(ctx, result);
                WriteW(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Add/subtract (shifted register)
        if (op1 == 0 && (op2 & 0x9) == 0x8)
        {
            bool op = ((instr >> 30) & 1) != 0;
            bool S = ((instr >> 29) & 1) != 0;
            int shift = (int)(instr >> 22) & 3;
            int rm = (int)(instr >> 16) & 0x1F;
            int imm6 = (int)(instr >> 10) & 0x3F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);

            if (sf)
            {
                ulong a = ReadX(ctx, rn);
                ulong b = ShiftReg64(ReadX(ctx, rm), shift, imm6);
                ulong result = op ? a - b : a + b;
                if (S) { if (op) SetNZCV_Sub64(ctx, a, b, result); else SetNZCV_Add64(ctx, a, b, result); WriteX(ctx, rd, result); }
                else WriteXSp(ctx, rd, result);
            }
            else
            {
                uint a = ReadW(ctx, rn);
                uint b = ShiftReg32(ReadW(ctx, rm), shift, imm6);
                uint result = op ? a - b : a + b;
                if (S) { if (op) SetNZCV_Sub32(ctx, a, b, result); else SetNZCV_Add32(ctx, a, b, result); WriteW(ctx, rd, result); }
                else WriteWSp(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Add/subtract (extended register)
        if (op1 == 0 && (op2 & 0x9) == 0x9)
        {
            bool op = ((instr >> 30) & 1) != 0;
            bool S = ((instr >> 29) & 1) != 0;
            int rm = (int)(instr >> 16) & 0x1F;
            int option = (int)(instr >> 13) & 7;
            int imm3 = (int)(instr >> 10) & 7;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);

            ulong a = sf ? ReadXSp(ctx, rn) : ReadWSp(ctx, rn);
            ulong b = ExtendReg(ReadX(ctx, rm), option, imm3);

            if (sf)
            {
                ulong result = op ? a - b : a + b;
                if (S) { if (op) SetNZCV_Sub64(ctx, a, b, result); else SetNZCV_Add64(ctx, a, b, result); WriteX(ctx, rd, result); }
                else WriteXSp(ctx, rd, result);
            }
            else
            {
                uint result = op ? (uint)a - (uint)b : (uint)a + (uint)b;
                if (S) { if (op) SetNZCV_Sub32(ctx, (uint)a, (uint)b, result); else SetNZCV_Add32(ctx, (uint)a, (uint)b, result); WriteW(ctx, rd, result); }
                else WriteWSp(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Conditional select (CSEL/CSINC/CSINV/CSNEG)
        if ((instr & 0x1FE00000) == 0x1A800000)
        {
            int op2b = (int)(instr >> 10) & 3;
            int cond = (int)(instr >> 12) & 0xF;
            int rm = (int)(instr >> 16) & 0x1F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);
            bool isInv = ((instr >> 30) & 1) != 0;

            bool condTrue = EvalCond(ctx, cond);

            if (sf)
            {
                ulong valTrue = ReadX(ctx, rn);
                ulong valFalse = ReadX(ctx, rm);
                if (!isInv) valFalse = op2b == 1 ? valFalse + 1 : valFalse; // CSINC
                else valFalse = op2b == 0 ? ~valFalse : (ulong)(-(long)valFalse); // CSINV/CSNEG
                WriteX(ctx, rd, condTrue ? valTrue : valFalse);
            }
            else
            {
                uint valTrue = ReadW(ctx, rn);
                uint valFalse = ReadW(ctx, rm);
                if (!isInv) valFalse = op2b == 1 ? valFalse + 1 : valFalse;
                else valFalse = op2b == 0 ? ~valFalse : (uint)(-(int)valFalse);
                WriteW(ctx, rd, condTrue ? valTrue : valFalse);
            }
            ctx->Pc += 4;
            return true;
        }

        // Data processing (2 source): UDIV/SDIV/LSLV/LSRV/ASRV/RORV
        if ((instr & 0x5FE00000) == 0x1AC00000)
        {
            int opcode2 = (int)(instr >> 10) & 0x3F;
            int rm = (int)(instr >> 16) & 0x1F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);

            if (sf)
            {
                ulong a = ReadX(ctx, rn), b = ReadX(ctx, rm);
                ulong result = opcode2 switch
                {
                    0b000010 => b != 0 ? a / b : 0,                  // UDIV
                    0b000011 => b != 0 ? (ulong)((long)a / (long)b) : 0, // SDIV
                    0b001000 => a << (int)(b & 63),                   // LSLV
                    0b001001 => a >> (int)(b & 63),                   // LSRV
                    0b001010 => (ulong)((long)a >> (int)(b & 63)),    // ASRV
                    0b001011 => ShiftReg64(a, 3, (int)(b & 63)),      // RORV
                    _ => 0
                };
                WriteX(ctx, rd, result);
            }
            else
            {
                uint a = ReadW(ctx, rn), b = ReadW(ctx, rm);
                uint result = opcode2 switch
                {
                    0b000010 => b != 0 ? a / b : 0,
                    0b000011 => b != 0 ? (uint)((int)a / (int)b) : 0,
                    0b001000 => a << (int)(b & 31),
                    0b001001 => a >> (int)(b & 31),
                    0b001010 => (uint)((int)a >> (int)(b & 31)),
                    0b001011 => ShiftReg32(a, 3, (int)(b & 31)),
                    _ => 0
                };
                WriteW(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Data processing (1 source): RBIT/REV/REV16/REV32/CLZ/CLS
        if ((instr & 0x5FE00000) == 0x5AC00000)
        {
            int opcode2 = (int)(instr >> 10) & 0x3F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);

            if (sf)
            {
                ulong val = ReadX(ctx, rn);
                ulong result = opcode2 switch
                {
                    0b000000 => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(val), // RBIT (simplified as REV for now)
                    0b000001 => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(val), // REV
                    0b000100 => (ulong)BitOperations.LeadingZeroCount(val), // CLZ
                    _ => val
                };
                WriteX(ctx, rd, result);
            }
            else
            {
                uint val = ReadW(ctx, rn);
                uint result = opcode2 switch
                {
                    0b000000 => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(val),
                    0b000001 => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(val),
                    0b000100 => (uint)BitOperations.LeadingZeroCount(val),
                    _ => val
                };
                WriteW(ctx, rd, result);
            }
            ctx->Pc += 4;
            return true;
        }

        // Multiply (MADD/MSUB/SMADDL/SMSUBL/UMADDL/UMSUBL/SMULH/UMULH)
        if ((instr & 0x1F000000) == 0x1B000000)
        {
            int op31 = (int)(instr >> 21) & 7;
            int rm = (int)(instr >> 16) & 0x1F;
            int ra = (int)(instr >> 10) & 0x1F;
            int rn = (int)(instr >> 5) & 0x1F;
            int rd = (int)(instr & 0x1F);
            bool o0 = ((instr >> 15) & 1) != 0;

            if (op31 == 0) // MADD/MSUB
            {
                if (sf)
                {
                    ulong a = ReadX(ctx, rn), b = ReadX(ctx, rm), acc = ReadX(ctx, ra);
                    WriteX(ctx, rd, o0 ? acc - a * b : acc + a * b);
                }
                else
                {
                    uint a = ReadW(ctx, rn), b = ReadW(ctx, rm), acc = ReadW(ctx, ra);
                    WriteW(ctx, rd, o0 ? acc - a * b : acc + a * b);
                }
            }
            else if (op31 == 1) // SMADDL/SMSUBL
            {
                long a = (int)ReadW(ctx, rn), b = (int)ReadW(ctx, rm);
                long acc = (long)ReadX(ctx, ra);
                WriteX(ctx, rd, (ulong)(o0 ? acc - a * b : acc + a * b));
            }
            else if (op31 == 5) // UMADDL/UMSUBL
            {
                ulong a = ReadW(ctx, rn), b = ReadW(ctx, rm), acc = ReadX(ctx, ra);
                WriteX(ctx, rd, o0 ? acc - a * b : acc + a * b);
            }
            else if (op31 == 2) // SMULH
            {
                Int128 r = (Int128)(long)ReadX(ctx, rn) * (long)ReadX(ctx, rm);
                WriteX(ctx, rd, (ulong)(long)(r >> 64));
            }
            else if (op31 == 6) // UMULH
            {
                UInt128 r = (UInt128)ReadX(ctx, rn) * ReadX(ctx, rm);
                WriteX(ctx, rd, (ulong)(r >> 64));
            }

            ctx->Pc += 4;
            return true;
        }

        // Conditional compare (CCMP/CCMN)
        if ((instr & 0x1FE00800) == 0x1A400000 || (instr & 0x1FE00800) == 0x1A400800)
        {
            bool isImm = ((instr >> 11) & 1) != 0;
            int cond = (int)(instr >> 12) & 0xF;
            int rm = (int)(instr >> 16) & 0x1F;
            int rn = (int)(instr >> 5) & 0x1F;
            uint nzcv = instr & 0xF;
            bool isSub = ((instr >> 30) & 1) != 0; // CCMP vs CCMN

            if (EvalCond(ctx, cond))
            {
                ulong a = sf ? ReadX(ctx, rn) : ReadW(ctx, rn);
                ulong b = isImm ? (ulong)rm : (sf ? ReadX(ctx, rm) : ReadW(ctx, rm)); // rm is imm5 for immediate form

                if (sf)
                {
                    ulong result = isSub ? a - b : a + b;
                    if (isSub) SetNZCV_Sub64(ctx, a, b, result);
                    else SetNZCV_Add64(ctx, a, b, result);
                }
                else
                {
                    uint result = isSub ? (uint)a - (uint)b : (uint)a + (uint)b;
                    if (isSub) SetNZCV_Sub32(ctx, (uint)a, (uint)b, result);
                    else SetNZCV_Add32(ctx, (uint)a, (uint)b, result);
                }
            }
            else
            {
                // Set NZCV directly from immediate
                ctx->Cpsr = (ctx->Cpsr & ~NZCV_MASK) | (nzcv << 28);
            }
            ctx->Pc += 4;
            return true;
        }

        return false;
    }

    // ========== SIMD/FP (basic stubs) ==========

    private static bool HandleSimdFp(CONTEXT_ARM64* ctx, uint instr)
    {
        // For now: skip SIMD/FP instructions (advance PC by 4)
        // TODO: implement NEON vector ops
        ctx->Pc += 4;
        return true;
    }

    // ========== Bitmask immediate decoder ==========

    private static ulong DecodeBitmaskImm(uint instr, bool sf)
    {
        int N = (int)(instr >> 22) & 1;
        int immr = (int)(instr >> 16) & 0x3F;
        int imms = (int)(instr >> 10) & 0x3F;

        int len = 31 - BitOperations.LeadingZeroCount((uint)((N << 6) | (~imms & 0x3F)));
        if (len < 1) return 0;

        int esize = 1 << len;
        int levels = esize - 1;
        int s = imms & levels;
        int r = immr & levels;

        ulong welem = (1UL << (s + 1)) - 1;
        // Rotate right by r
        welem = ((welem >> r) | (welem << (esize - r))) & ((1UL << esize) - 1);

        // Replicate to fill 64 bits
        ulong result = 0;
        for (int i = 0; i < 64; i += esize)
            result |= welem << i;

        if (!sf) result &= 0xFFFFFFFF;
        return result;
    }
}
