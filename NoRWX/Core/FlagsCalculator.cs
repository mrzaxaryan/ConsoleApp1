using System.Numerics;

namespace NoRWX.Core;

public static class FlagsCalculator
{
    // EFLAGS bit positions
    public const uint CF = 1u << 0;   // Carry Flag
    public const uint PF = 1u << 2;   // Parity Flag
    public const uint AF = 1u << 4;   // Auxiliary Carry Flag
    public const uint ZF = 1u << 6;   // Zero Flag
    public const uint SF = 1u << 7;   // Sign Flag
    public const uint OF = 1u << 11;  // Overflow Flag
    public const uint DF = 1u << 10;  // Direction Flag

    private const uint ArithmeticFlags = CF | PF | AF | ZF | SF | OF;
    private const uint LogicFlags = CF | PF | ZF | SF | OF; // CF=0, OF=0 for logic ops

    /// <summary>Compute parity of the low byte (true = even parity).</summary>
    public static bool Parity(ulong value)
    {
        return (BitOperations.PopCount((uint)(value & 0xFF)) & 1) == 0;
    }

    /// <summary>Update flags after an ADD/ADC operation.</summary>
    public static uint SetAddFlags(uint eflags, ulong a, ulong b, ulong result, int operandSize, int carry = 0)
    {
        uint f = eflags & ~ArithmeticFlags;
        ulong signBit = SignBit(operandSize);
        ulong mask = SizeMask(operandSize);

        ulong maskedResult = result & mask;
        ulong maskedA = a & mask;
        ulong maskedB = b & mask;

        // CF: unsigned overflow
        if (result > mask || maskedResult < maskedA)
            f |= CF;

        // OF: signed overflow - both operands same sign, result different sign
        if (((maskedA ^ maskedResult) & (maskedB ^ maskedResult) & signBit) != 0)
            f |= OF;

        // AF: carry from bit 3 to bit 4
        if ((((uint)a & 0xF) + ((uint)b & 0xF) + (uint)carry & 0x10) != 0)
            f |= AF;

        // ZF
        if (maskedResult == 0) f |= ZF;

        // SF
        if ((maskedResult & signBit) != 0) f |= SF;

        // PF
        if (Parity(maskedResult)) f |= PF;

        return f;
    }

    /// <summary>Update flags after a SUB/SBB/CMP operation.</summary>
    public static uint SetSubFlags(uint eflags, ulong a, ulong b, ulong result, int operandSize, int borrow = 0)
    {
        uint f = eflags & ~ArithmeticFlags;
        ulong signBit = SignBit(operandSize);
        ulong mask = SizeMask(operandSize);

        ulong maskedResult = result & mask;
        ulong maskedA = a & mask;
        ulong maskedB = b & mask;

        // CF: unsigned borrow
        if (maskedA < maskedB + (ulong)borrow)
            f |= CF;

        // OF: signed overflow
        if (((maskedA ^ maskedB) & (maskedA ^ maskedResult) & signBit) != 0)
            f |= OF;

        // AF
        if (((maskedA ^ maskedB ^ maskedResult) & 0x10) != 0)
            f |= AF;

        // ZF
        if (maskedResult == 0) f |= ZF;

        // SF
        if ((maskedResult & signBit) != 0) f |= SF;

        // PF
        if (Parity(maskedResult)) f |= PF;

        return f;
    }

    /// <summary>Update flags after a logic operation (AND/OR/XOR/TEST). CF=0, OF=0.</summary>
    public static uint SetLogicFlags(uint eflags, ulong result, int operandSize)
    {
        uint f = eflags & ~LogicFlags;
        ulong signBit = SignBit(operandSize);
        ulong mask = SizeMask(operandSize);
        ulong maskedResult = result & mask;

        // CF = 0, OF = 0 (already cleared)
        if (maskedResult == 0) f |= ZF;
        if ((maskedResult & signBit) != 0) f |= SF;
        if (Parity(maskedResult)) f |= PF;

        return f;
    }

    /// <summary>Update flags after INC. CF is not affected.</summary>
    public static uint SetIncFlags(uint eflags, ulong a, ulong result, int operandSize)
    {
        uint f = eflags & ~(PF | AF | ZF | SF | OF); // CF preserved
        ulong signBit = SignBit(operandSize);
        ulong mask = SizeMask(operandSize);
        ulong maskedResult = result & mask;
        ulong maskedA = a & mask;

        // OF: signed overflow (a was max positive)
        if (((maskedA ^ maskedResult) & (~0UL ^ maskedResult) & signBit) != 0)
            f |= OF;

        if (((maskedA ^ 1 ^ maskedResult) & 0x10) != 0) f |= AF;
        if (maskedResult == 0) f |= ZF;
        if ((maskedResult & signBit) != 0) f |= SF;
        if (Parity(maskedResult)) f |= PF;

        return f;
    }

    /// <summary>Update flags after DEC. CF is not affected.</summary>
    public static uint SetDecFlags(uint eflags, ulong a, ulong result, int operandSize)
    {
        uint f = eflags & ~(PF | AF | ZF | SF | OF); // CF preserved
        ulong signBit = SignBit(operandSize);
        ulong mask = SizeMask(operandSize);
        ulong maskedResult = result & mask;
        ulong maskedA = a & mask;

        // OF: signed overflow (a was min negative)
        if (((maskedA ^ 1) & (maskedA ^ maskedResult) & signBit) != 0)
            f |= OF;

        if (((maskedA ^ 1 ^ maskedResult) & 0x10) != 0) f |= AF;
        if (maskedResult == 0) f |= ZF;
        if ((maskedResult & signBit) != 0) f |= SF;
        if (Parity(maskedResult)) f |= PF;

        return f;
    }

    private static ulong SignBit(int operandSize) => operandSize switch
    {
        8 => 0x80UL,
        16 => 0x8000UL,
        32 => 0x8000_0000UL,
        64 => 0x8000_0000_0000_0000UL,
        _ => 0x8000_0000UL
    };

    private static ulong SizeMask(int operandSize) => operandSize switch
    {
        8 => 0xFFUL,
        16 => 0xFFFFUL,
        32 => 0xFFFF_FFFFUL,
        64 => 0xFFFF_FFFF_FFFF_FFFFUL,
        _ => 0xFFFF_FFFFUL
    };
}
