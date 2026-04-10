using static NoRWX.Emulator;

namespace NoRWX.Core;

/// <summary>
/// Provides indexed access to CONTEXT registers (RAX=0 through R15=15).
/// </summary>
public static unsafe class RegisterHelper
{
    /// <summary>Read a 64-bit register by index (0=RAX, 1=RCX, ..., 15=R15).</summary>
    public static ulong Read64(CONTEXT* ctx, int index)
    {
        return *(&ctx->Rax + (index & 15));
    }

    /// <summary>Read a 32-bit register by index (zero-extended).</summary>
    public static uint Read32(CONTEXT* ctx, int index)
    {
        return (uint)(*(&ctx->Rax + (index & 15)));
    }

    /// <summary>Read a 16-bit register by index.</summary>
    public static ushort Read16(CONTEXT* ctx, int index)
    {
        return (ushort)(*(&ctx->Rax + (index & 15)));
    }

    /// <summary>Read an 8-bit register by index. Without REX, indices 4-7 map to AH/CH/DH/BH.</summary>
    public static byte Read8(CONTEXT* ctx, int index, bool hasRex)
    {
        if (!hasRex && index >= 4 && index <= 7)
        {
            // AH=4, CH=5, DH=6, BH=7 → high byte of AX/CX/DX/BX
            int baseIdx = index - 4; // 0=RAX, 1=RCX, 2=RDX, 3=RBX
            return *((byte*)(&ctx->Rax + baseIdx) + 1);
        }
        return (byte)(*(&ctx->Rax + (index & 15)));
    }

    /// <summary>Write a 64-bit value to a register.</summary>
    public static void Write64(CONTEXT* ctx, int index, ulong value)
    {
        *(&ctx->Rax + (index & 15)) = value;
    }

    /// <summary>Write a 32-bit value to a register (zero-extends to 64-bit).</summary>
    public static void Write32(CONTEXT* ctx, int index, uint value)
    {
        *(&ctx->Rax + (index & 15)) = value; // zero-extend
    }

    /// <summary>Write a 16-bit value to a register (preserves upper bits).</summary>
    public static void Write16(CONTEXT* ctx, int index, ushort value)
    {
        ulong* reg = &ctx->Rax + (index & 15);
        *reg = (*reg & ~0xFFFFUL) | value;
    }

    /// <summary>Write an 8-bit value to a register (preserves upper bits). Without REX, indices 4-7 map to AH/CH/DH/BH.</summary>
    public static void Write8(CONTEXT* ctx, int index, byte value, bool hasRex)
    {
        if (!hasRex && index >= 4 && index <= 7)
        {
            int baseIdx = index - 4;
            *((byte*)(&ctx->Rax + baseIdx) + 1) = value;
            return;
        }
        ulong* reg = &ctx->Rax + (index & 15);
        *reg = (*reg & ~0xFFUL) | value;
    }

    /// <summary>Get a pointer to a register by index.</summary>
    public static ulong* GetRegPtr(CONTEXT* ctx, int index)
    {
        return &ctx->Rax + (index & 15);
    }

    /// <summary>Read a register value with the specified operand size.</summary>
    public static ulong ReadSized(CONTEXT* ctx, int index, int operandSize, bool hasRex = true)
    {
        return operandSize switch
        {
            8 => Read8(ctx, index, hasRex),
            16 => Read16(ctx, index),
            32 => Read32(ctx, index),
            64 => Read64(ctx, index),
            _ => Read64(ctx, index)
        };
    }

    /// <summary>Write a value to a register with the specified operand size.</summary>
    public static void WriteSized(CONTEXT* ctx, int index, ulong value, int operandSize, bool hasRex = true)
    {
        switch (operandSize)
        {
            case 8: Write8(ctx, index, (byte)value, hasRex); break;
            case 16: Write16(ctx, index, (ushort)value); break;
            case 32: Write32(ctx, index, (uint)value); break;
            case 64: Write64(ctx, index, value); break;
        }
    }

    public static string RegName(int index, int operandSize) => operandSize switch
    {
        8 => index switch
        {
            0 => "AL", 1 => "CL", 2 => "DL", 3 => "BL",
            4 => "SPL", 5 => "BPL", 6 => "SIL", 7 => "DIL",
            _ => $"R{index}B"
        },
        16 => index switch
        {
            0 => "AX", 1 => "CX", 2 => "DX", 3 => "BX",
            4 => "SP", 5 => "BP", 6 => "SI", 7 => "DI",
            _ => $"R{index}W"
        },
        32 => index switch
        {
            0 => "EAX", 1 => "ECX", 2 => "EDX", 3 => "EBX",
            4 => "ESP", 5 => "EBP", 6 => "ESI", 7 => "EDI",
            _ => $"R{index}D"
        },
        64 => index switch
        {
            0 => "RAX", 1 => "RCX", 2 => "RDX", 3 => "RBX",
            4 => "RSP", 5 => "RBP", 6 => "RSI", 7 => "RDI",
            8 => "R8", 9 => "R9", 10 => "R10", 11 => "R11",
            12 => "R12", 13 => "R13", 14 => "R14", 15 => "R15",
            _ => $"R{index}"
        },
        _ => $"R{index}"
    };
}
