using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Handlers;

/// <summary>
/// Handles stack instructions: PUSH, POP.
/// </summary>
public static unsafe class StackHandler
{
    /// <summary>PUSH r64 (50-57)</summary>
    public static bool HandlePushReg(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int reg = (opcode - 0x50) | (prefix.B ? 8 : 0);
        ulong value = RegisterHelper.Read64(ctx, reg);

        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = value;

        log($"PUSH {RegisterHelper.RegName(reg, 64)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>POP r64 (58-5F)</summary>
    public static bool HandlePopReg(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int reg = (opcode - 0x58) | (prefix.B ? 8 : 0);
        ulong value = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;

        RegisterHelper.Write64(ctx, reg, value);

        log($"POP {RegisterHelper.RegName(reg, 64)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>PUSH imm8 (6A)</summary>
    public static bool HandlePushImm8(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        sbyte imm8 = *(sbyte*)(ip + offs++);
        ulong value = (ulong)(long)imm8; // sign-extend to 64

        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = value;

        log($"PUSH imm8 0x{(byte)imm8:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>PUSH imm32 (68)</summary>
    public static bool HandlePushImm32(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        int imm32 = *(int*)(ip + offs);
        offs += 4;
        ulong value = (ulong)(long)imm32; // sign-extend to 64

        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = value;

        log($"PUSH imm32 0x{(uint)imm32:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>POP r/m64 (8F /0)</summary>
    public static bool HandlePopRm64(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (((modrm.Raw >> 3) & 7) != 0) return false; // must be /0

        ulong value = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;

        if (modrm.Mod == 0b11)
        {
            RegisterHelper.Write64(ctx, modrm.Rm, value);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            *(ulong*)addr = value;
        }

        log($"POP r/m64 => 0x{value:X}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
