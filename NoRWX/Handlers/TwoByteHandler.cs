using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Handlers;

/// <summary>
/// Handles two-byte opcodes (0F xx) not covered by other handlers:
/// XADD, CMPXCHG, SHLD, SHRD, CPUID, RDTSC, UD2, SYSCALL, PUSH/POP FS/GS,
/// PUSHF, POPF, MOVNTI, POPCNT, LZCNT, TZCNT.
/// </summary>
public static unsafe class TwoByteHandler
{
    /// <summary>XADD r/m, r (0F C0=8bit, 0F C1=32/64bit)</summary>
    public static bool HandleXadd(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        int operandSize = op2 == 0xC0 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong result = dst + src;
        // XADD: TEMP=SRC+DEST; SRC=DEST; DEST=TEMP
        RegisterHelper.WriteSized(ctx, modrm.Reg, dst, operandSize, prefix.HasRex);
        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"XADD r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMPXCHG r/m, r (0F B0=8bit, 0F B1=32/64bit)</summary>
    public static bool HandleCmpxchg(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        int operandSize = op2 == 0xB0 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong acc = RegisterHelper.ReadSized(ctx, 0, operandSize); // AL/AX/EAX/RAX
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong cmpResult = acc - dst;
        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, acc, dst, cmpResult, operandSize);

        if (acc == dst)
        {
            // ZF=1, dest <- src
            if (isMem) InstructionDecoder.WriteMemory(addr, src, operandSize);
            else RegisterHelper.WriteSized(ctx, modrm.Rm, src, operandSize, prefix.HasRex);
        }
        else
        {
            // ZF=0, accumulator <- dest
            RegisterHelper.WriteSized(ctx, 0, dst, operandSize);
        }

        log($"CMPXCHG r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SHLD r/m, r, imm8 (0F A4) / SHLD r/m, r, CL (0F A5)</summary>
    public static bool HandleShld(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        int operandSize = prefix.OperandSize;
        bool byCL = op2 == 0xA5;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        byte count = byCL ? (byte)(ctx->Rcx & 0x3F) : ip[offs++];
        count &= (byte)(operandSize == 64 ? 0x3F : 0x1F);

        if (count > 0)
        {
            ulong result = (dst << count) | (src >> (operandSize - count));
            if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
            else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);
        }

        log($"SHLD r/m{operandSize}, r{operandSize}, {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SHRD r/m, r, imm8 (0F AC) / SHRD r/m, r, CL (0F AD)</summary>
    public static bool HandleShrd(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        int operandSize = prefix.OperandSize;
        bool byCL = op2 == 0xAD;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        byte count = byCL ? (byte)(ctx->Rcx & 0x3F) : ip[offs++];
        count &= (byte)(operandSize == 64 ? 0x3F : 0x1F);

        if (count > 0)
        {
            ulong result = (dst >> count) | (src << (operandSize - count));
            if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
            else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);
        }

        log($"SHRD r/m{operandSize}, r{operandSize}, {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>UD2 (0F 0B)</summary>
    public static bool HandleUd2(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        log("UD2", 2);
        return false; // intentional undefined instruction
    }

    /// <summary>CPUID (0F A2)</summary>
    public static bool HandleCpuid(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        // Return minimal CPUID info
        uint leaf = (uint)ctx->Rax;
        switch (leaf)
        {
            case 0: // Max leaf + vendor
                ctx->Rax = 0x16; // max leaf
                ctx->Rbx = 0x756E6547; // "Genu"
                ctx->Rdx = 0x49656E69; // "ineI"
                ctx->Rcx = 0x6C65746E; // "ntel"
                break;
            case 1: // Feature bits
                ctx->Rax = 0x000806E9; // family/model
                ctx->Rbx = 0;
                ctx->Rcx = 0x7FFAFBBF; // SSE4.2, POPCNT, etc.
                ctx->Rdx = 0xBFEBFBFF;
                break;
            default:
                ctx->Rax = 0;
                ctx->Rbx = 0;
                ctx->Rcx = 0;
                ctx->Rdx = 0;
                break;
        }

        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F A2
        log($"CPUID (leaf=0x{leaf:X})", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>RDTSC (0F 31)</summary>
    public static bool HandleRdtsc(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        ulong tsc = (ulong)Environment.TickCount64 * 3000; // approximate TSC
        ctx->Rax = tsc & 0xFFFFFFFF;
        ctx->Rdx = tsc >> 32;

        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2;
        log($"RDTSC => 0x{tsc:X}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SYSCALL (0F 05) - not truly emulatable, returns false</summary>
    public static bool HandleSyscall(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        log("SYSCALL (not emulated)", 2);
        return false;
    }

    /// <summary>POPCNT r, r/m (F3 0F B8)</summary>
    public static bool HandlePopcnt(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F B8
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        int count = System.Numerics.BitOperations.PopCount(src);
        RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)count, operandSize);

        ctx->EFlags = (ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.ZF | FlagsCalculator.SF | FlagsCalculator.OF | FlagsCalculator.PF | FlagsCalculator.AF));
        if (count == 0) ctx->EFlags |= FlagsCalculator.ZF;

        log($"POPCNT r{operandSize}, r/m{operandSize} => {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>LZCNT r, r/m (F3 0F BD)</summary>
    public static bool HandleLzcnt(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F BD
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        int count = operandSize == 64
            ? System.Numerics.BitOperations.LeadingZeroCount(src)
            : System.Numerics.BitOperations.LeadingZeroCount((uint)src);
        RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)count, operandSize);

        ctx->EFlags = (ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.ZF));
        if (src == 0) ctx->EFlags |= FlagsCalculator.CF;
        if (count == 0) ctx->EFlags |= FlagsCalculator.ZF;

        log($"LZCNT r{operandSize}, r/m{operandSize} => {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>TZCNT r, r/m (F3 0F BC)</summary>
    public static bool HandleTzcnt(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F BC
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        int count = System.Numerics.BitOperations.TrailingZeroCount(src);
        if (operandSize == 32 && src == 0) count = 32;
        RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)count, operandSize);

        ctx->EFlags = (ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.ZF));
        if (src == 0) ctx->EFlags |= FlagsCalculator.CF;
        if (count == 0) ctx->EFlags |= FlagsCalculator.ZF;

        log($"TZCNT r{operandSize}, r/m{operandSize} => {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
