using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

/// <summary>
/// Handles data movement instructions: MOV, MOVZX, MOVSX, MOVSXD, LEA, XCHG, CMOVcc.
/// </summary>
public static unsafe class MoveHandler
{
    /// <summary>MOV r/m, r (88=8bit, 89=32/64bit)</summary>
    public static bool HandleMovRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x88 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        if (modrm.Mod == 0b11)
        {
            RegisterHelper.WriteSized(ctx, modrm.Rm, src, operandSize, prefix.HasRex);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            InstructionDecoder.WriteMemory(addr, src, operandSize);
        }

        log($"MOV r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOV r, r/m (8A=8bit, 8B=32/64bit)</summary>
    public static bool HandleMovRRm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x8A ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        RegisterHelper.WriteSized(ctx, modrm.Reg, src, operandSize, prefix.HasRex);

        log($"MOV r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOV r/m, imm (C6 /0=8bit, C7 /0=32/64bit)</summary>
    public static bool HandleMovRmImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0xC6 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (((modrm.Raw >> 3) & 7) != 0) return false; // must be /0

        // For memory operands, resolve address first
        ulong addr = 0;
        bool isMem = modrm.Mod != 0b11;
        if (isMem)
            addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

        // Read immediate
        int immSize = operandSize == 8 ? 8 : (operandSize == 64 ? 32 : operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong value;
        if (prefix.W) // REX.W: sign-extend imm32 to 64
            value = (ulong)immSigned;
        else
            value = (ulong)immSigned & ((1UL << (operandSize > 32 ? 32 : operandSize)) - 1);

        if (isMem)
            InstructionDecoder.WriteMemory(addr, value, operandSize == 64 && prefix.W ? 64 : operandSize);
        else
            RegisterHelper.WriteSized(ctx, modrm.Rm, value, operandSize, prefix.HasRex);

        log($"MOV r/m{operandSize}, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOV r, imm (B0-B7=8bit, B8-BF=32/64bit)</summary>
    public static bool HandleMovRegImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int operandSize;
        int reg;
        if (opcode >= 0xB0 && opcode <= 0xB7)
        {
            operandSize = 8;
            reg = (opcode - 0xB0) | (prefix.B ? 8 : 0);
        }
        else // B8-BF
        {
            operandSize = prefix.W ? 64 : (prefix.HasOperandSize ? 16 : 32);
            reg = (opcode - 0xB8) | (prefix.B ? 8 : 0);
        }

        int immSize = operandSize;
        if (operandSize == 32) immSize = 32;
        // For MOV r64, imm64 the immediate is full 64-bit

        ulong value = InstructionDecoder.ReadImmediateUnsigned(ip, ref offs, immSize);
        RegisterHelper.WriteSized(ctx, reg, value, operandSize, prefix.HasRex);

        log($"MOV r{operandSize}, imm{immSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>LEA r, m (8D /r)</summary>
    public static bool HandleLea(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode 0x8D

        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

        RegisterHelper.WriteSized(ctx, modrm.Reg, addr, operandSize);

        log($"LEA r{operandSize}, m", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>XCHG r, r/m (86=8bit, 87=32/64bit)</summary>
    public static bool HandleXchg(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x86 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong regVal = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong rmVal = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);

        RegisterHelper.WriteSized(ctx, modrm.Reg, rmVal, operandSize, prefix.HasRex);
        if (isMem) InstructionDecoder.WriteMemory(addr, regVal, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, regVal, operandSize, prefix.HasRex);

        log($"XCHG r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>XCHG rAX, r (90+r, except 90=NOP)</summary>
    public static bool HandleXchgAccReg(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int reg = (opcode - 0x90) | (prefix.B ? 8 : 0);

        // 90 without REX.B is NOP
        if (reg == 0 && !prefix.HasRex)
        {
            log("NOP", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        int operandSize = prefix.OperandSize;
        ulong rax = RegisterHelper.ReadSized(ctx, 0, operandSize);
        ulong other = RegisterHelper.ReadSized(ctx, reg, operandSize);

        RegisterHelper.WriteSized(ctx, 0, other, operandSize);
        RegisterHelper.WriteSized(ctx, reg, rax, operandSize);

        log($"XCHG acc, r{reg}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOVZX r, r/m8 (0F B6) or MOVZX r, r/m16 (0F B7)</summary>
    public static bool HandleMovzx(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // skip 0F B6 or 0F B7
        byte opcode2 = ip[offs - 1];
        int srcSize = opcode2 == 0xB6 ? 8 : 16;
        int dstSize = prefix.OperandSize; // 32 or 64

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, srcSize, prefix.HasRex);

        // Zero-extend: just write to the appropriately-sized register
        RegisterHelper.WriteSized(ctx, modrm.Reg, src, dstSize);

        log($"MOVZX r{dstSize}, r/m{srcSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOVSX r, r/m8 (0F BE) or MOVSX r, r/m16 (0F BF)</summary>
    public static bool HandleMovsx(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // skip 0F BE or 0F BF
        byte opcode2 = ip[offs - 1];
        int srcSize = opcode2 == 0xBE ? 8 : 16;
        int dstSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, srcSize, prefix.HasRex);

        // Sign-extend
        ulong result = InstructionDecoder.SignExtend(src, srcSize);
        if (dstSize == 32)
            result &= 0xFFFFFFFF; // 32-bit write zero-extends to 64

        RegisterHelper.WriteSized(ctx, modrm.Reg, result, dstSize);

        log($"MOVSX r{dstSize}, r/m{srcSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOVSXD r64, r/m32 (63 with REX.W)</summary>
    public static bool HandleMovsxd(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode 0x63

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        uint src = (uint)InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, 32, prefix.HasRex);

        ulong result = prefix.W ? (ulong)(long)(int)src : src;
        RegisterHelper.WriteSized(ctx, modrm.Reg, result, prefix.W ? 64 : 32);

        log($"MOVSXD r{(prefix.W ? 64 : 32)}, r/m32", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMOVcc r, r/m (0F 40-4F)</summary>
    public static bool HandleCmovcc(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte cc = (byte)(ip[offs++] & 0xF);
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        bool cond = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);
        if (cond)
            RegisterHelper.WriteSized(ctx, modrm.Reg, src, operandSize);

        log($"CMOV{InstructionDecoder.ConditionName(cc)} r{operandSize}, r/m{operandSize} => {(cond ? "moved" : "not moved")}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SETcc r/m8 (0F 90-9F)</summary>
    public static bool HandleSetcc(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte cc = (byte)(ip[offs++] & 0xF);

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        bool cond = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);
        byte result = cond ? (byte)1 : (byte)0;

        if (modrm.Mod == 0b11)
        {
            RegisterHelper.Write8(ctx, modrm.Rm, result, prefix.HasRex);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            *(byte*)addr = result;
        }

        log($"SET{InstructionDecoder.ConditionName(cc)} r/m8 => {result}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>BSWAP r32/r64 (0F C8+r)</summary>
    public static bool HandleBswap(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte opcode2 = ip[offs++];
        int reg = (opcode2 - 0xC8) | (prefix.B ? 8 : 0);

        if (prefix.W)
        {
            ulong val = RegisterHelper.Read64(ctx, reg);
            val = ((val & 0xFF) << 56) | ((val & 0xFF00) << 40) | ((val & 0xFF0000) << 24) | ((val & 0xFF000000) << 8) |
                  ((val >> 8) & 0xFF000000) | ((val >> 24) & 0xFF0000) | ((val >> 40) & 0xFF00) | ((val >> 56) & 0xFF);
            RegisterHelper.Write64(ctx, reg, val);
        }
        else
        {
            uint val = RegisterHelper.Read32(ctx, reg);
            val = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
            RegisterHelper.Write32(ctx, reg, val);
        }

        log($"BSWAP r{(prefix.W ? 64 : 32)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
