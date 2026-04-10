using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

/// <summary>
/// Handles logic instructions: AND, OR, XOR, TEST.
/// </summary>
public static unsafe class LogicHandler
{
    /// <summary>AND/OR/XOR r/m, r (opcode 08/09=OR, 20/21=AND, 30/31=XOR)</summary>
    public static bool HandleLogicRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = (opcode & 1) == 0 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        int savedOffs = offs;
        ulong result = (opcode >> 3 & 0x7) switch
        {
            1 => dst | src,   // 08/09
            4 => dst & src,   // 20/21
            6 => dst ^ src,   // 30/31
            _ => dst
        };
        string mnem = (opcode >> 3 & 0x7) switch
        {
            1 => "OR", 4 => "AND", 6 => "XOR", _ => "?"
        };

        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++;
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);
        log($"{mnem} r/m{operandSize}, r{operandSize}", savedOffs);
        ctx->Rip += (ulong)savedOffs;
        return true;
    }

    /// <summary>AND/OR/XOR r, r/m (opcode 0A/0B=OR, 22/23=AND, 32/33=XOR)</summary>
    public static bool HandleLogicRRm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = (opcode & 1) == 0 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong result = (opcode >> 3 & 0x7) switch
        {
            1 => dst | src,
            4 => dst & src,
            6 => dst ^ src,
            _ => dst
        };
        string mnem = (opcode >> 3 & 0x7) switch
        {
            1 => "OR", 4 => "AND", 6 => "XOR", _ => "?"
        };

        RegisterHelper.WriteSized(ctx, modrm.Reg, result, operandSize, prefix.HasRex);
        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);

        log($"{mnem} r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>AND/OR/XOR AL/AX/EAX/RAX, imm (0C/0D=OR, 24/25=AND, 34/35=XOR)</summary>
    public static bool HandleLogicAccImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = (opcode & 1) == 0 ? 8 : prefix.OperandSize;
        int immSize = operandSize == 64 ? 32 : operandSize;

        ulong dst = RegisterHelper.ReadSized(ctx, 0, operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result = (opcode >> 3 & 0x7) switch
        {
            1 => dst | src,
            4 => dst & src,
            6 => dst ^ src,
            _ => dst
        };
        string mnem = (opcode >> 3 & 0x7) switch
        {
            1 => "OR", 4 => "AND", 6 => "XOR", _ => "?"
        };

        RegisterHelper.WriteSized(ctx, 0, result, operandSize);
        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);

        log($"{mnem} acc, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>TEST r/m, r (84=8bit, 85=32/64bit)</summary>
    public static bool HandleTestRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x84 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong result = dst & src;
        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);

        log($"TEST r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>TEST AL/AX/EAX/RAX, imm (A8=8bit, A9=32/64bit)</summary>
    public static bool HandleTestAccImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0xA8 ? 8 : prefix.OperandSize;
        int immSize = operandSize == 64 ? 32 : operandSize;

        ulong dst = RegisterHelper.ReadSized(ctx, 0, operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result = dst & src;
        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);

        log($"TEST acc, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
