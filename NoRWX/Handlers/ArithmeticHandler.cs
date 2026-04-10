using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Handlers;

/// <summary>
/// Handles arithmetic instructions: ADD, SUB, ADC, SBB, INC, DEC, NEG, MUL, IMUL, DIV, IDIV.
/// Also handles Group1 (83 /digit, 81 /digit) and Group3 (F6/F7).
/// </summary>
public static unsafe class ArithmeticHandler
{
    /// <summary>ADD r/m, r (00=8bit, 01=32/64bit)</summary>
    public static bool HandleAddRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x00 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong result = dst + src;

        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"ADD r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>ADD r, r/m (02=8bit, 03=32/64bit)</summary>
    public static bool HandleAddRRm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x02 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong result = dst + src;
        RegisterHelper.WriteSized(ctx, modrm.Reg, result, operandSize, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"ADD r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>ADD AL/AX/EAX/RAX, imm (04=8bit, 05=32/64bit)</summary>
    public static bool HandleAddAccImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x04 ? 8 : prefix.OperandSize;
        int immSize = operandSize == 64 ? 32 : operandSize;

        ulong dst = RegisterHelper.ReadSized(ctx, 0, operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result = dst + src;
        RegisterHelper.WriteSized(ctx, 0, result, operandSize);

        ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"ADD acc, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SUB r/m, r (28=8bit, 29=32/64bit)</summary>
    public static bool HandleSubRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x28 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong result = dst - src;

        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"SUB r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SUB r, r/m (2A=8bit, 2B=32/64bit)</summary>
    public static bool HandleSubRRm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x2A ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong result = dst - src;
        RegisterHelper.WriteSized(ctx, modrm.Reg, result, operandSize, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"SUB r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SUB AL/AX/EAX/RAX, imm (2C=8bit, 2D=32/64bit)</summary>
    public static bool HandleSubAccImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x2C ? 8 : prefix.OperandSize;
        int immSize = operandSize == 64 ? 32 : operandSize;

        ulong dst = RegisterHelper.ReadSized(ctx, 0, operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result = dst - src;
        RegisterHelper.WriteSized(ctx, 0, result, operandSize);

        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"SUB acc, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMP r/m, r (38=8bit, 39=32/64bit)</summary>
    public static bool HandleCmpRmR(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x38 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        ulong result = dst - src;
        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);

        log($"CMP r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMP r, r/m (3A=8bit, 3B=32/64bit)</summary>
    public static bool HandleCmpRRm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x3A ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        ulong dst = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong result = dst - src;
        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);

        log($"CMP r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMP AL/AX/EAX/RAX, imm (3C=8bit, 3D=32/64bit)</summary>
    public static bool HandleCmpAccImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0x3C ? 8 : prefix.OperandSize;
        int immSize = operandSize == 64 ? 32 : operandSize;

        ulong dst = RegisterHelper.ReadSized(ctx, 0, operandSize);
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result = dst - src;
        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);

        log($"CMP acc, imm", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// Group 1: 80/81/83 /digit r/m, imm
    /// Handles ADD, OR, ADC, SBB, AND, SUB, XOR, CMP with immediate operands.
    /// </summary>
    public static bool HandleGroup1(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int operandSize;
        int immSize;
        switch (opcode)
        {
            case 0x80: operandSize = 8; immSize = 8; break;
            case 0x81: operandSize = prefix.OperandSize; immSize = operandSize == 64 ? 32 : operandSize; break;
            case 0x83: operandSize = prefix.OperandSize; immSize = 8; break;
            default: return false;
        }

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;

        // Resolve address once for memory operands
        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);

        // Read immediate (sign-extended to operand size)
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);
        ulong src;
        if (operandSize == 64)
            src = (ulong)immSigned;
        else
            src = (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result;
        uint eflags = ctx->EFlags;
        bool cf = (eflags & FlagsCalculator.CF) != 0;

        string[] mnemonics = ["ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP"];

        switch (grp)
        {
            case 0: result = dst + src; eflags = FlagsCalculator.SetAddFlags(eflags, dst, src, result, operandSize); break;
            case 1: result = dst | src; eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize); break;
            case 2: result = dst + src + (cf ? 1UL : 0UL); eflags = FlagsCalculator.SetAddFlags(eflags, dst, src, result, operandSize, cf ? 1 : 0); break;
            case 3: result = dst - src - (cf ? 1UL : 0UL); eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize, cf ? 1 : 0); break;
            case 4: result = dst & src; eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize); break;
            case 5: result = dst - src; eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize); break;
            case 6: result = dst ^ src; eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize); break;
            case 7: // CMP - no writeback
                result = dst - src;
                eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize);
                ctx->EFlags = eflags;
                log($"{mnemonics[grp]} r/m{operandSize}, imm{immSize}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            default: return false;
        }

        ctx->EFlags = eflags;

        // Write back result
        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        log($"{mnemonics[grp]} r/m{operandSize}, imm{immSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// Group 3: F6 (8-bit) / F7 (16/32/64-bit)
    /// TEST, NOT, NEG, MUL, IMUL, DIV, IDIV
    /// </summary>
    public static bool HandleGroup3(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0xF6 ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong operand = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);

        switch (grp)
        {
            case 0: case 1: // TEST r/m, imm
            {
                int immSz = operandSize == 64 ? 32 : operandSize;
                long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSz);
                ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);
                ulong result = operand & src;
                ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);
                log($"TEST r/m{operandSize}, imm", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }

            case 2: // NOT r/m
            {
                ulong result = ~operand;
                if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
                else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);
                log($"NOT r/m{operandSize}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }

            case 3: // NEG r/m
            {
                ulong result = 0 - operand;
                if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
                else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);
                ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, 0, operand, result, operandSize);
                if (operand != 0) ctx->EFlags |= FlagsCalculator.CF;
                else ctx->EFlags &= ~FlagsCalculator.CF;
                log($"NEG r/m{operandSize}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }

            case 4: HandleMul(ctx, operand, operandSize); log($"MUL r/m{operandSize}", offs); ctx->Rip += (ulong)offs; return true;
            case 5: HandleImul1(ctx, operand, operandSize); log($"IMUL r/m{operandSize}", offs); ctx->Rip += (ulong)offs; return true;
            case 6:
                if (!HandleDiv(ctx, operand, operandSize)) { log($"DIV by zero", offs); return false; }
                log($"DIV r/m{operandSize}", offs); ctx->Rip += (ulong)offs; return true;
            case 7:
                if (!HandleIdiv(ctx, operand, operandSize)) { log($"IDIV by zero", offs); return false; }
                log($"IDIV r/m{operandSize}", offs); ctx->Rip += (ulong)offs; return true;
            default: return false;
        }
    }

    /// <summary>INC/DEC: FE (8-bit), FF /0 and /1 (32/64-bit)</summary>
    public static bool HandleIncDec(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = opcode == 0xFE ? 8 : prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;
        if (grp != 0 && grp != 1) return false;

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong operand = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);

        ulong result;
        if (grp == 0) { result = operand + 1; ctx->EFlags = FlagsCalculator.SetIncFlags(ctx->EFlags, operand, result, operandSize); }
        else { result = operand - 1; ctx->EFlags = FlagsCalculator.SetDecFlags(ctx->EFlags, operand, result, operandSize); }

        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        log(grp == 0 ? $"INC r/m{operandSize}" : $"DEC r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>Group 2: C0/C1/D0/D1/D2/D3 - Shift/rotate operations</summary>
    public static bool HandleGroup2Shift(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int operandSize;
        bool byCL = false, by1 = false;
        switch (opcode)
        {
            case 0xC0: operandSize = 8; break;
            case 0xC1: operandSize = prefix.OperandSize; break;
            case 0xD0: operandSize = 8; by1 = true; break;
            case 0xD1: operandSize = prefix.OperandSize; by1 = true; break;
            case 0xD2: operandSize = 8; byCL = true; break;
            case 0xD3: operandSize = prefix.OperandSize; byCL = true; break;
            default: return false;
        }

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int sub = (modrm.Raw >> 3) & 7;

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong value = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, prefix.HasRex);

        byte count;
        if (by1) count = 1;
        else if (byCL) count = (byte)(ctx->Rcx & (operandSize == 64 ? 0x3FUL : 0x1FUL));
        else { count = ip[offs++]; count &= (byte)(operandSize == 64 ? 0x3F : 0x1F); }

        ulong result;
        int bits = operandSize;
        string opName;

        switch (sub)
        {
            case 0: opName = "ROL"; result = (value << count) | (value >> (bits - count)); break;
            case 1: opName = "ROR"; result = (value >> count) | (value << (bits - count)); break;
            case 2: opName = "RCL"; result = value; break;
            case 3: opName = "RCR"; result = value; break;
            case 4: case 6: opName = "SHL"; result = value << count; break;
            case 5: opName = "SHR"; result = value >> count; break;
            case 7:
                opName = "SAR";
                result = operandSize switch
                {
                    8 => (ulong)(long)(sbyte)(byte)value >> count,
                    16 => (ulong)(long)(short)(ushort)value >> count,
                    32 => (ulong)(long)(int)(uint)value >> count,
                    64 => (ulong)((long)value >> count),
                    _ => value
                };
                break;
            default: return false;
        }

        if (isMem) InstructionDecoder.WriteMemory(addr, result, operandSize);
        else RegisterHelper.WriteSized(ctx, modrm.Rm, result, operandSize, prefix.HasRex);

        if (count > 0 && sub >= 4)
        {
            ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);
            if (sub == 4 || sub == 6)
            { ulong mask = 1UL << (bits - count); ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF; }
            else if (sub == 5)
            { ulong mask = 1UL << (count - 1); ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF; }
            else if (sub == 7)
            { ulong mask = 1UL << (count - 1); ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF; }
        }

        log($"{opName} r/m{operandSize}, {count}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>IMUL r, r/m (0F AF) - two-operand form</summary>
    public static bool HandleImul2(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // skip 0F AF
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        long dst = (long)InstructionDecoder.SignExtend(RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize), operandSize);
        long src = (long)InstructionDecoder.SignExtend(InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex), operandSize);

        long result = dst * src;
        RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)result, operandSize);

        bool overflow = operandSize switch
        {
            16 => result != (short)result,
            32 => result != (int)result,
            _ => false
        };
        ctx->EFlags = overflow
            ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
            : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);

        log($"IMUL r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>IMUL r, r/m, imm8 (6B) or IMUL r, r/m, imm32 (69)</summary>
    public static bool HandleImul3(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int operandSize = prefix.OperandSize;
        int immSize = opcode == 0x6B ? 8 : (operandSize == 64 ? 32 : operandSize);

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        long src = (long)InstructionDecoder.SignExtend(
            InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex),
            operandSize);
        long imm = InstructionDecoder.ReadImmediateSigned(ip, ref offs, immSize);

        long result = src * imm;
        RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)result, operandSize);

        log($"IMUL r{operandSize}, r/m{operandSize}, imm{immSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    // --- Internal helpers (MUL/IMUL1/DIV/IDIV unchanged) ---

    private static void HandleMul(CONTEXT* ctx, ulong operand, int operandSize)
    {
        switch (operandSize)
        {
            case 8:
            { ushort r = (ushort)((byte)ctx->Rax * (byte)operand); ctx->Rax = (ctx->Rax & ~0xFFFFUL) | r;
              ctx->EFlags = (r >> 8) != 0 ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 16:
            { uint r = (uint)((ushort)ctx->Rax * (ushort)operand); ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (r & 0xFFFF); ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (r >> 16);
              ctx->EFlags = (r >> 16) != 0 ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 32:
            { ulong r = (ulong)(uint)ctx->Rax * (uint)operand; ctx->Rax = (uint)r; ctx->Rdx = (uint)(r >> 32);
              ctx->EFlags = (r >> 32) != 0 ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 64:
            { UInt128 r = (UInt128)ctx->Rax * operand; ctx->Rax = (ulong)r; ctx->Rdx = (ulong)(r >> 64);
              ctx->EFlags = ctx->Rdx != 0 ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
        }
    }

    private static void HandleImul1(CONTEXT* ctx, ulong operand, int operandSize)
    {
        switch (operandSize)
        {
            case 8:
            { short r = (short)((sbyte)(byte)ctx->Rax * (sbyte)(byte)operand); ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)r;
              ctx->EFlags = r != (sbyte)r ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 16:
            { int r = (short)(ushort)ctx->Rax * (short)(ushort)operand; ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)r; ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (ushort)(r >> 16);
              ctx->EFlags = r != (short)r ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 32:
            { long r = (long)(int)(uint)ctx->Rax * (int)(uint)operand; ctx->Rax = (uint)r; ctx->Rdx = (uint)(ulong)(r >> 32);
              ctx->EFlags = r != (int)r ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
            case 64:
            { Int128 r = (Int128)(long)ctx->Rax * (long)operand; ctx->Rax = (ulong)(long)r; ctx->Rdx = (ulong)(long)(r >> 64);
              ctx->EFlags = r != (long)r ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF); break; }
        }
    }

    private static bool HandleDiv(CONTEXT* ctx, ulong divisor, int operandSize)
    {
        if (divisor == 0) return false;
        switch (operandSize)
        {
            case 8: { ushort d = (ushort)(ctx->Rax & 0xFFFF); ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)((byte)(d / (byte)divisor) | ((byte)(d % (byte)divisor) << 8)); break; }
            case 16: { uint d = (uint)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF)); ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)(d / (ushort)divisor); ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (ushort)(d % (ushort)divisor); break; }
            case 32: { ulong d = (ctx->Rdx & 0xFFFFFFFF) << 32 | (ctx->Rax & 0xFFFFFFFF); ctx->Rax = (uint)(d / (uint)divisor); ctx->Rdx = (uint)(d % (uint)divisor); break; }
            case 64: { UInt128 d = ((UInt128)ctx->Rdx << 64) | ctx->Rax; ctx->Rax = (ulong)(d / divisor); ctx->Rdx = (ulong)(d % divisor); break; }
        }
        return true;
    }

    private static bool HandleIdiv(CONTEXT* ctx, ulong divisor, int operandSize)
    {
        if (divisor == 0) return false;
        switch (operandSize)
        {
            case 8: { short d = (short)(ushort)(ctx->Rax & 0xFFFF); sbyte q = (sbyte)(d / (sbyte)(byte)divisor); sbyte r = (sbyte)(d % (sbyte)(byte)divisor);
                       ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ulong)(ushort)(byte)q | ((ulong)(ushort)(byte)r << 8); break; }
            case 16: { int d = (int)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF)); short q = (short)(d / (short)(ushort)divisor); short r = (short)(d % (short)(ushort)divisor);
                        ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)q; ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (ushort)r; break; }
            case 32: { long d = (long)((ctx->Rdx & 0xFFFFFFFF) << 32 | (ctx->Rax & 0xFFFFFFFF)); int q = (int)(d / (int)(uint)divisor); int r = (int)(d % (int)(uint)divisor);
                        ctx->Rax = (uint)q; ctx->Rdx = (uint)r; break; }
            case 64: { Int128 d = ((Int128)(long)ctx->Rdx << 64) | ctx->Rax; long q = (long)(d / (long)divisor); long r = (long)(d % (long)divisor);
                        ctx->Rax = (ulong)q; ctx->Rdx = (ulong)r; break; }
        }
        return true;
    }
}
