using NoRWX.Core;
using static NoRWX.Emulator;

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

        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        int savedOffs = offs;
        ulong result = dst + src;

        // Write back (need to re-resolve address for memory operands)
        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"ADD r/m{operandSize}, r{operandSize}", savedOffs);
        ctx->Rip += (ulong)savedOffs;
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
        int immSize = operandSize == 64 ? 32 : operandSize; // RAX gets sign-extended imm32

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

        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);
        ulong src = RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize, prefix.HasRex);

        int savedOffs = offs;
        ulong result = dst - src;

        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++;
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, dst, src, result, operandSize);
        log($"SUB r/m{operandSize}, r{operandSize}", savedOffs);
        ctx->Rip += (ulong)savedOffs;
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

        // Read destination operand
        int offsAfterModrm = offs;
        ulong dst = InstructionDecoder.ReadRmOperand(ctx, ip, ref offsAfterModrm, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        // Read immediate (sign-extended to operand size)
        long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offsAfterModrm, immSize);
        ulong src;
        if (operandSize == 64)
            src = (ulong)immSigned; // sign-extend to 64
        else
            src = (ulong)immSigned & ((1UL << operandSize) - 1);

        ulong result;
        uint eflags = ctx->EFlags;
        bool cf = (eflags & FlagsCalculator.CF) != 0;

        string[] mnemonics = ["ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP"];

        switch (grp)
        {
            case 0: // ADD
                result = dst + src;
                eflags = FlagsCalculator.SetAddFlags(eflags, dst, src, result, operandSize);
                break;
            case 1: // OR
                result = dst | src;
                eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize);
                break;
            case 2: // ADC
                result = dst + src + (cf ? 1UL : 0UL);
                eflags = FlagsCalculator.SetAddFlags(eflags, dst, src, result, operandSize, cf ? 1 : 0);
                break;
            case 3: // SBB
                result = dst - src - (cf ? 1UL : 0UL);
                eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize, cf ? 1 : 0);
                break;
            case 4: // AND
                result = dst & src;
                eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize);
                break;
            case 5: // SUB
                result = dst - src;
                eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize);
                break;
            case 6: // XOR
                result = dst ^ src;
                eflags = FlagsCalculator.SetLogicFlags(eflags, result, operandSize);
                break;
            case 7: // CMP (no writeback)
                result = dst - src;
                eflags = FlagsCalculator.SetSubFlags(eflags, dst, src, result, operandSize);
                ctx->EFlags = eflags;
                log($"{mnemonics[grp]} r/m{operandSize}, imm{immSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            default:
                return false;
        }

        ctx->EFlags = eflags;

        // Write back result
        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        log($"{mnemonics[grp]} r/m{operandSize}, imm{immSize}", offsAfterModrm);
        ctx->Rip += (ulong)offsAfterModrm;
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

        int offsAfterModrm = offs;
        ulong operand = InstructionDecoder.ReadRmOperand(ctx, ip, ref offsAfterModrm, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        switch (grp)
        {
            case 0: // TEST r/m, imm
            case 1: // TEST r/m, imm (alternate encoding)
            {
                int immSize = operandSize == 64 ? 32 : operandSize;
                long immSigned = InstructionDecoder.ReadImmediateSigned(ip, ref offsAfterModrm, immSize);
                ulong src = operandSize == 64 ? (ulong)immSigned : (ulong)immSigned & ((1UL << operandSize) - 1);
                ulong result = operand & src;
                ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);
                log($"TEST r/m{operandSize}, imm", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 2: // NOT r/m
            {
                ulong result = ~operand;
                offs = 0;
                InstructionDecoder.ParsePrefixes(ip, ref offs);
                offs++;
                InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);
                // NOT does not affect flags
                log($"NOT r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 3: // NEG r/m
            {
                ulong result = 0 - operand;
                offs = 0;
                InstructionDecoder.ParsePrefixes(ip, ref offs);
                offs++;
                InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);
                ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, 0, operand, result, operandSize);
                // CF is set if operand != 0
                if (operand != 0)
                    ctx->EFlags |= FlagsCalculator.CF;
                else
                    ctx->EFlags &= ~FlagsCalculator.CF;
                log($"NEG r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 4: // MUL r/m (unsigned)
            {
                HandleMul(ctx, operand, operandSize);
                log($"MUL r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 5: // IMUL r/m (signed, one-operand form)
            {
                HandleImul1(ctx, operand, operandSize);
                log($"IMUL r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 6: // DIV r/m (unsigned)
            {
                if (!HandleDiv(ctx, operand, operandSize))
                {
                    log($"DIV by zero", offsAfterModrm);
                    return false;
                }
                log($"DIV r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            case 7: // IDIV r/m (signed)
            {
                if (!HandleIdiv(ctx, operand, operandSize))
                {
                    log($"IDIV by zero", offsAfterModrm);
                    return false;
                }
                log($"IDIV r/m{operandSize}", offsAfterModrm);
                ctx->Rip += (ulong)offsAfterModrm;
                return true;
            }

            default:
                return false;
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
        if (grp != 0 && grp != 1) return false; // /0=INC, /1=DEC

        int offsAfterModrm = offs;
        ulong operand = InstructionDecoder.ReadRmOperand(ctx, ip, ref offsAfterModrm, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong result;
        if (grp == 0)
        {
            result = operand + 1;
            ctx->EFlags = FlagsCalculator.SetIncFlags(ctx->EFlags, operand, result, operandSize);
        }
        else
        {
            result = operand - 1;
            ctx->EFlags = FlagsCalculator.SetDecFlags(ctx->EFlags, operand, result, operandSize);
        }

        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++;
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        log(grp == 0 ? $"INC r/m{operandSize}" : $"DEC r/m{operandSize}", offsAfterModrm);
        ctx->Rip += (ulong)offsAfterModrm;
        return true;
    }

    /// <summary>
    /// Group 2: C0/C1/D0/D1/D2/D3 - Shift/rotate operations
    /// SHL, SHR, SAR, ROL, ROR, RCL, RCR
    /// </summary>
    public static bool HandleGroup2Shift(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int operandSize;
        bool byImm8 = false, byCL = false, by1 = false;
        switch (opcode)
        {
            case 0xC0: operandSize = 8; byImm8 = true; break;
            case 0xC1: operandSize = prefix.OperandSize; byImm8 = true; break;
            case 0xD0: operandSize = 8; by1 = true; break;
            case 0xD1: operandSize = prefix.OperandSize; by1 = true; break;
            case 0xD2: operandSize = 8; byCL = true; break;
            case 0xD3: operandSize = prefix.OperandSize; byCL = true; break;
            default: return false;
        }

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int sub = (modrm.Raw >> 3) & 7;

        int offsAfterModrm = offs;
        ulong value = InstructionDecoder.ReadRmOperand(ctx, ip, ref offsAfterModrm, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        byte count;
        if (by1) count = 1;
        else if (byCL) count = (byte)(ctx->Rcx & (operandSize == 64 ? 0x3FUL : 0x1FUL));
        else { count = ip[offsAfterModrm++]; count &= (byte)(operandSize == 64 ? 0x3F : 0x1F); }

        ulong result;
        int bits = operandSize;
        string opName;

        switch (sub)
        {
            case 0: opName = "ROL"; result = (value << count) | (value >> (bits - count)); break;
            case 1: opName = "ROR"; result = (value >> count) | (value << (bits - count)); break;
            case 2: opName = "RCL"; result = value; /* simplified */ break; // TODO: full RCL
            case 3: opName = "RCR"; result = value; /* simplified */ break; // TODO: full RCR
            case 4: opName = "SHL"; result = value << count; break;
            case 5: opName = "SHR"; result = value >> count; break;
            case 6: opName = "SHL"; result = value << count; break; // SAL = SHL
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
            default:
                return false;
        }

        // Write back
        offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++;
        InstructionDecoder.WriteRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, result, prefix.HasRex);

        // Flags for shifts (simplified - CF, OF, SF, ZF, PF)
        if (count > 0 && sub >= 4)
        {
            ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, operandSize);
            // CF = last bit shifted out
            if (sub == 4 || sub == 6) // SHL
            {
                ulong mask = 1UL << (bits - count);
                ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;
            }
            else if (sub == 5) // SHR
            {
                ulong mask = 1UL << (count - 1);
                ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;
            }
            else if (sub == 7) // SAR
            {
                ulong mask = 1UL << (count - 1);
                ctx->EFlags = (value & mask) != 0 ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;
            }
        }

        log($"{opName} r/m{operandSize}, {count}", offsAfterModrm);
        ctx->Rip += (ulong)offsAfterModrm;
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

        // CF=OF=1 if result doesn't fit in operandSize
        bool overflow = operandSize switch
        {
            16 => result != (short)result,
            32 => result != (int)result,
            _ => false // 64-bit overflow requires 128-bit check, simplified
        };
        ctx->EFlags = overflow
            ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
            : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);

        log($"IMUL r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>IMUL r, r/m, imm8 (6B) or IMUL r, r/m, imm32 (69) - three-operand form</summary>
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

    // --- Internal helpers ---

    private static void HandleMul(CONTEXT* ctx, ulong operand, int operandSize)
    {
        switch (operandSize)
        {
            case 8:
            {
                ushort result = (ushort)((byte)ctx->Rax * (byte)operand);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | result;
                bool overflow = (result >> 8) != 0;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 16:
            {
                uint result = (uint)((ushort)ctx->Rax * (ushort)operand);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (result & 0xFFFF);
                ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (result >> 16);
                bool overflow = (result >> 16) != 0;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 32:
            {
                ulong result = (ulong)(uint)ctx->Rax * (uint)operand;
                ctx->Rax = (uint)result;
                ctx->Rdx = (uint)(result >> 32);
                bool overflow = (result >> 32) != 0;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 64:
            {
                UInt128 result = (UInt128)ctx->Rax * operand;
                ctx->Rax = (ulong)result;
                ctx->Rdx = (ulong)(result >> 64);
                bool overflow = ctx->Rdx != 0;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
        }
    }

    private static void HandleImul1(CONTEXT* ctx, ulong operand, int operandSize)
    {
        switch (operandSize)
        {
            case 8:
            {
                short result = (short)((sbyte)(byte)ctx->Rax * (sbyte)(byte)operand);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)result;
                bool overflow = result != (sbyte)result;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 16:
            {
                int result = (short)(ushort)ctx->Rax * (short)(ushort)operand;
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)result;
                ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (ushort)(result >> 16);
                bool overflow = result != (short)result;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 32:
            {
                long result = (long)(int)(uint)ctx->Rax * (int)(uint)operand;
                ctx->Rax = (uint)result;
                ctx->Rdx = (uint)(ulong)(result >> 32);
                bool overflow = result != (int)result;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
            case 64:
            {
                Int128 result = (Int128)(long)ctx->Rax * (long)operand;
                ctx->Rax = (ulong)(long)result;
                ctx->Rdx = (ulong)(long)(result >> 64);
                bool overflow = result != (long)result;
                ctx->EFlags = overflow
                    ? ctx->EFlags | FlagsCalculator.CF | FlagsCalculator.OF
                    : ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.OF);
                break;
            }
        }
    }

    private static bool HandleDiv(CONTEXT* ctx, ulong divisor, int operandSize)
    {
        if (divisor == 0) return false;

        switch (operandSize)
        {
            case 8:
            {
                ushort dividend = (ushort)(ctx->Rax & 0xFFFF);
                byte quotient = (byte)(dividend / (byte)divisor);
                byte remainder = (byte)(dividend % (byte)divisor);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)(remainder << 8 | quotient);
                break;
            }
            case 16:
            {
                uint dividend = (uint)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF));
                ushort quotient = (ushort)(dividend / (ushort)divisor);
                ushort remainder = (ushort)(dividend % (ushort)divisor);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | quotient;
                ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | remainder;
                break;
            }
            case 32:
            {
                ulong dividend = (ctx->Rdx & 0xFFFFFFFF) << 32 | (ctx->Rax & 0xFFFFFFFF);
                uint quotient = (uint)(dividend / (uint)divisor);
                uint remainder = (uint)(dividend % (uint)divisor);
                ctx->Rax = quotient;
                ctx->Rdx = remainder;
                break;
            }
            case 64:
            {
                UInt128 dividend = ((UInt128)ctx->Rdx << 64) | ctx->Rax;
                ulong quotient = (ulong)(dividend / divisor);
                ulong remainder = (ulong)(dividend % divisor);
                ctx->Rax = quotient;
                ctx->Rdx = remainder;
                break;
            }
        }
        return true;
    }

    private static bool HandleIdiv(CONTEXT* ctx, ulong divisor, int operandSize)
    {
        if (divisor == 0) return false;

        switch (operandSize)
        {
            case 8:
            {
                short dividend = (short)(ushort)(ctx->Rax & 0xFFFF);
                sbyte sdivisor = (sbyte)(byte)divisor;
                sbyte quotient = (sbyte)(dividend / sdivisor);
                sbyte remainder = (sbyte)(dividend % sdivisor);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ulong)(ushort)(byte)quotient | ((ulong)(ushort)(byte)remainder << 8);
                break;
            }
            case 16:
            {
                int dividend = (int)((ctx->Rdx & 0xFFFF) << 16 | (ctx->Rax & 0xFFFF));
                short sdivisor = (short)(ushort)divisor;
                short quotient = (short)(dividend / sdivisor);
                short remainder = (short)(dividend % sdivisor);
                ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)quotient;
                ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | (ushort)remainder;
                break;
            }
            case 32:
            {
                long dividend = (long)((ctx->Rdx & 0xFFFFFFFF) << 32 | (ctx->Rax & 0xFFFFFFFF));
                int sdivisor = (int)(uint)divisor;
                int quotient = (int)(dividend / sdivisor);
                int remainder = (int)(dividend % sdivisor);
                ctx->Rax = (uint)quotient;
                ctx->Rdx = (uint)remainder;
                break;
            }
            case 64:
            {
                Int128 dividend = ((Int128)(long)ctx->Rdx << 64) | ctx->Rax;
                long sdivisor = (long)divisor;
                long quotient = (long)(dividend / sdivisor);
                long remainder = (long)(dividend % sdivisor);
                ctx->Rax = (ulong)quotient;
                ctx->Rdx = (ulong)remainder;
                break;
            }
        }
        return true;
    }
}
