using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

/// <summary>
/// Handles miscellaneous instructions: NOP, CWD/CDQ/CQO, CBW/CWDE/CDQE,
/// CLC/STC/CMC/CLD/STD, LAHF/SAHF, GS prefix, string operations, BT/BTS/BTR/BTC.
/// </summary>
public static unsafe class MiscHandler
{
    /// <summary>NOP (90)</summary>
    public static bool HandleNop(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        log("NOP", 1);
        ctx->Rip += 1;
        return true;
    }

    /// <summary>Multi-byte NOP: 0F 1F /0 (with various lengths)</summary>
    public static bool HandleMultiByteNop(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // skip 0F 1F

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (modrm.Mod != 0b11)
            InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

        log($"NOP (multi-byte)", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CBW/CWDE/CDQE (98): sign-extend AL→AX / AX→EAX / EAX→RAX</summary>
    public static bool HandleCbwCwdeCdqe(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        if (prefix.W) // CDQE: sign-extend EAX to RAX
        {
            ctx->Rax = (ulong)(long)(int)(uint)ctx->Rax;
            log("CDQE", offs);
        }
        else if (prefix.HasOperandSize) // CBW: sign-extend AL to AX
        {
            ctx->Rax = (ctx->Rax & ~0xFFFFUL) | (ushort)(short)(sbyte)(byte)ctx->Rax;
            log("CBW", offs);
        }
        else // CWDE: sign-extend AX to EAX
        {
            ctx->Rax = (uint)(int)(short)(ushort)ctx->Rax;
            log("CWDE", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CWD/CDQ/CQO (99): sign-extend AX→DX:AX / EAX→EDX:EAX / RAX→RDX:RAX</summary>
    public static bool HandleCwdCdqCqo(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        if (prefix.W) // CQO
        {
            ctx->Rdx = (long)ctx->Rax < 0 ? 0xFFFFFFFFFFFFFFFF : 0;
            log("CQO", offs);
        }
        else if (prefix.HasOperandSize) // CWD
        {
            ctx->Rdx = (ctx->Rdx & ~0xFFFFUL) | ((short)(ushort)ctx->Rax < 0 ? 0xFFFFUL : 0UL);
            log("CWD", offs);
        }
        else // CDQ
        {
            ctx->Rdx = (int)(uint)ctx->Rax < 0 ? 0xFFFFFFFF : 0;
            log("CDQ", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CLC (F8), STC (F9), CMC (F5)</summary>
    public static bool HandleClearSetCarry(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        byte opcode = *ip;
        switch (opcode)
        {
            case 0xF8: ctx->EFlags &= ~FlagsCalculator.CF; log("CLC", 1); break;
            case 0xF9: ctx->EFlags |= FlagsCalculator.CF; log("STC", 1); break;
            case 0xF5: ctx->EFlags ^= FlagsCalculator.CF; log("CMC", 1); break;
            default: return false;
        }
        ctx->Rip += 1;
        return true;
    }

    /// <summary>CLD (FC), STD (FD)</summary>
    public static bool HandleClearSetDirection(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        byte opcode = *ip;
        switch (opcode)
        {
            case 0xFC: ctx->EFlags &= ~FlagsCalculator.DF; log("CLD", 1); break;
            case 0xFD: ctx->EFlags |= FlagsCalculator.DF; log("STD", 1); break;
            default: return false;
        }
        ctx->Rip += 1;
        return true;
    }

    /// <summary>LAHF (9F): Load AH from Flags</summary>
    public static bool HandleLahf(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        byte flags = (byte)(ctx->EFlags & 0xFF);
        RegisterHelper.Write8(ctx, 4, flags, false); // AH = flags[7:0]
        log("LAHF", 1);
        ctx->Rip += 1;
        return true;
    }

    /// <summary>SAHF (9E): Store AH into Flags</summary>
    public static bool HandleSahf(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        byte ah = RegisterHelper.Read8(ctx, 4, false); // AH
        ctx->EFlags = (ctx->EFlags & ~0xFFu) | ah;
        log("SAHF", 1);
        ctx->Rip += 1;
        return true;
    }

    /// <summary>GS segment override prefix (65) - resolve GS:[...] accesses</summary>
    public static bool HandleGsPrefix(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        // GS prefix followed by an instruction - the most common use is GS:[0x30] (TEB access on Windows)
        // We handle this by getting the GS base (TEB) and resolving the effective address
        ulong gsBase = ThreadInformation.GetCurrentThreadGsBase();

        byte nextOpcode = *(ip + 1);

        // Common patterns: 65 48 8B xx xx => MOV r64, GS:[...]
        if (nextOpcode >= 0x40 && nextOpcode <= 0x4F)
        {
            byte rex = nextOpcode;
            bool W = (rex & 0x08) != 0;
            bool R = (rex & 0x04) != 0;
            bool X = (rex & 0x02) != 0;
            bool B = (rex & 0x01) != 0;

            byte op = *(ip + 2);
            if (op == 0x8B) // MOV r, GS:[r/m]
            {
                int offs = 3;
                var modrm = InstructionDecoder.ParseModRM(ip, ref offs, R, B);
                int operandSize = W ? 64 : 32;

                if (modrm.Mod == 0b11) return false;

                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, X, B);
                // For GS-relative, we interpret the computed address as an offset from GS base
                // Special case: if mod=00 and rm=100 (SIB) with base=none, the displacement is the GS offset
                ulong effectiveAddr = gsBase + addr;
                if (modrm.Mod == 0b00 && (modrm.Raw & 7) == 0b100)
                {
                    // SIB with no base - addr is already the absolute offset
                    effectiveAddr = gsBase + addr;
                }
                // Common: [disp32] via RIP-rel won't happen with GS, typically it's [GS:abs32]
                // For mod=00, rm=101: this would be RIP-rel, but with GS it means GS:[disp32]
                if (modrm.Mod == 0b00 && (modrm.Raw & 7) == 0b101)
                {
                    // Re-read the disp32 as absolute GS offset
                    int d32offs = 3; // after REX + opcode
                    InstructionDecoder.ParseModRM(ip, ref d32offs, R, B); // skip modrm
                    int disp32 = *(int*)(ip + d32offs);
                    effectiveAddr = gsBase + (ulong)(uint)disp32;
                    offs = d32offs + 4;
                }

                ulong value = operandSize == 64 ? *(ulong*)effectiveAddr : *(uint*)effectiveAddr;
                RegisterHelper.WriteSized(ctx, modrm.Reg, value, operandSize);

                log($"MOV r{operandSize}, GS:[0x{effectiveAddr:X}] => 0x{value:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
        }

        // Simple 65 8B ... (no REX)
        if (nextOpcode == 0x8B)
        {
            int offs = 2;
            var modrm = InstructionDecoder.ParseModRM(ip, ref offs, false, false);
            if (modrm.Mod == 0b11) return false;

            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, false, false);
            ulong effectiveAddr = gsBase + addr;
            uint value = *(uint*)effectiveAddr;
            RegisterHelper.Write32(ctx, modrm.Reg, value);

            log($"MOV r32, GS:[0x{effectiveAddr:X}] => 0x{value:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        log($"Unsupported GS-prefixed opcode 0x{nextOpcode:X2}", 2);
        return false;
    }

    /// <summary>BT r/m, r (0F A3), BTS r/m, r (0F AB), BTR r/m, r (0F B3), BTC r/m, r (0F BB)</summary>
    public static bool HandleBitTest(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte opcode2 = ip[offs++];
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize);
        int bitIndex = (int)(RegisterHelper.ReadSized(ctx, modrm.Reg, operandSize) % (ulong)operandSize);

        bool bitValue = (dst & (1UL << bitIndex)) != 0;
        ctx->EFlags = bitValue ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;

        string mnem;
        switch (opcode2)
        {
            case 0xA3: mnem = "BT"; break;
            case 0xAB: mnem = "BTS"; dst |= (1UL << bitIndex); break;
            case 0xB3: mnem = "BTR"; dst &= ~(1UL << bitIndex); break;
            case 0xBB: mnem = "BTC"; dst ^= (1UL << bitIndex); break;
            default: return false;
        }

        if (opcode2 != 0xA3)
        {
            if (isMem) InstructionDecoder.WriteMemory(addr, dst, operandSize);
            else RegisterHelper.WriteSized(ctx, modrm.Rm, dst, operandSize);
        }

        log($"{mnem} r/m{operandSize}, r{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>BT/BTS/BTR/BTC r/m, imm8 (0F BA /4, /5, /6, /7)</summary>
    public static bool HandleBitTestImm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // skip 0F BA
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;
        if (grp < 4) return false;

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong dst = isMem ? InstructionDecoder.ReadMemory(addr, operandSize) : RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize);
        byte imm8 = ip[offs++];
        int bitIndex = imm8 % operandSize;

        bool bitValue = (dst & (1UL << bitIndex)) != 0;
        ctx->EFlags = bitValue ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;

        string[] mnems = ["", "", "", "", "BT", "BTS", "BTR", "BTC"];
        if (grp >= 5)
        {
            switch (grp)
            {
                case 5: dst |= (1UL << bitIndex); break;
                case 6: dst &= ~(1UL << bitIndex); break;
                case 7: dst ^= (1UL << bitIndex); break;
            }
            if (isMem) InstructionDecoder.WriteMemory(addr, dst, operandSize);
            else RegisterHelper.WriteSized(ctx, modrm.Rm, dst, operandSize);
        }

        log($"{mnems[grp]} r/m{operandSize}, {imm8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>BSF r, r/m (0F BC) / BSR r, r/m (0F BD)</summary>
    public static bool HandleBsfBsr(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte opcode2 = ip[offs++];
        int operandSize = prefix.OperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        ulong src = InstructionDecoder.ReadRmOperand(ctx, ip, ref offs, modrm, prefix.X, prefix.B, operandSize, prefix.HasRex);

        ulong masked = src & ((operandSize == 64) ? ulong.MaxValue : (1UL << operandSize) - 1);
        bool isZero = masked == 0;
        ctx->EFlags = isZero ? ctx->EFlags | FlagsCalculator.ZF : ctx->EFlags & ~FlagsCalculator.ZF;

        if (!isZero)
        {
            int result;
            if (opcode2 == 0xBC) // BSF
                result = System.Numerics.BitOperations.TrailingZeroCount(masked);
            else // BSR
            {
                if (operandSize == 64)
                    result = 63 - System.Numerics.BitOperations.LeadingZeroCount(masked);
                else
                    result = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)masked);
            }

            RegisterHelper.WriteSized(ctx, modrm.Reg, (ulong)result, operandSize);
        }

        string mnem = opcode2 == 0xBC ? "BSF" : "BSR";
        log($"{mnem} r{operandSize}, r/m{operandSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// String operations with REP/REPNE prefix handling:
    /// MOVSB/MOVSW/MOVSD/MOVSQ (A4/A5), STOSB/STOSW/STOSD/STOSQ (AA/AB),
    /// LODSB/LODSW/LODSD/LODSQ (AC/AD), CMPSB/CMPSW/CMPSD/CMPSQ (A6/A7),
    /// SCASB/SCASW/SCASD/SCASQ (AE/AF)
    /// </summary>
    public static bool HandleStringOp(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        int operandSize = (opcode & 1) == 0 ? 8 : prefix.OperandSize;
        int step = operandSize / 8;
        bool forward = (ctx->EFlags & FlagsCalculator.DF) == 0;
        long delta = forward ? step : -step;

        bool hasRep = prefix.HasRep;
        bool hasRepne = prefix.HasRepne;
        bool isRepPrefixed = hasRep || hasRepne;

        // REP with RCX=0: skip entirely
        if (isRepPrefixed && ctx->Rcx == 0)
        {
            string[] n2 = { "", "", "", "", "MOVS", "MOVS", "CMPS", "CMPS",
                          "", "", "STOS", "STOS", "LODS", "LODS", "SCAS", "SCAS" };
            log($"REP {n2[opcode - 0xA0]} (count=0, skipped)", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        do
        {
            switch (opcode)
            {
                case 0xA4: case 0xA5: // MOVS
                {
                    ulong val = InstructionDecoder.ReadMemory(ctx->Rsi, operandSize);
                    InstructionDecoder.WriteMemory(ctx->Rdi, val, operandSize);
                    ctx->Rsi = (ulong)((long)ctx->Rsi + delta);
                    ctx->Rdi = (ulong)((long)ctx->Rdi + delta);
                    break;
                }
                case 0xAA: case 0xAB: // STOS
                {
                    ulong val = RegisterHelper.ReadSized(ctx, 0, operandSize);
                    InstructionDecoder.WriteMemory(ctx->Rdi, val, operandSize);
                    ctx->Rdi = (ulong)((long)ctx->Rdi + delta);
                    break;
                }
                case 0xAC: case 0xAD: // LODS
                {
                    ulong val = InstructionDecoder.ReadMemory(ctx->Rsi, operandSize);
                    RegisterHelper.WriteSized(ctx, 0, val, operandSize);
                    ctx->Rsi = (ulong)((long)ctx->Rsi + delta);
                    break;
                }
                case 0xA6: case 0xA7: // CMPS
                {
                    ulong src = InstructionDecoder.ReadMemory(ctx->Rsi, operandSize);
                    ulong dst = InstructionDecoder.ReadMemory(ctx->Rdi, operandSize);
                    ulong result = src - dst;
                    ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, src, dst, result, operandSize);
                    ctx->Rsi = (ulong)((long)ctx->Rsi + delta);
                    ctx->Rdi = (ulong)((long)ctx->Rdi + delta);
                    break;
                }
                case 0xAE: case 0xAF: // SCAS
                {
                    ulong val = InstructionDecoder.ReadMemory(ctx->Rdi, operandSize);
                    ulong acc = RegisterHelper.ReadSized(ctx, 0, operandSize);
                    ulong result = acc - val;
                    ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, acc, val, result, operandSize);
                    ctx->Rdi = (ulong)((long)ctx->Rdi + delta);
                    break;
                }
                default:
                    return false;
            }

            if (isRepPrefixed)
            {
                ctx->Rcx--;
                if (ctx->Rcx == 0) break;

                // For CMPS/SCAS: check ZF condition
                if (opcode is 0xA6 or 0xA7 or 0xAE or 0xAF)
                {
                    bool zf = (ctx->EFlags & FlagsCalculator.ZF) != 0;
                    if (hasRep && !zf) break;    // REPE: stop if not equal
                    if (hasRepne && zf) break;    // REPNE: stop if equal
                }
            }
        } while (isRepPrefixed && ctx->Rcx > 0);

        string[] names = { "", "", "", "", "MOVS", "MOVS", "CMPS", "CMPS",
                          "", "", "STOS", "STOS", "LODS", "LODS", "SCAS", "SCAS" };
        string name = names[opcode - 0xA0];
        string repPrefix = hasRep ? "REP " : hasRepne ? "REPNE " : "";
        log($"{repPrefix}{name}{(operandSize == 8 ? "B" : operandSize == 16 ? "W" : operandSize == 32 ? "D" : "Q")}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
