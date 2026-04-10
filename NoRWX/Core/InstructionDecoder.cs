using static NoRWX.EmulatorX64;

namespace NoRWX.Core;

/// <summary>
/// Unified x86-64 instruction decoder. Handles prefix parsing, ModRM/SIB decoding,
/// displacement/immediate reading, and effective address resolution.
/// </summary>
public static unsafe class InstructionDecoder
{
    /// <summary>Parsed instruction prefixes and state.</summary>
    public struct PrefixState
    {
        public byte Rex;
        public bool HasRex;
        public bool W, R, X, B;
        public bool HasOperandSize;  // 0x66
        public bool HasAddressSize;  // 0x67
        public bool HasRepne;        // F2
        public bool HasRep;          // F3
        public byte SegmentOverride; // 0x26/2E/36/3E/64/65

        /// <summary>Determine operand size based on prefixes and default.</summary>
        public readonly int OperandSize
        {
            get
            {
                if (W) return 64;
                if (HasOperandSize) return 16;
                return 32; // default in 64-bit long mode
            }
        }
    }

    /// <summary>Parsed ModRM byte with REX extensions applied.</summary>
    public struct ModRM
    {
        public byte Raw;
        public byte Mod;
        public int Reg;  // with REX.R applied
        public int Rm;   // with REX.B applied
    }

    /// <summary>Parse all legacy prefixes and REX prefix from instruction stream.</summary>
    public static PrefixState ParsePrefixes(byte* ip, ref int offs)
    {
        var state = new PrefixState();

        // Parse legacy prefixes
        bool parsing = true;
        while (parsing)
        {
            byte b = ip[offs];
            switch (b)
            {
                case 0x66: state.HasOperandSize = true; offs++; break;
                case 0x67: state.HasAddressSize = true; offs++; break;
                case 0xF2: state.HasRepne = true; offs++; break;
                case 0xF3: state.HasRep = true; offs++; break;
                case 0x26: case 0x2E: case 0x36: case 0x3E:
                case 0x64: case 0x65:
                    state.SegmentOverride = b; offs++; break;
                default:
                    parsing = false; break;
            }
        }

        // Parse REX prefix (0x40-0x4F)
        if ((ip[offs] & 0xF0) == 0x40)
        {
            state.Rex = ip[offs++];
            state.HasRex = true;
            state.W = (state.Rex & 0x08) != 0;
            state.R = (state.Rex & 0x04) != 0;
            state.X = (state.Rex & 0x02) != 0;
            state.B = (state.Rex & 0x01) != 0;
        }

        return state;
    }

    /// <summary>Parse just the REX byte (when you know it's at position 0).</summary>
    public static void ParseRex(byte rex, out bool W, out bool R, out bool X, out bool B)
    {
        W = (rex & 0x08) != 0;
        R = (rex & 0x04) != 0;
        X = (rex & 0x02) != 0;
        B = (rex & 0x01) != 0;
    }

    /// <summary>Parse ModRM byte with REX extensions.</summary>
    public static ModRM ParseModRM(byte* ip, ref int offs, bool rexR, bool rexB)
    {
        byte raw = ip[offs++];
        return new ModRM
        {
            Raw = raw,
            Mod = (byte)(raw >> 6 & 3),
            Reg = (raw >> 3 & 7) | (rexR ? 8 : 0),
            Rm = (raw & 7) | (rexB ? 8 : 0)
        };
    }

    /// <summary>Parse ModRM byte without REX extensions.</summary>
    public static ModRM ParseModRM(byte* ip, ref int offs)
    {
        return ParseModRM(ip, ref offs, false, false);
    }

    /// <summary>
    /// Resolve effective address from ModRM (and optional SIB) bytes.
    /// Handles all x86-64 addressing modes: register-indirect, SIB, RIP-relative, displacement.
    /// </summary>
    /// <param name="ctx">Thread context for register values and RIP.</param>
    /// <param name="ip">Instruction pointer (start of instruction).</param>
    /// <param name="offs">Current offset into instruction (after ModRM). Updated past SIB/displacement.</param>
    /// <param name="mod">ModRM.mod field (0-2 for memory, 3 for register).</param>
    /// <param name="rm">ModRM.rm field with REX.B applied.</param>
    /// <param name="rexX">REX.X bit for SIB index extension.</param>
    /// <param name="rexB">REX.B bit (already applied to rm, needed for SIB base).</param>
    /// <returns>Effective memory address.</returns>
    public static ulong ResolveAddress(CONTEXT* ctx, byte* ip, ref int offs, byte mod, int rm, bool rexX, bool rexB)
    {
        int rmLow = rm & 7;

        // SIB byte present (rmLow == 0b100)
        if (rmLow == 0b100)
        {
            return ResolveSIB(ctx, ip, ref offs, mod, rexX, rexB);
        }

        // RIP-relative (mod=00, rm=101, no REX.B)
        if (mod == 0b00 && rmLow == 0b101 && !rexB)
        {
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            return ctx->Rip + (ulong)offs + (ulong)(long)disp32;
        }

        // Simple base + displacement
        ulong baseVal = RegisterHelper.Read64(ctx, rm);

        if (mod == 0b01)
        {
            sbyte disp8 = *(sbyte*)(ip + offs);
            offs += 1;
            return baseVal + (ulong)(long)disp8;
        }
        if (mod == 0b10)
        {
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            return baseVal + (ulong)(long)disp32;
        }

        return baseVal; // mod == 0b00
    }

    /// <summary>Resolve SIB-based effective address.</summary>
    private static ulong ResolveSIB(CONTEXT* ctx, byte* ip, ref int offs, byte mod, bool rexX, bool rexB)
    {
        byte sib = ip[offs++];
        int scaleBits = sib >> 6;
        int indexLow = sib >> 3 & 7;
        int baseLow = sib & 7;

        int indexReg = indexLow | (rexX ? 8 : 0);
        int baseReg = baseLow | (rexB ? 8 : 0);

        // Index: suppressed when indexLow==0b100 and !REX.X
        bool noIndex = indexLow == 0b100 && !rexX;
        ulong indexVal = noIndex ? 0UL : RegisterHelper.Read64(ctx, indexReg) << scaleBits;

        // Base: special case when mod==00 and baseLow==101 → disp32 only (no base register)
        if (baseLow == 0b101 && mod == 0b00)
        {
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            return (ulong)(long)disp32 + indexVal;
        }

        ulong baseVal = RegisterHelper.Read64(ctx, baseReg);
        ulong ea = baseVal + indexVal;

        if (mod == 0b01)
        {
            sbyte disp8 = *(sbyte*)(ip + offs);
            offs += 1;
            ea += (ulong)(long)disp8;
        }
        else if (mod == 0b10)
        {
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            ea += (ulong)(long)disp32;
        }

        return ea;
    }

    /// <summary>
    /// Read an operand value (register or memory) based on ModRM decoding.
    /// For mod==11 (register), reads from the register file.
    /// For memory modes, resolves effective address and reads from memory.
    /// </summary>
    public static ulong ReadRmOperand(CONTEXT* ctx, byte* ip, ref int offs, ModRM modrm, bool rexX, bool rexB, int operandSize, bool hasRex = true)
    {
        if (modrm.Mod == 0b11)
        {
            return RegisterHelper.ReadSized(ctx, modrm.Rm, operandSize, hasRex);
        }

        ulong addr = ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, rexX, rexB);
        return ReadMemory(addr, operandSize);
    }

    /// <summary>
    /// Write a value to an operand (register or memory) based on ModRM decoding.
    /// </summary>
    public static void WriteRmOperand(CONTEXT* ctx, byte* ip, ref int offs, ModRM modrm, bool rexX, bool rexB, int operandSize, ulong value, bool hasRex = true)
    {
        if (modrm.Mod == 0b11)
        {
            RegisterHelper.WriteSized(ctx, modrm.Rm, value, operandSize, hasRex);
            return;
        }

        ulong addr = ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, rexX, rexB);
        WriteMemory(addr, value, operandSize);
    }

    /// <summary>
    /// Resolve the effective address of an r/m operand without reading the value.
    /// For mod==11, returns 0 (caller should check mod first).
    /// </summary>
    public static ulong ResolveRmAddress(CONTEXT* ctx, byte* ip, ref int offs, ModRM modrm, bool rexX, bool rexB)
    {
        if (modrm.Mod == 0b11) return 0; // register mode, no address
        return ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, rexX, rexB);
    }

    /// <summary>Read a value from memory with the specified size.</summary>
    public static ulong ReadMemory(ulong addr, int operandSize)
    {
        return operandSize switch
        {
            8 => *(byte*)addr,
            16 => *(ushort*)addr,
            32 => *(uint*)addr,
            64 => *(ulong*)addr,
            _ => *(uint*)addr
        };
    }

    /// <summary>Write a value to memory with the specified size.</summary>
    public static void WriteMemory(ulong addr, ulong value, int operandSize)
    {
        switch (operandSize)
        {
            case 8: *(byte*)addr = (byte)value; break;
            case 16: *(ushort*)addr = (ushort)value; break;
            case 32: *(uint*)addr = (uint)value; break;
            case 64: *(ulong*)addr = value; break;
        }
    }

    /// <summary>Read a sign-extended immediate value.</summary>
    public static long ReadImmediateSigned(byte* ip, ref int offs, int immSize)
    {
        switch (immSize)
        {
            case 8:
                sbyte imm8 = *(sbyte*)(ip + offs);
                offs += 1;
                return imm8;
            case 16:
                short imm16 = *(short*)(ip + offs);
                offs += 2;
                return imm16;
            case 32:
                int imm32 = *(int*)(ip + offs);
                offs += 4;
                return imm32;
            case 64:
                long imm64 = *(long*)(ip + offs);
                offs += 8;
                return imm64;
            default:
                return 0;
        }
    }

    /// <summary>Read an unsigned immediate value.</summary>
    public static ulong ReadImmediateUnsigned(byte* ip, ref int offs, int immSize)
    {
        switch (immSize)
        {
            case 8:
                byte u8 = ip[offs++];
                return u8;
            case 16:
                ushort u16 = *(ushort*)(ip + offs);
                offs += 2;
                return u16;
            case 32:
                uint u32 = *(uint*)(ip + offs);
                offs += 4;
                return u32;
            case 64:
                ulong u64 = *(ulong*)(ip + offs);
                offs += 8;
                return u64;
            default:
                return 0;
        }
    }

    /// <summary>Evaluate a condition code (0x0-0xF) against EFLAGS.</summary>
    public static bool EvaluateCondition(uint eflags, int cc)
    {
        bool cf = (eflags & FlagsCalculator.CF) != 0;
        bool pf = (eflags & FlagsCalculator.PF) != 0;
        bool zf = (eflags & FlagsCalculator.ZF) != 0;
        bool sf = (eflags & FlagsCalculator.SF) != 0;
        bool of = (eflags & FlagsCalculator.OF) != 0;

        return (cc & 0xF) switch
        {
            0x0 => of,                      // O
            0x1 => !of,                     // NO
            0x2 => cf,                      // B/C/NAE
            0x3 => !cf,                     // NB/AE/NC
            0x4 => zf,                      // E/Z
            0x5 => !zf,                     // NE/NZ
            0x6 => cf || zf,                // BE/NA
            0x7 => !cf && !zf,              // A/NBE
            0x8 => sf,                      // S
            0x9 => !sf,                     // NS
            0xA => pf,                      // P/PE
            0xB => !pf,                     // NP/PO
            0xC => sf != of,                // L/NGE
            0xD => sf == of,                // GE/NL
            0xE => zf || sf != of,          // LE/NG
            0xF => !zf && sf == of,         // G/NLE
            _ => false
        };
    }

    /// <summary>Get the mnemonic suffix for a condition code.</summary>
    public static string ConditionName(int cc) => (cc & 0xF) switch
    {
        0x0 => "O", 0x1 => "NO", 0x2 => "B", 0x3 => "AE",
        0x4 => "E", 0x5 => "NE", 0x6 => "BE", 0x7 => "A",
        0x8 => "S", 0x9 => "NS", 0xA => "P", 0xB => "NP",
        0xC => "L", 0xD => "GE", 0xE => "LE", 0xF => "G",
        _ => "?"
    };

    /// <summary>Sign-extend a value from the given source size to 64 bits.</summary>
    public static ulong SignExtend(ulong value, int fromSize) => fromSize switch
    {
        8 => (ulong)(long)(sbyte)(byte)value,
        16 => (ulong)(long)(short)(ushort)value,
        32 => (ulong)(long)(int)(uint)value,
        64 => value,
        _ => value
    };

    /// <summary>Zero-extend a value from the given source size to 64 bits.</summary>
    public static ulong ZeroExtend(ulong value, int fromSize) => fromSize switch
    {
        8 => value & 0xFF,
        16 => value & 0xFFFF,
        32 => value & 0xFFFFFFFF,
        64 => value,
        _ => value
    };
}
