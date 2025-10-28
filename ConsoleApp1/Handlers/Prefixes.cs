using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1.Handlers;

public static unsafe class Prefixes
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            case X64Opcodes.GS_PREFIX: return HandleSegmentPrefix(ctx, address, Log);
            case X64Opcodes.OPSIZE_PREFIX: return HandleOperandSizePrefix(ctx, address, Log);
            case X64Opcodes.REX_PREFIX:
            case X64Opcodes.REX_B_GROUP:
            case X64Opcodes.REX_R_GROUP:
            case X64Opcodes.REX_W_GROUP:
                return Rex.Handle(ctx, address, Log);
            case X64Opcodes.TWO_BYTE:
                return TwoByteOpcodes.Handle(ctx, address, Log);
            default:
                return false;
        }
    }
    private static unsafe bool HandleGrp1_EwIb(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Encoding: 66 83 /r ib   ; /0 ADD, /1 OR, /2 ADC, /3 SBB, /4 AND, /5 SUB, /6 XOR, /7 CMP
        int offs = 2;                  // start at ModRM
        byte modrm = *(address + offs++);
        byte mod = (byte)(modrm >> 6 & 0x3);
        int grp = modrm >> 3 & 0x7; // /digit
        int rm = modrm & 0x7;

        // Addressing (reg or simple [reg]/[reg+disp])
        bool regDirect = mod == 0b11;
        ulong memAddr = 0;

        if (!regDirect)
        {
            if (mod == 0b00)
            {
                if (rm == 0b100) { byte sib = *(address + offs++); memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs); }
                else if (rm == 0b101) { int disp32 = *(int*)(address + offs); offs += 4; memAddr = (ulong)(long)disp32; }
                else memAddr = *(&ctx->Rax + rm);
            }
            else if (mod == 0b01)
            {
                if (rm == 0b100) { byte sib = *(address + offs++); memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs); }
                else { long d8 = *(sbyte*)(address + offs++); memAddr = *(&ctx->Rax + rm) + (ulong)d8; }
            }
            else // 0b10
            {
                if (rm == 0b100) { byte sib = *(address + offs++); int d32 = *(int*)(address + offs); offs += 4; memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs) + (ulong)(long)d32; }
                else { int d32 = *(int*)(address + offs); offs += 4; memAddr = *(&ctx->Rax + rm) + (ulong)(long)d32; }
            }
        }

        // imm8 sign-extended to 16
        sbyte imm8s = *(sbyte*)(address + offs++);
        ushort imm16 = (ushort)(short)imm8s;

        // Load/store target
        ushort* dst16 = regDirect ? (ushort*)(&ctx->Rax + rm) : (ushort*)memAddr;
        ushort lhs = *dst16, res = 0;

        // Flags
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags;

        void SetLogic(ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF);                 // CF=OF=0; update ZF/SF/PF
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
        }
        void SetAdd(ushort a, ushort b, int cin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ua = a, ub = (uint)(b + cin);
            if (ua + ub > 0xFFFF) f |= CF;
            if (((a ^ r) & (b ^ r) & 0x8000) != 0) f |= OF;
            if (((a & 0xF) + (b & 0xF) + (uint)cin & 0x10) != 0) f |= AF;
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
        }
        void SetSub(ushort a, ushort b, int bin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ub = (uint)(b + bin);
            if (a < ub) f |= CF;                              // borrow -> CF=1
            if (((a ^ b) & (a ^ r) & 0x8000) != 0) f |= OF;
            if ((~(a ^ b) & (a ^ r) & 0x10) != 0) f |= AF;    // Intel AF formula
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
        }

        string mnem = grp switch { 0 => "ADD", 1 => "OR", 2 => "ADC", 3 => "SBB", 4 => "AND", 5 => "SUB", 6 => "XOR", 7 => "CMP", _ => "???" };
        string dstTxt = regDirect ? $"R{rm}w" : $"WORD PTR [0x{memAddr:X}]";

        switch (grp)
        {
            case 0: res = (ushort)(lhs + imm16); SetAdd(lhs, imm16, 0, res); *dst16 = res; break;
            case 1: res = (ushort)(lhs | imm16); SetLogic(res); *dst16 = res; break;
            case 2: { int c = (f & CF) != 0 ? 1 : 0; res = (ushort)(lhs + (ushort)(imm16 + c)); SetAdd(lhs, imm16, c, res); *dst16 = res; } break;
            case 3: { int b = (f & CF) != 0 ? 1 : 0; res = (ushort)(lhs - (ushort)(imm16 + b)); SetSub(lhs, imm16, b, res); *dst16 = res; } break;
            case 4: res = (ushort)(lhs & imm16); SetLogic(res); *dst16 = res; break;
            case 5: res = (ushort)(lhs - imm16); SetSub(lhs, imm16, 0, res); *dst16 = res; break;
            case 6: res = (ushort)(lhs ^ imm16); SetLogic(res); *dst16 = res; break;
            case 7: res = (ushort)(lhs - imm16); SetSub(lhs, imm16, 0, res); /* no write-back */ break;
            default: Log($"Unsupported 66 83 /{grp}", offs); return false;
        }

        ctx->EFlags = f;
        Log($"{mnem} {dstTxt}, 0x{imm16:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;

        // local SIB helper (16-bit op, but addressing is standard 64-bit)
        static ulong ComputeSibAddr16(CONTEXT* ctx, byte* baseAddr, byte sib, byte modLocal, ref int offsLocal)
        {
            byte scaleBits = (byte)(sib >> 6 & 0x3);
            byte idxBits = (byte)(sib >> 3 & 0x7);
            byte baseBits = (byte)(sib & 0x7);

            ulong baseVal = 0;
            if (!(modLocal == 0b00 && baseBits == 0b101))
                baseVal = *(&ctx->Rax + baseBits);

            ulong indexVal = 0;
            if (idxBits != 0b100)
            {
                indexVal = *(&ctx->Rax + idxBits);
                indexVal <<= scaleBits;
            }

            ulong addr = baseVal + indexVal;
            if (modLocal == 0b01) { long d8 = *(sbyte*)(baseAddr + offsLocal); offsLocal += 1; addr += (ulong)d8; }
            else if (modLocal == 0b10) { int d32 = *(int*)(baseAddr + offsLocal); offsLocal += 4; addr += (ulong)(long)d32; }
            return addr;
        }
    }
    private static bool HandleOperandSizePrefix(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0x66 prefix
        byte op = *(address + 1);
        if (op == 0x83) // Group-1 Ew,Ib  (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP — imm8 sign-extended to 16)
        {
            return HandleGrp1_EwIb(ctx, address, Log);
        }
        // Support the pattern we hit: 66 C7 /0 r/m16, imm16
        if (op == 0xC7) // MOV r/m16, imm16 (because of 0x66 prefix)
        {
            int offs = 2; // at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)(modrm >> 6 & 0x3);
            int regop = modrm >> 3 & 0x7;   // must be /0
            int rm = modrm & 0x7;

            if (regop != 0)
            {
                Log($"Unsupported 66 C7 /{regop}", offs);
                return false;
            }

            // SIB helper (no REX here; it’s a legacy prefix)
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)(sib >> 6 & 0x3);
                byte idxBits = (byte)(sib >> 3 & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32;  // no base, disp32 only
                }
                else
                {
                    baseVal = *(&ctx->Rax + baseBits);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 = no index
                {
                    indexVal = *(&ctx->Rax + idxBits);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }
                return baseVal + indexVal;
            }

            if (mod == 0b11)
            {
                // register form: write low 16 bits of the target reg
                ushort imm16 = *(ushort*)(address + offs); offs += 2;
                // low 16 of (&Rax)[rm]
                ushort* dst16 = (ushort*)(&ctx->Rax + rm);
                *dst16 = imm16;

                Log($"MOV R{rm}w, 0x{imm16:X4}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            else
            {
                // memory form
                ulong memAddr = 0;

                if (mod == 0b00)
                {
                    if ((modrm & 0x7) == 0b100)       // SIB
                    {
                        byte sib = *(address + offs++);
                        memAddr = computeSibAddr(sib, mod, ref offs);
                    }
                    else if ((modrm & 0x7) == 0b101)  // RIP-rel disp32 (rare under 0x66, but support)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        ulong nextRip = ctx->Rip + (ulong)offs;
                        memAddr = nextRip + (ulong)(long)disp32;
                    }
                    else
                    {
                        memAddr = *(&ctx->Rax + rm);
                    }
                }
                else if (mod == 0b01) // disp8
                {
                    if ((modrm & 0x7) == 0b100)
                    {
                        byte sib = *(address + offs++);
                        long disp8 = *(sbyte*)(address + offs++);  // sign-extend
                        memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)disp8;
                    }
                    else
                    {
                        long disp8 = *(sbyte*)(address + offs++);  // sign-extend
                        memAddr = *(&ctx->Rax + rm) + (ulong)disp8;
                    }
                }
                else // mod == 0b10  disp32
                {
                    if ((modrm & 0x7) == 0b100)
                    {
                        byte sib = *(address + offs++);
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)(long)disp32;
                    }
                    else
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr = *(&ctx->Rax + rm) + (ulong)(long)disp32;
                    }
                }

                ushort imm16 = *(ushort*)(address + offs); offs += 2;
                *(ushort*)memAddr = imm16;

                Log($"MOV WORD PTR [0x{memAddr:X}], 0x{imm16:X4}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
        }
        if (op == 0x83) // Group-1, Ew,Ib (imm8 sign-extended to 16)
        {
            return HandleGrp1_EwIb(ctx, address, Log);
        }
        if (op == 0x89) // MOV r/m16, r16
        {
            return HandleMovEwGw(ctx, address, Log);
        }
        if (op == 0x3B) return HandleCmpGvEv16(ctx, address, Log);
        if (op == 0x85) // TEST r/m16, r16 (because of 0x66)
            return HandleTestRmR(ctx, address, operandBitsOverride: 16, Log);
        if (op == 0x39) // CMP r/m16, r16
            return HandleCmpEvGv16(ctx, address, Log);
        Log($"Unhandled 0x66-prefixed opcode 0x{*(address + 1):X2}", 2);
        return false;
    }
    private static unsafe bool HandleCmpGvEv16(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 3B /r → CMP r16, r/m16
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // destination (r16)
        int rm = modrm & 7;      // source (r/m16)
        ulong* R = &ctx->Rax;

        ushort src, dst;
        ulong memAddr = 0;
        string srcDesc, dstDesc;

        if (mod == 0b11)
        {
            src = (ushort)(R[rm] & 0xFFFF);
            srcDesc = $"R{rm}w";
        }
        else
        {
            memAddr = R[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(ip + offs); offs += 1;
                memAddr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                memAddr += (ulong)(long)d32;
            }

            src = *(ushort*)memAddr;
            srcDesc = $"WORD PTR [0x{memAddr:X}]";
        }

        dst = (ushort)(R[reg] & 0xFFFF);
        dstDesc = $"R{reg}w";

        ushort result = (ushort)(dst - src);

        // ---- update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (dst < src) f |= CF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if (((dst ^ src) & (dst ^ result) & 0x8000) != 0) f |= OF;
        if (((dst ^ src ^ result) & 0x10) != 0) f |= AF; // added AF
        byte low = (byte)(result & 0xFF);
        if ((System.Numerics.BitOperations.PopCount(low) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        Log($"CMP {dstDesc}, {srcDesc} => result=0x{result:X4} [ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, CF={(f & CF) != 0}, OF={(f & OF) != 0}, PF={(f & PF) != 0}, AF={(f & AF) != 0}]", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleCmpEvGv16(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 39 /r  →  CMP r/m16, r16
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7;   // source (r16)
        int rm = modrm & 7;         // destination (r/m16)
        ulong* R = &ctx->Rax;

        ushort lhs;   // r/m16
        ushort rhs;   // r16
        ulong addr = 0;
        string lhsDesc, rhsDesc;

        if (mod == 0b11)
        {
            lhs = (ushort)(R[rm] & 0xFFFF);
            lhsDesc = $"R{rm}w";
        }
        else
        {
            addr = R[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(ip + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                addr += (ulong)(long)d32;
            }

            lhs = *(ushort*)addr;
            lhsDesc = $"WORD PTR [0x{addr:X}]";
        }

        rhs = (ushort)(R[reg] & 0xFFFF);
        rhsDesc = $"R{reg}w";

        ushort result = (ushort)(lhs - rhs);

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (lhs < rhs) f |= CF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if (((lhs ^ rhs) & (lhs ^ result) & 0x8000) != 0) f |= OF;
        if (((lhs ^ rhs ^ result) & 0x10) != 0) f |= AF; // added AF
        byte low = (byte)(result & 0xFF);
        if ((System.Numerics.BitOperations.PopCount(low) & 1) == 0)
            f |= PF;

        ctx->EFlags = f;

        Log($"CMP {lhsDesc}, {rhsDesc} => result=0x{result:X4} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, CF={(f & CF) != 0}, OF={(f & OF) != 0}, PF={(f & PF) != 0}, AF={(f & AF) != 0}]", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleTestRmR(CONTEXT* ctx, byte* address, int operandBitsOverride, Action<string, int> Log)
    {
        // Address may point to 0x66 or directly to opcode.
        bool has66 = *address == 0x66;
        byte* p = has66 ? address + 1 : address; // p -> opcode (84/85)

        byte op = *p;            // 0x84 (byte) or 0x85 (word/dword/qword)
        byte modrm = *(p + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);

        // Check for a REX prefix immediately before 'op' (common in your decoder flow).
        // If your decoder already captures the active REX byte, pass it in instead.
        byte rex = 0;
        if (!has66 && address > (byte*)0) // quick, local peek
        {
            byte prev = *(address - 1);
            if ((prev & 0xF0) == 0x40) rex = prev;
        }
        else if (has66)
        {
            // 66 may be followed by REX, then the opcode (rare in compiler output, but valid)
            byte maybeRex = *(address + 1); // this is actually op; if you want full generality, expand prefix scanner
                                            // keep as-is for now; your codebase already handles REX in a separate path
        }

        bool rexW = (rex & 0x08) != 0;
        bool rexR = (rex & 0x04) != 0;
        bool rexB = (rex & 0x01) != 0;

        // Extend reg indices with REX
        int dst = rexR ? reg | 8 : reg;
        int src = rexB ? rm | 8 : rm;

        // Decide operand size
        int bits;
        if (op == 0x84) bits = 8;
        else if (operandBitsOverride == 16) bits = 16;            // 66 85 -> word
        else if (rexW) bits = 64;                                 // REX.W 85 -> qword
        else bits = 32;                                           // default in long mode

        // Access regs
        ulong* R = &ctx->Rax;

        // Fetch operands (simple addressing only)
        ulong lhs, rhs;
        string lhsDesc, rhsDesc;

        if (op == 0x84)
        {
            // TEST r/m8, r8
            if (mod == 0b11)
            {
                lhs = R[src] & 0xFF;
                lhsDesc = $"R{src}";
            }
            else
            {
                ulong addr = R[src];
                lhs = *(byte*)addr;
                lhsDesc = $"BYTE PTR [0x{addr:X}]";
            }
            rhs = R[dst] & 0xFF;
            rhsDesc = $"R{dst}";
        }
        else // 0x85
        {
            if (mod == 0b11)
            {
                ulong s = R[src];
                lhs = bits == 16 ? s & 0xFFFFUL
                     : bits == 32 ? s & 0xFFFF_FFFFUL
                     : s;
                lhsDesc = $"R{src}";
            }
            else
            {
                ulong addr = R[src];
                if (bits == 16) lhs = *(ushort*)addr;
                else if (bits == 32) lhs = *(uint*)addr;
                else lhs = *(ulong*)addr;
                lhsDesc = bits == 16 ? $"WORD PTR [0x{addr:X}]"
                        : bits == 32 ? $"DWORD PTR [0x{addr:X}]"
                                      : $"QWORD PTR [0x{addr:X}]";
            }

            ulong d = R[dst];
            rhs = bits == 16 ? d & 0xFFFFUL
                 : bits == 32 ? d & 0xFFFF_FFFFUL
                              : d;
            rhsDesc = $"R{dst}";
        }

        ulong result = lhs & rhs;

        // ----- EFLAGS update for TEST -----
        const uint CF = 1U << 0;
        const uint PF = 1U << 2;
        const uint AF = 1U << 4; // undefined, leave as-is
        const uint ZF = 1U << 6;
        const uint SF = 1U << 7;
        const uint OF = 1U << 11;

        // Clear CF, OF, ZF, SF, PF; preserve AF
        uint keep = ctx->EFlags & AF;
        ctx->EFlags = keep;
        // CF, OF are 0 by definition for TEST

        // ZF
        if (result == 0) ctx->EFlags |= ZF;

        // SF (sign bit of the chosen width)
        int msb = bits - 1;
        if ((result >> msb & 1UL) != 0) ctx->EFlags |= SF;

        // PF (parity of low byte, even parity -> PF=1)
        byte low = (byte)(result & 0xFF);
        // 0x6996 parity trick: bit=1 for even parity
        if ((0x6996 >> (low & 0x0F) & 1) == 1)
        {
            // fold high nibble
            byte folded = (byte)(low ^ low >> 4);
            if ((0x6996 >> (folded & 0x0F) & 1) == 1) ctx->EFlags |= PF;
        }

        // ----- Advance RIP & log -----
        int len = has66 ? 3 : 2; // 66 + 85 + modrm  OR  85 + modrm
                                 // (No SIB/disp yet; extend len when you add them)

        string sizeTag = bits == 8 ? "BYTE"
                         : bits == 16 ? "WORD"
                         : bits == 32 ? "DWORD"
                         : "QWORD";

        Log($"TEST {sizeTag} {lhsDesc}, {rhsDesc} => ZF={((ctx->EFlags & ZF) != 0 ? 1 : 0)}, SF={((ctx->EFlags & SF) != 0 ? 1 : 0)}, PF={((ctx->EFlags & PF) != 0 ? 1 : 0)}", len);
        ctx->Rip += (ulong)len;
        return true;
    }
    private static unsafe bool HandleMovEwGw(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 66 89 /r → MOV r/m16, r16
        int offs = 2;
        byte modrm = *(address + offs++);
        byte mod = (byte)(modrm >> 6 & 0x3);
        int reg = modrm >> 3 & 0x7; // source
        int rm = modrm & 0x7;      // destination
        ulong* R = &ctx->Rax;

        ushort srcVal = (ushort)(R[reg] & 0xFFFF);
        ulong memAddr = 0;
        string dstDesc;

        if (mod == 0b11)
        {
            // Register to register: overwrite low 16 bits only
            R[rm] = R[rm] & ~0xFFFFUL | srcVal;
            dstDesc = $"R{rm}w";
        }
        else
        {
            // Compute effective address (simple + disp)
            memAddr = R[rm];
            if (mod == 0b01) // disp8
            {
                long disp8 = *(sbyte*)(address + offs++);
                memAddr += (ulong)disp8;
            }
            else if (mod == 0b10) // disp32
            {
                int disp32 = *(int*)(address + offs);
                offs += 4;
                memAddr += (ulong)(long)disp32;
            }

            *(ushort*)memAddr = srcVal;
            dstDesc = $"WORD PTR [0x{memAddr:X}]";
        }

        Log($"MOV {dstDesc}, R{reg}w => 0x{srcVal:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleSegmentPrefix(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        if (*address != 0x65) // only GS prefix
            return false;

        byte* next = address + 1;

        // Case 1: 65 48 8B 04 25 <disp32> → MOV RAX, [GS:disp32]
        if (*next == 0x48 && *(next + 1) == 0x8B && *(next + 2) == 0x04 && *(next + 3) == 0x25)
        {
            uint disp32 = *(uint*)(next + 4);   // read displacement
            ulong tebBase = ThreadInformation.GetCurrentThreadGsBase();
            ulong addr = tebBase + disp32;
            ulong value = *(ulong*)addr;

            ctx->Rax = value;
            Log($"MOV RAX, [GS:0x{disp32:X}] => RAX=0x{value:X} (TEB base=0x{tebBase:X})", 9);
            ctx->Rip += 9;
            return true;
        }

        // Case 2: 65 48 8B /r (register-based addressing, no disp32)
        if (*next == 0x48 && *(next + 1) == 0x8B)
        {
            byte prefix = *address; // 0x65 (GS)
                                    //    if (prefix != 0x65)
                                    //        return false;
                                    // 65 48 8B 00  => MOV RAX, [GS:RAX]
                                    // General pattern: 65 48 8B /r (modrm with mod==00)
            if (*next == 0x48 && *(next + 1) == 0x8B)
            {
                byte modrm = *(next + 2);
                byte mod = (byte)(modrm >> 6 & 3);
                byte reg = (byte)(modrm >> 3 & 7);
                byte rm = (byte)(modrm & 7);

                if (mod == 0) // no displacement
                {
                    ulong tebBase = ThreadInformation.GetCurrentThreadGsBase();
                    var offset = (&ctx->Rax)[rm];
                    ulong addr = tebBase + offset;
                    ulong value = *(ulong*)addr;
                    (&ctx->Rax)[reg] = value;

                    Log($"MOV R{reg}, [GS:R{rm}] => R{reg}=0x{value:X} (addr=0x{addr:X}, GS=0x{tebBase:X})", 4);
                    ctx->Rip += 4;
                    return true;
                }
            }
        }

        Log("Unhandled GS-prefixed opcode", 8);
        return false;
    }
}
