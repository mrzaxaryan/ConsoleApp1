using static ConsoleApp1.RWXless;

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
    private static unsafe bool HandleGrp1_EwIb(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 83 /r ib  →  Grp1 on r/m16 with imm8 (sign-extended)
        int offs = 0;

        // Expect operand-size override 0x66
        if (ip[offs++] != 0x66) return false;

        // Optional REX (affects addressing: B/X; R not used here)
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40) rex = ip[offs++];

        // Opcode 0x83
        if (ip[offs++] != 0x83) return false;

        bool REX_B = (rex & 0x01) != 0;
        bool REX_X = (rex & 0x02) != 0;

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int grp = (modrm >> 3) & 7;              // /digit selects op
        int rm = (modrm & 7) | (REX_B ? 8 : 0); // extend r/m with REX.B for R8..R15

        // ---- Addressing ----
        bool regDirect = (mod == 0b11);
        ulong memAddr = 0;
        ulong* R64 = &ctx->Rax;

        if (!regDirect)
        {
            bool usesSib = ((modrm & 7) == 0b100);
            if (mod == 0b00 && !usesSib && ((modrm & 7) == 0b101))
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idx = ((sib >> 3) & 7) | (REX_X ? 8 : 0);
                int bas = (sib & 7) | (REX_B ? 8 : 0);

                bool indexNone = (((sib >> 3) & 7) == 0b100) && !REX_X; // index==4 w/o REX.X → no index
                ulong indexVal = indexNone ? 0 : (R64[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101); // SIB base==101 & mod==00 → disp32-only (absolute)
                ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32; // absolute disp32 (NOT RIP-relative)
                }
            }
            else
            {
                memAddr = R64[rm];
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
            }
        }

        // ---- imm8 sign-extended to 16 ----
        sbyte imm8s = *(sbyte*)(ip + offs++);      // signed 8
        ushort imm16 = (ushort)(short)imm8s;       // 8→16 sign extend

        // ---- Load/store target ----
        ushort* dst16 = regDirect ? (ushort*)(R64 + rm) : (ushort*)memAddr;
        ushort lhs = *dst16, res = 0;

        // ---- Flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags;

        void SetLogic(ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF);
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            if ((System.Numerics.BitOperations.PopCount((byte)r) & 1) == 0) f |= PF;
        }

        void SetAdd(ushort a, ushort b, int cin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ua = a, ub = (uint)b + (uint)cin;
            if (ua + ub > 0xFFFF) f |= CF;
            if (((a ^ r) & (b ^ r) & 0x8000) != 0) f |= OF;
            if ((((a & 0xF) + (b & 0xF) + (uint)cin) & 0x10) != 0) f |= AF; // fixed precedence
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            if ((System.Numerics.BitOperations.PopCount((byte)r) & 1) == 0) f |= PF;
        }

        void SetSub(ushort a, ushort b, int bin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ub = (uint)b + (uint)bin;
            if (a < ub) f |= CF; // borrow
            if (((a ^ b) & (a ^ r) & 0x8000) != 0) f |= OF;
            if ((~(a ^ b) & (a ^ r) & 0x10) != 0) f |= AF;
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            if ((System.Numerics.BitOperations.PopCount((byte)r) & 1) == 0) f |= PF;
        }

        string mnem = grp switch
        {
            0 => "ADD",
            1 => "OR",
            2 => "ADC",
            3 => "SBB",
            4 => "AND",
            5 => "SUB",
            6 => "XOR",
            7 => "CMP",
            _ => "???"
        };
        string dstTxt = regDirect ? $"R{rm}w" : $"WORD PTR [0x{(regDirect ? 0UL : memAddr):X}]";

        switch (grp)
        {
            case 0: res = (ushort)(lhs + imm16); SetAdd(lhs, imm16, 0, res); *dst16 = res; break;                // ADD
            case 1: res = (ushort)(lhs | imm16); SetLogic(res); *dst16 = res; break;                              // OR
            case 2: { int c = (f & CF) != 0 ? 1 : 0; res = (ushort)(lhs + (ushort)(imm16 + c)); SetAdd(lhs, imm16, c, res); *dst16 = res; } break; // ADC
            case 3: { int b = (f & CF) != 0 ? 1 : 0; res = (ushort)(lhs - (ushort)(imm16 + b)); SetSub(lhs, imm16, b, res); *dst16 = res; } break; // SBB
            case 4: res = (ushort)(lhs & imm16); SetLogic(res); *dst16 = res; break;                              // AND
            case 5: res = (ushort)(lhs - imm16); SetSub(lhs, imm16, 0, res); *dst16 = res; break;                 // SUB
            case 6: res = (ushort)(lhs ^ imm16); SetLogic(res); *dst16 = res; break;                              // XOR
            case 7: res = (ushort)(lhs - imm16); SetSub(lhs, imm16, 0, res); /* CMP: no write-back */ break;      // CMP
            default: Log($"Unsupported 66 83 /{grp}", offs); return false;
        }

        ctx->EFlags = f;
        Log($"{mnem} {dstTxt}, 0x{imm16:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleOperandSizePrefix(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // We are at 0x66 (operand-size override)
        int offs = 0;
        if (ip[offs++] != 0x66)
            return false;

        // Optional REX prefix (extends addressing)
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        byte op = ip[offs++];

        // Handle 66 83 /r ib → Grp1 Ew,Ib
        if (op == 0x83)
            return HandleGrp1_EwIb(ctx, ip, Log);

        // ---- Handle 66 C7 /0 → MOV r/m16, imm16 ----
        if (op == 0xC7)
        {
            bool REX_B = (rex & 0x01) != 0;
            bool REX_X = (rex & 0x02) != 0;

            byte modrm = ip[offs++];
            byte mod = (byte)((modrm >> 6) & 3);
            int regop = (modrm >> 3) & 7; // must be /0
            int rm = ((modrm & 7) | (REX_B ? 8 : 0));

            if (regop != 0)
            {
                Log($"Unsupported 66 C7 /{regop}", offs);
                return false;
            }

            ulong* R64 = &ctx->Rax;
            ulong memAddr = 0;
            ushort imm16;

            if (mod == 0b11)
            {
                // Register-direct: MOV r16, imm16
                imm16 = *(ushort*)(ip + offs);
                offs += 2;
                *(ushort*)(R64 + rm) = imm16;

                Log($"MOV R{rm}w, 0x{imm16:X4}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }

            // --- Memory addressing ---
            bool usesSib = ((modrm & 7) == 0b100);

            if (mod == 0b00 && !usesSib && ((modrm & 7) == 0b101))
            {
                // RIP-relative [RIP + disp32]
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idx = ((sib >> 3) & 7) | (REX_X ? 8 : 0);
                int bas = (sib & 7) | (REX_B ? 8 : 0);

                bool indexNone = (((sib >> 3) & 7) == 0b100) && !REX_X; // index==4 && !REX.X → no index
                ulong indexVal = indexNone ? 0 : (R64[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101);
                ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32; // absolute disp32 (not RIP-relative)
                }
            }
            else
            {
                memAddr = R64[rm];
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
            }

            imm16 = *(ushort*)(ip + offs);
            offs += 2;
            *(ushort*)memAddr = imm16;

            Log($"MOV WORD PTR [0x{memAddr:X}], 0x{imm16:X4}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // ---- Forward other prefixed ops ----
        if (op == 0x89) return HandleMovEwGw(ctx, ip, Log);          // MOV r/m16, r16
        if (op == 0x3B) return HandleCmpGvEv16(ctx, ip, Log);        // CMP r16, r/m16
        if (op == 0x39) return HandleCmpEvGv16(ctx, ip, Log);        // CMP r/m16, r16
        if (op == 0x85) return HandleTestRmR(ctx, ip, 16, Log);      // TEST r/m16, r16

        Log($"Unhandled 0x66-prefixed opcode 0x{op:X2}", 2);
        return false;
    }
    private static unsafe bool HandleCmpGvEv16(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 3B /r → CMP r16, r/m16
        int offs = 0;

        // Operand-size override (0x66)
        if (ip[offs++] != 0x66)
            return false;

        // Optional REX prefix (affects R/B)
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // Opcode 0x3B
        if (ip[offs++] != 0x3B)
            return false;

        bool REX_R = (rex & 0x04) != 0; // extends ModRM.reg
        bool REX_B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool REX_X = (rex & 0x02) != 0; // for SIB index (if used)

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (REX_R ? 8 : 0); // destination (r16)
        int rm = (modrm & 7) | (REX_B ? 8 : 0);       // source (r/m16)

        ulong* R = &ctx->Rax;
        ushort src, dst;
        ulong memAddr = 0;
        string srcDesc, dstDesc;

        // --- Decode addressing ---
        if (mod == 0b11)
        {
            // Register operand
            src = (ushort)(R[rm] & 0xFFFF);
            srcDesc = $"R{rm}w";
        }
        else
        {
            bool usesSib = ((modrm & 7) == 0b100);

            if (mod == 0b00 && !usesSib && ((modrm & 7) == 0b101))
            {
                // RIP-relative [RIP + disp32]
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idx = ((sib >> 3) & 7) | (REX_X ? 8 : 0);
                int bas = ((sib & 7) | (REX_B ? 8 : 0));

                bool indexNone = (((sib >> 3) & 7) == 0b100) && !REX_X; // no index if index==4 & !REX.X
                ulong indexVal = indexNone ? 0 : (R[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101);
                ulong baseVal = baseIsDisp32 ? 0 : R[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32;
                }
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
            }

            src = *(ushort*)memAddr;
            srcDesc = $"WORD PTR [0x{memAddr:X}]";
        }

        dst = (ushort)(R[reg] & 0xFFFF);
        dstDesc = $"R{reg}w";

        ushort result = (ushort)(dst - src);

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4,
                   ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;

        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (dst < src) f |= CF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if (((dst ^ src) & (dst ^ result) & 0x8000) != 0) f |= OF;
        if (((dst ^ src ^ result) & 0x10) != 0) f |= AF;
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        Log($"CMP {dstDesc}, {srcDesc} => result=0x{result:X4} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, CF={(f & CF) != 0}, "
            + $"OF={(f & OF) != 0}, PF={(f & PF) != 0}, AF={(f & AF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleCmpEvGv16(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 39 /r → CMP r/m16, r16
        int offs = 0;

        // Operand-size override
        if (ip[offs++] != 0x66)
            return false;

        // Optional REX (affects addressing: R/B/X)
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // Opcode
        if (ip[offs++] != 0x39)
            return false;

        bool REX_R = (rex & 0x04) != 0; // extends ModRM.reg
        bool REX_B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool REX_X = (rex & 0x02) != 0; // extends SIB.index

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (REX_R ? 8 : 0); // source r16
        int rm = (modrm & 7) | (REX_B ? 8 : 0); // destination r/m16

        ulong* R = &ctx->Rax;

        ushort lhs;   // r/m16 (destination operand)
        ushort rhs;   // r16   (source operand)
        ulong memAddr = 0;
        string lhsDesc, rhsDesc;

        // ---- Resolve r/m16 ----
        if (mod == 0b11)
        {
            lhs = (ushort)(R[rm] & 0xFFFF);
            lhsDesc = $"R{rm}w";
        }
        else
        {
            bool usesSib = ((modrm & 7) == 0b100);

            if (mod == 0b00 && !usesSib && ((modrm & 7) == 0b101))
            {
                // RIP-relative: [RIP + disp32]
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idx = ((sib >> 3) & 7) | (REX_X ? 8 : 0);
                int bas = ((sib & 7) | (REX_B ? 8 : 0));

                bool indexNone = (((sib >> 3) & 7) == 0b100) && !REX_X; // index==4 and no REX.X ⇒ no index
                ulong indexVal = indexNone ? 0 : (R[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101);
                ulong baseVal = baseIsDisp32 ? 0 : R[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32; // absolute disp32 (NOT RIP-relative)
                }
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
            }

            lhs = *(ushort*)memAddr;
            lhsDesc = $"WORD PTR [0x{memAddr:X}]";
        }

        // ---- Source r16 ----
        rhs = (ushort)(R[reg] & 0xFFFF);
        rhsDesc = $"R{reg}w";

        // ---- Perform compare (lhs - rhs) and set flags ----
        ushort result = (ushort)(lhs - rhs);

        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4,
                   ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;

        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (lhs < rhs) f |= CF;                             // borrow
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if (((lhs ^ rhs) & (lhs ^ result) & 0x8000) != 0) f |= OF;
        if (((lhs ^ rhs ^ result) & 0x10) != 0) f |= AF;    // nibble borrow
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        Log($"CMP {lhsDesc}, {rhsDesc} => result=0x{result:X4} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, CF={(f & CF) != 0}, "
            + $"OF={(f & OF) != 0}, PF={(f & PF) != 0}, AF={(f & AF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleTestRmR(CONTEXT* ctx, byte* ip, int operandBitsOverride, Action<string, int> Log)
    {
        int offs = 0;

        // Prefix scan: 0x66 (optional), then optional REX
        bool has66 = false;
        if (ip[offs] == 0x66) { has66 = true; offs++; }

        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40) rex = ip[offs++];

        // Opcode: 0x84 (byte) or 0x85 (word/dword/qword)
        byte op = ip[offs++];
        if (op != 0x84 && op != 0x85) return false;

        bool REX_W = (rex & 0x08) != 0;
        bool REX_R = (rex & 0x04) != 0;
        bool REX_X = (rex & 0x02) != 0;
        bool REX_B = (rex & 0x01) != 0;
        bool hasREX = rex != 0;

        // ModRM
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int regLo = (modrm >> 3) & 7;
        int rmLo = (modrm & 7);

        int reg = regLo | (REX_R ? 8 : 0);
        int rm = rmLo | (REX_B ? 8 : 0);

        // Determine operand width
        int bits = (op == 0x84) ? 8
                  : (operandBitsOverride == 16) ? 16
                  : (REX_W ? 64 : 32);

        // Helpers
        ulong* R64 = &ctx->Rax;

        static bool IsHighByteSel(int low3) => (low3 >= 4 && low3 <= 7);
        static string Reg8Name(int low3, int ext, bool hasREX)
        {
            if (!hasREX && IsHighByteSel(low3))
                return low3 switch { 4 => "AH", 5 => "CH", 6 => "DH", 7 => "BH", _ => $"R{ext}b" };
            return $"R{ext}b";
        }

        // Read an 8-bit register value honoring AH/CH/DH/BH rules
        static byte ReadReg8(ulong* R64, int low3, int ext, bool hasREX)
        {
            if (!hasREX && IsHighByteSel(low3))
            {
                // High byte of AX/CX/DX/BX (maps to base regs 0..3)
                int baseIdx = low3 - 4; // 4→0(A),5→1(C),6→2(D),7→3(B)
                return *(((byte*)(R64 + baseIdx)) + 1);
            }
            // Low byte of RAX..R15
            return *(byte*)(R64 + ext);
        }

        // Effective address computation (RIP-rel / SIB / disp)
        ulong memAddr = 0;
        bool usesSib = (rmLo == 0b100);

        if (mod != 0b11)
        {
            if (mod == 0b00 && !usesSib && rmLo == 0b101)
            {
                // RIP-relative
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idxLo = (sib >> 3) & 7;
                int basLo = (sib & 7);

                int idx = idxLo | (REX_X ? 8 : 0);
                int bas = basLo | (REX_B ? 8 : 0);

                bool indexNone = (idxLo == 0b100) && !REX_X; // no index
                ulong indexVal = indexNone ? 0 : (R64[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && (basLo == 0b101);
                ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

                memAddr = baseVal + indexVal;

                if (mod == 0b01) { long d8 = *(sbyte*)(ip + offs); offs += 1; memAddr += (ulong)d8; }
                else if (mod == 0b10) { int d32 = *(int*)(ip + offs); offs += 4; memAddr += (ulong)(long)d32; }
                else if (baseIsDisp32) { int d32 = *(int*)(ip + offs); offs += 4; memAddr = (ulong)(long)d32; }
            }
            else
            {
                memAddr = R64[rm];
                if (mod == 0b01) { long d8 = *(sbyte*)(ip + offs); offs += 1; memAddr += (ulong)d8; }
                else if (mod == 0b10) { int d32 = *(int*)(ip + offs); offs += 4; memAddr += (ulong)(long)d32; }
            }
        }

        // Fetch operands and descriptions
        ulong lhs, rhs;
        string lhsDesc, rhsDesc, sizeTag = (bits == 8) ? "BYTE" : (bits == 16) ? "WORD" : (bits == 32) ? "DWORD" : "QWORD";

        if (op == 0x84) // TEST r/m8, r8
        {
            // RHS: r8 (reg field)
            rhs = ReadReg8(R64, regLo, reg, hasREX);
            rhsDesc = Reg8Name(regLo, reg, hasREX);

            // LHS: r/m8
            if (mod == 0b11)
            {
                lhs = ReadReg8(R64, rmLo, rm, hasREX);
                lhsDesc = Reg8Name(rmLo, rm, hasREX);
            }
            else
            {
                lhs = *(byte*)memAddr;
                lhsDesc = $"BYTE PTR [0x{memAddr:X}]";
            }
        }
        else // 0x85 → TEST r/m16/32/64, r16/32/64
        {
            // RHS (reg)
            ulong r = R64[reg];
            rhs = bits == 16 ? r & 0xFFFFUL
                 : bits == 32 ? r & 0xFFFF_FFFFUL
                              : r;
            rhsDesc = (bits == 16) ? $"R{reg}w" : (bits == 32) ? $"R{reg}d" : $"R{reg}";

            // LHS (r/m)
            if (mod == 0b11)
            {
                ulong s = R64[rm];
                lhs = bits == 16 ? s & 0xFFFFUL
                     : bits == 32 ? s & 0xFFFF_FFFFUL
                                  : s;
                lhsDesc = (bits == 16) ? $"R{rm}w" : (bits == 32) ? $"R{rm}d" : $"R{rm}";
            }
            else
            {
                if (bits == 16) lhs = *(ushort*)memAddr;
                else if (bits == 32) lhs = *(uint*)memAddr;
                else lhs = *(ulong*)memAddr;

                lhsDesc = (bits == 16) ? $"WORD PTR [0x{memAddr:X}]"
                        : (bits == 32) ? $"DWORD PTR [0x{memAddr:X}]"
                                       : $"QWORD PTR [0x{memAddr:X}]";
            }
        }

        ulong result = lhs & rhs;

        // ----- Flags -----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;

        uint prev = ctx->EFlags;
        uint keepAF = prev & AF;               // AF is undefined; keep prior bit (common practice)
        uint f = keepAF;                       // CF/OF cleared (remain 0), we’ll set ZF/SF/PF

        if (result == 0) f |= ZF;              // ZF
        int msb = bits - 1;
        if (((result >> msb) & 1UL) != 0) f |= SF; // SF from sign bit
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF; // even parity

        ctx->EFlags = f;

        Log($"TEST {sizeTag} {lhsDesc}, {rhsDesc} => "
            + $"ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, PF={(f & PF) != 0}", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleMovEwGw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 89 /r → MOV r/m16, r16
        int offs = 0;

        // Operand-size override
        if (ip[offs++] != 0x66) return false;

        // Optional REX (affects addressing)
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // Opcode 0x89
        if (ip[offs++] != 0x89) return false;

        bool REX_R = (rex & 0x04) != 0; // extends ModRM.reg
        bool REX_B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool REX_X = (rex & 0x02) != 0; // extends SIB.index

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (REX_R ? 8 : 0); // source
        int rm = ((modrm & 7) & 7) | (REX_B ? 8 : 0);  // destination

        ulong* R64 = &ctx->Rax;
        ushort srcVal = (ushort)(R64[reg] & 0xFFFF);
        ulong memAddr = 0;
        string dstDesc;

        // --- Effective address decoding ---
        if (mod == 0b11)
        {
            // Register → Register: overwrite only low 16 bits
            ulong old = R64[rm];
            R64[rm] = (old & ~0xFFFFUL) | srcVal;
            dstDesc = $"R{rm}w";
        }
        else
        {
            bool usesSib = ((modrm & 7) == 0b100);

            if (mod == 0b00 && !usesSib && ((modrm & 7) == 0b101))
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = (sib >> 6) & 3;
                int idx = ((sib >> 3) & 7) | (REX_X ? 8 : 0);
                int bas = ((sib & 7) | (REX_B ? 8 : 0));

                bool indexNone = (((sib >> 3) & 7) == 0b100) && !REX_X;
                ulong indexVal = indexNone ? 0 : (R64[idx] << scale);

                bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101);
                ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32; // absolute disp32 (not RIP-rel)
                }
            }
            else
            {
                memAddr = R64[rm];
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
