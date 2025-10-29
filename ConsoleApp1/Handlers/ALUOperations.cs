using static ConsoleApp1.RWXless;

namespace ConsoleApp1.Handlers;

public static unsafe class ALUOperations
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            // Basic ALU and logical instructions
            case X64Opcodes.ADD_R32_RM32: return HandleAddGvEv(ctx, address, Log);
            case X64Opcodes.XOR_R32_RM32: return HandleXorRvEv(ctx, address, Log);
            case X64Opcodes.ADD_RM8_R8: return HandleAddRm8R8(ctx, address, Log);
            case X64Opcodes.TEST_RM8_R8: return HandleTestRm8R8(ctx, address, Log);
            case X64Opcodes.TEST_RM32_R32: return HandleTestRm32R32(ctx, address, Log);
            case X64Opcodes.INCDEC_RM8: return HandleIncDecRm8(ctx, address, Log);
            case X64Opcodes.GRP1_EdIb: return HandleGrp1_EdIb(ctx, address, Log);

            // Handle operand-size prefix TEST (0x66 85 /r)
            case X64Opcodes.OPSIZE_PREFIX:
                if (*(address + 1) == 0x85)
                    return HandleTestEwGw(ctx, address, Log);
                break;

            // REX.W prefixed ADD r/m64, imm8
            case X64Opcodes.REX_PREFIX:
                {
                    byte next = *(address + 1);
                    if (next == 0x83)
                    {
                        byte modrm = *(address + 2);
                        byte regField = (byte)((modrm >> 3) & 0x7);
                        if (regField == 0) // /0 = ADD
                            return HandleAddRm64Imm8(ctx, address, Log);
                    }
                    return false;
                }

            default:
                return false;
        }

        return false;
    }
    private static unsafe bool HandleTestEwGw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 85 /r → TEST r/m16, r16
        if (ip[0] != 0x66 || ip[1] != 0x85)
            return false;

        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7;  // source (r16)
        int rm = modrm & 0x7;         // destination (r/m16)
        ulong* R = &ctx->Rax;

        ushort lhs, rhs;
        ulong addr = 0;
        string lhsDesc, rhsDesc;

        if (mod == 0b11)
        {
            lhs = (ushort)(R[rm] & 0xFFFF);
            rhs = (ushort)(R[reg] & 0xFFFF);
            lhsDesc = $"R{rm}w";
            rhsDesc = $"R{reg}w";
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
            rhs = (ushort)(R[reg] & 0xFFFF);
            lhsDesc = $"WORD PTR [0x{addr:X}]";
            rhsDesc = $"R{reg}w";
        }

        ushort res = (ushort)(lhs & rhs);

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | OF | ZF | SF | PF);

        if (res == 0)
            f |= ZF;
        if ((res & 0x8000) != 0)
            f |= SF;

        // Parity flag (even number of 1s in low byte)
        byte low = (byte)(res & 0xFF);
        if ((System.Numerics.BitOperations.PopCount(low) & 1) == 0)
            f |= PF;

        ctx->EFlags = f;

        Log($"TEST {lhsDesc}, {rhsDesc} => res=0x{res:X4} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleAddRm64Imm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 48 83 /0 r/m64, imm8  (ADD)
        byte modrm = *(address + 2);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
        byte rm = (byte)(modrm & 0x7);
        if (reg != 0)
        {
            Log($"Unsupported 48 83 /{reg} form (only /0=ADD)", 3);
            return false;
        }

        int offs = 3;
        ulong memAddr = 0;
        ulong* R = &ctx->Rax;

        // SIB resolver
        ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
        {
            byte scaleBits = (byte)((sib >> 6) & 0x3);
            byte idxBits = (byte)((sib >> 3) & 0x7);
            byte baseBits = (byte)(sib & 0x7);

            ulong baseVal = 0, indexVal = 0;
            if (baseBits != 0b101)
                baseVal = R[baseBits];
            if (idxBits != 0b100)
            {
                indexVal = R[idxBits] << scaleBits;
            }

            ulong addr = baseVal + indexVal;
            if (modLocal == 0b01)
            {
                long disp8 = *(sbyte*)(address + offsLocal); offsLocal += 1;
                addr += (ulong)disp8;
            }
            else if (modLocal == 0b10)
            {
                int disp32 = *(int*)(address + offsLocal); offsLocal += 4;
                addr += (ulong)(long)disp32;
            }
            return addr;
        }

        ulong oldVal, newVal;
        long imm8;

        if (mod == 0b11)
        {
            imm8 = *(sbyte*)(address + offs++);
            ulong* dst = R + rm;
            oldVal = *dst;
            newVal = oldVal + (ulong)imm8;
            *dst = newVal;
            Log($"ADD R{rm}, {imm8}", offs);
        }
        else
        {
            if (mod == 0b00)
            {
                if (rm == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else memAddr = R[rm];
            }
            else if (mod == 0b01)
            {
                if (rm == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else
                {
                    long disp8 = *(sbyte*)(address + offs++);
                    memAddr = R[rm] + (ulong)disp8;
                }
            }
            else if (mod == 0b10)
            {
                if (rm == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = R[rm] + (ulong)(long)disp32;
                }
            }

            imm8 = *(sbyte*)(address + offs++);
            oldVal = *(ulong*)memAddr;
            newVal = oldVal + (ulong)imm8;
            *(ulong*)memAddr = newVal;
            Log($"ADD QWORD PTR [0x{memAddr:X}], {imm8}", offs);
        }

        // ---- Update Flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        ulong result = newVal;
        if (result < oldVal) f |= CF;
        if (((oldVal ^ (ulong)imm8) & (oldVal ^ result) & 0x8000_0000_0000_0000UL) != 0) f |= OF;
        if (((oldVal ^ (ulong)imm8 ^ result) & 0x10) != 0) f |= AF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000_0000_0000_0000UL) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF;

        ctx->EFlags = f;
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleGrp1_EdIb(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Encoding family: 83 /digit r/m32, imm8
        // /0 ADD, /1 OR, /2 ADC, /3 SBB, /4 AND, /5 SUB, /6 XOR, /7 CMP

        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++];

        // Opcode must be 0x83
        if (address[offs++] != 0x83)
            return false;

        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool X = (rex & 0x02) != 0; // extends SIB.index
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m (and SIB.base)

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int grp = (modrm >> 3) & 7;
        int rm = (modrm & 7) | (B ? 8 : 0);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);

        ulong* R64 = &ctx->Rax;
        ulong rip0 = ctx->Rip; // RIP at start of instruction

        bool regDirect = (mod == 0b11);

        // Effective address calculation (SIB + disp + RIP-relative)
        ulong ea = 0;
        string memDesc = string.Empty;
        bool usedRipRel = false;

        if (!regDirect)
        {
            bool usesSib = ((modrm & 7) == 0b100);
            if (mod == 0b00 && ((modrm & 7) == 0b101))
            {
                // RIP-relative: disp32 + RIP_after_disp32
                int disp32 = *(int*)(address + offs); offs += 4;
                ulong ripAfter = rip0 + (ulong)(offs); // offs now points after disp32
                ea = ripAfter + (ulong)(long)disp32;
                usedRipRel = true;
                memDesc = disp32 >= 0
                    ? $"DWORD PTR [RIP+0x{(uint)disp32:X}]"
                    : $"DWORD PTR [RIP-0x{(uint)(-disp32):X}]";
            }
            else
            {
                ulong baseVal = 0, indexVal = 0;
                if (usesSib)
                {
                    byte sib = address[offs++];
                    int scale = (sib >> 6) & 3;
                    int idx = ((sib >> 3) & 7) | (X ? 8 : 0);
                    int bas = (sib & 7) | (B ? 8 : 0);

                    // Index "none" when idx == 4 and REX.X == 0
                    bool indexNone = (((sib >> 3) & 7) == 0b100) && !X;
                    if (!indexNone)
                        indexVal = R64[idx] << scale;

                    // Base “none” when mod==00 and base==101 (disp32 addressing)
                    bool baseIsDisp32 = (mod == 0b00) && ((sib & 7) == 0b101);
                    if (!baseIsDisp32)
                        baseVal = R64[bas];

                    ea = baseVal + indexVal;

                    if (mod == 0b01)
                    {
                        long d8 = *(sbyte*)(address + offs); offs += 1;
                        ea += (ulong)d8;
                    }
                    else if (mod == 0b10)
                    {
                        int d32 = *(int*)(address + offs); offs += 4;
                        ea += (ulong)(long)d32;
                    }
                    else if (baseIsDisp32)
                    {
                        int d32 = *(int*)(address + offs); offs += 4;
                        ea = (ulong)(long)d32; // absolute disp32 (no RIP-rel here)
                    }
                }
                else
                {
                    ea = R64[rm];
                    if (mod == 0b01)
                    {
                        long d8 = *(sbyte*)(address + offs); offs += 1;
                        ea += (ulong)d8;
                    }
                    else if (mod == 0b10)
                    {
                        int d32 = *(int*)(address + offs); offs += 4;
                        ea += (ulong)(long)d32;
                    }
                }

                // Fallback description: resolved absolute address
                if (string.IsNullOrEmpty(memDesc))
                    memDesc = $"DWORD PTR [0x{ea:X}]";
            }
        }

        // imm8 (sign-extended)
        sbyte imm8s = *(sbyte*)(address + offs++);
        uint imm32 = (uint)(int)imm8s; // 8→32 sign extension

        // Destination view (r/m32 as uint)
        uint* dst32 = regDirect ? (uint*)(R64 + rm) : (uint*)ea;
        uint lhs = *dst32;
        uint res = 0;

        // EFLAGS bits
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags;

        // Helpers (keep AF undefined for logic ops by not touching it there)
        void SetLogic(uint r)
        {
            f &= ~(CF | OF | ZF | SF | PF);
            if (r == 0) f |= ZF;
            if ((r & 0x80000000) != 0) f |= SF;
            if ((System.Numerics.BitOperations.PopCount((byte)r) & 1) == 0) f |= PF;
        }

        void SetAdd(uint a, uint b, int cin, uint r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            ulong ua = a, ub = (ulong)b + (uint)cin;
            if (ua + ub > 0xFFFFFFFFUL) f |= CF;
            if (((a ^ r) & (b ^ r) & 0x80000000) != 0) f |= OF;
            if ((((a & 0xF) + (b & 0xF) + (uint)cin) & 0x10) != 0) f |= AF; // fixed precedence
            if (r == 0) f |= ZF;
            if ((r & 0x80000000) != 0) f |= SF;
            if ((System.Numerics.BitOperations.PopCount((byte)r) & 1) == 0) f |= PF;
        }

        void SetSub(uint a, uint b, int bin, uint r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ub = b + (uint)bin;
            if (a < ub) f |= CF;
            if (((a ^ b) & (a ^ r) & 0x80000000) != 0) f |= OF;
            if ((~(a ^ b) & (a ^ r) & 0x10) != 0) f |= AF;
            if (r == 0) f |= ZF;
            if ((r & 0x80000000) != 0) f |= SF;
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

        string dstName = regDirect ? $"R{rm}d"
                                   : (usedRipRel ? memDesc : $"DWORD PTR [0x{ea:X}]");

        // Execute
        switch (grp)
        {
            case 0: // ADD
                res = lhs + imm32;
                SetAdd(lhs, imm32, 0, res);
                if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res; // zero-extend on reg
                break;

            case 1: // OR
                res = lhs | imm32;
                SetLogic(res);
                if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                break;

            case 2: // ADC
                {
                    int c = (f & CF) != 0 ? 1 : 0; // use incoming CF
                    uint addend = imm32 + (uint)c;
                    res = lhs + addend;
                    SetAdd(lhs, imm32, c, res);
                    if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                    break;
                }

            case 3: // SBB
                {
                    int b = (f & CF) != 0 ? 1 : 0; // incoming borrow = CF
                    uint subtrahend = imm32 + (uint)b;
                    res = lhs - subtrahend;
                    SetSub(lhs, imm32, b, res);
                    if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                    break;
                }

            case 4: // AND
                res = lhs & imm32;
                SetLogic(res);
                if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                break;

            case 5: // SUB
                res = lhs - imm32;
                SetSub(lhs, imm32, 0, res);
                if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                break;

            case 6: // XOR
                res = lhs ^ imm32;
                SetLogic(res);
                if (regDirect) R64[rm] = (ulong)res; else *(uint*)ea = res;
                break;

            case 7: // CMP
                res = lhs - imm32;
                SetSub(lhs, imm32, 0, res);
                // no writeback
                break;

            default:
                Log($"Unsupported 83 /{grp}", offs);
                return false;
        }

        ctx->EFlags = f;

        // Log: show signed imm8 and its 32-bit sign-extended form
        string immLog = $"{(int)imm8s} (0x{imm32:X8})";
        Log($"{mnem} {dstName}, {immLog}", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleIncDecRm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // FE /0 INC r/m8
        // FE /1 DEC r/m8
        int offs = 0;

        // Handle optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++]; // consume REX

        if (address[offs++] != 0xFE)
            return false;

        bool B = (rex & 0x01) != 0;

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int regop = (modrm >> 3) & 7;
        int rm = (modrm & 7) | (B ? 8 : 0);

        if (regop != 0 && regop != 1)
        {
            Log($"Unsupported FE /{regop}", offs);
            return false;
        }

        ulong* R = &ctx->Rax;
        ulong addr = 0;
        byte* dstPtr;

        if (mod == 0b11)
        {
            // Register form (low 8 bits)
            dstPtr = (byte*)(R + rm);
        }
        else
        {
            // Memory form: simple [reg] + optional displacement
            addr = R[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(address + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(address + offs); offs += 4;
                addr += (ulong)(long)d32;
            }
            dstPtr = (byte*)addr;
        }

        byte oldVal = *dstPtr;
        byte newVal = (byte)(regop == 0 ? oldVal + 1 : oldVal - 1);
        *dstPtr = newVal;

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags;

        // CF not affected
        f &= ~(ZF | SF | PF | OF | AF);

        // ZF/SF/PF
        if (newVal == 0) f |= ZF;
        if ((newVal & 0x80) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)newVal) & 1) == 0) f |= PF;

        // AF
        if (((oldVal ^ newVal) & 0x10) != 0) f |= AF;

        // OF
        if (regop == 0 && oldVal == 0x7F) f |= OF; // INC overflow
        if (regop == 1 && oldVal == 0x80) f |= OF; // DEC overflow

        ctx->EFlags = f;

        string opName = regop == 0 ? "INC" : "DEC";
        string dest = mod == 0b11 ? $"R{rm}b" : $"BYTE PTR [0x{addr:X}]";

        Log($"{opName} {dest} => 0x{oldVal:X2}->0x{newVal:X2} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, OF={(f & OF) != 0}, AF={(f & AF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleTestRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 84 /r  →  TEST r/m8, r8
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++];

        if (address[offs++] != 0x84)
            return false;

        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool hasREX = rex != 0;

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);
        int rm = (modrm & 7) | (B ? 8 : 0);

        ulong* R64 = &ctx->Rax;

        byte src, dst;
        ulong addr = 0;

        // Operand resolution
        if (mod == 0b11)
        {
            // Register form
            dst = (byte)(R64[rm] & 0xFF);
            src = (byte)(R64[reg] & 0xFF);
        }
        else
        {
            // Memory form with optional disp
            addr = R64[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(address + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(address + offs); offs += 4;
                addr += (ulong)(long)d32;
            }

            dst = *(byte*)addr;
            src = (byte)(R64[reg] & 0xFF);
        }

        // ---- Logical AND (no store) ----
        byte res = (byte)(dst & src);

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (res == 0) f |= ZF;
        if ((res & 0x80) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)res) & 1) == 0) f |= PF; // even parity

        ctx->EFlags = f;

        // Logging
        string srcDesc = $"R{reg}b";
        string dstDesc = mod == 0b11 ? $"R{rm}b" : $"BYTE PTR [0x{addr:X}]";
        Log($"TEST {dstDesc}, {srcDesc} => (0x{dst:X2} & 0x{src:X2}) = 0x{res:X2} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleAddRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 00 /r → ADD r/m8, r8
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++];

        if (address[offs++] != 0x00)
            return false;

        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);
        int rm = (modrm & 7) | (B ? 8 : 0);

        ulong* R64 = &ctx->Rax;
        ulong memAddr = 0;
        byte* destPtr;

        // Effective address resolution
        if (mod == 0b11)
        {
            destPtr = (byte*)(R64 + rm);
        }
        else
        {
            if (mod == 0b00)
            {
                if (rm == 0b101)
                {
                    // RIP-relative
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
                }
                else if (rm == 0b100)
                {
                    byte sib = *(address + offs++);
                    byte scale = (byte)((sib >> 6) & 3);
                    int idx = ((sib >> 3) & 7);
                    int bas = (sib & 7);
                    ulong baseVal = (bas == 0b101) ? 0 : R64[bas];
                    ulong indexVal = (idx == 0b100) ? 0 : (R64[idx] << scale);
                    memAddr = baseVal + indexVal;
                }
                else
                {
                    memAddr = R64[rm];
                }
            }
            else
            {
                long disp = (mod == 0b01)
                    ? *(sbyte*)(address + offs)
                    : *(int*)(address + offs);
                offs += (mod == 0b01) ? 1 : 4;
                memAddr = R64[rm] + (ulong)disp;
            }
            destPtr = (byte*)memAddr;
        }

        // Fetch operands
        byte src = (byte)(R64[reg] & 0xFF);
        byte dest = *destPtr;
        byte result = (byte)(dest + src);
        *destPtr = result;

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if ((ushort)(dest + src) > 0xFF) f |= CF;
        if (((dest ^ result) & (src ^ result) & 0x80) != 0) f |= OF;
        if ((((dest & 0xF) + (src & 0xF)) & 0x10) != 0) f |= AF;
        if (result == 0) f |= ZF;
        if ((result & 0x80) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount(result) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        string dstDesc = mod == 0b11 ? $"R{rm}b" : $"BYTE PTR [0x{memAddr:X}]";
        Log($"ADD {dstDesc}, R{reg}b => 0x{dest:X2}+0x{src:X2}=0x{result:X2} "
            + $"[CF={(f & CF) != 0}, ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, OF={(f & OF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleTestRm32R32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 85 /r → TEST r/m32, r32
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++];

        if (address[offs++] != 0x85)
            return false;

        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);
        int rm = (modrm & 7) | (B ? 8 : 0);

        ulong* R64 = &ctx->Rax;
        uint src = (uint)R64[reg]; // r32 operand
        uint val;
        ulong memAddr = 0;

        if (mod == 0b11)
        {
            val = (uint)R64[rm];
        }
        else
        {
            // Compute effective address (simple version; no SIB)
            memAddr = R64[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(address + offs); offs += 1;
                memAddr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(address + offs); offs += 4;
                memAddr += (ulong)(long)d32;
            }
            else if (mod == 0b00 && rm == 0b101)
            {
                // RIP-relative
                int disp32 = *(int*)(address + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }

            val = *(uint*)memAddr;
        }

        uint res = val & src;

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (res == 0) f |= ZF;
        if ((res & 0x80000000) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)res) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        string dstDesc = mod == 0b11 ? $"R{rm}d" : $"DWORD PTR [0x{memAddr:X}]";
        Log($"TEST {dstDesc}, R{reg}d => (0x{val:X8} & 0x{src:X8}) = 0x{res:X8} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleAddGvEv(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 03 /r → ADD r64, r/m64
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        if (ip[offs++] != 0x03)
            return false;

        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool W = (rex & 0x08) != 0; // 1 = 64-bit op (we assume yes)

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);
        int rm = (modrm & 7) | (B ? 8 : 0);

        ulong* R64 = &ctx->Rax;
        ulong srcVal;
        ulong memAddr = 0;

        // ---- resolve r/m operand ----
        if (mod == 0b11)
        {
            srcVal = R64[rm];
        }
        else
        {
            if (mod == 0b00 && rm == 0b101)
            {
                // RIP-relative
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
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
            srcVal = *(ulong*)memAddr;
        }

        ulong dstVal = R64[reg];
        ulong result = dstVal + srcVal;

        // ---- update destination ----
        R64[reg] = result;

        // ---- update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4,
                   ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (result < dstVal) f |= CF; // carry
        if (((dstVal ^ result) & (srcVal ^ result) & 0x8000_0000_0000_0000UL) != 0) f |= OF;
        if ((((dstVal & 0xF) + (srcVal & 0xF)) & 0x10) != 0) f |= AF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000_0000_0000_0000UL) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        // ---- log ----
        string srcDesc = mod == 0b11 ? $"R{rm}" : $"QWORD PTR [0x{memAddr:X}]";
        Log($"ADD R{reg}, {srcDesc} => 0x{dstVal:X}+0x{srcVal:X}=0x{result:X} "
            + $"[CF={(f & CF) != 0}, ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, OF={(f & OF) != 0}, PF={(f & PF) != 0}, AF={(f & AF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleXorRvEv(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 31 /r  →  XOR r/m64, r64   (REX.W=1 for 64-bit)
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++];

        if (address[offs++] != 0x31)   // opcode
            return false;

        bool R = (rex & 0x04) != 0;   // ModRM.reg extension
        bool B = (rex & 0x01) != 0;   // ModRM.r/m extension

        byte modrm = address[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = ((modrm >> 3) & 7) | (R ? 8 : 0);
        int rm = (modrm & 7) | (B ? 8 : 0);

        ulong* R64 = &ctx->Rax;
        ulong src = R64[reg];
        ulong dst;
        ulong addr = 0;

        if (mod == 0b11)
        {
            dst = R64[rm];
        }
        else
        {
            // basic memory EA decode: [reg] + disp8/disp32 + RIP-rel (optional)
            addr = R64[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(address + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(address + offs); offs += 4;
                addr += (ulong)(long)d32;
            }
            else if (mod == 0b00 && rm == 0b101)
            {
                int disp32 = *(int*)(address + offs); offs += 4;
                addr = ctx->Rip + (ulong)offs + (ulong)(long)disp32; // RIP-relative
            }
            dst = *(ulong*)addr;
        }

        ulong result = dst ^ src;

        // write back (no memory destination here; we write to r/m when mod==11)
        if (mod == 0b11)
            R64[rm] = result;
        else
            *(ulong*)addr = result;

        // ---- flag updates (CF=OF=0, ZF/SF/PF set) ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4,
                   ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~(CF | PF | AF | ZF | SF | OF);

        if (result == 0) f |= ZF;
        if ((result & 0x8000_0000_0000_0000UL) != 0) f |= SF;
        if ((System.Numerics.BitOperations.PopCount((byte)result) & 1) == 0) f |= PF;

        ctx->EFlags = f;

        string srcDesc = $"R{reg}";
        string dstDesc = mod == 0b11 ? $"R{rm}" : $"QWORD PTR [0x{addr:X}]";
        Log($"XOR {dstDesc}, {srcDesc} => result=0x{result:X} "
            + $"[ZF={(f & ZF) != 0}, SF={(f & SF) != 0}, PF={(f & PF) != 0}]", offs);

        ctx->Rip += (ulong)offs;
        return true;
    }

}