using static ConsoleApp1.X64Emulator;

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
        if (ip[0] != 0x66 || ip[1] != 0x85) return false;

        byte modrm = ip[2];
        byte mod = (byte)(modrm >> 6 & 0x3);
        int reg = modrm >> 3 & 0x7;
        int rm = modrm & 0x7;
        int len = 3;

        ushort lhs, rhs;

        // We only need the AX/word forms used here, but implement the general /r form:
        if (mod == 0b11)
        {
            lhs = (ushort)((&ctx->Rax)[rm] & 0xFFFF);
            rhs = (ushort)((&ctx->Rax)[reg] & 0xFFFF);
            Log($"TEST R{rm}w, R{reg}w", len);
        }
        else
        {
            ulong addr = (&ctx->Rax)[rm];
            lhs = *(ushort*)addr;
            rhs = (ushort)((&ctx->Rax)[reg] & 0xFFFF);
            Log($"TEST WORD PTR [0x{addr:X}], R{reg}w", len);
        }

        uint res = (uint)(lhs & rhs);

        // Update flags: ZF, SF, PF; clear CF/OF for TEST
        // (assuming you store flags in EFlags like Windows CONTEXT does)
        const uint CF = 1 << 0, PF = 1 << 2, ZF = 1 << 6, SF = 1 << 7, OF = 1 << 11;
        uint f = ctx->EFlags;
        f &= ~(CF | OF | ZF | SF | PF);

        if ((res & 0xFFFF) == 0) f |= ZF;
        if ((res >> 15 & 1) != 0) f |= SF;

        // Simple parity of low byte:
        byte low = (byte)(res & 0xFF);
        bool parity = (System.Numerics.BitOperations.PopCount(low) & 1) == 0;
        if (parity) f |= PF;

        ctx->EFlags = f;
        ctx->Rip += (ulong)len;
        return true;
    }
    private static bool HandleAddRm64Imm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 48 83 /0 r/m64, imm8  (ADD)
        byte modrm = *(address + 2);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);
        if (reg != 0)
        {
            Log($"Unsupported 48 83 /{reg} form (only /0=ADD)", 3);
            return false;
        }

        int offs = 3; // start at ModRM
        ulong memAddr = 0;

        // helper for SIB forms
        ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
        {
            byte scaleBits = (byte)(sib >> 6 & 0x3);
            byte idxBits = (byte)(sib >> 3 & 0x7);
            byte baseBits = (byte)(sib & 0x7);

            ulong baseVal = 0, indexVal = 0;
            if (baseBits != 0b101)
                baseVal = *(&ctx->Rax + baseBits);
            if (idxBits != 0b100)
            {
                indexVal = *(&ctx->Rax + idxBits);
                indexVal <<= scaleBits;
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

        if (mod == 0b11)
        {
            // register form, e.g. ADD RAX, imm8
            byte imm8 = *(address + offs++);
            ulong* dst = &ctx->Rax + rm;
            ulong old = *dst;
            *dst = old + imm8;
            Log($"ADD R{rm}, 0x{imm8:X2} => 0x{old:X}+0x{imm8:X}=0x{*dst:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
        else
        {
            // memory form
            if (mod == 0b00)
            {
                if (rm == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else
                {
                    memAddr = *(&ctx->Rax + rm);
                }
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
                    memAddr = *(&ctx->Rax + rm) + (ulong)disp8;
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
                    memAddr = *(&ctx->Rax + rm) + (ulong)(long)disp32;
                }
            }

            byte imm8 = *(address + offs++);
            ulong oldVal = *(ulong*)memAddr;
            ulong newVal = oldVal + imm8;
            *(ulong*)memAddr = newVal;

            Log($"ADD QWORD PTR [0x{memAddr:X}], 0x{imm8:X2} => 0x{oldVal:X}+0x{imm8:X}=0x{newVal:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
    }
    private static unsafe bool HandleGrp1_EdIb(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Encoding: 83 /digit r/m32, imm8
        // /0 ADD, /1 OR, /2 ADC, /3 SBB, /4 AND, /5 SUB, /6 XOR, /7 CMP
        int offs = 1;
        byte modrm = *(address + offs++);
        byte mod = (byte)(modrm >> 6 & 3);
        int grp = modrm >> 3 & 7;
        int rm = modrm & 7;

        bool regDirect = mod == 0b11;
        ulong memAddr = 0;

        // memory addressing (basic forms, same as your MOV handler)
        if (!regDirect)
        {
            if (mod == 0b00)
                memAddr = *(&ctx->Rax + rm);
            else if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(address + offs++);
                memAddr = *(&ctx->Rax + rm) + (ulong)disp8;
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(address + offs);
                offs += 4;
                memAddr = *(&ctx->Rax + rm) + (ulong)(long)disp32;
            }
        }

        sbyte imm8s = *(sbyte*)(address + offs++);
        uint imm32 = (uint)(int)imm8s; // sign-extended 8→32

        uint* dst32 = regDirect ? (uint*)(&ctx->Rax + rm) : (uint*)memAddr;
        uint lhs = *dst32, res = 0;

        const uint CF = 1, PF = 1 << 2, AF = 1 << 4, ZF = 1 << 6, SF = 1 << 7, OF = 1 << 11;
        uint f = ctx->EFlags;

        void SetLogic(uint r)
        {
            f &= ~(CF | OF | ZF | SF | PF);
            if (r == 0) f |= ZF;
            if ((r & 0x80000000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
        }
        void SetAdd(uint a, uint b, int cin, uint r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            ulong ua = a, ub = b + (ulong)cin;
            if (ua + ub > 0xFFFFFFFF) f |= CF;
            if (((a ^ r) & (b ^ r) & 0x80000000) != 0) f |= OF;
            if (((a & 0xF) + (b & 0xF) + (uint)cin & 0x10) != 0) f |= AF;
            if (r == 0) f |= ZF;
            if ((r & 0x80000000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
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
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount(lo) & 1) == 0) f |= PF;
        }

        string mnem = grp switch { 0 => "ADD", 1 => "OR", 2 => "ADC", 3 => "SBB", 4 => "AND", 5 => "SUB", 6 => "XOR", 7 => "CMP", _ => "???" };
        string dstName = regDirect ? $"R{rm}d" : $"DWORD PTR [0x{memAddr:X}]";

        switch (grp)
        {
            case 0: res = lhs + imm32; SetAdd(lhs, imm32, 0, res); *dst32 = res; break;
            case 1: res = lhs | imm32; SetLogic(res); *dst32 = res; break;
            case 2: { int c = (f & CF) != 0 ? 1 : 0; res = lhs + (uint)(imm32 + c); SetAdd(lhs, imm32, c, res); *dst32 = res; } break;
            case 3: { int b = (f & CF) != 0 ? 1 : 0; res = lhs - (uint)(imm32 + b); SetSub(lhs, imm32, b, res); *dst32 = res; } break;
            case 4: res = lhs & imm32; SetLogic(res); *dst32 = res; break;
            case 5: res = lhs - imm32; SetSub(lhs, imm32, 0, res); *dst32 = res; break;
            case 6: res = lhs ^ imm32; SetLogic(res); *dst32 = res; break;
            case 7: res = lhs - imm32; SetSub(lhs, imm32, 0, res); break; // CMP
            default: Log($"Unsupported 83 /{grp}", offs); return false;
        }

        ctx->EFlags = f;
        Log($"{mnem} {dstName}, 0x{imm32:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleIncDecRm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // FE /0 INC r/m8
        // FE /1 DEC r/m8
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        int regop = modrm >> 3 & 0x7; // /digit selects op
        int rm = modrm & 0x7;
        int offs = 2;

        if (regop != 0 && regop != 1)
        {
            Log($"Unsupported FE /{regop}", offs);
            return false;
        }

        // Get operand location
        ulong addr = 0;
        byte* dstPtr;
        if (mod == 0b11)
        {
            dstPtr = (byte*)(&ctx->Rax + rm);
        }
        else
        {
            // Simple [reg] only for now
            addr = *(&ctx->Rax + rm);
            dstPtr = (byte*)addr;
        }

        byte oldVal = *dstPtr;
        byte newVal;
        if (regop == 0) newVal = (byte)(oldVal + 1); // INC
        else newVal = (byte)(oldVal - 1); // DEC
        *dstPtr = newVal;

        // Update flags (Intel rules)
        uint f = ctx->EFlags;
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        // CF not affected
        f &= ~(ZF | SF | PF | OF | AF);
        if (newVal == 0) f |= ZF;
        if ((newVal & 0x80) != 0) f |= SF;
        byte low = (byte)(newVal & 0xFF);
        if ((System.Numerics.BitOperations.PopCount(low) & 1) == 0) f |= PF;
        // OF = set if signed overflow (old==0x7F for INC, 0x80 for DEC)
        if (regop == 0 && oldVal == 0x7F) f |= OF;
        if (regop == 1 && oldVal == 0x80) f |= OF;
        ctx->EFlags = f;

        string opName = regop == 0 ? "INC" : "DEC";
        string dest = mod == 0b11 ? $"R{rm}b" : $"BYTE PTR [0x{addr:X}]";
        Log($"{opName} {dest} => 0x{oldVal:X2}->0x{newVal:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleTestRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // TEST r/m8, r8  => bitwise AND but no result stored
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);
        int offs = 2;

        byte src, dst;

        if (mod == 0b11)
        {
            src = (byte)((&ctx->Rax)[reg] & 0xFF);
            dst = (byte)((&ctx->Rax)[rm] & 0xFF);
        }
        else
        {
            ulong memAddr = *(&ctx->Rax + rm);
            dst = *(byte*)memAddr;
            src = (byte)((&ctx->Rax)[reg] & 0xFF);
        }

        byte res = (byte)(src & dst);
        bool zf = res == 0;
        bool sf = (res & 0x80) != 0;

        ctx->EFlags = ctx->EFlags & ~0xC0u |
                             (zf ? 0x40u : 0u) |
                             (sf ? 0x80u : 0u);

        Log($"TEST r/m8, r8 => (0x{dst:X2} & 0x{src:X2}) => ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleAddRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);
        int offs = 2;
        ulong memAddr = 0;
        byte* destPtr = null;
        if (mod == 0b11)
        {
            destPtr = (byte*)(&ctx->Rax + rm);
        }
        else
        {
            switch (mod)
            {
                case 0b00:
                    if (rm == 0b101)
                    {
                        int disp32 = *(int*)(address + offs);
                        offs += 4;
                        memAddr = ctx->Rip + (ulong)disp32;
                    }
                    else if (rm == 0b100)
                    {
                        byte sib = *(address + offs++);
                        byte scale = (byte)(sib >> 6 & 0x3);
                        byte index = (byte)(sib >> 3 & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        ulong baseVal = baseReg == 0b101 ? 0 : *(&ctx->Rax + baseReg);
                        ulong indexVal = index == 0b100 ? 0 : *(&ctx->Rax + index) << scale;
                        int disp32 = baseReg == 0b101 ? *(int*)(address + offs) : 0;
                        offs += baseReg == 0b101 ? 4 : 0;
                        memAddr = baseVal + indexVal + (ulong)disp32;
                    }
                    else
                    {
                        memAddr = *(&ctx->Rax + rm);
                    }
                    destPtr = (byte*)memAddr;
                    break;
                case 0b01:
                case 0b10:
                    {
                        int dispSize = mod == 0b01 ? 1 : 4;
                        long disp = dispSize == 1
                            ? *(sbyte*)(address + offs)
                            : *(int*)(address + offs);
                        offs += dispSize;
                        ulong baseVal = *(&ctx->Rax + rm);
                        memAddr = baseVal + (ulong)disp;
                        destPtr = (byte*)memAddr;
                    }
                    break;
                default:
                    Log($"Unsupported ADD ModRM 0x{modrm:X2}", 2);
                    return false;
            }
        }
        byte* srcPtr = (byte*)(&ctx->Rax + reg);
        byte src = *srcPtr;
        byte dest = *destPtr;
        byte result = (byte)(dest + src);
        *destPtr = result;
        bool zf = result == 0;
        bool sf = (result & 0x80) != 0;
        ctx->EFlags = (uint)(ctx->EFlags & ~0x85 | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));
        Log($"ADD r/m8, r8 => [0x{(ulong)destPtr:X}]=0x{result:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleTestRm32R32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        int offs = 1;
        byte modrm = *(address + offs++);
        byte mod = (byte)(modrm >> 6 & 0x3);
        int reg = modrm >> 3 & 0x7;
        int rm = modrm & 0x7;

        uint src = ((uint*)&ctx->Rax)[reg];
        uint val;

        if (mod == 0b11)
        {
            val = ((uint*)&ctx->Rax)[rm];
        }
        else
        {
            ulong memAddr = *(&ctx->Rax + rm);
            if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
            else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
            val = *(uint*)memAddr;
        }

        uint res = val & src;
        bool zf = res == 0;
        bool sf = (res & 0x80000000u) != 0;
        ctx->EFlags = ctx->EFlags & ~0xC0u | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u);

        Log($"TEST {(mod == 0b11 ? $"R{rm}d" : "r/m32")}, R{reg}d => ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleAddGvEv(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        int offs = 1; // opcode 0x03
        byte modrm = *(ip + offs++);
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // destination
        int rm = modrm & 7;         // source
        ulong* R = &ctx->Rax;

        ulong value;
        if (mod == 0b11)
        {
            // Register to register
            value = R[reg] + R[rm];
            Log($"ADD R{reg}, R{rm} => 0x{R[reg]:X}+0x{R[rm]:X}=0x{value:X}", offs);
        }
        else
        {
            // Memory source: [Rm] + possible displacement
            ulong addr = R[rm];
            if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(ip + offs++);
                addr = (ulong)((long)addr + disp8);
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                addr = (ulong)((long)addr + disp32);
            }

            value = R[reg] + *(ulong*)addr;
            Log($"ADD R{reg}, [0x{addr:X}] => 0x{R[reg]:X}+0x{*(ulong*)addr:X}=0x{value:X}", offs);
        }

        R[reg] = value;
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleXorRvEv(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 3);
        byte reg = (byte)(modrm >> 3 & 7);
        byte rm = (byte)(modrm & 7);
        ulong value;

        if (mod == 0b11)
        {
            // Register to register
            ulong src = (&ctx->Rax)[rm];
            ulong dst = (&ctx->Rax)[reg];
            value = dst ^ src;
            (&ctx->Rax)[reg] = value;
            Log($"XOR R{reg}, R{rm}", 2);
        }
        else
        {
            // Memory form (simplified)
            ulong addr = (&ctx->Rax)[rm];
            uint src = *(uint*)addr;
            uint dst = (uint)(&ctx->Rax)[reg];
            (&ctx->Rax)[reg] = dst ^ src;
            Log($"XOR R{reg}, [0x{addr:X}]", 2);
        }

        ctx->Rip += 2;
        return true;
    }
}