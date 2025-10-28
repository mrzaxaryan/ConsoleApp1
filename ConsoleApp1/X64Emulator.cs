using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public static unsafe class X64Emulator
{
    public static bool Emulate(ref EXCEPTION_POINTERS exceptionInfo, byte* address)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        var before = RegSnapshot.FromContext(ctx);

        void Log(string mnemonic, int instrLen)
        {
            string bytes = FormatBytes(address, instrLen);
            string instrAddr = $"0x{before.Rip:X}";
            var afterSnap = RegSnapshot.FromContext(ctx);
            string diff = FormatRegisterDiff(before, afterSnap);
            string log = $"[{instrAddr}] [{bytes}] {mnemonic} | {(diff.Length > 0 ? " => " + diff : "")}";
            Console.WriteLine(log);
            File.AppendAllText("emulator_log.txt", log + Environment.NewLine);
        }

        byte opcode = *address;
        bool result = false;

        // --------------------------------
        // Two-byte opcode prefix (0x0F)
        // --------------------------------
        if (opcode == X64Opcodes.TWO_BYTE)
        {
            byte op2 = *(address + 1);
            switch (op2)
            {
                case X64Opcodes.JNE_NEAR: return HandleJneNear(ctx, address, Log);
                case X64Opcodes.JE_NEAR: return HandleJeNear(ctx, address, Log);
                case X64Opcodes.MOVZX_GvEw: return HandleMovzxGvEw(ctx, address, Log);
                case X64Opcodes.MOVZX_R32_RM8: return HandleMovzxR32Rm8(ctx, address, Log);
                case X64Opcodes.SETE: return HandleSetcc(ctx, address, Log, condition: "ZF");
                default:
                    Log($"Unsupported two-byte opcode 0F {op2:X2}", 8);
                    throw new NotImplementedException($"0F {op2:X2} not implemented");
            }
        }

        // --------------------------------
        // Complex instruction patterns
        // --------------------------------
        if (opcode == X64Opcodes.REX_PREFIX && *(address + 1) == 0x83 && *(address + 2) == 0xAC && *(address + 3) == 0x24)
            return Sub.Handle(ctx, address, Log);

        if (opcode == X64Opcodes.REX_PREFIX && *(address + 1) == 0x83 && (*(address + 2) & 0x38) == 0x00)
            return HandleAddRm64Imm8(ctx, address, Log);

        if (opcode == X64Opcodes.GS_PREFIX)
            return HandleSegmentPrefix(ctx, address, Log);

        if (opcode == X64Opcodes.OPSIZE_PREFIX)
            return HandleOperandSizePrefix(ctx, address, Log);

        // --------------------------------
        // Conditional short jumps (0x70–0x7F)
        // --------------------------------
        if (opcode >= X64Opcodes.JO_SHORT && opcode <= X64Opcodes.JG_SHORT)
            return HandleShortConditionalJump(ctx, address, Log);

        // --------------------------------
        // Primary opcode dispatch
        // --------------------------------
        switch (opcode)
        {
            // Stack operations
            case X64Opcodes.PUSH_RBP: result = HandlePushRbp(ctx, Log); break;
            case X64Opcodes.PUSH_RDI: result = HandlePushRdi(ctx, Log); break;
            case X64Opcodes.PUSH_RSI: result = HandlePushRsi(ctx, Log); break;
            case X64Opcodes.PUSH_RBX: result = HandlePushRbx(ctx, Log); break;

            case X64Opcodes.POP_RAX:
            case X64Opcodes.POP_RCX:
            case X64Opcodes.POP_RDX:
            case X64Opcodes.POP_RBX:
            case X64Opcodes.POP_RSP:
            case X64Opcodes.POP_RBP:
            case X64Opcodes.POP_RSI:
            case X64Opcodes.POP_RDI:
                result = HandlePopReg(ctx, *address, Log);
                break;

            // MOV family
            case X64Opcodes.MOV_RM64_R64: result = Mov.HandleMovRm64R64(ctx, address, Log); break;
            case X64Opcodes.MOV_RM32_IMM32: result = Mov.HandleMovRm32Imm32(ctx, address, Log); break;
            case X64Opcodes.MOV_R32_RM32: result = HandleMovR32Rm32(ctx, address, Log); break;
            case X64Opcodes.MOV_RM8_IMM8: result = HandleMovRm8Imm8(ctx, address, Log); break;
            case >= X64Opcodes.MOV_RAX_IMM64 and <= X64Opcodes.MOV_RDI_IMM64:
                result = HandleMovImmToReg_NoRex(ctx, address, Log); break;

            // Arithmetic / Logic
            case X64Opcodes.ADD_R32_RM32: result = HandleAddGvEv(ctx, address, Log); break;
            case X64Opcodes.XOR_R32_RM32: result = HandleXorRvEv(ctx, address, Log); break;
            case X64Opcodes.GRP1_EdIb: result = HandleGrp1_EdIb(ctx, address, Log); break;
            case X64Opcodes.ADD_RM8_R8: result = HandleAddRm8R8(ctx, address, Log); break;
            case X64Opcodes.TEST_RM8_R8: result = HandleTestRm8R8(ctx, address, Log); break;
            case X64Opcodes.TEST_RM32_R32: result = HandleTestRm32R32(ctx, address, Log); break;
            case X64Opcodes.INCDEC_RM8: result = HandleIncDecRm8(ctx, address, Log); break;

            // Control flow
            case X64Opcodes.CALL: result = HandleCall(ctx, address, Log); break;
            case X64Opcodes.RET: result = HandleRet(ctx, Log); break;
            case X64Opcodes.LEAVE: result = HandleLeave(ctx, Log); break;
            case X64Opcodes.JMP_NEAR: result = HandleJmpNear(ctx, address, Log); break;
            case X64Opcodes.JMP_SHORT: result = HandleJmpShort(ctx, address, Log); break;
            case X64Opcodes.JE_SHORT: result = HandleJeShort(ctx, address, Log); break;
            case X64Opcodes.JNE_SHORT: result = HandleJneShort(ctx, address, Log); break;
            case X64Opcodes.JBE_SHORT: result = HandleJbeShort(ctx, address, Log); break;
            case X64Opcodes.JA_SHORT: result = HandleJaShort(ctx, address, Log); break;

            // Misc
            case X64Opcodes.NOP: result = HandleNop(ctx, Log); break;
            case X64Opcodes.CMP_AL_IMM8: result = HandleCmpAlImm8(ctx, address, Log); break;
            case X64Opcodes.REX_PREFIX:
            case X64Opcodes.REX_B_GROUP:
            case X64Opcodes.REX_R_GROUP:
            case X64Opcodes.REX_W_GROUP:
                result = Rex.Handle(ctx, address, Log); break;

            // Default
            default:
                Log($"Unsupported opcode 0x{opcode:X2}", 32);
                result = false;
                break;
        }

        return result;
    }
    private static unsafe bool HandleAddGvEv(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        int offs = 1; // opcode 0x03
        byte modrm = *(ip + offs++);
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // destination
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

    private static unsafe bool HandleShortConditionalJump(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        byte opcode = *ip;        // 70..7F
        sbyte rel8 = *(sbyte*)(ip + 1);
        ulong nextRip = ctx->Rip + 2;
        ulong target = (ulong)((long)nextRip + rel8);

        bool take = false;
        ulong eflags = ctx->EFlags;

        bool CF = (eflags & 1) != 0;
        bool PF = (eflags & 4) != 0;
        bool ZF = (eflags & 0x40) != 0;
        bool SF = (eflags & 0x80) != 0;
        bool OF = (eflags & 0x800) != 0;

        switch (opcode)
        {
            case 0x70: take = OF; break;             // JO
            case 0x71: take = !OF; break;            // JNO
            case 0x72: take = CF; break;             // JB / JC / JNAE
            case 0x73: take = !CF; break;            // JNB / JAE / JNC
            case 0x74: take = ZF; break;             // JE / JZ
            case 0x75: take = !ZF; break;            // JNE / JNZ
            case 0x76: take = CF || ZF; break;       // JBE / JNA
            case 0x77: take = !CF && !ZF; break;     // JA / JNBE
            case 0x78: take = SF; break;             // JS
            case 0x79: take = !SF; break;            // JNS
            case 0x7A: take = PF; break;             // JP / JPE
            case 0x7B: take = !PF; break;            // JNP / JPO
            case 0x7C: take = SF != OF; break;       // JL / JNGE
            case 0x7D: take = SF == OF; break;       // JGE / JNL
            case 0x7E: take = ZF || (SF != OF); break; // JLE / JNG
            case 0x7F: take = !ZF && (SF == OF); break; // JG / JNLE
            default: Log($"Unhandled short jump opcode 0x{opcode:X2}", 2); return false;
        }

        if (take)
        {
            Log($"Jcc taken: 0x{ctx->Rip:X} -> 0x{target:X}", 2);
            ctx->Rip = target;
        }
        else
        {
            Log($"Jcc not taken (0x{opcode:X2}), RIP -> 0x{nextRip:X}", 2);
            ctx->Rip = nextRip;
        }

        return true;
    }

    private static unsafe bool HandleJmpNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // E9 cd cd cd cd   ; rel32 is SIGNED
        int rel32 = *(int*)(address + 1);
        ulong nextRip = ctx->Rip + 5;                       // length = 5 bytes
        ulong target = nextRip + (ulong)(long)rel32;       // sign-extend to 64-bit

        Log($"JMP near {rel32:+#;-#;0} -> 0x{target:X}", 5);
        ctx->Rip = target;
        return true;
    }
    private static unsafe bool HandleSetcc(CONTEXT* ctx, byte* ip, Action<string, int> Log, string condition)
    {
        // 0F 94 /r → SETZ r/m8
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // condition selector for other SETcc variants, not used here
        int rm = (modrm & 7);

        ulong* R = &ctx->Rax;

        // Determine condition result
        bool condMet = false;
        if (condition == "ZF") condMet = (ctx->EFlags & (1 << 6)) != 0; // Zero Flag

        byte value = condMet ? (byte)1 : (byte)0;
        string destDesc;

        if (mod == 0b11)
        {
            // register
            byte* dst = (byte*)(R + rm);
            *dst = value;
            destDesc = $"R{rm}b";
        }
        else
        {
            // simple [register] memory
            ulong addr = R[rm];
            *(byte*)addr = value;
            destDesc = $"BYTE PTR [0x{addr:X}]";
        }

        Log($"SETZ {destDesc} => {(condMet ? "1" : "0")}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleCmpEvGv16(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 66 39 /r  →  CMP r/m16, r16
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7;   // source (r16)
        int rm = (modrm & 7);        // destination (r/m16)
        ulong* R = &ctx->Rax;

        ushort lhs;   // left = r/m16 (destination)
        ushort rhs;   // right = r16  (source)
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
        uint f = ctx->EFlags & ~((uint)(CF | PF | AF | ZF | SF | OF));

        if (lhs < rhs) f |= CF;
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if ((((lhs ^ rhs) & (lhs ^ result)) & 0x8000) != 0) f |= OF;
        byte low = (byte)(result & 0xFF);
        if ((System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0)
            f |= PF;

        ctx->EFlags = f;

        Log($"CMP {lhsDesc}, {rhsDesc} => result=0x{result:X4} "
            + $"ZF={((f & ZF) != 0 ? 1 : 0)} SF={((f & SF) != 0 ? 1 : 0)} CF={((f & CF) != 0 ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleIncDecRm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // FE /0 INC r/m8
        // FE /1 DEC r/m8
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        int regop = (modrm >> 3) & 0x7; // /digit selects op
        int rm = (modrm & 0x7);
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
            dstPtr = (byte*)((&ctx->Rax) + rm);
        }
        else
        {
            // Simple [reg] only for now
            addr = *((&ctx->Rax) + rm);
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
        if ((System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0) f |= PF;
        // OF = set if signed overflow (old==0x7F for INC, 0x80 for DEC)
        if (regop == 0 && oldVal == 0x7F) f |= OF;
        if (regop == 1 && oldVal == 0x80) f |= OF;
        ctx->EFlags = f;

        string opName = (regop == 0) ? "INC" : "DEC";
        string dest = (mod == 0b11) ? $"R{rm}b" : $"BYTE PTR [0x{addr:X}]";
        Log($"{opName} {dest} => 0x{oldVal:X2}->0x{newVal:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleGrp1_EdIb(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Encoding: 83 /digit r/m32, imm8
        // /0 ADD, /1 OR, /2 ADC, /3 SBB, /4 AND, /5 SUB, /6 XOR, /7 CMP
        int offs = 1;
        byte modrm = *(address + offs++);
        byte mod = (byte)((modrm >> 6) & 3);
        int grp = (modrm >> 3) & 7;
        int rm = modrm & 7;

        bool regDirect = (mod == 0b11);
        ulong memAddr = 0;

        // memory addressing (basic forms, same as your MOV handler)
        if (!regDirect)
        {
            if (mod == 0b00)
                memAddr = *((&ctx->Rax) + rm);
            else if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(address + offs++);
                memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(address + offs);
                offs += 4;
                memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
            }
        }

        sbyte imm8s = *(sbyte*)(address + offs++);
        uint imm32 = (uint)(int)imm8s; // sign-extended 8→32

        uint* dst32 = regDirect ? (uint*)((&ctx->Rax) + rm) : (uint*)memAddr;
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
            ulong ua = a, ub = (ulong)b + (ulong)cin;
            if (ua + ub > 0xFFFFFFFF) f |= CF;
            if ((((a ^ r) & (b ^ r)) & 0x80000000) != 0) f |= OF;
            if ((((a & 0xF) + (b & 0xF) + (uint)cin) & 0x10) != 0) f |= AF;
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
            if ((((a ^ b) & (a ^ r)) & 0x80000000) != 0) f |= OF;
            if ((((~(a ^ b)) & (a ^ r)) & 0x10) != 0) f |= AF;
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

    private static bool HandleJaShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0x77 rel8  — Jump if Above (unsigned), i.e., CF==0 && ZF==0
        sbyte rel8 = *(sbyte*)(address + 1);
        bool cf = (ctx->EFlags & 0x01) != 0;
        bool zf = (ctx->EFlags & 0x40) != 0;

        ulong nextRip = ctx->Rip + 2;
        ulong target = (ulong)((long)nextRip + rel8);
        bool taken = !cf && !zf;

        Log($"JA short 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 2);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    private static unsafe bool HandleTestRmR(CONTEXT* ctx, byte* address, int operandBitsOverride, Action<string, int> Log)
    {
        // Address may point to 0x66 or directly to opcode.
        bool has66 = (*address == 0x66);
        byte* p = has66 ? address + 1 : address; // p -> opcode (84/85)

        byte op = *p;            // 0x84 (byte) or 0x85 (word/dword/qword)
        byte modrm = *(p + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
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
        int dst = rexR ? (reg | 8) : reg;
        int src = rexB ? (rm | 8) : rm;

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
                lhs = bits == 16 ? (s & 0xFFFFUL)
                     : bits == 32 ? (s & 0xFFFF_FFFFUL)
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
            rhs = bits == 16 ? (d & 0xFFFFUL)
                 : bits == 32 ? (d & 0xFFFF_FFFFUL)
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
        if (((result >> msb) & 1UL) != 0) ctx->EFlags |= SF;

        // PF (parity of low byte, even parity -> PF=1)
        byte low = (byte)(result & 0xFF);
        // 0x6996 parity trick: bit=1 for even parity
        if (((0x6996 >> (low & 0x0F)) & 1) == 1)
        {
            // fold high nibble
            byte folded = (byte)(low ^ (low >> 4));
            if (((0x6996 >> (folded & 0x0F)) & 1) == 1) ctx->EFlags |= PF;
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

    // MOVZX r32/64, r/m16 : 0F B7 /r
    private static unsafe bool HandleMovzxGvEw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 0F B7 /r → MOVZX r32/64, r/m16
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7;
        int rm = (modrm & 0x7);
        ulong* R = &ctx->Rax;

        ulong memAddr = 0;
        ushort val16;
        string srcDesc;

        if (mod == 0b11)
        {
            val16 = (ushort)(R[rm] & 0xFFFF);
            srcDesc = $"R{rm}w";
        }
        else
        {
            if (mod == 0b00 && rm == 0b101)
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
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

            val16 = *(ushort*)memAddr;
            srcDesc = $"WORD PTR [0x{memAddr:X}]";
        }

    ((uint*)R)[reg] = val16;
        Log($"MOVZX E{reg}, {srcDesc} => 0x{val16:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }




    // TEST with operand-size override (66 85 /r)
    // Example here: 66 85 C0  -> TEST AX, AX
    private static unsafe bool HandleTestEwGw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        if (ip[0] != 0x66 || ip[1] != 0x85) return false;

        byte modrm = ip[2];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7;
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
            ulong addr = ((&ctx->Rax)[rm]);
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
        if (((res >> 15) & 1) != 0) f |= SF;

        // Simple parity of low byte:
        byte low = (byte)(res & 0xFF);
        bool parity = (System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0;
        if (parity) f |= PF;

        ctx->EFlags = f;
        ctx->Rip += (ulong)len;
        return true;
    }
    // Add this handler method anywhere in the X64Emulator class (e.g., near other branch handlers)
    private static bool HandleJeShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = (ulong)((long)ctx->Rip + 2 + rel8);
        Log($"JE short 0x{target:X} {(zf ? "TAKEN" : "NOT taken")}", 2);
        ctx->Rip = zf ? target : ctx->Rip + 2;
        return true;
    }

    private static bool HandleXorRvEv(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 3);
        byte reg = (byte)((modrm >> 3) & 7);
        byte rm = (byte)(modrm & 7);
        ulong value;

        if (mod == 0b11)
        {
            // Register to register
            ulong src = ((&ctx->Rax)[rm]);
            ulong dst = ((&ctx->Rax)[reg]);
            value = dst ^ src;
            ((&ctx->Rax)[reg]) = value;
            Log($"XOR R{reg}, R{rm}", 2);
        }
        else
        {
            // Memory form (simplified)
            ulong addr = ((&ctx->Rax)[rm]);
            uint src = *(uint*)addr;
            uint dst = (uint)((&ctx->Rax)[reg]);
            ((&ctx->Rax)[reg]) = dst ^ src;
            Log($"XOR R{reg}, [0x{addr:X}]", 2);
        }

        ctx->Rip += 2;
        return true;
    }

    private static bool HandleJneNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F 85 rel32  (length = 6)
        int rel32 = *(int*)(address + 2);
        ulong nextRip = ctx->Rip + 6;
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = nextRip + (ulong)(long)rel32;
        bool taken = !zf;

        Log($"JNE near 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 6);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }

    private static bool HandleJeNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F 84 rel32  (length = 6)
        int rel32 = *(int*)(address + 2);
        ulong nextRip = ctx->Rip + 6;
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = nextRip + (ulong)(long)rel32;
        bool taken = zf;

        Log($"JE near 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 6);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }

    private static bool HandleTestRm32R32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        int offs = 1;
        byte modrm = *(address + offs++);
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7;
        int rm = (modrm & 0x7);

        uint src = ((uint*)(&ctx->Rax))[reg];
        uint val;

        if (mod == 0b11)
        {
            val = ((uint*)(&ctx->Rax))[rm];
        }
        else
        {
            ulong memAddr = *((&ctx->Rax) + rm);
            if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
            else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
            val = *(uint*)memAddr;
        }

        uint res = val & src;
        bool zf = (res == 0);
        bool sf = ((res & 0x80000000u) != 0);
        ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

        Log($"TEST {((mod == 0b11) ? $"R{rm}d" : "r/m32")}, R{reg}d => ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
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
            byte mod = (byte)((modrm >> 6) & 0x3);
            int regop = (modrm >> 3) & 0x7;   // must be /0
            int rm = (modrm & 0x7);

            if (regop != 0)
            {
                Log($"Unsupported 66 C7 /{regop}", offs);
                return false;
            }

            // SIB helper (no REX here; it’s a legacy prefix)
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32;  // no base, disp32 only
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseBits);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 = no index
                {
                    indexVal = *((&ctx->Rax) + idxBits);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }
                return baseVal + indexVal;
            }

            if (mod == 0b11)
            {
                // register form: write low 16 bits of the target reg
                ushort imm16 = *(ushort*)(address + offs); offs += 2;
                // low 16 of (&Rax)[rm]
                ushort* dst16 = (ushort*)((&ctx->Rax) + rm);
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
                        memAddr = *((&ctx->Rax) + rm);
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
                        memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
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
                        memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
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
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // destination (r16)
        int rm = (modrm & 7);      // source (r/m16)
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

        // ---- update flags (Intel rules) ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~((uint)(CF | PF | AF | ZF | SF | OF));

        if (dst < src) f |= CF;                               // borrow
        if (result == 0) f |= ZF;
        if ((result & 0x8000) != 0) f |= SF;
        if ((((dst ^ src) & (dst ^ result)) & 0x8000) != 0) f |= OF;
        // parity flag
        byte low = (byte)(result & 0xFF);
        if ((System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0)
            f |= PF;

        ctx->EFlags = f;

        Log($"CMP {dstDesc}, {srcDesc} => result=0x{result:X4} ZF={((f & ZF) != 0 ? 1 : 0)} SF={((f & SF) != 0 ? 1 : 0)} CF={((f & CF) != 0 ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleMovEwGw(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 66 89 /r → MOV r/m16, r16
        int offs = 2;
        byte modrm = *(address + offs++);
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7; // source
        int rm = (modrm & 0x7);      // destination
        ulong* R = &ctx->Rax;

        ushort srcVal = (ushort)(R[reg] & 0xFFFF);
        ulong memAddr = 0;
        string dstDesc;

        if (mod == 0b11)
        {
            // Register to register: overwrite low 16 bits only
            R[rm] = (R[rm] & ~0xFFFFUL) | srcVal;
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


    private static unsafe bool HandleGrp1_EwIb(X64Emulator.CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Encoding: 66 83 /r ib   ; /0 ADD, /1 OR, /2 ADC, /3 SBB, /4 AND, /5 SUB, /6 XOR, /7 CMP
        int offs = 2;                  // start at ModRM
        byte modrm = *(address + offs++);
        byte mod = (byte)((modrm >> 6) & 0x3);
        int grp = (modrm >> 3) & 0x7; // /digit
        int rm = (modrm & 0x7);

        // Addressing (reg or simple [reg]/[reg+disp])
        bool regDirect = (mod == 0b11);
        ulong memAddr = 0;

        if (!regDirect)
        {
            if (mod == 0b00)
            {
                if (rm == 0b100) { byte sib = *(address + offs++); memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs); }
                else if (rm == 0b101) { int disp32 = *(int*)(address + offs); offs += 4; memAddr = (ulong)(long)disp32; }
                else memAddr = *((&ctx->Rax) + rm);
            }
            else if (mod == 0b01)
            {
                if (rm == 0b100) { byte sib = *(address + offs++); memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs); }
                else { long d8 = *(sbyte*)(address + offs++); memAddr = *((&ctx->Rax) + rm) + (ulong)d8; }
            }
            else // 0b10
            {
                if (rm == 0b100) { byte sib = *(address + offs++); int d32 = *(int*)(address + offs); offs += 4; memAddr = ComputeSibAddr16(ctx, address, sib, mod, ref offs) + (ulong)(long)d32; }
                else { int d32 = *(int*)(address + offs); offs += 4; memAddr = *((&ctx->Rax) + rm) + (ulong)(long)d32; }
            }
        }

        // imm8 sign-extended to 16
        sbyte imm8s = *(sbyte*)(address + offs++);
        ushort imm16 = (ushort)(short)imm8s;

        // Load/store target
        ushort* dst16 = regDirect ? (ushort*)((&ctx->Rax) + rm) : (ushort*)memAddr;
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
            if ((System.Numerics.BitOperations.PopCount((uint)lo) & 1) == 0) f |= PF;
        }
        void SetAdd(ushort a, ushort b, int cin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ua = a, ub = (uint)(b + cin);
            if (ua + ub > 0xFFFF) f |= CF;
            if ((((a ^ r) & (b ^ r)) & 0x8000) != 0) f |= OF;
            if ((((a & 0xF) + (b & 0xF) + (uint)cin) & 0x10) != 0) f |= AF;
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount((uint)lo) & 1) == 0) f |= PF;
        }
        void SetSub(ushort a, ushort b, int bin, ushort r)
        {
            f &= ~(CF | OF | ZF | SF | PF | AF);
            uint ub = (uint)(b + bin);
            if ((uint)a < ub) f |= CF;                              // borrow -> CF=1
            if ((((a ^ b) & (a ^ r)) & 0x8000) != 0) f |= OF;
            if ((((~(a ^ b)) & (a ^ r)) & 0x10) != 0) f |= AF;    // Intel AF formula
            if (r == 0) f |= ZF;
            if ((r & 0x8000) != 0) f |= SF;
            byte lo = (byte)(r & 0xFF);
            if ((System.Numerics.BitOperations.PopCount((uint)lo) & 1) == 0) f |= PF;
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
            byte scaleBits = (byte)((sib >> 6) & 0x3);
            byte idxBits = (byte)((sib >> 3) & 0x7);
            byte baseBits = (byte)(sib & 0x7);

            ulong baseVal = 0;
            if (!(modLocal == 0b00 && baseBits == 0b101))
                baseVal = *((&ctx->Rax) + baseBits);

            ulong indexVal = 0;
            if (idxBits != 0b100)
            {
                indexVal = *((&ctx->Rax) + idxBits);
                indexVal <<= scaleBits;
            }

            ulong addr = baseVal + indexVal;
            if (modLocal == 0b01) { long d8 = *(sbyte*)(baseAddr + offsLocal); offsLocal += 1; addr += (ulong)d8; }
            else if (modLocal == 0b10) { int d32 = *(int*)(baseAddr + offsLocal); offsLocal += 4; addr += (ulong)(long)d32; }
            return addr;
        }
    }

    private static unsafe bool HandleMovRm8Imm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        int offs = 1; // opcode length (C6)
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // must be 0 for C6 /0
        int rm = (modrm & 7);

        // Validate reg field (must be 0 for MOV r/m8, imm8)
        if (reg != 0)
        {
            Log($"Invalid reg field {reg} for MOV r/m8, imm8", offs);
            return false;
        }

        ulong addr = 0;
        ulong* R = &ctx->Rax;

        // Register direct mode (mod == 11) is invalid for C6
        if (mod == 0b11)
        {
            Log("Invalid: MOV r8, imm8 uses register mode", offs);
            return false;
        }

        // --- Handle SIB (rm == 100b) ---
        if (rm == 4)
        {
            byte sib = ip[offs++];
            byte scale = (byte)((sib >> 6) & 3);
            byte index = (byte)((sib >> 3) & 7);
            byte baseReg = (byte)(sib & 7);

            addr = R[baseReg];
            if (index != 4) // 4 means "no index"
                addr += R[index] << scale;

            // Optional displacement
            if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(ip + offs);
                offs++;
                addr = (ulong)((long)addr + disp8);
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                addr = (ulong)((long)addr + disp32);
            }
        }
        else if (mod == 0b00 && rm == 0b101)
        {
            // disp32 absolute address (no base)
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            addr = (ulong)(long)disp32;
        }
        else
        {
            addr = R[rm];

            if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(ip + offs);
                offs++;
                addr = (ulong)((long)addr + disp8);
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                addr = (ulong)((long)addr + disp32);
            }
        }

        // --- Immediate 8-bit value ---
        byte imm = *(byte*)(ip + offs);
        offs++;

        *(byte*)addr = imm;

        Log($"MOV BYTE PTR [0x{addr:X}], 0x{imm:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }



    private static bool HandlePopReg(CONTEXT* ctx, byte opcode, Action<string, int> Log)
    {
        int reg = opcode - 0x58;            // 0..7 => RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI
        ulong val = *(ulong*)ctx->Rsp;      // read from stack
        ctx->Rsp += 8;                      // pop
        *((&ctx->Rax) + reg) = val;         // write destination

        Log($"POP R{reg}", 1);
        ctx->Rip += 1;
        return true;
    }
    private static bool HandleTestRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // TEST r/m8, r8  => bitwise AND but no result stored
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
        byte rm = (byte)(modrm & 0x7);
        int offs = 2;

        byte src, dst;

        if (mod == 0b11)
        {
            src = (byte)(((&ctx->Rax)[reg]) & 0xFF);
            dst = (byte)(((&ctx->Rax)[rm]) & 0xFF);
        }
        else
        {
            ulong memAddr = *((&ctx->Rax) + rm);
            dst = *(byte*)memAddr;
            src = (byte)(((&ctx->Rax)[reg]) & 0xFF);
        }

        byte res = (byte)(src & dst);
        bool zf = (res == 0);
        bool sf = (res & 0x80) != 0;

        ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) |
                             (zf ? 0x40u : 0u) |
                             (sf ? 0x80u : 0u));

        Log($"TEST r/m8, r8 => (0x{dst:X2} & 0x{src:X2}) => ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS
    {
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    private static string FormatBytes(byte* address, int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++) bytes[i] = *(address + i);
        return string.Join(" ", bytes.Select(b => $"{b:X2}"));
    }

    private struct RegSnapshot
    {
        public ulong Rax, Rbx, Rcx, Rdx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
        public uint EFlags;
        public ulong Rip;
        public static RegSnapshot FromContext(CONTEXT* ctx)
        {
            return new RegSnapshot
            {
                Rax = ctx->Rax, Rbx = ctx->Rbx, Rcx = ctx->Rcx, Rdx = ctx->Rdx, Rsp = ctx->Rsp, Rbp = ctx->Rbp, Rsi = ctx->Rsi, Rdi = ctx->Rdi,
                R8 = ctx->R8, R9 = ctx->R9, R10 = ctx->R10, R11 = ctx->R11, R12 = ctx->R12, R13 = ctx->R13, R14 = ctx->R14, R15 = ctx->R15,
                EFlags = ctx->EFlags, Rip = ctx->Rip
            };
        }
    }

    private static bool HandleMovImmToReg_NoRex(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte opcode = *address;                 // B8..BF
        int reg = opcode - 0xB8;                // 0..7 => RAX..RDI
        uint imm32 = *(uint*)(address + 1);

        // Write 64-bit with zero-extend semantics (writing r32 clears upper 32)
        ulong* dst = (&ctx->Rax) + reg;
        *dst = (ulong)imm32;

        Log($"MOV R{reg}, 0x{imm32:X8}", 5);
        ctx->Rip += 5;
        return true;
    }
    private static string FormatRegisterDiff(RegSnapshot before, RegSnapshot after)
    {
        var sb = new StringBuilder();
        void diff(string name, ulong b, ulong a) { if (b != a) sb.Append($" {name}:0x{b:X}->0x{a:X}"); }
        diff("RAX", before.Rax, after.Rax); diff("RBX", before.Rbx, after.Rbx); diff("RCX", before.Rcx, after.Rcx);
        diff("RDX", before.Rdx, after.Rdx); diff("RSP", before.Rsp, after.Rsp); diff("RBP", before.Rbp, after.Rbp);
        diff("RSI", before.Rsi, after.Rsi); diff("RDI", before.Rdi, after.Rdi); diff("R8", before.R8, after.R8);
        diff("R9", before.R9, after.R9); diff("R10", before.R10, after.R10); diff("R11", before.R11, after.R11);
        diff("R12", before.R12, after.R12); diff("R13", before.R13, after.R13); diff("R14", before.R14, after.R14);
        diff("R15", before.R15, after.R15);
        if (before.EFlags != after.EFlags) sb.Append($" EFlags:0x{before.EFlags:X}->0x{after.EFlags:X}");
        return sb.ToString();
    }
   
    private static bool HandleMovR32Rm32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // MOV r32, r/m32  =>  8B /r
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7); // destination (r32)
        byte rm = (byte)(modrm & 0x7);        // source (r/m32)
        int offs = 2;

        ulong memAddr = 0;
        uint value;

        if (mod == 0b11)
        {
            // Register to register
            value = (uint)(((&ctx->Rax)[rm]) & 0xFFFFFFFF);
            ((uint*)(&ctx->Rax))[reg] = value;
            Log($"MOV R{reg}, R{rm} (32-bit) => 0x{value:X8}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // Memory addressing
        if (mod == 0b00)
        {
            // [reg]
            memAddr = *((&ctx->Rax) + rm);
        }
        else if (mod == 0b01)
        {
            // [reg + disp8]
            sbyte disp8 = *(sbyte*)(address + offs);
            offs += 1;
            memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
        }
        else if (mod == 0b10)
        {
            // [reg + disp32]
            int disp32 = *(int*)(address + offs);
            offs += 4;
            memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
        }
        else
        {
            Log($"Unsupported MOV r32,[r/m32] Mod={mod}", offs);
            return false;
        }

        value = *(uint*)memAddr;
        ((uint*)(&ctx->Rax))[reg] = value;

        Log($"MOV R{reg}, [0x{memAddr:X}] => R{reg}=0x{value:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static bool HandleRet(CONTEXT* ctx, Action<string, int> Log)
    {
        ulong returnAddress = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;
        Log($"RET => RIP=0x{returnAddress:X}", 1);
        ctx->Rip = returnAddress;
        return true;
    }

    private static bool HandleLeave(CONTEXT* ctx, Action<string, int> Log)
    {
        // LEAVE: MOV RSP, RBP; POP RBP
        ctx->Rsp = ctx->Rbp;
        ctx->Rbp = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;
        Log("LEAVE (MOV RSP, RBP; POP RBP)", 1);
        ctx->Rip += 1;
        return true;
    }

    private static bool HandleJmpShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        ulong nextRip = ctx->Rip + 2;
        long target = (long)nextRip + rel8;

        Log($"JMP short {rel8:+#;-#;0} -> 0x{(ulong)target:X}", 2);

        ctx->Rip = (ulong)target;
        return true;
    }


    private static unsafe bool HandleMovzxR32Rm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // ip[0]=0F, ip[1]=B6
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7; // dest (Ereg)
        int rm = (modrm & 0x7);      // src
        ulong* R = &ctx->Rax;

        byte value8;
        string srcDesc;
        ulong memAddr = 0;

        if (mod == 0b11)
        {
            value8 = (byte)(R[rm] & 0xFF);
            srcDesc = $"R{rm}b";
        }
        else
        {
            if (mod == 0b00 && rm == 0b101)
            {
                int disp32 = *(int*)(ip + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01) { long d8 = *(sbyte*)(ip + offs); offs += 1; memAddr += (ulong)d8; }
                else if (mod == 0b10) { int d32 = *(int*)(ip + offs); offs += 4; memAddr += (ulong)(long)d32; }
            }
            value8 = *(byte*)memAddr;
            srcDesc = $"BYTE PTR [0x{memAddr:X}]";
        }

        ((uint*)R)[reg] = value8; // zero-extend via Ereg write

        Log($"MOVZX E{reg}, {srcDesc} => 0x{value8:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }


    private static bool HandleCmpAlImm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte imm8 = *(address + 1);
        byte al = (byte)(ctx->Rax & 0xFF);
        byte result = (byte)(al - imm8);
        bool zf = (result == 0);
        bool sf = (result & 0x80) != 0;
        ctx->EFlags = (uint)((ctx->EFlags & ~0x85) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));
        Log($"CMP AL, 0x{imm8:X2}", 2);
        ctx->Rip += 2;
        return true;
    }

    private static bool HandleJneShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = (ulong)((long)ctx->Rip + 2 + rel8);
        Log($"JNE short 0x{target:X} {(zf ? "NOT taken" : "TAKEN")}", 2);
        ctx->Rip = zf ? ctx->Rip + 2 : target;
        return true;
    }


    // --- Opcode Handlers ---
    private static bool HandleAddRm64Imm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
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

        int offs = 3; // start at ModRM
        ulong memAddr = 0;

        // helper for SIB forms
        ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
        {
            byte scaleBits = (byte)((sib >> 6) & 0x3);
            byte idxBits = (byte)((sib >> 3) & 0x7);
            byte baseBits = (byte)(sib & 0x7);

            ulong baseVal = 0, indexVal = 0;
            if (baseBits != 0b101)
                baseVal = *((&ctx->Rax) + baseBits);
            if (idxBits != 0b100)
            {
                indexVal = *((&ctx->Rax) + idxBits);
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
            ulong* dst = (&ctx->Rax) + rm;
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
                    memAddr = *((&ctx->Rax) + rm);
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
                    memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
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
                    memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
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

    private static bool HandleAddRm8R8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
        byte rm = (byte)(modrm & 0x7);
        int offs = 2;
        ulong memAddr = 0;
        byte* destPtr = null;
        if (mod == 0b11)
        {
            destPtr = (byte*)((&ctx->Rax) + rm);
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
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        ulong baseVal = (baseReg == 0b101) ? 0 : *((&ctx->Rax) + baseReg);
                        ulong indexVal = (index == 0b100) ? 0 : (*((&ctx->Rax) + index) << scale);
                        int disp32 = (baseReg == 0b101) ? *(int*)(address + offs) : 0;
                        offs += (baseReg == 0b101) ? 4 : 0;
                        memAddr = baseVal + indexVal + (ulong)disp32;
                    }
                    else
                    {
                        memAddr = *((&ctx->Rax) + rm);
                    }
                    destPtr = (byte*)memAddr;
                    break;
                case 0b01:
                case 0b10:
                    {
                        int dispSize = (mod == 0b01) ? 1 : 4;
                        long disp = (dispSize == 1)
                            ? *(sbyte*)(address + offs)
                            : *(int*)(address + offs);
                        offs += dispSize;
                        ulong baseVal = *((&ctx->Rax) + rm);
                        memAddr = baseVal + (ulong)disp;
                        destPtr = (byte*)memAddr;
                    }
                    break;
                default:
                    Log($"Unsupported ADD ModRM 0x{modrm:X2}", 2);
                    return false;
            }
        }
        byte* srcPtr = (byte*)((&ctx->Rax) + reg);
        byte src = *srcPtr;
        byte dest = *destPtr;
        byte result = (byte)(dest + src);
        *destPtr = result;
        bool zf = (result == 0);
        bool sf = (result & 0x80) != 0;
        ctx->EFlags = (uint)((ctx->EFlags & ~0x85) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));
        Log($"ADD r/m8, r8 => [0x{(ulong)destPtr:X}]=0x{result:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static bool HandleJbeShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        long disp = rel8;
        ulong target = (ulong)((long)ctx->Rip + 2 + disp);
        bool cf = (ctx->EFlags & 0x1) != 0;
        bool zf = (ctx->EFlags & 0x40) != 0;
        bool taken = cf || zf;
        Log($"JBE short 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 2);
        ctx->Rip = taken ? target : ctx->Rip + 2;
        return true;
    }

    private static bool HandleNop(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("NOP", 1);
        ctx->Rip += 1;
        return true;
    }

    private static bool HandlePushRbp(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RBP", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rbp;
        ctx->Rip += 1;
        return true;
    }

    private static bool HandlePushRdi(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RDI", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rdi;
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRsi(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RSI", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rsi;
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRbx(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RBX", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rbx;
        ctx->Rip += 1;
        return true;
    }

    private static bool HandleCall(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        int rel32 = *(int*)(address + 1);
        ulong returnAddress = ctx->Rip + 5;
        ulong newRip = returnAddress + (ulong)rel32;
        Log($"CALL to 0x{newRip:X}, return address 0x{returnAddress:X}", 5);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = returnAddress;
        ctx->Rip = newRip;
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
                byte mod = (byte)((modrm >> 6) & 3);
                byte reg = (byte)((modrm >> 3) & 7);
                byte rm = (byte)(modrm & 7);

                if (mod == 0) // no displacement
                {
                    ulong tebBase = ThreadInformation.GetCurrentThreadGsBase();
                    var offset = ((&ctx->Rax)[rm]);
                    ulong addr = tebBase + offset;
                    ulong value = *(ulong*)addr;
                    ((&ctx->Rax)[reg]) = value;

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

