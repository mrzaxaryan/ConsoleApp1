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
            //string regs = $"RIP=0x{before.Rip:X} RSP=0x{before.Rsp:X} RAX=0x{before.Rax:X} RCX=0x{before.Rcx:X} RDX=0x{before.Rdx:X} RBP=0x{before.Rbp:X} EFlags=0x{before.EFlags:X}";
            var afterSnap = RegSnapshot.FromContext(ctx);
            string diff = FormatRegisterDiff(before, afterSnap);
            string currentLog = $"[{instrAddr}] [{bytes}] {mnemonic} | {(diff.Length > 0 ? " =>" + diff : "")}";
            Console.WriteLine(currentLog);
        }

        bool result;
        if (*address == 0x0F && *(address + 1) == 0xB6)
        {
            result = HandleMovzxR32Rm8(ctx, address, Log);
        }
        else if (*address == 0x48 && *(address + 1) == 0x83 && *(address + 2) == 0xAC && *(address + 3) == 0x24)
        {
            result = Sub.Handle(ctx, address, Log);
        }
        else if (*address == 0x48 && *(address + 1) == 0x83 && (*(address + 2) & 0x38) == 0x00)
        {
            result = HandleAddRm64Imm8(ctx, address, Log);
        }
        else if (*address == 0x65)
        {
            result = HandleSegmentPrefix(ctx, address, Log);
        }
        else if(*address == 0x4C) // ???
        {
            result = Rex.Handle(ctx, address, Log);
        }
        else
        {
            switch (*address)
            {
                case 0x58: // POP RAX
                case 0x59: // POP RCX
                case 0x5A: // POP RDX
                case 0x5B: // POP RBX
                case 0x5C: // POP RSP
                case 0x5D: // POP RBP
                case 0x5E: // POP RSI
                case 0x5F: // POP RDI
                    result = HandlePopReg(ctx, *address, Log);
                    break;
                case 0x84:
                    result = HandleTestRm8R8(ctx, address, Log);
                    break;
                case 0xB8:
                case 0xB9:
                case 0xBA:
                case 0xBB:
                case 0xBC:
                case 0xBD:
                case 0xBE:
                case 0xBF:
                    result = HandleMovImmToReg_NoRex(ctx, address, Log);
                    break;
                case X64Opcodes.ADD_RM8_R8:
                    result = HandleAddRm8R8(ctx, address, Log); break;
                case X64Opcodes.JBE_SHORT:
                    result = HandleJbeShort(ctx, address, Log); break;
                case X64Opcodes.JNE_SHORT:
                    result = HandleJneShort(ctx, address, Log); break;
                case X64Opcodes.NOP:
                    result = HandleNop(ctx, Log); break;
                case X64Opcodes.PUSH_RBP:
                    result = HandlePushRbp(ctx, Log); break;
                case X64Opcodes.REX_PREFIX:
                    result = Rex.Handle(ctx, address, Log); break;
                case X64Opcodes.REX_B_GROUP:
                    result = HandleRexBGroup(ctx, address, Log); break;
                case X64Opcodes.PUSH_RDI:
                    result = HandlePushRdi(ctx, Log); break;
                case X64Opcodes.PUSH_RSI:
                    result = HandlePushRsi(ctx, Log); break;
                case X64Opcodes.PUSH_RBX:
                    result = HandlePushRbx(ctx, Log); break;
                case X64Opcodes.MOV_RM64_R64:
                    result = Mov.HandleMovRm64R64(ctx, address, Log); break;
                case X64Opcodes.MOV_RM32_IMM32:
                    result = Mov.HandleMovRm32Imm32(ctx, address, Log); break;
                case X64Opcodes.CALL:
                    result = HandleCall(ctx, address, Log); break;
                case X64Opcodes.RET:
                    result = HandleRet(ctx, Log); break;
                case 0xC9: // LEAVE
                    result = HandleLeave(ctx, Log); break;
                case 0x8B:
                    result = HandleMovR32Rm32(ctx, address, Log);
                    break;
                // In the Emulate method's switch statement, add this case:
                case 0x74: // JE rel8
                    result = HandleJeShort(ctx, address, Log); break;
                case X64Opcodes.JMP_SHORT:
                    result = HandleJmpShort(ctx, address, Log); break;
                case X64Opcodes.CMP_AL_IMM8:
                    result = HandleCmpAlImm8(ctx, address, Log); break;
                case 0xC6:
                    result = HandleMovRm8Imm8(ctx, address, Log);
                    break;
                // ... keep other cases as-is for now ...
                default:
                    Log($"Unsupported opcode 0x{*address:X2}", 32);
                    result = false;
                    break;
            }
        }       
        return result;
    }
    private static  bool HandleMovRm8Imm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);   // must be 0 for MOV
        byte rm = (byte)(modrm & 0x7);
        int offs = 2;

        if (reg != 0)
        {
            Log($"Unsupported C6 /{reg} variant", offs);
            return false;
        }

        byte imm8 = *(address + offs);
        offs++;

        if (mod == 0b11)
        {
            // register direct
            byte* dst = (byte*)((&ctx->Rax) + rm);
            *dst = imm8;
            Log($"MOV R{rm}b, 0x{imm8:X2}", offs);
        }
        else
        {
            // memory
            ulong addr = *((&ctx->Rax) + rm);
            if (mod == 0b01)
            {
                long disp8 = *(sbyte*)(address + offs);
                offs++;
                addr += (ulong)disp8;
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(address + offs);
                offs += 4;
                addr += (ulong)(long)disp32;
            }
            *(byte*)addr = imm8;
            Log($"MOV BYTE PTR [0x{addr:X}], 0x{imm8:X2}", offs);
        }

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
    private static bool HandleRexBGroup(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte op2 = *(address + 1);
        // PUSH R8–R15 (41 50–57)
        if (op2 >= 0x50 && op2 <= 0x57)
        {
            int reg = op2 - 0x50; // 0..7 → R8..R15
            ulong* regPtr = (&ctx->R8) + reg;
            Log($"PUSH R{8 + reg}", 2);
            ctx->Rsp -= 8;
            *(ulong*)ctx->Rsp = *regPtr;
            ctx->Rip += 2;
            return true;
        }
        // POP R8–R15 (41 58–5F)
        if (op2 >= 0x58 && op2 <= 0x5F)
        {
            int reg = op2 - 0x58; // 0..7 → R8..R15
            ulong* regPtr = (&ctx->R8) + reg;
            ulong v = *(ulong*)ctx->Rsp;
            ctx->Rsp += 8;
            *regPtr = v;
            Log($"POP R{8 + reg}", 2);
            ctx->Rip += 2;
            return true;
        }
        Log($"Unsupported 41 0x{op2:X2}", 2);
        return false;
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
        ulong target = (ulong)((long)ctx->Rip + 2 + rel8);
        Log($"JMP short 0x{target:X}", 2);
        ctx->Rip = target;
        return true;
    }

    private static bool HandleMovzxR32Rm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 2);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
        byte rm = (byte)(modrm & 0x7);
        int instrLen = 3;
        byte value;
        if (mod == 0b11)
        {
            // Register to register
            value = (byte)((((&ctx->Rax)[rm]) & 0xFF));
        }
        else
        {
            // Only simple [register] addressing for now
            ulong addr = ((&ctx->Rax)[rm]);
            value = *(byte*)addr;
        }
        // Zero-extend to 32 bits and store in destination register
        ((uint*)(&ctx->Rax))[reg] = value;
        Log($"MOVZX R{reg}, r/m8 => R{reg}=0x{value:X2}", instrLen);
        ctx->Rip += (ulong)instrLen;
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
    private static bool HandleSegmentPrefix(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        if (*address != 0x65) return false; // only GS prefix

        byte* next = address + 1;

        // Example: 65 48 8B 04 25 XX XX XX XX  => MOV RAX, [GS:disp32]
        if (*next == 0x48 && *(next + 1) == 0x8B && *(next + 2) == 0x04 && *(next + 3) == 0x25)
        {
            uint disp32 = *(uint*)(next + 4);
            ulong tebBase = ThreadInformation.GetCurrentThreadGsBase();
            ulong addr = tebBase + disp32;
            ulong value = *(ulong*)addr;
            ctx->Rax = value;
            Log($"MOV RAX, [GS:0x{disp32:X}] => RAX=0x{value:X} (TEB base=0x{tebBase:X})", 9);
            ctx->Rip += 9;
            return true;
        }

        Log("Unhandled GS-prefixed opcode", 2);
        return false;
    }
    
}

