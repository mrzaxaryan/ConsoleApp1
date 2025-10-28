using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using ConsoleApp1.Handlers;

namespace ConsoleApp1;

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

        // Stack operations
        if (StackOperations.Handle(opcode, ctx, address, Log))
            return true;
        // Control flow operations
        if (ControlFlow.Handle(opcode, ctx, address, Log))
            return true;

        // Mov operations
        if (MovOperations.Handle(opcode, ctx, address, Log))
            return true;

        // Arithmetic and logic operations
        if (ALUOperations.Handle(opcode, ctx, address, Log))
            return true;

        // Prefixes and two-byte opcodes
        if (Prefixes.Handle(opcode, ctx, address, Log))
            return true;

        // Miscellaneous operations
        if (Miscellaneous.Handle(opcode, ctx, address, Log))
            return true;

        Log($"Unsupported opcode 0x{opcode:X2}", 32);
        return false;
    }





    // TEST with operand-size override (66 85 /r)
    // Example here: 66 85 C0  -> TEST AX, AX
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





    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS
    {
        public nint ExceptionRecord;
        public nint ContextRecord;
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
                Rax = ctx->Rax,
                Rbx = ctx->Rbx,
                Rcx = ctx->Rcx,
                Rdx = ctx->Rdx,
                Rsp = ctx->Rsp,
                Rbp = ctx->Rbp,
                Rsi = ctx->Rsi,
                Rdi = ctx->Rdi,
                R8 = ctx->R8,
                R9 = ctx->R9,
                R10 = ctx->R10,
                R11 = ctx->R11,
                R12 = ctx->R12,
                R13 = ctx->R13,
                R14 = ctx->R14,
                R15 = ctx->R15,
                EFlags = ctx->EFlags,
                Rip = ctx->Rip
            };
        }
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
    // --- Opcode Handlers ---
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

    









   
}