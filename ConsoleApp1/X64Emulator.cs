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
}