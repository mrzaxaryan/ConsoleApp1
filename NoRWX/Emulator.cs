using NoRWX.Core;
using NoRWX.Handlers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace NoRWX;

public static unsafe class Emulator
{
    public static bool Emulate(ref EXCEPTION_POINTERS exceptionInfo, byte* address)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        var before = RegSnapshot.FromContext(ctx);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void Log(string mnemonic, int instrLen)
        {
            // Uncomment for debugging:
            // string bytes = FormatBytes(address, instrLen);
            // string instrAddr = $"0x{before.Rip:X}";
            // var afterSnap = RegSnapshot.FromContext(ctx);
            // string diff = FormatRegisterDiff(before, afterSnap);
            // Console.WriteLine($"[{instrAddr}] [{bytes}] {mnemonic} | {(diff.Length > 0 ? " => " + diff : "")}");
        }

        byte opcode = *address;

        // ---- Fast dispatch for single-byte opcodes ----
        switch (opcode)
        {
            // === NOP ===
            case 0x90:
                return MiscHandler.HandleNop(ctx, address, Log);

            // === Stack: PUSH r64 (50-57), POP r64 (58-5F) ===
            case >= 0x50 and <= 0x57:
                return StackHandler.HandlePushReg(ctx, address, Log);
            case >= 0x58 and <= 0x5F:
                return StackHandler.HandlePopReg(ctx, address, Log);

            // === Stack: PUSH imm ===
            case 0x6A: return StackHandler.HandlePushImm8(ctx, address, Log);
            case 0x68: return StackHandler.HandlePushImm32(ctx, address, Log);
            case 0x8F: return StackHandler.HandlePopRm64(ctx, address, Log);

            // === MOV ===
            case 0x88: case 0x89: return MoveHandler.HandleMovRmR(ctx, address, Log);
            case 0x8A: case 0x8B: return MoveHandler.HandleMovRRm(ctx, address, Log);
            case 0xC6: case 0xC7: return MoveHandler.HandleMovRmImm(ctx, address, Log);
            case >= 0xB0 and <= 0xB7: return MoveHandler.HandleMovRegImm(ctx, address, Log);
            case >= 0xB8 and <= 0xBF: return MoveHandler.HandleMovRegImm(ctx, address, Log);

            // === LEA ===
            case 0x8D: return MoveHandler.HandleLea(ctx, address, Log);

            // === MOVSXD ===
            case 0x63: return MoveHandler.HandleMovsxd(ctx, address, Log);

            // === ADD ===
            case 0x00: case 0x01: return ArithmeticHandler.HandleAddRmR(ctx, address, Log);
            case 0x02: case 0x03: return ArithmeticHandler.HandleAddRRm(ctx, address, Log);
            case 0x04: case 0x05: return ArithmeticHandler.HandleAddAccImm(ctx, address, Log);

            // === OR ===
            case 0x08: case 0x09: return LogicHandler.HandleLogicRmR(ctx, address, Log);
            case 0x0A: case 0x0B: return LogicHandler.HandleLogicRRm(ctx, address, Log);
            case 0x0C: case 0x0D: return LogicHandler.HandleLogicAccImm(ctx, address, Log);

            // === AND ===
            case 0x20: case 0x21: return LogicHandler.HandleLogicRmR(ctx, address, Log);
            case 0x22: case 0x23: return LogicHandler.HandleLogicRRm(ctx, address, Log);
            case 0x24: case 0x25: return LogicHandler.HandleLogicAccImm(ctx, address, Log);

            // === SUB ===
            case 0x28: case 0x29: return ArithmeticHandler.HandleSubRmR(ctx, address, Log);
            case 0x2A: case 0x2B: return ArithmeticHandler.HandleSubRRm(ctx, address, Log);
            case 0x2C: case 0x2D: return ArithmeticHandler.HandleSubAccImm(ctx, address, Log);

            // === XOR ===
            case 0x30: case 0x31: return LogicHandler.HandleLogicRmR(ctx, address, Log);
            case 0x32: case 0x33: return LogicHandler.HandleLogicRRm(ctx, address, Log);
            case 0x34: case 0x35: return LogicHandler.HandleLogicAccImm(ctx, address, Log);

            // === CMP ===
            case 0x38: case 0x39: return ArithmeticHandler.HandleCmpRmR(ctx, address, Log);
            case 0x3A: case 0x3B: return ArithmeticHandler.HandleCmpRRm(ctx, address, Log);
            case 0x3C: case 0x3D: return ArithmeticHandler.HandleCmpAccImm(ctx, address, Log);

            // === Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm ===
            case 0x80: case 0x81: case 0x83:
                return ArithmeticHandler.HandleGroup1(ctx, address, Log);

            // === TEST ===
            case 0x84: case 0x85: return LogicHandler.HandleTestRmR(ctx, address, Log);
            case 0xA8: case 0xA9: return LogicHandler.HandleTestAccImm(ctx, address, Log);

            // === XCHG ===
            case 0x86: case 0x87: return MoveHandler.HandleXchg(ctx, address, Log);
            case >= 0x91 and <= 0x97: return MoveHandler.HandleXchgAccReg(ctx, address, Log);

            // === CBW/CWDE/CDQE and CWD/CDQ/CQO ===
            case 0x98: return MiscHandler.HandleCbwCwdeCdqe(ctx, address, Log);
            case 0x99: return MiscHandler.HandleCwdCdqCqo(ctx, address, Log);

            // === SAHF/LAHF ===
            case 0x9E: return MiscHandler.HandleSahf(ctx, address, Log);
            case 0x9F: return MiscHandler.HandleLahf(ctx, address, Log);

            // === String operations ===
            case 0xA4: case 0xA5: return MiscHandler.HandleStringOp(ctx, address, Log);
            case 0xA6: case 0xA7: return MiscHandler.HandleStringOp(ctx, address, Log);
            case 0xAA: case 0xAB: return MiscHandler.HandleStringOp(ctx, address, Log);
            case 0xAC: case 0xAD: return MiscHandler.HandleStringOp(ctx, address, Log);
            case 0xAE: case 0xAF: return MiscHandler.HandleStringOp(ctx, address, Log);

            // === Group 2: Shift/rotate ===
            case 0xC0: case 0xC1: return ArithmeticHandler.HandleGroup2Shift(ctx, address, Log);
            case 0xD0: case 0xD1: return ArithmeticHandler.HandleGroup2Shift(ctx, address, Log);
            case 0xD2: case 0xD3: return ArithmeticHandler.HandleGroup2Shift(ctx, address, Log);

            // === Control flow ===
            case 0xE8: return ControlFlowHandler.HandleCallRel32(ctx, address, Log);
            case 0xC3: case 0xC2: return ControlFlowHandler.HandleRet(ctx, address, Log);
            case 0xC9: return ControlFlowHandler.HandleLeave(ctx, address, Log);
            case 0xC8: return ControlFlowHandler.HandleEnter(ctx, address, Log);
            case 0xE9: case 0xEB: return ControlFlowHandler.HandleJmp(ctx, address, Log);
            case >= 0x70 and <= 0x7F: return ControlFlowHandler.HandleJccShort(ctx, address, Log);
            case 0xE0: case 0xE1: case 0xE2: return ControlFlowHandler.HandleLoop(ctx, address, Log);
            case 0xCC: return ControlFlowHandler.HandleInt3(ctx, address, Log);

            // === INC/DEC r/m8 ===
            case 0xFE: return ArithmeticHandler.HandleIncDec(ctx, address, Log);

            // === Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV ===
            case 0xF6: case 0xF7: return ArithmeticHandler.HandleGroup3(ctx, address, Log);

            // === Group 5: INC/DEC/CALL/JMP/PUSH r/m ===
            case 0xFF: return ControlFlowHandler.HandleGroup5(ctx, address, Log);

            // === IMUL r, r/m, imm ===
            case 0x69: case 0x6B: return ArithmeticHandler.HandleImul3(ctx, address, Log);

            // === Flag manipulation ===
            case 0xF5: case 0xF8: case 0xF9: return MiscHandler.HandleClearSetCarry(ctx, address, Log);
            case 0xFC: case 0xFD: return MiscHandler.HandleClearSetDirection(ctx, address, Log);

            // === GS prefix ===
            case 0x65: return MiscHandler.HandleGsPrefix(ctx, address, Log);

            // === Operand-size prefix (0x66) ===
            case 0x66:
                return HandleWithOperandSizePrefix(ctx, address, Log);

            // === REP/REPNE prefixes ===
            case 0xF2: case 0xF3:
                return HandleWithRepPrefix(ctx, address, Log);

            // === REX prefixes (0x40-0x4F) ===
            case >= 0x40 and <= 0x4F:
                return HandleWithRexPrefix(ctx, address, Log);

            // === Two-byte opcode escape (0F) ===
            case 0x0F:
                return HandleTwoByteOpcode(ctx, address, Log);

            default:
                Log($"Unsupported opcode 0x{opcode:X2}", 1);
                return false;
        }
    }

    /// <summary>Handle instructions starting with REX prefix (0x40-0x4F).</summary>
    private static bool HandleWithRexPrefix(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        // REX prefix is transparent - the unified handlers use ParsePrefixes which handles REX.
        // We just need to dispatch based on the opcode AFTER the REX byte.
        byte op2 = *(ip + 1);

        switch (op2)
        {
            // Stack
            case >= 0x50 and <= 0x57: return StackHandler.HandlePushReg(ctx, ip, log);
            case >= 0x58 and <= 0x5F: return StackHandler.HandlePopReg(ctx, ip, log);

            // MOV
            case 0x88: case 0x89: return MoveHandler.HandleMovRmR(ctx, ip, log);
            case 0x8A: case 0x8B: return MoveHandler.HandleMovRRm(ctx, ip, log);
            case 0xC6: case 0xC7: return MoveHandler.HandleMovRmImm(ctx, ip, log);
            case >= 0xB0 and <= 0xB7: return MoveHandler.HandleMovRegImm(ctx, ip, log);
            case >= 0xB8 and <= 0xBF: return MoveHandler.HandleMovRegImm(ctx, ip, log);

            // LEA
            case 0x8D: return MoveHandler.HandleLea(ctx, ip, log);

            // MOVSXD
            case 0x63: return MoveHandler.HandleMovsxd(ctx, ip, log);

            // ADD
            case 0x00: case 0x01: return ArithmeticHandler.HandleAddRmR(ctx, ip, log);
            case 0x02: case 0x03: return ArithmeticHandler.HandleAddRRm(ctx, ip, log);
            case 0x04: case 0x05: return ArithmeticHandler.HandleAddAccImm(ctx, ip, log);

            // OR
            case 0x08: case 0x09: return LogicHandler.HandleLogicRmR(ctx, ip, log);
            case 0x0A: case 0x0B: return LogicHandler.HandleLogicRRm(ctx, ip, log);

            // AND
            case 0x20: case 0x21: return LogicHandler.HandleLogicRmR(ctx, ip, log);
            case 0x22: case 0x23: return LogicHandler.HandleLogicRRm(ctx, ip, log);

            // SUB
            case 0x28: case 0x29: return ArithmeticHandler.HandleSubRmR(ctx, ip, log);
            case 0x2A: case 0x2B: return ArithmeticHandler.HandleSubRRm(ctx, ip, log);
            case 0x2C: case 0x2D: return ArithmeticHandler.HandleSubAccImm(ctx, ip, log);

            // XOR
            case 0x30: case 0x31: return LogicHandler.HandleLogicRmR(ctx, ip, log);
            case 0x32: case 0x33: return LogicHandler.HandleLogicRRm(ctx, ip, log);

            // CMP
            case 0x38: case 0x39: return ArithmeticHandler.HandleCmpRmR(ctx, ip, log);
            case 0x3A: case 0x3B: return ArithmeticHandler.HandleCmpRRm(ctx, ip, log);
            case 0x3C: case 0x3D: return ArithmeticHandler.HandleCmpAccImm(ctx, ip, log);

            // Group 1
            case 0x80: case 0x81: case 0x83:
                return ArithmeticHandler.HandleGroup1(ctx, ip, log);

            // TEST
            case 0x84: case 0x85: return LogicHandler.HandleTestRmR(ctx, ip, log);

            // XCHG
            case 0x86: case 0x87: return MoveHandler.HandleXchg(ctx, ip, log);

            // CBW/CWDE/CDQE and CWD/CDQ/CQO
            case 0x98: return MiscHandler.HandleCbwCwdeCdqe(ctx, ip, log);
            case 0x99: return MiscHandler.HandleCwdCdqCqo(ctx, ip, log);

            // Shift/rotate
            case 0xC0: case 0xC1: return ArithmeticHandler.HandleGroup2Shift(ctx, ip, log);
            case 0xD0: case 0xD1: return ArithmeticHandler.HandleGroup2Shift(ctx, ip, log);
            case 0xD2: case 0xD3: return ArithmeticHandler.HandleGroup2Shift(ctx, ip, log);

            // INC/DEC
            case 0xFE: return ArithmeticHandler.HandleIncDec(ctx, ip, log);

            // Group 3
            case 0xF6: case 0xF7: return ArithmeticHandler.HandleGroup3(ctx, ip, log);

            // Group 5
            case 0xFF: return ControlFlowHandler.HandleGroup5(ctx, ip, log);

            // IMUL 3-operand
            case 0x69: case 0x6B: return ArithmeticHandler.HandleImul3(ctx, ip, log);

            // String ops
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0xAE: case 0xAF:
                return MiscHandler.HandleStringOp(ctx, ip, log);

            // Two-byte opcode escape (REX + 0F ...)
            case 0x0F:
                return HandleTwoByteOpcode(ctx, ip, log);

            default:
                log($"Unsupported REX-prefixed opcode 0x{*ip:X2} 0x{op2:X2}", 2);
                return false;
        }
    }

    /// <summary>Handle instructions starting with operand-size prefix (0x66).</summary>
    private static bool HandleWithOperandSizePrefix(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        // Find the actual opcode after prefix(es)
        int offs = 1; // skip 0x66
        // Skip any REX
        byte next = ip[offs];
        if ((next & 0xF0) == 0x40) offs++;
        byte opcode = ip[offs];

        // Most handlers already handle 0x66 via ParsePrefixes
        switch (opcode)
        {
            case 0x89: return MoveHandler.HandleMovRmR(ctx, ip, log);
            case 0x8B: return MoveHandler.HandleMovRRm(ctx, ip, log);
            case 0xC7: return MoveHandler.HandleMovRmImm(ctx, ip, log);
            case >= 0xB8 and <= 0xBF: return MoveHandler.HandleMovRegImm(ctx, ip, log);
            case 0x83: case 0x81: case 0x80:
                return ArithmeticHandler.HandleGroup1(ctx, ip, log);
            case 0x85: return LogicHandler.HandleTestRmR(ctx, ip, log);
            case 0x39: return ArithmeticHandler.HandleCmpRmR(ctx, ip, log);
            case 0x3B: return ArithmeticHandler.HandleCmpRRm(ctx, ip, log);
            case 0x01: return ArithmeticHandler.HandleAddRmR(ctx, ip, log);
            case 0x29: return ArithmeticHandler.HandleSubRmR(ctx, ip, log);
            case 0x31: return LogicHandler.HandleLogicRmR(ctx, ip, log);
            case 0x0F: return HandleTwoByteOpcode(ctx, ip, log);
            case 0x8D: return MoveHandler.HandleLea(ctx, ip, log);
            case 0x90: return MiscHandler.HandleNop(ctx, ip, log); // 66 90 = 2-byte NOP
            default:
                log($"Unsupported 0x66-prefixed opcode 0x{opcode:X2}", 2);
                return false;
        }
    }

    /// <summary>Handle instructions with REP/REPNE prefix (F2/F3).</summary>
    private static bool HandleWithRepPrefix(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 1; // skip F2/F3
        if ((ip[offs] & 0xF0) == 0x40) offs++; // skip REX
        byte opcode = ip[offs];

        switch (opcode)
        {
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0xAE: case 0xAF:
                return MiscHandler.HandleStringOp(ctx, ip, log);
            default:
                log($"Unsupported REP-prefixed opcode 0x{opcode:X2}", 2);
                return false;
        }
    }

    /// <summary>Handle two-byte opcodes (0F xx).</summary>
    private static bool HandleTwoByteOpcode(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        // Find 0F byte position
        int offs = 0;
        while (ip[offs] != 0x0F)
        {
            if (offs > 4) return false; // too many prefixes
            offs++;
        }
        byte op2 = ip[offs + 1];

        switch (op2)
        {
            // Jcc near (0F 80-8F)
            case >= 0x80 and <= 0x8F:
                return ControlFlowHandler.HandleJccNear(ctx, ip, log);

            // SETcc (0F 90-9F)
            case >= 0x90 and <= 0x9F:
                return MoveHandler.HandleSetcc(ctx, ip, log);

            // CMOVcc (0F 40-4F)
            case >= 0x40 and <= 0x4F:
                return MoveHandler.HandleCmovcc(ctx, ip, log);

            // MOVZX (0F B6, 0F B7)
            case 0xB6: case 0xB7:
                return MoveHandler.HandleMovzx(ctx, ip, log);

            // MOVSX (0F BE, 0F BF)
            case 0xBE: case 0xBF:
                return MoveHandler.HandleMovsx(ctx, ip, log);

            // IMUL r, r/m (0F AF)
            case 0xAF:
                return ArithmeticHandler.HandleImul2(ctx, ip, log);

            // BSWAP (0F C8-CF)
            case >= 0xC8 and <= 0xCF:
                return MoveHandler.HandleBswap(ctx, ip, log);

            // BT/BTS/BTR/BTC r/m, r (0F A3, 0F AB, 0F B3, 0F BB)
            case 0xA3: case 0xAB: case 0xB3: case 0xBB:
                return MiscHandler.HandleBitTest(ctx, ip, log);

            // BT/BTS/BTR/BTC r/m, imm8 (0F BA /4-/7)
            case 0xBA:
                return MiscHandler.HandleBitTestImm(ctx, ip, log);

            // BSF/BSR (0F BC, 0F BD)
            case 0xBC: case 0xBD:
                return MiscHandler.HandleBsfBsr(ctx, ip, log);

            // Multi-byte NOP (0F 1F)
            case 0x1F:
                return MiscHandler.HandleMultiByteNop(ctx, ip, log);

            default:
                log($"Unsupported two-byte opcode 0F {op2:X2}", 2);
                return false;
        }
    }

    // === Structs ===

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

    // === Logging helpers ===

    private static string FormatBytes(byte* address, int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++) bytes[i] = *(address + i);
        return string.Join(" ", bytes.Select(b => $"{b:X2}"));
    }

    private struct RegSnapshot
    {
        public ulong Rax, Rbx, Rcx, Rdx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public uint EFlags;
        public ulong Rip;

        public static RegSnapshot FromContext(CONTEXT* ctx) => new()
        {
            Rax = ctx->Rax, Rbx = ctx->Rbx, Rcx = ctx->Rcx, Rdx = ctx->Rdx,
            Rsp = ctx->Rsp, Rbp = ctx->Rbp, Rsi = ctx->Rsi, Rdi = ctx->Rdi,
            R8 = ctx->R8, R9 = ctx->R9, R10 = ctx->R10, R11 = ctx->R11,
            R12 = ctx->R12, R13 = ctx->R13, R14 = ctx->R14, R15 = ctx->R15,
            EFlags = ctx->EFlags, Rip = ctx->Rip
        };
    }

    private static string FormatRegisterDiff(RegSnapshot before, RegSnapshot after)
    {
        var sb = new StringBuilder();
        void diff(string name, ulong b, ulong a) { if (b != a) sb.Append($" {name}:0x{b:X}->0x{a:X}"); }
        diff("RAX", before.Rax, after.Rax); diff("RBX", before.Rbx, after.Rbx);
        diff("RCX", before.Rcx, after.Rcx); diff("RDX", before.Rdx, after.Rdx);
        diff("RSP", before.Rsp, after.Rsp); diff("RBP", before.Rbp, after.Rbp);
        diff("RSI", before.Rsi, after.Rsi); diff("RDI", before.Rdi, after.Rdi);
        diff("R8", before.R8, after.R8); diff("R9", before.R9, after.R9);
        diff("R10", before.R10, after.R10); diff("R11", before.R11, after.R11);
        diff("R12", before.R12, after.R12); diff("R13", before.R13, after.R13);
        diff("R14", before.R14, after.R14); diff("R15", before.R15, after.R15);
        if (before.EFlags != after.EFlags) sb.Append($" EFlags:0x{before.EFlags:X}->0x{after.EFlags:X}");
        return sb.ToString();
    }
}
