using NoRWX.Handlers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Markup;

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
            string bytes = FormatBytes(address, instrLen);
            string instrAddr = $"0x{before.Rip:X}";
            var afterSnap = RegSnapshot.FromContext(ctx);
            string diff = FormatRegisterDiff(before, afterSnap);
            string log = $"[{instrAddr}] [{bytes}] {mnemonic} | {(diff.Length > 0 ? " => " + diff : "")}";
            Console.WriteLine(log);
            //File.AppendAllText("emulator_log.txt", log + Environment.NewLine);
        }

        byte opcode = *address;
        
        switch (opcode)
        {
            case 0xC1: return ALUOperations.HandleShiftRm32Imm8(ctx, address, Log);
            case 0x01: return ALUOperations.HandleAddEvGv32(ctx, address, Log);
            // Stack operations
            case >= X64Opcodes.PUSH_RAX and <= X64Opcodes.PUSH_RDI: // PUSH RAX–RDI
                {
                    int reg = opcode - 0x50; // 0..7
                    ulong value = *(&ctx->Rax + reg);
                    if (reg == 4) value = ctx->Rsp; // special rule
                    return StackOperations.Push(ctx, value, $"R{reg}", Log);
                }

            case >= X64Opcodes.POP_RAX and <= X64Opcodes.POP_RDI: // POP RAX–RDI
                {
                    int reg = opcode - 0x58;
                    return StackOperations.Pop(ctx, reg, Log);
                }

            case X64Opcodes.REX_B_GROUP when *(address + 1) is >= 0x50 and <= 0x57: // PUSH R8–R15 (REX.B=1)
                {
                    int reg = *(address + 1) - 0x50 + 8;
                    ulong value = *(&ctx->Rax + reg);
                    return StackOperations.Push(ctx, value, $"R{reg}", Log, instrLen: 2);
                }

            case X64Opcodes.REX_B_GROUP when *(address + 1) is >= 0x58 and <= 0x5F: // POP R8–R15 (REX.B=1)
                {
                    int reg = *(address + 1) - 0x58 + 8;
                    return StackOperations.Pop(ctx, reg, Log, instrLen: 2);
                }
            case X64Opcodes.PUSH_IMM8: // PUSH imm8 (6A ib)
                {
                    sbyte imm8 = *(sbyte*)(address + 1);
                    ulong value = (ulong)(long)imm8; // sign-extend
                    ctx->Rsp -= 8;
                    *(ulong*)ctx->Rsp = value;
                    Log($"PUSH imm8 (0x{(byte)imm8:X2}) => 0x{value:X}", 2);
                    ctx->Rip += 2;
                    return true;
                }

            case X64Opcodes.PUSH_IMM32: // PUSH imm32 (68 id)
                {
                    uint imm32 = *(uint*)(address + 1);
                    ulong value = imm32; // zero-extend
                    ctx->Rsp -= 8;
                    *(ulong*)ctx->Rsp = value;
                    Log($"PUSH imm32 (0x{imm32:X8})", 5);
                    ctx->Rip += 5;
                    return true;
                }
            case X64Opcodes.PUSH_RM64: // PUSH r/m64 (FF /6)
                {
                    byte modrm = *(address + 1);
                    int regop = modrm >> 3 & 0x7;

                    if (regop == 6)
                    {
                        ulong value = StackOperations.ReadRm64(ctx, address + 1, out int len);
                        ctx->Rsp -= 8;
                        *(ulong*)ctx->Rsp = value;
                        Log($"PUSH r/m64 (0x{value:X})", len + 1);
                        ctx->Rip += (ulong)(len + 1);
                        return true;
                    }
                    Log($"Unsupported opcode 0x{opcode:X2}", 32);
                    return false;
                }
            case X64Opcodes.POP_RM64: // POP r/m64 (8F /0)
                {
                    byte modrm = *(address + 1);
                    int regop = modrm >> 3 & 0x7;

                    if (regop == 0)
                    {
                        ulong value = *(ulong*)ctx->Rsp;
                        ctx->Rsp += 8;
                        StackOperations.WriteRm64(ctx, address + 1, value, out int len);
                        Log($"POP r/m64 => 0x{value:X}", len + 1);
                        ctx->Rip += (ulong)(len + 1);
                        return true;
                    }
                    Log($"Unsupported opcode 0x{opcode:X2}", 32);
                    return false;
                }
            // Prefixes and two-byte opcodes
            case X64Opcodes.GS_PREFIX: return Prefixes.HandleGsPrefix(ctx, address, Log);
            // Handle operand-size prefix TEST (0x66 85 /r)
            case X64Opcodes.OPSIZE_PREFIX when *(address + 1) == 0x85:
                return ALUOperations.HandleTestEwGw(ctx, address, Log);
            case X64Opcodes.OPSIZE_PREFIX:
                return Prefixes.HandleOperandSizePrefix(ctx, address, Log);
            case X64Opcodes.REX_PREFIX:
            case X64Opcodes.REX_B_GROUP:
            case X64Opcodes.REX_R_GROUP:
            case X64Opcodes.REX_W_GROUP:
                {
                    byte next = *(address + 1);
                    if (next == 0x83) // REX.W prefixed ADD r/m64, imm8
                    {
                        byte modrm = *(address + 2);
                        byte regField = (byte)(modrm >> 3 & 0x7);
                        if (regField == 0) // /0 = ADD
                            return ALUOperations.HandleAddRm64Imm8(ctx, address, Log);
                    }
                    byte rex = *address;                     // 0x4X
                    bool W = (rex & 0x08) != 0;
                    bool R = (rex & 0x04) != 0;
                    bool X = (rex & 0x02) != 0;
                    bool B = (rex & 0x01) != 0;

                    byte op2 = *(address + 1);
                    byte op3 = *(address + 2);

                    // 1) trivial PUSH/POP R8..R15
                    if (Rex.HandlePushPopExt(ctx, address, Log, op2)) return true;

                    // 2) tiny special cases
                    if (Rex.HandleMovRbpRsp(ctx, address, Log, op2, op3)) return true;
                    if (Rex.HandleSubRspImm8(ctx, address, Log, op2, op3)) return true;

                    // 3) grouped/common patterns
                    if (Rex.HandleGroup1_81(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleGroup2Shift(ctx, address, Log, W, R, X, B)) return true;   // 48 C1 /r ib
                    if (Rex.HandleMovImm(ctx, address, Log, W, X, B, op2)) return true;
                    if (Rex.HandleAndRspImm8(ctx, address, Log, op2, op3)) return true;
                    if (Rex.HandleSubRspImm32(ctx, address, Log, op2, op3)) return true;
                    if (Rex.HandleMovRaxFromRsp(ctx, address, Log, op2, op3)) return true;

                    if (Rex.HandleMovRm32R32(ctx, address, Log, W, R, X, B)) return true; // 41 89 /r
                    if (Rex.HandleMovRm64R64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleGroup1_83(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleMovR64Rm64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleLeaRdxRip(ctx, address, Log, op2, op3)) return true;
                    if (Rex.HandleSubRm64R64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleLeaRm64R64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleAddRm64R64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleMovRegImm(ctx, address, Log, rex, B, op2)) return true;
                    if (Rex.HandleAddRaxImm(ctx, address, Log, W, op2)) return true;
                    if (Rex.HandleGroup5_FF(ctx, address, Log, R, X, B, op2)) return true;

                    if (Rex.HandleTestRm64R64(ctx, address, Log, W, R, X, B, op2)) return true;
                    if (Rex.HandleMovsxdRm32R64(ctx, address, Log, op2)) return true;

                    if (Rex.HandleCdqe(ctx, address, Log, W, op2)) return true; // 48 98
                    if (Rex.HandleCqo(ctx, address, Log, W, op2)) return true;  // 48 99
                    if (Rex.HandleCmpEvGv(ctx, address, Log, R, X, B, op2)) return true; // 48 39 /r
                    if (Rex.HandleCmpGvEv(ctx, address, Log, R, X, B, op2)) return true; // 48 3B /r

                    if (op2 == 0x31) return Rex.HandleXorRm64R64(ctx, address, Log);

                    // fallback
                    Log($"Unsupported REX-prefixed opcode 0x{rex:X2} 0x{op2:X2} 0x{op3:X2}", 3);
                    return false;
                }
           
            // Control flow operations
            case X64Opcodes.CALL: return ControlFlow.HandleCall(ctx, address, Log);
            case X64Opcodes.RET: return ControlFlow.HandleRet(ctx, address, Log);
            case X64Opcodes.LEAVE: return ControlFlow.HandleLeave(ctx, Log);
            case X64Opcodes.JMP_NEAR: return ControlFlow.HandleJmpNear(ctx, address, Log);
            case X64Opcodes.JMP_SHORT: return ControlFlow.HandleJmpShort(ctx, address, Log);
            case X64Opcodes.JE_SHORT: return ControlFlow.HandleJeShort(ctx, address, Log);
            case X64Opcodes.JNE_SHORT: return ControlFlow.HandleJneShort(ctx, address, Log);
            case X64Opcodes.JBE_SHORT: return ControlFlow.HandleJbeShort(ctx, address, Log);
            case X64Opcodes.JA_SHORT: return ControlFlow.HandleJaShort(ctx, address, Log);
            case >= X64Opcodes.JO_SHORT and <= X64Opcodes.JG_SHORT:
                return ControlFlow.HandleShortConditionalJump(ctx, address, Log);
            case X64Opcodes.TWO_BYTE:
                {
                    byte op2 = *(address + 1);
                    switch (op2)
                    {
                        case >= 0x80 and <= 0x8F: return ControlFlow.HandleTwoByteConditionalJump(ctx, address, Log); //DDD
                        case 0xB6: return ControlFlow.HandleMovzxGvEb32(ctx, address, Log);   // MOVZX r32, r/m8
                        case 0xB7: return ControlFlow.HandleMovzxGvEw32(ctx, address, Log);   // MOVZX r32, r/m16
                        case X64Opcodes.SETE: return TwoByteOpcodes.HandleSetcc(ctx, address, Log);
                        case 0xBE: return ControlFlow.HandleMovsxGvEb32(ctx, address, Log);
                        default:
                            Log($"Unsupported opcode 0x{opcode:X2}", 32);
                            return false;
                    }
                }
            // Mov operations
            case X64Opcodes.MOV_Ev_Gv: return MoveOperations.HandleMovEvGv32(ctx, address, Log);
            case X64Opcodes.MOV_RM32_IMM32: return MoveOperations.HandleMovRm32Imm32(ctx, address, Log);
            case X64Opcodes.MOV_R32_RM32: return MoveOperations.HandleMovR32Rm32(ctx, address, Log);
            case X64Opcodes.MOV_RM8_IMM8: return MoveOperations.HandleMovRm8Imm8(ctx, address, Log);

            // MOV r64, imm64 (B8–BF)
            case >= X64Opcodes.MOV_RAX_IMM64 and <= X64Opcodes.MOV_RDI_IMM64:
                return MoveOperations.HandleMovImmToReg(ctx, address, Log);
            // Arithmetic and logic operations
            case X64Opcodes.ADD_R32_RM32: return ALUOperations.HandleAddGvEv(ctx, address, Log);
            case X64Opcodes.XOR_R32_RM32: return ALUOperations.HandleXorRvEv(ctx, address, Log);
            case X64Opcodes.ADD_RM8_R8: return ALUOperations.HandleAddRm8R8(ctx, address, Log);
            case X64Opcodes.TEST_RM8_R8: return ALUOperations.HandleTestRm8R8(ctx, address, Log);
            case X64Opcodes.TEST_RM32_R32: return ALUOperations.HandleTestRm32R32(ctx, address, Log);
            case X64Opcodes.INCDEC_RM8: return ALUOperations.HandleIncDecRm8(ctx, address, Log);
            case X64Opcodes.GRP1_EdIb: return ALUOperations.HandleGroup1_EdIb(ctx, address, Log);
         
            // Miscellaneous operations
            case X64Opcodes.NOP:
                return Miscellaneous.HandleNop(ctx, Log);

            case X64Opcodes.CMP_AL_IMM8:
                return Miscellaneous.HandleCmpAlImm8(ctx, address, Log);

            case X64Opcodes.CMP_RM32_R32:
                return Miscellaneous.HandleCmpEvGv32(ctx, address, Log);

            case X64Opcodes.MOV_RM8_R8:
                return Miscellaneous.HandleMovRm8R8(ctx, address, Log); // MOV r/m8,r8

            case X64Opcodes.MOV_R8_RM8:
                return Miscellaneous.HandleMovR8Rm8(ctx, address, Log); // MOV r8,r/m8

            case X64Opcodes.CMP_RM8_R8:
                return Miscellaneous.HandleCmpEvGv8(ctx, address, Log); // CMP r/m8, r8

            case X64Opcodes.CMP_R8_RM8:
                return Miscellaneous.HandleCmpGvEv8(ctx, address, Log); // CMP r8, r/m8
            default:
                Log($"Unsupported opcode 0x{opcode:X2}", 32);
                return false;
        }
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