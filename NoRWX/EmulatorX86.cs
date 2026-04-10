using NoRWX.Core;
using NoRWX.Handlers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace NoRWX;

/// <summary>
/// i386 (32-bit x86) instruction emulator. Runs 32-bit position-independent code
/// by decoding and emulating instructions using a 32-bit register context.
///
/// Key differences from x64:
/// - 0x40-0x4F = INC/DEC r32 (not REX prefixes)
/// - No R8-R15 extended registers
/// - Default operand size = 32-bit, 0x66 switches to 16-bit
/// - Default address size = 32-bit, 0x67 switches to 16-bit
/// - Stack push/pop = 4 bytes (not 8)
/// - No RIP-relative addressing (mod=00 rm=101 = disp32 absolute)
/// - CALL/RET use 4-byte addresses
/// </summary>
public static unsafe class EmulatorX86
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT32
    {
        public uint EFlags;
        public uint Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi;
        public uint Eip;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint MxCsr;
    }

    private static readonly Action<string, int> _noopLog = static (_, _) => { };
    public static bool EnableLogging = true;

    /// <summary>
    /// Emulate a single i386 instruction at the given address.
    /// Returns true if the instruction was successfully emulated.
    /// </summary>
    public static bool Emulate(CONTEXT32* ctx, byte* address)
    {
        Action<string, int> Log = _noopLog;
        if (EnableLogging)
        {
            Log = (string mnemonic, int instrLen) =>
            {
                Console.WriteLine($"[0x{ctx->Eip:X8}] {mnemonic}");
            };
        }

        byte opcode = *address;

        switch (opcode)
        {
            // === NOP ===
            case 0x90:
                Log("NOP", 1);
                ctx->Eip += 1;
                return true;

            // === INC r32 (0x40-0x47) — this is i386-specific, NOT REX! ===
            case >= 0x40 and <= 0x47:
            {
                int reg = opcode - 0x40;
                uint* r = GetReg(ctx, reg);
                uint old = *r;
                *r = old + 1;
                ctx->EFlags = FlagsCalculator.SetIncFlags(ctx->EFlags, old, *r, 32);
                Log($"INC {RegName32(reg)}", 1);
                ctx->Eip += 1;
                return true;
            }

            // === DEC r32 (0x48-0x4F) ===
            case >= 0x48 and <= 0x4F:
            {
                int reg = opcode - 0x48;
                uint* r = GetReg(ctx, reg);
                uint old = *r;
                *r = old - 1;
                ctx->EFlags = FlagsCalculator.SetDecFlags(ctx->EFlags, old, *r, 32);
                Log($"DEC {RegName32(reg)}", 1);
                ctx->Eip += 1;
                return true;
            }

            // === PUSH r32 (0x50-0x57) ===
            case >= 0x50 and <= 0x57:
            {
                int reg = opcode - 0x50;
                uint val = *GetReg(ctx, reg);
                Push32(ctx, val);
                Log($"PUSH {RegName32(reg)}", 1);
                ctx->Eip += 1;
                return true;
            }

            // === POP r32 (0x58-0x5F) ===
            case >= 0x58 and <= 0x5F:
            {
                int reg = opcode - 0x58;
                uint val = Pop32(ctx);
                *GetReg(ctx, reg) = val;
                Log($"POP {RegName32(reg)}", 1);
                ctx->Eip += 1;
                return true;
            }

            // === PUSH imm8 (0x6A) ===
            case 0x6A:
            {
                sbyte imm = *(sbyte*)(address + 1);
                Push32(ctx, (uint)(int)imm); // sign-extend to 32
                Log($"PUSH imm8 0x{(byte)imm:X2}", 2);
                ctx->Eip += 2;
                return true;
            }

            // === PUSH imm32 (0x68) ===
            case 0x68:
            {
                uint imm = *(uint*)(address + 1);
                Push32(ctx, imm);
                Log($"PUSH imm32 0x{imm:X8}", 5);
                ctx->Eip += 5;
                return true;
            }

            // === MOV r/m32, r32 (0x89) / MOV r/m8, r8 (0x88) ===
            case 0x88: case 0x89:
            {
                int offs = 1;
                int opSize = opcode == 0x88 ? 8 : 32;
                return HandleRmR_Store(ctx, address, ref offs, opSize, Log);
            }

            // === MOV r32, r/m32 (0x8B) / MOV r8, r/m8 (0x8A) ===
            case 0x8A: case 0x8B:
            {
                int offs = 1;
                int opSize = opcode == 0x8A ? 8 : 32;
                return HandleRRm_Load(ctx, address, ref offs, opSize, Log, "MOV");
            }

            // === MOV r/m32, imm32 (0xC7 /0) / MOV r/m8, imm8 (0xC6 /0) ===
            case 0xC6: case 0xC7:
            {
                int offs = 1;
                int opSize = opcode == 0xC6 ? 8 : 32;
                byte modrm = address[offs++];
                byte mod = (byte)(modrm >> 6 & 3);
                int rm = modrm & 7;
                if (((modrm >> 3) & 7) != 0) return false;

                uint addr = 0;
                bool isMem = mod != 0b11;
                if (isMem) addr = ResolveEA32(ctx, address, ref offs, mod, rm);

                uint imm;
                if (opSize == 8) { imm = address[offs++]; }
                else { imm = *(uint*)(address + offs); offs += 4; }

                if (isMem) WriteMemSized(addr, imm, opSize);
                else WriteSized32(ctx, rm, imm, opSize);

                Log($"MOV r/m{opSize}, imm", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // === MOV r32, imm32 (0xB8-0xBF) ===
            case >= 0xB8 and <= 0xBF:
            {
                int reg = opcode - 0xB8;
                uint imm = *(uint*)(address + 1);
                *GetReg(ctx, reg) = imm;
                Log($"MOV {RegName32(reg)}, 0x{imm:X8}", 5);
                ctx->Eip += 5;
                return true;
            }

            // === MOV r8, imm8 (0xB0-0xB7) ===
            case >= 0xB0 and <= 0xB7:
            {
                int reg = opcode - 0xB0;
                byte imm = address[1];
                WriteReg8(ctx, reg, imm);
                Log($"MOV {RegName8(reg)}, 0x{imm:X2}", 2);
                ctx->Eip += 2;
                return true;
            }

            // === LEA r32, m (0x8D) ===
            case 0x8D:
            {
                int offs = 1;
                byte modrm = address[offs++];
                byte mod = (byte)(modrm >> 6 & 3);
                int reg = (modrm >> 3) & 7;
                int rm = modrm & 7;
                uint ea = ResolveEA32(ctx, address, ref offs, mod, rm);
                *GetReg(ctx, reg) = ea;
                Log($"LEA {RegName32(reg)}, [0x{ea:X8}]", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // === ADD ===
            case 0x00: case 0x01: return HandleAluRmR(ctx, address, 0, opcode, Log); // ADD r/m, r
            case 0x02: case 0x03: return HandleAluRRm(ctx, address, 0, opcode, Log); // ADD r, r/m
            case 0x04: return HandleAluAccImm8(ctx, address, 0, Log);
            case 0x05: return HandleAluAccImm32(ctx, address, 0, Log);

            // === OR ===
            case 0x08: case 0x09: return HandleAluRmR(ctx, address, 1, opcode, Log);
            case 0x0A: case 0x0B: return HandleAluRRm(ctx, address, 1, opcode, Log);
            case 0x0C: return HandleAluAccImm8(ctx, address, 1, Log);
            case 0x0D: return HandleAluAccImm32(ctx, address, 1, Log);

            // === AND ===
            case 0x20: case 0x21: return HandleAluRmR(ctx, address, 4, opcode, Log);
            case 0x22: case 0x23: return HandleAluRRm(ctx, address, 4, opcode, Log);
            case 0x24: return HandleAluAccImm8(ctx, address, 4, Log);
            case 0x25: return HandleAluAccImm32(ctx, address, 4, Log);

            // === SUB ===
            case 0x28: case 0x29: return HandleAluRmR(ctx, address, 5, opcode, Log);
            case 0x2A: case 0x2B: return HandleAluRRm(ctx, address, 5, opcode, Log);
            case 0x2C: return HandleAluAccImm8(ctx, address, 5, Log);
            case 0x2D: return HandleAluAccImm32(ctx, address, 5, Log);

            // === XOR ===
            case 0x30: case 0x31: return HandleAluRmR(ctx, address, 6, opcode, Log);
            case 0x32: case 0x33: return HandleAluRRm(ctx, address, 6, opcode, Log);
            case 0x34: return HandleAluAccImm8(ctx, address, 6, Log);
            case 0x35: return HandleAluAccImm32(ctx, address, 6, Log);

            // === CMP ===
            case 0x38: case 0x39: return HandleAluRmR(ctx, address, 7, opcode, Log);
            case 0x3A: case 0x3B: return HandleAluRRm(ctx, address, 7, opcode, Log);
            case 0x3C: return HandleAluAccImm8(ctx, address, 7, Log);
            case 0x3D: return HandleAluAccImm32(ctx, address, 7, Log);

            // === TEST ===
            case 0x84: case 0x85: return HandleTestRmR(ctx, address, opcode, Log);
            case 0xA8: { byte imm = address[1]; uint r = ctx->Eax & imm; ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, r, 8); Log("TEST AL, imm8", 2); ctx->Eip += 2; return true; }
            case 0xA9: { uint imm = *(uint*)(address + 1); uint r = ctx->Eax & imm; ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, r, 32); Log("TEST EAX, imm32", 5); ctx->Eip += 5; return true; }

            // === XCHG ===
            case 0x86: case 0x87: return HandleXchg32(ctx, address, opcode, Log);
            case >= 0x91 and <= 0x97:
            {
                int reg = opcode - 0x90;
                uint tmp = ctx->Eax;
                ctx->Eax = *GetReg(ctx, reg);
                *GetReg(ctx, reg) = tmp;
                Log($"XCHG EAX, {RegName32(reg)}", 1);
                ctx->Eip += 1;
                return true;
            }

            // === Group 1: 80/81/83 ===
            case 0x80: case 0x81: case 0x83: return HandleGroup1_32(ctx, address, opcode, Log);

            // === Group 2: Shifts C0/C1/D0/D1/D2/D3 ===
            case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
                return HandleGroup2_32(ctx, address, opcode, Log);

            // === Group 3: F6/F7 (TEST/NOT/NEG/MUL/DIV) ===
            case 0xF6: case 0xF7: return HandleGroup3_32(ctx, address, opcode, Log);

            // === INC/DEC r/m8 (FE) ===
            case 0xFE: return HandleIncDec8_32(ctx, address, Log);

            // === Group 5: FF (INC/DEC/CALL/JMP/PUSH r/m32) ===
            case 0xFF: return HandleGroup5_32(ctx, address, Log);

            // === IMUL ===
            case 0x69: case 0x6B: return HandleImul3_32(ctx, address, opcode, Log);

            // === CBW/CWDE (0x98) ===
            case 0x98:
                ctx->Eax = (uint)(int)(short)(ushort)ctx->Eax; // CWDE: AX → EAX
                Log("CWDE", 1); ctx->Eip += 1; return true;

            // === CDQ (0x99) ===
            case 0x99:
                ctx->Edx = (int)ctx->Eax < 0 ? 0xFFFFFFFF : 0;
                Log("CDQ", 1); ctx->Eip += 1; return true;

            // === Control flow ===
            case 0xE8: // CALL rel32
            {
                int rel32 = *(int*)(address + 1);
                uint retAddr = ctx->Eip + 5;
                Push32(ctx, retAddr);
                ctx->Eip = (uint)((int)retAddr + rel32);
                Log($"CALL 0x{ctx->Eip:X8}", 5);
                return true;
            }
            case 0xC3: // RET
            {
                ctx->Eip = Pop32(ctx);
                Log($"RET => 0x{ctx->Eip:X8}", 1);
                return true;
            }
            case 0xC2: // RET imm16
            {
                ctx->Eip = Pop32(ctx);
                ushort adj = *(ushort*)(address + 1);
                ctx->Esp += adj;
                Log($"RET {adj}", 3);
                return true;
            }
            case 0xC9: // LEAVE
            {
                ctx->Esp = ctx->Ebp;
                ctx->Ebp = Pop32(ctx);
                Log("LEAVE", 1); ctx->Eip += 1; return true;
            }
            case 0xC8: // ENTER imm16, imm8
            {
                ushort allocSize = *(ushort*)(address + 1);
                byte nesting = address[3];
                Push32(ctx, ctx->Ebp);
                ctx->Ebp = ctx->Esp;
                ctx->Esp -= allocSize;
                Log($"ENTER {allocSize}, {nesting}", 4);
                ctx->Eip += 4;
                return true;
            }

            // === JMP ===
            case 0xE9: { int rel32 = *(int*)(address + 1); ctx->Eip = (uint)((int)(ctx->Eip + 5) + rel32); Log("JMP near", 5); return true; }
            case 0xEB: { sbyte rel8 = *(sbyte*)(address + 1); ctx->Eip = (uint)((int)(ctx->Eip + 2) + rel8); Log("JMP short", 2); return true; }

            // === Jcc short (0x70-0x7F) ===
            case >= 0x70 and <= 0x7F:
            {
                int cc = opcode & 0xF;
                sbyte rel8 = *(sbyte*)(address + 1);
                uint next = ctx->Eip + 2;
                uint target = (uint)((int)next + rel8);
                bool taken = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);
                ctx->Eip = taken ? target : next;
                Log($"J{InstructionDecoder.ConditionName(cc)} short", 2);
                return true;
            }

            // === LOOP/LOOPE/LOOPNE ===
            case 0xE0: case 0xE1: case 0xE2:
            {
                sbyte rel8 = *(sbyte*)(address + 1);
                uint next = ctx->Eip + 2;
                uint target = (uint)((int)next + rel8);
                ctx->Ecx--;
                bool zf = (ctx->EFlags & FlagsCalculator.ZF) != 0;
                bool taken = opcode switch { 0xE0 => ctx->Ecx != 0 && !zf, 0xE1 => ctx->Ecx != 0 && zf, _ => ctx->Ecx != 0 };
                ctx->Eip = taken ? target : next;
                Log("LOOP", 2);
                return true;
            }

            // === JECXZ ===
            case 0xE3:
            {
                sbyte rel8 = *(sbyte*)(address + 1);
                uint next = ctx->Eip + 2;
                uint target = (uint)((int)next + rel8);
                ctx->Eip = ctx->Ecx == 0 ? target : next;
                Log("JECXZ", 2);
                return true;
            }

            // === INT3/INT/HLT ===
            case 0xCC: Log("INT3", 1); ctx->Eip += 1; return true;
            case 0xCD: Log($"INT 0x{address[1]:X2}", 2); ctx->Eip += 2; return true;
            case 0xF4: Log("HLT", 1); return false;

            // === Flags ===
            case 0xF5: ctx->EFlags ^= FlagsCalculator.CF; Log("CMC", 1); ctx->Eip += 1; return true;
            case 0xF8: ctx->EFlags &= ~FlagsCalculator.CF; Log("CLC", 1); ctx->Eip += 1; return true;
            case 0xF9: ctx->EFlags |= FlagsCalculator.CF; Log("STC", 1); ctx->Eip += 1; return true;
            case 0xFC: ctx->EFlags &= ~FlagsCalculator.DF; Log("CLD", 1); ctx->Eip += 1; return true;
            case 0xFD: ctx->EFlags |= FlagsCalculator.DF; Log("STD", 1); ctx->Eip += 1; return true;
            case 0x9C: Push32(ctx, ctx->EFlags); Log("PUSHFD", 1); ctx->Eip += 1; return true;
            case 0x9D: ctx->EFlags = Pop32(ctx); Log("POPFD", 1); ctx->Eip += 1; return true;
            case 0x9E: ctx->EFlags = (ctx->EFlags & ~0xFFu) | (ctx->Eax >> 8 & 0xFF); Log("SAHF", 1); ctx->Eip += 1; return true;
            case 0x9F: ctx->Eax = (ctx->Eax & ~0xFF00u) | ((ctx->EFlags & 0xFF) << 8); Log("LAHF", 1); ctx->Eip += 1; return true;

            // === MOV moffs ===
            case 0xA0: { uint a = *(uint*)(address+1); ctx->Eax = (ctx->Eax & ~0xFFu) | *(byte*)a; Log("MOV AL, moffs8", 5); ctx->Eip += 5; return true; }
            case 0xA1: { uint a = *(uint*)(address+1); ctx->Eax = *(uint*)a; Log("MOV EAX, moffs32", 5); ctx->Eip += 5; return true; }
            case 0xA2: { uint a = *(uint*)(address+1); *(byte*)a = (byte)ctx->Eax; Log("MOV moffs8, AL", 5); ctx->Eip += 5; return true; }
            case 0xA3: { uint a = *(uint*)(address+1); *(uint*)a = ctx->Eax; Log("MOV moffs32, EAX", 5); ctx->Eip += 5; return true; }

            // === String ops ===
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0xAE: case 0xAF:
                return HandleStringOp32(ctx, address, false, false, Log);

            // === Operand-size prefix (0x66) ===
            case 0x66:
            {
                // 16-bit operand override — recurse with next byte
                // Most common: 66 + MOV/ADD/CMP with 16-bit operands
                // For now, skip prefix and handle next opcode (simplified)
                Log("66 prefix (16-bit)", 1);
                ctx->Eip += 1;
                return Emulate(ctx, address + 1);
            }

            // === REP/REPNE ===
            case 0xF2: case 0xF3:
            {
                byte next = address[1];
                if (next >= 0xA4 && next <= 0xAF)
                    return HandleStringOp32(ctx, address + 1, opcode == 0xF3, opcode == 0xF2, Log);
                Log($"REP 0x{next:X2} (unsupported)", 2);
                ctx->Eip += 1;
                return Emulate(ctx, address + 1);
            }

            // === LOCK prefix ===
            case 0xF0:
                ctx->Eip += 1;
                return Emulate(ctx, address + 1);

            // === Two-byte escape (0F) ===
            case 0x0F: return HandleTwoByte32(ctx, address, Log);

            // === Segment overrides (skip) ===
            case 0x26: case 0x2E: case 0x36: case 0x3E: case 0x64: case 0x65:
                ctx->Eip += 1;
                return Emulate(ctx, address + 1);

            default:
                if (EnableLogging)
                    Console.WriteLine($"i386 UNSUPPORTED: 0x{opcode:X2} at EIP=0x{ctx->Eip:X8}");
                return false;
        }
    }

    // ===================== Helpers =====================

    private static uint* GetReg(CONTEXT32* ctx, int idx) => idx switch
    {
        0 => &ctx->Eax, 1 => &ctx->Ecx, 2 => &ctx->Edx, 3 => &ctx->Ebx,
        4 => &ctx->Esp, 5 => &ctx->Ebp, 6 => &ctx->Esi, 7 => &ctx->Edi,
        _ => &ctx->Eax
    };

    private static uint ReadReg32(CONTEXT32* ctx, int idx) => *GetReg(ctx, idx);

    private static byte ReadReg8(CONTEXT32* ctx, int idx)
    {
        if (idx < 4) return (byte)*GetReg(ctx, idx);
        return (byte)(*GetReg(ctx, idx - 4) >> 8); // AH=4, CH=5, DH=6, BH=7
    }

    private static void WriteReg8(CONTEXT32* ctx, int idx, byte val)
    {
        uint* r;
        if (idx < 4) { r = GetReg(ctx, idx); *r = (*r & ~0xFFu) | val; }
        else { r = GetReg(ctx, idx - 4); *r = (*r & ~0xFF00u) | ((uint)val << 8); }
    }

    private static uint ReadSized32(CONTEXT32* ctx, int idx, int size)
    {
        if (size == 8) return ReadReg8(ctx, idx);
        return ReadReg32(ctx, idx);
    }

    private static void WriteSized32(CONTEXT32* ctx, int idx, uint val, int size)
    {
        if (size == 8) { WriteReg8(ctx, idx, (byte)val); return; }
        *GetReg(ctx, idx) = val;
    }

    private static uint ReadMemSized(uint addr, int size) => size == 8 ? *(byte*)addr : *(uint*)addr;
    private static void WriteMemSized(uint addr, uint val, int size) { if (size == 8) *(byte*)addr = (byte)val; else *(uint*)addr = val; }

    private static void Push32(CONTEXT32* ctx, uint val) { ctx->Esp -= 4; *(uint*)ctx->Esp = val; }
    private static uint Pop32(CONTEXT32* ctx) { uint v = *(uint*)ctx->Esp; ctx->Esp += 4; return v; }

    private static string RegName32(int i) => i switch { 0=>"EAX",1=>"ECX",2=>"EDX",3=>"EBX",4=>"ESP",5=>"EBP",6=>"ESI",7=>"EDI",_=>"?" };
    private static string RegName8(int i) => i switch { 0=>"AL",1=>"CL",2=>"DL",3=>"BL",4=>"AH",5=>"CH",6=>"DH",7=>"BH",_=>"?" };

    // ===================== 32-bit EA resolution (NO RIP-relative!) =====================

    private static uint ResolveEA32(CONTEXT32* ctx, byte* ip, ref int offs, byte mod, int rm)
    {
        // mod=00, rm=101 → disp32 absolute (NOT RIP-relative in 32-bit mode)
        if (mod == 0b00 && rm == 0b101)
        {
            uint disp32 = *(uint*)(ip + offs); offs += 4;
            return disp32;
        }

        // SIB (rm=100)
        if (rm == 0b100)
        {
            byte sib = ip[offs++];
            int scaleBits = sib >> 6;
            int idx = (sib >> 3) & 7;
            int bas = sib & 7;

            uint baseVal = (mod == 0b00 && bas == 0b101) ? 0 : ReadReg32(ctx, bas);
            uint indexVal = (idx == 0b100) ? 0 : ReadReg32(ctx, idx) << scaleBits;
            uint ea = baseVal + indexVal;

            if (mod == 0b00 && bas == 0b101) { ea += *(uint*)(ip + offs); offs += 4; }
            else if (mod == 0b01) { ea += (uint)(int)*(sbyte*)(ip + offs); offs += 1; }
            else if (mod == 0b10) { ea += *(uint*)(ip + offs); offs += 4; }
            return ea;
        }

        uint baseAddr = ReadReg32(ctx, rm);
        if (mod == 0b01) { baseAddr += (uint)(int)*(sbyte*)(ip + offs); offs += 1; }
        else if (mod == 0b10) { baseAddr += *(uint*)(ip + offs); offs += 4; }
        return baseAddr;
    }

    // ===================== Unified ALU handlers =====================

    private static uint DoAlu(uint a, uint b, int op, uint eflags, int size, out uint newFlags)
    {
        uint result;
        switch (op)
        {
            case 0: result = a + b; newFlags = FlagsCalculator.SetAddFlags(eflags, a, b, result, size); break;
            case 1: result = a | b; newFlags = FlagsCalculator.SetLogicFlags(eflags, result, size); break;
            case 2: { uint cf = (eflags & FlagsCalculator.CF) != 0 ? 1u : 0; result = a + b + cf; newFlags = FlagsCalculator.SetAddFlags(eflags, a, b, result, size, (int)cf); break; }
            case 3: { uint cf = (eflags & FlagsCalculator.CF) != 0 ? 1u : 0; result = a - b - cf; newFlags = FlagsCalculator.SetSubFlags(eflags, a, b, result, size, (int)cf); break; }
            case 4: result = a & b; newFlags = FlagsCalculator.SetLogicFlags(eflags, result, size); break;
            case 5: result = a - b; newFlags = FlagsCalculator.SetSubFlags(eflags, a, b, result, size); break;
            case 6: result = a ^ b; newFlags = FlagsCalculator.SetLogicFlags(eflags, result, size); break;
            case 7: result = a - b; newFlags = FlagsCalculator.SetSubFlags(eflags, a, b, result, size); break; // CMP
            default: result = a; newFlags = eflags; break;
        }
        return result;
    }

    private static readonly string[] AluNames = ["ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"];

    private static bool HandleAluRmR(CONTEXT32* ctx, byte* ip, int op, byte opcode, Action<string, int> log)
    {
        int offs = 1;
        int opSize = (opcode & 1) == 0 ? 8 : 32;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = (modrm >> 3) & 7;
        int rm = modrm & 7;

        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint dst = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
        uint src = ReadSized32(ctx, reg, opSize);

        uint result = DoAlu(dst, src, op, ctx->EFlags, opSize, out uint nf);
        ctx->EFlags = nf;
        if (op != 7) { if (isMem) WriteMemSized(addr, result, opSize); else WriteSized32(ctx, rm, result, opSize); }
        log($"{AluNames[op]} r/m{opSize}, r{opSize}", offs);
        ctx->Eip += (uint)offs;
        return true;
    }

    private static bool HandleAluRRm(CONTEXT32* ctx, byte* ip, int op, byte opcode, Action<string, int> log)
    {
        int offs = 1;
        int opSize = (opcode & 1) == 0 ? 8 : 32;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = (modrm >> 3) & 7;
        int rm = modrm & 7;

        uint dst = ReadSized32(ctx, reg, opSize);
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint src = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);

        uint result = DoAlu(dst, src, op, ctx->EFlags, opSize, out uint nf);
        ctx->EFlags = nf;
        if (op != 7) WriteSized32(ctx, reg, result, opSize);
        log($"{AluNames[op]} r{opSize}, r/m{opSize}", offs);
        ctx->Eip += (uint)offs;
        return true;
    }

    private static bool HandleAluAccImm8(CONTEXT32* ctx, byte* ip, int op, Action<string, int> log)
    {
        byte imm = ip[1];
        uint dst = (byte)ctx->Eax;
        uint result = DoAlu(dst, imm, op, ctx->EFlags, 8, out uint nf);
        ctx->EFlags = nf;
        if (op != 7) ctx->Eax = (ctx->Eax & ~0xFFu) | (result & 0xFF);
        log($"{AluNames[op]} AL, imm8", 2);
        ctx->Eip += 2;
        return true;
    }

    private static bool HandleAluAccImm32(CONTEXT32* ctx, byte* ip, int op, Action<string, int> log)
    {
        uint imm = *(uint*)(ip + 1);
        uint dst = ctx->Eax;
        uint result = DoAlu(dst, imm, op, ctx->EFlags, 32, out uint nf);
        ctx->EFlags = nf;
        if (op != 7) ctx->Eax = result;
        log($"{AluNames[op]} EAX, imm32", 5);
        ctx->Eip += 5;
        return true;
    }

    // ===================== Other handlers =====================

    private static bool HandleRmR_Store(CONTEXT32* ctx, byte* ip, ref int offs, int opSize, Action<string, int> log)
    {
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
        uint val = ReadSized32(ctx, reg, opSize);
        if (mod == 0b11) WriteSized32(ctx, rm, val, opSize);
        else { uint addr = ResolveEA32(ctx, ip, ref offs, mod, rm); WriteMemSized(addr, val, opSize); }
        log($"MOV r/m{opSize}, r{opSize}", offs);
        ctx->Eip += (uint)offs;
        return true;
    }

    private static bool HandleRRm_Load(CONTEXT32* ctx, byte* ip, ref int offs, int opSize, Action<string, int> log, string mnem)
    {
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint val = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
        WriteSized32(ctx, reg, val, opSize);
        log($"{mnem} r{opSize}, r/m{opSize}", offs);
        ctx->Eip += (uint)offs;
        return true;
    }

    private static bool HandleTestRmR(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1; int opSize = opcode == 0x84 ? 8 : 32;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint dst = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
        uint src = ReadSized32(ctx, reg, opSize);
        ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, dst & src, opSize);
        log($"TEST r/m{opSize}, r{opSize}", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleXchg32(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1; int opSize = opcode == 0x86 ? 8 : 32;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint a = ReadSized32(ctx, reg, opSize);
        uint b = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
        WriteSized32(ctx, reg, b, opSize);
        if (isMem) WriteMemSized(addr, a, opSize); else WriteSized32(ctx, rm, a, opSize);
        log($"XCHG r{opSize}, r/m{opSize}", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleGroup1_32(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1;
        int opSize = opcode == 0x80 ? 8 : 32;
        int immSize = opcode == 0x81 ? 32 : 8;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int grp = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint dst = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);

        uint imm;
        if (immSize == 8) { imm = (uint)(int)*(sbyte*)(ip + offs); offs += 1; }
        else { imm = *(uint*)(ip + offs); offs += 4; }

        uint result = DoAlu(dst, imm, grp, ctx->EFlags, opSize, out uint nf);
        ctx->EFlags = nf;
        if (grp != 7) { if (isMem) WriteMemSized(addr, result, opSize); else WriteSized32(ctx, rm, result, opSize); }
        log($"{AluNames[grp]} r/m{opSize}, imm{immSize}", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleGroup2_32(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1;
        int opSize = (opcode & 1) == 0 ? 8 : 32;
        bool by1 = opcode == 0xD0 || opcode == 0xD1;
        bool byCL = opcode == 0xD2 || opcode == 0xD3;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int sub = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint val = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
        byte count = by1 ? (byte)1 : byCL ? (byte)(ctx->Ecx & 0x1F) : (byte)(ip[offs++] & 0x1F);
        uint result = sub switch
        {
            0 => (val << count) | (val >> (opSize - count)),
            1 => (val >> count) | (val << (opSize - count)),
            4 or 6 => val << count,
            5 => val >> count,
            7 => opSize == 8 ? (uint)((sbyte)(byte)val >> count) : (uint)((int)val >> count),
            _ => val
        };
        if (isMem) WriteMemSized(addr, result, opSize); else WriteSized32(ctx, rm, result, opSize);
        if (count > 0 && sub >= 4) ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, result, opSize);
        string[] names = ["ROL","ROR","RCL","RCR","SHL","SHR","SHL","SAR"];
        log($"{names[sub]} r/m{opSize}, {count}", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleGroup3_32(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1; int opSize = opcode == 0xF6 ? 8 : 32;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int grp = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint val = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);

        switch (grp)
        {
            case 0: case 1: // TEST
                uint imm = opSize == 8 ? ip[offs++] : *(uint*)(ip + offs); if (opSize == 32) offs += 4;
                ctx->EFlags = FlagsCalculator.SetLogicFlags(ctx->EFlags, val & imm, opSize);
                break;
            case 2: // NOT
                uint r2 = ~val;
                if (isMem) WriteMemSized(addr, r2, opSize); else WriteSized32(ctx, rm, r2, opSize);
                break;
            case 3: // NEG
                uint r3 = 0 - val;
                if (isMem) WriteMemSized(addr, r3, opSize); else WriteSized32(ctx, rm, r3, opSize);
                ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, 0, val, r3, opSize);
                if (val != 0) ctx->EFlags |= FlagsCalculator.CF; else ctx->EFlags &= ~FlagsCalculator.CF;
                break;
            case 4: // MUL
                if (opSize == 8) { ushort r = (ushort)((byte)ctx->Eax * (byte)val); ctx->Eax = (ctx->Eax & ~0xFFFFu) | r; }
                else { ulong r = (ulong)ctx->Eax * val; ctx->Eax = (uint)r; ctx->Edx = (uint)(r >> 32); }
                break;
            case 5: // IMUL
                if (opSize == 8) { short r = (short)((sbyte)(byte)ctx->Eax * (sbyte)(byte)val); ctx->Eax = (ctx->Eax & ~0xFFFFu) | (ushort)r; }
                else { long r = (long)(int)ctx->Eax * (int)val; ctx->Eax = (uint)r; ctx->Edx = (uint)(r >> 32); }
                break;
            case 6: // DIV
                if (val == 0) return false;
                if (opSize == 8) { ushort d = (ushort)(ctx->Eax & 0xFFFF); ctx->Eax = (ctx->Eax & ~0xFFFFu) | (ushort)((byte)(d / (byte)val) | ((byte)(d % (byte)val) << 8)); }
                else { ulong d = ((ulong)ctx->Edx << 32) | ctx->Eax; ctx->Eax = (uint)(d / val); ctx->Edx = (uint)(d % val); }
                break;
            case 7: // IDIV
                if (val == 0) return false;
                if (opSize == 8) { short d = (short)(ushort)(ctx->Eax & 0xFFFF); sbyte q = (sbyte)(d / (sbyte)(byte)val); sbyte r = (sbyte)(d % (sbyte)(byte)val); ctx->Eax = (ctx->Eax & ~0xFFFFu) | (ushort)(byte)q | ((uint)(byte)r << 8); }
                else { long d = ((long)(int)ctx->Edx << 32) | ctx->Eax; ctx->Eax = (uint)(int)(d / (int)val); ctx->Edx = (uint)(int)(d % (int)val); }
                break;
        }
        string[] names = ["TEST","TEST","NOT","NEG","MUL","IMUL","DIV","IDIV"];
        log($"{names[grp]} r/m{opSize}", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleIncDec8_32(CONTEXT32* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 1;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int grp = (modrm >> 3) & 7; int rm = modrm & 7;
        if (grp != 0 && grp != 1) return false;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint val = isMem ? *(byte*)addr : ReadReg8(ctx, rm);
        uint result = grp == 0 ? val + 1 : val - 1;
        ctx->EFlags = grp == 0 ? FlagsCalculator.SetIncFlags(ctx->EFlags, val, result, 8) : FlagsCalculator.SetDecFlags(ctx->EFlags, val, result, 8);
        if (isMem) *(byte*)addr = (byte)result; else WriteReg8(ctx, rm, (byte)result);
        log(grp == 0 ? "INC r/m8" : "DEC r/m8", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleGroup5_32(CONTEXT32* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 1;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int grp = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        uint val = isMem ? *(uint*)addr : ReadReg32(ctx, rm);

        switch (grp)
        {
            case 0: // INC
                uint r0 = val + 1; ctx->EFlags = FlagsCalculator.SetIncFlags(ctx->EFlags, val, r0, 32);
                if (isMem) *(uint*)addr = r0; else *GetReg(ctx, rm) = r0;
                log("INC r/m32", offs); ctx->Eip += (uint)offs; return true;
            case 1: // DEC
                uint r1 = val - 1; ctx->EFlags = FlagsCalculator.SetDecFlags(ctx->EFlags, val, r1, 32);
                if (isMem) *(uint*)addr = r1; else *GetReg(ctx, rm) = r1;
                log("DEC r/m32", offs); ctx->Eip += (uint)offs; return true;
            case 2: // CALL r/m32
                Push32(ctx, ctx->Eip + (uint)offs);
                ctx->Eip = val;
                log($"CALL r/m32 => 0x{val:X8}", offs); return true;
            case 4: // JMP r/m32
                ctx->Eip = val;
                log($"JMP r/m32 => 0x{val:X8}", offs); return true;
            case 6: // PUSH r/m32
                Push32(ctx, val);
                log("PUSH r/m32", offs); ctx->Eip += (uint)offs; return true;
            default: return false;
        }
    }

    private static bool HandleImul3_32(CONTEXT32* ctx, byte* ip, byte opcode, Action<string, int> log)
    {
        int offs = 1;
        byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
        bool isMem = mod != 0b11;
        uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
        int src = (int)(isMem ? *(uint*)addr : ReadReg32(ctx, rm));
        int imm = opcode == 0x6B ? *(sbyte*)(ip + offs++) : *(int*)(ip + offs); if (opcode == 0x69) offs += 4;
        *GetReg(ctx, reg) = (uint)(src * imm);
        log($"IMUL r32, r/m32, imm", offs);
        ctx->Eip += (uint)offs; return true;
    }

    private static bool HandleStringOp32(CONTEXT32* ctx, byte* ip, bool hasRep, bool hasRepne, Action<string, int> log)
    {
        byte opcode = *ip;
        int opSize = (opcode & 1) == 0 ? 8 : 32;
        int step = opSize / 8;
        bool fwd = (ctx->EFlags & FlagsCalculator.DF) == 0;
        int delta = fwd ? step : -step;
        bool isRep = hasRep || hasRepne;

        if (isRep && ctx->Ecx == 0) { log("REP (count=0)", 1); ctx->Eip += 1; return true; }

        do
        {
            switch (opcode)
            {
                case 0xA4: case 0xA5: *(uint*)ctx->Edi = opSize == 8 ? *(byte*)ctx->Esi : *(uint*)ctx->Esi; ctx->Esi = (uint)((int)ctx->Esi + delta); ctx->Edi = (uint)((int)ctx->Edi + delta); break;
                case 0xAA: case 0xAB: if (opSize == 8) *(byte*)ctx->Edi = (byte)ctx->Eax; else *(uint*)ctx->Edi = ctx->Eax; ctx->Edi = (uint)((int)ctx->Edi + delta); break;
                case 0xAC: case 0xAD: if (opSize == 8) ctx->Eax = (ctx->Eax & ~0xFFu) | *(byte*)ctx->Esi; else ctx->Eax = *(uint*)ctx->Esi; ctx->Esi = (uint)((int)ctx->Esi + delta); break;
                case 0xA6: case 0xA7: { uint a = opSize == 8 ? *(byte*)ctx->Esi : *(uint*)ctx->Esi; uint b = opSize == 8 ? *(byte*)ctx->Edi : *(uint*)ctx->Edi; ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, a, b, a - b, opSize); ctx->Esi = (uint)((int)ctx->Esi + delta); ctx->Edi = (uint)((int)ctx->Edi + delta); break; }
                case 0xAE: case 0xAF: { uint v = opSize == 8 ? *(byte*)ctx->Edi : *(uint*)ctx->Edi; uint acc = opSize == 8 ? (byte)ctx->Eax : ctx->Eax; ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, acc, v, acc - v, opSize); ctx->Edi = (uint)((int)ctx->Edi + delta); break; }
                default: return false;
            }
            if (isRep)
            {
                ctx->Ecx--;
                if (ctx->Ecx == 0) break;
                if (opcode is 0xA6 or 0xA7 or 0xAE or 0xAF)
                {
                    bool zf = (ctx->EFlags & FlagsCalculator.ZF) != 0;
                    if (hasRep && !zf) break;
                    if (hasRepne && zf) break;
                }
            }
        } while (isRep && ctx->Ecx > 0);

        log("string op", 1);
        ctx->Eip += 1;
        return true;
    }

    // ===================== Two-byte opcodes (0F xx) =====================

    private static bool HandleTwoByte32(CONTEXT32* ctx, byte* ip, Action<string, int> log)
    {
        byte op2 = ip[1];

        switch (op2)
        {
            // Jcc near (0F 80-8F)
            case >= 0x80 and <= 0x8F:
            {
                int cc = op2 & 0xF;
                int rel32 = *(int*)(ip + 2);
                uint next = ctx->Eip + 6;
                uint target = (uint)((int)next + rel32);
                bool taken = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);
                ctx->Eip = taken ? target : next;
                log($"J{InstructionDecoder.ConditionName(cc)} near", 6);
                return true;
            }

            // SETcc (0F 90-9F)
            case >= 0x90 and <= 0x9F:
            {
                int cc = op2 & 0xF;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int rm = modrm & 7;
                bool cond = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);
                byte result = cond ? (byte)1 : (byte)0;
                if (mod == 0b11) WriteReg8(ctx, rm, result);
                else { uint addr = ResolveEA32(ctx, ip, ref offs, mod, rm); *(byte*)addr = result; }
                log($"SET{InstructionDecoder.ConditionName(cc)}", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // CMOVcc (0F 40-4F)
            case >= 0x40 and <= 0x4F:
            {
                int cc = op2 & 0xF;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint src = isMem ? *(uint*)addr : ReadReg32(ctx, rm);
                if (InstructionDecoder.EvaluateCondition(ctx->EFlags, cc)) *GetReg(ctx, reg) = src;
                log($"CMOV{InstructionDecoder.ConditionName(cc)}", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // MOVZX r32, r/m8 (0F B6) / MOVZX r32, r/m16 (0F B7)
            case 0xB6: case 0xB7:
            {
                int srcSize = op2 == 0xB6 ? 8 : 16;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint val;
                if (srcSize == 8) val = isMem ? *(byte*)addr : ReadReg8(ctx, rm);
                else val = isMem ? *(ushort*)addr : (ushort)ReadReg32(ctx, rm);
                *GetReg(ctx, reg) = val;
                log($"MOVZX r32, r/m{srcSize}", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // MOVSX r32, r/m8 (0F BE) / MOVSX r32, r/m16 (0F BF)
            case 0xBE: case 0xBF:
            {
                int srcSize = op2 == 0xBE ? 8 : 16;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                int val;
                if (srcSize == 8) val = isMem ? *(sbyte*)addr : (sbyte)ReadReg8(ctx, rm);
                else val = isMem ? *(short*)addr : (short)(ushort)ReadReg32(ctx, rm);
                *GetReg(ctx, reg) = (uint)val;
                log($"MOVSX r32, r/m{srcSize}", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // IMUL r32, r/m32 (0F AF)
            case 0xAF:
            {
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                int src = (int)(isMem ? *(uint*)addr : ReadReg32(ctx, rm));
                *GetReg(ctx, reg) = (uint)((int)ReadReg32(ctx, reg) * src);
                log("IMUL r32, r/m32", offs);
                ctx->Eip += (uint)offs;
                return true;
            }

            // XADD (0F C0/C1)
            case 0xC0: case 0xC1:
            {
                int opSize = op2 == 0xC0 ? 8 : 32;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint dst = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
                uint src = ReadSized32(ctx, reg, opSize);
                uint result = dst + src;
                WriteSized32(ctx, reg, dst, opSize);
                if (isMem) WriteMemSized(addr, result, opSize); else WriteSized32(ctx, rm, result, opSize);
                ctx->EFlags = FlagsCalculator.SetAddFlags(ctx->EFlags, dst, src, result, opSize);
                log($"XADD r/m{opSize}, r{opSize}", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // CMPXCHG (0F B0/B1)
            case 0xB0: case 0xB1:
            {
                int opSize = op2 == 0xB0 ? 8 : 32;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint dst = isMem ? ReadMemSized(addr, opSize) : ReadSized32(ctx, rm, opSize);
                uint acc = opSize == 8 ? (byte)ctx->Eax : ctx->Eax;
                ctx->EFlags = FlagsCalculator.SetSubFlags(ctx->EFlags, acc, dst, acc - dst, opSize);
                if (acc == dst) { uint src = ReadSized32(ctx, reg, opSize); if (isMem) WriteMemSized(addr, src, opSize); else WriteSized32(ctx, rm, src, opSize); }
                else { if (opSize == 8) ctx->Eax = (ctx->Eax & ~0xFFu) | (dst & 0xFF); else ctx->Eax = dst; }
                log($"CMPXCHG r/m{opSize}, r{opSize}", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // BSF/BSR (0F BC/BD)
            case 0xBC: case 0xBD:
            {
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint src = isMem ? *(uint*)addr : ReadReg32(ctx, rm);
                if (src == 0) { ctx->EFlags |= FlagsCalculator.ZF; }
                else
                {
                    ctx->EFlags &= ~FlagsCalculator.ZF;
                    int r = op2 == 0xBC ? System.Numerics.BitOperations.TrailingZeroCount(src)
                                        : 31 - System.Numerics.BitOperations.LeadingZeroCount(src);
                    *GetReg(ctx, reg) = (uint)r;
                }
                log(op2 == 0xBC ? "BSF" : "BSR", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // BSWAP (0F C8-CF)
            case >= 0xC8 and <= 0xCF:
            {
                int reg = op2 - 0xC8;
                uint* r = GetReg(ctx, reg);
                uint v = *r;
                *r = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
                log($"BSWAP {RegName32(reg)}", 2);
                ctx->Eip += 2; return true;
            }

            // BT/BTS/BTR/BTC (0F A3/AB/B3/BB) and imm8 (0F BA)
            case 0xA3: case 0xAB: case 0xB3: case 0xBB: case 0xBA:
            {
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int regOrGrp = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint dst = isMem ? *(uint*)addr : ReadReg32(ctx, rm);
                int bitIdx;
                if (op2 == 0xBA) { bitIdx = ip[offs++] % 32; } // imm8
                else { bitIdx = (int)(ReadReg32(ctx, regOrGrp) % 32); }
                bool bit = (dst & (1u << bitIdx)) != 0;
                ctx->EFlags = bit ? ctx->EFlags | FlagsCalculator.CF : ctx->EFlags & ~FlagsCalculator.CF;
                if (op2 == 0xAB || (op2 == 0xBA && regOrGrp == 5)) dst |= (1u << bitIdx);
                else if (op2 == 0xB3 || (op2 == 0xBA && regOrGrp == 6)) dst &= ~(1u << bitIdx);
                else if (op2 == 0xBB || (op2 == 0xBA && regOrGrp == 7)) dst ^= (1u << bitIdx);
                if (op2 != 0xA3 && !(op2 == 0xBA && regOrGrp == 4)) { if (isMem) *(uint*)addr = dst; else *GetReg(ctx, rm) = dst; }
                log("BT*", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // SHLD/SHRD (0F A4/A5/AC/AD)
            case 0xA4: case 0xA5: case 0xAC: case 0xAD:
            {
                bool isShld = op2 < 0xAC;
                bool byCL = (op2 & 1) != 0;
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int reg = (modrm >> 3) & 7; int rm = modrm & 7;
                bool isMem = mod != 0b11;
                uint addr = isMem ? ResolveEA32(ctx, ip, ref offs, mod, rm) : 0;
                uint dst = isMem ? *(uint*)addr : ReadReg32(ctx, rm);
                uint src = ReadReg32(ctx, reg);
                byte count = byCL ? (byte)(ctx->Ecx & 0x1F) : (byte)(ip[offs++] & 0x1F);
                if (count > 0)
                {
                    uint result = isShld ? (dst << count) | (src >> (32 - count)) : (dst >> count) | (src << (32 - count));
                    if (isMem) *(uint*)addr = result; else *GetReg(ctx, rm) = result;
                }
                log(isShld ? "SHLD" : "SHRD", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // UD2 (0F 0B)
            case 0x0B: log("UD2", 2); return false;

            // NOP (0F 1F and others)
            case >= 0x18 and <= 0x1F: case 0x0D:
            {
                int offs = 2;
                byte modrm = ip[offs++]; byte mod = (byte)(modrm >> 6 & 3); int rm = modrm & 7;
                if (mod != 0b11) ResolveEA32(ctx, ip, ref offs, mod, rm);
                log("NOP (multi)", offs);
                ctx->Eip += (uint)offs; return true;
            }

            // CPUID (0F A2)
            case 0xA2:
                ctx->Eax = 0; ctx->Ebx = 0x756E6547; ctx->Edx = 0x49656E69; ctx->Ecx = 0x6C65746E;
                log("CPUID", 2); ctx->Eip += 2; return true;

            // RDTSC (0F 31)
            case 0x31:
            {
                ulong tsc = (ulong)Environment.TickCount64 * 3000;
                ctx->Eax = (uint)tsc; ctx->Edx = (uint)(tsc >> 32);
                log("RDTSC", 2); ctx->Eip += 2; return true;
            }

            default:
                if (EnableLogging)
                    Console.WriteLine($"i386 UNSUPPORTED 0F {op2:X2} at EIP=0x{ctx->Eip:X8}");
                return false;
        }
    }
}
