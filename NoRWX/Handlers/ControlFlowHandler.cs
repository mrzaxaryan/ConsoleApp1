using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

/// <summary>
/// Handles control flow instructions: JMP, Jcc, CALL, RET, LEAVE, ENTER, LOOP, INT3.
/// </summary>
public static unsafe class ControlFlowHandler
{
    /// <summary>CALL rel32 (E8)</summary>
    public static bool HandleCallRel32(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        int rel32 = *(int*)(ip + offs);
        offs += 4;

        ulong returnAddr = ctx->Rip + (ulong)offs;
        ulong target = (ulong)((long)ctx->Rip + offs + rel32);

        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = returnAddr;
        ctx->Rip = target;

        log($"CALL 0x{target:X}", offs);
        return true;
    }

    /// <summary>RET (C3) / RET imm16 (C2)</summary>
    public static bool HandleRet(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        ulong returnAddr = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;

        ushort stackAdj = 0;
        if (opcode == 0xC2)
        {
            stackAdj = *(ushort*)(ip + offs);
            offs += 2;
            ctx->Rsp += stackAdj;
        }

        ctx->Rip = returnAddr;
        log($"RET{(opcode == 0xC2 ? $" {stackAdj}" : "")} => 0x{returnAddr:X}", offs);
        return true;
    }

    /// <summary>LEAVE (C9)</summary>
    public static bool HandleLeave(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        ctx->Rsp = ctx->Rbp;
        ctx->Rbp = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;

        log("LEAVE", 1);
        ctx->Rip += 1;
        return true;
    }

    /// <summary>ENTER imm16, imm8 (C8)</summary>
    public static bool HandleEnter(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip opcode

        ushort allocSize = *(ushort*)(ip + offs); offs += 2;
        byte nestingLevel = ip[offs++];

        // Push RBP
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rbp;

        ulong frameTemp = ctx->Rsp;

        if (nestingLevel > 0)
        {
            for (int i = 1; i < nestingLevel; i++)
            {
                ctx->Rbp -= 8;
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = *(ulong*)ctx->Rbp;
            }
            ctx->Rsp -= 8;
            *(ulong*)ctx->Rsp = frameTemp;
        }

        ctx->Rbp = frameTemp;
        ctx->Rsp -= allocSize;

        log($"ENTER {allocSize}, {nestingLevel}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>JMP rel8 (EB) / JMP rel32 (E9)</summary>
    public static bool HandleJmp(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        ulong target;
        if (opcode == 0xEB)
        {
            sbyte rel8 = *(sbyte*)(ip + offs++);
            target = (ulong)((long)(ctx->Rip + (ulong)offs) + rel8);
        }
        else // E9
        {
            int rel32 = *(int*)(ip + offs);
            offs += 4;
            target = (ulong)((long)(ctx->Rip + (ulong)offs) + rel32);
        }

        log($"JMP 0x{target:X}", offs);
        ctx->Rip = target;
        return true;
    }

    /// <summary>Jcc short rel8 (70-7F)</summary>
    public static bool HandleJccShort(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];
        int cc = opcode & 0xF;

        sbyte rel8 = *(sbyte*)(ip + offs++);
        ulong nextRip = ctx->Rip + (ulong)offs;
        ulong target = (ulong)((long)nextRip + rel8);

        bool taken = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);

        log($"J{InstructionDecoder.ConditionName(cc)} short {(taken ? "TAKEN" : "NOT taken")} -> 0x{target:X}", offs);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }

    /// <summary>Jcc near rel32 (0F 80-8F)</summary>
    public static bool HandleJccNear(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip 0F
        byte opcode2 = ip[offs++];
        int cc = opcode2 & 0xF;

        int rel32 = *(int*)(ip + offs);
        offs += 4;
        ulong nextRip = ctx->Rip + (ulong)offs;
        ulong target = (ulong)((long)nextRip + rel32);

        bool taken = InstructionDecoder.EvaluateCondition(ctx->EFlags, cc);

        log($"J{InstructionDecoder.ConditionName(cc)} near {(taken ? "TAKEN" : "NOT taken")} -> 0x{target:X}", offs);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }

    /// <summary>FF /2 = CALL r/m64, FF /4 = JMP r/m64, FF /6 = PUSH r/m64</summary>
    public static bool HandleGroup5(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // skip FF

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;

        bool isMem = modrm.Mod != 0b11;
        ulong addr = isMem ? InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B) : 0;
        ulong operand = isMem ? InstructionDecoder.ReadMemory(addr, 64) : RegisterHelper.Read64(ctx, modrm.Rm);

        switch (grp)
        {
            case 0: // INC r/m64
            {
                ulong result = operand + 1;
                if (isMem) InstructionDecoder.WriteMemory(addr, result, 64);
                else RegisterHelper.Write64(ctx, modrm.Rm, result);
                ctx->EFlags = FlagsCalculator.SetIncFlags(ctx->EFlags, operand, result, 64);
                log($"INC r/m64", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            case 1: // DEC r/m64
            {
                ulong result = operand - 1;
                if (isMem) InstructionDecoder.WriteMemory(addr, result, 64);
                else RegisterHelper.Write64(ctx, modrm.Rm, result);
                ctx->EFlags = FlagsCalculator.SetDecFlags(ctx->EFlags, operand, result, 64);
                log($"DEC r/m64", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            case 2: // CALL r/m64
            {
                ulong returnAddr = ctx->Rip + (ulong)offs;
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = returnAddr;
                ctx->Rip = operand;
                log($"CALL r/m64 => 0x{operand:X}", offs);
                return true;
            }
            case 4: // JMP r/m64
            {
                ctx->Rip = operand;
                log($"JMP r/m64 => 0x{operand:X}", offs);
                return true;
            }
            case 6: // PUSH r/m64
            {
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = operand;
                log($"PUSH r/m64 => 0x{operand:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            default:
                log($"Unsupported FF /{grp}", offs);
                return false;
        }
    }

    /// <summary>LOOP/LOOPE/LOOPNE (E0/E1/E2)</summary>
    public static bool HandleLoop(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        InstructionDecoder.ParsePrefixes(ip, ref offs);
        byte opcode = ip[offs++];

        sbyte rel8 = *(sbyte*)(ip + offs++);
        ulong nextRip = ctx->Rip + (ulong)offs;
        ulong target = (ulong)((long)nextRip + rel8);

        ctx->Rcx--;
        bool zf = (ctx->EFlags & FlagsCalculator.ZF) != 0;

        bool taken = opcode switch
        {
            0xE0 => ctx->Rcx != 0 && !zf,  // LOOPNE
            0xE1 => ctx->Rcx != 0 && zf,    // LOOPE
            0xE2 => ctx->Rcx != 0,           // LOOP
            _ => false
        };
        string name = opcode switch
        {
            0xE0 => "LOOPNE", 0xE1 => "LOOPE", 0xE2 => "LOOP", _ => "LOOP?"
        };

        log($"{name} {(taken ? "TAKEN" : "NOT taken")} -> 0x{target:X} (RCX={ctx->Rcx})", offs);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }

    /// <summary>INT3 (CC)</summary>
    public static bool HandleInt3(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        log("INT3", 1);
        ctx->Rip += 1;
        return true;
    }
}
