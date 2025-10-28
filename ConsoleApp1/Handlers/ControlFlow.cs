using static X64Emulator;

public static unsafe class ControlFlow
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            case X64Opcodes.CALL: return HandleCall(ctx, address, Log);
            case X64Opcodes.RET: return HandleRet(ctx, Log);
            case X64Opcodes.LEAVE: return HandleLeave(ctx, Log);
            case X64Opcodes.JMP_NEAR: return HandleJmpNear(ctx, address, Log);
            case X64Opcodes.JMP_SHORT: return HandleJmpShort(ctx, address, Log);
            case X64Opcodes.JE_SHORT: return HandleJeShort(ctx, address, Log);
            case X64Opcodes.JNE_SHORT: return HandleJneShort(ctx, address, Log);
            case X64Opcodes.JBE_SHORT: return HandleJbeShort(ctx, address, Log);
            case X64Opcodes.JA_SHORT: return HandleJaShort(ctx, address, Log);
            case >= X64Opcodes.JO_SHORT and <= X64Opcodes.JG_SHORT:
                return HandleShortConditionalJump(ctx, address, Log);
            default:
                Log($"Unsupported control flow opcode 0x{opcode:X2}", 8);
                return false;
        }
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
    private static bool HandleJmpShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        ulong nextRip = ctx->Rip + 2;
        long target = (long)nextRip + rel8;

        Log($"JMP short {rel8:+#;-#;0} -> 0x{(ulong)target:X}", 2);

        ctx->Rip = (ulong)target;
        return true;
    }
    private static bool HandleJeShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        sbyte rel8 = *(sbyte*)(address + 1);
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = (ulong)((long)ctx->Rip + 2 + rel8);
        Log($"JE short 0x{target:X} {(zf ? "TAKEN" : "NOT taken")}", 2);
        ctx->Rip = zf ? target : ctx->Rip + 2;
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
}