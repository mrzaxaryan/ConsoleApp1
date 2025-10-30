using static NoRWX.Emulator;

namespace NoRWX.Handlers;

public static unsafe class ControlFlow
{
    public static unsafe bool HandleMovsxGvEb32(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 0F BE /r  => MOVSX r32, r/m8   (sign-extend 8-bit to 32-bit; write zero-extends into 64-bit reg)
        if (ip[0] != 0x0F || ip[1] != 0xBE) return false;

        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 0x3);
        int reg = modrm >> 3 & 0x7;   // destination r32 (no REX.R assumed here)
        int rm = modrm & 0x7;        // source r/m8

        ulong* R = &ctx->Rax;
        int disp = 0;
        ulong memAddr = 0;
        byte src8;

        if (mod == 0b11)
        {
            // Register-direct: r8 source
            // NOTE (x64): without a REX prefix, rm=4..7 map to AH,CH,DH,BH. If you need those, add mapping.
            // Here we implement the common low-8 regs (AL/CL/DL/BL) and treat 4..7 as their low-8 counterparts
            // which is acceptable if your codegen never uses AH..BH.
            ulong v = R[rm];
            src8 = (byte)(v & 0xFF);
        }
        else
        {
            // Memory source
            // Handle the form used in your trace: mod==01 with disp8; general base = R[rm] + disp8
            // SIB (rm==4) not handled here; RIP-relative (mod==00 && rm==101) not handled.
            if (mod == 0b01)
            {
                sbyte disp8 = unchecked((sbyte)ip[offs++]);
                if (rm == 0b100) { Log("0F BE with SIB not supported in this stub", 2); return false; }
                // In mod=01, rm=101 means [RBP + disp8] (NOT RIP-rel)
                memAddr = (ulong)((long)R[rm] + disp8);
            }
            else if (mod == 0b10)
            {
                // disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                if (rm == 0b100) { Log("0F BE with SIB not supported in this stub", 2); return false; }
                memAddr = (ulong)((long)R[rm] + disp32);
            }
            else /* mod == 0b00 */
            {
                if (rm == 0b101)
                {
                    // [disp32] (absolute) in 64-bit mode is legal but uncommon; RIP-relative would be for LEA, not here.
                    int disp32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (uint)disp32; // zero-extend absolute 32-bit
                }
                else
                {
                    if (rm == 0b100) { Log("0F BE with SIB not supported in this stub", 2); return false; }
                    memAddr = R[rm];
                }
            }

            src8 = *(byte*)memAddr;
        }

        // Sign-extend 8->32
        int sext = (sbyte)src8;
        uint result = unchecked((uint)sext);

        // Write to 32-bit destination register (zero-extends into 64-bit)
        R[reg] = R[reg] & ~0xFFFF_FFFFUL | result;

        // Flags: MOVSX does not affect any flags.
        // Advance RIP by the bytes we consumed.
        int instrLen = offs; // 2 + ModRM + disp if any
        ctx->Rip += (uint)instrLen;

        string srcDesc = mod == 0b11
            ? $"R{rm}b"
            : mod == 0b01 ? $"[R{rm}+disp8]" :
               mod == 0b10 ? $"[R{rm}+disp32]" :
               rm == 0b101 ? "[disp32]" : $"[R{rm}]";

        Log($"0F BE /r  MOVSX R{reg}d, {srcDesc} => 0x{result:X8}", instrLen);
        return true;
    }
    public static unsafe bool HandleMovzxGvEw32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F B7 /r → MOVZX r32, r/m16
        int offs = 2;
        byte modrm = address[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7;
        int rm = modrm & 7;

        ulong* R = &ctx->Rax;
        ushort src;
        string srcDesc;

        if (mod == 0b11)
        {
            src = (ushort)R[rm];          // take low 16 of the source reg
            srcDesc = $"R{rm}w";
        }
        else
        {
            ulong addr = Miscellaneous.ResolveEA_NoRex_BaseDispOrRip(ctx, address, ref offs, mod, rm, out srcDesc);
            src = *(ushort*)addr;
        }

        // CRITICAL: zero upper 32 on r32 writes
        R[reg] = src;

        Log($"MOVZX R{reg}d, {srcDesc} => 0x{src:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleMovzxGvEb32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F B6 /r → MOVZX r32, r/m8
        int offs = 2; // skip 0F B6
        byte modrm = address[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // destination
        int rm = modrm & 7;         // source

        ulong* R = &ctx->Rax;
        byte src;
        string srcDesc;

        if (mod == 0b11)
        {
            src = (byte)R[rm];
            srcDesc = $"R{rm}b";
        }
        else
        {
            ulong addr = Miscellaneous.ResolveEA_NoRex_BaseDispOrRip(ctx, address, ref offs, mod, rm, out srcDesc);
            src = *(byte*)addr;
        }

        R[reg] = src;

        Log($"MOVZX R{reg}d, {srcDesc} => 0x{src:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleCall(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // E8 rel32 → CALL near relative
        const int instrLen = 5;

        // Displacement is a signed 32-bit relative offset
        long rel32 = *(int*)(address + 1);

        ulong returnAddress = ctx->Rip + instrLen;
        ulong newRip = (ulong)((long)ctx->Rip + instrLen + rel32);

        // Push return address
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = returnAddress;

        // Transfer control
        ctx->Rip = newRip;

        Log($"CALL 0x{newRip:X} (rel32=0x{rel32:X8}), return=0x{returnAddress:X}", instrLen);
        return true;
    }
    public static unsafe bool HandleRet(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0xC3 → RET
        // 0xC2 iw → RET imm16 (pops immediate bytes)
        byte opcode = *address;
        int offs = 1;

        // Pop return address
        ulong returnAddress = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;

        ushort stackAdjust = 0;
        if (opcode == 0xC2)
        {
            stackAdjust = *(ushort*)(address + offs);
            offs += 2;
            ctx->Rsp += stackAdjust; // Callee cleanup
        }

        ctx->Rip = returnAddress;
        Log($"RET{(opcode == 0xC2 ? $" {stackAdjust}" : "")} => RIP=0x{returnAddress:X}", offs);
        return true;
    }
    public static unsafe bool HandleLeave(CONTEXT* ctx, Action<string, int> Log)
    {
        ulong oldRbp = ctx->Rbp;
        ctx->Rsp = oldRbp;

        ulong newRbp = *(ulong*)ctx->Rsp; // 8 bytes in 64-bit mode
        ctx->Rbp = newRbp;
        ctx->Rsp += 8;

        Log($"LEAVE (RSP=RBP; POP RBP={newRbp:X})", 1);
        ctx->Rip += 1;
        return true;
    }

    public static unsafe bool HandleJmpNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // E9 cd cd cd cd  →  JMP rel32 (signed displacement)
        const int instrLen = 5;

        int rel32 = *(int*)(address + 1); // signed 32-bit offset
        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel32); // sign-extend to 64-bit

        Log($"JMP near {rel32:+#;-#;0} (to 0x{target:X})", instrLen);

        ctx->Rip = target;
        return true;
    }
    public static unsafe bool HandleJmpShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // EB cb  →  JMP short (rel8 signed)
        const int instrLen = 2;

        sbyte rel8 = *(sbyte*)(address + 1);
        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel8);

        Log($"JMP short {rel8:+#;-#;0} (to 0x{target:X})", instrLen);

        ctx->Rip = target;
        return true;
    }
    public static unsafe bool HandleJeShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 74 cb → JE (JZ) short, rel8 signed displacement
        const int instrLen = 2;

        sbyte rel8 = *(sbyte*)(address + 1);
        bool zf = (ctx->EFlags & 0x40) != 0; // ZF bit 6

        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel8);

        Log($"JE short {(zf ? "TAKEN" : "NOT taken")} -> 0x{target:X}", instrLen);

        ctx->Rip = zf ? target : nextRip;
        return true;
    }
    public static unsafe bool HandleJneShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 75 cb → JNE (JNZ) short, rel8 signed displacement
        const int instrLen = 2;

        sbyte rel8 = *(sbyte*)(address + 1);
        bool zf = (ctx->EFlags & 0x40) != 0; // Zero flag

        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel8);

        Log($"JNE short {(zf ? "NOT taken" : "TAKEN")} -> 0x{target:X}", instrLen);

        ctx->Rip = zf ? nextRip : target;
        return true;
    }
    public static unsafe bool HandleJaShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 77 cb → JA (JNBE) short, unsigned jump if CF==0 && ZF==0
        const int instrLen = 2;

        sbyte rel8 = *(sbyte*)(address + 1);
        bool cf = (ctx->EFlags & 0x01) != 0; // Carry Flag
        bool zf = (ctx->EFlags & 0x40) != 0; // Zero Flag

        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel8);
        bool taken = !cf && !zf;

        Log($"JA short {(taken ? "TAKEN" : "NOT taken")} -> 0x{target:X}", instrLen);

        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    public static unsafe bool HandleJbeShort(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 76 cb → JBE (JNA) short, unsigned jump if CF==1 || ZF==1
        const int instrLen = 2;

        sbyte rel8 = *(sbyte*)(address + 1);
        bool cf = (ctx->EFlags & 0x01) != 0;  // Carry Flag
        bool zf = (ctx->EFlags & 0x40) != 0;  // Zero Flag

        ulong nextRip = ctx->Rip + instrLen;
        ulong target = (ulong)((long)nextRip + rel8);
        bool taken = cf || zf;

        Log($"JBE short {(taken ? "TAKEN" : "NOT taken")} -> 0x{target:X}", instrLen);

        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    public static unsafe bool HandleShortConditionalJump(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte opcode = *address;        // 70..7F
        sbyte rel8 = *(sbyte*)(address + 1);
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
            case 0x7E: take = ZF || SF != OF; break; // JLE / JNG
            case 0x7F: take = !ZF && SF == OF; break; // JG / JNLE
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
    public static unsafe bool HandleTwoByteConditionalJump(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // Opcode form: 0F 8x + rel32
        byte sub = *(address + 1);
        int disp32 = *(int*)(address + 2);
        ulong target = ctx->Rip + 6 + (ulong)disp32; // 6-byte total length
        uint f = ctx->EFlags;
        bool take;

        switch (sub)
        {
            case 0x80: take = (f & 0x800) != 0; break;                        // JO
            case 0x81: take = (f & 0x800) == 0; break;                        // JNO
            case 0x82: take = (f & 1) != 0 || (f & 0x40) != 0; break;     // JBE/JNA
            case 0x83: take = (f & 1) == 0 && (f & 0x40) == 0; break;     // JA/JNBE
            case 0x84: take = (f & 0x40) != 0; break;                         // JE/JZ
            case 0x85: take = (f & 0x40) == 0; break;                         // JNE/JNZ
            case 0x86: take = (f >> 2 & 1) != 0; break;                     // JBE(PF) rarely used (JP)
            case 0x87: take = (f >> 2 & 1) == 0; break;                     // JNP
            case 0x88: take = (f & 0x80) != 0; break;                         // JS
            case 0x89: take = (f & 0x80) == 0; break;                         // JNS
            case 0x8A: take = (f >> 11 ^ f >> 7 & 1) != 0; break;       // JP
            case 0x8B: take = (f >> 11 ^ f >> 7 & 1) == 0; break;       // JNP
            case 0x8C: take = (f >> 7 & 1) != (f >> 11 & 1); break;     // JL
            case 0x8D: take = (f >> 7 & 1) == (f >> 11 & 1); break;     // JGE
            case 0x8E: take = (f & 0x40) != 0 || (f >> 7 & 1) != (f >> 11 & 1); break; // JLE
            case 0x8F: take = (f & 0x40) == 0 && (f >> 7 & 1) == (f >> 11 & 1); break; // JG
            default:
                Log($"Unsupported two-byte Jcc 0F {sub:X2}", 6);
                return false;
        }

        if (take)
        {
            Log($"Jcc near taken -> 0x{target:X}", 6);
            ctx->Rip = target;
        }
        else
        {
            Log($"Jcc near NOT taken -> 0x{target:X}", 6);
            ctx->Rip += 6;
        }

        return true;
    }

}