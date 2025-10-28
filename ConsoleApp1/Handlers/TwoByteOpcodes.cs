using System;
using System.IO;
using System.Runtime.InteropServices;
using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1.Handlers;

public static unsafe class TwoByteOpcodes
{
    public static bool Handle(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte op2 = *(address + 1);
        switch (op2)
        {
            case X64Opcodes.JNE_NEAR: return HandleJneNear(ctx, address, Log);
            case X64Opcodes.JE_NEAR: return HandleJccNear(ctx, address, Log);
            case X64Opcodes.MOVZX_GvEw: return HandleMovzxGvEw(ctx, address, Log);
            case X64Opcodes.MOVZX_R32_RM8: return HandleMovzxR32Rm8(ctx, address, Log);
            case X64Opcodes.SETE: return HandleSetcc(ctx, address, Log);
            default:
                return false;
        }
    }
    private static unsafe bool HandleSetcc(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 0F 9x /r → SETcc r/m8
        int offs = 0;
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++]; // optional REX
        bool rexB = (rex & 1) != 0;

        if (ip[offs] != 0x0F)
            return false;
        offs++;

        byte opcode = ip[offs++];
        if (opcode < 0x90 || opcode > 0x9F)
            return false; // not SETcc

        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int rm = (modrm & 7) | (rexB ? 8 : 0);
        ulong* R = &ctx->Rax;

        // --- condition evaluation ---
        uint flags = ctx->EFlags;
        bool cf = (flags & 1) != 0;
        bool pf = (flags & 4) != 0;
        bool zf = (flags & 0x40) != 0;
        bool sf = (flags & 0x80) != 0;
        bool of = (flags & 0x800) != 0;

        bool cond = opcode switch
        {
            0x90 => of,                       // SETO
            0x91 => !of,                      // SETNO
            0x92 => cf,                       // SETB/SETC
            0x93 => !cf,                      // SETNB/SETNC
            0x94 => zf,                       // SETE/SETZ
            0x95 => !zf,                      // SETNE/SETNZ
            0x96 => cf || zf,                 // SETBE
            0x97 => !cf && !zf,               // SETA
            0x98 => sf,                       // SETS
            0x99 => !sf,                      // SETNS
            0x9A => pf,                       // SETP
            0x9B => !pf,                      // SETNP
            0x9C => sf != of,                 // SETL
            0x9D => sf == of,                 // SETGE
            0x9E => zf || (sf != of),         // SETLE
            0x9F => !zf && (sf == of),        // SETG
            _ => false
        };

        byte result = cond ? (byte)1 : (byte)0;

        string mnemonic = opcode switch
        {
            0x90 => "SETO",
            0x91 => "SETNO",
            0x92 => "SETB",
            0x93 => "SETNB",
            0x94 => "SETZ",
            0x95 => "SETNZ",
            0x96 => "SETBE",
            0x97 => "SETA",
            0x98 => "SETS",
            0x99 => "SETNS",
            0x9A => "SETP",
            0x9B => "SETNP",
            0x9C => "SETL",
            0x9D => "SETGE",
            0x9E => "SETLE",
            0x9F => "SETG",
            _ => "SET?"
        };

        // --- destination decode ---
        if (mod == 0b11)
        {
            // register destination
            byte* regPtr = (byte*)(R + rm);
            *regPtr = result;
            Log($"{mnemonic} R{rm}b => {result}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
        else
        {
            // memory destination
            ulong memAddr = 0;
            if (mod == 0b00 && (modrm & 7) == 0b101)
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01)
                    memAddr += (ulong)*(sbyte*)(ip + offs++);
                else if (mod == 0b10)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    memAddr += (ulong)(long)disp32;
                }
            }

            // guard against null/small addresses
            if (memAddr < 0x10000)
            {
                Log($"{mnemonic} invalid [0x{memAddr:X}] skipped", offs);
                ctx->Rip += (ulong)offs;
                return false;
            }

            *(byte*)memAddr = result;
            Log($"{mnemonic} BYTE PTR [0x{memAddr:X}] => {result}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
    }

    private static unsafe bool HandleMovzxR32Rm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 0F B6 /r  → MOVZX r32/64, r/m8
        int offs = 0;
        byte rex = 0;

        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++]; // optional REX

        bool rexW = (rex & 0x08) != 0; // if 1 → MOVZX r64, r/m8
        bool rexR = (rex & 0x04) != 0;
        bool rexX = (rex & 0x02) != 0;
        bool rexB = (rex & 0x01) != 0;

        if (ip[offs] != 0x0F || ip[offs + 1] != 0xB6)
            return false;

        offs += 2; // consume 0F B6
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = (modrm >> 3 & 7) | (rexR ? 8 : 0);  // destination
        int rm = (modrm & 7) | (rexB ? 8 : 0);       // source
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
            // --- memory decoding with SIB + RIP-relative ---
            if (mod == 0b00 && (rm & 7) == 0b101)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
            }
            else if ((rm & 7) == 0b100)
            {
                // SIB
                byte sib = ip[offs++];
                byte scale = (byte)(sib >> 6 & 3);
                byte idx = (byte)(sib >> 3 & 7);
                byte baseBits = (byte)(sib & 7);

                int indexReg = idx != 0b100 ? idx | (rexX ? 8 : 0) : -1;
                int baseReg = baseBits | (rexB ? 8 : 0);

                ulong baseVal;
                if (mod == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    baseVal = ctx->Rip + (ulong)offs + (ulong)(long)disp32; // RIP-relative
                }
                else
                {
                    baseVal = R[baseReg];
                }

                ulong indexVal = indexReg >= 0 ? R[indexReg] << scale : 0;
                memAddr = baseVal + indexVal;

                if (mod == 0b01)
                    memAddr += (ulong)*(sbyte*)(ip + offs++);
                else if (mod == 0b10)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    memAddr += (ulong)(long)disp32;
                }
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01)
                    memAddr += (ulong)*(sbyte*)(ip + offs++);
                else if (mod == 0b10)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    memAddr += (ulong)(long)disp32;
                }
            }

            // guard to prevent AV
            if (memAddr < 0x10000)
            {
                Log($"MOVZX invalid [0x{memAddr:X}] skipped", offs);
                return false;
            }

            value8 = *(byte*)memAddr;
            srcDesc = $"BYTE PTR [0x{memAddr:X}]";
        }

        // ---- zero-extend ----
        if (rexW)
        {
            // MOVZX r64, r/m8
            R[reg] = value8; // upper bits zeroed by full 64-bit write
            Log($"MOVZX R{reg}, {srcDesc} => 0x{value8:X2}", offs);
        }
        else
        {
            // MOVZX r32, r/m8 → zero-extend to 64-bit per x64 semantics
            R[reg] = (ulong)value8;
            Log($"MOVZX E{reg}, {srcDesc} => 0x{value8:X2}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleJneNear(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 0F 85 rel32
        // JNE (Jump if Not Equal) — jumps if ZF == 0
        int offs = 0;

        // optional REX prefix (some assemblers can emit 0x40..0x4F before 0F)
        if ((ip[offs] & 0xF0) == 0x40)
            offs++;

        if (ip[offs] != 0x0F || ip[offs + 1] != 0x85)
            return false; // not a JNE near
        offs += 2;

        int rel32 = *(int*)(ip + offs);
        offs += 4;

        ulong nextRip = ctx->Rip + (ulong)offs;
        bool zf = (ctx->EFlags & 0x40) != 0;  // Zero flag
        bool taken = !zf;
        ulong target = nextRip + (ulong)(long)rel32;

        Log($"JNE 0x{target:X} {(taken ? "TAKEN" : "not taken")}", offs);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    private static unsafe bool HandleJccNear(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 0F 8x rel32  → conditional near jumps
        int offs = 0;

        // Optional REX prefix (x64 allows 0x40–0x4F even if ignored)
        if ((ip[offs] & 0xF0) == 0x40)
            offs++;

        if (ip[offs] != 0x0F)
            return false;
        offs++;

        byte opcode = ip[offs++];
        if (opcode < 0x80 || opcode > 0x8F)
            return false; // not a conditional jump

        int rel32 = *(int*)(ip + offs);
        offs += 4;
        ulong nextRip = ctx->Rip + (ulong)offs;

        // ---- Flag extraction ----
        bool cf = (ctx->EFlags & 1) != 0;
        bool pf = (ctx->EFlags & 4) != 0;
        bool zf = (ctx->EFlags & 0x40) != 0;
        bool sf = (ctx->EFlags & 0x80) != 0;
        bool of = (ctx->EFlags & 0x800) != 0;

        bool taken = opcode switch
        {
            0x80 => of,                        // JO
            0x81 => !of,                       // JNO
            0x82 => cf,                        // JB/JNAE/JC
            0x83 => !cf,                       // JNB/JAE/JNC
            0x84 => zf,                        // JE/JZ
            0x85 => !zf,                       // JNE/JNZ
            0x86 => (cf || zf),                // JBE/JNA
            0x87 => (!cf && !zf),              // JA/JNBE
            0x88 => sf,                        // JS
            0x89 => !sf,                       // JNS
            0x8A => pf,                        // JP/JPE
            0x8B => !pf,                       // JNP/JPO
            0x8C => (sf != of),                // JL/JNGE
            0x8D => (sf == of),                // JGE/JNL
            0x8E => (zf || (sf != of)),        // JLE/JNG
            0x8F => (!zf && (sf == of)),       // JG/JNLE
            _ => false
        };

        ulong target = nextRip + (ulong)(long)rel32;

        string mnemonic = opcode switch
        {
            0x80 => "JO",
            0x81 => "JNO",
            0x82 => "JB",
            0x83 => "JNB",
            0x84 => "JE",
            0x85 => "JNE",
            0x86 => "JBE",
            0x87 => "JA",
            0x88 => "JS",
            0x89 => "JNS",
            0x8A => "JP",
            0x8B => "JNP",
            0x8C => "JL",
            0x8D => "JGE",
            0x8E => "JLE",
            0x8F => "JG",
            _ => "J?"
        };

        Log($"{mnemonic} 0x{target:X} {(taken ? "TAKEN" : "not taken")}", offs);

        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    private static unsafe bool HandleMovzxGvEw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 0F B7 /r → MOVZX r32/64, r/m16
        int offs = 0;
        byte rex = 0;

        // optional REX prefix
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        bool rexW = (rex & 0x08) != 0;  // 1 => MOVZX r64, r/m16
        bool rexR = (rex & 0x04) != 0;
        bool rexX = (rex & 0x02) != 0;
        bool rexB = (rex & 0x01) != 0;

        if (ip[offs] != 0x0F || ip[offs + 1] != 0xB7)
            return false;

        offs += 2; // consume 0F B7
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3 & 7) | (rexR ? 8 : 0);  // destination
        int rm = (modrm & 7) | (rexB ? 8 : 0);       // source
        ulong* R = &ctx->Rax;

        ushort value16;
        string srcDesc;
        ulong memAddr = 0;

        if (mod == 0b11)
        {
            value16 = (ushort)(R[rm] & 0xFFFF);
            srcDesc = $"R{rm}w";
        }
        else
        {
            // full ModRM/SIB/RIP-rel decode
            if (mod == 0b00 && (rm & 7) == 0b101)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32; // RIP-relative
            }
            else if ((rm & 7) == 0b100)
            {
                // SIB form
                byte sib = ip[offs++];
                byte scale = (byte)((sib >> 6) & 3);
                byte idxBits = (byte)((sib >> 3) & 7);
                byte baseBits = (byte)(sib & 7);

                int indexReg = idxBits != 0b100 ? idxBits | (rexX ? 8 : 0) : -1;
                int baseReg = baseBits | (rexB ? 8 : 0);

                ulong baseVal;
                if (mod == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    baseVal = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
                }
                else
                {
                    baseVal = R[baseReg];
                }

                ulong indexVal = indexReg >= 0 ? R[indexReg] << scale : 0;
                memAddr = baseVal + indexVal;

                if (mod == 0b01)
                    memAddr += (ulong)*(sbyte*)(ip + offs++);
                else if (mod == 0b10)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    memAddr += (ulong)(long)disp32;
                }
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01)
                    memAddr += (ulong)*(sbyte*)(ip + offs++);
                else if (mod == 0b10)
                {
                    int disp32 = *(int*)(ip + offs);
                    offs += 4;
                    memAddr += (ulong)(long)disp32;
                }
            }

            // safety check
            if (memAddr < 0x10000)
            {
                Log($"MOVZX invalid [0x{memAddr:X}] skipped", offs);
                return false;
            }

            value16 = *(ushort*)memAddr;
            srcDesc = $"WORD PTR [0x{memAddr:X}]";
        }

        // zero-extend destination
        if (rexW)
        {
            // MOVZX r64, r/m16
            R[reg] = value16;
            Log($"MOVZX R{reg}, {srcDesc} => 0x{value16:X4}", offs);
        }
        else
        {
            // MOVZX r32, r/m16 → zero-extend to 64-bit architectural write
            R[reg] = (ulong)value16;
            Log($"MOVZX E{reg}, {srcDesc} => 0x{value16:X4}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }
}