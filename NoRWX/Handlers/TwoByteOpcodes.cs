using System;
using System.IO;
using System.Runtime.InteropServices;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

public static unsafe class TwoByteOpcodes
{
    public static unsafe bool HandleSetcc(CONTEXT* ctx, byte* ip, Action<string, int> Log)
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
        byte mod = (byte)(modrm >> 6 & 3);
        int rm = modrm & 7 | (rexB ? 8 : 0);
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
            0x9E => zf || sf != of,         // SETLE
            0x9F => !zf && sf == of,        // SETG
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

    // [REX?] 0F 4x /r → CMOVcc r32/r64, r/m32/r/m64
    public static unsafe bool HandleCmovcc(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        int offs = 0;
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];
        bool W = (rex & 0x08) != 0;
        bool REX_R = (rex & 0x04) != 0;
        bool REX_X = (rex & 0x02) != 0;
        bool REX_B = (rex & 0x01) != 0;

        if (ip[offs++] != 0x0F) return false;
        byte opcode = ip[offs++];
        if (opcode < 0x40 || opcode > 0x4F) return false;

        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7 | (REX_R ? 8 : 0);
        int rm = modrm & 7 | (REX_B ? 8 : 0);
        ulong* R = &ctx->Rax;

        ulong src;
        if (mod == 0b11)
            src = W ? R[rm] : (uint)R[rm];
        else
        {
            ulong addr = Rex.ResolveEA_Rex(ctx, ip, ref offs, mod, rm, REX_X, REX_B, out _);
            src = W ? *(ulong*)addr : *(uint*)addr;
        }

        uint flags = ctx->EFlags;
        bool cf = (flags & 1) != 0;
        bool zf = (flags & 0x40) != 0;
        bool sf = (flags & 0x80) != 0;
        bool of = (flags & 0x800) != 0;
        bool pf = (flags & 4) != 0;

        bool cond = opcode switch
        {
            0x40 => of,              0x41 => !of,
            0x42 => cf,              0x43 => !cf,
            0x44 => zf,              0x45 => !zf,
            0x46 => cf || zf,        0x47 => !cf && !zf,
            0x48 => sf,              0x49 => !sf,
            0x4A => pf,              0x4B => !pf,
            0x4C => sf != of,        0x4D => sf == of,
            0x4E => zf || sf != of,  0x4F => !zf && sf == of,
            _ => false
        };

        if (cond)
            R[reg] = W ? src : (uint)src;

        string[] names = ["CMOVO","CMOVNO","CMOVB","CMOVAE","CMOVE","CMOVNE","CMOVBE","CMOVA",
                          "CMOVS","CMOVNS","CMOVP","CMOVNP","CMOVL","CMOVGE","CMOVLE","CMOVG"];
        Log($"{names[opcode - 0x40]} R{reg}, R{rm} => {(cond ? "moved" : "not moved")}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}