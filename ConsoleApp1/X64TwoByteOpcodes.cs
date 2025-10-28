using System;
using System.IO;
using System.Runtime.InteropServices;
using static X64Emulator;

public static unsafe class X64TwoByteOpcodes
{
    public static bool Handle(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte op2 = *(address + 1);

        switch (op2)
        {
            case X64Opcodes.JNE_NEAR:
                return HandleJneNear(ctx, address, Log);

            case X64Opcodes.JE_NEAR:
                return HandleJeNear(ctx, address, Log);

            case X64Opcodes.MOVZX_GvEw:
                return HandleMovzxGvEw(ctx, address, Log);

            case X64Opcodes.MOVZX_R32_RM8:
                return HandleMovzxR32Rm8(ctx, address, Log);

            case X64Opcodes.SETE:
                return HandleSetcc(ctx, address, Log, condition: "ZF");

            default:
                Log($"Unsupported two-byte opcode 0F {op2:X2}", 8);
                throw new NotImplementedException($"0F {op2:X2} not implemented");
        }
    }
    private static unsafe bool HandleSetcc(CONTEXT* ctx, byte* ip, Action<string, int> Log, string condition)
    {
        // 0F 94 /r → SETZ r/m8
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // condition selector for other SETcc variants, not used here
        int rm = (modrm & 7);

        ulong* R = &ctx->Rax;

        // Determine condition result
        bool condMet = false;
        if (condition == "ZF") condMet = (ctx->EFlags & (1 << 6)) != 0; // Zero Flag

        byte value = condMet ? (byte)1 : (byte)0;
        string destDesc;

        if (mod == 0b11)
        {
            // register
            byte* dst = (byte*)(R + rm);
            *dst = value;
            destDesc = $"R{rm}b";
        }
        else
        {
            // simple [register] memory
            ulong addr = R[rm];
            *(byte*)addr = value;
            destDesc = $"BYTE PTR [0x{addr:X}]";
        }

        Log($"SETZ {destDesc} => {(condMet ? "1" : "0")}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static unsafe bool HandleMovzxR32Rm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // ip[0]=0F, ip[1]=B6
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7; // dest (Ereg)
        int rm = (modrm & 0x7);      // src
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
            if (mod == 0b00 && rm == 0b101)
            {
                int disp32 = *(int*)(ip + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01) { long d8 = *(sbyte*)(ip + offs); offs += 1; memAddr += (ulong)d8; }
                else if (mod == 0b10) { int d32 = *(int*)(ip + offs); offs += 4; memAddr += (ulong)(long)d32; }
            }
            value8 = *(byte*)memAddr;
            srcDesc = $"BYTE PTR [0x{memAddr:X}]";
        }

       ((uint*)R)[reg] = value8; // zero-extend via Ereg write

        Log($"MOVZX E{reg}, {srcDesc} => 0x{value8:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleJneNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F 85 rel32  (length = 6)
        int rel32 = *(int*)(address + 2);
        ulong nextRip = ctx->Rip + 6;
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = nextRip + (ulong)(long)rel32;
        bool taken = !zf;

        Log($"JNE near 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 6);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    private static bool HandleJeNear(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 0F 84 rel32  (length = 6)
        int rel32 = *(int*)(address + 2);
        ulong nextRip = ctx->Rip + 6;
        bool zf = (ctx->EFlags & 0x40) != 0;
        ulong target = nextRip + (ulong)(long)rel32;
        bool taken = zf;

        Log($"JE near 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 6);
        ctx->Rip = taken ? target : nextRip;
        return true;
    }
    // MOVZX r32/64, r/m16 : 0F B7 /r
    private static unsafe bool HandleMovzxGvEw(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 0F B7 /r → MOVZX r32/64, r/m16
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 0x3);
        int reg = (modrm >> 3) & 0x7;
        int rm = (modrm & 0x7);
        ulong* R = &ctx->Rax;

        ulong memAddr = 0;
        ushort val16;
        string srcDesc;

        if (mod == 0b11)
        {
            val16 = (ushort)(R[rm] & 0xFFFF);
            srcDesc = $"R{rm}w";
        }
        else
        {
            if (mod == 0b00 && rm == 0b101)
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                memAddr = nextRip + (ulong)(long)disp32;
            }
            else
            {
                memAddr = R[rm];
                if (mod == 0b01)
                {
                    long d8 = *(sbyte*)(ip + offs); offs += 1;
                    memAddr += (ulong)d8;
                }
                else if (mod == 0b10)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr += (ulong)(long)d32;
                }
            }

            val16 = *(ushort*)memAddr;
            srcDesc = $"WORD PTR [0x{memAddr:X}]";
        }

    ((uint*)R)[reg] = val16;
        Log($"MOVZX E{reg}, {srcDesc} => 0x{val16:X4}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
