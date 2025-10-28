
using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1;

internal static class Mov
{

    public static unsafe bool HandleMovRm32Imm32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);
        if (reg != 0)
        {
            Log($"Unsupported C7 /{reg}", 3);
            return false;
        }
        ulong memAddr = 0;
        int offs = 2;
        if (mod == 0b01)
        {
            if (rm == 0b100)
            {
                byte sib = *(address + offs);
                offs += 1;
                sbyte disp8 = *(sbyte*)(address + offs);
                offs += 1;
                byte baseReg = (byte)(sib & 0x7);
                if (baseReg != 0b100)
                {
                    Log($"C7 with unexpected SIB base={baseReg}", 3);
                    return false;
                }
                memAddr = ctx->Rsp + (ulong)disp8;
            }
            else
            {
                sbyte disp8 = *(sbyte*)(address + offs);
                offs += 1;
                ulong baseVal = *(&ctx->Rax + rm);
                memAddr = baseVal + (ulong)disp8;
            }
        }
        else if (mod == 0b10)
        {
            if (rm == 0b100)
            {
                byte sib = *(address + offs);
                offs += 1;
                int disp32 = *(int*)(address + offs);
                offs += 4;
                byte baseReg = (byte)(sib & 0x7);
                if (baseReg != 0b100)
                {
                    Log($"C7 with unexpected SIB base={baseReg}", 3);
                    return false;
                }
                memAddr = ctx->Rsp + (ulong)disp32;
            }
            else
            {
                int disp32 = *(int*)(address + offs);
                offs += 4;
                ulong baseVal = *(&ctx->Rax + rm);
                memAddr = baseVal + (ulong)disp32;
            }
        }
        uint imm32 = *(uint*)(address + offs);
        offs += 4;
        *(uint*)memAddr = imm32;
        Log($"MOV dword ptr [0x{memAddr:X}], 0x{imm32:X8}", 3);
        ctx->Rip += (ulong)offs;
        return true;
    }


    public static unsafe bool HandleMovRm64R64(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7);
        byte rm = (byte)(modrm & 0x7);

        ulong* srcRegPtr = &ctx->Rax + reg;

        // MOV r/m64, r64
        if (mod == 0b11)
        {
            // register to register
            ulong* dstRegPtr = &ctx->Rax + rm;
            *dstRegPtr = *srcRegPtr;
            Log($"MOV R{rm}, R{reg} => R{rm}=0x{*dstRegPtr:X}", 2);
            ctx->Rip += 2;
            return true;
        }
        else if (mod == 0b01)
        {
            // [base + disp8]
            sbyte disp8 = *(sbyte*)(address + 2);
            ulong baseAddr = *(&ctx->Rax + rm);
            ulong memAddr = baseAddr + (ulong)disp8;
            ulong value = *srcRegPtr;
            *(ulong*)memAddr = value;
            Log($"MOV [R{rm}{disp8:+#;-#;0}], R{reg}  => 0x{memAddr:X}=0x{value:X}", 3);
            ctx->Rip += 3;
            return true;
        }
        else if (mod == 0b10)
        {
            if (rm == 0b100) // SIB + disp32
            {
                byte sib = *(address + 2);
                byte scale = (byte)(sib >> 6 & 0x3);
                byte index = (byte)(sib >> 3 & 0x7);
                byte baseReg = (byte)(sib & 0x7);
                int disp32 = *(int*)(address + 3);
                ulong baseVal = baseReg == 0b101 ? 0 : *(&ctx->Rax + baseReg);
                ulong indexVal = index == 0b100 ? 0 : *(&ctx->Rax + index) << scale;
                ulong memAddr = baseVal + indexVal + (ulong)disp32;
                ulong value = *srcRegPtr;
                *(ulong*)memAddr = value;
                Log($"MOV [SIB+disp32 0x{memAddr:X}], R{reg} => 0x{memAddr:X}=0x{value:X}", 7);
                ctx->Rip += 7;
                return true;
            }
            else
            {
                // [base + disp32]
                int disp32 = *(int*)(address + 2);
                ulong baseAddr = *(&ctx->Rax + rm);
                ulong memAddr = baseAddr + (ulong)disp32;
                ulong value = *srcRegPtr;
                *(ulong*)memAddr = value;
                Log($"MOV [R{rm}+0x{disp32:X}], R{reg} => 0x{memAddr:X}=0x{value:X}", 6);
                ctx->Rip += 6;
                return true;
            }
        }
        else if (mod == 0b00 && rm == 0b100) // SIB addressing, no displacement
        {
            byte sib = *(address + 2);
            byte scale = (byte)(sib >> 6 & 0x3);
            byte index = (byte)(sib >> 3 & 0x7);
            byte baseReg = (byte)(sib & 0x7);
            ulong baseVal = baseReg == 0b101 ? 0 : *(&ctx->Rax + baseReg);
            ulong indexVal = index == 0b100 ? 0 : *(&ctx->Rax + index) << scale;
            ulong memAddr = baseVal + indexVal;
            ulong value = *srcRegPtr;
            *(ulong*)memAddr = value;
            Log($"MOV [SIB 0x{memAddr:X}], R{reg} => 0x{memAddr:X}=0x{value:X}", 3);
            ctx->Rip += 3;
            return true;
        }

        Log($"Unsupported MOV with ModRM 0x{modrm:X2}", 3);
        return false;
    }
}