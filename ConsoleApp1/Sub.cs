using static X64Emulator;

internal static class Sub
{

    public static unsafe bool Handle(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // 48 83 /5 r/m64, imm8 (SUB)
        byte modrm = *(address + 2);
        byte mod = (byte)((modrm >> 6) & 0x3);
        byte reg = (byte)((modrm >> 3) & 0x7);
        byte rm = (byte)(modrm & 0x7);
        if (reg != 5)
        {
            Log($"Unsupported 48 83 /{reg} form", 3);
            return false;
        }

        int offs = 3; // after ModRM
        ulong memAddr = 0;

        // helper: compute SIB addressing
        ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
        {
            byte scaleBits = (byte)((sib >> 6) & 0x3);
            byte idxBits = (byte)((sib >> 3) & 0x7);
            byte baseBits = (byte)(sib & 0x7);
            ulong baseVal = 0, indexVal = 0;

            if (baseBits != 0b101)
                baseVal = *((&ctx->Rax) + baseBits);
            if (idxBits != 0b100)
            {
                indexVal = *((&ctx->Rax) + idxBits);
                indexVal <<= scaleBits;
            }

            ulong addr = baseVal + indexVal;
            if (modLocal == 0b01)
            {
                long disp8 = *(sbyte*)(address + offsLocal); offsLocal += 1;
                addr += (ulong)disp8;
            }
            else if (modLocal == 0b10)
            {
                int disp32 = *(int*)(address + offsLocal); offsLocal += 4;
                addr += (ulong)(long)disp32;
            }
            return addr;
        }

        // decode addressing
        if (mod == 0b00)
        {
            if (rm == 0b100)
            {
                byte sib = *(address + offs++);
                memAddr = computeSibAddr(sib, mod, ref offs);
            }
            else
            {
                memAddr = *((&ctx->Rax) + rm);
            }
        }
        else if (mod == 0b01)
        {
            if (rm == 0b100)
            {
                byte sib = *(address + offs++);
                memAddr = computeSibAddr(sib, mod, ref offs);
            }
            else
            {
                long disp8 = *(sbyte*)(address + offs++);
                memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
            }
        }
        else if (mod == 0b10)
        {
            if (rm == 0b100)
            {
                byte sib = *(address + offs++);
                memAddr = computeSibAddr(sib, mod, ref offs);
            }
            else
            {
                int disp32 = *(int*)(address + offs); offs += 4;
                memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
            }
        }

        // perform subtraction
        byte imm8 = *(address + offs++);
        ulong orig = *(ulong*)memAddr;
        ulong result = orig - imm8;
        *(ulong*)memAddr = result;

        Log($"SUB QWORD PTR [0x{memAddr:X}], 0x{imm8:X2} => 0x{orig:X}-0x{imm8:X}=0x{result:X}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}