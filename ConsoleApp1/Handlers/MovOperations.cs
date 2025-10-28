using System;
using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1.Handlers;

public static unsafe class MovOperations
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            case X64Opcodes.MOV_RM64_R64: return HandleMovRm64R64(ctx, address, Log);
            case X64Opcodes.MOV_RM32_IMM32: return HandleMovRm32Imm32(ctx, address, Log);
            case X64Opcodes.MOV_R32_RM32: return HandleMovR32Rm32(ctx, address, Log);
            case X64Opcodes.MOV_RM8_IMM8: return HandleMovRm8Imm8(ctx, address, Log);

            // MOV r64, imm64 (B8–BF)
            case >= X64Opcodes.MOV_RAX_IMM64 and <= X64Opcodes.MOV_RDI_IMM64:
                return HandleMovImmToReg_NoRex(ctx, address, Log);

            // 0F-prefixed MOVZX handled in X64TwoByteOpcodes
            default:
                Log($"Unhandled MOV opcode 0x{opcode:X2}", 8);
                return false;
        }
    }
    private static unsafe bool HandleMovRm32Imm32(CONTEXT* ctx, byte* address, Action<string, int> Log)
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


    private static unsafe bool HandleMovRm64R64(CONTEXT* ctx, byte* address, Action<string, int> Log)
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
    private static unsafe bool HandleMovRm8Imm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        int offs = 1; // opcode length (C6)
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // must be 0 for C6 /0
        int rm = modrm & 7;

        // Validate reg field (must be 0 for MOV r/m8, imm8)
        if (reg != 0)
        {
            Log($"Invalid reg field {reg} for MOV r/m8, imm8", offs);
            return false;
        }

        ulong addr = 0;
        ulong* R = &ctx->Rax;

        // Register direct mode (mod == 11) is invalid for C6
        if (mod == 0b11)
        {
            Log("Invalid: MOV r8, imm8 uses register mode", offs);
            return false;
        }

        // --- Handle SIB (rm == 100b) ---
        if (rm == 4)
        {
            byte sib = ip[offs++];
            byte scale = (byte)(sib >> 6 & 3);
            byte index = (byte)(sib >> 3 & 7);
            byte baseReg = (byte)(sib & 7);

            addr = R[baseReg];
            if (index != 4) // 4 means "no index"
                addr += R[index] << scale;

            // Optional displacement
            if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(ip + offs);
                offs++;
                addr = (ulong)((long)addr + disp8);
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                addr = (ulong)((long)addr + disp32);
            }
        }
        else if (mod == 0b00 && rm == 0b101)
        {
            // disp32 absolute address (no base)
            int disp32 = *(int*)(ip + offs);
            offs += 4;
            addr = (ulong)(long)disp32;
        }
        else
        {
            addr = R[rm];

            if (mod == 0b01)
            {
                sbyte disp8 = *(sbyte*)(ip + offs);
                offs++;
                addr = (ulong)((long)addr + disp8);
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs);
                offs += 4;
                addr = (ulong)((long)addr + disp32);
            }
        }

        // --- Immediate 8-bit value ---
        byte imm = *(ip + offs);
        offs++;

        *(byte*)addr = imm;

        Log($"MOV BYTE PTR [0x{addr:X}], 0x{imm:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    private static bool HandleMovImmToReg_NoRex(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte opcode = *address;                 // B8..BF
        int reg = opcode - 0xB8;                // 0..7 => RAX..RDI
        uint imm32 = *(uint*)(address + 1);

        // Write 64-bit with zero-extend semantics (writing r32 clears upper 32)
        ulong* dst = &ctx->Rax + reg;
        *dst = imm32;

        Log($"MOV R{reg}, 0x{imm32:X8}", 5);
        ctx->Rip += 5;
        return true;
    }
    private static bool HandleMovR32Rm32(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // MOV r32, r/m32  =>  8B /r
        byte modrm = *(address + 1);
        byte mod = (byte)(modrm >> 6 & 0x3);
        byte reg = (byte)(modrm >> 3 & 0x7); // destination (r32)
        byte rm = (byte)(modrm & 0x7);        // source (r/m32)
        int offs = 2;

        ulong memAddr = 0;
        uint value;

        if (mod == 0b11)
        {
            // Register to register
            value = (uint)((&ctx->Rax)[rm] & 0xFFFFFFFF);
            ((uint*)&ctx->Rax)[reg] = value;
            Log($"MOV R{reg}, R{rm} (32-bit) => 0x{value:X8}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // Memory addressing
        if (mod == 0b00)
        {
            // [reg]
            memAddr = *(&ctx->Rax + rm);
        }
        else if (mod == 0b01)
        {
            // [reg + disp8]
            sbyte disp8 = *(sbyte*)(address + offs);
            offs += 1;
            memAddr = *(&ctx->Rax + rm) + (ulong)disp8;
        }
        else if (mod == 0b10)
        {
            // [reg + disp32]
            int disp32 = *(int*)(address + offs);
            offs += 4;
            memAddr = *(&ctx->Rax + rm) + (ulong)(long)disp32;
        }
        else
        {
            Log($"Unsupported MOV r32,[r/m32] Mod={mod}", offs);
            return false;
        }

        value = *(uint*)memAddr;
        ((uint*)&ctx->Rax)[reg] = value;

        Log($"MOV R{reg}, [0x{memAddr:X}] => R{reg}=0x{value:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}