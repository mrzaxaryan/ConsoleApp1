using System;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

public static unsafe class MoveOperations
{
    public static unsafe bool HandleMovEvGv32(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 0x89 /r → MOV r/m32, r32
        int offs = 1; // skip opcode
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6);
        int reg = modrm >> 3 & 7; // source r32
        int rm = modrm & 7;        // destination r/m32

        ulong* R64 = &ctx->Rax;
        uint src = (uint)R64[reg];

        // --- Register destination ---
        if (mod == 0b11)
        {
            R64[rm] = src; // zero-extend
            Log($"MOV E{rm}, E{reg}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // --- Memory destination ---
        ulong addr = 0;
        int disp = 0;

        if (mod == 0b00 && rm == 5)
        {
            // [disp32]
            disp = *(int*)(ip + offs);
            offs += 4;
            addr = (ulong)disp;
        }
        else
        {
            addr = R64[rm];

            if (mod == 0b01)
            {
                disp = *(sbyte*)(ip + offs);
                offs += 1;
            }
            else if (mod == 0b10)
            {
                disp = *(int*)(ip + offs);
                offs += 4;
            }

            addr += (ulong)disp;
        }

        *(uint*)addr = src;
        Log($"MOV [0x{addr:X}], E{reg}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }


    public static unsafe bool HandleMovRm32Imm32(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // C7 /0 → MOV r/m32, imm32
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        if (ip[offs++] != 0xC7)
            return false;

        bool B = (rex & 0x01) != 0;
        bool W = (rex & 0x08) != 0; // if REX.W=1, this is actually MOV r/m64, imm32 sign-extended

        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int regop = modrm >> 3 & 7;
        int rm = modrm & 7 | (B ? 8 : 0);

        if (regop != 0)
        {
            Log($"Unsupported C7 /{regop}", offs);
            return false;
        }

        ulong* R64 = &ctx->Rax;
        ulong addr = 0;
        string dstDesc;

        // --- Resolve addressing ---
        if (mod == 0b11)
        {
            // Register direct
            dstDesc = $"R{rm}d";
        }
        else
        {
            // Memory addressing
            if (mod == 0b00 && (modrm & 7) == 0b101)
            {
                // RIP-relative disp32
                int disp32 = *(int*)(ip + offs); offs += 4;
                addr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
                dstDesc = $"DWORD PTR [RIP+0x{disp32:X}]";
            }
            else
            {
                if ((modrm & 7) == 0b100)
                {
                    // SIB byte present
                    byte sib = ip[offs++];
                    int scale = sib >> 6 & 3;
                    int index = sib >> 3 & 7;
                    int bas = sib & 7 | (B ? 8 : 0);

                    ulong baseVal = bas == 0b101 && mod == 0b00 ? 0 : R64[bas];
                    ulong indexVal = index == 0b100 ? 0 : R64[index] << scale;

                    addr = baseVal + indexVal;
                    if (mod == 0b01)
                    {
                        long d8 = *(sbyte*)(ip + offs); offs += 1;
                        addr += (ulong)d8;
                    }
                    else if (mod == 0b10)
                    {
                        int d32 = *(int*)(ip + offs); offs += 4;
                        addr += (ulong)(long)d32;
                    }

                    dstDesc = $"DWORD PTR [0x{addr:X}]";
                }
                else
                {
                    addr = R64[rm];
                    if (mod == 0b01)
                    {
                        long d8 = *(sbyte*)(ip + offs); offs += 1;
                        addr += (ulong)d8;
                    }
                    else if (mod == 0b10)
                    {
                        int d32 = *(int*)(ip + offs); offs += 4;
                        addr += (ulong)(long)d32;
                    }

                    dstDesc = $"DWORD PTR [0x{addr:X}]";
                }
            }
        }

        // --- Immediate value ---
        uint imm32 = *(uint*)(ip + offs);
        offs += 4;

        if (mod == 0b11)
        {
            // Register form — MOV r32, imm32 (zero-extend into 64-bit)
            R64[rm] = imm32;
        }
        else
        {
            // Memory form
            *(uint*)addr = imm32;
        }

        Log($"MOV {dstDesc}, 0x{imm32:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleMovRm64R64(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // MOV r/m64, r64  →  0x89 with REX.W=1 in 64-bit mode
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // We assume the dispatcher ensured opcode is 0x89; no need to re-check here
        offs++; // skip opcode (0x89)

        bool W = (rex & 0x08) != 0; // must be 1 for 64-bit
        bool R = (rex & 0x04) != 0; // extends ModRM.reg
        bool X = (rex & 0x02) != 0; // extends SIB.index
        bool B = (rex & 0x01) != 0; // extends ModRM.r/m (and SIB.base)

        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7 | (R ? 8 : 0); // source register (r64)
        int rm = modrm & 7 | (B ? 8 : 0);       // destination (r/m64)

        ulong* R64 = &ctx->Rax;

        // Register-direct form
        if (mod == 0b11)
        {
            // Write 64-bit reg (we assume REX.W=1)
            R64[rm] = R64[reg];

            Log($"MOV R{rm}, R{reg} => R{rm}=0x{R64[rm]:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // -------- Memory addressing (EA resolution) --------
        ulong addr = 0;
        string dstDesc;

        bool usesSib = (modrm & 7) == 0b100;
        if (mod == 0b00 && (modrm & 7) == 0b101)
        {
            // RIP-relative disp32: [RIP + disp32]
            int disp32 = *(int*)(ip + offs); offs += 4;
            addr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            dstDesc = $"QWORD PTR [RIP+0x{disp32:X}]";
        }
        else if (usesSib)
        {
            byte sib = ip[offs++];
            int scale = sib >> 6 & 3;
            int idx = sib >> 3 & 7 | (X ? 8 : 0);
            int bas = sib & 7 | (B ? 8 : 0);

            // Index suppressed when original index==100 and REX.X==0
            bool indexNone = (sib >> 3 & 7) == 0b100 && !X;
            ulong indexVal = indexNone ? 0 : R64[idx] << scale;

            // Base “disp32 only” when mod==00 and base==101 (no REX.B effect on that special case)
            bool baseIsDisp32 = mod == 0b00 && (sib & 7) == 0b101;
            ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

            addr = baseVal + indexVal;

            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(ip + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                addr += (ulong)(long)d32;
            }
            else if (baseIsDisp32)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                addr = (ulong)(long)d32; // absolute disp32 (no RIP-rel here)
            }

            dstDesc = $"QWORD PTR [0x{addr:X}]";
        }
        else
        {
            // Simple [reg] + optional disp
            addr = R64[rm];
            if (mod == 0b01)
            {
                long d8 = *(sbyte*)(ip + offs); offs += 1;
                addr += (ulong)d8;
            }
            else if (mod == 0b10)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                addr += (ulong)(long)d32;
            }
            dstDesc = $"QWORD PTR [0x{addr:X}]";
        }

        // -------- Perform the move --------
        // For MOV r/m64, r64 we must store 64-bit (REX.W expected to be 1)
        *(ulong*)addr = R64[reg];

        Log($"MOV {dstDesc}, R{reg} => [0x{addr:X}]=0x{R64[reg]:X}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleMovRm8Imm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // C6 /0  →  MOV r/m8, imm8
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // Dispatcher already matched opcode; just skip it
        // opcode = 0xC6
        offs++;

        bool REX_B = (rex & 0x01) != 0; // extends ModRM.r/m (and SIB.base)
        bool REX_X = (rex & 0x02) != 0; // extends SIB.index
        bool REX_W = (rex & 0x08) != 0; // unused here (byte op), but present is fine
        bool hasREX = rex != 0;

        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int regop = modrm >> 3 & 7;                // must be 0 for C6 /0
        int rm = modrm & 7 | (REX_B ? 8 : 0);   // r/m (maybe extended)

        if (regop != 0)
        {
            Log($"Invalid C6 /{regop} (expected /0 for MOV r/m8, imm8)", offs);
            return false;
        }

        ulong* R64 = &ctx->Rax;

        // Helper: get pointer to an 8-bit GPR, honoring AH/CH/DH/BH vs REX rules
        static byte* GetByteRegPtr(ulong* R64, int rmLow3, bool rexPresent, int rmExtended /*0..15*/)
        {
            if (!rexPresent && rmLow3 >= 4 && rmLow3 <= 7)
            {
                // AH(4)/CH(5)/DH(6)/BH(7): high 8-bit of AX/CX/DX/BX (only encodable without REX)
                int baseIdx = rmLow3 switch { 4 => 0, 5 => 1, 6 => 2, 7 => 3, _ => 0 };
                return (byte*)(R64 + baseIdx) + 1; // high byte of the 16-bit low word
            }
            else
            {
                // Low 8-bit of selected register (RAX..R15)
                return (byte*)(R64 + rmExtended);
            }
        }

        // Destination: either register byte or memory byte
        byte* dstPtr = null;
        ulong memAddr = 0;

        if (mod == 0b11)
        {
            // Register-direct: MOV r8, imm8  (valid for C6 /0)
            int rmLow3 = modrm & 7;
            dstPtr = GetByteRegPtr(R64, rmLow3, hasREX, rm);
        }
        else
        {
            // ----- Memory addressing -----
            bool usesSib = (modrm & 7) == 0b100;

            if (mod == 0b00 && (modrm & 7) == 0b101)
            {
                // RIP-relative disp32: [RIP + disp32]
                int disp32 = *(int*)(ip + offs); offs += 4;
                memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
            }
            else if (usesSib)
            {
                byte sib = ip[offs++];
                int scale = sib >> 6 & 3;
                int idx = sib >> 3 & 7 | (REX_X ? 8 : 0);
                int bas = sib & 7 | (REX_B ? 8 : 0);

                bool indexNone = (sib >> 3 & 7) == 0b100 && !REX_X; // index==4 with no REX.X ⇒ no index
                ulong indexVal = indexNone ? 0 : R64[idx] << scale;

                bool baseIsDisp32 = mod == 0b00 && (sib & 7) == 0b101; // SIB base==101 and mod==00 ⇒ disp32-only
                ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

                memAddr = baseVal + indexVal;

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
                else if (baseIsDisp32)
                {
                    int d32 = *(int*)(ip + offs); offs += 4;
                    memAddr = (ulong)(long)d32; // absolute disp32 (not RIP-relative)
                }
            }
            else
            {
                memAddr = R64[rm];

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

            dstPtr = (byte*)memAddr;
        }

        // Immediate
        byte imm8 = *(ip + offs); offs += 1;

        // Store
        *dstPtr = imm8;

        // Log
        if (mod == 0b11)
        {
            int rmLow3 = modrm & 7;
            string regName =
                !hasREX && rmLow3 >= 4 && rmLow3 <= 7
                    ? rmLow3 switch { 4 => "AH", 5 => "CH", 6 => "DH", 7 => "BH", _ => $"R{rm}b" }
                    : $"R{rm}b";
            Log($"MOV {regName}, 0x{imm8:X2}", offs);
        }
        else
        {
            Log($"MOV BYTE PTR [0x{memAddr:X}], 0x{imm8:X2}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleMovImmToReg(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // MOV rAX..rDI, imm32 or imm64
        int offs = 0;
        byte rex = 0;
        if ((address[offs] & 0xF0) == 0x40)
            rex = address[offs++]; // optional REX prefix

        byte opcode = address[offs++];
        int reg = opcode - 0xB8 | ((rex & 0x01) != 0 ? 8 : 0); // extend with REX.B

        ulong* R = &ctx->Rax;

        if ((rex & 0x08) != 0)
        {
            // REX.W=1 → MOV r64, imm64 (sign-extended)
            ulong imm64 = *(ulong*)(address + offs);
            offs += 8;
            R[reg] = imm64;
            Log($"MOV R{reg}, 0x{imm64:X16}", offs);
        }
        else
        {
            // No REX.W → MOV r32, imm32 (zero-extend)
            uint imm32 = *(uint*)(address + offs);
            offs += 4;
            R[reg] = imm32;
            Log($"MOV R{reg}, 0x{imm32:X8}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleMovR32Rm32(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 8B /r → MOV r32, r/m32
        int offs = 0;

        // Optional REX prefix
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40)
            rex = ip[offs++];

        // Opcode already matched (0x8B)
        offs++;

        bool REX_R = (rex & 0x04) != 0; // extends ModRM.reg
        bool REX_B = (rex & 0x01) != 0; // extends ModRM.r/m
        bool REX_X = (rex & 0x02) != 0; // extends SIB.index

        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7 | (REX_R ? 8 : 0); // destination register
        int rm = modrm & 7 | (REX_B ? 8 : 0);       // source (r/m32)

        ulong* R64 = &ctx->Rax;
        uint value;
        ulong memAddr = 0;

        if (mod == 0b11)
        {
            // Register to register: MOV r32, r/m32
            value = (uint)R64[rm];    // take low 32 bits
            R64[reg] = value;         // zero-extend write
            Log($"MOV R{reg}d, R{rm}d => 0x{value:X8}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // --- Memory addressing ---
        bool usesSib = (modrm & 7) == 0b100;

        if (mod == 0b00 && (modrm & 7) == 0b101)
        {
            // RIP-relative: [RIP + disp32]
            int disp32 = *(int*)(ip + offs); offs += 4;
            memAddr = ctx->Rip + (ulong)offs + (ulong)(long)disp32;
        }
        else if (usesSib)
        {
            // SIB byte
            byte sib = ip[offs++];
            int scale = sib >> 6 & 3;
            int idx = sib >> 3 & 7 | (REX_X ? 8 : 0);
            int bas = sib & 7 | (REX_B ? 8 : 0);

            bool indexNone = (sib >> 3 & 7) == 0b100 && !REX_X; // index==4, no REX.X ⇒ no index
            ulong indexVal = indexNone ? 0 : R64[idx] << scale;

            bool baseIsDisp32 = mod == 0b00 && (sib & 7) == 0b101;
            ulong baseVal = baseIsDisp32 ? 0 : R64[bas];

            memAddr = baseVal + indexVal;

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
            else if (baseIsDisp32)
            {
                int d32 = *(int*)(ip + offs); offs += 4;
                memAddr = (ulong)(long)d32;
            }
        }
        else
        {
            memAddr = R64[rm];
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

        // Load 32-bit value from memory
        value = *(uint*)memAddr;
        R64[reg] = value; // zero-extend into 64-bit register

        Log($"MOV R{reg}d, [0x{memAddr:X}] => 0x{value:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}