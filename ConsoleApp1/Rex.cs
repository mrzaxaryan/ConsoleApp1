using ConsoleApp1;
using static ConsoleApp1.X64Emulator;

internal static class Rex
{
    public static unsafe bool Handle(X64Emulator.CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        // REX bits
        byte rex = *address;                 // 0x4X
        bool W = (rex & 0x08) != 0;
        bool R = (rex & 0x04) != 0;
        bool X = (rex & 0x02) != 0;
        bool B = (rex & 0x01) != 0;

        byte op2 = *(address + 1);
        byte op3 = *(address + 2);

        if (op2 >= 0x50 && op2 <= 0x57)
        {
            int reg = op2 - 0x50; // 0..7 → R8..R15
            ulong* regPtr = (&ctx->R8) + reg;
            Log($"PUSH R{8 + reg}", 2);
            ctx->Rsp -= 8;
            *(ulong*)ctx->Rsp = *regPtr;
            ctx->Rip += 2;
            return true;
        }
        // POP R8–R15 (41 58–5F)
        if (op2 >= 0x58 && op2 <= 0x5F)
        {
            int reg = op2 - 0x58; // 0..7 → R8..R15
            ulong* regPtr = (&ctx->R8) + reg;
            ulong v = *(ulong*)ctx->Rsp;
            ctx->Rsp += 8;
            *regPtr = v;
            Log($"POP R{8 + reg}", 2);
            ctx->Rip += 2;
            return true;
        }

        // --- keep your existing special-cases ---
        if (op2 == 0x89 && op3 == 0xE5)      // 48 89 E5  -> MOV RBP, RSP
        {
            Log("MOV RBP, RSP", 3);
            ctx->Rbp = ctx->Rsp;
            ctx->Rip += 3;
            return true;
        }
        if (op2 == 0x83 && op3 == 0xEC) // 48 83 EC imm8 → SUB RSP, imm8
        {
            byte imm8 = *(address + 3);
            ctx->Rsp -= imm8;
            Log($"SUB RSP, 0x{imm8:X2} => new RSP=0x{ctx->Rsp:X}", 4);
            ctx->Rip += 4;
            return true;
        }

        // --- generic: REX.W + 81 /r  => Group1 (imm32 sign-extended) on r/m64 ---
        if (op2 == 0x81)
        {
            if (!W)
            {
                Log($"Unsupported REX(non-W) 0x48 0x81 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2; // ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int grp = (modrm >> 3) & 0x7;     // /0 .. /7
            int rm = (modrm & 0x7) | (B ? 8 : 0);

            // SIB/RIP-rel helper (same style as your other handlers)
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(address + offsLocal);
                    offsLocal += 4;
                    baseVal = (ulong)(long)disp32;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 => no index, REX.X ignored
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }
                return baseVal + indexVal;
            }

            // Destination: register or memory
            ulong* dstReg = null;
            ulong memAddr = 0;
            bool isReg = (mod == 0b11);
            if (isReg)
            {
                dstReg = (&ctx->Rax) + rm;
            }
            else
            {
                if ((mod == 0b00) && ((modrm & 0x7) == 0b101))
                {
                    // RIP-relative disp32
                    int disp32r = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32r;
                }
                else if (((modrm & 0x7) == 0b100))
                {
                    // SIB (with optional disp8/disp32 inside)
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                    if (mod == 0b01)
                    {
                        long disp8 = *(sbyte*)(address + offs++);
                        memAddr += (ulong)disp8;
                    }
                    else if (mod == 0b10)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr += (ulong)(long)disp32;
                    }
                }
                else
                {
                    // [base] [+ disp8/disp32]
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01)
                    {
                        long disp8 = *(sbyte*)(address + offs++);
                        memAddr += (ulong)disp8;
                    }
                    else if (mod == 0b10)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr += (ulong)(long)disp32;
                    }
                }
            }

            // Fetch imm32 (sign-extended to 64)
            long imm32 = *(int*)(address + offs); offs += 4;
            ulong uimm = (ulong)imm32;

            // Execute based on /r group
            if (grp == 0) // ADD
            {
                if (isReg)
                {
                    ulong old = *dstReg; *dstReg = old + uimm;
                    Log($"ADD R{rm}, 0x{(uint)imm32:X8} => 0x{old:X}+0x{uimm:X}=0x{*dstReg:X}", offs);
                }
                else
                {
                    ulong old = *(ulong*)memAddr; ulong nw = old + uimm; *(ulong*)memAddr = nw;
                    Log($"ADD QWORD PTR [0x{memAddr:X}], 0x{(uint)imm32:X8} => 0x{old:X}+0x{uimm:X}=0x{nw:X}", offs);
                }
                // (Optional) set ZF/SF if you need them; you’ve been selective so far.
                ctx->Rip += (ulong)offs; return true;
            }
            else if (grp == 5) // SUB
            {
                if (isReg)
                {
                    ulong old = *dstReg; *dstReg = old - uimm;
                    Log($"SUB R{rm}, 0x{(uint)imm32:X8} => 0x{old:X}-0x{uimm:X}=0x{*dstReg:X}", offs);
                }
                else
                {
                    ulong old = *(ulong*)memAddr; ulong nw = old - uimm; *(ulong*)memAddr = nw;
                    Log($"SUB QWORD PTR [0x{memAddr:X}], 0x{(uint)imm32:X8} => 0x{old:X}-0x{uimm:X}=0x{nw:X}", offs);
                }
                ctx->Rip += (ulong)offs; return true;
            }
            else if (grp == 7) // CMP
            {
                ulong lhs = isReg ? *dstReg : *(ulong*)memAddr;
                ulong res = lhs - uimm;

                // Minimal flags (you’ve been using ZF/SF in branches)
                bool zf = (res == 0);
                bool sf = (res & (1UL << 63)) != 0;
                ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                if (isReg)
                    Log($"CMP R{rm}, 0x{(uint)imm32:X8} => (R{rm}=0x{lhs:X})", offs);
                else
                    Log($"CMP QWORD PTR [0x{memAddr:X}], 0x{(uint)imm32:X8} => (mem=0x{lhs:X})", offs);

                ctx->Rip += (ulong)offs; return true;
            }

            Log($"Unsupported 48 81 /{grp} form", offs);
            return false;
        }

        // --- generic: REX.W + C7 /0  => MOV r/m64, imm32 (sign-extended) ---
        if (op2 == 0xC7)
        {
            if ((rex & 0x08) == 0) // W bit must be 1
            {
                Log($"Unsupported REX(non-W) 0x48 0xC7 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2;                           // start at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int regop = (modrm >> 3) & 0x7;        // must be /0
            int rm = (modrm & 0x7) | (B ? 8 : 0);

            if (regop != 0)
            {
                Log($"Unsupported 48 C7 /{regop}", 3);
                return false;
            }

            // helper for SIB
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    // no base, disp32 only
                    int disp32 = *(int*)(address + offsLocal);
                    offsLocal += 4;
                    baseVal = (ulong)(long)disp32;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 => no index, REX.X ignored
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }

                return baseVal + indexVal;
            }

            // destination: register or memory
            if (mod == 0b11)
            {
                // register form: MOV r64, imm32 (sign-extended)
                int imm32 = *(int*)(address + offs); offs += 4;
                ulong* dst = (&ctx->Rax) + rm;
                *dst = (ulong)(long)imm32;
                Log($"MOV R{rm}, 0x{imm32:X8} (sext) => R{rm}=0x{*dst:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            else
            {
                // memory form
                ulong memAddr = 0;

                if (mod == 0b00)
                {
                    if ((modrm & 0x7) == 0b100)          // SIB, no disp or disp32 handled inside
                    {
                        byte sib = *(address + offs++);
                        memAddr = computeSibAddr(sib, mod, ref offs);
                    }
                    else if ((modrm & 0x7) == 0b101)     // RIP-relative disp32
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        ulong nextRip = ctx->Rip + (ulong)offs;
                        memAddr = nextRip + (ulong)(long)disp32;
                    }
                    else
                    {
                        memAddr = *((&ctx->Rax) + rm);
                    }
                }
                else if (mod == 0b01)                    // disp8
                {
                    if ((modrm & 0x7) == 0b100)
                    {
                        byte sib = *(address + offs++);
                        long disp8 = *(sbyte*)(address + offs++);    // sign-extend
                        memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)disp8;
                    }
                    else
                    {
                        long disp8 = *(sbyte*)(address + offs++);
                        memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
                    }
                }
                else                                     // mod == 0b10  disp32
                {
                    if ((modrm & 0x7) == 0b100)
                    {
                        byte sib = *(address + offs++);
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)(long)disp32;
                    }
                    else
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
                    }
                }

                int imm32m = *(int*)(address + offs); offs += 4;
                ulong val = (ulong)(long)imm32m;         // sign-extend imm32 → 64
                *(ulong*)memAddr = val;

                Log($"MOV QWORD PTR [0x{memAddr:X}], 0x{imm32m:X8} (sext) => [mem]=0x{val:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
        }

        if (op2 == 0x83 && op3 == 0xE4)      // 48 83 E4 imm8 -> AND RSP, imm8
        {
            byte imm8 = *(address + 3);
            ctx->Rsp &= 0xFFFFFFFFFFFFFF00UL | (ulong)imm8;
            Log($"AND RSP, 0x{imm8:X2} => new RSP=0x{ctx->Rsp:X}", 4);
            ctx->Rip += 4;
            return true;
        }
        if (op2 == 0x81 && op3 == 0xEC)      // 48 81 EC imm32 -> SUB RSP, imm32
        {
            uint imm32 = *(uint*)(address + 3);
            ctx->Rsp -= imm32;
            Log($"SUB RSP, 0x{imm32:X8} => new RSP=0x{ctx->Rsp:X}", 7);
            ctx->Rip += 7;
            return true;
        }
        if (op2 == 0x8B && op3 == 0x04)      // 48 8B 04 24  -> MOV RAX, [RSP]
        {
            byte sib = *(address + 3);
            if (sib == 0x24)
            {
                ulong value = *(ulong*)ctx->Rsp;
                ctx->Rax = value;
                Log($"MOV RAX, [RSP] => RAX=0x{value:X}", 4);
                ctx->Rip += 4;
                return true;
            }
        }
        if (op2 == 0x89) // generic: REX.* + 89 /r  => MOV r/m(32|64), r(32|64)
        {
            // We only commit when REX.W is set (64-bit move). If not W, you can extend similarly.
            if (!W)
            {
                Log($"Unsupported REX(non-W) 0x48 0x89 (only W=1 supported here)", 2);
                return false;
            }

            // Decode ModRM/SIB/disp and compute effective address or reg
            int offs = 2;                    // start at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // source register (with REX.R)
            int rm = (modrm & 0x7) | (B ? 8 : 0);         // r/m with REX.B

            // Source reg pointer
            ulong* src = (&ctx->Rax) + reg;

            if (mod == 0b11)
            {
                // register to register
                ulong* dst = (&ctx->Rax) + rm;
                *dst = *src;
                Log($"MOV R{rm}, R{reg} => R{rm}=0x{*dst:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }

            // memory forms
            ulong memAddr = 0;

            // Helper: compute SIB
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);

                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    // no base, disp32 only
                    int disp32 = *(int*)(address + offsLocal);
                    offsLocal += 4;
                    baseVal = (ulong)(long)disp32;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // if there IS an index
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }

                return baseVal + indexVal;
            }

            // Compute effective address
            if (mod == 0b00)
            {
                if ((modrm & 0x7) == 0b100) // SIB
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else if ((modrm & 0x7) == 0b101)
                {
                    // RIP-relative disp32
                    int disp32 = *(int*)(address + offs); offs += 4;
                    // RIP of next instruction:
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;
                }
                else
                {
                    memAddr = *((&ctx->Rax) + rm);
                }
            }
            else if (mod == 0b01) // disp8
            {
                if ((modrm & 0x7) == 0b100) // SIB
                {
                    byte sib = *(address + offs++);
                    long disp8 = *(sbyte*)(address + offs++); // sign-extend
                    memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)disp8;
                }
                else
                {
                    long disp8 = *(sbyte*)(address + offs++);
                    memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
                }
            }
            else // mod == 0b10  disp32
            {
                if ((modrm & 0x7) == 0b100) // SIB + disp32
                {
                    byte sib = *(address + offs++);
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)(long)disp32;
                }
                else
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
                }
            }

            // Store 64-bit
            *(ulong*)memAddr = *src;

            // Pretty log of addressing
            Log($"MOV [0x{memAddr:X}], R{reg} => [mem]=0x{*src:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
        // --- generic: REX.W + 83 /r  => Group1 with imm8 (sign-extended) on r/m64 ---
        if (op2 == 0x83)
        {
            if ((rex & 0x08) == 0)  // must be W=1 for 64-bit
            {
                Log($"Unsupported REX(non-W) 0x48 0x83 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2; // at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int grp = (modrm >> 3) & 0x7;            // /0..7
            int rm = (modrm & 0x7) | (B ? 8 : 0);

            // Helper: SIB / RIP-rel address computation
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32sib = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32sib;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 => no index
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }
                return baseVal + indexVal;
            }

            bool isReg = (mod == 0b11);
            ulong memAddr = 0;
            ulong* dstReg = null;

            if (isReg)
            {
                dstReg = (&ctx->Rax) + rm;
            }
            else
            {
                if (mod == 0b00 && (modrm & 0x7) == 0b101)
                {
                    // RIP-relative disp32
                    int disp32r = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32r;
                }
                else if ((modrm & 0x7) == 0b100)
                {
                    // SIB
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                    if (mod == 0b01)
                    {
                        long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8;
                    }
                    else if (mod == 0b10)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr += (ulong)(long)disp32;
                    }
                }
                else
                {
                    // [base] [+disp8/disp32]
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01) { long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8; }
                    else if (mod == 0b10) { int disp32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)disp32; }
                }
            }

            // imm8 sign-extended to 64
            long simm8 = *(sbyte*)(address + offs); offs += 1;
            ulong uimm = (ulong)simm8;

            switch (grp)
            {
                case 0: // ADD
                    if (isReg)
                    {
                        ulong old = *dstReg; *dstReg = old + uimm;
                        Log($"ADD R{rm}, 0x{(byte)simm8:X2} => 0x{old:X}+0x{uimm:X}=0x{*dstReg:X}", offs);
                    }
                    else
                    {
                        ulong old = *(ulong*)memAddr; ulong nw = old + uimm; *(ulong*)memAddr = nw;
                        Log($"ADD QWORD PTR [0x{memAddr:X}], 0x{(byte)simm8:X2} => 0x{old:X}+0x{uimm:X}=0x{nw:X}", offs);
                    }
                    ctx->Rip += (ulong)offs;
                    return true;

                case 5: // SUB
                    if (isReg)
                    {
                        ulong old = *dstReg; *dstReg = old - uimm;
                        Log($"SUB R{rm}, 0x{(byte)simm8:X2} => 0x{old:X}-0x{uimm:X}=0x{*dstReg:X}", offs);
                    }
                    else
                    {
                        ulong old = *(ulong*)memAddr; ulong nw = old - uimm; *(ulong*)memAddr = nw;
                        Log($"SUB QWORD PTR [0x{memAddr:X}], 0x{(byte)simm8:X2} => 0x{old:X}-0x{uimm:X}=0x{nw:X}", offs);
                    }
                    ctx->Rip += (ulong)offs;
                    return true;

                case 7: // CMP
                    {
                        ulong lhs = isReg ? *dstReg : *(ulong*)memAddr;
                        ulong res = lhs - uimm;
                        bool zf = (res == 0);
                        bool sf = (res & (1UL << 63)) != 0;
                        ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                        if (isReg)
                            Log($"CMP R{rm}, 0x{(byte)simm8:X2} => (R{rm}=0x{lhs:X})", offs);
                        else
                            Log($"CMP QWORD PTR [0x{memAddr:X}], 0x{(byte)simm8:X2} => (mem=0x{lhs:X})", offs);

                        ctx->Rip += (ulong)offs;
                        return true;
                    }

                default:
                    Log($"Unsupported 48 83 /{grp} form", offs);
                    return false;
            }
        }

        if (op2 == 0x8B)
        {
            if (!W)
            {
                Log($"Unsupported REX(non-W) 0x48 0x8B (only W=1 supported)", 2);
                return false;
            }

            int offs = 2;                      // start at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // destination register
            int rm = (modrm & 0x7) | (B ? 8 : 0);          // r/m
            ulong* dst = (&ctx->Rax) + reg;

            ulong memAddr = 0;

            // helper identical to your computeSibAddr()
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32 = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32;
                }
                else baseVal = *((&ctx->Rax) + baseReg);

                ulong indexVal = 0;
                if (idxBits != 0b100)
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits;
                }
                return baseVal + indexVal;
            }

            // effective-address decode
            if (mod == 0b00)
            {
                if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                }
                else if ((modrm & 0x7) == 0b101)
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;      // RIP-relative
                }
                else memAddr = *((&ctx->Rax) + rm);
            }
            else if (mod == 0b01)
            {
                if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    long disp8 = *(sbyte*)(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)disp8;
                }
                else
                {
                    long disp8 = *(sbyte*)(address + offs++);
                    memAddr = *((&ctx->Rax) + rm) + (ulong)disp8;
                }
            }
            else
            {
                if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = computeSibAddr(sib, mod, ref offs) + (ulong)(long)disp32;
                }
                else
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    memAddr = *((&ctx->Rax) + rm) + (ulong)(long)disp32;
                }
            }

            ulong value = *(ulong*)memAddr;
            *dst = value;

            Log($"MOV R{reg}, [0x{memAddr:X}] => R{reg}=0x{value:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        // Add inside HandleRexPrefix, after other special-cases:
        if (op2 == 0x8D && op3 == 0x15) // 48 8D 15 xx xx xx xx => LEA RDX, [RIP+imm32]
        {
            int imm32 = *(int*)(address + 3);
            ulong target = ctx->Rip + 7 + (ulong)(long)imm32; // 7 = length of instruction
            ctx->Rdx = target;
            Log($"LEA RDX, [RIP+0x{imm32:X}] => RDX=0x{target:X}", 7);
            ctx->Rip += 7;
            return true;
        }
        // --- generic: REX.W + 29 /r  => SUB r/m64, r64 ---
        if (op2 == 0x29)
        {
            if ((rex & 0x08) == 0) // must be W=1
            {
                Log($"Unsupported REX(non-W) 0x48 0x29 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2; // start at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // source r64 (REX.R)
            int rm = (modrm & 0x7) | (B ? 8 : 0);         // dest   r/m64 (REX.B)

            // Helper for SIB / RIP-relative
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32sib = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32sib;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100)
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // 1<<scaleBits
                }
                return baseVal + indexVal;
            }

            ulong* src = (&ctx->Rax) + reg;

            if (mod == 0b11)
            {
                // register form: SUB r64, r64
                ulong* dst = (&ctx->Rax) + rm;
                ulong old = *dst;
                ulong nw = old - *src;
                *dst = nw;

                // Minimal flags used by your branches (ZF/SF)
                bool zf = (nw == 0);
                bool sf = (nw & (1UL << 63)) != 0;
                ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                Log($"SUB R{rm}, R{reg} => 0x{old:X}-0x{*src:X}=0x{nw:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            else
            {
                // memory form: SUB [mem64], r64
                ulong memAddr = 0;

                if (mod == 0b00 && (modrm & 0x7) == 0b101)
                {
                    // RIP-relative disp32
                    int disp32 = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;
                }
                else if ((modrm & 0x7) == 0b100)
                {
                    // SIB (+ optional disp)
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                    if (mod == 0b01)
                    {
                        long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8;
                    }
                    else if (mod == 0b10)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4;
                        memAddr += (ulong)(long)disp32;
                    }
                }
                else
                {
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01)
                    {
                        long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8;
                    }
                    else if (mod == 0b10)
                    {
                        int disp32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)disp32;
                    }
                }

                ulong old = *(ulong*)memAddr;
                ulong nw = old - *src;
                *(ulong*)memAddr = nw;

                bool zf = (nw == 0);
                bool sf = (nw & (1UL << 63)) != 0;
                ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                Log($"SUB QWORD PTR [0x{memAddr:X}], R{reg} => 0x{old:X}-0x{*src:X}=0x{nw:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
        }

        // --- generic: REX.W + 8D /r  => LEA r64, m ---
        if (op2 == 0x8D)
        {
            if ((rex & 0x08) == 0) // must be W=1 for 64-bit result
            {
                Log($"Unsupported REX(non-W) 0x48 0x8D (only W=1 supported)", 2);
                return false;
            }

            int offs = 2; // at ModRM
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // destination r64 (REX.R)
            int rm = (modrm & 0x7) | (B ? 8 : 0);         // base (REX.B)

            // SIB/RIP-rel helper
            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);      // REX.X extends index when present
                int baseReg = baseBits | (B ? 8 : 0);              // REX.B extends base

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32sib = *(int*)(address + offsLocal); offsLocal += 4;
                    baseVal = (ulong)(long)disp32sib;
                }
                else
                {
                    baseVal = *((&ctx->Rax) + baseReg);
                }

                ulong indexVal = 0;
                if (idxBits != 0b100) // 0b100 => no index
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits; // scale = 1<<scaleBits
                }

                return baseVal + indexVal;
            }

            ulong ea = 0;

            if (mod == 0b11)
            {
                // LEA does not allow mod==11 (register); treat as unsupported
                Log("Unsupported LEA with mod==11 (register)", offs);
                return false;
            }

            if (mod == 0b00 && (modrm & 0x7) == 0b101)
            {
                // RIP-relative disp32
                int disp32 = *(int*)(address + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                ea = nextRip + (ulong)(long)disp32;
            }
            else if ((modrm & 0x7) == 0b100)
            {
                // SIB (+ optional disp8/disp32)
                byte sib = *(address + offs++);
                ea = computeSibAddr(sib, mod, ref offs);
                if (mod == 0b01) { long disp8 = *(sbyte*)(address + offs++); ea += (ulong)disp8; }
                else if (mod == 0b10) { int disp32 = *(int*)(address + offs); offs += 4; ea += (ulong)(long)disp32; }
            }
            else
            {
                // [base] [+ disp8/disp32]
                ea = *((&ctx->Rax) + rm);
                if (mod == 0b01) { long disp8 = *(sbyte*)(address + offs++); ea += (ulong)disp8; }
                else if (mod == 0b10) { int disp32 = *(int*)(address + offs); offs += 4; ea += (ulong)(long)disp32; }
            }

            ulong* dst = (&ctx->Rax) + reg;
            *dst = ea;

            Log($"LEA R{reg}, [..] => R{reg}=0x{ea:X}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }
        // --- generic: REX.W + 01 /r  => ADD r/m64, r64 ---
        if (op2 == 0x01)
        {
            if ((rex & 0x08) == 0) // must be W=1
            {
                Log($"Unsupported REX(non-W) 0x48 0x01 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2;
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // source
            int rm = (modrm & 0x7) | (B ? 8 : 0);         // dest

            ulong* src = (&ctx->Rax) + reg;

            if (mod == 0b11)
            {
                // ADD r64, r64
                ulong* dst = (&ctx->Rax) + rm;
                ulong old = *dst;
                *dst = old + *src;

                bool zf = (*dst == 0);
                bool sf = ((*dst & (1UL << 63)) != 0);
                ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                Log($"ADD R{rm}, R{reg} => 0x{old:X}+0x{*src:X}=0x{*dst:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
            else
            {
                // memory form ADD [r/m64], r64
                ulong memAddr = 0;

                // basic address decoding (reuse your existing computeSibAddr helper)
                if (mod == 0b00 && (modrm & 0x7) == 0b101)
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;
                }
                else if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    byte scale = (byte)((sib >> 6) & 0x3);
                    byte index = (byte)((sib >> 3) & 0x7);
                    byte baseReg = (byte)(sib & 0x7);
                    ulong baseVal = *((&ctx->Rax) + baseReg);
                    ulong indexVal = (index == 0b100) ? 0 : *((&ctx->Rax) + index) << scale;
                    memAddr = baseVal + indexVal;
                    if (mod == 0b01) { long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8; }
                    else if (mod == 0b10) { int disp32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)disp32; }
                }
                else
                {
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01) { long disp8 = *(sbyte*)(address + offs++); memAddr += (ulong)disp8; }
                    else if (mod == 0b10) { int disp32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)disp32; }
                }

                ulong old = *(ulong*)memAddr;
                *(ulong*)memAddr = old + *src;

                bool zf = (*(ulong*)memAddr == 0);
                bool sf = ((*(ulong*)memAddr & (1UL << 63)) != 0);
                ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                Log($"ADD QWORD PTR [0x{memAddr:X}], R{reg} => 0x{old:X}+0x{*src:X}=0x{*(ulong*)memAddr:X}", offs);
                ctx->Rip += (ulong)offs;
                return true;
            }
        }
        if (op2 >= 0xB8 && op2 <= 0xBF)
        {
            int reg = (op2 - 0xB8) | (B ? 8 : 0);   // extend to R8..R15 if REX.B

            if ((rex & 0x08) != 0) // REX.W=1  => MOV r64, imm64 (10 bytes total)
            {
                ulong imm64 = *(ulong*)(address + 2);
                ulong* dst = (&ctx->Rax) + reg;
                *dst = imm64;
                Log($"MOV R{reg}, 0x{imm64:X}", 10);
                ctx->Rip += 10;
                return true;
            }
            else
            {
                // REX.W=0 => MOV r32, imm32; still allow REX.B to choose R8..R15
                uint imm32 = *(uint*)(address + 2);
                ulong* dst = (&ctx->Rax) + reg;
                *dst = (ulong)imm32;                // zero-extend to 64-bit
                Log($"MOV R{reg}, 0x{imm32:X8}", 6);
                ctx->Rip += 6;
                return true;
            }
        }
        // REX.W + 05 imm32  => ADD RAX, imm32 (sign-extended)
        if (op2 == 0x05)
        {
            if ((rex & 0x08) == 0)
            { // W must be 1
                Log("Unsupported REX(non-W) 0x48 0x05", 2);
                return false;
            }
            int imm32 = *(int*)(address + 2);
            ulong old = ctx->Rax;
            ulong nw = old + (ulong)(long)imm32;  // sign-extend imm32
            ctx->Rax = nw;

            // minimal flags you already use in branches (ZF/SF)
            bool zf = (nw == 0);
            bool sf = (nw & (1UL << 63)) != 0;
            ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

            Log($"ADD RAX, 0x{(uint)imm32:X8} (sext) => 0x{old:X}+0x{(ulong)(long)imm32:X}=0x{nw:X}", 6);
            ctx->Rip += 6;
            return true;
        }

        //// --- generic: REX.* + FF /r  => inc/dec/call/jmp/push on r/m(16|32|64).
        //// we only implement /2 = CALL r/m64 (and optional /4 = JMP r/m64).
        //if (op2 == 0xFF)
        //{
        //    int offs = 2; // includes REX + opcode
        //    byte modrm = *(address + offs++);
        //    byte mod = (byte)((modrm >> 6) & 0x3);
        //    int grp = (modrm >> 3) & 0x7;         // /0..7
        //    int rm = (modrm & 0x7) | (B ? 8 : 0);

        //    ulong memAddr = 0;  // ← move declaration here so it’s visible later
        //    ulong target;

        //    ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
        //    {
        //        byte scaleBits = (byte)((sib >> 6) & 0x3);
        //        byte idxBits = (byte)((sib >> 3) & 0x7);
        //        byte baseBits = (byte)(sib & 0x7);

        //        int indexReg = idxBits; if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
        //        int baseReg = baseBits | (B ? 8 : 0);

        //        ulong baseVal;
        //        if (modLocal == 0b00 && baseBits == 0b101)
        //        {
        //            int disp32sib = *(int*)(address + offsLocal);
        //            offsLocal += 4;
        //            baseVal = (ulong)(long)disp32sib;
        //        }
        //        else baseVal = *((&ctx->Rax) + baseReg);

        //        ulong indexVal = 0;
        //        if (idxBits != 0b100)
        //        {
        //            indexVal = *((&ctx->Rax) + indexReg);
        //            indexVal <<= scaleBits;
        //        }
        //        return baseVal + indexVal;
        //    }

        //    // --- operand decoding ---
        //    if (mod == 0b11)  // register operand
        //    {
        //        target = *((&ctx->Rax) + rm);
        //    }
        //    else
        //    {
        //        if (mod == 0b00 && ((modrm & 0x7) == 0b101))
        //        {
        //            int disp32 = *(int*)(address + offs);
        //            offs += 4;
        //            ulong nextRip = ctx->Rip + (ulong)offs;
        //            memAddr = nextRip + (ulong)(long)disp32;
        //        }
        //        else if ((modrm & 0x7) == 0b100)
        //        {
        //            byte sib = *(address + offs++);
        //            memAddr = computeSibAddr(sib, mod, ref offs);
        //            if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
        //            else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
        //        }
        //        else
        //        {
        //            memAddr = *((&ctx->Rax) + rm);
        //            if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
        //            else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
        //        }

        //        target = *(ulong*)memAddr;
        //    }

        //    // --- execute the grouped instruction ---
        //    switch (grp)
        //    {
        //        case 2: // CALL r/m64
        //            {
        //                ulong ret = ctx->Rip + (ulong)offs;
        //                ctx->Rsp -= 8;
        //                *(ulong*)ctx->Rsp = ret;
        //                Log($"CALL {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => target=0x{target:X}, return=0x{ret:X}", offs);
        //                ctx->Rip = target;
        //                return true;
        //            }
        //        case 4: // JMP r/m64
        //            {
        //                Log($"JMP {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => target=0x{target:X}", offs);
        //                ctx->Rip = target;
        //                return true;
        //            }
        //        case 6: // PUSH r/m64
        //            {
        //                ulong val = (mod == 0b11) ? *((&ctx->Rax) + rm) : *(ulong*)memAddr;
        //                ctx->Rsp -= 8;
        //                *(ulong*)ctx->Rsp = val;
        //                Log($"PUSH {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => value=0x{val:X}", offs);
        //                ctx->Rip += (ulong)offs;
        //                return true;
        //            }
        //        default:
        //            Log($"Unsupported REX 0xFF /{grp}", offs);
        //            return false;
        //    }
        //}

        else if (op2 == 0xFF)
        {
            int offs = 2; // includes REX + opcode
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int grp = (modrm >> 3) & 0x7; // /0..7
            int rm = (modrm & 0x7) | (B ? 8 : 0);

            ulong memAddr = 0;
            ulong target;

            ulong computeSibAddr(byte sib, byte modLocal, ref int offsLocal)
            {
                byte scaleBits = (byte)((sib >> 6) & 0x3);
                byte idxBits = (byte)((sib >> 3) & 0x7);
                byte baseBits = (byte)(sib & 0x7);

                int indexReg = idxBits;
                if (idxBits != 0b100) indexReg |= (X ? 8 : 0);
                int baseReg = baseBits | (B ? 8 : 0);

                ulong baseVal;
                if (modLocal == 0b00 && baseBits == 0b101)
                {
                    int disp32sib = *(int*)(address + offsLocal);
                    offsLocal += 4;
                    baseVal = (ulong)(long)disp32sib;
                }
                else baseVal = *((&ctx->Rax) + baseReg);

                ulong indexVal = 0;
                if (idxBits != 0b100)
                {
                    indexVal = *((&ctx->Rax) + indexReg);
                    indexVal <<= scaleBits;
                }
                return baseVal + indexVal;
            }

            // --- operand decoding ---
            if (mod == 0b11)
            {
                target = *((&ctx->Rax) + rm);
            }
            else
            {
                if (mod == 0b00 && ((modrm & 0x7) == 0b101))
                {
                    int disp32 = *(int*)(address + offs);
                    offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;
                }
                else if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    memAddr = computeSibAddr(sib, mod, ref offs);
                    if (mod == 0b01) { sbyte d8 = *(sbyte*)(address + offs++); memAddr = (ulong)((long)memAddr + d8); }
                    else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr = (ulong)((long)memAddr + d32); }
                }
                else
                {
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01) { sbyte d8 = *(sbyte*)(address + offs++); memAddr = (ulong)((long)memAddr + d8); }
                    else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr = (ulong)((long)memAddr + d32); }
                }

                target = *(ulong*)memAddr;
            }

            // --- execute the grouped instruction ---
            switch (grp)
            {
                case 0: // INC r/m64
                    {
                        if (mod == 0b11)
                        {
                            ((&ctx->Rax)[rm])++;
                            Log($"INC R{rm}", offs);
                        }
                        else
                        {
                            ulong val = *(ulong*)memAddr + 1;
                            *(ulong*)memAddr = val;
                            Log($"INC [0x{memAddr:X}] => 0x{val:X}", offs);
                        }
                        ctx->Rip += (ulong)offs;
                        return true;
                    }

                case 1: // DEC r/m64
                    {
                        if (mod == 0b11)
                        {
                            ((&ctx->Rax)[rm])--;
                            Log($"DEC R{rm}", offs);
                        }
                        else
                        {
                            ulong val = *(ulong*)memAddr - 1;
                            *(ulong*)memAddr = val;
                            Log($"DEC [0x{memAddr:X}] => 0x{val:X}", offs);
                        }
                        ctx->Rip += (ulong)offs;
                        return true;
                    }

                case 2: // CALL r/m64
                    {
                        ulong ret = ctx->Rip + (ulong)offs;
                        ctx->Rsp -= 8;
                        *(ulong*)ctx->Rsp = ret;
                        Log($"CALL {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => target=0x{target:X}, return=0x{ret:X}", offs);
                        ctx->Rip = target;
                        return true;
                    }

                case 4: // JMP r/m64
                    {
                        Log($"JMP {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => target=0x{target:X}", offs);
                        ctx->Rip = target;
                        return true;
                    }

                case 6: // PUSH r/m64
                    {
                        ulong val = (mod == 0b11) ? *((&ctx->Rax) + rm) : *(ulong*)memAddr;
                        ctx->Rsp -= 8;
                        *(ulong*)ctx->Rsp = val;
                        Log($"PUSH {((mod == 0b11) ? $"R{rm}" : $"[0x{memAddr:X}]")} => value=0x{val:X}", offs);
                        ctx->Rip += (ulong)offs;
                        return true;
                    }

                default:
                    Log($"Unsupported REX 0xFF /{grp}", offs);
                    return false;
            }
        }

        // --- generic: REX.W + 85 /r  => TEST r/m64, r64 (bitwise AND, flags only)
        if (op2 == 0x85)
        {
            if (!W)
            {
                Log($"Unsupported REX(non-W) 0x{rex:X2} 0x85 (only W=1 supported)", 2);
                return false;
            }

            int offs = 2;
            byte modrm = *(address + offs++);
            byte mod = (byte)((modrm >> 6) & 0x3);
            int reg = ((modrm >> 3) & 0x7) | (R ? 8 : 0);   // src (REX.R)
            int rm = (modrm & 0x7) | (B ? 8 : 0);         // dst (REX.B)
            ulong src = *((&ctx->Rax) + reg);
            ulong val;

            if (mod == 0b11)
            {
                val = *((&ctx->Rax) + rm);
            }
            else
            {
                // effective address (same helpers as elsewhere)
                ulong memAddr = 0;

                if (mod == 0b00 && (modrm & 0x7) == 0b101)
                {
                    int disp32 = *(int*)(address + offs); offs += 4;
                    ulong nextRip = ctx->Rip + (ulong)offs;
                    memAddr = nextRip + (ulong)(long)disp32;
                }
                else if ((modrm & 0x7) == 0b100)
                {
                    byte sib = *(address + offs++);
                    byte scale = (byte)((sib >> 6) & 0x3);
                    byte index = (byte)((sib >> 3) & 0x7);
                    byte baseBits = (byte)(sib & 0x7);
                    int indexReg = index; if (index != 0b100) indexReg |= (X ? 8 : 0);
                    int baseReg = baseBits | (B ? 8 : 0);
                    ulong baseVal = *((&ctx->Rax) + baseReg);
                    ulong indexVal = (index == 0b100) ? 0 : (*((&ctx->Rax) + indexReg) << scale);
                    memAddr = baseVal + indexVal;
                    if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
                    else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
                }
                else
                {
                    memAddr = *((&ctx->Rax) + rm);
                    if (mod == 0b01) { long d8 = *(sbyte*)(address + offs++); memAddr += (ulong)d8; }
                    else if (mod == 0b10) { int d32 = *(int*)(address + offs); offs += 4; memAddr += (ulong)(long)d32; }
                }

                val = *(ulong*)memAddr;
            }

            ulong res = val & src;
            bool zf = (res == 0);
            bool sf = ((res >> 63) & 1) != 0;
            ctx->EFlags = (uint)((ctx->EFlags & ~0xC0u) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

            Log($"TEST {((mod == 0b11) ? $"R{rm}" : "r/m64")}, R{reg} => ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)}", offs);
            ctx->Rip += (ulong)offs;
            return true;
        }

        if (op2 == 0x63)
        {
            byte modrm = *(address + 1);
            byte mod = (byte)((modrm >> 6) & 3);
            byte reg = (byte)((modrm >> 3) & 7);
            byte rm = (byte)(modrm & 7);
            int instrLen = 2;
            long value = 0;

            if (mod == 0b11)
            {
                // Register to register
                int src = (int)((&ctx->Rax)[rm]);
                value = src; // sign-extend
                ((&ctx->Rax)[reg]) = (ulong)value;
                Log($"MOVSXD R{reg}, R{rm}", instrLen);
            }
            else
            {
                // Memory operand (simplified)
                ulong addr = ((&ctx->Rax)[rm]);
                int src = *(int*)addr;
                value = src; // sign-extend 32 -> 64
                ((&ctx->Rax)[reg]) = (ulong)value;
                Log($"MOVSXD R{reg}, [0x{addr:X}]", instrLen);
            }

            ctx->Rip += (ulong)instrLen;
            return true;
        }
        if (op2 == 0x3B)
        {
            return HandleCmpGvEv64(ctx, address, Log);
        }
        if (op2 == 0x31)
        {
            return HandleXorEvGv(ctx, address, Log);
        }

        Log($"Unsupported REX-prefixed opcode 0x48 0x{op2:X2} 0x{op3:X2}", 3);
        return false;
    }
    private static unsafe bool HandleXorEvGv(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // [REX?] 31 /r  → XOR r/m32, r32   (default)
        // with REX.W    → XOR r/m64, r64
        int offs = 0;

        // Optional REX
        byte rex = 0;
        if ((ip[offs] & 0xF0) == 0x40) { rex = ip[offs]; offs++; }
        bool rexW = (rex & 0x08) != 0;
        bool rexR = (rex & 0x04) != 0;
        bool rexB = (rex & 0x01) != 0;

        if (ip[offs] != 0x31) return false;
        offs++; // consume opcode

        byte modrm = ip[offs++]; // /r
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // source Gv
        int rm = (modrm & 7);      // destination Ev

        // Extend indices with REX.R / REX.B
        int src = rexR ? (reg | 8) : reg;
        int dst = rexB ? (rm | 8) : rm;

        ulong* R = &ctx->Rax;

        // Resolve destination pointer / value width
        bool is64 = rexW;
        ulong addr = 0;
        string dstDesc;

        // Effective address for r/m
        if (mod == 0b11)
        {
            dstDesc = is64 ? $"R{dst}" : $"R{dst}d";
        }
        else
        {
            // RIP-relative: mod==00 && rm==101
            if (mod == 0b00 && rm == 0b101)
            {
                int disp32 = *(int*)(ip + offs); offs += 4;
                ulong nextRip = ctx->Rip + (ulong)offs;
                addr = nextRip + (ulong)(long)disp32;
            }
            else
            {
                // Simple [reg] + disp
                addr = *((&ctx->Rax) + dst);
                if (mod == 0b01) { long d8 = *(sbyte*)(ip + offs); offs += 1; addr += (ulong)d8; }
                else if (mod == 0b10) { int d32 = *(int*)(ip + offs); offs += 4; addr += (ulong)(long)d32; }
            }
            dstDesc = is64 ? $"QWORD PTR [0x{addr:X}]" : $"DWORD PTR [0x{addr:X}]";
        }

        // Fetch operands
        ulong srcVal = R[src];
        ulong dstVal;

        if (mod == 0b11)
            dstVal = R[dst];
        else
            dstVal = is64 ? *(ulong*)addr : *(uint*)addr;

        // Narrow/zero-extend src (XOR is width-specific)
        ulong s = is64 ? srcVal : (srcVal & 0xFFFF_FFFFUL);
        ulong d = is64 ? dstVal : (dstVal & 0xFFFF_FFFFUL);
        ulong r = d ^ s;

        // Write back
        if (mod == 0b11)
        {
            if (is64) R[dst] = r;
            else R[dst] = (R[dst] & 0xFFFF_FFFF00000000UL) | (uint)r; // r/m32 write zero-extends architecturally, but since we write to the 64-bit slot, keep upper as-is or, if you want architectural behavior, force zero-extend:
                                                                      // R[dst] = (ulong)(uint)r;  // <- use this if you want true x64 semantics: writing to a 32-bit GPR zero-extends to 64 bits
        }
        else
        {
            if (is64) *(ulong*)addr = r;
            else *(uint*)addr = (uint)r;
        }

        // Flags for logical XOR: CF=0, OF=0, AF undefined, update ZF/SF/PF
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags;
        f &= ~(CF | OF | ZF | SF | PF);   // clear CF,OF,ZF,SF,PF; preserve AF
        ulong mask = is64 ? 0x8000_0000_0000_0000UL : 0x8000_0000UL;
        if ((r == 0)) f |= ZF;
        if ((r & mask) != 0) f |= SF;

        // Parity of low byte
        byte low = (byte)(r & 0xFF);
        if ((System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0) f |= PF;
        ctx->EFlags = f;

        string srcDesc = is64 ? $"R{src}" : $"R{src}d";
        Log($"XOR {dstDesc}, {srcDesc}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    private static unsafe bool HandleCmpGvEv64(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 48 3B /r → CMP r64, r/m64
        int offs = 2;
        byte modrm = ip[offs++];
        byte mod = (byte)((modrm >> 6) & 3);
        int reg = (modrm >> 3) & 7; // destination (r64)
        int rm = (modrm & 7);      // source (r/m64)
        ulong* R = &ctx->Rax;

        ulong lhs = R[reg]; // left operand
        ulong rhs;
        ulong addr = 0;
        string srcDesc;

        if (mod == 0b11)
        {
            rhs = R[rm];
            srcDesc = $"R{rm}";
        }
        else
        {
            addr = R[rm];
            if (mod == 0b01)
            {
                long disp8 = *(sbyte*)(ip + offs); offs += 1;
                addr += (ulong)disp8;
            }
            else if (mod == 0b10)
            {
                int disp32 = *(int*)(ip + offs); offs += 4;
                addr += (ulong)(long)disp32;
            }

            rhs = *(ulong*)addr;
            srcDesc = $"QWORD PTR [0x{addr:X}]";
        }

        ulong result = lhs - rhs;

        // ---- Update flags ----
        const uint CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
        uint f = ctx->EFlags & ~((uint)(CF | PF | AF | ZF | SF | OF));

        if (lhs < rhs) f |= CF;                    // carry/borrow
        if (result == 0) f |= ZF;
        if ((result & 0x8000_0000_0000_0000UL) != 0) f |= SF;
        if ((((lhs ^ rhs) & (lhs ^ result)) & 0x8000_0000_0000_0000UL) != 0) f |= OF;

        // Parity flag of low byte
        byte low = (byte)(result & 0xFF);
        if ((System.Numerics.BitOperations.PopCount((uint)low) & 1) == 0)
            f |= PF;

        ctx->EFlags = f;

        Log($"CMP R{reg}, {srcDesc} => result=0x{result:X} ZF={((f & ZF) != 0 ? 1 : 0)} SF={((f & SF) != 0 ? 1 : 0)} CF={((f & CF) != 0 ? 1 : 0)}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

}