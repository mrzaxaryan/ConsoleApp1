using System;
using System.Linq;
using System.Runtime.InteropServices;

public static unsafe class InstructionEmulator
{
    private static string FormatBytes(byte* address, int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++) bytes[i] = *(address + i);
        return string.Join(" ", bytes.Select(b => $"{b:X2}"));
    }

    private static void LogRegisters(CONTEXT* ctx, string prefix = "[REGS]")
    {
        Console.WriteLine($"{prefix} RIP=0x{ctx->Rip:X} RSP=0x{ctx->Rsp:X} RAX=0x{ctx->Rax:X} RBX=0x{ctx->Rbx:X} RCX=0x{ctx->Rcx:X} RDX=0x{ctx->Rdx:X} RBP=0x{ctx->Rbp:X} RSI=0x{ctx->Rsi:X} RDI=0x{ctx->Rdi:X} R8=0x{ctx->R8:X} R9=0x{ctx->R9:X} R10=0x{ctx->R10:X} R11=0x{ctx->R11:X} R12=0x{ctx->R12:X} R13=0x{ctx->R13:X} R14=0x{ctx->R14:X} R15=0x{ctx->R15:X} EFlags=0x{ctx->EFlags:X}");
    }

    private static bool EmulateX64Instruction(ref EXCEPTION_POINTERS exceptionInfo, byte* address)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        LogRegisters(ctx, "[BEFORE]");
        byte opcode = *address;
        void Log(string info, int instrLen)
        {
            string bytes = FormatBytes(address, instrLen);
            // Add more debug info: RIP, RSP, RAX, RCX, RDX, RBP, EFlags
            string regs = $"RIP=0x{ctx->Rip:X} RSP=0x{ctx->Rsp:X} RAX=0x{ctx->Rax:X} RCX=0x{ctx->Rcx:X} RDX=0x{ctx->Rdx:X} RBP=0x{ctx->Rbp:X} EFlags=0x{ctx->EFlags:X}";
            Console.WriteLine($"[{bytes}] [0x{opcode:X2}] {info} | {regs}");
        }

        //byte* ip = address;
        //byte rex = 0;

        //// skip all 0x40–0x4F prefixes
        //while ((*ip & 0xF0) == 0x40)
        //{
        //    rex = *ip;
        //    ip++;
        //}

        //address = ip;

        switch (opcode)
        {
            case 0x00: // ADD r/m8, r8
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte reg = (byte)((modrm >> 3) & 0x7); // source
                    byte rm = (byte)(modrm & 0x7);        // destination

                    int offs = 2;
                    ulong memAddr = 0;
                    byte* destPtr = null;

                    if (mod == 0b11)
                    {
                        // Register to register
                        destPtr = (byte*)((&ctx->Rax) + rm);
                    }
                    else
                    {
                        // Memory destination
                        switch (mod)
                        {
                            case 0b00:
                                if (rm == 0b101)
                                {
                                    int disp32 = *(int*)(address + offs);
                                    offs += 4;
                                    memAddr = ctx->Rip + (ulong)disp32; // RIP-relative
                                }
                                else if (rm == 0b100)
                                {
                                    byte sib = *(address + offs++);
                                    byte scale = (byte)((sib >> 6) & 0x3);
                                    byte index = (byte)((sib >> 3) & 0x7);
                                    byte baseReg = (byte)(sib & 0x7);
                                    ulong baseVal = (baseReg == 0b101) ? 0 : *((&ctx->Rax) + baseReg);
                                    ulong indexVal = (index == 0b100) ? 0 : (*((&ctx->Rax) + index) << scale);
                                    int disp32 = (baseReg == 0b101) ? *(int*)(address + offs) : 0;
                                    offs += (baseReg == 0b101) ? 4 : 0;
                                    memAddr = baseVal + indexVal + (ulong)disp32;
                                }
                                else
                                {
                                    memAddr = *((&ctx->Rax) + rm);
                                }
                                destPtr = (byte*)memAddr;
                                break;

                            case 0b01:
                            case 0b10:
                                {
                                    int dispSize = (mod == 0b01) ? 1 : 4;
                                    long disp = (dispSize == 1)
                                        ? *(sbyte*)(address + offs)
                                        : *(int*)(address + offs);
                                    offs += dispSize;
                                    ulong baseVal = *((&ctx->Rax) + rm);
                                    memAddr = baseVal + (ulong)disp;
                                    destPtr = (byte*)memAddr;
                                }
                                break;

                            default:
                                Log($"Unsupported ADD ModRM 0x{modrm:X2}", 2);
                                return false;
                        }
                    }

                    // Fetch source register (r8)
                    byte* srcPtr = (byte*)((&ctx->Rax) + reg);

                    // Perform addition
                    byte src = *srcPtr;
                    byte dest = *destPtr;
                    byte result = (byte)(dest + src);

                    *destPtr = result;

                    // Update flags (basic subset)
                    bool zf = (result == 0);
                    bool sf = (result & 0x80) != 0;
                    ctx->EFlags = (uint)((ctx->EFlags & ~0x85) | (zf ? 0x40u : 0u) | (sf ? 0x80u : 0u));

                    Log($"ADD r/m8, r8 => [0x{(ulong)destPtr:X}]=0x{result:X2}", offs);
                    ctx->Rip += (ulong)offs;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x76: // JBE short rel8
                {
                    sbyte rel8 = *(sbyte*)(address + 1);
                    long disp = rel8; // sign-extended
                    ulong target = (ulong)((long)ctx->Rip + 2 + disp);

                    bool cf = (ctx->EFlags & 0x1) != 0;   // CF
                    bool zf = (ctx->EFlags & 0x40) != 0;  // ZF
                    bool taken = cf || zf;

                    Log($"JBE short 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 2);

                    ctx->Rip = taken ? target : ctx->Rip + 2;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x90:
                Log("NOP", 1);
                ctx->Rip += 1;
                LogRegisters(ctx, "[AFTER]");
                return true;
            case 0xC9:
                {
                    Log("LEAVE", 1);
                    ctx->Rsp = ctx->Rbp;
                    ctx->Rbp = *(ulong*)ctx->Rsp;
                    ctx->Rsp += 8;
                    ctx->Rip += 1;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0xC3:
                {
                    ulong ret = *(ulong*)ctx->Rsp;
                    Log($"RET to 0x{ret:X}", 1);
                    ctx->Rip = ret;
                    ctx->Rsp += 8;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x55:
                Log("PUSH RBP", 1);
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = ctx->Rbp;
                ctx->Rip += 1;
                LogRegisters(ctx, "[AFTER]");
                return true;
            case 0xC6: // MOV r/m8, imm8
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte reg = (byte)((modrm >> 3) & 0x7);
                    byte rm = (byte)(modrm & 0x7);
                    bool usedSib = false;
                    if (reg != 0)
                    {
                        Log($"Unsupported C6 /{reg}", 2);
                        return false;
                    }

                    ulong memAddr = 0;
                    int offs = 2;

                    // Helper for register value fetch
                    static ulong GetReg64(CONTEXT* ctx, int reg)
                    {
                        switch (reg)
                        {
                            case 0: return ctx->Rax;
                            case 1: return ctx->Rcx;
                            case 2: return ctx->Rdx;
                            case 3: return ctx->Rbx;
                            case 4: return ctx->Rsp;
                            case 5: return ctx->Rbp;
                            case 6: return ctx->Rsi;
                            case 7: return ctx->Rdi;
                            default: throw new InvalidOperationException($"Invalid register {reg}");
                        }
                    }

                    // --- Decode addressing ---
                    ulong baseVal = 0;
                    ulong indexVal = 0;
                    long disp = 0;

                    if (rm == 4) // SIB present
                    {
                        usedSib = true;
                        byte sib = *(address + offs++);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                       
                        // Base
                        if (baseReg == 5 && mod == 0)
                        {
                            // no base, disp32
                            disp = *(int*)(address + offs);
                            offs += 4;
                        }
                        else
                        {
                            baseVal = GetReg64(ctx, baseReg);
                        }

                        // Index
                        if (index != 4) // 4 = no index
                            indexVal = GetReg64(ctx, index) << scale;
                    }
                    else if (mod == 0 && rm == 5)
                    {
                        // disp32 (RIP-relative)
                        disp = *(int*)(address + offs);
                        offs += 4;
                        // baseVal will be RIP of NEXT instruction; set it later once offs includes imm8
                        baseVal = 0; // placeholder; we’ll set after reading imm8
                    }
                    else
                    {
                        baseVal = GetReg64(ctx, rm);
                    }

                    // Displacement if mod == 01 or 10
                    if (mod == 1)
                    {
                        disp += *(sbyte*)(address + offs);
                        offs += 1;
                    }
                    else if (mod == 2)
                    {
                        disp += *(int*)(address + offs);
                        offs += 4;
                    }

                    

                    // --- Immediate value ---
                    byte imm8 = *(address + offs++);

                    if (mod == 0 && rm == 5 && !usedSib)
                    {
                        ulong ripNext = ctx->Rip + (ulong)offs; // offs now == full instr length
                        baseVal = ripNext;
                    }

                    if (mod == 3)
                    {
                        // MOV r8, imm8 – write a byte register, not memory
                        // Minimal (no-REX) implementation; see TODOs below.
                        switch (rm)
                        {
                            case 0: ctx->Rax = (ctx->Rax & ~0xFFUL) | (ulong)imm8; break; // AL
                            case 1: ctx->Rcx = (ctx->Rcx & ~0xFFUL) | (ulong)imm8; break; // CL
                            case 2: ctx->Rdx = (ctx->Rdx & ~0xFFUL) | (ulong)imm8; break; // DL
                            case 3: ctx->Rbx = (ctx->Rbx & ~0xFFUL) | (ulong)imm8; break; // BL
                            case 4: // AH (no REX) / SPL (with REX) – see TODO
                                    // No-REX path: AH
                                ctx->Rax = (ctx->Rax & ~(0xFFUL << 8)) | ((ulong)imm8 << 8);
                                break;
                            case 5: // CH / BPL (with REX)
                                ctx->Rcx = (ctx->Rcx & ~(0xFFUL << 8)) | ((ulong)imm8 << 8);
                                break;
                            case 6: // DH / SIL (with REX)
                                ctx->Rdx = (ctx->Rdx & ~(0xFFUL << 8)) | ((ulong)imm8 << 8);
                                break;
                            case 7: // BH / DIL (with REX)
                                ctx->Rbx = (ctx->Rbx & ~(0xFFUL << 8)) | ((ulong)imm8 << 8);
                                break;
                        }

                        Log($"MOV , 0x{imm8:X2}", offs);
                        ctx->Rip += (ulong)offs;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    memAddr = baseVal + indexVal + (ulong)disp;
                    Log($"MOV byte ptr [0x{memAddr:X}], 0x{imm8:X2}", offs);
                    *(byte*)memAddr = imm8;

                    
                    ctx->Rip += (ulong)offs;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            //8B C1
            case 0x8B: // MOV r64, r/m64
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte reg = (byte)((modrm >> 3) & 0x7); // destination
                    byte rm = (byte)(modrm & 0x7);        // source
                    int offs = 2;
                    ulong memAddr = 0;
                    ulong value = 0;
                    if (mod == 0b11)
                    {
                        // Register to register
                        value = *((&ctx->Rax) + rm);
                    }
                    else
                    {
                        // Memory source
                        switch (mod)
                        {
                            case 0b00:
                                if (rm == 0b101)
                                {
                                    int disp32 = *(int*)(address + offs);
                                    offs += 4;
                                    memAddr = ctx->Rip + (ulong)disp32; // RIP-relative
                                }
                                else
                                {
                                    memAddr = *((&ctx->Rax) + rm);
                                }
                                break;
                            default:
                                Log($"Unsupported MOV ModRM 0x{modrm:X2}", 2);
                                return false;
                        }
                        value = *(ulong*)memAddr;
                    }
                    *((&ctx->Rax) + reg) = value;
                    Log($"MOV r64, r/m64 => reg={reg}, value=0x{value:X}", offs);
                    ctx->Rip += (ulong)offs;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            //03 45
            case 0x03: // ADD r32/64, r/m32/64  (REX.W => 64-bit)
                {
                    // --- Detect a single REX prefix immediately before opcode (simple but effective) ---
                    bool rexPresent = (address > (byte*)0) && (*(address - 1) >= 0x40 && *(address - 1) <= 0x4F);
                    byte rex = rexPresent ? *(address - 1) : (byte)0;
                    bool rexW = (rex & 0x08) != 0;
                    bool rexR = (rex & 0x04) != 0;
                    bool rexX = (rex & 0x02) != 0;
                    bool rexB = (rex & 0x01) != 0;

                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    int reg = ((modrm >> 3) & 0x7) | (rexR ? 0x8 : 0x0); // destination register
                    int rm = (modrm & 0x7) | (rexB ? 0x8 : 0x0); // source (or base) register

                    int offs = 2;

                    // Helpers
                    static ref ulong REG64(CONTEXT* c, int i)
                    {
                        // Layout assumes RAX..RDI are contiguous then R8..R15 accessible via switch.
                        // Map 0..15 to fields:
                        switch (i & 0xF)
                        {
                            case 0: return ref c->Rax;
                            case 1: return ref c->Rcx;
                            case 2: return ref c->Rdx;
                            case 3: return ref c->Rbx;
                            case 4: return ref c->Rsp;
                            case 5: return ref c->Rbp;
                            case 6: return ref c->Rsi;
                            case 7: return ref c->Rdi;
                            case 8: return ref c->R8;
                            case 9: return ref c->R9;
                            case 10: return ref c->R10;
                            case 11: return ref c->R11;
                            case 12: return ref c->R12;
                            case 13: return ref c->R13;
                            case 14: return ref c->R14;
                            default: return ref c->R15;
                        }
                    }

                    ulong memAddr = 0;
                    bool memSrc = (mod != 0b11);

                    if (memSrc)
                    {
                        // --- Build effective address ---
                        if (mod == 0b00)
                        {
                            if ((rm & 7) == 0b100) // SIB present
                            {
                                byte sib = *(address + offs++);
                                int scale = 1 << ((sib >> 6) & 0x3);
                                int index = ((sib >> 3) & 0x7) | (rexX ? 0x8 : 0x0);
                                int baseR = (sib & 0x7) | (rexB ? 0x8 : 0x0);

                                ulong baseVal;
                                if ((baseR & 7) == 0b101) // base==RBP with mod==00 -> disp32 only (no base)
                                {
                                    int disp32 = *(int*)(address + offs); offs += 4;
                                    baseVal = 0;
                                    memAddr = baseVal + (index == 0b100 ? 0UL : (REG64(ctx, index) * (ulong)scale)) + (ulong)disp32;
                                }
                                else
                                {
                                    baseVal = REG64(ctx, baseR);
                                    memAddr = baseVal + (index == 0b100 ? 0UL : (REG64(ctx, index) * (ulong)scale));
                                }
                            }
                            else if ((rm & 7) == 0b101)
                            {
                                // RIP-relative disp32
                                int disp32 = *(int*)(address + offs); offs += 4;
                                memAddr = ctx->Rip + (ulong)offs + (ulong)disp32; // RIP points to next instr (after ModRM+disp)
                            }
                            else
                            {
                                memAddr = REG64(ctx, rm);
                            }
                        }
                        else if (mod == 0b01) // disp8
                        {
                            long disp8 = *(sbyte*)(address + offs); offs += 1;

                            if ((rm & 7) == 0b100) // SIB
                            {
                                byte sib = *(address + offs++);
                                int scale = 1 << ((sib >> 6) & 0x3);
                                int index = ((sib >> 3) & 0x7) | (rexX ? 0x8 : 0x0);
                                int baseR = (sib & 0x7) | (rexB ? 0x8 : 0x0);
                                ulong baseVal = REG64(ctx, baseR);
                                ulong idxVal = ((index & 7) == 0b100) ? 0UL : REG64(ctx, index) * (ulong)scale;
                                memAddr = baseVal + idxVal + (ulong)disp8;
                            }
                            else
                            {
                                ulong baseVal = REG64(ctx, rm);
                                memAddr = baseVal + (ulong)disp8; // here 0x45 → base=RBP + disp8
                            }
                        }
                        else // mod == 0b10, disp32
                        {
                            int disp32 = *(int*)(address + offs); offs += 4;

                            if ((rm & 7) == 0b100) // SIB
                            {
                                byte sib = *(address + offs++);
                                int scale = 1 << ((sib >> 6) & 0x3);
                                int index = ((sib >> 3) & 0x7) | (rexX ? 0x8 : 0x0);
                                int baseR = (sib & 0x7) | (rexB ? 0x8 : 0x0);
                                ulong baseVal = REG64(ctx, baseR);
                                ulong idxVal = ((index & 7) == 0b100) ? 0UL : REG64(ctx, index) * (ulong)scale;
                                memAddr = baseVal + idxVal + (ulong)disp32;
                            }
                            else
                            {
                                ulong baseVal = REG64(ctx, rm);
                                memAddr = baseVal + (ulong)disp32;
                            }
                        }
                    }

                    // --- Fetch source and perform add with correct operand-size semantics ---
                    if (rexW)
                    {
                        ulong src = memSrc ? *(ulong*)memAddr : REG64(ctx, rm);
                        ref ulong dst = ref REG64(ctx, reg);
                        dst = dst + src;
                        Log($"ADD r64, {(memSrc ? "m64" : "r64")} => reg={reg}, +0x{src:X}", offs);
                    }
                    else
                    {
                        uint src = memSrc ? *(uint*)memAddr : (uint)(REG64(ctx, rm) & 0xFFFFFFFF);
                        ref ulong dst64 = ref REG64(ctx, reg);
                        uint dst32 = (uint)(dst64 & 0xFFFFFFFF);
                        uint res32 = dst32 + src;
                        dst64 = res32; // zero-extended to 64 bits per x86-64 r32 write
                        Log($"ADD r32, {(memSrc ? "m32" : "r32")} => reg={reg}, +0x{src:X}", offs);
                    }

                    ctx->Rip += (ulong)offs;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            //0xFF
            case 0xFF:
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte regop = (byte)((modrm >> 3) & 0x7);
                    byte rm = (byte)(modrm & 0x7);

                    if (mod == 0b11)
                    {
                        ulong* regPtr = (&ctx->Rax) + rm;

                        if (regop == 0) *regPtr += 1;   // INC
                        else if (regop == 1) *regPtr -= 1; // DEC
                        else return false;

                        ctx->Rip += 2;
                        return true;
                    }
                    return false;
                }

            //0x72
            case 0x72: // JB short rel8
                {
                    sbyte rel8 = *(sbyte*)(address + 1);
                    long disp = rel8; // sign-extended
                    ulong target = (ulong)((long)ctx->Rip + 2 + disp);
                    bool cf = (ctx->EFlags & 0x1) != 0;   // CF
                    bool taken = cf;
                    Log($"JB short 0x{target:X} {(taken ? "TAKEN" : "NOT taken")}", 2);
                    ctx->Rip = taken ? target : ctx->Rip + 2;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x48:
                {
                    byte op2 = *(address + 1);
                    byte op3 = *(address + 2);
                    if (op2 == 0xC7) // MOV r/m64, imm32
                    {
                        byte modrm = *(address + 2);
                        byte mod = (byte)((modrm >> 6) & 0x3);
                        byte regop = (byte)((modrm >> 3) & 0x7);
                        byte rm = (byte)(modrm & 0x7);

                        if (regop != 0)
                        {
                            Log($"Unsupported 48 C7 /{regop}", 3);
                            return false;
                        }

                        ulong memAddr = 0;
                        int offs = 3;

                        switch (mod)
                        {
                            case 0b00:
                                if (rm == 0b101)
                                {
                                    int disp32 = *(int*)(address + offs);
                                    offs += 4;
                                    memAddr = ctx->Rip + (ulong)disp32;
                                }
                                else if (rm == 0b100)
                                {
                                    byte sib = *(address + offs++);
                                    byte baseReg = (byte)(sib & 0x7);
                                    byte indexReg = (byte)((sib >> 3) & 0x7);
                                    byte scale = (byte)((sib >> 6) & 0x3);
                                    ulong baseVal = (baseReg == 0b101) ? 0 : *((&ctx->Rax) + baseReg);
                                    ulong indexVal = (indexReg == 0b100) ? 0 : (*((&ctx->Rax) + indexReg) << scale);
                                    int disp32 = (baseReg == 0b101) ? *(int*)(address + offs) : 0;
                                    offs += (baseReg == 0b101) ? 4 : 0;
                                    memAddr = baseVal + indexVal + (ulong)disp32;
                                }
                                else
                                {
                                    memAddr = *((&ctx->Rax) + rm);
                                }
                                break;

                            case 0b01:
                            case 0b10:
                                {
                                    int dispSize = (mod == 0b01) ? 1 : 4;
                                    long disp = 0;

                                    if (rm == 0b100)
                                    {
                                        byte sib = *(address + offs++);
                                        byte baseReg = (byte)(sib & 0x7);
                                        byte indexReg = (byte)((sib >> 3) & 0x7);
                                        byte scale = (byte)((sib >> 6) & 0x3);

                                        // Displacement comes *after* SIB
                                        disp = (dispSize == 1)
                                            ? *(sbyte*)(address + offs)
                                            : *(int*)(address + offs);
                                        offs += dispSize;

                                        ulong baseVal = *((&ctx->Rax) + baseReg);
                                        ulong indexVal = (indexReg == 0b100) ? 0 : (*((&ctx->Rax) + indexReg) << scale);
                                        memAddr = baseVal + indexVal + (ulong)disp;
                                    }
                                    else
                                    {
                                        disp = (dispSize == 1)
                                            ? *(sbyte*)(address + offs)
                                            : *(int*)(address + offs);
                                        offs += dispSize;

                                        ulong baseVal = *((&ctx->Rax) + rm);
                                        memAddr = baseVal + (ulong)disp;
                                    }
                                    break;
                                }

                            default:
                                Log($"48 C7 unsupported ModRM 0x{modrm:X2}", 3);
                                return false;
                        }

                        uint imm32 = *(uint*)(address + offs);
                        offs += 4;
                        ulong value = (ulong)(long)(int)imm32;

                        *(ulong*)memAddr = value;

                        Log($"MOV qword ptr [0x{memAddr:X}], 0x{value:X}", 2 + offs);
                        ctx->Rip += (ulong)(2 + offs);
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x31 0xC9
                    if (op2 == 0x31 && op3 == 0xC9)
                    {
                        ctx->Rcx = 0;
                        Log($"XOR RCX, RCX => RCX=0x{ctx->Rcx:X}", 3);
                        ctx->Rip += 3;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0xFF 0xC1
                    if (op2 == 0xFF && op3 == 0xC1)
                    {
                        ctx->Rcx += 1;                     // was  ctx->Rcx -= 1;
                        Log($"INC RCX => RCX=0x{ctx->Rcx:X}", 3);
                        ctx->Rip += 3;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x81 0xF9
                    if (op2 == 0x81 && op3 == 0xF9)
                    {
                        // Immediate value
                        uint imm32 = *(uint*)(address + 3);
                        ulong lhs = ctx->Rcx;
                        ulong rhs = (ulong)(long)(int)imm32;

                        // Compute subtraction (for flag effects only)
                        ulong result = lhs - rhs;

                        uint flags = ctx->EFlags;

                        // --- CF: Carry flag (borrow in subtraction)
                        // Set if unsigned lhs < rhs
                        if (lhs < rhs)
                            flags |= 0x1u;
                        else
                            flags &= ~0x1u;

                        // --- ZF: Zero flag
                        // Set if equal
                        if (lhs == rhs)
                            flags |= 0x40u;
                        else
                            flags &= ~0x40u;

                        // --- SF: Sign flag (bit 63 of result)
                        if ((result & (1UL << 63)) != 0)
                            flags |= 0x80u;
                        else
                            flags &= ~0x80u;

                        // --- OF: Overflow flag (signed overflow)
                        bool of = ((lhs ^ rhs) & (lhs ^ result) & (1UL << 63)) != 0;
                        if (of)
                            flags |= (1u << 11);
                        else
                            flags &= ~(1u << 11);

                        // --- AF (optional auxiliary carry flag, bit 4)
                        if (((lhs ^ rhs ^ result) & 0x10) != 0)
                            flags |= (1u << 4);
                        else
                            flags &= ~(1u << 4);

                        ctx->EFlags = flags;

                        // Log result
                        Log($"CMP RCX, 0x{imm32:X8} => RCX=0x{lhs:X}, " +
                            $"ZF={(flags >> 6) & 1}, SF={(flags >> 7) & 1}, " +
                            $"CF={flags & 1}, OF={(flags >> 11) & 1}", 7);

                        // Advance instruction pointer
                        ctx->Rip += 7;

                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }

                    //0x48 0x83 0xEC
                    if (op2 == 0x83 && op3 == 0xEC)
                    {
                        byte imm8 = *(address + 3);
                        ctx->Rsp -= (ulong)(long)(sbyte)imm8;
                        Log($"SUB RSP, 0x{imm8:X2}  => new RSP=0x{ctx->Rsp:X}", 4);
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x8D 0x54
                    if (op2 == 0x8D && op3 == 0x54)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);

                        // Expect 24 (scale=0, index=RSP, base=RSP)
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 8D 54: scale={scale}, index={index}, base={baseReg}", 4);
                            return false;
                        }

                        sbyte disp8 = *(sbyte*)(address + 4);
                        ulong addr = ctx->Rsp + (ulong)disp8;

                        // LEA computes address, not memory content
                        ctx->Rdx = addr;

                        Log($"LEA RDX, [RSP+0x{disp8:X2}] => RDX=0x{ctx->Rdx:X}", 5);
                        ctx->Rip += 5;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x01 0xD0
                    if (op2 == 0x01 && op3 == 0xD0)
                    {
                        ctx->Rax += ctx->Rdx;
                        Log($"ADD RAX, RDX => RAX=0x{ctx->Rax:X}", 3);
                        ctx->Rip += 3;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x89 && op3 == 0xE5)
                    {
                        Log("MOV RBP, RSP", 3);
                        ctx->Rbp = ctx->Rsp;
                        ctx->Rip += 3;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x89 && op3 == 0x55)
                    {
                        sbyte disp8 = *(sbyte*)(address + 3);
                        ulong memAddr = ctx->Rbp + (ulong)disp8;
                        Log($"MOV [RBP+0x{(ulong)disp8:X8}], RDX", 4);
                        *(ulong*)memAddr = ctx->Rdx;
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    // 48 89 EC
                    if (op2 == 0x89 && op3 == 0xEC)
                    {
                        Log("MOV RSP, RBP", 3);
                        ctx->Rsp = ctx->Rbp;
                        ctx->Rip += 3;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x83 0x84
                    if (op2 == 0x83 && op3 == 0x84)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 83 84: scale={scale}, index={index}, base={baseReg}", 9);
                            return false;
                        }
                        uint disp32 = *(uint*)(address + 4);
                        byte imm8 = *(address + 8);
                        ulong addr = ctx->Rsp + (ulong)disp32;
                        ulong oldVal = *(ulong*)addr;
                        ulong newVal = oldVal + (ulong)(long)(sbyte)imm8;
                        *(ulong*)addr = newVal;
                        Log($"ADD [RSP+0x{disp32:X8}], 0x{imm8:X2} => [0x{addr:X}]: 0x{oldVal:X} -> 0x{newVal:X}", 9);
                        ctx->Rip += 9;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x81 0xBC
                    if (op2 == 0x81 && op3 == 0xBC)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 81 BC: scale={scale}, index={index}, base={baseReg}", 10);
                            return false;
                        }
                        uint disp32 = *(uint*)(address + 4);
                        uint imm32 = *(uint*)(address + 8);
                        ulong addr = ctx->Rsp + (ulong)disp32;
                        ulong oldVal = *(ulong*)addr;
                        ulong newVal = oldVal + (ulong)(long)(int)imm32;
                        *(ulong*)addr = newVal;
                        Log($"ADD [RSP+0x{disp32:X8}], 0x{imm32:X8} => [0x{addr:X}]: 0x{oldVal:X} -> 0x{newVal:X}", 10);
                        ctx->Rip += 10;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x89 && op3 == 0x4d)
                    {
                        sbyte disp8 = *(sbyte*)(address + 3);
                        ulong memAddr = ctx->Rbp + (ulong)disp8;
                        Log($"MOV [RBP+0x{(ulong)disp8:X8}], RCX", 4);
                        *(ulong*)memAddr = ctx->Rcx;
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x83 && op3 == 0xE4)
                    {
                        byte imm8 = *(address + 3);
                        ulong imm64 = (ulong)(long)(sbyte)imm8;
                        ctx->Rsp &= imm64;
                        Log($"AND RSP, 0x{imm8:X2}  => new RSP=0x{ctx->Rsp:X}", 4);
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    //0x48 0x83 0xC0
                    if (op2 == 0x83 && op3 == 0xC0)
                    {
                        byte imm8 = *(address + 3);
                        ctx->Rax += (ulong)(long)(sbyte)imm8;
                        Log($"ADD RAX, 0x{imm8:X2}  => new RAX=0x{ctx->Rax:X}", 4);
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x81 && op3 == 0xEC)
                    {
                        uint imm32 = *(uint*)(address + 3);
                        ctx->Rsp -= imm32;
                        Log($"SUB RSP, 0x{imm32:X8}  => new RSP=0x{ctx->Rsp:X}", 7);
                        ctx->Rip += 7;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x8B && op3 == 0x04)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 8B 04: scale={scale}, index={index}, base={baseReg}", 4);
                            return false;
                        }
                        ulong addr = ctx->Rsp;
                        ulong value = *(ulong*)addr;
                        ctx->Rax = value;
                        Log($"MOV RAX, [RSP] => RAX=0x{value:X}", 4);
                        ctx->Rip += 4;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x89 && op3 == 0x84)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 89 84: scale={scale}, index={index}, base={baseReg}", 8);
                            return false;
                        }
                        uint disp32 = *(uint*)(address + 4);
                        ulong addr = ctx->Rsp + (ulong)disp32;
                        *(ulong*)addr = ctx->Rax;
                        Log($"MOV [RSP+0x{disp32:X8}], RAX => [0x{addr:X}]=0x{ctx->Rax:X}", 8);
                        ctx->Rip += 8;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x8B && op3 == 0x84)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 8B 84: scale={scale}, index={index}, base={baseReg}", 8);
                            return false;
                        }
                        uint disp32 = *(uint*)(address + 4);
                        ulong addr = ctx->Rsp + (ulong)disp32;
                        ulong value = *(ulong*)addr;
                        ctx->Rax = value;
                        Log($"MOV RAX, [RSP+0x{disp32:X8}] => RAX=0x{value:X}", 8);
                        ctx->Rip += 8;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    if (op2 == 0x83 && op3 == 0xAC)
                    {
                        byte sib = *(address + 3);
                        byte scale = (byte)((sib >> 6) & 0x3);
                        byte index = (byte)((sib >> 3) & 0x7);
                        byte baseReg = (byte)(sib & 0x7);
                        if (scale != 0 || index != 4 || baseReg != 4)
                        {
                            Log($"Unsupported SIB in 48 83 AC: scale={scale}, index={index}, base={baseReg}", 9);
                            return false;
                        }
                        uint disp32 = *(uint*)(address + 4);
                        byte imm8 = *(address + 8);
                        ulong addr = ctx->Rsp + (ulong)disp32;
                        ulong oldVal = *(ulong*)addr;
                        ulong newVal = oldVal - (ulong)(long)(sbyte)imm8;
                        *(ulong*)addr = newVal;
                        Log($"SUB [RSP+0x{disp32:X8}], 0x{imm8:X2} => [0x{addr:X}]: 0x{oldVal:X} -> 0x{newVal:X}", 9);
                        ctx->Rip += 9;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    Log($"Unsupported opcode sequence 0x48 0x{op2:X2} 0x{op3:X2}", 3);
                    return false;
                }
            // PUSH R15
            case 0x41:
                {
                    byte op2 = *(address + 1);

                    // PUSH R8–R15 (41 50–57)
                    if (op2 >= 0x50 && op2 <= 0x57)
                    {
                        int reg = op2 - 0x50; // 0..7 → R8..R15
                        ulong* regPtr = (&ctx->R8) + reg;
                        Log($"PUSH R{8 + reg}", 1);
                        ctx->Rsp -= 8;
                        *(ulong*)ctx->Rsp = *regPtr;
                        ctx->Rip += 2;
                        LogRegisters(ctx, "[AFTER]");
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
                        Log($"POP R{8 + reg}", 1);
                        ctx->Rip += 2;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }

                    Log($"Unsupported 41 0x{op2:X2}", 3);
                    return false;
                }
            // MOV DWORD PTR
            case 0xC7:
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte reg = (byte)((modrm >> 3) & 0x7);
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
                            ulong baseVal = *((&ctx->Rax) + rm);
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
                            ulong baseVal = *((&ctx->Rax) + rm);
                            memAddr = baseVal + (ulong)disp32;
                        }
                    }
                    uint imm32 = *(uint*)(address + offs);
                    offs += 4;
                    *(uint*)memAddr = imm32;
                    Log($"MOV dword ptr [0x{memAddr:X}], 0x{imm32:X8}", 3);
                    ctx->Rip += (ulong)(offs);
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x57: // push rdi
                Log("PUSH RDI", 1);
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = ctx->Rdi;
                ctx->Rip += 1;
                LogRegisters(ctx, "[AFTER]");
                return true;
            case 0x56: // push rsi
                Log("PUSH RSI", 1);
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = ctx->Rsi;
                ctx->Rip += 1;
                LogRegisters(ctx, "[AFTER]");
                return true;
            case 0x53: // push rbx
                Log("PUSH RBX", 1);
                ctx->Rsp -= 8;
                *(ulong*)ctx->Rsp = ctx->Rbx;
                ctx->Rip += 1;
                LogRegisters(ctx, "[AFTER]");
                return true;
            case 0x89:
                {
                    byte modrm = *(address + 1);
                    byte mod = (byte)((modrm >> 6) & 0x3);
                    byte reg = (byte)((modrm >> 3) & 0x7);
                    byte rm = (byte)(modrm & 0x7);

                    ulong* srcRegPtr = (&ctx->Rax) + reg;

                    // MOV r/m64, r64
                    if (mod == 0b11)
                    {
                        // register to register
                        ulong* dstRegPtr = (&ctx->Rax) + rm;
                        *dstRegPtr = *srcRegPtr;
                        Log($"MOV R{rm}, R{reg} => R{rm}=0x{*dstRegPtr:X}", 2);
                        ctx->Rip += 2;
                        return true;
                    }
                    else if (mod == 0b01)
                    {
                        // [base + disp8]
                        sbyte disp8 = *(sbyte*)(address + 2);
                        ulong baseAddr = *((&ctx->Rax) + rm);
                        ulong memAddr = baseAddr + (ulong)disp8;

                        ulong value = *srcRegPtr;

                        *(ulong*)memAddr = value;

                        Log($"MOV [R{rm}{disp8:+#;-#;0}], R{reg}  => 0x{memAddr:X}=0x{value:X}", 3);
                        ctx->Rip += 3;
                        return true;
                    }

                    Log($"Unsupported MOV with ModRM 0x{modrm:X2}", 3);
                    return false;
                }
            case 0xEB:
                {
                    sbyte rel8 = *(sbyte*)(address + 1);
                    ulong newRip = ctx->Rip + 2 + (ulong)rel8;
                    Log($"JMP short to 0x{newRip:X}", 2);
                    ctx->Rip = newRip;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            //5D C3
            case 0x5D:
                {
                    Log("POP RBP", 1);
                    ctx->Rbp = *(ulong*)ctx->Rsp;
                    ctx->Rsp += 8;
                    ctx->Rip += 1;
                    byte nextOpcode = *(address + 1);
                    if (nextOpcode == 0xC3)
                    {
                        Log("RET", 1);
                        ulong returnAddress = *(ulong*)ctx->Rsp;
                        ctx->Rsp += 8;
                        ctx->Rip = returnAddress;
                        LogRegisters(ctx, "[AFTER]");
                        return true;
                    }
                    else
                    {
                        Log($"Unsupported opcode after POP RBP: 0x{nextOpcode:X2}", 2);
                        return false;
                    }
                }
            // jmp
            case 0xE9:
                {
                    int rel32 = *(int*)(address + 1);
                    ulong newRip = ctx->Rip + 5 + (ulong)rel32;
                    Log($"JMP to 0x{newRip:X}", 5);
                    ctx->Rip = newRip;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            // call
            case 0xE8:
                {
                    int rel32 = *(int*)(address + 1);
                    ulong returnAddress = ctx->Rip + 5;
                    ulong newRip = returnAddress + (ulong)rel32;
                    Log($"CALL to 0x{newRip:X}, return address 0x{returnAddress:X}", 5);
                    ctx->Rsp -= 8;
                    *(ulong*)ctx->Rsp = returnAddress;
                    ctx->Rip = newRip;
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            case 0x0F:
                {
                    byte op2 = *(address + 1);

                    // 0F 1F /0  → multi-byte NOPs
                    if (op2 == 0x1F)
                    {
                        byte modrm = *(address + 2);
                        byte mod = (byte)((modrm >> 6) & 0x3);
                        byte reg = (byte)((modrm >> 3) & 0x7);
                        byte rm = (byte)(modrm & 0x7);

                        if (reg != 0)
                        {
                            Log($"Unsupported 0F 1F /{reg}", 3);
                            return false;
                        }

                        int instrSize = 3; // opcode + modrm
                        if (mod == 0b00 && rm == 0b101) instrSize += 4; // RIP+disp32
                        else if (mod == 0b01) instrSize += 1;            // disp8
                        else if (mod == 0b10) instrSize += 4;            // disp32

                        Log($"NOP (0F 1F) size {instrSize} bytes", 3);
                        ctx->Rip += (ulong)instrSize;
                        return true;
                    }

                    // 0F B6 /r → MOVZX r32/64, r/m8
                    if (op2 == 0xB6)
                    {
                        byte modrm = *(address + 2);
                        byte mod = (byte)((modrm >> 6) & 0x3);
                        byte reg = (byte)((modrm >> 3) & 0x7);
                        byte rm = (byte)(modrm & 0x7);
                        ulong value = 0;
                        if (mod == 0b11)
                        {
                            // register
                            byte* srcRegPtr = (byte*)((&ctx->Rax) + rm);
                            value = *srcRegPtr;
                        }
                        else if (mod == 0b00)
                        {
                            // [RAX] or RIP-relative
                            ulong memAddr = 0;
                            if (rm == 0b101)
                            {
                                // RIP-relative
                                int disp32 = *(int*)(address + 3);
                                memAddr = ctx->Rip + 7 + (ulong)disp32; // 7 = opcode + modrm + disp32
                            }
                            else
                            {
                                ulong baseVal = *((&ctx->Rax) + rm);
                                memAddr = baseVal;
                            }
                            value = *(byte*)memAddr;
                        }
                        else
                        {
                            Log($"Unsupported MOD in 0F B6 ModRM 0x{modrm:X2}", 3);
                            return false;
                        }
                        ulong* dstRegPtr = (&ctx->Rax) + reg;
                        *dstRegPtr = value;
                        Log($"MOVZX R{reg}, r/m8 => R{reg}=0x{value:X}", 3);
                        ctx->Rip += (ulong)(3 + (mod == 0b00 && rm == 0b101 ? 4 : 0)); // opcode + modrm + disp32 if any
                        return true;
                    }

                    Log($"Unsupported opcode sequence 0x0F 0x{op2:X2}", 3);
                    return false;
                }
            case 0x3C: // CMP AL, imm8
                {
                    byte imm8 = *(address + 1);
                    byte al = (byte)(ctx->Rax & 0xFF);
                    int result = al - imm8;

                    uint flags = (uint)ctx->EFlags;

                    // Zero Flag (bit 6)
                    if ((result & 0xFF) == 0)
                        flags |= (1u << 6);
                    else
                        flags &= ~(1u << 6);

                    // Sign Flag (bit 7)
                    if ((result & 0x80) != 0)
                        flags |= (1u << 7);
                    else
                        flags &= ~(1u << 7);

                    // Carry Flag (bit 0)
                    if (al < imm8)
                        flags |= (1u << 0);
                    else
                        flags &= ~(1u << 0);

                    // Overflow Flag (bit 11)
                    bool overflow = ((al ^ imm8) & (al ^ result) & 0x80) != 0;
                    if (overflow)
                        flags |= (1u << 11);
                    else
                        flags &= ~(1u << 11);

                    // Parity Flag (bit 2)
                    byte low = (byte)(result & 0xFF);
                    bool parity = ((0x6996 >> (low & 0xF)) & 1) == 0; // even parity
                    if (parity)
                        flags |= (1u << 2);
                    else
                        flags &= ~(1u << 2);

                    ctx->EFlags = flags;

                    Log($"CMP AL, 0x{imm8:X2} => AL=0x{al:X2}, Result=0x{(byte)result:X2}, "
                        + $"ZF={(flags >> 6) & 1}, SF={(flags >> 7) & 1}, CF={(flags) & 1}, OF={(flags >> 11) & 1}", 2);

                    ctx->Rip += 2;
                    return true;
                }
            case 0x75:
                {
                    sbyte rel8 = *(sbyte*)(address + 1);
                    bool zeroFlag = (ctx->EFlags & 0x40) != 0;
                    if (!zeroFlag)
                    {
                        ulong newRip = ctx->Rip + 2 + (ulong)rel8;
                        Log($"JNE taken to 0x{newRip:X}", 2);
                        ctx->Rip = newRip;
                    }
                    else
                    {
                        Log($"JNE not taken", 2);
                        ctx->Rip += 2;
                    }
                    LogRegisters(ctx, "[AFTER]");
                    return true;
                }
            default:
                Log($"Unsupported opcode 0x{opcode:X2}", 2);
                return false;
        }
    }
    // ------------------------------------------------------------------------
    // Global State
    // ------------------------------------------------------------------------
    private static IntPtr g_codeAddress = IntPtr.Zero;
    private static UIntPtr g_codeSize = UIntPtr.Zero;
    private static int g_instructionCount = 0;

    // ------------------------------------------------------------------------
    // Win32 Interop
    // ------------------------------------------------------------------------
    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    private const uint EXCEPTION_CONTINUE_SEARCH = 0x0;

    private const int CONTEXT_FULL = 0x10007;
    public const int CONTEXT_DEBUG_REGISTERS = 0x00100010;

    [StructLayout(LayoutKind.Sequential)]
    private struct EXCEPTION_POINTERS
    {
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }
   

    [DllImport("kernel32.dll")]
    private static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

    [DllImport("kernel32.dll")]
    private static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

    private static void SetHWBP(ref EXCEPTION_POINTERS exceptionInfo, void* address)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        var context = *ctx;
        ctx->Dr0 = (ulong)address;
        ctx->Dr7 = 0x1ul; // Enable DR0 as execute breakpoint
    }

    private static void ClearHWBP(ref EXCEPTION_POINTERS exceptionInfo)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ctx->Dr0 = 0;
        ctx->Dr7 = 0;
    }
   
    private static uint ExceptionHandler(ref EXCEPTION_POINTERS exceptionInfo)
    {
        // Access ExceptionRecord->ExceptionCode
        uint code = *((uint*)exceptionInfo.ExceptionRecord);

        if (code == EXCEPTION_SINGLE_STEP)
        {
            var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
            ulong rip = ctx->Rip;
            if (rip >= (ulong)g_codeAddress && rip < (ulong)g_codeAddress + (ulong)g_codeSize)
            {
                g_instructionCount++;

                if (!EmulateX64Instruction(ref exceptionInfo, (byte*)rip))
                {
                    ClearHWBP(ref exceptionInfo);
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                if (ctx->Rip >= (ulong)g_codeAddress && ctx->Rip < (ulong)g_codeAddress + (ulong)g_codeSize)
                {
                    SetHWBP(ref exceptionInfo, (void*)ctx->Rip);

                }
                else
                {
                    ClearHWBP(ref exceptionInfo);
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                Console.WriteLine($"[VEH] RIP 0x{rip:X} outside target code range, continuing search.");
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        Console.WriteLine($"[VEH] Exception code 0x{code:X} not handled, continuing search.");

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static IntPtr _vehHandle;
    public static void Initialize(IntPtr codeAddr, UIntPtr codeSize)
    {
        g_codeAddress = codeAddr;
        g_codeSize = codeSize;
        var method = typeof(InstructionEmulator).GetMethod(nameof(ExceptionHandler), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
            .MethodHandle
            .GetFunctionPointer();

        _vehHandle = AddVectoredExceptionHandler(1, method);
    }

    public static void Uninitialize()
    {
        if (_vehHandle != IntPtr.Zero)
        {
            RemoveVectoredExceptionHandler(_vehHandle);
            _vehHandle = IntPtr.Zero;
        }
    }
}

