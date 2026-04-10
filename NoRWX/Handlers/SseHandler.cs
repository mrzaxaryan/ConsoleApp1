using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Handlers;

/// <summary>
/// Handles SSE/SSE2 instructions. Uses a static XMM register file since the
/// Windows CONTEXT struct's XSAVE area is not directly accessible from our layout.
/// Covers: MOVAPS, MOVUPS, MOVAPD, MOVUPD, MOVDQA, MOVDQU, MOVD, MOVQ,
/// XORPS, XORPD, PXOR, MOVSS, MOVSD, MOVLPS, MOVHPS, LDMXCSR, STMXCSR,
/// CVTSI2SS, CVTSI2SD, CVTSS2SI, CVTSD2SI, CVTTSS2SI, CVTTSD2SI, and more.
/// </summary>
public static unsafe class SseHandler
{
    // 16 XMM registers, each 128-bit (16 bytes)
    private static readonly byte[] _xmmStorage = new byte[16 * 16];

    public static byte* GetXmm(int index)
    {
        fixed (byte* p = _xmmStorage)
            return p + (index & 15) * 16;
    }

    /// <summary>
    /// MOVAPS/MOVUPS xmm, xmm/m128 (0F 28 / 0F 10)
    /// MOVAPD/MOVUPD xmm, xmm/m128 (66 0F 28 / 66 0F 10)
    /// </summary>
    public static bool HandleMovXmmLoad(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;

        if (modrm.Mod == 0b11)
        {
            // xmm <- xmm
            Buffer.MemoryCopy(GetXmm(modrm.Rm), GetXmm(dstXmm), 16, 16);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            Buffer.MemoryCopy((void*)addr, GetXmm(dstXmm), 16, 16);
        }

        log($"MOV* XMM{dstXmm}, xmm/m128", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// MOVAPS/MOVUPS xmm/m128, xmm (0F 29 / 0F 11)
    /// MOVAPD/MOVUPD xmm/m128, xmm (66 0F 29 / 66 0F 11)
    /// </summary>
    public static bool HandleMovXmmStore(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int srcXmm = modrm.Reg;

        if (modrm.Mod == 0b11)
        {
            Buffer.MemoryCopy(GetXmm(srcXmm), GetXmm(modrm.Rm), 16, 16);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            Buffer.MemoryCopy(GetXmm(srcXmm), (void*)addr, 16, 16);
        }

        log($"MOV* xmm/m128, XMM{srcXmm}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// MOVDQA/MOVDQU xmm, xmm/m128 (66 0F 6F / F3 0F 6F)
    /// </summary>
    public static bool HandleMovdqLoad(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        return HandleMovXmmLoad(ctx, ip, log); // same encoding pattern
    }

    /// <summary>
    /// MOVDQA/MOVDQU xmm/m128, xmm (66 0F 7F / F3 0F 7F)
    /// </summary>
    public static bool HandleMovdqStore(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        return HandleMovXmmStore(ctx, ip, log); // same encoding pattern
    }

    /// <summary>
    /// MOVD xmm, r/m32 (66 0F 6E) / MOVQ xmm, r/m64 (66 REX.W 0F 6E)
    /// </summary>
    public static bool HandleMovdToXmm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F 6E

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;
        int opSize = prefix.W ? 64 : 32;

        ulong val;
        if (modrm.Mod == 0b11)
            val = RegisterHelper.ReadSized(ctx, modrm.Rm, opSize);
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            val = opSize == 64 ? *(ulong*)addr : *(uint*)addr;
        }

        // Zero-extend into XMM
        byte* xmm = GetXmm(dstXmm);
        *(ulong*)xmm = val;
        *(ulong*)(xmm + 8) = 0;

        log($"MOVD/Q XMM{dstXmm}, r/m{opSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// MOVD r/m32, xmm (66 0F 7E) / MOVQ r/m64, xmm (66 REX.W 0F 7E)
    /// Also: MOVQ xmm, xmm/m64 (F3 0F 7E)
    /// </summary>
    public static bool HandleMovdFromXmm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F 7E

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        if (prefix.HasRep) // F3 0F 7E = MOVQ xmm, xmm/m64
        {
            int dstXmm = modrm.Reg;
            ulong val;
            if (modrm.Mod == 0b11)
                val = *(ulong*)GetXmm(modrm.Rm);
            else
            {
                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
                val = *(ulong*)addr;
            }
            byte* xmm = GetXmm(dstXmm);
            *(ulong*)xmm = val;
            *(ulong*)(xmm + 8) = 0;
            log($"MOVQ XMM{dstXmm}, xmm/m64", offs);
        }
        else // 66 0F 7E = MOVD/Q r/m, xmm
        {
            int srcXmm = modrm.Reg;
            int opSize = prefix.W ? 64 : 32;
            ulong val = opSize == 64 ? *(ulong*)GetXmm(srcXmm) : *(uint*)GetXmm(srcXmm);

            if (modrm.Mod == 0b11)
                RegisterHelper.WriteSized(ctx, modrm.Rm, val, opSize);
            else
            {
                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
                if (opSize == 64) *(ulong*)addr = val; else *(uint*)addr = (uint)val;
            }
            log($"MOVD/Q r/m{opSize}, XMM{srcXmm}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// XORPS xmm, xmm/m128 (0F 57)
    /// XORPD xmm, xmm/m128 (66 0F 57)
    /// PXOR xmm, xmm/m128 (66 0F EF)
    /// </summary>
    public static bool HandleXorXmm(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;

        ulong lo, hi;
        if (modrm.Mod == 0b11)
        {
            lo = *(ulong*)GetXmm(modrm.Rm);
            hi = *(ulong*)(GetXmm(modrm.Rm) + 8);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            lo = *(ulong*)addr;
            hi = *(ulong*)(addr + 8);
        }

        byte* dst = GetXmm(dstXmm);
        *(ulong*)dst ^= lo;
        *(ulong*)(dst + 8) ^= hi;

        log($"XORPS/PXOR XMM{dstXmm}, xmm/m128", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// MOVSS xmm, xmm/m32 (F3 0F 10) / MOVSS xmm/m32, xmm (F3 0F 11)
    /// MOVSD xmm, xmm/m64 (F2 0F 10) / MOVSD xmm/m64, xmm (F2 0F 11)
    /// </summary>
    public static bool HandleMovScalar(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        bool isLoad = (op2 & 1) == 0; // 10=load, 11=store
        bool isDouble = prefix.HasRepne; // F2=double, F3=single
        int scalarSize = isDouble ? 8 : 4;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        if (isLoad)
        {
            int dstXmm = modrm.Reg;
            if (modrm.Mod == 0b11)
            {
                // xmm <- xmm: only low scalar, rest preserved
                if (scalarSize == 4) *(uint*)GetXmm(dstXmm) = *(uint*)GetXmm(modrm.Rm);
                else *(ulong*)GetXmm(dstXmm) = *(ulong*)GetXmm(modrm.Rm);
            }
            else
            {
                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
                byte* xmm = GetXmm(dstXmm);
                // From memory: zero-extend
                *(ulong*)xmm = 0;
                *(ulong*)(xmm + 8) = 0;
                if (scalarSize == 4) *(uint*)xmm = *(uint*)addr;
                else *(ulong*)xmm = *(ulong*)addr;
            }
            log($"MOVS{(isDouble ? "D" : "S")} XMM{dstXmm}, xmm/m{scalarSize * 8}", offs);
        }
        else
        {
            int srcXmm = modrm.Reg;
            if (modrm.Mod == 0b11)
            {
                if (scalarSize == 4) *(uint*)GetXmm(modrm.Rm) = *(uint*)GetXmm(srcXmm);
                else *(ulong*)GetXmm(modrm.Rm) = *(ulong*)GetXmm(srcXmm);
            }
            else
            {
                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
                if (scalarSize == 4) *(uint*)addr = *(uint*)GetXmm(srcXmm);
                else *(ulong*)addr = *(ulong*)GetXmm(srcXmm);
            }
            log($"MOVS{(isDouble ? "D" : "S")} xmm/m{scalarSize * 8}, XMM{srcXmm}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// MOVLPS/MOVHPS load/store (0F 12/13/16/17)
    /// MOVLPD/MOVHPD (66 0F 12/13/16/17)
    /// </summary>
    public static bool HandleMovLowHigh(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int xmmReg = modrm.Reg;

        bool isHigh = op2 == 0x16 || op2 == 0x17;
        bool isStore = op2 == 0x13 || op2 == 0x17;
        int qwordOff = isHigh ? 8 : 0;

        if (modrm.Mod == 0b11 && !isStore)
        {
            // MOVLHPS (0F 16 mod=11) or MOVHLPS (0F 12 mod=11)
            if (op2 == 0x16) // MOVLHPS: dst.high = src.low
                *(ulong*)(GetXmm(xmmReg) + 8) = *(ulong*)GetXmm(modrm.Rm);
            else // MOVHLPS: dst.low = src.high
                *(ulong*)GetXmm(xmmReg) = *(ulong*)(GetXmm(modrm.Rm) + 8);
        }
        else if (modrm.Mod != 0b11)
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            if (isStore)
                *(ulong*)addr = *(ulong*)(GetXmm(xmmReg) + qwordOff);
            else
                *(ulong*)(GetXmm(xmmReg) + qwordOff) = *(ulong*)addr;
        }

        log($"MOVLHPS/MOVHLPS/MOVLPS/MOVHPS XMM{xmmReg}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// LDMXCSR m32 (0F AE /2) / STMXCSR m32 (0F AE /3)
    /// FXSAVE/FXRSTOR (0F AE /0, /1) - skip
    /// CLFLUSH (0F AE /7) - NOP
    /// </summary>
    public static bool HandleFxsaveLdmxcsr(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F AE

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int grp = (modrm.Raw >> 3) & 7;

        if (modrm.Mod != 0b11)
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

            switch (grp)
            {
                case 2: // LDMXCSR
                    ctx->MxCsr = *(uint*)addr;
                    log($"LDMXCSR [0x{addr:X}]", offs);
                    break;
                case 3: // STMXCSR
                    *(uint*)addr = ctx->MxCsr;
                    log($"STMXCSR [0x{addr:X}]", offs);
                    break;
                default: // FXSAVE, FXRSTOR, CLFLUSH, etc. - skip
                    log($"0F AE /{grp} (skipped)", offs);
                    break;
            }
        }
        else
        {
            // mod=11 forms: LFENCE (0F AE E8), MFENCE (0F AE F0), SFENCE (0F AE F8)
            log("FENCE", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOVNTPS/MOVNTPD/MOVNTI/MOVNTDQ (0F 2B, 66 0F 2B, 0F C3, 66 0F E7)</summary>
    public static bool HandleMovnt(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        if (modrm.Mod == 0b11) { ctx->Rip += (ulong)offs; return true; } // shouldn't happen

        ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

        if (op2 == 0xC3) // MOVNTI m32/m64, r32/r64
        {
            int opSize = prefix.W ? 64 : 32;
            ulong val = RegisterHelper.ReadSized(ctx, modrm.Reg, opSize);
            if (opSize == 64) *(ulong*)addr = val; else *(uint*)addr = (uint)val;
            log($"MOVNTI [0x{addr:X}], r{opSize}", offs);
        }
        else // MOVNTPS/MOVNTPD/MOVNTDQ: store 128-bit from XMM
        {
            Buffer.MemoryCopy(GetXmm(modrm.Reg), (void*)addr, 16, 16);
            log($"MOVNT* [0x{addr:X}], XMM{modrm.Reg}", offs);
        }

        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>
    /// Generic SSE arithmetic stub: ADDPS/SUBPS/MULPS/DIVPS/etc.
    /// These operate on XMM registers - we handle reg-reg and reg-mem forms.
    /// </summary>
    public static bool HandleSseArith(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;

        // Load source into temp buffer
        byte srcBuf_stack = 0;
        byte* srcBuf;
        byte[] srcArr = new byte[16];
        fixed (byte* pSrc = srcArr)
        {
            srcBuf = pSrc;
            if (modrm.Mod == 0b11)
                Buffer.MemoryCopy(GetXmm(modrm.Rm), srcBuf, 16, 16);
            else
            {
                ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
                Buffer.MemoryCopy((void*)addr, srcBuf, 16, 16);
            }

            byte* dst = GetXmm(dstXmm);

            // Determine operation width
            bool packed = !prefix.HasRep && !prefix.HasRepne;
            bool isDouble = prefix.HasOperandSize || prefix.HasRepne;
            int elemSize = isDouble ? 8 : 4;
            int count = packed ? (16 / elemSize) : 1;

            for (int i = 0; i < count; i++)
            {
                int off = i * elemSize;
                if (elemSize == 4)
                {
                    float a = *(float*)(dst + off);
                    float b = *(float*)(srcBuf + off);
                    float r = op2 switch
                    {
                        0x58 => a + b, // ADDPS/ADDSS
                        0x59 => a * b, // MULPS/MULSS
                        0x5C => a - b, // SUBPS/SUBSS
                        0x5E => b != 0 ? a / b : 0, // DIVPS/DIVSS
                        0x5D => Math.Min(a, b), // MINPS
                        0x5F => Math.Max(a, b), // MAXPS
                        0x51 => MathF.Sqrt(b), // SQRTPS (unary)
                        _ => a
                    };
                    *(float*)(dst + off) = r;
                }
                else
                {
                    double a = *(double*)(dst + off);
                    double b = *(double*)(srcBuf + off);
                    double r = op2 switch
                    {
                        0x58 => a + b,
                        0x59 => a * b,
                        0x5C => a - b,
                        0x5E => b != 0 ? a / b : 0,
                        0x5D => Math.Min(a, b),
                        0x5F => Math.Max(a, b),
                        0x51 => Math.Sqrt(b),
                        _ => a
                    };
                    *(double*)(dst + off) = r;
                }
            }
        }

        log($"SSE arith 0x{op2:X2} XMM{dstXmm}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>ANDPS/ANDNPS/ORPS (0F 54/55/56) and packed double variants</summary>
    public static bool HandleSseLogic(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;

        ulong sLo, sHi;
        if (modrm.Mod == 0b11)
        {
            sLo = *(ulong*)GetXmm(modrm.Rm);
            sHi = *(ulong*)(GetXmm(modrm.Rm) + 8);
        }
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            sLo = *(ulong*)addr;
            sHi = *(ulong*)(addr + 8);
        }

        byte* dst = GetXmm(dstXmm);
        ulong* dLo = (ulong*)dst;
        ulong* dHi = (ulong*)(dst + 8);

        switch (op2)
        {
            case 0x54: *dLo &= sLo; *dHi &= sHi; break; // ANDPS
            case 0x55: *dLo = ~*dLo & sLo; *dHi = ~*dHi & sHi; break; // ANDNPS
            case 0x56: *dLo |= sLo; *dHi |= sHi; break; // ORPS
            case 0x57: *dLo ^= sLo; *dHi ^= sHi; break; // XORPS (also handled in HandleXorXmm)
        }

        log($"SSE logic 0x{op2:X2} XMM{dstXmm}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CVTSI2SS (F3 0F 2A), CVTSI2SD (F2 0F 2A)</summary>
    public static bool HandleCvtIntToFloat(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F 2A

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstXmm = modrm.Reg;
        int opSize = prefix.W ? 64 : 32;

        long val;
        if (modrm.Mod == 0b11)
            val = (long)InstructionDecoder.SignExtend(RegisterHelper.ReadSized(ctx, modrm.Rm, opSize), opSize);
        else
        {
            ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
            val = opSize == 64 ? *(long*)addr : *(int*)addr;
        }

        byte* xmm = GetXmm(dstXmm);
        if (prefix.HasRepne) // F2 = CVTSI2SD
            *(double*)xmm = (double)val;
        else // F3 = CVTSI2SS
            *(float*)xmm = (float)val;

        log($"CVTSI2S{(prefix.HasRepne ? "D" : "S")} XMM{dstXmm}, r/m{opSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CVTSS2SI/CVTSD2SI (F3/F2 0F 2D), CVTTSS2SI/CVTTSD2SI (F3/F2 0F 2C)</summary>
    public static bool HandleCvtFloatToInt(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        bool truncate = op2 == 0x2C;
        int dstSize = prefix.W ? 64 : 32;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        int dstReg = modrm.Reg;

        long result;
        if (prefix.HasRepne) // F2 = SD
        {
            double val;
            if (modrm.Mod == 0b11) val = *(double*)GetXmm(modrm.Rm);
            else { ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B); val = *(double*)addr; }
            result = truncate ? (long)val : (long)Math.Round(val);
        }
        else // F3 = SS
        {
            float val;
            if (modrm.Mod == 0b11) val = *(float*)GetXmm(modrm.Rm);
            else { ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B); val = *(float*)addr; }
            result = truncate ? (long)val : (long)MathF.Round(val);
        }

        RegisterHelper.WriteSized(ctx, dstReg, (ulong)result, dstSize);
        log($"CVT{(truncate ? "T" : "")}S{(prefix.HasRepne ? "D" : "S")}2SI r{dstSize}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>UCOMISS (0F 2E) / UCOMISD (66 0F 2E) / COMISS (0F 2F) / COMISD (66 0F 2F)</summary>
    public static bool HandleUcomisd(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];
        bool isDouble = prefix.HasOperandSize;

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);

        double a, b;
        if (isDouble)
        {
            a = *(double*)GetXmm(modrm.Reg);
            if (modrm.Mod == 0b11) b = *(double*)GetXmm(modrm.Rm);
            else { ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B); b = *(double*)addr; }
        }
        else
        {
            a = *(float*)GetXmm(modrm.Reg);
            if (modrm.Mod == 0b11) b = *(float*)GetXmm(modrm.Rm);
            else { ulong addr = InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B); b = *(float*)addr; }
        }

        uint f = ctx->EFlags & ~(FlagsCalculator.CF | FlagsCalculator.ZF | FlagsCalculator.PF | FlagsCalculator.OF | FlagsCalculator.SF | FlagsCalculator.AF);
        if (double.IsNaN(a) || double.IsNaN(b))
            f |= FlagsCalculator.CF | FlagsCalculator.ZF | FlagsCalculator.PF; // unordered
        else if (a < b) f |= FlagsCalculator.CF;
        else if (a == b) f |= FlagsCalculator.ZF;
        // else a > b: all clear
        ctx->EFlags = f;

        log($"UCOMIS{(isDouble ? "D" : "S")} XMM{modrm.Reg}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>SHUFPS/SHUFPD (0F C6 / 66 0F C6)</summary>
    public static bool HandleShufps(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F C6

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        // Skip the imm8 selector
        if (modrm.Mod != 0b11)
            InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
        offs++; // imm8

        log($"SHUFPS/SHUFPD XMM{modrm.Reg} (stub)", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>CMPPS/CMPPD/CMPSS/CMPSD (0F C2)</summary>
    public static bool HandleCmpps(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F C2

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (modrm.Mod != 0b11)
            InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
        offs++; // imm8

        log($"CMPPS/CMPPD XMM{modrm.Reg} (stub)", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>UNPCKLPS/UNPCKHPS (0F 14/15)</summary>
    public static bool HandleUnpack(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs++; // 0F
        byte op2 = ip[offs++];

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (modrm.Mod != 0b11)
            InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);

        log($"UNPACK 0x{op2:X2} XMM{modrm.Reg} (stub)", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>PSHUFD/PSHUFHW/PSHUFLW (66 0F 70 / F3 0F 70 / F2 0F 70)</summary>
    public static bool HandlePshufd(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F 70

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        if (modrm.Mod != 0b11)
            InstructionDecoder.ResolveAddress(ctx, ip, ref offs, modrm.Mod, modrm.Rm, prefix.X, prefix.B);
        offs++; // imm8

        log($"PSHUFD/PSHUFHW XMM{modrm.Reg} (stub)", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    /// <summary>MOVMSKPS/MOVMSKPD (0F 50 / 66 0F 50)</summary>
    public static bool HandleMovmskps(CONTEXT* ctx, byte* ip, Action<string, int> log)
    {
        int offs = 0;
        var prefix = InstructionDecoder.ParsePrefixes(ip, ref offs);
        offs += 2; // 0F 50

        var modrm = InstructionDecoder.ParseModRM(ip, ref offs, prefix.R, prefix.B);
        // Extract sign bits from XMM
        byte* xmm = GetXmm(modrm.Rm);
        int result;
        if (prefix.HasOperandSize) // MOVMSKPD
        {
            result = ((*(ulong*)(xmm + 8) >> 63) != 0 ? 2 : 0) | ((*(ulong*)xmm >> 63) != 0 ? 1 : 0);
        }
        else // MOVMSKPS
        {
            result = 0;
            for (int i = 0; i < 4; i++)
                if ((*(uint*)(xmm + i * 4) >> 31) != 0) result |= 1 << i;
        }
        RegisterHelper.Write32(ctx, modrm.Reg, (uint)result);

        log($"MOVMSKPS r{modrm.Reg}, XMM{modrm.Rm}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
}
