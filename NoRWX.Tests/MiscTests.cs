using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

public unsafe class MiscTests
{
    // === NOP ===

    [Fact]
    public void Nop()
    {
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x90];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code, out int len));
        Assert.Equal(1, len);
    }

    // === CBW/CWDE/CDQE ===

    [Fact]
    public void Cdqe_SignExtend_EaxToRax()
    {
        // CDQE (48 98) - sign-extend EAX to RAX
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x00000000FFFFFF80; // EAX = 0xFFFFFF80 (negative int32)
        byte[] code = [0x48, 0x98];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFFFFFFF80UL, ctx.Rax);
    }

    [Fact]
    public void Cdqe_Positive()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFF0000007F; // EAX = 0x7F
        byte[] code = [0x48, 0x98];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x7FUL, ctx.Rax);
    }

    [Fact]
    public void Cwde_SignExtend_AxToEax()
    {
        // CWDE (98) - sign-extend AX to EAX
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF80; // AX = 0xFF80 (negative int16)
        byte[] code = [0x98];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFF80UL, ctx.Rax); // zero-extended to 64-bit from 32-bit sign-extend
    }

    // === CWD/CDQ/CQO ===

    [Fact]
    public void Cqo_SignExtend_Negative()
    {
        // CQO (48 99) - RDX = sign-extend(RAX)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x8000000000000000; // negative
        byte[] code = [0x48, 0x99];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFFFFFFFFFUL, ctx.Rdx);
    }

    [Fact]
    public void Cqo_SignExtend_Positive()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x7FFFFFFFFFFFFFFF;
        byte[] code = [0x48, 0x99];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rdx);
    }

    [Fact]
    public void Cdq_SignExtend_Negative()
    {
        // CDQ (99) - EDX = sign-extend(EAX)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80000000;
        byte[] code = [0x99];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFUL, ctx.Rdx);
    }

    // === Flag manipulation ===

    [Fact]
    public void Clc()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.CF;
        byte[] code = [0xF8]; // CLC

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
    }

    [Fact]
    public void Stc()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.CF;
        byte[] code = [0xF9]; // STC

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
    }

    [Fact]
    public void Cmc()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.CF;
        byte[] code = [0xF5]; // CMC

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));

        // CMC again
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
    }

    [Fact]
    public void Cld()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.DF;
        byte[] code = [0xFC]; // CLD

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.DF));
    }

    [Fact]
    public void Std()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        byte[] code = [0xFD]; // STD

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.DF));
    }

    // === String operations ===

    [Fact]
    public void Stosb_Single()
    {
        // STOSB (AA) - store AL to [RDI], advance RDI
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF; // forward
        var buf = new byte[16];
        fixed (byte* p = buf)
        {
            ctx.Rdi = (ulong)p;
            ctx.Rax = 0x42;
            byte[] code = [0xAA];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42, buf[0]);
            Assert.Equal((ulong)p + 1, ctx.Rdi);
        }
    }

    [Fact]
    public void Rep_Stosb()
    {
        // REP STOSB (F3 AA) - fill RCX bytes with AL
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var buf = new byte[16];
        fixed (byte* p = buf)
        {
            ctx.Rdi = (ulong)p;
            ctx.Rax = 0xBB;
            ctx.Rcx = 4;
            byte[] code = [0xF3, 0xAA];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBB, buf[0]);
            Assert.Equal(0xBB, buf[1]);
            Assert.Equal(0xBB, buf[2]);
            Assert.Equal(0xBB, buf[3]);
            Assert.Equal(0, buf[4]);
            Assert.Equal(0UL, ctx.Rcx);
        }
    }

    [Fact]
    public void Movsb_Single()
    {
        // MOVSB (A4) - copy byte from [RSI] to [RDI]
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 0x42, 0x43 };
        var dst = new byte[4];
        fixed (byte* pSrc = src)
        fixed (byte* pDst = dst)
        {
            ctx.Rsi = (ulong)pSrc;
            ctx.Rdi = (ulong)pDst;
            byte[] code = [0xA4];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42, dst[0]);
            Assert.Equal((ulong)pSrc + 1, ctx.Rsi);
            Assert.Equal((ulong)pDst + 1, ctx.Rdi);
        }
    }

    [Fact]
    public void Lodsb_Single()
    {
        // LODSB (AC) - load byte from [RSI] into AL
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 0x99 };
        fixed (byte* p = src)
        {
            ctx.Rsi = (ulong)p;
            byte[] code = [0xAC];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x99UL, ctx.Rax & 0xFF);
        }
    }

    // === BSF/BSR ===

    [Fact]
    public void Bsf_R32()
    {
        // BSF ECX, EAX (0F BC C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x08; // bit 3 is lowest set
        byte[] code = [0x0F, 0xBC, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(3UL, ctx.Rcx);
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Bsf_Zero_SetsZF()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0;
        byte[] code = [0x0F, 0xBC, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Bsr_R32()
    {
        // BSR ECX, EAX (0F BD C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80; // bit 7 is highest set
        byte[] code = [0x0F, 0xBD, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(7UL, ctx.Rcx);
    }

    // === INT3 ===

    [Fact]
    public void Int3()
    {
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xCC];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code, out int len));
        Assert.Equal(1, len);
    }
}
