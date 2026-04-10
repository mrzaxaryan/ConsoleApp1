using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

/// <summary>
/// Tests for string operations (MOVS/STOS/LODS/CMPS/SCAS) with REP/REPNE and direction flag.
/// </summary>
public unsafe class StringOpTests
{
    // ========== MOVS ==========

    [Fact]
    public void Movsb_Forward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 0xAA, 0xBB };
        var dst = new byte[4];
        fixed (byte* pS = src, pD = dst)
        {
            ctx.Rsi = (ulong)pS;
            ctx.Rdi = (ulong)pD;
            byte[] code = [0xA4]; // MOVSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xAA, dst[0]);
            Assert.Equal((ulong)pS + 1, ctx.Rsi);
            Assert.Equal((ulong)pD + 1, ctx.Rdi);
        }
    }

    [Fact]
    public void Movsb_Backward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.DF; // backward
        var src = new byte[] { 0, 0, 0xCC };
        var dst = new byte[4];
        fixed (byte* pS = src, pD = dst)
        {
            ctx.Rsi = (ulong)(pS + 2); // point to last byte
            ctx.Rdi = (ulong)(pD + 2);
            byte[] code = [0xA4];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xCC, dst[2]);
            Assert.Equal((ulong)(pS + 1), ctx.Rsi); // decremented
            Assert.Equal((ulong)(pD + 1), ctx.Rdi);
        }
    }

    [Fact]
    public void Movsd_Forward()
    {
        // MOVSD (A5 without 66 prefix = 32-bit)
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[8];
        var dst = new byte[8];
        fixed (byte* pS = src, pD = dst)
        {
            *(uint*)pS = 0x12345678;
            ctx.Rsi = (ulong)pS;
            ctx.Rdi = (ulong)pD;
            byte[] code = [0xA5];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x12345678U, *(uint*)pD);
            Assert.Equal((ulong)pS + 4, ctx.Rsi);
            Assert.Equal((ulong)pD + 4, ctx.Rdi);
        }
    }

    [Fact]
    public void Rep_Movsb_Multiple()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 1, 2, 3, 4, 5, 0, 0, 0 };
        var dst = new byte[8];
        fixed (byte* pS = src, pD = dst)
        {
            ctx.Rsi = (ulong)pS;
            ctx.Rdi = (ulong)pD;
            ctx.Rcx = 5;
            byte[] code = [0xF3, 0xA4]; // REP MOVSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(1, dst[0]);
            Assert.Equal(2, dst[1]);
            Assert.Equal(3, dst[2]);
            Assert.Equal(4, dst[3]);
            Assert.Equal(5, dst[4]);
            Assert.Equal(0UL, ctx.Rcx);
        }
    }

    // ========== STOS ==========

    [Fact]
    public void Stosd_Forward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var dst = new byte[8];
        fixed (byte* pD = dst)
        {
            ctx.Rdi = (ulong)pD;
            ctx.Rax = 0xDEADBEEF;
            byte[] code = [0xAB]; // STOSD
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xDEADBEEFU, *(uint*)pD);
            Assert.Equal((ulong)pD + 4, ctx.Rdi);
        }
    }

    [Fact]
    public void Rep_Stosb_Fill()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var dst = new byte[16];
        fixed (byte* pD = dst)
        {
            ctx.Rdi = (ulong)pD;
            ctx.Rax = 0xFF;
            ctx.Rcx = 8;
            byte[] code = [0xF3, 0xAA]; // REP STOSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            for (int i = 0; i < 8; i++) Assert.Equal(0xFF, dst[i]);
            for (int i = 8; i < 16; i++) Assert.Equal(0, dst[i]);
            Assert.Equal(0UL, ctx.Rcx);
        }
    }

    [Fact]
    public void Rep_Stosd_Fill()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var dst = new byte[32];
        fixed (byte* pD = dst)
        {
            ctx.Rdi = (ulong)pD;
            ctx.Rax = 0xAABBCCDD;
            ctx.Rcx = 3;
            byte[] code = [0xF3, 0xAB]; // REP STOSD
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xAABBCCDDU, *(uint*)(pD));
            Assert.Equal(0xAABBCCDDU, *(uint*)(pD + 4));
            Assert.Equal(0xAABBCCDDU, *(uint*)(pD + 8));
            Assert.Equal(0U, *(uint*)(pD + 12)); // untouched
        }
    }

    // ========== LODS ==========

    [Fact]
    public void Lodsb_Forward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 0x42 };
        fixed (byte* pS = src)
        {
            ctx.Rsi = (ulong)pS;
            byte[] code = [0xAC];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42UL, ctx.Rax & 0xFF);
            Assert.Equal((ulong)pS + 1, ctx.Rsi);
        }
    }

    [Fact]
    public void Lodsd_Forward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[8];
        fixed (byte* pS = src)
        {
            *(uint*)pS = 0xFEEDFACE;
            ctx.Rsi = (ulong)pS;
            byte[] code = [0xAD]; // LODSD
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFEEDFACEUL, ctx.Rax & 0xFFFFFFFF);
        }
    }

    // ========== CMPS ==========

    [Fact]
    public void Cmpsb_Equal()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var a = new byte[] { 0x42 };
        var b = new byte[] { 0x42 };
        fixed (byte* pA = a, pB = b)
        {
            ctx.Rsi = (ulong)pA;
            ctx.Rdi = (ulong)pB;
            byte[] code = [0xA6]; // CMPSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Cmpsb_NotEqual()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var a = new byte[] { 1 };
        var b = new byte[] { 2 };
        fixed (byte* pA = a, pB = b)
        {
            ctx.Rsi = (ulong)pA;
            ctx.Rdi = (ulong)pB;
            byte[] code = [0xA6];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Repe_Cmpsb_FindMismatch()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var b = new byte[] { 1, 2, 3, 9, 5 }; // differs at index 3
        fixed (byte* pA = a, pB = b)
        {
            ctx.Rsi = (ulong)pA;
            ctx.Rdi = (ulong)pB;
            ctx.Rcx = 5;
            byte[] code = [0xF3, 0xA6]; // REPE CMPSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(1UL, ctx.Rcx); // stopped at index 3, 1 remaining
            Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Repe_Cmpsb_AllEqual()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var a = new byte[] { 1, 2, 3 };
        var b = new byte[] { 1, 2, 3 };
        fixed (byte* pA = a, pB = b)
        {
            ctx.Rsi = (ulong)pA;
            ctx.Rdi = (ulong)pB;
            ctx.Rcx = 3;
            byte[] code = [0xF3, 0xA6]; // REPE CMPSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0UL, ctx.Rcx);
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // ========== SCAS ==========

    [Fact]
    public void Scasb_Found()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var buf = new byte[] { 0x42 };
        fixed (byte* p = buf)
        {
            ctx.Rdi = (ulong)p;
            ctx.Rax = 0x42;
            byte[] code = [0xAE]; // SCASB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Repne_Scasb_FindByte()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var buf = new byte[] { 0, 0, 0, 0x42, 0 };
        fixed (byte* p = buf)
        {
            ctx.Rdi = (ulong)p;
            ctx.Rax = 0x42;
            ctx.Rcx = 5;
            byte[] code = [0xF2, 0xAE]; // REPNE SCASB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(1UL, ctx.Rcx); // found at index 3, 1 remaining
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Repne_Scasb_NotFound()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var buf = new byte[] { 1, 2, 3, 4 };
        fixed (byte* p = buf)
        {
            ctx.Rdi = (ulong)p;
            ctx.Rax = 0xFF;
            ctx.Rcx = 4;
            byte[] code = [0xF2, 0xAE]; // REPNE SCASB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0UL, ctx.Rcx);
            Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // ========== Direction flag variations ==========

    [Fact]
    public void Stosb_Backward()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.DF;
        var dst = new byte[8];
        fixed (byte* p = dst)
        {
            ctx.Rdi = (ulong)(p + 4);
            ctx.Rax = 0xEE;
            byte[] code = [0xAA]; // STOSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xEE, dst[4]);
            Assert.Equal((ulong)(p + 3), ctx.Rdi); // decremented
        }
    }

    [Fact]
    public void Rep_Movsb_ZeroCount()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var src = new byte[] { 0xAA };
        var dst = new byte[4];
        fixed (byte* pS = src, pD = dst)
        {
            ctx.Rsi = (ulong)pS;
            ctx.Rdi = (ulong)pD;
            ctx.Rcx = 0; // zero iterations
            byte[] code = [0xF3, 0xA4]; // REP MOVSB
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0, dst[0]); // nothing copied
            Assert.Equal(0UL, ctx.Rcx);
        }
    }
}
