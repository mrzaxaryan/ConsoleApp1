using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

public unsafe class ControlFlowTests
{
    // === JMP ===

    [Fact]
    public void Jmp_Short_Forward()
    {
        // JMP +5 (EB 05) - skip 5 bytes forward from end of instruction
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xEB, 0x05];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code, out int len));
        // RIP should be: original + 2 + 5 = original + 7
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 7, ctx.Rip);
        }
    }

    [Fact]
    public void Jmp_Short_Backward()
    {
        // JMP -2 (EB FE) - jump to self (infinite loop)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xEB, 0xFE];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p, ctx.Rip); // jumps back to start
        }
    }

    [Fact]
    public void Jmp_Near_Forward()
    {
        // JMP +0x100 (E9 00 01 00 00)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xE9, 0x00, 0x01, 0x00, 0x00];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 5 + 0x100, ctx.Rip);
        }
    }

    // === Jcc short ===

    [Fact]
    public void Je_Short_Taken()
    {
        // JE +5 (74 05) with ZF=1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x74, 0x05];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 2 + 5, ctx.Rip);
        }
    }

    [Fact]
    public void Je_Short_NotTaken()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.ZF;
        byte[] code = [0x74, 0x05];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 2, ctx.Rip); // falls through
        }
    }

    [Fact]
    public void Jne_Short_Taken()
    {
        // JNE +3 (75 03) with ZF=0
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.ZF;
        byte[] code = [0x75, 0x03];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 2 + 3, ctx.Rip);
        }
    }

    [Fact]
    public void Jl_Short_SFneOF()
    {
        // JL +3 (7C 03) with SF=1, OF=0
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = (ctx.EFlags & ~FlagsCalculator.OF) | FlagsCalculator.SF;
        byte[] code = [0x7C, 0x03];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 5, ctx.Rip); // taken
        }
    }

    [Fact]
    public void Jge_Short_SFeqOF()
    {
        // JGE +3 (7D 03) with SF=1, OF=1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.SF | FlagsCalculator.OF;
        byte[] code = [0x7D, 0x03];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 5, ctx.Rip);
        }
    }

    [Fact]
    public void Jb_Short_CF()
    {
        // JB +3 (72 03) with CF=1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.CF;
        byte[] code = [0x72, 0x03];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 5, ctx.Rip);
        }
    }

    [Fact]
    public void Ja_Short_NoCF_NoZF()
    {
        // JA +3 (77 03) with CF=0, ZF=0
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~(FlagsCalculator.CF | FlagsCalculator.ZF);
        byte[] code = [0x77, 0x03];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 5, ctx.Rip);
        }
    }

    // === Jcc near ===

    [Fact]
    public void Je_Near_Taken()
    {
        // JE +0x100 (0F 84 00 01 00 00) with ZF=1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x0F, 0x84, 0x00, 0x01, 0x00, 0x00];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 6 + 0x100, ctx.Rip);
        }
    }

    [Fact]
    public void Jne_Near_NotTaken()
    {
        // JNE +0x100 (0F 85 00 01 00 00) with ZF=1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x0F, 0x85, 0x00, 0x01, 0x00, 0x00];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 6, ctx.Rip); // falls through
        }
    }

    // === CALL/RET ===

    [Fact]
    public void Call_Rel32()
    {
        // CALL +0x100 (E8 00 01 00 00)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            byte[] code = [0xE8, 0x00, 0x01, 0x00, 0x00];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            fixed (byte* p = code)
            {
                // RIP should be target
                Assert.Equal((ulong)p + 5 + 0x100, ctx.Rip);
                // RSP should be decremented by 8
                Assert.Equal((ulong)pStack + 256 - 8, ctx.Rsp);
                // Return address pushed on stack
                Assert.Equal((ulong)p + 5, *(ulong*)ctx.Rsp);
            }
        }
    }

    [Fact]
    public void Ret_Simple()
    {
        // RET (C3) - pops return address from stack
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Rsp = (ulong)(pStack + 248);
            *(ulong*)ctx.Rsp = 0xDEADBEEF;
            byte[] code = [0xC3];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xDEADBEEFUL, ctx.Rip);
            Assert.Equal((ulong)(pStack + 256), ctx.Rsp);
        }
    }

    [Fact]
    public void Ret_Imm16()
    {
        // RET 8 (C2 08 00) - pops return address and adjusts stack by 8
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Rsp = (ulong)(pStack + 240);
            *(ulong*)ctx.Rsp = 0x12345678;
            byte[] code = [0xC2, 0x08, 0x00];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x12345678UL, ctx.Rip);
            Assert.Equal((ulong)(pStack + 256), ctx.Rsp); // 240 + 8 (pop) + 8 (imm16)
        }
    }

    // === LEAVE ===

    [Fact]
    public void Leave()
    {
        // LEAVE (C9) - RSP=RBP; POP RBP
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ulong savedRbp = 0xBEEF;
            ctx.Rbp = (ulong)(pStack + 200);
            *(ulong*)(pStack + 200) = savedRbp; // value to pop into RBP
            byte[] code = [0xC9];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(savedRbp, ctx.Rbp);
            Assert.Equal((ulong)(pStack + 208), ctx.Rsp);
        }
    }

    // === LOOP ===

    [Fact]
    public void Loop_Taken()
    {
        // LOOP -2 (E2 FE) with RCX=5
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 5;
        byte[] code = [0xE2, 0xFE];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(4UL, ctx.Rcx);
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p, ctx.Rip); // jumps back to start
        }
    }

    [Fact]
    public void Loop_NotTaken_RcxZero()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 1;
        byte[] code = [0xE2, 0xFE];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx);
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 2, ctx.Rip); // falls through
        }
    }
}
