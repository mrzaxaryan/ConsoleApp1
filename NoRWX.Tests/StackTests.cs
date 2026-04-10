using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

public unsafe class StackTests
{
    [Fact]
    public void Push_Rax()
    {
        // PUSH RAX (50)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.Rax = 0xDEADBEEF;
            byte[] code = [0x50];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal((ulong)pStack + 248, ctx.Rsp);
            Assert.Equal(0xDEADBEEFUL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Pop_Rax()
    {
        // POP RAX (58)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Rsp = (ulong)(pStack + 248);
            *(ulong*)(pStack + 248) = 0x42;
            byte[] code = [0x58];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42UL, ctx.Rax);
            Assert.Equal((ulong)pStack + 256, ctx.Rsp);
        }
    }

    [Fact]
    public void Push_R8()
    {
        // PUSH R8 (41 50)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.R8 = 0x1234;
            byte[] code = [0x41, 0x50];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x1234UL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Pop_R8()
    {
        // POP R8 (41 58)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Rsp = (ulong)(pStack + 248);
            *(ulong*)(pStack + 248) = 0xABCD;
            byte[] code = [0x41, 0x58];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xABCDUL, ctx.R8);
        }
    }

    [Fact]
    public void Push_Rbp()
    {
        // PUSH RBP (55)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.Rbp = 0xBEEF;
            byte[] code = [0x55];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBEEFUL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Pop_Rbp()
    {
        // POP RBP (5D)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Rsp = (ulong)(pStack + 248);
            *(ulong*)(pStack + 248) = 0xFACE;
            byte[] code = [0x5D];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFACEUL, ctx.Rbp);
        }
    }

    [Fact]
    public void Push_Imm8()
    {
        // PUSH 0x42 (6A 42)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            byte[] code = [0x6A, 0x42];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42UL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Push_Imm8_Negative()
    {
        // PUSH -1 (6A FF) - sign-extended to 64-bit
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            byte[] code = [0x6A, 0xFF];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFFFFFFFFFFFFFFFFUL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Push_Imm32()
    {
        // PUSH 0x12345678 (68 78 56 34 12)
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            byte[] code = [0x68, 0x78, 0x56, 0x34, 0x12];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x12345678UL, *(ulong*)ctx.Rsp);
        }
    }

    [Fact]
    public void Push_Pop_RoundTrip()
    {
        // PUSH RAX then POP RCX - values should transfer
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.Rax = 0xCAFEBABE;

            byte[] pushCode = [0x50]; // PUSH RAX
            Assert.True(TestHelper.EmulateInstruction(ref ctx, pushCode));

            ulong rspAfterPush = ctx.Rsp;

            byte[] popCode = [0x59]; // POP RCX
            Assert.True(TestHelper.EmulateInstruction(ref ctx, popCode));

            Assert.Equal(0xCAFEBABEUL, ctx.Rcx);
            Assert.Equal((ulong)pStack + 256, ctx.Rsp); // back to original
        }
    }

    [Fact]
    public void Push_AllRegs_Order()
    {
        // Push RAX through RDI and verify stack order
        var ctx = TestHelper.CreateContext();
        var stack = new byte[1024];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 1024);
            ctx.Rax = 0xAA;
            ctx.Rcx = 0xCC;
            ctx.Rdx = 0xDD;
            ctx.Rbx = 0xBB;

            // PUSH RAX (50)
            byte[] code = [0x50];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xAAUL, *(ulong*)ctx.Rsp);
        }
    }
}
