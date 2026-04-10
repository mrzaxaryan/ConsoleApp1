using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

public unsafe class LogicTests
{
    // === AND ===

    [Fact]
    public void And_R32_R32()
    {
        // AND ECX, EAX (21 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x0F0F;
        ctx.Rcx = 0xFF00;
        byte[] code = [0x21, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0F00UL, ctx.Rcx);
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
    }

    [Fact]
    public void And_SetsZF()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xF0;
        ctx.Rcx = 0x0F;
        byte[] code = [0x21, 0xC1]; // AND ECX, EAX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void And_R64_R64()
    {
        // AND RCX, RAX (48 21 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x00FF00FF00FF00FF;
        ctx.Rcx = 0xFF00FF00FF00FF00;
        byte[] code = [0x48, 0x21, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    // === OR ===

    [Fact]
    public void Or_R32_R32()
    {
        // OR ECX, EAX (09 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x0F;
        ctx.Rcx = 0xF0;
        byte[] code = [0x09, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFUL, ctx.Rcx);
    }

    [Fact]
    public void Or_ClearsFlags()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.CF | FlagsCalculator.OF;
        ctx.Rax = 1;
        ctx.Rcx = 2;
        byte[] code = [0x09, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
    }

    // === XOR ===

    [Fact]
    public void Xor_R32_R32()
    {
        // XOR ECX, EAX (31 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xAA;
        ctx.Rcx = 0xFF;
        byte[] code = [0x31, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x55UL, ctx.Rcx);
    }

    [Fact]
    public void Xor_SelfClear()
    {
        // XOR EAX, EAX (31 C0) - common idiom to zero a register
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xDEADBEEF;
        byte[] code = [0x31, 0xC0];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.PF));
    }

    [Fact]
    public void Xor_R64_SelfClear()
    {
        // XOR RAX, RAX (48 31 C0)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xDEADBEEFCAFEBABE;
        byte[] code = [0x48, 0x31, 0xC0];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax);
    }

    // === TEST ===

    [Fact]
    public void Test_R32_R32()
    {
        // TEST ECX, EAX (85 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x01;
        ctx.Rcx = 0x02;
        byte[] code = [0x85, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 1 & 2 = 0
    }

    [Fact]
    public void Test_R32_R32_NonZero()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x03;
        ctx.Rcx = 0x01;
        byte[] code = [0x85, 0xC1]; // TEST ECX, EAX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 3 & 1 = 1
    }

    [Fact]
    public void Test_R8_R8()
    {
        // TEST CL, AL (84 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x00;
        ctx.Rcx = 0xFF;
        byte[] code = [0x84, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Test_AL_Imm8()
    {
        // TEST AL, 0x01 (A8 01)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x03;
        byte[] code = [0xA8, 0x01];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Test_AL_Imm8_Zero()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFE;
        byte[] code = [0xA8, 0x01]; // TEST AL, 0x01

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 0xFE & 0x01 = 0
    }

    // === AND/OR/XOR with accumulator ===

    [Fact]
    public void And_AL_Imm8()
    {
        // AND AL, 0x0F (24 0F)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF;
        byte[] code = [0x24, 0x0F];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0FUL, ctx.Rax & 0xFF);
    }

    [Fact]
    public void Or_AL_Imm8()
    {
        // OR AL, 0xF0 (0C F0)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x0F;
        byte[] code = [0x0C, 0xF0];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFUL, ctx.Rax & 0xFF);
    }

    [Fact]
    public void Xor_AL_Imm8()
    {
        // XOR AL, 0xFF (34 FF)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xAA;
        byte[] code = [0x34, 0xFF];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x55UL, ctx.Rax & 0xFF);
    }
}
