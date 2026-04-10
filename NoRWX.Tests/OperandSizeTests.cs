using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

/// <summary>
/// Tests for correct operand size handling (8/16/32/64-bit) across instructions.
/// </summary>
public unsafe class OperandSizeTests
{
    // ========== 16-bit operations with 0x66 prefix ==========

    [Fact]
    public void Mov_R16_Imm16()
    {
        // MOV AX, 0x1234 => 66 B8 34 12
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFFFFFF0000;
        byte[] code = [0x66, 0xB8, 0x34, 0x12];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFFFFF1234UL, ctx.Rax); // upper bits preserved
    }

    [Fact]
    public void Add_R16_R16()
    {
        // ADD AX, CX => 66 01 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFF0010;
        ctx.Rcx = 0xFFFF0020;
        byte[] code = [0x66, 0x01, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFF0030UL, ctx.Rax); // only low 16 bits affected
    }

    [Fact]
    public void Sub_R16_Imm8()
    {
        // SUB AX, 0x10 => 66 83 E8 10
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x100;
        byte[] code = [0x66, 0x83, 0xE8, 0x10];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xF0UL, ctx.Rax & 0xFFFF);
    }

    [Fact]
    public void Cmp_R16_Imm8()
    {
        // CMP AX, 0 => 66 83 F8 00
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0;
        byte[] code = [0x66, 0x83, 0xF8, 0x00]; // 83 /7 ib
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Mov_Mem16_Imm16()
    {
        // MOV WORD [RAX], 0x1234 => 66 C7 00 34 12
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0xFFFFFFFF;
            byte[] code = [0x66, 0xC7, 0x00, 0x34, 0x12];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal((ushort)0x1234, *(ushort*)p);
            Assert.Equal((ushort)0xFFFF, *(ushort*)(p + 2)); // upper bytes untouched
        }
    }

    // ========== 8-bit operations ==========

    [Fact]
    public void Add_R8_R8()
    {
        // ADD AL, CL => 00 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF10;
        ctx.Rcx = 5;
        byte[] code = [0x00, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFF15UL, ctx.Rax); // only AL modified
    }

    [Fact]
    public void Sub_R8_R8()
    {
        // SUB AL, CL => 28 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 20;
        ctx.Rcx = 5;
        byte[] code = [0x28, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(15UL, ctx.Rax & 0xFF);
    }

    [Fact]
    public void Cmp_R8_R8()
    {
        // CMP AL, CL => 38 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x42;
        ctx.Rcx = 0x42;
        byte[] code = [0x38, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Mov_R8_R8()
    {
        // MOV AL, CL => 88 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF00;
        ctx.Rcx = 0x42;
        byte[] code = [0x88, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFF42UL, ctx.Rax); // only AL changed
    }

    [Fact]
    public void Mov_R8_Mem8()
    {
        // MOV AL, [RCX] => 8A 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            *p = 0x99;
            ctx.Rax = 0xFF00;
            byte[] code = [0x8A, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFF99UL, ctx.Rax);
        }
    }

    [Fact]
    public void Xor_R8_R8()
    {
        // XOR AL, CL => 30 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xAA;
        ctx.Rcx = 0xFF;
        byte[] code = [0x30, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x55UL, ctx.Rax & 0xFF);
    }

    // ========== 32-bit zero extension ==========

    [Fact]
    public void Mov_R32_ZeroExtends_Upper()
    {
        // MOV EAX, ECX => 89 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFFFFFFFFFF;
        ctx.Rcx = 0x00000001;
        byte[] code = [0x89, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(1UL, ctx.Rax); // upper 32 bits cleared
    }

    [Fact]
    public void Add_R32_ZeroExtends()
    {
        // ADD EAX, ECX => 01 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFF00000001;
        ctx.Rcx = 1;
        byte[] code = [0x01, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(2UL, ctx.Rax); // 32-bit result zero-extended
    }

    [Fact]
    public void Xor_R32_ZeroExtends()
    {
        // XOR EAX, EAX => 31 C0
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFFFFFFFFFF;
        byte[] code = [0x31, 0xC0];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax); // zero-extended
    }

    // ========== 64-bit operations ==========

    [Fact]
    public void Add_R64_Large()
    {
        // ADD RAX, RCX => 48 01 C8
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x7FFFFFFFFFFFFFFF;
        ctx.Rcx = 1;
        byte[] code = [0x48, 0x01, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x8000000000000000UL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
    }

    [Fact]
    public void Mov_R64_Imm64_Full()
    {
        // MOV RAX, 0xFEDCBA9876543210 => 48 B8 10 32 54 76 98 BA DC FE
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x48, 0xB8, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFEDCBA9876543210UL, ctx.Rax);
    }

    // ========== Group1 80h (8-bit r/m, imm8) ==========

    [Fact]
    public void Group1_Add_Rm8_Imm8()
    {
        // ADD AL, 0x10 => 80 C0 10
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x20;
        byte[] code = [0x80, 0xC0, 0x10];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x30UL, ctx.Rax & 0xFF);
    }

    [Fact]
    public void Group1_Cmp_Rm8_Imm8()
    {
        // CMP CL, 0x42 => 80 F9 42
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x42;
        byte[] code = [0x80, 0xF9, 0x42]; // 80 /7 ib
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Group1_And_Rm8_Imm8()
    {
        // AND AL, 0x0F => 80 E0 0F
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF;
        byte[] code = [0x80, 0xE0, 0x0F]; // 80 /4 ib
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0FUL, ctx.Rax & 0xFF);
    }
}
