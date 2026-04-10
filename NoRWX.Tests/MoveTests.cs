using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

public unsafe class MoveTests
{
    // === MOV r/m, r ===

    [Fact]
    public void Mov_R32_R32()
    {
        // MOV ECX, EAX (89 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x12345678;
        byte[] code = [0x89, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x12345678UL, ctx.Rcx);
    }

    [Fact]
    public void Mov_R64_R64()
    {
        // MOV RCX, RAX (48 89 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x123456789ABCDEF0;
        byte[] code = [0x48, 0x89, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x123456789ABCDEF0UL, ctx.Rcx);
    }

    [Fact]
    public void Mov_R32_ZeroExtends()
    {
        // MOV ECX, EAX (89 C1) - should zero-extend upper 32 bits
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x00000001;
        ctx.Rcx = 0xFFFFFFFFFFFFFFFF;
        byte[] code = [0x89, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(1UL, ctx.Rcx); // upper 32 bits zeroed
    }

    // === MOV r, r/m ===

    [Fact]
    public void Mov_R_Rm32()
    {
        // MOV EAX, ECX (8B C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xDEADBEEF;
        byte[] code = [0x8B, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xDEADBEEFUL, ctx.Rax);
    }

    // === MOV r, imm ===

    [Fact]
    public void Mov_R32_Imm32()
    {
        // MOV EAX, 0x12345678 (B8 78 56 34 12)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xB8, 0x78, 0x56, 0x34, 0x12];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x12345678UL, ctx.Rax);
    }

    [Fact]
    public void Mov_R64_Imm64()
    {
        // MOV RAX, 0x0102030405060708 (48 B8 ...)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x48, 0xB8, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0102030405060708UL, ctx.Rax);
    }

    [Fact]
    public void Mov_R8_Imm8()
    {
        // MOV AL, 0x42 (B0 42)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF00;
        byte[] code = [0xB0, 0x42];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.Rax & 0xFF);
        Assert.Equal(0xFF00UL, ctx.Rax & 0xFF00); // upper byte preserved
    }

    [Fact]
    public void Mov_ExtendedReg_Imm32()
    {
        // MOV R8D, 0x12345678 (41 B8 78 56 34 12)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x41, 0xB8, 0x78, 0x56, 0x34, 0x12];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x12345678UL, ctx.R8);
    }

    // === MOV r/m, imm ===

    [Fact]
    public void Mov_Rm32_Imm32_Register()
    {
        // MOV ECX, 0x42 (C7 C1 42 00 00 00)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0xC7, 0xC1, 0x42, 0x00, 0x00, 0x00];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.Rcx);
    }

    // === LEA ===

    [Fact]
    public void Lea_R32_RegPlusDisp()
    {
        // LEA ECX, [EAX+0x10] (8D 48 10) - mod=01, reg=1, rm=0, disp8=0x10
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x1000;
        byte[] code = [0x8D, 0x48, 0x10];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x1010UL, ctx.Rcx);
    }

    [Fact]
    public void Lea_R64_RegPlusDisp()
    {
        // LEA RCX, [RAX+0x10] (48 8D 48 10)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x100000000;
        byte[] code = [0x48, 0x8D, 0x48, 0x10];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x100000010UL, ctx.Rcx);
    }

    // === MOVZX ===

    [Fact]
    public void Movzx_R32_R8()
    {
        // MOVZX ECX, AL (0F B6 C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF42;
        byte[] code = [0x0F, 0xB6, 0xC8]; // mod=11, reg=1, rm=0

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.Rcx); // zero-extended from AL
    }

    [Fact]
    public void Movzx_R32_R16()
    {
        // MOVZX ECX, AX (0F B7 C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xDEAD1234;
        byte[] code = [0x0F, 0xB7, 0xC8]; // mod=11, reg=1, rm=0

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x1234UL, ctx.Rcx);
    }

    // === MOVSX ===

    [Fact]
    public void Movsx_R32_R8_Positive()
    {
        // MOVSX ECX, AL (0F BE C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x42;
        byte[] code = [0x0F, 0xBE, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.Rcx);
    }

    [Fact]
    public void Movsx_R32_R8_Negative()
    {
        // MOVSX ECX, AL (0F BE C8) with AL=0x80 (negative byte)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80;
        byte[] code = [0x0F, 0xBE, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFF80UL, ctx.Rcx); // sign-extended to 32-bit
    }

    [Fact]
    public void Movsx_R64_R8_Negative()
    {
        // MOVSX RCX, AL (48 0F BE C8) with AL=0x80
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80;
        byte[] code = [0x48, 0x0F, 0xBE, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFFFFFFF80UL, ctx.Rcx); // sign-extended to 64-bit
    }

    // === MOVSXD ===

    [Fact]
    public void Movsxd_R64_R32()
    {
        // MOVSXD RCX, EAX (48 63 C8) with EAX=0x80000000 (negative int32)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80000000;
        byte[] code = [0x48, 0x63, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFF80000000UL, ctx.Rcx);
    }

    [Fact]
    public void Movsxd_R64_R32_Positive()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x7FFFFFFF;
        byte[] code = [0x48, 0x63, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x7FFFFFFFUL, ctx.Rcx);
    }

    // === SETcc ===

    [Fact]
    public void Sete_WhenZF()
    {
        // SETE CL (0F 94 C1) - sets CL to 1 if ZF
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        ctx.Rcx = 0xFF;
        byte[] code = [0x0F, 0x94, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(1UL, ctx.Rcx & 0xFF);
    }

    [Fact]
    public void Sete_WhenNotZF()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.ZF;
        ctx.Rcx = 0xFF;
        byte[] code = [0x0F, 0x94, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx & 0xFF);
    }

    [Fact]
    public void Setl_WhenSFneOF()
    {
        // SETL CL (0F 9C C1)
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.SF; // SF=1, OF=0 -> SF!=OF -> true
        byte[] code = [0x0F, 0x9C, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(1UL, ctx.Rcx & 0xFF);
    }

    // === CMOVcc ===

    [Fact]
    public void Cmove_Taken()
    {
        // CMOVE ECX, EAX (0F 44 C8)
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        ctx.Rax = 0x42;
        ctx.Rcx = 0;
        byte[] code = [0x0F, 0x44, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.Rcx);
    }

    [Fact]
    public void Cmove_NotTaken()
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.ZF;
        ctx.Rax = 0x42;
        ctx.Rcx = 0x99;
        byte[] code = [0x0F, 0x44, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x99UL, ctx.Rcx); // not moved
    }

    // === XCHG ===

    [Fact]
    public void Xchg_R32_R32()
    {
        // XCHG ECX, EAX (87 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 1;
        ctx.Rcx = 2;
        byte[] code = [0x87, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(2UL, ctx.Rax);
        Assert.Equal(1UL, ctx.Rcx);
    }

    // === BSWAP ===

    [Fact]
    public void Bswap_R32()
    {
        // BSWAP EAX (0F C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x01020304;
        byte[] code = [0x0F, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x04030201UL, ctx.Rax);
    }

    [Fact]
    public void Bswap_R64()
    {
        // BSWAP RAX (48 0F C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x0102030405060708;
        byte[] code = [0x48, 0x0F, 0xC8];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0807060504030201UL, ctx.Rax);
    }
}
