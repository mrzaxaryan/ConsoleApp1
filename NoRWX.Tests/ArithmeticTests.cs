using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

public unsafe class ArithmeticTests
{
    // === ADD ===

    [Fact]
    public void Add_R32_R32_RegisterDirect()
    {
        // ADD ECX, EAX (01 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 10;
        ctx.Rcx = 20;
        byte[] code = [0x01, 0xC1]; // ADD ECX, EAX (mod=11, reg=0, rm=1)

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(30UL, ctx.Rcx);
    }

    [Fact]
    public void Add_R64_R64_WithRexW()
    {
        // ADD RCX, RAX (48 01 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x100000000;
        ctx.Rcx = 0x200000000;
        byte[] code = [0x48, 0x01, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x300000000UL, ctx.Rcx);
    }

    [Fact]
    public void Add_SetsCarryFlag()
    {
        // ADD EAX, ECX (01 C8) where result overflows 32-bit
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFF;
        ctx.Rcx = 1;
        byte[] code = [0x01, 0xC8]; // ADD EAX, ECX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax); // wraps to 0
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Add_SetsOverflowFlag()
    {
        // ADD EAX, ECX where signed overflow occurs
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x7FFFFFFF; // max positive int32
        ctx.Rcx = 1;
        byte[] code = [0x01, 0xC8]; // ADD EAX, ECX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x80000000UL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.SF));
    }

    [Fact]
    public void Add_R_Rm32()
    {
        // ADD EAX, ECX (03 C1) - r, r/m form
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 5;
        ctx.Rcx = 7;
        byte[] code = [0x03, 0xC1]; // ADD EAX, ECX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(12UL, ctx.Rax);
    }

    [Fact]
    public void Add_AL_Imm8()
    {
        // ADD AL, 0x42 (04 42)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x10;
        byte[] code = [0x04, 0x42];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x52UL, ctx.Rax);
    }

    [Fact]
    public void Add_EAX_Imm32()
    {
        // ADD EAX, 0x100 (05 00 01 00 00)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x50;
        byte[] code = [0x05, 0x00, 0x01, 0x00, 0x00];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x150UL, ctx.Rax);
    }

    // === SUB ===

    [Fact]
    public void Sub_R32_R32()
    {
        // SUB ECX, EAX (29 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 10;
        ctx.Rcx = 30;
        byte[] code = [0x29, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(20UL, ctx.Rcx);
    }

    [Fact]
    public void Sub_SetsCarryOnBorrow()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 50;
        ctx.Rcx = 30;
        byte[] code = [0x29, 0xC1]; // SUB ECX, EAX (30 - 50)

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
    }

    [Fact]
    public void Sub_R64_R64()
    {
        // SUB RCX, RAX (48 29 C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x100000000;
        ctx.Rcx = 0x300000000;
        byte[] code = [0x48, 0x29, 0xC1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x200000000UL, ctx.Rcx);
    }

    // === CMP ===

    [Fact]
    public void Cmp_Equal_SetsZF()
    {
        // CMP EAX, ECX (39 C8)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 42;
        ctx.Rcx = 42;
        byte[] code = [0x39, 0xC8]; // CMP EAX, ECX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.Equal(42UL, ctx.Rax); // not modified
    }

    [Fact]
    public void Cmp_Less_SetsCF()
    {
        // CMP EAX, ECX where EAX < ECX
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 10;
        ctx.Rcx = 20;
        byte[] code = [0x39, 0xC8]; // CMP EAX, ECX

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Cmp_AL_Imm8()
    {
        // CMP AL, 0x42 (3C 42)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x42;
        byte[] code = [0x3C, 0x42];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    // === Group 1 ===

    [Fact]
    public void Group1_Add_Rm32_Imm8()
    {
        // ADD ECX, 0x10 (83 C1 10)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x20;
        byte[] code = [0x83, 0xC1, 0x10]; // 83 /0 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x30UL, ctx.Rcx);
    }

    [Fact]
    public void Group1_Sub_Rm32_Imm8()
    {
        // SUB ECX, 0x10 (83 E9 10)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x30;
        byte[] code = [0x83, 0xE9, 0x10]; // 83 /5 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x20UL, ctx.Rcx);
    }

    [Fact]
    public void Group1_And_Rm32_Imm8()
    {
        // AND ECX, 0x0F (83 E1 0F)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xFF;
        byte[] code = [0x83, 0xE1, 0x0F]; // 83 /4 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0FUL, ctx.Rcx);
    }

    [Fact]
    public void Group1_Or_Rm32_Imm8()
    {
        // OR ECX, 0x10 (83 C9 10)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x01;
        byte[] code = [0x83, 0xC9, 0x10]; // 83 /1 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x11UL, ctx.Rcx);
    }

    [Fact]
    public void Group1_Xor_Rm32_Imm8()
    {
        // XOR ECX, 0xFF (83 F1 FF)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xAA;
        byte[] code = [0x83, 0xF1, 0xFF]; // 83 /6 ib, imm8=-1 sign-extends to 0xFFFFFFFF

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal((0xAAu ^ 0xFFFFFFFFu), (uint)ctx.Rcx);
    }

    [Fact]
    public void Group1_Cmp_Rm32_Imm8()
    {
        // CMP ECX, 0x20 (83 F9 20)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x20;
        byte[] code = [0x83, 0xF9, 0x20]; // 83 /7 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        Assert.Equal(0x20UL, ctx.Rcx); // not modified
    }

    [Fact]
    public void Group1_Add_R64_Imm8()
    {
        // ADD RCX, 0x10 (48 83 C1 10)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x100000000;
        byte[] code = [0x48, 0x83, 0xC1, 0x10];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x100000010UL, ctx.Rcx);
    }

    [Fact]
    public void Group1_Sub_R64_Imm32()
    {
        // SUB RAX, 0x100 (48 81 E8 00 01 00 00)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x200;
        byte[] code = [0x48, 0x81, 0xE8, 0x00, 0x01, 0x00, 0x00]; // 81 /5 id

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x100UL, ctx.Rax);
    }

    // === Group 2: Shifts ===

    [Fact]
    public void Shl_R32_Imm8()
    {
        // SHL ECX, 4 (C1 E1 04)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x01;
        byte[] code = [0xC1, 0xE1, 0x04]; // C1 /4 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x10UL, ctx.Rcx);
    }

    [Fact]
    public void Shr_R32_Imm8()
    {
        // SHR ECX, 4 (C1 E9 04)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x100;
        byte[] code = [0xC1, 0xE9, 0x04]; // C1 /5 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x10UL, ctx.Rcx);
    }

    [Fact]
    public void Sar_R32_Imm8()
    {
        // SAR ECX, 4 (C1 F9 04)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xFFFFFF00; // negative when interpreted as int32
        byte[] code = [0xC1, 0xF9, 0x04]; // C1 /7 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFF0UL & 0xFFFFFFFF, ctx.Rcx & 0xFFFFFFFF); // sign-extended shift
    }

    [Fact]
    public void Shl_R64_Imm8()
    {
        // SHL RCX, 32 (48 C1 E1 20)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 1;
        byte[] code = [0x48, 0xC1, 0xE1, 0x20]; // REX.W C1 /4 ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x100000000UL, ctx.Rcx);
    }

    // === Group 3: TEST/NOT/NEG/MUL/DIV ===

    [Fact]
    public void Not_R32()
    {
        // NOT ECX (F7 D1)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x0000FFFF;
        byte[] code = [0xF7, 0xD1]; // F7 /2

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFF0000UL, ctx.Rcx);
    }

    [Fact]
    public void Neg_R32()
    {
        // NEG ECX (F7 D9)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 10;
        byte[] code = [0xF7, 0xD9]; // F7 /3

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(unchecked((uint)-10), (uint)ctx.Rcx);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF)); // CF set when operand != 0
    }

    [Fact]
    public void Neg_Zero_ClearsCF()
    {
        // NEG ECX where ECX=0 (F7 D9)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0;
        byte[] code = [0xF7, 0xD9];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx);
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Mul_R32_Unsigned()
    {
        // MUL ECX (F7 E1) - EDX:EAX = EAX * ECX
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 100;
        ctx.Rcx = 200;
        byte[] code = [0xF7, 0xE1]; // F7 /4

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(20000UL, ctx.Rax);
        Assert.Equal(0UL, ctx.Rdx);
    }

    [Fact]
    public void Mul_R32_Overflow()
    {
        // MUL ECX (F7 E1) where result > 32 bits
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x80000000;
        ctx.Rcx = 4;
        byte[] code = [0xF7, 0xE1];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax);
        Assert.Equal(2UL, ctx.Rdx);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
    }

    [Fact]
    public void Div_R32()
    {
        // DIV ECX (F7 F1) - EAX = EDX:EAX / ECX, EDX = remainder
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 17;
        ctx.Rdx = 0;
        ctx.Rcx = 5;
        byte[] code = [0xF7, 0xF1]; // F7 /6

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(3UL, ctx.Rax);
        Assert.Equal(2UL, ctx.Rdx);
    }

    [Fact]
    public void Idiv_R32()
    {
        // IDIV ECX (F7 F9) - EAX = EDX:EAX / ECX (signed)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = unchecked((uint)-17);
        ctx.Rdx = 0xFFFFFFFF; // sign-extend to EDX:EAX
        ctx.Rcx = 5;
        byte[] code = [0xF7, 0xF9]; // F7 /7

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(unchecked((uint)-3), (uint)ctx.Rax);
        Assert.Equal(unchecked((uint)-2), (uint)ctx.Rdx);
    }

    [Fact]
    public void Test_R32_Imm32()
    {
        // TEST ECX, 0x01 (F7 C1 01 00 00 00)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x03;
        byte[] code = [0xF7, 0xC1, 0x01, 0x00, 0x00, 0x00]; // F7 /0

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 3 & 1 = 1 != 0
    }

    // === INC/DEC ===

    [Fact]
    public void Inc_R8()
    {
        // INC CL (FE C1)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xFF;
        byte[] code = [0xFE, 0xC1]; // FE /0

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx & 0xFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Dec_R8()
    {
        // DEC CL (FE C9)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 1;
        byte[] code = [0xFE, 0xC9]; // FE /1

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx & 0xFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    // === IMUL ===

    [Fact]
    public void Imul3_R32_Rm32_Imm8()
    {
        // IMUL ECX, EDX, 0x0A (6B CA 0A)
        var ctx = TestHelper.CreateContext();
        ctx.Rdx = 5;
        byte[] code = [0x6B, 0xCA, 0x0A]; // 6B /r ib

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(50UL, ctx.Rcx);
    }

    [Fact]
    public void Imul3_R64_Rm64_Imm8()
    {
        // IMUL RCX, RDX, 0x0A (48 6B CA 0A)
        var ctx = TestHelper.CreateContext();
        ctx.Rdx = 0x100000000;
        byte[] code = [0x48, 0x6B, 0xCA, 0x0A];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xA00000000UL, ctx.Rcx);
    }
}
