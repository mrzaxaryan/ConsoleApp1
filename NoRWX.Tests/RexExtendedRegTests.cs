using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

/// <summary>
/// Tests for REX-prefixed operations using extended registers R8-R15.
/// </summary>
public unsafe class RexExtendedRegTests
{
    // === MOV with R8-R15 ===

    [Fact]
    public void Mov_R8_Imm64()
    {
        // MOV R8, imm64 => 49 B8 ...
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x49, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x0807060504030201UL, ctx.R8);
    }

    [Fact]
    public void Mov_R15_R8()
    {
        // MOV R15, R8 => 4D 89 C7 (REX.WRB MOV r/m64, r64)
        var ctx = TestHelper.CreateContext();
        ctx.R8 = 0xCAFE;
        byte[] code = [0x4D, 0x89, 0xC7]; // REX.W+R+B
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xCAFEUL, ctx.R15);
    }

    [Fact]
    public void Mov_R9_Mem_Disp8()
    {
        // MOV R9, [RBP-8] => 4C 8B 4D F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rbp = (ulong)(p + 128);
            *(ulong*)(p + 120) = 0xBEEF;
            byte[] code = [0x4C, 0x8B, 0x4D, 0xF8]; // REX.WR
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBEEFUL, ctx.R9);
        }
    }

    [Fact]
    public void Mov_Mem_R10()
    {
        // MOV [RBP-8], R10 => 4C 89 55 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rbp = (ulong)(p + 128);
            ctx.R10 = 0x1234;
            byte[] code = [0x4C, 0x89, 0x55, 0xF8]; // REX.WR
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x1234UL, *(ulong*)(p + 120));
        }
    }

    // === ADD with extended regs ===

    [Fact]
    public void Add_R8_R9()
    {
        // ADD R8, R9 => 4D 01 C8
        var ctx = TestHelper.CreateContext();
        ctx.R8 = 100;
        ctx.R9 = 200;
        byte[] code = [0x4D, 0x01, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(300UL, ctx.R8);
    }

    [Fact]
    public void Sub_R12_R13()
    {
        // SUB R12, R13 => 4D 29 EC
        var ctx = TestHelper.CreateContext();
        ctx.R12 = 500;
        ctx.R13 = 200;
        byte[] code = [0x4D, 0x29, 0xEC];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(300UL, ctx.R12);
    }

    // === XOR with extended regs ===

    [Fact]
    public void Xor_R11_R11_SelfClear()
    {
        // XOR R11, R11 => 4D 31 DB
        var ctx = TestHelper.CreateContext();
        ctx.R11 = 0xDEADBEEF;
        byte[] code = [0x4D, 0x31, 0xDB];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.R11);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    // === CMP with extended regs ===

    [Fact]
    public void Cmp_R14_R15()
    {
        // CMP R14, R15 => 4D 39 FE
        var ctx = TestHelper.CreateContext();
        ctx.R14 = 42;
        ctx.R15 = 42;
        byte[] code = [0x4D, 0x39, 0xFE];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    // === LEA with extended regs ===

    [Fact]
    public void Lea_R8_RbpDisp8()
    {
        // LEA R8, [RBP+0x10] => 4C 8D 45 10
        var ctx = TestHelper.CreateContext();
        ctx.Rbp = 0x1000;
        byte[] code = [0x4C, 0x8D, 0x45, 0x10];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x1010UL, ctx.R8);
    }

    // === Group1 with extended regs ===

    [Fact]
    public void Group1_Add_R8_Imm8()
    {
        // ADD R8, 0x10 => 49 83 C0 10
        var ctx = TestHelper.CreateContext();
        ctx.R8 = 0x100;
        byte[] code = [0x49, 0x83, 0xC0, 0x10];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x110UL, ctx.R8);
    }

    [Fact]
    public void Group1_Sub_R9_Imm8()
    {
        // SUB R9, 0x10 => 49 83 E9 10
        var ctx = TestHelper.CreateContext();
        ctx.R9 = 0x100;
        byte[] code = [0x49, 0x83, 0xE9, 0x10];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xF0UL, ctx.R9);
    }

    // === PUSH/POP extended regs ===

    [Fact]
    public void Push_Pop_R12_Roundtrip()
    {
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.R12 = 0xFEEDFACE;

            byte[] pushCode = [0x41, 0x54]; // PUSH R12
            Assert.True(TestHelper.EmulateInstruction(ref ctx, pushCode));
            Assert.Equal(0xFEEDFACEUL, *(ulong*)ctx.Rsp);

            byte[] popCode = [0x41, 0x5C]; // POP R12
            ctx.R12 = 0; // clear
            Assert.True(TestHelper.EmulateInstruction(ref ctx, popCode));
            Assert.Equal(0xFEEDFACEUL, ctx.R12);
        }
    }

    [Fact]
    public void Push_Pop_R15_Roundtrip()
    {
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ctx.R15 = 0x42;
            byte[] pushCode = [0x41, 0x57]; // PUSH R15
            Assert.True(TestHelper.EmulateInstruction(ref ctx, pushCode));

            ctx.R15 = 0;
            byte[] popCode = [0x41, 0x5F]; // POP R15
            Assert.True(TestHelper.EmulateInstruction(ref ctx, popCode));
            Assert.Equal(0x42UL, ctx.R15);
        }
    }

    // === MOV r8b with REX (SPL, BPL, SIL, DIL) ===

    [Fact]
    public void Mov_R8b_Imm8()
    {
        // MOV R8B, 0x42 => 41 B0 42
        var ctx = TestHelper.CreateContext();
        ctx.R8 = 0xFF00;
        byte[] code = [0x41, 0xB0, 0x42];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.R8 & 0xFF);
    }

    // === MOVZX/MOVSX with extended regs ===

    [Fact]
    public void Movzx_R8_R32_Byte()
    {
        // MOVZX R8D, CL => 44 0F B6 C1
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xFF42;
        byte[] code = [0x44, 0x0F, 0xB6, 0xC1];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.R8);
    }

    [Fact]
    public void Movsx_R9_R32_Byte_Negative()
    {
        // MOVSX R9, CL (byte, sign-extend to 64) => 4C 0F BE C9
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x80; // -128 as byte
        byte[] code = [0x4C, 0x0F, 0xBE, 0xC9]; // REX.WR
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFFFFFFF80UL, ctx.R9);
    }

    // === SETcc with extended regs ===

    [Fact]
    public void Sete_R8b()
    {
        // SETE R8B => 41 0F 94 C0
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x41, 0x0F, 0x94, 0xC0];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(1UL, ctx.R8 & 0xFF);
    }

    // === TEST with extended regs ===

    [Fact]
    public void Test_R8_R9()
    {
        // TEST R8, R9 => 4D 85 C8
        var ctx = TestHelper.CreateContext();
        ctx.R8 = 0xF0;
        ctx.R9 = 0x0F;
        byte[] code = [0x4D, 0x85, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 0xF0 & 0x0F = 0
    }

    // === CMOVcc with extended regs ===

    [Fact]
    public void Cmovne_R8_R9()
    {
        // CMOVNE R8, R9 => 4D 0F 45 C1
        var ctx = TestHelper.CreateContext();
        ctx.EFlags &= ~FlagsCalculator.ZF; // NE condition true
        ctx.R8 = 0;
        ctx.R9 = 0x42;
        byte[] code = [0x4D, 0x0F, 0x45, 0xC1];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x42UL, ctx.R8);
    }

    // === IMUL with extended regs ===

    [Fact]
    public void Imul3_R8_R9_Imm8()
    {
        // IMUL R8, R9, 10 => 4D 6B C1 0A
        var ctx = TestHelper.CreateContext();
        ctx.R9 = 7;
        byte[] code = [0x4D, 0x6B, 0xC1, 0x0A];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(70UL, ctx.R8);
    }
}
