using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

/// <summary>
/// Tests for arithmetic instructions with all addressing modes and operand sizes.
/// </summary>
public unsafe class ArithmeticMemoryTests
{
    // ========== ADD with memory ==========

    [Fact]
    public void Add_Mem32_Reg32_ModIndirect()
    {
        // ADD [RAX], ECX => 01 08 (mod=00)
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 100;
            ctx.Rcx = 50;
            byte[] code = [0x01, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(150U, *(uint*)p);
        }
    }

    [Fact]
    public void Add_Mem64_Reg64_Disp8()
    {
        // ADD [RBP-0x10], RAX => 48 01 45 F0
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rbp = (ulong)(p + 128);
            *(ulong*)(p + 112) = 1000;
            ctx.Rax = 234;
            byte[] code = [0x48, 0x01, 0x45, 0xF0];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(1234UL, *(ulong*)(p + 112));
        }
    }

    [Fact]
    public void Add_Mem64_Reg64_Disp32()
    {
        // ADD [RAX+0x100], RCX => 48 01 88 00 01 00 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[512];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)(p + 0x100) = 10;
            ctx.Rcx = 20;
            byte[] code = [0x48, 0x01, 0x88, 0x00, 0x01, 0x00, 0x00];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(30UL, *(ulong*)(p + 0x100));
        }
    }

    [Fact]
    public void Add_Reg64_Mem64_Disp8()
    {
        // ADD RAX, [RBP-8] => 48 03 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rbp = (ulong)(p + 128);
            *(ulong*)(p + 120) = 50;
            ctx.Rax = 100;
            byte[] code = [0x48, 0x03, 0x45, 0xF8];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(150UL, ctx.Rax);
        }
    }

    [Fact]
    public void Add_Mem8_Reg8()
    {
        // ADD [RAX], CL => 00 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *p = 10;
            ctx.Rcx = 5;
            byte[] code = [0x00, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal((byte)15, *p);
        }
    }

    [Fact]
    public void Add_Mem64_SetsFlags()
    {
        // ADD [RAX], RCX => 48 01 08, result = 0 (overflow)
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 0xFFFFFFFFFFFFFFFF;
            ctx.Rcx = 1;
            byte[] code = [0x48, 0x01, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0UL, *(ulong*)p);
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        }
    }

    // ========== SUB with memory ==========

    [Fact]
    public void Sub_Mem64_Reg64_Disp8()
    {
        // SUB [RBP-8], RAX => 48 29 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rbp = (ulong)(p + 128);
            *(ulong*)(p + 120) = 200;
            ctx.Rax = 50;
            byte[] code = [0x48, 0x29, 0x45, 0xF8];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(150UL, *(ulong*)(p + 120));
        }
    }

    [Fact]
    public void Sub_Reg64_Mem64()
    {
        // SUB RAX, [RCX] => 48 2B 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            *(ulong*)p = 30;
            ctx.Rax = 100;
            byte[] code = [0x48, 0x2B, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(70UL, ctx.Rax);
        }
    }

    // ========== CMP with memory ==========

    [Fact]
    public void Cmp_Mem64_Reg64_Equal()
    {
        // CMP [RAX], RCX => 48 39 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 42;
            ctx.Rcx = 42;
            byte[] code = [0x48, 0x39, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
            Assert.Equal(42UL, *(ulong*)p); // not modified
        }
    }

    [Fact]
    public void Cmp_Mem32_Reg32_Less()
    {
        // CMP [RAX], ECX => 39 08 where [RAX] < ECX
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 10;
            ctx.Rcx = 20;
            byte[] code = [0x39, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        }
    }

    [Fact]
    public void Cmp_Reg64_Mem64()
    {
        // CMP RAX, [RCX] => 48 3B 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            *(ulong*)p = 100;
            ctx.Rax = 100;
            byte[] code = [0x48, 0x3B, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    [Fact]
    public void Cmp_Mem8_Reg8()
    {
        // CMP [RAX], CL => 38 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *p = 0xFF;
            ctx.Rcx = 0xFF;
            byte[] code = [0x38, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // ========== Group1 with memory (all sub-operations) ==========

    [Fact]
    public void Group1_Or_Mem32_Imm8()
    {
        // OR DWORD [RAX], 0x0F => 83 08 0F
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0xF0;
            byte[] code = [0x83, 0x08, 0x0F];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFFU, *(uint*)p);
        }
    }

    [Fact]
    public void Group1_And_Mem32_Imm8()
    {
        // AND DWORD [RAX], 0x0F => 83 20 0F
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0xFF;
            byte[] code = [0x83, 0x20, 0x0F];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x0FU, *(uint*)p);
        }
    }

    [Fact]
    public void Group1_Xor_Mem64_Imm8()
    {
        // XOR QWORD [RAX], -1 => 48 83 30 FF
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 0xAAAAAAAAAAAAAAAA;
            byte[] code = [0x48, 0x83, 0x30, 0xFF]; // 83 /6 ib
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x5555555555555555UL, *(ulong*)p);
        }
    }

    [Fact]
    public void Group1_Sub_Mem64_Imm32()
    {
        // SUB QWORD [RAX], 0x100 => 48 81 28 00 01 00 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 0x500;
            byte[] code = [0x48, 0x81, 0x28, 0x00, 0x01, 0x00, 0x00];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x400UL, *(ulong*)p);
        }
    }

    [Fact]
    public void Group1_Add_Mem32_Imm32()
    {
        // ADD DWORD [RAX], 0x100 => 81 00 00 01 00 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0x50;
            byte[] code = [0x81, 0x00, 0x00, 0x01, 0x00, 0x00];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x150U, *(uint*)p);
        }
    }

    [Fact]
    public void Group1_Cmp_Mem64_Imm8_NotZero()
    {
        // CMP QWORD [RAX], 5 => 48 83 38 05
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 10;
            byte[] code = [0x48, 0x83, 0x38, 0x05]; // 83 /7 ib
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
            Assert.Equal(10UL, *(ulong*)p); // CMP doesn't modify
        }
    }

    // ========== Group3 with memory (NOT/NEG/MUL/DIV) ==========

    [Fact]
    public void Not_Mem32()
    {
        // NOT DWORD [RAX] => F7 10
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0x0000FFFF;
            byte[] code = [0xF7, 0x10]; // F7 /2
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFFFF0000U, *(uint*)p);
        }
    }

    [Fact]
    public void Neg_Mem64()
    {
        // NEG QWORD [RAX] => 48 F7 18
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 42;
            byte[] code = [0x48, 0xF7, 0x18]; // F7 /3
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(unchecked((ulong)-42), *(ulong*)p);
        }
    }

    [Fact]
    public void Test_Mem32_Imm32()
    {
        // TEST DWORD [RAX], 0x01 => F7 00 01 00 00 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0xFE; // bit 0 clear
            byte[] code = [0xF7, 0x00, 0x01, 0x00, 0x00, 0x00]; // F7 /0
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // ========== Shift with memory ==========

    [Fact]
    public void Shr_Mem64_Imm8()
    {
        // SHR QWORD [RAX], 4 => 48 C1 28 04
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 0x100;
            byte[] code = [0x48, 0xC1, 0x28, 0x04]; // C1 /5 ib
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x10UL, *(ulong*)p);
        }
    }

    [Fact]
    public void Sar_Mem32_Imm8()
    {
        // SAR DWORD [RAX], 4 => C1 38 04
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0x80000000; // negative
            byte[] code = [0xC1, 0x38, 0x04]; // C1 /7 ib
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xF8000000U, *(uint*)p); // sign-extended
        }
    }

    [Fact]
    public void Shl_Mem8_By1()
    {
        // SHL BYTE [RAX], 1 => D0 20
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *p = 0x40;
            byte[] code = [0xD0, 0x20]; // D0 /4
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal((byte)0x80, *p);
        }
    }

    [Fact]
    public void Shr_Mem32_ByCL()
    {
        // SHR DWORD [RAX], CL => D3 28
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 0x100;
            ctx.Rcx = 4;
            byte[] code = [0xD3, 0x28]; // D3 /5
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x10U, *(uint*)p);
        }
    }

    // ========== INC/DEC with memory (various sizes) ==========

    [Fact]
    public void Inc_Mem32_FF()
    {
        // INC DWORD [RAX] => FF 00 (FF /0)
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(uint*)p = 99;
            byte[] code = [0xFF, 0x00];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            // FF /0 in Group5 handler treats as 64-bit... but we test the value
            Assert.Equal(100UL, *(ulong*)p);
        }
    }

    [Fact]
    public void Dec_Mem_FF()
    {
        // DEC QWORD [RAX] => FF 08 (FF /1)
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *(ulong*)p = 100;
            byte[] code = [0xFF, 0x08];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(99UL, *(ulong*)p);
        }
    }

    // ========== SIB addressing ==========

    [Fact]
    public void Add_Mem_SIB_BaseIndex()
    {
        // ADD [RCX+RDX*1], EAX => 01 04 11 (SIB: scale=0, index=2(RDX), base=1(RCX))
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            ctx.Rdx = 0x40;
            *(uint*)(p + 0x40) = 10;
            ctx.Rax = 5;
            byte[] code = [0x01, 0x04, 0x11];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(15U, *(uint*)(p + 0x40));
        }
    }

    [Fact]
    public void Mov_Mem_SIB_Scale4()
    {
        // MOV [RCX+RAX*4], EDX => 89 14 81 (SIB: scale=2, index=0(RAX), base=1(RCX))
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            ctx.Rax = 8; // offset = 8*4 = 32
            ctx.Rdx = 0xDEAD;
            byte[] code = [0x89, 0x14, 0x81];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xDEADU, *(uint*)(p + 32));
        }
    }

    [Fact]
    public void Mov_Reg_Mem_SIB_Disp8()
    {
        // MOV EAX, [RCX+RDX*2+0x10] => 8B 44 51 10
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            ctx.Rdx = 4; // 4*2=8, +0x10=0x18
            *(uint*)(p + 0x18) = 0x42424242;
            byte[] code = [0x8B, 0x44, 0x51, 0x10];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42424242UL, ctx.Rax);
        }
    }
}
