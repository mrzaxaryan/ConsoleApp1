using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

/// <summary>
/// Edge case tests: overflow, underflow, boundary conditions, flag behavior.
/// </summary>
public unsafe class EdgeCaseTests
{
    // ========== Arithmetic overflow/underflow ==========

    [Fact]
    public void Add_32bit_MaxUnsigned_Plus1()
    {
        // 0xFFFFFFFF + 1 = 0, CF=1, ZF=1
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFFFFFFFF;
        ctx.Rcx = 1;
        byte[] code = [0x01, 0xC8]; // ADD EAX, ECX
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Add_32bit_SignedOverflow()
    {
        // 0x7FFFFFFF + 1 = 0x80000000, OF=1, SF=1
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x7FFFFFFF;
        ctx.Rcx = 1;
        byte[] code = [0x01, 0xC8];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x80000000UL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.SF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
    }

    [Fact]
    public void Sub_32bit_Underflow()
    {
        // 0 - 1 = 0xFFFFFFFF, CF=1, SF=1
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0;
        ctx.Rcx = 1;
        byte[] code = [0x29, 0xC8]; // SUB EAX, ECX
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFFFFFFFUL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.SF));
    }

    [Fact]
    public void Sub_64bit_SignedOverflow()
    {
        // 0x8000000000000000 - 1 = 0x7FFFFFFFFFFFFFFF, OF=1
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x8000000000000000;
        ctx.Rcx = 1;
        byte[] code = [0x48, 0x29, 0xC8]; // SUB RAX, RCX
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x7FFFFFFFFFFFFFFFUL, ctx.Rax);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.OF));
    }

    [Fact]
    public void Add_8bit_Overflow()
    {
        // AL=0xFF + CL=1 = 0, CF=1
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0xFF;
        ctx.Rcx = 1;
        byte[] code = [0x00, 0xC8]; // ADD AL, CL
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax & 0xFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
    }

    [Fact]
    public void Inc_8bit_NoCarryFlag()
    {
        // INC CL where CL=0xFF => wraps to 0, ZF=1, but CF NOT affected
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0xFF;
        ctx.EFlags |= FlagsCalculator.CF; // pre-set CF
        byte[] code = [0xFE, 0xC1]; // INC CL
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rcx & 0xFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF)); // CF preserved!
    }

    [Fact]
    public void Dec_8bit_NoCarryFlag()
    {
        // DEC CL where CL=0 => wraps to 0xFF, SF=1, but CF NOT affected
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0;
        ctx.EFlags &= ~FlagsCalculator.CF; // clear CF
        byte[] code = [0xFE, 0xC9]; // DEC CL
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0xFFUL, ctx.Rcx & 0xFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.SF));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF)); // CF preserved!
    }

    // ========== Parity flag ==========

    [Fact]
    public void Parity_Even()
    {
        // XOR EAX, EAX => result=0, PF=1 (0 has even parity)
        var ctx = TestHelper.CreateContext();
        byte[] code = [0x31, 0xC0];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.PF));
    }

    [Fact]
    public void Parity_Odd()
    {
        // result with odd number of 1-bits in low byte => PF=0
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x01; // one 1-bit = odd parity
        ctx.Rcx = 0;
        byte[] code = [0x09, 0xC8]; // OR EAX, ECX (result = 0x01)
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.False(TestHelper.IsFlagSet(ctx, FlagsCalculator.PF));
    }

    // ========== Neg edge cases ==========

    [Fact]
    public void Neg_MinInt32()
    {
        // NEG 0x80000000 => 0x80000000 (OF=1 in 32-bit)
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x80000000;
        byte[] code = [0xF7, 0xD9]; // NEG ECX
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x80000000UL, ctx.Rcx);
    }

    // ========== MUL edge cases ==========

    [Fact]
    public void Mul_8bit()
    {
        // MUL CL (F6 E1) => AX = AL * CL
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 200;
        ctx.Rcx = 200;
        byte[] code = [0xF6, 0xE1]; // F6 /4
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(40000UL, ctx.Rax & 0xFFFF);
        Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.CF)); // result > 8-bit
    }

    [Fact]
    public void Mul_64bit()
    {
        // MUL RCX (48 F7 E1)
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 0x100000000;
        ctx.Rcx = 0x100000000;
        byte[] code = [0x48, 0xF7, 0xE1]; // REX.W F7 /4
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0UL, ctx.Rax);
        Assert.Equal(1UL, ctx.Rdx); // high 64 bits
    }

    // ========== DIV edge cases ==========

    [Fact]
    public void Div_8bit()
    {
        // DIV CL (F6 F1) => AL = AX / CL, AH = AX % CL
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 257; // AX = 257
        ctx.Rcx = 10;
        byte[] code = [0xF6, 0xF1];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(25UL, ctx.Rax & 0xFF); // quotient
        Assert.Equal(7UL, (ctx.Rax >> 8) & 0xFF); // remainder
    }

    [Fact]
    public void Div_ByZero_ReturnsFalse()
    {
        var ctx = TestHelper.CreateContext();
        ctx.Rax = 100;
        ctx.Rcx = 0;
        byte[] code = [0xF7, 0xF1]; // DIV ECX
        Assert.False(TestHelper.EmulateInstruction(ref ctx, code));
    }

    // ========== CALL/RET stack integrity ==========

    [Fact]
    public void Call_Ret_StackBalance()
    {
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256);
            ulong origRsp = ctx.Rsp;

            // CALL +0 (call next instruction, push return addr)
            byte[] callCode = [0xE8, 0x00, 0x00, 0x00, 0x00];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, callCode));
            Assert.Equal(origRsp - 8, ctx.Rsp);

            // RET (pop return addr)
            byte[] retCode = [0xC3];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, retCode));
            Assert.Equal(origRsp, ctx.Rsp);
        }
    }

    // ========== LEAVE correctness ==========

    [Fact]
    public void Leave_RestoresFrame()
    {
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            // Simulate a function prologue: PUSH RBP; MOV RBP, RSP; SUB RSP, 0x20
            TestHelper.SetStack(ref ctx, pStack, 256);
            ulong origRsp = ctx.Rsp;
            ctx.Rbp = 0xAAAA; // old RBP

            // Push RBP
            ctx.Rsp -= 8;
            *(ulong*)ctx.Rsp = ctx.Rbp;
            ulong framePtr = ctx.Rsp;
            ctx.Rbp = framePtr;
            ctx.Rsp -= 0x20; // local space

            // LEAVE should: RSP = RBP; POP RBP
            byte[] code = [0xC9];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xAAAAUL, ctx.Rbp); // restored old RBP
            Assert.Equal(origRsp, ctx.Rsp); // back to original
        }
    }

    // ========== Instruction length correctness ==========

    [Theory]
    [InlineData(new byte[] { 0x90 }, 1)]                          // NOP
    [InlineData(new byte[] { 0x50 }, 1)]                          // PUSH RAX
    [InlineData(new byte[] { 0xC3 }, 0)]                          // RET (changes RIP)
    [InlineData(new byte[] { 0x31, 0xC0 }, 2)]                    // XOR EAX, EAX
    [InlineData(new byte[] { 0x48, 0x31, 0xC0 }, 3)]              // XOR RAX, RAX
    [InlineData(new byte[] { 0x83, 0xC0, 0x01 }, 3)]              // ADD EAX, 1
    [InlineData(new byte[] { 0x48, 0xB8, 1, 0, 0, 0, 0, 0, 0, 0 }, 10)] // MOV RAX, imm64
    [InlineData(new byte[] { 0xB8, 1, 0, 0, 0 }, 5)]              // MOV EAX, imm32
    [InlineData(new byte[] { 0xB0, 0x42 }, 2)]                    // MOV AL, imm8
    public void InstructionLength_Correct(byte[] code, int expectedLen)
    {
        var ctx = TestHelper.CreateContext();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            TestHelper.SetStack(ref ctx, pStack, 256); // needed for PUSH/RET
            // For RET, push a return address
            if (code[0] == 0xC3)
            {
                ctx.Rsp -= 8;
                *(ulong*)ctx.Rsp = 0xDEAD;
            }
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code, out int len));
            if (expectedLen > 0) // 0 means RIP changes non-sequentially
                Assert.Equal(expectedLen, len);
        }
    }

    // ========== XCHG memory ==========

    [Fact]
    public void Xchg_Reg_Mem()
    {
        // XCHG EAX, [RCX] => 87 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            ctx.Rax = 0xAAAA;
            *(uint*)p = 0xBBBB;
            byte[] code = [0x87, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBBBBUL, ctx.Rax);
            Assert.Equal(0xAAAAU, *(uint*)p);
        }
    }

    // ========== NOT/NEG with memory ==========

    [Fact]
    public void Not_Mem8()
    {
        // NOT BYTE [RAX] => F6 10
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *p = 0x0F;
            byte[] code = [0xF6, 0x10]; // F6 /2
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xF0, *p);
        }
    }

    [Fact]
    public void Neg_Mem8()
    {
        // NEG BYTE [RAX] => F6 18
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            *p = 5;
            byte[] code = [0xF6, 0x18]; // F6 /3
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(unchecked((byte)-5), *p);
        }
    }

    // ========== MOVZX/MOVSX from memory ==========

    [Fact]
    public void Movzx_R32_Mem8()
    {
        // MOVZX EAX, BYTE [RCX] => 0F B6 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[] { 0x42 };
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            ctx.Rax = 0xFFFFFFFF;
            byte[] code = [0x0F, 0xB6, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42UL, ctx.Rax);
        }
    }

    [Fact]
    public void Movsx_R32_Mem8_Negative()
    {
        // MOVSX EAX, BYTE [RCX] => 0F BE 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[] { 0x80 };
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            byte[] code = [0x0F, 0xBE, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFFFFFF80UL, ctx.Rax); // sign-extended
        }
    }

    [Fact]
    public void Movzx_R32_Mem16()
    {
        // MOVZX EAX, WORD [RCX] => 0F B7 01
        var ctx = TestHelper.CreateContext();
        var mem = new byte[4];
        fixed (byte* p = mem)
        {
            *(ushort*)p = 0xBEEF;
            ctx.Rcx = (ulong)p;
            ctx.Rax = 0xFFFFFFFF;
            byte[] code = [0x0F, 0xB7, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBEEFUL, ctx.Rax);
        }
    }
}
