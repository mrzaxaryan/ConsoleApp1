using NoRWX.Core;
using static NoRWX.EmulatorX64;

namespace NoRWX.Tests;

/// <summary>
/// Tests for instructions with memory operands (mod != 11).
/// These test the address resolution path that was previously broken
/// in write-back handlers.
/// </summary>
public unsafe class MemoryOperandTests
{
    // === MOV [reg+disp8], reg (the exact pattern that was broken) ===

    [Fact]
    public void Mov_MemRbpDisp8_Rax()
    {
        // MOV [RBP-8], RAX  =>  48 89 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            ctx.Rax = 0xDEADBEEFCAFEBABE;
            byte[] code = [0x48, 0x89, 0x45, 0xF8]; // REX.W MOV [RBP-8], RAX

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));

            // Verify the value was written to [RBP-8] = pMem+120
            Assert.Equal(0xDEADBEEFCAFEBABEUL, *(ulong*)(pMem + 120));
        }
    }

    [Fact]
    public void Mov_MemRbpDisp8_Rcx()
    {
        // MOV [RBP-0x10], RCX  =>  48 89 4D F0
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            ctx.Rcx = 0x1234567890ABCDEF;
            byte[] code = [0x48, 0x89, 0x4D, 0xF0];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x1234567890ABCDEFUL, *(ulong*)(pMem + 112));
        }
    }

    [Fact]
    public void Mov_Rax_MemRbpDisp8()
    {
        // MOV RAX, [RBP-8]  =>  48 8B 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ulong*)(pMem + 120) = 0x42424242;
            byte[] code = [0x48, 0x8B, 0x45, 0xF8];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42424242UL, ctx.Rax);
        }
    }

    [Fact]
    public void Mov_StoreAndLoad_Roundtrip()
    {
        // Store RAX to [RBP-8], then load it back into RCX
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            ctx.Rax = 0xFEEDFACE;

            // MOV [RBP-8], RAX  =>  48 89 45 F8
            byte[] store = [0x48, 0x89, 0x45, 0xF8];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, store));

            // MOV RCX, [RBP-8]  =>  48 8B 4D F8
            byte[] load = [0x48, 0x8B, 0x4D, 0xF8];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, load));

            Assert.Equal(0xFEEDFACEUL, ctx.Rcx);
        }
    }

    // === MOV 32-bit memory operands ===

    [Fact]
    public void Mov_Mem32_R32()
    {
        // MOV [RAX], ECX  =>  89 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            ctx.Rcx = 0xAABBCCDD;
            byte[] code = [0x89, 0x08]; // mod=00, reg=1(ECX), rm=0(RAX)

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xAABBCCDDU, *(uint*)pMem);
        }
    }

    [Fact]
    public void Mov_R32_Mem32()
    {
        // MOV ECX, [RAX]  =>  8B 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *(uint*)pMem = 0x11223344;
            byte[] code = [0x8B, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x11223344UL, ctx.Rcx);
        }
    }

    // === ADD to memory ===

    [Fact]
    public void Add_Mem64_Reg64()
    {
        // ADD [RBP-8], RAX  =>  48 01 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ulong*)(pMem + 120) = 100;
            ctx.Rax = 50;
            byte[] code = [0x48, 0x01, 0x45, 0xF8];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(150UL, *(ulong*)(pMem + 120));
        }
    }

    // === SUB to memory ===

    [Fact]
    public void Sub_Mem64_Reg64()
    {
        // SUB [RBP-8], RAX  =>  48 29 45 F8
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ulong*)(pMem + 120) = 100;
            ctx.Rax = 30;
            byte[] code = [0x48, 0x29, 0x45, 0xF8];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(70UL, *(ulong*)(pMem + 120));
        }
    }

    // === Group1 with memory ===

    [Fact]
    public void Group1_Add_Mem64_Imm8()
    {
        // ADD QWORD [RBP-8], 0x10  =>  48 83 45 F8 10
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ulong*)(pMem + 120) = 0x100;
            byte[] code = [0x48, 0x83, 0x45, 0xF8, 0x10];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x110UL, *(ulong*)(pMem + 120));
        }
    }

    [Fact]
    public void Group1_Cmp_Mem64_Imm8()
    {
        // CMP QWORD [RBP-8], 0  =>  48 83 7D F8 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ulong*)(pMem + 120) = 0;
            byte[] code = [0x48, 0x83, 0x7D, 0xF8, 0x00];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // === XOR to memory ===

    [Fact]
    public void Xor_Mem32_Reg32()
    {
        // XOR [RAX], ECX  =>  31 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *(uint*)pMem = 0xFF00FF00;
            ctx.Rcx = 0xFFFFFFFF;
            byte[] code = [0x31, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x00FF00FFU, *(uint*)pMem);
        }
    }

    // === MOV r/m8 with memory ===

    [Fact]
    public void Mov_Mem8_R8()
    {
        // MOV [RAX], CL  =>  88 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            ctx.Rcx = 0x42;
            byte[] code = [0x88, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x42, *pMem);
        }
    }

    // === CMP with memory ===

    [Fact]
    public void Cmp_Mem32_Reg32()
    {
        // CMP [RAX], ECX  =>  39 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *(uint*)pMem = 42;
            ctx.Rcx = 42;
            byte[] code = [0x39, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
            Assert.Equal(42U, *(uint*)pMem); // CMP doesn't modify destination
        }
    }

    // === TEST with memory ===

    [Fact]
    public void Test_Mem32_Reg32()
    {
        // TEST [RAX], ECX  =>  85 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *(uint*)pMem = 0xF0;
            ctx.Rcx = 0x0F;
            byte[] code = [0x85, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF)); // 0xF0 & 0x0F = 0
        }
    }

    // === LEA with SIB ===

    [Fact]
    public void Lea_R64_SIB()
    {
        // LEA RAX, [RCX+RDX*4]  =>  48 8D 04 91
        var ctx = TestHelper.CreateContext();
        ctx.Rcx = 0x1000;
        ctx.Rdx = 0x10;
        byte[] code = [0x48, 0x8D, 0x04, 0x91]; // mod=00, reg=0, rm=4(SIB), SIB: scale=2, index=2(RDX), base=1(RCX)

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(0x1040UL, ctx.Rax); // 0x1000 + 0x10*4
    }

    // === INC/DEC memory ===

    [Fact]
    public void Inc_Mem8()
    {
        // INC BYTE [RAX]  =>  FE 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *pMem = 0xFE;
            byte[] code = [0xFE, 0x00];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xFF, *pMem);
        }
    }

    [Fact]
    public void Dec_Mem8()
    {
        // DEC BYTE [RAX]  =>  FE 08
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *pMem = 1;
            byte[] code = [0xFE, 0x08];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0, *pMem);
            Assert.True(TestHelper.IsFlagSet(ctx, FlagsCalculator.ZF));
        }
    }

    // === MOV r/m, imm with memory ===

    [Fact]
    public void Mov_Mem32_Imm32()
    {
        // MOV DWORD [RAX], 0x12345678  =>  C7 00 78 56 34 12
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            byte[] code = [0xC7, 0x00, 0x78, 0x56, 0x34, 0x12];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0x12345678U, *(uint*)pMem);
        }
    }

    [Fact]
    public void Mov_Mem16_Imm16()
    {
        // MOV WORD [RBP-0x28], 0  =>  66 C7 45 D8 00 00
        var ctx = TestHelper.CreateContext();
        var mem = new byte[256];
        fixed (byte* pMem = mem)
        {
            ctx.Rbp = (ulong)(pMem + 128);
            *(ushort*)(pMem + 88) = 0xFFFF; // pre-fill
            byte[] code = [0x66, 0xC7, 0x45, 0xD8, 0x00, 0x00];

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal((ushort)0, *(ushort*)(pMem + 88));
        }
    }

    // === Shift with memory ===

    [Fact]
    public void Shl_Mem32_Imm8()
    {
        // SHL DWORD [RAX], 4  =>  C1 20 04
        var ctx = TestHelper.CreateContext();
        var mem = new byte[64];
        fixed (byte* pMem = mem)
        {
            ctx.Rax = (ulong)pMem;
            *(uint*)pMem = 1;
            byte[] code = [0xC1, 0x20, 0x04]; // mod=00, /4=SHL, rm=0(RAX)

            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(16U, *(uint*)pMem);
        }
    }
}
