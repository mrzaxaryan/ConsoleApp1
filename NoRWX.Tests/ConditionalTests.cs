using NoRWX.Core;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

/// <summary>
/// Tests for all 16 condition codes across Jcc, SETcc, and CMOVcc.
/// </summary>
public unsafe class ConditionalTests
{
    // ========== All Jcc short conditions ==========

    [Theory]
    [InlineData(0x70, FlagsCalculator.OF, true)]         // JO: OF=1
    [InlineData(0x71, 0u, true)]                          // JNO: OF=0
    [InlineData(0x72, FlagsCalculator.CF, true)]          // JB: CF=1
    [InlineData(0x73, 0u, true)]                          // JAE: CF=0
    [InlineData(0x74, FlagsCalculator.ZF, true)]          // JE: ZF=1
    [InlineData(0x75, 0u, true)]                          // JNE: ZF=0
    [InlineData(0x76, FlagsCalculator.CF, true)]          // JBE: CF=1
    [InlineData(0x77, 0u, true)]                          // JA: CF=0,ZF=0
    [InlineData(0x78, FlagsCalculator.SF, true)]          // JS: SF=1
    [InlineData(0x79, 0u, true)]                          // JNS: SF=0
    [InlineData(0x7A, FlagsCalculator.PF, true)]          // JP: PF=1
    [InlineData(0x7B, 0u, true)]                          // JNP: PF=0
    [InlineData(0x7C, FlagsCalculator.SF, true)]          // JL: SF!=OF (SF=1,OF=0)
    [InlineData(0x7D, 0u, true)]                          // JGE: SF==OF (both 0)
    [InlineData(0x7E, FlagsCalculator.ZF, true)]          // JLE: ZF=1
    [InlineData(0x7F, 0u, true)]                          // JG: ZF=0,SF==OF
    public void Jcc_Short_Taken(byte opcode, uint flagsToSet, bool expectTaken)
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202 | flagsToSet; // base flags + condition flags
        byte[] code = [opcode, 0x10]; // Jcc +16

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            ulong fallthrough = (ulong)p + 2;
            ulong target = (ulong)p + 2 + 0x10;
            Assert.Equal(expectTaken ? target : fallthrough, ctx.Rip);
        }
    }

    [Theory]
    [InlineData(0x70, 0u)]             // JO not taken when OF=0
    [InlineData(0x71, FlagsCalculator.OF)]  // JNO not taken when OF=1
    [InlineData(0x72, 0u)]             // JB not taken when CF=0
    [InlineData(0x73, FlagsCalculator.CF)]  // JAE not taken when CF=1
    [InlineData(0x74, 0u)]             // JE not taken when ZF=0
    [InlineData(0x75, FlagsCalculator.ZF)]  // JNE not taken when ZF=1
    [InlineData(0x77, FlagsCalculator.CF)]  // JA not taken when CF=1
    [InlineData(0x78, 0u)]             // JS not taken when SF=0
    [InlineData(0x79, FlagsCalculator.SF)]  // JNS not taken when SF=1
    [InlineData(0x7A, 0u)]             // JP not taken when PF=0
    [InlineData(0x7B, FlagsCalculator.PF)]  // JNP not taken when PF=1
    public void Jcc_Short_NotTaken(byte opcode, uint flagsToSet)
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202 | flagsToSet;
        byte[] code = [opcode, 0x10];

        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 2, ctx.Rip); // falls through
        }
    }

    // ========== Jcc near (0F 8x) ==========

    [Fact]
    public void Je_Near_Taken_LargeOffset()
    {
        // JE near +0x1000 => 0F 84 00 10 00 00
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x0F, 0x84, 0x00, 0x10, 0x00, 0x00];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 6 + 0x1000, ctx.Rip);
        }
    }

    [Fact]
    public void Jg_Near_Taken()
    {
        // JG near +0x100 => 0F 8F 00 01 00 00 (ZF=0, SF==OF)
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202; // ZF=0, SF=0, OF=0
        byte[] code = [0x0F, 0x8F, 0x00, 0x01, 0x00, 0x00];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p + 6 + 0x100, ctx.Rip);
        }
    }

    [Fact]
    public void Jl_Near_Backward()
    {
        // JL near -6 => 0F 8C FA FF FF FF (jumps to itself)
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202 | FlagsCalculator.SF; // SF=1, OF=0 => SF!=OF => taken
        byte[] code = [0x0F, 0x8C, 0xFA, 0xFF, 0xFF, 0xFF];
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        fixed (byte* p = code)
        {
            Assert.Equal((ulong)p, ctx.Rip); // jumps back to start
        }
    }

    // ========== All SETcc conditions ==========

    [Theory]
    [InlineData(0x90, FlagsCalculator.OF, 1)]     // SETO
    [InlineData(0x90, 0u, 0)]                      // SETO (not set)
    [InlineData(0x91, 0u, 1)]                      // SETNO
    [InlineData(0x91, FlagsCalculator.OF, 0)]      // SETNO (not set)
    [InlineData(0x92, FlagsCalculator.CF, 1)]      // SETB
    [InlineData(0x93, 0u, 1)]                      // SETAE
    [InlineData(0x94, FlagsCalculator.ZF, 1)]      // SETE
    [InlineData(0x95, 0u, 1)]                      // SETNE
    [InlineData(0x96, FlagsCalculator.CF, 1)]      // SETBE
    [InlineData(0x97, 0u, 1)]                      // SETA
    [InlineData(0x98, FlagsCalculator.SF, 1)]      // SETS
    [InlineData(0x99, 0u, 1)]                      // SETNS
    [InlineData(0x9A, FlagsCalculator.PF, 1)]      // SETP
    [InlineData(0x9B, 0u, 1)]                      // SETNP
    [InlineData(0x9C, FlagsCalculator.SF, 1)]      // SETL (SF!=OF)
    [InlineData(0x9D, 0u, 1)]                      // SETGE (SF==OF)
    [InlineData(0x9E, FlagsCalculator.ZF, 1)]      // SETLE (ZF=1)
    [InlineData(0x9F, 0u, 1)]                      // SETG (ZF=0,SF==OF)
    public void Setcc_AllConditions(byte cc, uint flagsToSet, byte expected)
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202 | flagsToSet;
        ctx.Rax = 0xFF; // AL will be overwritten
        byte[] code = [0x0F, cc, 0xC0]; // SETcc AL (mod=11, rm=0)
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(expected, (byte)(ctx.Rax & 0xFF));
    }

    // ========== All CMOVcc conditions ==========

    [Theory]
    [InlineData(0x44, FlagsCalculator.ZF, true)]   // CMOVE
    [InlineData(0x44, 0u, false)]                   // CMOVE not taken
    [InlineData(0x45, 0u, true)]                    // CMOVNE
    [InlineData(0x45, FlagsCalculator.ZF, false)]  // CMOVNE not taken
    [InlineData(0x42, FlagsCalculator.CF, true)]   // CMOVB
    [InlineData(0x43, 0u, true)]                    // CMOVAE
    [InlineData(0x4C, FlagsCalculator.SF, true)]   // CMOVL (SF!=OF)
    [InlineData(0x4D, 0u, true)]                    // CMOVGE (SF==OF)
    [InlineData(0x4F, 0u, true)]                    // CMOVG (ZF=0,SF==OF)
    public void Cmovcc_Conditions(byte cc, uint flagsToSet, bool expectMoved)
    {
        var ctx = TestHelper.CreateContext();
        ctx.EFlags = 0x202 | flagsToSet;
        ctx.Rax = 0;
        ctx.Rcx = 0x42;
        byte[] code = [0x0F, cc, 0xC1]; // CMOVcc EAX, ECX
        Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
        Assert.Equal(expectMoved ? 0x42UL : 0UL, ctx.Rax);
    }

    // ========== SETcc to memory ==========

    [Fact]
    public void Sete_Memory()
    {
        // SETE [RAX] => 0F 94 00
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rax = (ulong)p;
            byte[] code = [0x0F, 0x94, 0x00]; // mod=00, rm=0(RAX)
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(1, *p);
        }
    }

    // ========== CMOVcc with memory source ==========

    [Fact]
    public void Cmove_Reg_Mem()
    {
        // CMOVE EAX, [RCX] => 0F 44 01
        var ctx = TestHelper.CreateContext();
        ctx.EFlags |= FlagsCalculator.ZF;
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Rcx = (ulong)p;
            *(uint*)p = 0xBEEF;
            ctx.Rax = 0;
            byte[] code = [0x0F, 0x44, 0x01];
            Assert.True(TestHelper.EmulateInstruction(ref ctx, code));
            Assert.Equal(0xBEEFUL, ctx.Rax);
        }
    }
}
