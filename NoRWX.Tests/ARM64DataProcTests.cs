using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static NoRWX.EmulatorARM64;

namespace NoRWX.Tests;

/// <summary>
/// Tests for ARM64 data processing: MOVZ/MOVK/MOVN, ADD/SUB immediate and register,
/// AND/ORR/EOR, MADD/MSUB, UDIV/SDIV, shifts, CSEL/CSINC, ADRP, bitfield ops.
/// </summary>
public unsafe class ARM64DataProcTests
{
    private const uint NF = N_FLAG, ZF = Z_FLAG, CF = C_FLAG, VF = V_FLAG;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool Em(CONTEXT_ARM64* ctx, uint instr)
    {
        byte[] code = BitConverter.GetBytes(instr);
        fixed (byte* p = code)
        {
            ctx->Pc = (ulong)p;
            return Emulate(ctx, p);
        }
    }

    // ========== MOVZ/MOVK/MOVN ==========

    [Fact]
    public void MovZ_X0_LargeImm()
    {
        // MOVZ X0, #0xFFFF => D280FFFE0... need correct encoding
        // MOVZ X0, #0xFFFF => D29FFFE0
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xD29FFFE0); // MOVZ X0, #0xFFFF
        Assert.Equal(0xFFFFUL, ctx.X0);
    }

    [Fact]
    public void MovZ_X0_Shifted()
    {
        // MOVZ X0, #1, LSL#16 => D2A00020
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xD2A00020); // MOVZ X0, #1, LSL#16
        Assert.Equal(0x10000UL, ctx.X0);
    }

    [Fact]
    public void MovK_Preserves_Other_Bits()
    {
        // MOVZ X0, #0xAAAA => D2955540
        // MOVK X0, #0xBBBB, LSL#16 => F2B77760
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xD2955540); // MOVZ X0, #0xAAAA
        Assert.Equal(0xAAAAUL, ctx.X0);

        Em(&ctx, 0xF2B77760); // MOVK X0, #0xBBBB, LSL#16
        Assert.Equal(0xBBBBAAAAUL, ctx.X0);
    }

    [Fact]
    public void MovN_W0()
    {
        // MOVN W0, #0 => 12800000 → W0 = ~0 = 0xFFFFFFFF
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x12800000);
        Assert.Equal(0xFFFFFFFFUL, ctx.X0);
    }

    [Fact]
    public void MovN_X0_With_Shift()
    {
        // MOVN X0, #0, LSL#48 => 92E00000 → X0 = ~(0 << 48) = 0xFFFFFFFFFFFFFFFF
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x92E00000);
        Assert.Equal(0xFFFFFFFFFFFFFFFFUL, ctx.X0);
    }

    // ========== ADD/SUB immediate with flags ==========

    [Fact]
    public void Adds_Imm_Overflow()
    {
        // ADDS X0, X1, #1 where X1=MAX => F1000420 (wrong, let me compute)
        // ADDS X0, X1, #1 => B1000420
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = ulong.MaxValue;
        Em(&ctx, 0xB1000420); // ADDS X0, X1, #1
        Assert.Equal(0UL, ctx.X0);
        Assert.True((ctx.Cpsr & ZF) != 0); // zero
        Assert.True((ctx.Cpsr & CF) != 0); // carry
    }

    [Fact]
    public void Subs_Imm_Borrow()
    {
        // SUBS X0, X1, #1 where X1=0 => F1000420
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0;
        Em(&ctx, 0xF1000420); // SUBS X0, X1, #1
        Assert.Equal(ulong.MaxValue, ctx.X0);
        Assert.True((ctx.Cpsr & NF) != 0); // negative
        Assert.False((ctx.Cpsr & CF) != 0); // borrow (CF=0 on ARM64 = borrow)
    }

    [Fact]
    public void Add_Imm_Lsl12()
    {
        // ADD X0, X1, #1, LSL#12 => 91400420
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0;
        Em(&ctx, 0x91400420); // ADD X0, X1, #1, LSL#12
        Assert.Equal(0x1000UL, ctx.X0); // 1 << 12 = 4096
    }

    // ========== ADD/SUB register with shift ==========

    [Fact]
    public void Sub_Reg_Lsl2()
    {
        // SUB X0, X1, X2, LSL#2 => CB020820
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 100; ctx.X2 = 10; // 100 - (10<<2) = 100-40 = 60
        Em(&ctx, 0xCB020820);
        Assert.Equal(60UL, ctx.X0);
    }

    [Fact]
    public void Add_W_Reg()
    {
        // ADD W0, W1, W2 => 0B020020
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0xFFFFFFFF00000001; // W1 = 1
        ctx.X2 = 0xFFFFFFFF00000002; // W2 = 2
        Em(&ctx, 0x0B020020);
        Assert.Equal(3UL, ctx.X0); // 32-bit result, zero-extended
    }

    // ========== Logic register ==========

    [Fact]
    public void Ands_Reg()
    {
        // ANDS X0, X1, X2 => EA020020
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0xF0; ctx.X2 = 0x0F;
        Em(&ctx, 0xEA020020);
        Assert.Equal(0UL, ctx.X0);
        Assert.True((ctx.Cpsr & ZF) != 0);
    }

    [Fact]
    public void Orr_Reg_Shifted()
    {
        // ORR X0, XZR, X1, LSL#8 => AA012000
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0x42;
        Em(&ctx, 0xAA012000); // ORR X0, XZR, X1, LSL#8
        Assert.Equal(0x4200UL, ctx.X0);
    }

    [Fact]
    public void Bic_Reg()
    {
        // BIC X0, X1, X2 = AND X0, X1, ~X2 => 8A220020
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0xFF; ctx.X2 = 0x0F;
        Em(&ctx, 0x8A220020); // AND X0, X1, NOT X2
        Assert.Equal(0xF0UL, ctx.X0);
    }

    // ========== MADD/MSUB ==========

    [Fact]
    public void Madd_Accumulate()
    {
        // MADD X0, X1, X2, X3 = X3 + X1*X2 => 9B020C20
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 3; ctx.X2 = 4; ctx.X3 = 10; // 10 + 3*4 = 22
        Em(&ctx, 0x9B020C20);
        Assert.Equal(22UL, ctx.X0);
    }

    [Fact]
    public void Msub()
    {
        // MSUB X0, X1, X2, X3 = X3 - X1*X2 => 9B028C20
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 3; ctx.X2 = 4; ctx.X3 = 22; // 22 - 3*4 = 10
        Em(&ctx, 0x9B028C20);
        Assert.Equal(10UL, ctx.X0);
    }

    // ========== CSINC/CSINV/CSNEG ==========

    [Fact]
    public void Csinc_Taken()
    {
        // CSINC X0, X1, X2, EQ => 9A820420
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr = ZF; // EQ true
        ctx.X1 = 10; ctx.X2 = 20;
        Em(&ctx, 0x9A820420);
        Assert.Equal(10UL, ctx.X0); // condition true: X0=X1
    }

    [Fact]
    public void Csinc_NotTaken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr = 0; // EQ false
        ctx.X1 = 10; ctx.X2 = 20;
        Em(&ctx, 0x9A820420);
        Assert.Equal(21UL, ctx.X0); // condition false: X0=X2+1
    }

    [Fact]
    public void Cset_Via_Csinc()
    {
        // CSET X0, NE = CSINC X0, XZR, XZR, EQ => 9A9F07E0
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr = 0; // EQ=false → NE=true → X0=1
        Em(&ctx, 0x9A9F07E0);
        Assert.Equal(1UL, ctx.X0);
    }

    [Fact]
    public void Cset_False()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr = ZF; // EQ=true → NE=false → X0=0
        Em(&ctx, 0x9A9F07E0);
        Assert.Equal(0UL, ctx.X0);
    }

    // ========== Shifts via register ==========

    [Fact]
    public void Asr_Reg()
    {
        // ASRV X0, X1, X2 => 9AC22820
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = unchecked((ulong)(long)(-256)); // 0xFFFFFFFFFFFFFF00
        ctx.X2 = 4;
        Em(&ctx, 0x9AC22820);
        Assert.Equal(unchecked((ulong)(long)(-16)), ctx.X0); // -256 >> 4 = -16
    }

    [Fact]
    public void Ror_Reg()
    {
        // RORV X0, X1, X2 => 9AC22C20
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0x0F; ctx.X2 = 4;
        Em(&ctx, 0x9AC22C20);
        Assert.Equal(0xF000000000000000UL, ctx.X0); // 0x0F ROR 4
    }

    // ========== SUB SP variations ==========

    [Fact]
    public void Sub_Sp_Imm()
    {
        // SUB SP, SP, #0x40 => D1010000 + SP encoding...
        // SUB SP, SP, #0x40 => D10103FF
        var ctx = new CONTEXT_ARM64();
        ctx.Sp = 0x1000;
        Em(&ctx, 0xD10103FF); // SUB SP, SP, #0x40
        Assert.Equal(0x1000UL - 0x40, ctx.Sp);
    }

    [Fact]
    public void Add_Sp_Imm()
    {
        // ADD SP, SP, #0x40 => 910103FF
        var ctx = new CONTEXT_ARM64();
        ctx.Sp = 0x1000;
        Em(&ctx, 0x910103FF);
        Assert.Equal(0x1000UL + 0x40, ctx.Sp);
    }

    // ========== CMP (SUBS with XZR dest) ==========

    [Fact]
    public void Cmp_Equal()
    {
        // CMP X1, X2 = SUBS XZR, X1, X2 => EB02003F
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 42; ctx.X2 = 42;
        Em(&ctx, 0xEB02003F);
        Assert.True((ctx.Cpsr & ZF) != 0);
        Assert.True((ctx.Cpsr & CF) != 0); // no borrow
    }

    [Fact]
    public void Cmp_Less()
    {
        // CMP X1, X2 where X1 < X2 => SUBS XZR, X1, X2
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 10; ctx.X2 = 20;
        Em(&ctx, 0xEB02003F);
        Assert.False((ctx.Cpsr & ZF) != 0);
        Assert.False((ctx.Cpsr & CF) != 0); // borrow occurred
    }

    [Fact]
    public void Cmn_Imm()
    {
        // CMN X1, #0 = ADDS XZR, X1, #0 => B100003F
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0;
        Em(&ctx, 0xB100003F);
        Assert.True((ctx.Cpsr & ZF) != 0);
    }

    // ========== TST (ANDS with XZR dest) ==========

    [Fact]
    public void Tst_Reg()
    {
        // TST X1, X2 = ANDS XZR, X1, X2 => EA02003F
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0xF0; ctx.X2 = 0x0F;
        Em(&ctx, 0xEA02003F);
        Assert.True((ctx.Cpsr & ZF) != 0); // 0xF0 & 0x0F = 0
    }

    // ========== MOV (ORR alias) ==========

    [Fact]
    public void Mov_Reg_X0_X5()
    {
        // MOV X0, X5 = ORR X0, XZR, X5 => AA0503E0
        var ctx = new CONTEXT_ARM64();
        ctx.X5 = 0xCAFE;
        Em(&ctx, 0xAA0503E0);
        Assert.Equal(0xCAFEUL, ctx.X0);
    }

    // ========== MVN (ORN alias) ==========

    [Fact]
    public void Mvn_Reg()
    {
        // MVN X0, X1 = ORN X0, XZR, X1 => AA2103E0
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 0;
        Em(&ctx, 0xAA2103E0);
        Assert.Equal(0xFFFFFFFFFFFFFFFFUL, ctx.X0);
    }

    // ========== NEG (SUB from XZR) ==========

    [Fact]
    public void Neg_Reg()
    {
        // NEG X0, X1 = SUB X0, XZR, X1 => CB0103E0
        var ctx = new CONTEXT_ARM64();
        ctx.X1 = 42;
        Em(&ctx, 0xCB0103E0);
        Assert.Equal(unchecked((ulong)(long)(-42)), ctx.X0);
    }
}
