using System.Runtime.InteropServices;
using static NoRWX.EmulatorARM64;

namespace NoRWX.Tests;

public unsafe class EmulatorARM64Tests
{
    private const uint ZF = EmulatorARM64.Z_FLAG;

    private static bool Em(CONTEXT_ARM64* ctx, uint instr)
    {
        byte[] code = BitConverter.GetBytes(instr);
        fixed (byte* p = code)
        {
            ctx->Pc = (ulong)p;
            return Emulate(ctx, p);
        }
    }

    private static long EmDelta(CONTEXT_ARM64* ctx, uint instr)
    {
        byte[] code = BitConverter.GetBytes(instr);
        fixed (byte* p = code)
        {
            ulong oldPc = (ulong)p;
            ctx->Pc = oldPc;
            Emulate(ctx, p);
            return (long)(ctx->Pc - oldPc);
        }
    }

    // ========== MOV wide ==========

    [Fact]
    public void MovZ_X0_42()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xD2800540); // MOVZ X0, #42
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void MovZ_W1_0x1234()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x52824681); // MOVZ W1, #0x1234
        Assert.Equal(0x1234UL, ctx.X[1]);
    }

    [Fact]
    public void MovK_X0_HighHalf()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xD2800020); // MOVZ X0, #1
        Em(&ctx, 0xF2BFFFE0); // MOVK X0, #0xFFFF, LSL#16
        Assert.Equal(0xFFFF0001UL, ctx.X[0]);
    }

    [Fact]
    public void MovN_X0()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x92800000); // MOVN X0, #0 => ~0
        Assert.Equal(0xFFFFFFFFFFFFFFFFUL, ctx.X[0]);
    }

    // ========== ADD/SUB immediate ==========

    [Fact]
    public void Add_Imm_X0_X1_10()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 32;
        Em(&ctx, 0x91002820); // ADD X0, X1, #10
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Sub_Imm_X0_X1_5()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 47;
        Em(&ctx, 0xD1001420); // SUB X0, X1, #5
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Subs_Imm_SetsZF()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 42;
        Em(&ctx, 0xF100A820); // SUBS X0, X1, #42
        Assert.True((ctx.Cpsr & ZF) != 0);
    }

    // ========== Logical immediate ==========

    [Fact]
    public void Orr_Imm_X0_XZR_1()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0xB2400000); // ORR X0, XZR, #1
        Assert.Equal(1UL, ctx.X[0]);
    }

    // ========== Data Processing Register ==========

    [Fact]
    public void Add_Reg_X0_X1_X2()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 10; ctx.X[2] = 32;
        Em(&ctx, 0x8B020020); // ADD X0, X1, X2
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Sub_Reg_X0_X1_X2()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 100; ctx.X[2] = 58;
        Em(&ctx, 0xCB020020); // SUB X0, X1, X2
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Subs_Reg_SetsFlags()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 42; ctx.X[2] = 42;
        Em(&ctx, 0xEB020020); // SUBS X0, X1, X2
        Assert.Equal(0UL, ctx.X[0]);
        Assert.True((ctx.Cpsr & ZF) != 0);
    }

    [Fact]
    public void And_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 0xFF; ctx.X[2] = 0x0F;
        Em(&ctx, 0x8A020020); // AND X0, X1, X2
        Assert.Equal(0x0FUL, ctx.X[0]);
    }

    [Fact]
    public void Orr_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 0xF0; ctx.X[2] = 0x0F;
        Em(&ctx, 0xAA020020); // ORR X0, X1, X2
        Assert.Equal(0xFFUL, ctx.X[0]);
    }

    [Fact]
    public void Eor_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 0xFF; ctx.X[2] = 0xAA;
        Em(&ctx, 0xCA020020); // EOR X0, X1, X2
        Assert.Equal(0x55UL, ctx.X[0]);
    }

    [Fact]
    public void Mov_Via_Orr()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 0xDEAD;
        Em(&ctx, 0xAA0103E0); // MOV X0, X1 = ORR X0, XZR, X1
        Assert.Equal(0xDEADUL, ctx.X[0]);
    }

    [Fact]
    public void Add_Shifted_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 10; ctx.X[2] = 8;
        Em(&ctx, 0x8B020820); // ADD X0, X1, X2, LSL#2 => 10 + 32 = 42
        Assert.Equal(42UL, ctx.X[0]);
    }

    // ========== Multiply / Divide ==========

    [Fact]
    public void Mul_X0_X1_X2()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 6; ctx.X[2] = 7;
        Em(&ctx, 0x9B027C20); // MUL X0, X1, X2
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Udiv_X0()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 17; ctx.X[2] = 5;
        Em(&ctx, 0x9AC20820); // UDIV X0, X1, X2
        Assert.Equal(3UL, ctx.X[0]);
    }

    [Fact]
    public void Sdiv_X0()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = unchecked((ulong)-17); ctx.X[2] = 5;
        Em(&ctx, 0x9AC20C20); // SDIV X0, X1, X2
        Assert.Equal(unchecked((ulong)-3), ctx.X[0]);
    }

    // ========== Branches ==========

    [Fact]
    public void B_Forward()
    {
        var ctx = new CONTEXT_ARM64();
        Assert.Equal(8, EmDelta(&ctx, 0x14000002)); // B +8
    }

    [Fact]
    public void BL_SetsLR()
    {
        var ctx = new CONTEXT_ARM64();
        long delta = EmDelta(&ctx, 0x94000002); // BL +8
        Assert.Equal(8, delta);
        Assert.NotEqual(0UL, ctx.X[30]);
    }

    [Fact]
    public void Ret()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[30] = 0xDEAD;
        Em(&ctx, 0xD65F03C0); // RET
        Assert.Equal(0xDEADUL, ctx.Pc);
    }

    [Fact]
    public void Cbz_Taken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[0] = 0;
        Assert.Equal(8, EmDelta(&ctx, 0xB4000040)); // CBZ X0, +8
    }

    [Fact]
    public void Cbz_NotTaken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[0] = 1;
        Assert.Equal(4, EmDelta(&ctx, 0xB4000040)); // falls through
    }

    [Fact]
    public void Cbnz_Taken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[0] = 1;
        Assert.Equal(8, EmDelta(&ctx, 0xB5000040)); // CBNZ X0, +8
    }

    [Fact]
    public void B_Cond_EQ_Taken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr |= ZF;
        Assert.Equal(8, EmDelta(&ctx, 0x54000040)); // B.EQ +8
    }

    [Fact]
    public void B_Cond_NE_NotTaken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr |= ZF;
        Assert.Equal(4, EmDelta(&ctx, 0x54000041)); // B.NE +8 — not taken
    }

    // ========== Load/Store ==========

    [Fact]
    public void Str_Ldr_Roundtrip()
    {
        var ctx = new CONTEXT_ARM64();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.X[1] = (ulong)p;
            ctx.X[0] = 0xCAFEBABE;

            byte[] strCode = BitConverter.GetBytes(0xF9000020u);
            fixed (byte* pStr = strCode) { ctx.Pc = (ulong)pStr; Emulate(&ctx, pStr); }
            Assert.Equal(0xCAFEBABEUL, *(ulong*)p);

            ctx.X[2] = 0;
            byte[] ldrCode = BitConverter.GetBytes(0xF9400022u);
            fixed (byte* pLdr = ldrCode) { ctx.Pc = (ulong)pLdr; Emulate(&ctx, pLdr); }
            Assert.Equal(0xCAFEBABEUL, ctx.X[2]);
        }
    }

    // ========== Conditional select ==========

    [Fact]
    public void Csel_Taken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr |= ZF;
        ctx.X[1] = 0xAA; ctx.X[2] = 0xBB;
        Em(&ctx, 0x9A820020); // CSEL X0, X1, X2, EQ
        Assert.Equal(0xAAUL, ctx.X[0]);
    }

    [Fact]
    public void Csel_NotTaken()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.Cpsr &= ~ZF;
        ctx.X[1] = 0xAA; ctx.X[2] = 0xBB;
        Em(&ctx, 0x9A820020);
        Assert.Equal(0xBBUL, ctx.X[0]);
    }

    // ========== Shifts via register ==========

    [Fact]
    public void Lsl_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 1; ctx.X[2] = 4;
        Em(&ctx, 0x9AC22020); // LSLV X0, X1, X2
        Assert.Equal(16UL, ctx.X[0]);
    }

    [Fact]
    public void Lsr_Reg()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 256; ctx.X[2] = 4;
        Em(&ctx, 0x9AC22420); // LSRV X0, X1, X2
        Assert.Equal(16UL, ctx.X[0]);
    }

    // ========== 32-bit ops ==========

    [Fact]
    public void Add_W0_W1_W2()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 0xFFFFFFFF00000010;
        ctx.X[2] = 0xFFFFFFFF00000020;
        Em(&ctx, 0x0B020020); // ADD W0, W1, W2
        Assert.Equal(0x30UL, ctx.X[0]); // zero-extended
    }

    [Fact]
    public void MovZ_W0()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x52824680); // MOVZ W0, #0x1234
        Assert.Equal(0x1234UL, ctx.X[0]);
    }

    // ========== XZR ==========

    [Fact]
    public void Xzr_ReadsZero()
    {
        var ctx = new CONTEXT_ARM64();
        Em(&ctx, 0x910A83E0); // ADD X0, XZR, #42
        Assert.Equal(42UL, ctx.X[0]);
    }

    [Fact]
    public void Xzr_WritesDiscard()
    {
        var ctx = new CONTEXT_ARM64();
        ctx.X[1] = 42; ctx.X[2] = 42;
        Em(&ctx, 0xEB02003F); // SUBS XZR, X1, X2
        Assert.True((ctx.Cpsr & ZF) != 0);
    }

    // ========== NOP ==========

    [Fact]
    public void Nop()
    {
        var ctx = new CONTEXT_ARM64();
        Assert.Equal(4, EmDelta(&ctx, 0xD503201F));
    }
}
