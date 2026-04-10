using NoRWX.Core;
using static NoRWX.EmulatorX86;

namespace NoRWX.Tests;

/// <summary>
/// Tests for the i386 (32-bit) emulator.
/// </summary>
public unsafe class EmulatorX86Tests
{
    private static bool Em32(ref CONTEXT32 ctx, byte[] code)
    {
        fixed (byte* p = code)
        fixed (CONTEXT32* pCtx = &ctx)
        {
            pCtx->Eip = (uint)(ulong)p;
            return Emulate(pCtx, p);
        }
    }

    private static CONTEXT32 NewCtx() => new() { EFlags = 0x202 };

    // On 64-bit hosts, heap addresses exceed 32 bits.
    // Skip tests that need 32-bit addressable memory.
    private static bool CanUse32BitAddresses()
    {
        var test = new byte[1];
        fixed (byte* p = test)
            return (ulong)p <= uint.MaxValue;
    }

    // === INC/DEC r32 (0x40-0x4F — the key i386 difference!) ===

    [Fact]
    public void Inc_Eax()
    {
        var ctx = NewCtx();
        ctx.Eax = 41;
        byte[] code = [0x40]; // INC EAX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(42u, ctx.Eax);
    }

    [Fact]
    public void Inc_Ecx()
    {
        var ctx = NewCtx();
        ctx.Ecx = 0xFFFFFFFF;
        byte[] code = [0x41]; // INC ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0u, ctx.Ecx);
        Assert.True((ctx.EFlags & FlagsCalculator.ZF) != 0);
    }

    [Fact]
    public void Dec_Eax()
    {
        var ctx = NewCtx();
        ctx.Eax = 1;
        byte[] code = [0x48]; // DEC EAX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0u, ctx.Eax);
        Assert.True((ctx.EFlags & FlagsCalculator.ZF) != 0);
    }

    [Fact]
    public void Dec_Edi()
    {
        var ctx = NewCtx();
        ctx.Edi = 100;
        byte[] code = [0x4F]; // DEC EDI
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(99u, ctx.Edi);
    }

    // === PUSH/POP ===

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Push_Pop_Eax()
    {
        var ctx = NewCtx();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Esp = (uint)(ulong)(pStack + 256);
            ctx.Eax = 0xDEADBEEF;
            byte[] push = [0x50]; // PUSH EAX
            Assert.True(Em32(ref ctx, push));
            Assert.Equal(0xDEADBEEFu, *(uint*)ctx.Esp);
            Assert.Equal((uint)(ulong)(pStack + 252), ctx.Esp); // 4 bytes, not 8!

            ctx.Eax = 0;
            byte[] pop = [0x58]; // POP EAX
            Assert.True(Em32(ref ctx, pop));
            Assert.Equal(0xDEADBEEFu, ctx.Eax);
            Assert.Equal((uint)(ulong)(pStack + 256), ctx.Esp);
        }
    }

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Push_Imm8()
    {
        var ctx = NewCtx();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Esp = (uint)(ulong)(pStack + 256);
            byte[] code = [0x6A, 0xFF]; // PUSH -1 (sign-extended to 32)
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(0xFFFFFFFFu, *(uint*)ctx.Esp);
        }
    }

    // === MOV ===

    [Fact]
    public void Mov_Eax_Imm32()
    {
        var ctx = NewCtx();
        byte[] code = [0xB8, 0x78, 0x56, 0x34, 0x12]; // MOV EAX, 0x12345678
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x12345678u, ctx.Eax);
    }

    [Fact]
    public void Mov_R32_R32()
    {
        var ctx = NewCtx();
        ctx.Eax = 0x42;
        byte[] code = [0x89, 0xC1]; // MOV ECX, EAX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x42u, ctx.Ecx);
    }

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Mov_Mem32_R32()
    {
        var ctx = NewCtx();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Eax = (uint)(ulong)p;
            ctx.Ecx = 0xBEEF;
            byte[] code = [0x89, 0x08]; // MOV [EAX], ECX
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(0xBEEFu, *(uint*)p);
        }
    }

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Mov_R32_Mem32_Disp8()
    {
        var ctx = NewCtx();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Ebp = (uint)(ulong)(p + 128);
            *(uint*)(p + 120) = 0xCAFE;
            byte[] code = [0x8B, 0x45, 0xF8]; // MOV EAX, [EBP-8]
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(0xCAFEu, ctx.Eax);
        }
    }

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Mov_StoreLoad_Roundtrip()
    {
        var ctx = NewCtx();
        var mem = new byte[256];
        fixed (byte* p = mem)
        {
            ctx.Ebp = (uint)(ulong)(p + 128);
            ctx.Eax = 0xFEED;
            byte[] store = [0x89, 0x45, 0xF8]; // MOV [EBP-8], EAX
            Assert.True(Em32(ref ctx, store));

            byte[] load = [0x8B, 0x4D, 0xF8]; // MOV ECX, [EBP-8]
            Assert.True(Em32(ref ctx, load));
            Assert.Equal(0xFEEDu, ctx.Ecx);
        }
    }

    // === ADD/SUB/CMP ===

    [Fact]
    public void Add_R32_R32()
    {
        var ctx = NewCtx();
        ctx.Eax = 10; ctx.Ecx = 20;
        byte[] code = [0x01, 0xC8]; // ADD EAX, ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(30u, ctx.Eax);
    }

    [Fact]
    public void Sub_R32_R32()
    {
        var ctx = NewCtx();
        ctx.Eax = 100; ctx.Ecx = 30;
        byte[] code = [0x29, 0xC8]; // SUB EAX, ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(70u, ctx.Eax);
    }

    [Fact]
    public void Cmp_Equal_SetsZF()
    {
        var ctx = NewCtx();
        ctx.Eax = 42; ctx.Ecx = 42;
        byte[] code = [0x39, 0xC8]; // CMP EAX, ECX
        Assert.True(Em32(ref ctx, code));
        Assert.True((ctx.EFlags & FlagsCalculator.ZF) != 0);
    }

    [Fact]
    public void Group1_Add_Imm8()
    {
        var ctx = NewCtx();
        ctx.Ecx = 0x100;
        byte[] code = [0x83, 0xC1, 0x10]; // ADD ECX, 0x10
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x110u, ctx.Ecx);
    }

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Group1_Sub_Mem_Imm8()
    {
        var ctx = NewCtx();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            ctx.Eax = (uint)(ulong)p;
            *(uint*)p = 100;
            byte[] code = [0x83, 0x28, 0x0A]; // SUB DWORD [EAX], 10
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(90u, *(uint*)p);
        }
    }

    // === XOR self-clear ===

    [Fact]
    public void Xor_Self()
    {
        var ctx = NewCtx();
        ctx.Eax = 0xDEADBEEF;
        byte[] code = [0x31, 0xC0]; // XOR EAX, EAX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0u, ctx.Eax);
        Assert.True((ctx.EFlags & FlagsCalculator.ZF) != 0);
    }

    // === LEA ===

    [Fact]
    public void Lea_RegDisp8()
    {
        var ctx = NewCtx();
        ctx.Eax = 0x1000;
        byte[] code = [0x8D, 0x48, 0x10]; // LEA ECX, [EAX+0x10]
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x1010u, ctx.Ecx);
    }

    // === CALL/RET ===

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Call_Ret()
    {
        var ctx = NewCtx();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Esp = (uint)(ulong)(pStack + 256);
            byte[] call = [0xE8, 0x00, 0x00, 0x00, 0x00]; // CALL +0
            Assert.True(Em32(ref ctx, call));
            Assert.Equal((uint)(ulong)(pStack + 252), ctx.Esp); // pushed 4-byte return addr

            byte[] ret = [0xC3]; // RET
            Assert.True(Em32(ref ctx, ret));
            Assert.Equal((uint)(ulong)(pStack + 256), ctx.Esp);
        }
    }

    // === Jcc ===

    [Fact]
    public void Je_Taken()
    {
        var ctx = NewCtx();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x74, 0x05]; // JE +5
        Assert.True(Em32(ref ctx, code));
        fixed (byte* p = code)
            Assert.Equal((uint)(ulong)p + 7, ctx.Eip);
    }

    [Fact]
    public void Jne_Near()
    {
        var ctx = NewCtx();
        ctx.EFlags &= ~FlagsCalculator.ZF;
        byte[] code = [0x0F, 0x85, 0x00, 0x01, 0x00, 0x00]; // JNE +0x100
        Assert.True(Em32(ref ctx, code));
        fixed (byte* p = code)
            Assert.Equal((uint)(ulong)p + 6 + 0x100, ctx.Eip);
    }

    // === MOVZX/MOVSX ===

    [Fact]
    public void Movzx_R32_R8()
    {
        var ctx = NewCtx();
        ctx.Eax = 0xFF42;
        byte[] code = [0x0F, 0xB6, 0xC8]; // MOVZX ECX, AL
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x42u, ctx.Ecx);
    }

    [Fact]
    public void Movsx_R32_R8_Negative()
    {
        var ctx = NewCtx();
        ctx.Eax = 0x80;
        byte[] code = [0x0F, 0xBE, 0xC8]; // MOVSX ECX, AL
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0xFFFFFF80u, ctx.Ecx);
    }

    // === SETcc ===

    [Fact]
    public void Sete_32()
    {
        var ctx = NewCtx();
        ctx.EFlags |= FlagsCalculator.ZF;
        byte[] code = [0x0F, 0x94, 0xC0]; // SETE AL
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(1u, ctx.Eax & 0xFF);
    }

    // === CMOVcc ===

    [Fact]
    public void Cmove_32()
    {
        var ctx = NewCtx();
        ctx.EFlags |= FlagsCalculator.ZF;
        ctx.Ecx = 0x42; ctx.Eax = 0;
        byte[] code = [0x0F, 0x44, 0xC1]; // CMOVE EAX, ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x42u, ctx.Eax);
    }

    // === Shift ===

    [Fact]
    public void Shl_R32_Imm8()
    {
        var ctx = NewCtx();
        ctx.Ecx = 1;
        byte[] code = [0xC1, 0xE1, 0x04]; // SHL ECX, 4
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x10u, ctx.Ecx);
    }

    // === NOT/NEG ===

    [Fact]
    public void Not_R32()
    {
        var ctx = NewCtx();
        ctx.Ecx = 0x0000FFFF;
        byte[] code = [0xF7, 0xD1]; // NOT ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0xFFFF0000u, ctx.Ecx);
    }

    [Fact]
    public void Neg_R32()
    {
        var ctx = NewCtx();
        ctx.Ecx = 10;
        byte[] code = [0xF7, 0xD9]; // NEG ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(unchecked((uint)-10), ctx.Ecx);
    }

    // === MUL/DIV ===

    [Fact]
    public void Mul_R32()
    {
        var ctx = NewCtx();
        ctx.Eax = 100; ctx.Ecx = 200;
        byte[] code = [0xF7, 0xE1]; // MUL ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(20000u, ctx.Eax);
        Assert.Equal(0u, ctx.Edx);
    }

    [Fact]
    public void Div_R32()
    {
        var ctx = NewCtx();
        ctx.Eax = 17; ctx.Edx = 0; ctx.Ecx = 5;
        byte[] code = [0xF7, 0xF1]; // DIV ECX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(3u, ctx.Eax);
        Assert.Equal(2u, ctx.Edx);
    }

    // === BSWAP ===

    [Fact]
    public void Bswap_Eax()
    {
        var ctx = NewCtx();
        ctx.Eax = 0x01020304;
        byte[] code = [0x0F, 0xC8]; // BSWAP EAX
        Assert.True(Em32(ref ctx, code));
        Assert.Equal(0x04030201u, ctx.Eax);
    }

    // === String op ===

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Rep_Stosb_32()
    {
        var ctx = NewCtx();
        ctx.EFlags &= ~FlagsCalculator.DF;
        var buf = new byte[16];
        fixed (byte* p = buf)
        {
            ctx.Edi = (uint)(ulong)p;
            ctx.Eax = 0xAA;
            ctx.Ecx = 4;
            byte[] code = [0xAA]; // STOSB (with rep handled separately)
            // Test single STOSB
            Assert.True(Em32(ref ctx, code));
            Assert.Equal((byte)0xAA, buf[0]);
        }
    }

    // === LEAVE ===

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Leave_32()
    {
        var ctx = NewCtx();
        var stack = new byte[256];
        fixed (byte* pStack = stack)
        {
            ctx.Ebp = (uint)(ulong)(pStack + 200);
            *(uint*)(pStack + 200) = 0xBEEF;
            byte[] code = [0xC9]; // LEAVE
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(0xBEEFu, ctx.Ebp);
            Assert.Equal((uint)(ulong)(pStack + 204), ctx.Esp);
        }
    }

    // === disp32 absolute (NOT RIP-relative in 32-bit!) ===

    [Fact(Skip = "Requires 32-bit addressable memory")]
    public void Mov_Disp32_Absolute()
    {
        var ctx = NewCtx();
        var mem = new byte[64];
        fixed (byte* p = mem)
        {
            *(uint*)p = 0x42424242;
            uint addr = (uint)(ulong)p;
            // MOV EAX, [disp32] => 8B 05 <addr32>
            byte[] code = [0x8B, 0x05, (byte)addr, (byte)(addr >> 8), (byte)(addr >> 16), (byte)(addr >> 24)];
            Assert.True(Em32(ref ctx, code));
            Assert.Equal(0x42424242u, ctx.Eax);
        }
    }
}
