using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1.Handlers;

public static unsafe class Miscellaneous
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            case X64Opcodes.NOP: return HandleNop(ctx, Log);
            case X64Opcodes.CMP_AL_IMM8: return HandleCmpAlImm8(ctx, address, Log);
            default:
                return false;
        }
    }
    private static bool HandleNop(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("NOP", 1);
        ctx->Rip += 1;
        return true;
    }
    private static bool HandleCmpAlImm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte imm8 = *(address + 1);
        byte al = (byte)(ctx->Rax & 0xFF);
        byte result = (byte)(al - imm8);

        bool cf = al < imm8;
        bool pf = ((0x6996 >> (result & 0xFF)) & 1) != 0;
        bool af = ((al ^ imm8 ^ result) & 0x10) != 0;
        bool zf = (result == 0);
        bool sf = (result & 0x80) != 0;
        bool of = ((al ^ imm8) & (al ^ result) & 0x80) != 0;

        ctx->EFlags = (uint)(
            (ctx->EFlags & ~0x8D5) |
            (cf ? 0x1u : 0u) |
            (pf ? 0x4u : 0u) |
            (af ? 0x10u : 0u) |
            (zf ? 0x40u : 0u) |
            (sf ? 0x80u : 0u) |
            (of ? 0x800u : 0u)
        );

        Log($"CMP AL, 0x{imm8:X2} => AL=0x{al:X2} result=0x{result:X2}", 2);
        ctx->Rip += 2;
        return true;
    }

}