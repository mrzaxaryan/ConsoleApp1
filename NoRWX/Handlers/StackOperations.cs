using static NoRWX.Emulator;

namespace NoRWX.Handlers;

public static unsafe class StackOperations
{
    public static bool Push(CONTEXT* ctx, ulong value, string name, Action<string, int> Log, int instrLen = 1)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = value;
        Log($"PUSH {name} (0x{value:X})", instrLen);
        ctx->Rip += (ulong)instrLen;
        return true;
    }

    public static bool Pop(CONTEXT* ctx, int reg, Action<string, int> Log, int instrLen = 1)
    {
        ulong val = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;
        *(&ctx->Rax + reg) = val;
        Log($"POP R{reg} => 0x{val:X}", instrLen);
        ctx->Rip += (ulong)instrLen;
        return true;
    }

    public static ulong ReadRm64(CONTEXT* ctx, byte* modrmPtr, out int len)
    {
        // TODO: integrate your ModRM decoding here
        len = 1;
        return *(ulong*)ctx->Rax;
    }

    public static void WriteRm64(CONTEXT* ctx, byte* modrmPtr, ulong value, out int len)
    {
        // TODO: integrate your ModRM decoding here
        len = 1;
        *(ulong*)ctx->Rax = value;
    }
}
