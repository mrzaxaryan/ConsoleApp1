using static ConsoleApp1.X64Emulator;

namespace ConsoleApp1.Handlers;

public static unsafe class Stack
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            case X64Opcodes.PUSH_RAX: return HandlePushRax(ctx, Log);
            case X64Opcodes.PUSH_RCX: return HandlePushRcx(ctx, Log);
            case X64Opcodes.PUSH_RDX: return HandlePushRdx(ctx, Log);
            case X64Opcodes.PUSH_RBX: return HandlePushRbx(ctx, Log);
            case X64Opcodes.PUSH_RSP: return HandlePushRsp(ctx, Log);
            case X64Opcodes.PUSH_RBP: return HandlePushRbp(ctx, Log);
            case X64Opcodes.PUSH_RSI: return HandlePushRsi(ctx, Log);
            case X64Opcodes.PUSH_RDI: return HandlePushRdi(ctx, Log);

            case X64Opcodes.POP_RAX:
            case X64Opcodes.POP_RCX:
            case X64Opcodes.POP_RDX:
            case X64Opcodes.POP_RBX:
            case X64Opcodes.POP_RSP:
            case X64Opcodes.POP_RBP:
            case X64Opcodes.POP_RSI:
            case X64Opcodes.POP_RDI:
                return HandlePopReg(ctx, opcode, Log);

            default:
                Log($"Unhandled stack opcode 0x{opcode:X2}", 8);
                return false;
        }
    }
    private static bool HandlePopReg(CONTEXT* ctx, byte opcode, Action<string, int> Log)
    {
        int reg = opcode - 0x58;            // 0..7 => RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI
        ulong val = *(ulong*)ctx->Rsp;      // read from stack
        ctx->Rsp += 8;                      // pop
        *(&ctx->Rax + reg) = val;         // write destination

        Log($"POP R{reg}", 1);
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRbp(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RBP", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rbp;
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRdi(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RDI", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rdi;
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRsi(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RSI", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rsi;
        ctx->Rip += 1;
        return true;
    }
    private static bool HandlePushRbx(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("PUSH RBX", 1);
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rbx;
        ctx->Rip += 1;
        return true;
    }
    public static bool HandlePushRax(CONTEXT* ctx, Action<string, int> Log)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rax;
        Log("PUSH RAX", 1);
        ctx->Rip += 1;
        return true;
    }

    public static bool HandlePushRcx(CONTEXT* ctx, Action<string, int> Log)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rcx;
        Log("PUSH RCX", 1);
        ctx->Rip += 1;
        return true;
    }

    public static bool HandlePushRdx(CONTEXT* ctx, Action<string, int> Log)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rdx;
        Log("PUSH RDX", 1);
        ctx->Rip += 1;
        return true;
    }

    public static bool HandlePushRsp(CONTEXT* ctx, Action<string, int> Log)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = ctx->Rsp + 8; // value of RSP *before* push
        Log("PUSH RSP", 1);
        ctx->Rip += 1;
        return true;
    }
}