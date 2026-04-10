using System.Runtime.InteropServices;
using static NoRWX.Emulator;

namespace NoRWX.Tests;

/// <summary>
/// Helper for creating CONTEXT structs and emulating instructions in tests.
/// </summary>
public static unsafe class TestHelper
{
    /// <summary>Create a zeroed CONTEXT with RIP set to the buffer address.</summary>
    public static CONTEXT CreateContext()
    {
        var ctx = new CONTEXT();
        ctx.EFlags = 0x202; // default: IF=1
        return ctx;
    }

    /// <summary>
    /// Emulate a single instruction from the given byte array.
    /// Returns true if emulation succeeded.
    /// </summary>
    public static bool EmulateInstruction(ref CONTEXT ctx, byte[] code)
    {
        fixed (byte* pCode = code)
        {
            ctx.Rip = (ulong)pCode;

            var exPtr = new EXCEPTION_POINTERS();
            // We need to pin ctx and set the ContextRecord
            fixed (CONTEXT* pCtx = &ctx)
            {
                exPtr.ContextRecord = (nint)pCtx;
                return Emulate(ref exPtr, pCode);
            }
        }
    }

    /// <summary>
    /// Emulate a single instruction, returning the instruction length consumed.
    /// </summary>
    public static bool EmulateInstruction(ref CONTEXT ctx, byte[] code, out int instrLen)
    {
        fixed (byte* pCode = code)
        {
            ulong startRip = (ulong)pCode;
            ctx.Rip = startRip;

            var exPtr = new EXCEPTION_POINTERS();
            fixed (CONTEXT* pCtx = &ctx)
            {
                exPtr.ContextRecord = (nint)pCtx;
                bool result = Emulate(ref exPtr, pCode);
                instrLen = (int)(ctx.Rip - startRip);
                return result;
            }
        }
    }

    /// <summary>Allocate a stack for the context (pinned).</summary>
    public static byte[] AllocateStack(ref CONTEXT ctx, int size = 4096)
    {
        var stack = new byte[size];
        // Pin is handled by caller. For simplicity, set RSP to middle of stack.
        return stack;
    }

    /// <summary>Set RSP to point to the given pinned stack buffer.</summary>
    public static void SetStack(ref CONTEXT ctx, byte* stackBase, int stackSize)
    {
        ctx.Rsp = (ulong)(stackBase + stackSize); // stack grows down
    }

    /// <summary>Check if a flag is set in EFlags.</summary>
    public static bool IsFlagSet(CONTEXT ctx, uint flag) => (ctx.EFlags & flag) != 0;
}
