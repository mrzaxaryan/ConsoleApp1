using System.Runtime.InteropServices;
using static NoRWX.Emulator;

namespace NoRWX;

public static unsafe class VectoredExceptionHandler
{
    private static int executedInstructionCount = 0;
    private static nint vectoredExceptionHandlerHandle;
    private static nint executingCodeAddress = nint.Zero;
    private static nuint executingCodeSize = nuint.Zero;

    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    private const uint EXCEPTION_CONTINUE_SEARCH = 0x0;

    private const int CONTEXT_FULL = 0x10007;
    private const int CONTEXT_DEBUG_REGISTERS = 0x00100010;


    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(nint hThread, nint ctx);

    [DllImport("kernel32.dll")]
    private static extern bool SetThreadContext(nint hThread, nint ctx);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentThread();

    [DllImport("kernel32.dll")]
    private static extern nint AddVectoredExceptionHandler(uint First, nint Handler);

    [DllImport("kernel32.dll")]
    private static extern uint RemoveVectoredExceptionHandler(nint handle);

    private static void SetHardwareBreakpoint(ref EXCEPTION_POINTERS exceptionInfo, void* address)
    {
        var context = (CONTEXT*)exceptionInfo.ContextRecord;
        SetHardwareBreakpoint(context, address);
    }
    private static void SetHardwareBreakpoint(CONTEXT* context, void* address)
    {
        context->Dr0 = (ulong)address;
        context->Dr7 = 0x1ul;
    }
    private static void ResetHardwareBreakpoint(ref EXCEPTION_POINTERS exceptionInfo)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ResetHardwareBreakpoint(ctx);
    }
    private static void ResetHardwareBreakpoint(CONTEXT* ctx)
    {
        ctx->Dr0 = 0;
        ctx->Dr7 = 0;
    }
    private static uint ExceptionHandler(ref EXCEPTION_POINTERS exceptionInfo)
    {
        uint code = *(uint*)exceptionInfo.ExceptionRecord;
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ulong rip = ctx->Rip;

        if (code == EXCEPTION_SINGLE_STEP)
        {
            if (rip >= (ulong)executingCodeAddress && rip < (ulong)executingCodeAddress + executingCodeSize)
            {
                //executedInstructionCount++;

                if (!Emulate(ref exceptionInfo, (byte*)rip))
                {
                    ResetHardwareBreakpoint(ref exceptionInfo);
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                if (ctx->Rip >= (ulong)executingCodeAddress && ctx->Rip < (ulong)executingCodeAddress + executingCodeSize)
                {
                    SetHardwareBreakpoint(ref exceptionInfo, (void*)ctx->Rip);
                }
                else
                {
                    SetHardwareBreakpoint(ref exceptionInfo, (void*)*(ulong*)ctx->Rsp);
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }


    public static void Initialize(nint codeAddr, nuint codeSize)
    {
        executingCodeAddress = codeAddr;
        executingCodeSize = codeSize;
        executedInstructionCount = 0;

        var methodInfo = typeof(VectoredExceptionHandler).GetMethod(
            nameof(ExceptionHandler),
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        ArgumentNullException.ThrowIfNull(methodInfo);

        var method = methodInfo.MethodHandle.GetFunctionPointer();

        vectoredExceptionHandlerHandle = AddVectoredExceptionHandler(1, method);

        int size = Marshal.SizeOf<CONTEXT>();
        CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
        CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((nint)pCtx);
        pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
        {
            Console.WriteLine("GetThreadContext failed");
            return;
        }

        SetHardwareBreakpoint(pCtx, (void*)codeAddr);

        if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
        {
            Console.WriteLine("SetThreadContext failed.");
            return;
        }
        Marshal.FreeHGlobal((nint)pCtx);

    }

    public static void Uninitialize()
    {
        int size = Marshal.SizeOf<CONTEXT>();
        CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
        CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((nint)pCtx);
        pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
        {
            Console.WriteLine("GetThreadContext failed");
            return;
        }

        ResetHardwareBreakpoint(pCtx);

        if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
        {
            Console.WriteLine("SetThreadContext failed.");
            return;
        }
        Marshal.FreeHGlobal((nint)pCtx);
        if (vectoredExceptionHandlerHandle != nint.Zero)
        {
            var handlerRemoveResult = RemoveVectoredExceptionHandler(vectoredExceptionHandlerHandle);
            if (handlerRemoveResult == 0)
            {
                Console.WriteLine("Failed to remove vectored exception handler.");
            }
            vectoredExceptionHandlerHandle = nint.Zero;
        }
    }
}