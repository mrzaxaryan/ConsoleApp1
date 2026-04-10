using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static NoRWX.Emulator;

namespace NoRWX;

public static unsafe class VectoredExceptionHandler
{
    private delegate uint ExceptionHandlerDelegate(ref EXCEPTION_POINTERS exceptionInfo);

    private static int executedInstructionCount = 0;
    private static nint vectoredExceptionHandlerHandle;
    private static nint executingCodeAddress = nint.Zero;
    private static nuint executingCodeSize = nuint.Zero;
    private static bool isArm64Emulated = false;
    private static ExceptionHandlerDelegate? handlerDelegate;
    private static GCHandle handlerDelegateHandle;

    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
    private const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    private const uint EXCEPTION_CONTINUE_SEARCH = 0x0;

    private const int CONTEXT_FULL = 0x10007;
    private const int CONTEXT_DEBUG_REGISTERS = 0x00100010;


    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(nint hThread, nint ctx);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadContext(nint hThread, nint ctx);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint AddVectoredExceptionHandler(uint First, nint Handler);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint RemoveVectoredExceptionHandler(nint handle);

    [DllImport("kernel32.dll")]
    private static extern bool IsWow64Process2(nint hProcess, out ushort pProcessMachine, out ushort pNativeMachine);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInCodeRegion(ulong rip) =>
        rip >= (ulong)executingCodeAddress && rip < (ulong)executingCodeAddress + executingCodeSize;

    private static uint ExceptionHandler(ref EXCEPTION_POINTERS exceptionInfo)
    {
        uint code = *(uint*)exceptionInfo.ExceptionRecord;
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ulong rip = ctx->Rip;

        // Native x64: hardware breakpoint fires EXCEPTION_SINGLE_STEP
        // ARM64 emulation: executing non-executable memory fires ACCESS_VIOLATION
        bool isOurException = code == EXCEPTION_SINGLE_STEP
            || (isArm64Emulated && code == EXCEPTION_ACCESS_VIOLATION);

        if (isOurException && IsInCodeRegion(rip))
        {
            if (!Emulate(ref exceptionInfo, (byte*)rip))
            {
                if (!isArm64Emulated)
                    ResetHardwareBreakpoint(ctx);
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // On ARM64 emulation, no hardware breakpoints needed:
            // - If RIP is still in buffer, next execution attempt faults again naturally
            // - If RIP left buffer (external call), it runs natively; when the call
            //   returns to the buffer address, it faults again and we resume emulation
            if (!isArm64Emulated)
            {
                if (IsInCodeRegion(ctx->Rip))
                {
                    SetHardwareBreakpoint(ctx, (void*)ctx->Rip);
                }
                else
                {
                    // External call: set breakpoint on return address
                    SetHardwareBreakpoint(ctx, (void*)*(ulong*)ctx->Rsp);
                }
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }


    public static void Initialize(nint codeAddr, nuint codeSize)
    {
        executingCodeAddress = codeAddr;
        executingCodeSize = codeSize;
        executedInstructionCount = 0;

        // Detect ARM64 emulation
        if (IsWow64Process2(GetCurrentProcess(), out ushort processMachine, out ushort nativeMachine))
        {
            isArm64Emulated = nativeMachine == 0xAA64;
            Console.WriteLine($"Process Machine: 0x{processMachine:X4}, Native Machine: 0x{nativeMachine:X4}");
            if (isArm64Emulated)
                Console.WriteLine("ARM64 detected: using ACCESS_VIOLATION-based single-stepping (no hardware breakpoints).");
        }

        handlerDelegate = ExceptionHandler;
        handlerDelegateHandle = GCHandle.Alloc(handlerDelegate);
        var handlerPtr = Marshal.GetFunctionPointerForDelegate(handlerDelegate);
        vectoredExceptionHandlerHandle = AddVectoredExceptionHandler(1, handlerPtr);
        if (vectoredExceptionHandlerHandle == nint.Zero)
        {
            Console.WriteLine($"AddVectoredExceptionHandler failed. Error: {Marshal.GetLastWin32Error()}");
            return;
        }

        if (!isArm64Emulated)
        {
            // Native x64: set hardware breakpoint on code entry
            int size = Marshal.SizeOf<CONTEXT>();
            CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
            CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((nint)pCtx);
            pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
            {
                Console.WriteLine("GetThreadContext failed");
                Marshal.FreeHGlobal((nint)pCtx);
                return;
            }

            SetHardwareBreakpoint(pCtx, (void*)codeAddr);

            if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
            {
                Console.WriteLine("SetThreadContext failed.");
                Marshal.FreeHGlobal((nint)pCtx);
                return;
            }
            Marshal.FreeHGlobal((nint)pCtx);
        }
        // ARM64 emulation: no setup needed — executing the buffer will
        // immediately trigger ACCESS_VIOLATION, caught by our VEH
    }

    public static void Uninitialize()
    {
        if (!isArm64Emulated)
        {
            // Native x64: clear hardware breakpoints
            int size = Marshal.SizeOf<CONTEXT>();
            CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
            CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((nint)pCtx);
            pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
            {
                Console.WriteLine("GetThreadContext failed");
                Marshal.FreeHGlobal((nint)pCtx);
                return;
            }

            ResetHardwareBreakpoint(pCtx);

            if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
            {
                Console.WriteLine("SetThreadContext failed.");
                Marshal.FreeHGlobal((nint)pCtx);
                return;
            }
            Marshal.FreeHGlobal((nint)pCtx);
        }

        if (vectoredExceptionHandlerHandle != nint.Zero)
        {
            var handlerRemoveResult = RemoveVectoredExceptionHandler(vectoredExceptionHandlerHandle);
            if (handlerRemoveResult == 0)
            {
                Console.WriteLine("Failed to remove vectored exception handler.");
            }
            vectoredExceptionHandlerHandle = nint.Zero;
        }

        if (handlerDelegateHandle.IsAllocated)
            handlerDelegateHandle.Free();
        handlerDelegate = null;
    }
}
