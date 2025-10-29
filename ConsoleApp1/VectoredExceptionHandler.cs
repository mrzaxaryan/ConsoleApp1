using ConsoleApp1;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using static ConsoleApp1.X64Emulator;

public static unsafe class VectoredExceptionHandler
{
    private static IntPtr g_codeAddress = IntPtr.Zero;
    private static UIntPtr g_codeSize = UIntPtr.Zero;
    private static int g_instructionCount = 0;

    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    private const uint EXCEPTION_CONTINUE_SEARCH = 0x0;

    private const int CONTEXT_FULL = 0x10007;
    public const int CONTEXT_DEBUG_REGISTERS = 0x00100010;



    [DllImport("kernel32.dll")]
    private static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

    [DllImport("kernel32.dll")]
    private static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

    private static void SetHWBP(ref EXCEPTION_POINTERS exceptionInfo, void* address)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        var context = *ctx;
        ctx->Dr0 = (ulong)address;
        ctx->Dr7 = 0x1ul; // Enable DR0 as execute breakpoint
    }

    private static void ClearHWBP(ref EXCEPTION_POINTERS exceptionInfo)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ctx->Dr0 = 0;
        ctx->Dr7 = 0;
    }
   
    private static uint ExceptionHandler(ref EXCEPTION_POINTERS exceptionInfo)
    {
        // Access ExceptionRecord->ExceptionCode
        uint code = *((uint*)exceptionInfo.ExceptionRecord);
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ulong rip = ctx->Rip;
        if (code == EXCEPTION_SINGLE_STEP)
        {
            if (rip >= (ulong)g_codeAddress && rip < (ulong)g_codeAddress + (ulong)g_codeSize)
            {
                g_instructionCount++;

                if (!X64Emulator.Emulate(ref exceptionInfo, (byte*)rip))
                {
                    ClearHWBP(ref exceptionInfo);
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                if (ctx->Rip >= (ulong)g_codeAddress && ctx->Rip < (ulong)g_codeAddress + (ulong)g_codeSize)
                {
                    SetHWBP(ref exceptionInfo, (void*)ctx->Rip);
                }
                else
                {
                    SetHWBP(ref exceptionInfo, (void*)*(ulong*)ctx->Rsp);
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                Console.WriteLine($"[VEH] RIP 0x{rip:X} outside target code range, continuing search.");
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        else
        {
            //Console.WriteLine($"[VEH] Received exception code RIP 0x{rip:X} 0x{code:X}, not handled, continuing search.");
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static IntPtr _vehHandle;
    public static void Initialize(IntPtr codeAddr, UIntPtr codeSize)
    {
        g_codeAddress = codeAddr;
        g_codeSize = codeSize;
        var method = typeof(VectoredExceptionHandler).GetMethod(nameof(ExceptionHandler), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
            .MethodHandle
            .GetFunctionPointer();

        _vehHandle = AddVectoredExceptionHandler(1, method);
    }

    public static void Uninitialize()
    {
        if (_vehHandle != IntPtr.Zero)
        {
            RemoveVectoredExceptionHandler(_vehHandle);
            _vehHandle = IntPtr.Zero;
        }
    }
}

