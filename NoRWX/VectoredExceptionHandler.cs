using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static NoRWX.EmulatorX64;

namespace NoRWX;

public static unsafe class VectoredExceptionHandler
{
    private delegate uint ExceptionHandlerDelegate(ref EXCEPTION_POINTERS exceptionInfo);

    private static ulong savedTebArm64; // X18 (TEB) saved on first ARM64 VEH entry
    private static bool tebSaved;
    private static bool arm64StackRedirected;
    private static byte[]? arm64Stack; // Separate stack for ARM64 emulated code
    private static GCHandle arm64StackHandle;
    private static nint vectoredExceptionHandlerHandle;
    private static nint executingCodeAddress = nint.Zero;
    private static nuint executingCodeSize = nuint.Zero;
    private static bool isArm64Emulated = false;
    private static bool is32BitMode = false;
    private static bool isArm64CodeMode = false;
    private static ExceptionHandlerDelegate? handlerDelegate;
    private static GCHandle handlerDelegateHandle;

    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
    private const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    private const uint EXCEPTION_CONTINUE_SEARCH = 0x0;

    private const int CONTEXT_FULL = 0x10007;
    private const int CONTEXT_DEBUG_REGISTERS = 0x00100010;
    private const int CONTEXT_DEBUG_REGISTERS_32 = 0x00010010; // x86 CONTEXT_DEBUG_REGISTERS


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

    /// <summary>
    /// UnmanagedCallersOnly entry point for VEH — required on native ARM64
    /// to correctly handle exception resume after modifying PC.
    /// </summary>
    [System.Runtime.InteropServices.UnmanagedCallersOnly(
        CallConvs = [typeof(System.Runtime.CompilerServices.CallConvStdcall)])]
    private static uint ExceptionHandlerNative(EXCEPTION_POINTERS* pExInfo)
    {
        ref EXCEPTION_POINTERS exceptionInfo = ref *pExInfo;
        uint code = *(uint*)exceptionInfo.ExceptionRecord;

        if (isArm64CodeMode)
            return ExceptionHandlerARM64(ref exceptionInfo, code);
        else if (is32BitMode)
            return ExceptionHandler32(ref exceptionInfo, code);
        else
            return ExceptionHandler64(ref exceptionInfo, code);
    }

    private static uint ExceptionHandler(ref EXCEPTION_POINTERS exceptionInfo)
    {
        uint code = *(uint*)exceptionInfo.ExceptionRecord;

        if (isArm64CodeMode)
            return ExceptionHandlerARM64(ref exceptionInfo, code);
        else if (is32BitMode)
            return ExceptionHandler32(ref exceptionInfo, code);
        else
            return ExceptionHandler64(ref exceptionInfo, code);
    }

    private static uint ExceptionHandler64(ref EXCEPTION_POINTERS exceptionInfo, uint code)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ulong rip = ctx->Rip;

        bool isOurException = code == EXCEPTION_SINGLE_STEP
            || (isArm64Emulated && code == EXCEPTION_ACCESS_VIOLATION);

        if (isOurException && IsInCodeRegion(rip))
        {
            if (isArm64Emulated)
            {
                if (!Emulate(ref exceptionInfo, (byte*)rip))
                    return EXCEPTION_CONTINUE_SEARCH;
            }
            else
            {
                while (IsInCodeRegion(ctx->Rip))
                {
                    if (!Emulate(ref exceptionInfo, (byte*)ctx->Rip))
                    {
                        ResetHardwareBreakpoint(ctx);
                        return EXCEPTION_CONTINUE_SEARCH;
                    }
                }
                SetHardwareBreakpoint(ctx, (void*)*(ulong*)ctx->Rsp);
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static uint ExceptionHandler32(ref EXCEPTION_POINTERS exceptionInfo, uint code)
    {
        var ctx = (EmulatorX86.CONTEXT32*)exceptionInfo.ContextRecord;
        ulong eip = ctx->Eip;

        bool isOurException = code == EXCEPTION_SINGLE_STEP
            || (isArm64Emulated && code == EXCEPTION_ACCESS_VIOLATION);

        if (isOurException && IsInCodeRegion(eip))
        {
            if (isArm64Emulated)
            {
                if (!EmulatorX86.Emulate(ctx, (byte*)eip))
                    return EXCEPTION_CONTINUE_SEARCH;
            }
            else
            {
                while (IsInCodeRegion(ctx->Eip))
                {
                    if (!EmulatorX86.Emulate(ctx, (byte*)(ulong)ctx->Eip))
                    {
                        ResetHardwareBreakpoint32(ctx);
                        return EXCEPTION_CONTINUE_SEARCH;
                    }
                }
                SetHardwareBreakpoint32(ctx, (void*)(ulong)*(uint*)ctx->Esp);
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static uint ExceptionHandlerARM64(ref EXCEPTION_POINTERS exceptionInfo, uint code)
    {
        bool isNativeArm64 = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture
            == System.Runtime.InteropServices.Architecture.Arm64;

        if (isNativeArm64)
            return ExceptionHandlerARM64Native(ref exceptionInfo, code);
        else
            return ExceptionHandlerARM64Prism(ref exceptionInfo, code);
    }

    /// <summary>Native ARM64 process: ContextRecord is a Windows ARM64_NT_CONTEXT.</summary>
    private static uint ExceptionHandlerARM64Native(ref EXCEPTION_POINTERS exceptionInfo, uint code)
    {
        // Windows ARM64 CONTEXT layout (ARM64_NT_CONTEXT):
        // Offset 0x000: ContextFlags (4) + Cpsr (4)
        // Offset 0x008: X0-X28 (29 * 8 = 232 bytes)
        // Offset 0x0F0: Fp (X29) (8)
        // Offset 0x0F8: Lr (X30) (8)
        // Offset 0x100: Sp (8)
        // Offset 0x108: Pc (8)
        byte* ctxBase = (byte*)exceptionInfo.ContextRecord;
        ulong* pPc = (ulong*)(ctxBase + 0x108);
        ulong* pSp = (ulong*)(ctxBase + 0x100);
        ulong* pX0 = (ulong*)(ctxBase + 0x008); // X0..X28 as array
        ulong* pFp = (ulong*)(ctxBase + 0x0F0); // X29
        ulong* pLr = (ulong*)(ctxBase + 0x0F8); // X30
        uint* pCpsr = (uint*)(ctxBase + 0x004);

        ulong pc = *pPc;

        if (code != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        // On native ARM64, PC might not point to our buffer (it might be the
        // faulting BLR instruction). Check ExceptionInformation[1] for the target.
        ulong faultAddr = pc;
        if (!IsInCodeRegion(pc))
        {
            byte* exRec = (byte*)exceptionInfo.ExceptionRecord;
            ulong targetAddr = *(ulong*)(exRec + 40);
            if (IsInCodeRegion(targetAddr))
            {
                faultAddr = targetAddr;
                *pPc = targetAddr;
                pc = targetAddr;
            }
        }

        if (!IsInCodeRegion(faultAddr))
            return EXCEPTION_CONTINUE_SEARCH;

        // Restore X18 = TEB before each emulation.
        // ARM64 shellcode uses X18 as scratch but reads [X18, #0x60] for PEB.
        // Use the real TEB from NtCurrentTeb(), not the saved X18 (which might
        // be a .NET runtime value, not the actual TEB).
        if (!tebSaved)
        {
            savedTebArm64 = ThreadInformation.GetCurrentThreadGsBase();
            tebSaved = true;
        }
        pX0[18] = savedTebArm64;

        // Copy native CONTEXT to ARM64 context for emulation
        EmulatorARM64.CONTEXT_ARM64 arm;
        arm.Pc = pc;
        arm.Cpsr = *pCpsr;
        ulong* armRegs = &arm.X0;
        for (int i = 0; i < 29; i++) armRegs[i] = pX0[i];
        arm.X29 = *pFp;
        arm.X30 = *pLr;

        // On native ARM64, use a PRIVATE stack for the emulated code.
        // The real process stack is shared with the .NET runtime which
        // corrupts emulated stack data between VEH calls.
        if (arm64Stack != null && !arm64StackRedirected)
        {
            byte* stackBase = (byte*)arm64StackHandle.AddrOfPinnedObject();
            arm.Sp = (ulong)(stackBase + arm64Stack.Length) & ~0xFUL; // 16-byte aligned top
            arm64StackRedirected = true;
        }
        else
        {
            arm.Sp = *pSp;
        }

        // Emulate in a tight loop. When PC leaves the code region (external
        // API call via BLR), call the API directly from managed code using a
        // function pointer. This avoids VEH re-entry which crashes on native ARM64.
        for (;;)
        {
            // Emulate instructions while PC is in our code region
            while (IsInCodeRegion(arm.Pc))
            {
                if (!EmulatorARM64.Emulate(&arm, (byte*)arm.Pc))
                {
                    if (Core.EmulatorLogger.IsEnabled)
                        Core.EmulatorLogger.Log($"ARM64 EMULATE FAILED: PC=0x{arm.Pc:X} instr=0x{*(uint*)arm.Pc:X8}");
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }

            // PC left the code region — the emulated code did a BLR/BR to an
            // external API. Call it directly from managed code instead of
            // resuming via EXCEPTION_CONTINUE_EXECUTION (which crashes on ARM64).
            ulong apiAddr = arm.Pc;
            ulong returnAddr = arm.X30; // LR set by BLR

            if (!IsInCodeRegion(returnAddr))
            {
                // Return address is also outside our region — the shellcode
                // is done (returning to caller). Write back and exit.
                break;
            }

            if (Core.EmulatorLogger.IsEnabled)
                Core.EmulatorLogger.Log($"ARM64 EXTERNAL CALL: API=0x{apiAddr:X} LR=0x{returnAddr:X} X0=0x{arm.X0:X}");

            // Call the external API with ARM64 calling convention (X0-X7 = args, X0 = return)
            var apiFunc = (delegate* unmanaged<ulong, ulong, ulong, ulong, ulong, ulong, ulong, ulong, ulong>)apiAddr;
            ulong retVal = apiFunc(armRegs[0], armRegs[1], armRegs[2], armRegs[3],
                                   armRegs[4], armRegs[5], armRegs[6], armRegs[7]);
            armRegs[0] = retVal; // X0 = return value

            // Resume emulation at the return address
            arm.Pc = returnAddr;

            // Restore X18 = TEB (API may have preserved it, but be safe)
            armRegs[18] = savedTebArm64;
        }

        // Write back final state to native CONTEXT
        *pPc = arm.Pc;
        *pSp = arm.Sp;
        *pCpsr = arm.Cpsr;
        for (int i = 0; i < 29; i++) pX0[i] = armRegs[i];
        *pFp = arm.X29;
        *pLr = arm.X30;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /// <summary>x64 process (Prism) emulating ARM64 code: ContextRecord is x64 CONTEXT.</summary>
    private static uint ExceptionHandlerARM64Prism(ref EXCEPTION_POINTERS exceptionInfo, uint code)
    {
        var ctx = (CONTEXT*)exceptionInfo.ContextRecord;
        ulong rip = ctx->Rip;

        bool isOurException = code == EXCEPTION_SINGLE_STEP
            || (isArm64Emulated && code == EXCEPTION_ACCESS_VIOLATION);

        if (isOurException && IsInCodeRegion(rip))
        {
            if (!EmulatorARM64.EmulateRaw(ctx, (byte*)rip))
                return EXCEPTION_CONTINUE_SEARCH;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    /// <summary>Initialize for ARM64 code emulation.</summary>
    public static void InitializeARM64(nint codeAddr, nuint codeSize)
    {
        isArm64CodeMode = true;

        // Allocate a separate stack for ARM64 emulated code.
        // On native ARM64, the real process stack is shared with .NET runtime
        // which corrupts emulated stack data between VEH calls.
        arm64Stack = new byte[1024 * 1024]; // 1 MB stack
        arm64StackHandle = GCHandle.Alloc(arm64Stack, GCHandleType.Pinned);

        Initialize(codeAddr, codeSize);
    }

    private static void SetHardwareBreakpoint32(EmulatorX86.CONTEXT32* ctx, void* address)
    {
        ctx->Dr0 = (uint)(ulong)address;
        ctx->Dr7 = 0x1;
    }

    private static void ResetHardwareBreakpoint32(EmulatorX86.CONTEXT32* ctx)
    {
        ctx->Dr0 = 0;
        ctx->Dr7 = 0;
    }


    /// <summary>Initialize for 32-bit i386 code emulation.</summary>
    public static void Initialize32(nint codeAddr, nuint codeSize)
    {
        is32BitMode = true;
        Initialize(codeAddr, codeSize);
    }

    public static void Initialize(nint codeAddr, nuint codeSize)
    {
        executingCodeAddress = codeAddr;
        executingCodeSize = codeSize;

        // Detect ARM64 emulation
        if (IsWow64Process2(GetCurrentProcess(), out ushort processMachine, out ushort nativeMachine))
        {
            isArm64Emulated = nativeMachine == 0xAA64;
            Console.WriteLine($"Process Machine: 0x{processMachine:X4}, Native Machine: 0x{nativeMachine:X4}");
            if (isArm64Emulated)
                Console.WriteLine("ARM64 detected: using ACCESS_VIOLATION-based single-stepping (no hardware breakpoints).");
        }

        // On native ARM64 running ARM64 code: use UnmanagedCallersOnly handler
        // to correctly handle exception resume after modifying PC.
        // On all other configs: managed delegate works fine (via Prism on ARM64).
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
            // Set hardware breakpoint on code entry
            if (is32BitMode)
            {
                int size = Marshal.SizeOf<EmulatorX86.CONTEXT32>();
                var pCtx = (EmulatorX86.CONTEXT32*)Marshal.AllocHGlobal(size);
                pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS_32;

                if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
                { Console.WriteLine("GetThreadContext failed"); Marshal.FreeHGlobal((nint)pCtx); return; }

                SetHardwareBreakpoint32(pCtx, (void*)codeAddr);

                if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
                { Console.WriteLine("SetThreadContext failed."); Marshal.FreeHGlobal((nint)pCtx); return; }

                Marshal.FreeHGlobal((nint)pCtx);
            }
            else
            {
                int size = Marshal.SizeOf<CONTEXT>();
                CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
                pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (!GetThreadContext(GetCurrentThread(), (nint)pCtx))
                { Console.WriteLine("GetThreadContext failed"); Marshal.FreeHGlobal((nint)pCtx); return; }

                SetHardwareBreakpoint(pCtx, (void*)codeAddr);

                if (!SetThreadContext(GetCurrentThread(), (nint)pCtx))
                { Console.WriteLine("SetThreadContext failed."); Marshal.FreeHGlobal((nint)pCtx); return; }

                Marshal.FreeHGlobal((nint)pCtx);
            }
        }
        // ARM64 emulation: no setup needed — executing the buffer will
        // immediately trigger ACCESS_VIOLATION, caught by our VEH
    }

    public static void Uninitialize()
    {
        if (!isArm64Emulated)
        {
            if (is32BitMode)
            {
                int size = Marshal.SizeOf<EmulatorX86.CONTEXT32>();
                var pCtx = (EmulatorX86.CONTEXT32*)Marshal.AllocHGlobal(size);
                pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS_32;
                if (GetThreadContext(GetCurrentThread(), (nint)pCtx))
                {
                    ResetHardwareBreakpoint32(pCtx);
                    SetThreadContext(GetCurrentThread(), (nint)pCtx);
                }
                Marshal.FreeHGlobal((nint)pCtx);
            }
            else
            {
                int size = Marshal.SizeOf<CONTEXT>();
                CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
                pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(GetCurrentThread(), (nint)pCtx))
                {
                    ResetHardwareBreakpoint(pCtx);
                    SetThreadContext(GetCurrentThread(), (nint)pCtx);
                }
                Marshal.FreeHGlobal((nint)pCtx);
            }
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

        if (arm64StackHandle.IsAllocated)
            arm64StackHandle.Free();
        arm64Stack = null;
    }
}
