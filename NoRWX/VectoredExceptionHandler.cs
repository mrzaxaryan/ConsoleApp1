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
    private static bool x64StackRedirected;
    private static nint x64StackBase = nint.Zero; // Native VirtualAlloc'd stack for x64 emulation
    private static nuint x64StackSize = 0;
    private static nint vectoredExceptionHandlerHandle;
    private static nint executingCodeAddress = nint.Zero;
    private static nuint executingCodeSize = nuint.Zero;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAlloc(nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(nint lpAddress, nuint dwSize, uint dwFreeType);

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_READWRITE = 0x04;

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
            || code == EXCEPTION_ACCESS_VIOLATION;

        if (isOurException && IsInCodeRegion(rip))
        {
            // Redirect emulated code to a private stack on first entry.
            // The faulting thread's real stack is shared with the VEH handler
            // and .NET runtime — shellcode SUB RSP writes would corrupt them.
            if (x64StackBase != nint.Zero && !x64StackRedirected)
            {
                ctx->Rsp = ((ulong)x64StackBase + (ulong)x64StackSize - 0x100) & ~0xFUL;
                x64StackRedirected = true;
            }

            // Tight emulation loop. When RIP leaves the code region (external
            // API call), call the API directly from managed code instead of
            // resuming via EXCEPTION_CONTINUE_EXECUTION. This avoids the TEB
            // stack-range mismatch caused by our private emulated stack.
            for (;;)
            {
                while (IsInCodeRegion(ctx->Rip))
                {
                    if (!Emulate(ref exceptionInfo, (byte*)ctx->Rip))
                    {
                        if (Core.EmulatorLogger.IsEnabled)
                        {
                            byte* failIp = (byte*)ctx->Rip;
                            Core.EmulatorLogger.Log($"X64 EMULATE FAILED: RIP=0x{ctx->Rip:X} bytes=[{failIp[0]:X2} {failIp[1]:X2} {failIp[2]:X2} {failIp[3]:X2} {failIp[4]:X2} {failIp[5]:X2}]");
                        }
                        ResetHardwareBreakpoint(ctx);
                        return EXCEPTION_CONTINUE_SEARCH;
                    }
                }

                // RIP left the code region — emulated code did a CALL/JMP to
                // an external API. Call it directly from managed code using a
                // function pointer (x64 MS ABI: RCX, RDX, R8, R9 = args, RAX = return).
                ulong apiAddr = ctx->Rip;
                ulong returnAddr = *(ulong*)ctx->Rsp; // pushed by the emulated CALL

                // Read stack args from emulated stack BEFORE popping return addr.
                // MS x64 ABI: [RSP+8..RSP+32] = shadow space, [RSP+32..] = stack args 5+
                // (Our RSP after emulated CALL points to return address.)
                ulong arg5 = *(ulong*)(ctx->Rsp + 40);
                ulong arg6 = *(ulong*)(ctx->Rsp + 48);
                ulong arg7 = *(ulong*)(ctx->Rsp + 56);
                ulong arg8 = *(ulong*)(ctx->Rsp + 64);

                if (Core.EmulatorLogger.IsEnabled)
                    Core.EmulatorLogger.Log($"X64 EXT CALL: API=0x{apiAddr:X} RCX=0x{ctx->Rcx:X} RDX=0x{ctx->Rdx:X} R8=0x{ctx->R8:X} R9=0x{ctx->R9:X} a5=0x{arg5:X} a6=0x{arg6:X} a7=0x{arg7:X} a8=0x{arg8:X}");

                if (!IsInCodeRegion(returnAddr))
                {
                    // Return address is also outside our region — shellcode is
                    // done (returning to the original caller). Exit cleanly.
                    break;
                }

                // Pop the return address off the emulated stack.
                ctx->Rsp += 8;

                // Intercept: write buffer directly to console. Length masked to 32-bit
                // since some calls leave upper bits dirty on stack slot.
                // Signature matches NtWriteFile — arg5 is IO_STATUS_BLOCK which the
                // shellcode checks for success after the call.
                bool intercepted = false;
                uint len = (uint)arg7;
                if (arg6 != 0 && len > 0 && len < 4096)
                {
                    try
                    {
                        var bytes = new byte[len];
                        for (uint i = 0; i < len; i++) bytes[i] = ((byte*)arg6)[i];
                        var text = System.Text.Encoding.UTF8.GetString(bytes);
                        Console.Out.Write(text);
                        Console.Out.Flush();

                        // Populate IO_STATUS_BLOCK: Status=0 (SUCCESS), Information=len
                        if (arg5 != 0)
                        {
                            *(ulong*)arg5 = 0;          // Status = STATUS_SUCCESS
                            *(ulong*)(arg5 + 8) = len;  // Information = bytes written
                        }
                        ctx->Rax = 0; // STATUS_SUCCESS — NTSTATUS return
                        intercepted = true;
                    }
                    catch { }
                }

                if (!intercepted)
                {
                    // Call the API. Pass 8 args — first 4 in registers, rest on stack.
                    var apiFunc = (delegate* unmanaged<ulong, ulong, ulong, ulong, ulong, ulong, ulong, ulong, ulong>)apiAddr;
                    ulong retVal = apiFunc(ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, arg5, arg6, arg7, arg8);
                    ctx->Rax = retVal;
                }

                // Resume emulation at the return address.
                ctx->Rip = returnAddr;
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
            || code == EXCEPTION_ACCESS_VIOLATION;

        if (isOurException && IsInCodeRegion(eip))
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
            || code == EXCEPTION_ACCESS_VIOLATION;

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

        // Allocate a private stack for emulated x64 code using VirtualAlloc.
        // Isolates the emulated stack from the VEH handler and .NET managed heap —
        // large shellcode SUB RSP writes would otherwise corrupt them.
        if (!is32BitMode && !isArm64CodeMode)
        {
            x64StackSize = 1024 * 1024; // 1 MB
            x64StackBase = VirtualAlloc(nint.Zero, x64StackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (x64StackBase == nint.Zero)
            {
                Console.WriteLine($"VirtualAlloc failed. Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            x64StackRedirected = false;
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

    public static void Uninitialize()
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

        if (x64StackBase != nint.Zero)
        {
            VirtualFree(x64StackBase, 0, MEM_RELEASE);
            x64StackBase = nint.Zero;
            x64StackSize = 0;
        }
        x64StackRedirected = false;
    }
}
