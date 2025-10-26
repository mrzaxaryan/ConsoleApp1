using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static VectoredExceptionHandler;
using static X64Emulator;
unsafe class Program
{
    static byte[] Build(int stackSize)
    {
        var b = new List<byte>(64);

        // prologue
        b.AddRange(new byte[] { 0x55, 0x48, 0x89, 0xE5 });

        // sub rsp, imm32
        b.AddRange(new byte[] { 0x48, 0x81, 0xEC });
        b.AddRange(BitConverter.GetBytes(stackSize)); // 00 80 00 00 for 0x8000

        // mov dword ptr [rbp-4], 5
        b.AddRange(new byte[] { 0xC7, 0x45, 0xFC, 0x05, 0x00, 0x00, 0x00 });

        // xor rcx, rcx
        b.AddRange(new byte[] { 0x48, 0x31, 0xC9 });

        // mov byte ptr [rbp+rcx+disp32], 0   (disp32 = -stackSize)
        b.AddRange(new byte[] { 0xC6, 0x84, 0x0D });
        b.AddRange(BitConverter.GetBytes(unchecked((int)-stackSize))); // 00 80 FF FF for 0x8000
        b.Add(0x00); // imm8

        // inc rcx
        b.AddRange(new byte[] { 0x48, 0xFF, 0xC1 });

        // cmp rcx, imm32
        b.AddRange(new byte[] { 0x48, 0x81, 0xF9 });
        b.AddRange(BitConverter.GetBytes(stackSize));

        // jb short -0x14
        b.AddRange(new byte[] { 0x72, 0xEC });

        // mov eax, ecx ; add eax, [rbp-4] ; epilogue
        b.AddRange(new byte[] { 0x8B, 0xC1, 0x03, 0x45, 0xFC, 0x48, 0x89, 0xEC, 0x5D, 0xC3 });

        return b.ToArray();
    }
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, IntPtr ctx);

    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, IntPtr ctx);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();
    //GetLastError
    [DllImport("kernel32.dll")]
    static extern uint GetLastError();
    delegate UInt32 HashPrototype();
    static void Main()
    {
        int[] a = new int[1024 * 64]; 
        byte[] code = File.ReadAllBytes("64.bin");
        int stackSize = 1024 * 40; // you can change this dynamically

        byte[] code1 = Build(stackSize);

        //IntPtr buffer = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x1000 | 0x2000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        //Marshal.Copy(code, 0, buffer, code.Length);

        // execute buffer as function pointer

        //HashPrototype MyHashingFunction = (HashPrototype)Marshal.GetDelegateForFunctionPointer(buffer, typeof(HashPrototype));
        //MyHashingFunction();

        fixed (byte* pCode = code)
        {
            IntPtr g_codeAddress = (IntPtr)pCode;
            UIntPtr g_codeSize = (UIntPtr)code.Length;

            // Initialize emulator (sets up VEH)
            VectoredExceptionHandler.Initialize(g_codeAddress, g_codeSize);

            int size = Marshal.SizeOf<CONTEXT>();
            CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
            CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((IntPtr)pCtx);
            pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(GetCurrentThread(), (IntPtr)pCtx))
            {
                Console.WriteLine("GetThreadContext failed with error: " + GetLastError());
                return;
            }
            // Set hardware breakpoint at start of our code
            pCtx->Dr0 = (ulong)g_codeAddress;
            pCtx->Dr7 = 0x1ul; // Enable DR0 (execute breakpoint, 1-byte length)

            if (!SetThreadContext(GetCurrentThread(), (IntPtr)pCtx))
            {
                Console.WriteLine("SetThreadContext failed.");
                return;
            }

            //PRINT_CONTEXT(&ctx);
            //DBG_Pause("HWBPs armed — ready to execute");

            // --- Simulate executing code that triggers HWBP ---
            ((delegate* unmanaged<void>)pCode)(); // This will trigger VEH
            Console.WriteLine("Returned from code execution.");
        }
    }

}

