using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static InstructionEmulator;
unsafe class Program
{
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
        byte[] code1 = File.ReadAllBytes("64.bin");
        byte[] code = new byte[]
        {
    0x55,                               // push rbp
    0x48, 0x89, 0xE5,                   // mov rbp, rsp
    0x48, 0x81, 0xEC, 0x00, 0x80, 0x00, 0x00, // sub rsp, 0x8000 (32 KB)
    0xC7, 0x45, 0xFC, 0x05, 0x00, 0x00, 0x00, // mov dword ptr [rbp-4], 5
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0xC6, 0x84, 0x0D, 0x00, 0x80, 0xFF, 0xFF, 0x00, // mov byte ptr [rbp+rcx-0x8000], 0
    0x48, 0xFF, 0xC1,                   // inc rcx
    0x48, 0x81, 0xF9, 0x00, 0x80, 0x00, 0x00, // cmp rcx, 0x8000
    0x72, 0xEC,                         // jb short back to MOV (-0x14)
    0x8B, 0xC1,                         // mov eax, ecx
    0x03, 0x45, 0xFC,                   // add eax, dword ptr [rbp-4]
    0x48, 0x89, 0xEC,                   // mov rsp, rbp
    0x5D,                               // pop rbp
    0xC3                                // ret
        };

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
            InstructionEmulator.Initialize(g_codeAddress, g_codeSize);

            int size = Marshal.SizeOf<CONTEXT>();
            CONTEXT* pCtx = (CONTEXT*)Marshal.AllocHGlobal(size);
            CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>((IntPtr)pCtx);
            pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(GetCurrentThread(), (IntPtr)pCtx))
            {
                Console.WriteLine("GetThreadContext failed with error: " + GetLastError());
                return;
            }
            Console.WriteLine("Start addressing code at: 0x" + ((ulong)g_codeAddress).ToString("X16"));
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

