namespace NoRWX;

unsafe class Program
{
    enum Arch { X86, X64, ARM64 }

    static void Main()
    {
        var processArch = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture;
        Console.WriteLine($"Process Architecture: {processArch}");

        // Enable logging: None (default), Console, or File
        Core.EmulatorLogger.Target = Core.EmulatorLogger.LogTarget.Console;

        switch (processArch)
        {
            case System.Runtime.InteropServices.Architecture.X86:
                Run("windows-i386.bin", Arch.X86);
                break;
            case System.Runtime.InteropServices.Architecture.X64:
                Run("windows-x86_64-nosyscall.bin", Arch.X64);
                //Run("HelloWorld.bin", Arch.X64);
                break;
            case System.Runtime.InteropServices.Architecture.Arm64:
                Run("windows-aarch64.bin", Arch.ARM64);
                break;
            default:
                Console.WriteLine($"Unsupported architecture: {processArch}");
                break;
        }
    }

    static void Run(string filePath, Arch arch)
    {
        byte[] buffer = File.ReadAllBytes(filePath);
        Console.WriteLine($"Running {filePath} as {arch}");

        fixed (byte* pBuffer = buffer)
        {
            switch (arch)
            {
                case Arch.X86:
                    VectoredExceptionHandler.Initialize32((nint)pBuffer, (nuint)buffer.Length);
                    break;
                case Arch.X64:
                    VectoredExceptionHandler.Initialize((nint)pBuffer, (nuint)buffer.Length);
                    break;
                case Arch.ARM64:
                    VectoredExceptionHandler.InitializeARM64((nint)pBuffer, (nuint)buffer.Length);
                    break;
            }

            ((delegate* unmanaged<void>)pBuffer)();
            VectoredExceptionHandler.Uninitialize();
        }
        Console.WriteLine("Execution finished.");
    }
}
