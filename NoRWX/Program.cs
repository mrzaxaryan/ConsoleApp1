namespace NoRWX;

unsafe class Program
{
    enum Arch { X86, X64 }

    static void Main()
    {
        var processArch = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture;
        Console.WriteLine($"Process Architecture: {processArch}");

        switch (processArch)
        {
            case System.Runtime.InteropServices.Architecture.X86:
                Run("windows-i386.bin", Arch.X86);
                break;
            case System.Runtime.InteropServices.Architecture.X64:
                Run("windows-x86_64.bin", Arch.X64);
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
            }

            ((delegate* unmanaged<void>)pBuffer)();
            VectoredExceptionHandler.Uninitialize();
        }
        Console.WriteLine("Execution finished.");
    }
}
