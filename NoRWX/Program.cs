namespace NoRWX;

unsafe class Program
{
    static void Main()
    {
        Console.WriteLine($"Process Architecture: {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");

        //Run("HelloWorld.bin");
        Run("windows-x86_64.bin");
        
        //Console.ReadLine();
    }

    static void Run(string filePath)
    {
        byte[] buffer = File.ReadAllBytes(filePath);
        fixed (byte* pBuffer = buffer)
        {
            VectoredExceptionHandler.Initialize((nint)pBuffer, (nuint)buffer.Length);
            ((delegate* unmanaged<void>)pBuffer)();
            VectoredExceptionHandler.Uninitialize();
        }
        Console.WriteLine("Execution finished.");
    }
}