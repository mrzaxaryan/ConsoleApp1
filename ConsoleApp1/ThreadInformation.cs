using System;
using System.Runtime.InteropServices;

public static class ThreadInformation
{
    [StructLayout(LayoutKind.Sequential)]
    private struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct THREAD_BASIC_INFORMATION
    {
        public int ExitStatus;
        public IntPtr TebBaseAddress;
        public CLIENT_ID ClientId;
        public UIntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        IntPtr ThreadHandle,
        int ThreadInformationClass, // ThreadBasicInformation = 0
        out THREAD_BASIC_INFORMATION ThreadInformation,
        int ThreadInformationLength,
        IntPtr ReturnLength
    );

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(int access, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const int ThreadBasicInformation = 0;
    private const int THREAD_QUERY_INFORMATION = 0x0040;

    public static ulong GetCurrentThreadGsBase()
    {
        THREAD_BASIC_INFORMATION tbi;
        NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation,
            out tbi, Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), IntPtr.Zero);
        return (ulong)tbi.TebBaseAddress.ToInt64();
    }

    public static ulong GetThreadGsBase(uint threadId)
    {
        IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, threadId);
        if (hThread == IntPtr.Zero)
            throw new InvalidOperationException("Cannot open thread");

        try
        {
            THREAD_BASIC_INFORMATION tbi;
            int status = NtQueryInformationThread(hThread, ThreadBasicInformation,
                out tbi, Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), IntPtr.Zero);
            if (status != 0)
                throw new InvalidOperationException($"NtQueryInformationThread failed with 0x{status:X}");
            return (ulong)tbi.TebBaseAddress.ToInt64();
        }
        finally
        {
            CloseHandle(hThread);
        }
    }
}
