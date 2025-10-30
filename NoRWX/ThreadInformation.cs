using System;
using System.Runtime.InteropServices;

namespace NoRWX;

public static class ThreadInformation
{
    [StructLayout(LayoutKind.Sequential)]
    private struct CLIENT_ID
    {
        public nint UniqueProcess;
        public nint UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct THREAD_BASIC_INFORMATION
    {
        public int ExitStatus;
        public nint TebBaseAddress;
        public CLIENT_ID ClientId;
        public nuint AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        nint ThreadHandle,
        int ThreadInformationClass, // ThreadBasicInformation = 0
        out THREAD_BASIC_INFORMATION ThreadInformation,
        int ThreadInformationLength,
        nint ReturnLength
    );

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentThread();

    [DllImport("kernel32.dll")]
    private static extern nint OpenThread(int access, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(nint handle);

    private const int ThreadBasicInformation = 0;
    private const int THREAD_QUERY_INFORMATION = 0x0040;

    public static ulong GetCurrentThreadGsBase()
    {
        THREAD_BASIC_INFORMATION tbi;
        NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation,
            out tbi, Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), nint.Zero);
        return (ulong)tbi.TebBaseAddress.ToInt64();
    }

    public static ulong GetThreadGsBase(uint threadId)
    {
        nint hThread = OpenThread(THREAD_QUERY_INFORMATION, false, threadId);
        if (hThread == nint.Zero)
            throw new InvalidOperationException("Cannot open thread");

        try
        {
            THREAD_BASIC_INFORMATION tbi;
            int status = NtQueryInformationThread(hThread, ThreadBasicInformation,
                out tbi, Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), nint.Zero);
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