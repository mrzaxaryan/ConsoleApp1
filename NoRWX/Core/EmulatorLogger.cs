namespace NoRWX.Core;

/// <summary>
/// Centralized logger for all emulators (x86, x64, ARM64).
/// Supports console and file output. Designed to be safe in VEH contexts
/// when disabled (zero overhead — no allocations, no delegate calls).
/// </summary>
public static class EmulatorLogger
{
    public enum LogTarget { None, Console, File }

    public static LogTarget Target { get; set; } = LogTarget.None;
    public static string FilePath { get; set; } = "emulator_log.txt";

    public static bool IsEnabled => Target != LogTarget.None;

    public static void Log(string message)
    {
        switch (Target)
        {
            case LogTarget.Console:
                Console.Error.WriteLine(message);
                Console.Error.Flush();
                break;
            case LogTarget.File:
                try { File.AppendAllText(FilePath, message + Environment.NewLine); }
                catch { /* swallow in VEH context */ }
                break;
        }
    }

    public static void Log(string prefix, string mnemonic, int instrLen)
    {
        if (Target == LogTarget.None) return;
        Log($"[{prefix}] {mnemonic} ({instrLen} bytes)");
    }
}
