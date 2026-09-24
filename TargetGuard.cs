using System.Diagnostics;

namespace OmniHax;

/// <summary>
/// Re-validates a target before any debugger attach / breakpoint arming so we can
/// never operate on a process that reused the PID after we opened it.
/// </summary>
internal static class TargetGuard
{
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "smss", "csrss", "wininit", "services", "lsass", "winlogon"
    };

    public static void Verify(ProcessMemory memory)
    {
        if (memory.ProcessId <= 4)
            throw new InvalidOperationException($"Refusing to operate on PID {memory.ProcessId}.");

        Process process;
        try
        {
            process = Process.GetProcessById(memory.ProcessId);
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException($"Target PID {memory.ProcessId} is no longer running.");
        }

        using (process)
        {
            if (CriticalProcesses.Contains(process.ProcessName))
                throw new InvalidOperationException(
                    $"Refusing to operate on critical process {process.ProcessName} (PID {memory.ProcessId}).");

            if (!string.Equals(process.ProcessName, StripExtension(memory.ProcessName), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"Target identity mismatch: expected {memory.ProcessName}, found {process.ProcessName} (PID {memory.ProcessId}).");

            if (memory.StartTimeUtc == DateTime.MinValue)
                return;

            DateTime actual;
            try
            {
                actual = process.StartTime.ToUniversalTime();
            }
            catch (Exception)
            {
                return;
            }

            if (actual != memory.StartTimeUtc)
                throw new InvalidOperationException(
                    $"Target PID {memory.ProcessId} was reused (start time changed).");
        }
    }

    private static string StripExtension(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
}
