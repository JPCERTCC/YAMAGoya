using System;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace YAMAGoya.Core
{
    /// <summary>
    /// A utility class to terminate a specific process by its ID.
    /// </summary>
    internal static class ProcessTerminator
    {
        /// <summary>
        /// Terminates the process with the specified process ID.
        /// </summary>
        /// <param name="processId">The ID of the process to terminate.</param>
        [SupportedOSPlatform("windows")]
        public static void TerminateProcess(int processId)
        {
            using (var Logger = new DualLogger())
            {
                try
                {
                    // Retrieve the Process object by ID.
                    Process proc = Process.GetProcessById(processId);
                    // Attempt to kill the process.
                    proc.Kill();
                    Console.WriteLine($"[INFO] Process with PID={processId} has been terminated.");
                    Logger.Log($"Process with PID={processId} has been terminated.", Config.LogLevel.Info);
                }
                catch (ArgumentException)
                {
                    // Thrown if the process ID is not running, or has already exited.
                    Console.WriteLine($"[ERROR] No process found with PID={processId}.");
                    Logger.Log($"No process found with PID={processId}.", Config.LogLevel.Error);
                }
                catch (System.ComponentModel.Win32Exception ex)
                {
                    // Thrown if the current user doesn't have access to kill the process.
                    Console.WriteLine($"[ERROR] Access denied when trying to terminate process with PID={processId}: {ex.Message}");
                    Logger.Log($"Access denied when trying to terminate process with PID={processId}: {ex.Message}", Config.LogLevel.Error);
                }
                catch (InvalidOperationException ex)
                {
                    // Thrown if the process has already exited, or cannot be killed.
                    Console.WriteLine($"[ERROR] Failed to terminate process with PID={processId}: {ex.Message}");
                    Logger.Log($"Failed to terminate process with PID={processId}: {ex.Message}", Config.LogLevel.Error);
                }
            }
        }
    }
}
