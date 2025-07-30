using System;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Represents an ETW session that can be started or stopped.
    /// </summary>
    internal static class EtwSession
    {
        /// <summary>
        /// Starts an ETW session with the specified name.
        /// If a session with the same name already exists, it will be stopped before creating a new one.
        /// </summary>
        /// <param name="sessionName">The name of the ETW session to start</param>
        public static void StartEtwSession(string sessionName)
        {
            // Stop an existing session if another session with the same name is already running
            if (TraceEventSession.GetActiveSessionNames().Contains(sessionName))
            {
                try
                {
                    // Use ? to handle the possibility of null
                    var existingSession = TraceEventSession.GetActiveSession(sessionName);
                    existingSession?.Stop();
                }
                catch
                {
                    // Rethrow an exception with more detailed error information
                    throw new InvalidOperationException($"Failed to stop the existing ETW session '{sessionName}'.");
                }
            }

            // Create the session instance outside a using block and dispose it in the finally block
            // This makes it easier to handle Ctrl+C scenario
            var session = new TraceEventSession(sessionName)
            {
                StopOnDispose = false // Do not automatically stop the session when Dispose() is called
            };

            try
            {
                Console.WriteLine("Starting ETW session...");

                // Enable the ETW providers you want to collect
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-File",
                    TraceEventLevel.Verbose,
                    0x1090 // FILENAME, CREATE, CREATE_HEW_FILE
                );
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-Process",
                    TraceEventLevel.Verbose,
                    0x10 // WINEVENT_KEYWORD_PROCESS
                );
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-Registry",
                    TraceEventLevel.Verbose,
                    0xf700 // SetValueKey, DeleteValueKey, QueryValueKey, CreateKey, OpenKey, DeleteKey, QueryKey
                );
                session.EnableProvider(
                    "Microsoft-Windows-DNS-Client",
                    TraceEventLevel.Verbose,
                    0x8000000000000000 // Operational
                );
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-Network",
                    TraceEventLevel.Verbose,
                    0x30 // IPv4 and IPv6
                );
                session.EnableProvider(
                    "Microsoft-Windows-PowerShell",
                    TraceEventLevel.Verbose,
                    0x21 // Runspace, Cmdlets
                );
                session.EnableProvider(
                    "Microsoft-Windows-Shell-Core",
                    TraceEventLevel.Verbose,
                    0xFFFFFFFFFFFFFFFF
                );
                session.EnableProvider(
                    "Microsoft-Windows-WinINet-Capture",
                    TraceEventLevel.Verbose,
                    0x300000000 // WININET_KEYWORD_SEND, WININET_KEYWORD_RECEIVE
                );
                session.EnableProvider(
                    "Microsoft-Windows-WinRM",
                    TraceEventLevel.Verbose,
                    0x6 // Client, Server
                );
                session.EnableProvider(
                    "Microsoft-Windows-WMI-Activity",
                    TraceEventLevel.Verbose,
                    0x8000000000000000 // Trace
                );
                session.EnableProvider(
                    "Microsoft-Windows-Security-Mitigations",
                    TraceEventLevel.Verbose,
                    0xc000000000000000 // userland, kernel
                );
                session.EnableProvider(
                    "Microsoft-Windows-Security-Adminless",
                    TraceEventLevel.Verbose,
                    0x8000000000000000 // Operational
                );
                /*session.EnableProvider(
                    "Microsoft-Windows-Security-LessPrivilegedAppContainer",
                    TraceEventLevel.Verbose,
                    0xFFFFFFFFFFFFFFFF
                );*/
                session.EnableProvider(
                    "Microsoft-Windows-Audit-CVE",
                    TraceEventLevel.Verbose,
                    0xc000000000000000 // Application, System
                );
                session.EnableProvider(
                    "Microsoft-Windows-SMBServer",
                    TraceEventLevel.Verbose,
                    0x1a0 // File, Share, Session
                );
                session.EnableProvider(
                    "Microsoft-Windows-SMBClient",
                    TraceEventLevel.Verbose,
                    0x14 // Smb_Info, Smb_TFO
                );
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-Audit-API-Calls",
                    TraceEventLevel.Verbose,
                    0xFFFFFFFFFFFFFFFF // TaskCreated, TaskCompleted
                );
                session.EnableProvider(
                    "Microsoft-Windows-Kernel-EventTracing",
                    TraceEventLevel.Verbose,
                    0x10 // ETW_KEYWORD_SESSION
                );

                // When Ctrl+C is received, stop the session
                Console.CancelKeyPress += (sender, e) =>
                {
                    Console.WriteLine("Stopping ETW session...");
                    session.Stop();
                    e.Cancel = true; // Cancel the default process termination behavior
                };

                Console.WriteLine("ETW session started. Press Ctrl+C to stop.");

                // Real-time event processing (blocking call)
                var thread = new Thread(() =>
                {
                    session.Source.Process();
                });
            } 
            catch
            {
                throw new UnauthorizedAccessException("Failed to start the ETW session. Please run as Administrator.");
            }
            finally
            {
                // Dispose the session in the finally block
                session.Dispose();
            }
        }

        /// <summary>
        /// Stops the ETW session with the specified name.
        /// If no session with that name exists, nothing happens.
        /// </summary>
        /// <param name="sessionName">The name of the ETW session to stop</param>
        public static void StopEtwSession(string sessionName)
        {
            // Check if the specified session name is in the list of active sessions
            if (TraceEventSession.GetActiveSessionNames().Contains(sessionName))
            {
                try
                {
                    var existingSession = TraceEventSession.GetActiveSession(sessionName);
                    existingSession?.Stop();

                    Console.WriteLine($"ETW session '{sessionName}' has been stopped.");
                }
                catch
                {
                    throw new InvalidOperationException($"Failed to stop the ETW session '{sessionName}'.");
                }
            }
            else
            {
                Console.WriteLine($"No active ETW session found with the name '{sessionName}'.");
            }
        }

        /// <summary>
        /// Check session status
        /// </summary>
        /// <param name="sessionName">The name of the ETW session to check</param>
        public static bool CheckEtwSession(string sessionName)
        {
            if (TraceEventSession.GetActiveSessionNames().Contains(sessionName))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
