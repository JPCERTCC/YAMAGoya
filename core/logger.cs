using System;
using System.IO;
using System.Windows;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Diagnostics.CodeAnalysis;
using WpfApp = System.Windows.Application;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Logs messages to both a text file and the Windows Event Log (Application).
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SuppressMessage("Performance", "CA1863:Use 'CompositeFormat'", Justification = "Not available in current .NET version")]
    internal sealed class DualLogger : IDisposable
    {
        private readonly bool _isEventLog = Config.isEventLog;
        private readonly bool _isTextLog = Config.isTextLog;
        private readonly string _eventLogSource = Config.eventLogSource;

        private DateTime _currentLogDate = DateTime.Today;
        private string _currentLogFilePath = string.Empty;

        // Chache the log format
        private static readonly string s_logFileNameFormat = Config.logFileNameFormat;
        
        // Chache the log format line
        private const string LogLineFormat = "[{0}] [{1}] (EventID={2}) {3}{4}";

        /// <summary>
        /// Creates a new instance of DualLogger.
        /// </summary>
        public DualLogger()
        {
            // If the source doesn't exist, try to create it (requires admin)
            if (_isEventLog && !EventLog.SourceExists(_eventLogSource))
            {
                EventLog.CreateEventSource(_eventLogSource, "Application");
            }

            // init log file path
            UpdateLogFilePath();
        }

        /// <summary>
        /// Updates the log file path based on the current date.
        /// </summary>
        private void UpdateLogFilePath()
        {
            string dateStr = _currentLogDate.ToString(Config.logDateFormat, CultureInfo.InvariantCulture);
            
            if (!Directory.Exists(Config.logDirectory))
            {
                try
                {
                    Directory.CreateDirectory(Config.logDirectory);
                }
                catch (IOException ioEx)
                {
                    Console.Error.WriteLine($"[DualLogger] Failed to create log directory: {ioEx.Message}");
                }
                catch (UnauthorizedAccessException uaEx)
                {
                    Console.Error.WriteLine($"[DualLogger] Access denied creating log directory: {uaEx.Message}");
                }
                catch (Exception ex) when (ex is not StackOverflowException && ex is not OutOfMemoryException)
                {
                    Console.Error.WriteLine($"[DualLogger] Unexpected error creating log directory: {ex.Message}");
                }
            }
            
            string fileName = string.Format(CultureInfo.InvariantCulture, s_logFileNameFormat, dateStr);
            
            _currentLogFilePath = Path.Combine(Config.logDirectory, fileName);
        }

        /// <summary>
        /// Logs a message with the specified log level.
        /// Outputs to both text file and Windows Event Log (Application), and updates the GUI if in GUI mode.
        /// </summary>
        /// <param name="message">The log message.</param>
        /// <param name="level">The log level (Debug, Info, Warning, Error).</param>
        /// <param name="eventId">The event ID to associate with the log entry.</param>
        internal void Log(string message, Config.LogLevel level = Config.LogLevel.Info, int eventId = 0)
        {
            if (message == null) return;

            DateTime now = DateTime.Now;
            string timeStamp = now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
            string levelStr = level.ToString().ToUpper(CultureInfo.InvariantCulture);

            // log loataion
            if (now.Date != _currentLogDate)
            {
                _currentLogDate = now.Date;
                UpdateLogFilePath();
            }

            // 1) Write to text file
            if (_isTextLog)
            {
                try
                {
                    var logLine = string.Format(
                        CultureInfo.InvariantCulture, 
                        LogLineFormat, 
                        timeStamp, 
                        levelStr, 
                        eventId, 
                        message, 
                        Environment.NewLine);
                        
                    File.AppendAllText(_currentLogFilePath, logLine);
                }
                catch (IOException ioEx)
                {
                    Console.Error.WriteLine($"[DualLogger] Failed to write to file: {ioEx.Message}");
                }
            }

            // 2) Write to Windows Event Log
            if (_isEventLog)
            {
                try
                {
                    var entryType = ConvertLogLevelToEventType(level);
                    EventLog.WriteEntry(_eventLogSource, message, entryType, eventId);
                }
                catch (IOException ioEx)
                {
                    Console.Error.WriteLine($"[DualLogger] Failed to write to event log: {ioEx.Message}");
                }
            }

            // 3) Write to GUI console
            var dispatcher = WpfApp.Current?.Dispatcher;
            if (App.IsGuiMode && dispatcher != null)
            {
                dispatcher.Invoke(() =>
                {
                    var mainWindow = WpfApp.Current?.MainWindow as MainWindow;
                    if (mainWindow != null)
                    {
                        mainWindow.AppendAlert($"[{levelStr}] {message}");
                    }
                });
            }
        }

        /// <summary>
        /// Converts LogLevel to EventLogEntryType.
        /// </summary>
        private static EventLogEntryType ConvertLogLevelToEventType(Config.LogLevel level)
        {
            return level switch
            {
                Config.LogLevel.Info => EventLogEntryType.Information,
                Config.LogLevel.Warning => EventLogEntryType.Warning,
                Config.LogLevel.Error => EventLogEntryType.Error,
                Config.LogLevel.Debug => EventLogEntryType.Information,
                _ => EventLogEntryType.Information,
            };
        }

        /// <summary>
        /// Prints a console message with the entire line in red color when "DETECTED" is found.
        /// </summary>
        /// <param name="message">The message to display</param>
        internal static void WriteDetectedMessage(string message)
        {
            var originalColor = Console.ForegroundColor;
            try
            {
                // Check if the message contains "DETECTED"
                if (message.Contains("DETECTED", StringComparison.Ordinal))
                {
                    // Print the entire message in red
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(message);
                }
                else
                {
                    Console.WriteLine(message);
                }
            }
            finally
            {
                Console.ForegroundColor = originalColor;
            }
        }

        /// <summary>
        /// Disposes resources if any.
        /// </summary>
        public void Dispose()
        {
            // If you had resources that require cleanup, do it here.
        }
    }
}
