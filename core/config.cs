using System;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Provides global configuration constants used by the YAMAGoya application.
    /// </summary>
    internal static class Config
    {
        /// <summary>
        /// Logging levels for the application.
        /// </summary>
        internal enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error
        }

        /// <summary>
        /// The default name of the ETW session to be created or attached.
        /// </summary>
        public static string sessionName = "YAMAGoya";

        /// <summary>
        /// Indicates whether a text log file is enabled.
        /// </summary>
        public static bool isTextLog = true;

        /// <summary>
        /// The directory where log files are stored.
        /// </summary>
        public static string logDirectory = @"logs";

        /// <summary>
        /// The date format used in log file names.
        /// </summary>
        public static string logDateFormat = "yyyy-MM-dd";

        /// <summary>
        /// The format of log filenames.
        /// {0} will be replaced with the date formatted according to logDateFormat.
        /// </summary>
        public static string logFileNameFormat = "yamagoya_{0}.log";

        /// <summary>
        /// Indicates whether logging to the Windows Event Log is enabled.
        /// </summary>
        public static bool isEventLog = true;

        /// <summary>
        /// The source name used when writing to the Windows Event Log.
        /// </summary>
        public static string eventLogSource = "YAMAGoya";

        /// <summary>
        /// The time interval, in seconds, used for checking if rules have timed out.
        /// </summary>
        public static int checkInterval = 10;

        /// <summary>
        /// The time interval, in hours, used for memory scanning.
        /// </summary>
        public static int memoryScanInterval = 1;

        /// <summary>
        /// The logging level for the application.
        /// </summary>
        public static LogLevel logLevel = LogLevel.Info;

        /// <summary>
        /// Yama.dll file sha256 hash.
        /// </summary>
        public static string yamaDllSha256 = "AFC90E6CD201FA69939DFE3AC35B015322B012DCB18409468F52169AF11E9A28";
    }
}
