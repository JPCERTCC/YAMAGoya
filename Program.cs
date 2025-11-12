using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using YAMAGoya.Core;

namespace YAMAGoya
{
    /// <summary>
    /// The main entry point for the YAMAGoya application.
    /// Processes command-line arguments to start or stop an ETW session,
    /// perform detection based on YAML rule files, and optionally enable verbose logging.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class CommandLineProcessor
    {
        // Define all valid options in a set
        private static readonly HashSet<string> ValidOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "--help", "-h",
            "--session", "-s",
            "--stop", "-x",
            "--detect", "-d",
            "--process", "-p",
            "--load", "-l",
            "--file", "-f",
            "--delfile", "-df",
            "--registry", "-r",
            "--open", "-o",
            "--dns", "-n",
            "--ipv4", "-i4",
            "--ipv6", "-i6",
            "--powershell", "-ps1",
            "--shell", "-sh",
            "--wmi", "-w",
            "--sigma", "-si",
            "--all", "-a",
            "--kill", "-k",
            "--yara", "-y",
            "--session_name",
            "--no_text_log",
            "--no_event_log",
            "--check_interval",
            "--memory_scan_interval",
            "--log_path",
            "--verbose"
        };

        /// <summary>
        /// Validates and sanitizes session name to prevent injection attacks
        /// </summary>
        private static string ValidateSessionName(string sessionName)
        {
            if (string.IsNullOrWhiteSpace(sessionName))
            {
                throw new ArgumentException("Session name cannot be null, empty, or whitespace.");
            }

            // Session name should only contain alphanumeric characters, hyphens, and underscores
            if (!Regex.IsMatch(sessionName, @"^[a-zA-Z0-9_-]+$"))
            {
                throw new ArgumentException("Session name can only contain alphanumeric characters, hyphens, and underscores.");
            }

            if (sessionName.Length > 20)
            {
                throw new ArgumentException("Session name cannot exceed 20 characters.");
            }

            return sessionName;
        }

        /// <summary>
        /// Validates and sanitizes file/folder paths to prevent directory traversal attacks
        /// </summary>
        private static string ValidateAndSanitizePath(string path, bool mustExist = true)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Path cannot be null, empty, or whitespace.");
            }

            // Remove any potential directory traversal sequences with explicit StringComparison
            string sanitizedPath = path;
            while (sanitizedPath.Contains("../", StringComparison.Ordinal) || 
                   sanitizedPath.Contains("..\\", StringComparison.Ordinal))
            {
                sanitizedPath = sanitizedPath.Replace("../", "", StringComparison.Ordinal)
                                              .Replace("..\\", "", StringComparison.Ordinal);
            }
            
            try
            {
                // Get the full path to resolve any relative paths
                string fullPath = Path.GetFullPath(sanitizedPath);
                
                // Ensure the path doesn't contain any remaining traversal attempts
                if (fullPath.Contains("..", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Path contains invalid directory traversal sequences.");
                }

                // Check if path exists when required
                if (mustExist && !Directory.Exists(fullPath) && !File.Exists(fullPath))
                {
                    throw new ArgumentException($"The specified path does not exist: {fullPath}");
                }

                return fullPath;
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw new ArgumentException($"Invalid path format: {path}", ex);
            }
        }

        /// <summary>
        /// Validates integer input within specified range
        /// </summary>
        private static int ValidateIntegerInput(string input, string parameterName, int minValue = 1, int maxValue = int.MaxValue)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                throw new ArgumentException($"{parameterName} cannot be null, empty, or whitespace.");
            }

            if (!int.TryParse(input, out int value))
            {
                throw new ArgumentException($"{parameterName} must be a valid integer.");
            }

            if (value < minValue || value > maxValue)
            {
                throw new ArgumentException($"{parameterName} must be between {minValue} and {maxValue}.");
            }

            return value;
        }

        /// <summary>
        /// The main entry point for the YAMAGoya application.
        /// </summary>
        public static void Process(string[] args)
        {
            string sessionName = "";

            // If session name is set, use it
            if (args.Contains("--session_name"))
            {
                int sessionNameIndex = Array.IndexOf(args, "--session_name");
                if (sessionNameIndex < 0 || sessionNameIndex == args.Length - 1)
                {
                    throw new ArgumentException("You must specify a session name after --session_name.");
                }
                sessionName = ValidateSessionName(args[sessionNameIndex + 1]);
                Console.WriteLine($"[INFO] Using session name: {sessionName}");
            } else {
                sessionName = ValidateSessionName(Config.sessionName);
                Console.WriteLine($"[INFO] Using default session name: {sessionName}");
            }

            if (args.Contains("--no_text_log"))
            {
                Config.isTextLog = false;
                Console.WriteLine("[INFO] Text logging disabled.");
            }

            if (args.Contains("--no_event_log"))
            {
                Config.isEventLog = false;
                Console.WriteLine("[INFO] Windows Event Log disabled.");
            }

            if (args.Contains("--check_interval"))
            {
                int index = Array.IndexOf(args, "--check_interval");
                if (index >= 0 && index < args.Length - 1)
                {
                    int interval = ValidateIntegerInput(args[index + 1], "Check interval", 1, 3600);
                    Config.checkInterval = interval;
                    Console.WriteLine($"[INFO] Check interval set to: {Config.checkInterval} seconds.");
                }
                else
                {
                    throw new ArgumentException("You must specify a valid integer after --check_interval.");
                }
            }

            if (args.Contains("--memory_scan_interval"))
            {
                int index = Array.IndexOf(args, "--memory_scan_interval");
                if (index >= 0 && index < args.Length - 1)
                {
                    int interval = ValidateIntegerInput(args[index + 1], "Memory scan interval", 1, 24);
                    Config.memoryScanInterval = interval;
                    Console.WriteLine($"[INFO] Memory scan interval set to: {Config.memoryScanInterval} hour(s).");
                }
                else
                {
                    throw new ArgumentException("You must specify a valid integer after --memory_scan_interval.");
                }
            }

            if (args.Contains("--log_path"))
            {
                int index = Array.IndexOf(args, "--log_path");
                if (index >= 0 && index < args.Length - 1)
                {
                    string validatedPath = ValidateAndSanitizePath(args[index + 1], false);
                    
                    // Ensure the directory exists or can be created
                    string? directory = Path.GetDirectoryName(validatedPath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        try
                        {
                            Directory.CreateDirectory(directory);
                        }
                        catch (Exception ex)
                        {
                            throw new ArgumentException($"Cannot create log directory: {directory}", ex);
                        }
                    }
                    
                    Config.logDirectory = validatedPath;
                    Console.WriteLine($"[INFO] Log folder set to: {Config.logDirectory}");
                }
                else
                {
                    throw new ArgumentException("You must specify a valid path after --log_path.");
                }
            }

            // If there's no args or help is requested, show usage
            if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
            {
                ShowUsageDetail();
                return;
            }

            // Check each argument. If it starts with "-" (or "--"), validate it.
            var invalidOption = args.FirstOrDefault(arg => arg.StartsWith('-') && !ValidOptions.Contains(arg));
            if (invalidOption != null)
            {
                ShowUsage();
                throw new ArgumentException($"Unknown option: {invalidOption}");
            }

            // If --verbose is specified, you can handle it here
            bool isVerbose = args.Contains("--verbose");
            if (isVerbose)
            {
                Console.WriteLine("[VERBOSE] Verbose mode enabled.");
                Config.logLevel = Config.LogLevel.Debug;
            }

            // Handle recognized options
            if (args.Contains("--session") || args.Contains("-s"))
            {
                EtwSession.StartEtwSession(sessionName);
            }

            if (args.Contains("--stop") || args.Contains("-x"))
            {
                EtwSession.StopEtwSession(sessionName);
            }

            if (args.Contains("--detect") || args.Contains("-d"))
            {
                // Find the index of the option
                int detectIndex = Array.IndexOf(args, "--detect");
                if (detectIndex < 0)
                {
                    detectIndex = Array.IndexOf(args, "-d");
                }

                // The folder path should be the argument after the option
                if (detectIndex < 0 || detectIndex == args.Length - 1)
                {
                    throw new ArgumentException("You must specify a folder path after --detect or -d.");
                }
                string folder = ValidateAndSanitizePath(args[detectIndex + 1]);

                using (var newDetect = new Detect())
                {
                    newDetect.StartEtwDetection(folder, args, sessionName, CancellationToken.None);
                }
            }

            if (args.Contains("--sigma") || args.Contains("-si"))
            {
                // Find the index of the option
                int sigmaIndex = Array.IndexOf(args, "--sigma");
                if (sigmaIndex < 0)
                {
                    sigmaIndex = Array.IndexOf(args, "-si");
                }

                // The folder path should be the argument after the option
                if (sigmaIndex < 0 || sigmaIndex == args.Length - 1)
                {
                    throw new ArgumentException("You must specify a folder path after --sigma or -si.");
                }
                string folder = ValidateAndSanitizePath(args[sigmaIndex + 1]);

                using (var newDetect = new Detect())
                {
                    newDetect.StartEtwDetection(folder, args, sessionName, CancellationToken.None);
                }
            }

            if (args.Contains("--yara") || args.Contains("-y"))
            {
                int yaraIndex = Array.IndexOf(args, "--yara");
                if (yaraIndex < 0)
                {
                    yaraIndex = Array.IndexOf(args, "-y");
                }
                if (yaraIndex < 0 || yaraIndex == args.Length - 1)
                {
                    throw new ArgumentException("You must specify a folder path after --yara or -y.");
                }
                string folder = ValidateAndSanitizePath(args[yaraIndex + 1]);

                using (var newDetect = new Detect())
                {
                    newDetect.StartEtwDetection(folder, args, sessionName, CancellationToken.None);
                }
            }
        }

        private static void ShowUsage()
        {
            Console.WriteLine("YAMAGoya - A simple ETW tool for detecting malicious activities");
            Console.WriteLine("Usage: YAMAGoya.exe [--help|-h] [--session|-s]");
            Console.WriteLine("                     [--detect folder|-d folder]");
            Console.WriteLine("                     [--sigma folder|-si folder]");
            Console.WriteLine("                     [--yara folder|-y folder]");
            Console.WriteLine("                     [--process|-p] [--file|-f] [--registry|-r]");
            Console.WriteLine("                     [--dns|-n] [--ipv4|-i4] [--ipv6|-i6] [--powershell|-ps1]");
            Console.WriteLine("                     [--shell|-sh] [--stop|-x] [--load|-l]");
            Console.WriteLine("                     [--open|-o]");
            Console.WriteLine("                     [--delfile|-df] [--all|-a] [--kill|-k]");
            Console.WriteLine("                     [--session_name sessionName] [--no_text_log] [--no_event_log]");
            Console.WriteLine("                     [--check_interval interval] [--memory_scan_interval interval] [--log_path path]");
            Console.WriteLine("                     [--wmi|-w] [--verbose]");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("  YAMAGoya.exe --session --detect C:\\Rules --file --verbose");
        }

        private static void ShowUsageDetail()
        {
            Console.WriteLine("YAMAGoya - A simple ETW tool for detecting malicious activities");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --help, -h                       Show this help message and exit");
            Console.WriteLine("  --session, -s                    Start an ETW session");
            Console.WriteLine("  --stop, -x                       Stop the current ETW session");
            Console.WriteLine("  --detect [filder], -d [folder]   Detect using default YAML rules");
            Console.WriteLine("  --sigma [filder], -si [filder]   Detect using Sigma rules");
            Console.WriteLine("  --yara [filder], -y [filder]     Detect using YARA rules");
            Console.WriteLine("  --kill, -k                       Terminate the detected process");
            Console.WriteLine("  --all, -a                        Detect all activities");
            Console.WriteLine("  --process, -p                    Detect process creation and termination");
            Console.WriteLine("  --load, -l                       Detect DLL loading");
            Console.WriteLine("  --file, -f                       Detect file creation");
            Console.WriteLine("  --delfile, -df                   Detect file deletion");
            Console.WriteLine("  --registry, -r                   Detect registry key creation");
            Console.WriteLine("  --open, -o                       Detect OpenProcess calls");
            Console.WriteLine("  --dns, -n                        Detect DNS queries and responses");
            Console.WriteLine("  --ipv4, -i4                      Detect IPv4 network activities");
            Console.WriteLine("  --ipv6, -i6                      Detect IPv6 network activities");
            Console.WriteLine("  --powershell, -ps1               Detect PowerShell script execution");
            Console.WriteLine("  --wmi, -w                        Detect WMI command execution");
            Console.WriteLine("  --shell, -sh                     Detect shell commands execution(startup and Runkey)");
            Console.WriteLine("  --session_name [sessionName]     Set the name of the ETW session");
            Console.WriteLine("  --no_text_log                    Disable text log file");
            Console.WriteLine("  --no_event_log                   Disable logging to the Windows Event Log");
            Console.WriteLine("  --check_interval [interval]      Set the time interval for checking rule timeouts");
            Console.WriteLine("  --memory_scan_interval [interval] Set the memory scan interval for YARA rules (1-24 hours)");
            Console.WriteLine("  --log_path [path]                Set the path to the text log file");
            Console.WriteLine("  --verbose                        Enable verbose mode");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  YAMAGoya.exe --session --detect C:\\Rules --file --verbose");
        }
    }
}
