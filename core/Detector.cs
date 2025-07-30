using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text;
using System.Timers;
using System.Globalization;
using System.Runtime.Versioning;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using WpfApp = System.Windows.Application;
using System.Threading;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Detection class that reads rule files and performs ETW event detection.
    /// Default mode loads YAML rule files (Rule objects).
    /// If the "--sigma" option is specified, SIGMA rule files (SigmaRule objects) are loaded and evaluated.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal sealed class Detect : IDisposable
    {
        /// <summary>
        /// Check interval (in seconds). If it exceeds this time, default rule states are reset.
        /// </summary>
        private readonly int checkInterval = Config.checkInterval;

        // Timer used in default mode to periodically reset rule states.
        private System.Timers.Timer? _resetTimer;

        // FileSystemWatcher to monitor rule file changes
        private FileSystemWatcher? _fileWatcher;

        // YARA memory scan thread and cancellation token source
        private Thread? _yaraMemoryScanThread;
        private CancellationTokenSource? _yaraCancellationSource;

        // Collections for rule models.
        private List<Rule>? _defaultRules;
        private List<SigmaRule>? _sigmaRules;

        // Timestamp to prevent consecutive execution of reload processing
        private DateTime _lastDefaultRulesReload = DateTime.MinValue;
        private DateTime _lastSigmaRulesReload = DateTime.MinValue;
        private DateTime _lastYaraRulesReload = DateTime.MinValue;

        // Minimum interval (in milliseconds) between reloads
        private const int MinReloadInterval = 2000;

        /// <summary>
        /// Converts the specified object to an <see cref="IPAddress"/>.
        /// If the conversion using the default method fails (for example, for negative values), an alternative conversion is applied.
        /// </summary>
        /// <param name="addr">An object convertible to a 32-bit unsigned integer representing an IP address.</param>
        /// <returns>An <see cref="IPAddress"/> constructed from the 32-bit address.</returns>
        /// <exception cref="ArgumentException">Thrown if conversion fails.</exception>
        public static IPAddress UInt32ToIPAddress(object addr)
        {
            uint address;

            if (addr is uint u)
            {
                address = u;
            }
            else if (addr is int i)
            {
                address = i < 0 ? (uint)(-i + 2147483648) : (uint)i;
            }
            else if (addr is string s)
            {
                if (!uint.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out address))
                {
                    throw new ArgumentException($"Unable to convert string '{s}' to a 32-bit unsigned integer.");
                }
            }
            else if (addr is IConvertible convertible)
            {
                string str = convertible.ToString(CultureInfo.InvariantCulture);
                if (!uint.TryParse(str, NumberStyles.Any, CultureInfo.InvariantCulture, out address))
                {
                    throw new ArgumentException($"Unable to convert value '{str}' to a 32-bit unsigned integer.");
                }
            }
            else
            {
                throw new ArgumentException("The provided value cannot be converted to a 32-bit unsigned integer.", nameof(addr));
            }

            return new IPAddress(new byte[]
            {
                (byte)(address & 0xFF),
                (byte)((address >> 8) & 0xFF),
                (byte)((address >> 16) & 0xFF),
                (byte)((address >> 24) & 0xFF)
            });
        }

        /// <summary>
        /// Converts data received from ETW to an IPv6 address.
        /// Supports various data formats (byte arrays, numbers, strings, etc.).
        /// </summary>
        /// <param name="addr">Data representing an IPv6 address</param>
        /// <returns>Converted IPAddress, or null if conversion is not possible</returns>
        public static IPAddress? IntToIPv6Address(object? addr)
        {
            if (addr == null)
            {
                return null;
            }

            try
            {
                // Data received from ETW for IPv6 is typically a 16-byte array
                if (addr is byte[] byteArray)
                {
                    // Adjust if not 16 bytes in length
                    if (byteArray.Length != 16)
                    {
                        byte[] fullBytes = new byte[16];
                        // For smaller arrays, pack at the end (similar to standard IPv6 address conversion)
                        Array.Copy(byteArray, 0, fullBytes, 
                                  byteArray.Length < 16 ? 16 - byteArray.Length : 0, 
                                  Math.Min(byteArray.Length, 16));
                        return new IPAddress(fullBytes);
                    }
                    return new IPAddress(byteArray);
                }
                // For int arrays
                else if (addr is int[] intArray)
                {
                    byte[] ipv6Bytes = new byte[16];
                    for (int i = 0; i < Math.Min(intArray.Length, 4); i++)
                    {
                        byte[] intBytes = BitConverter.GetBytes(intArray[i]);
                        Array.Copy(intBytes, 0, ipv6Bytes, i * 4, 4);
                    }
                    return new IPAddress(ipv6Bytes);
                }
                // For long arrays
                else if (addr is long[] longArray)
                {
                    byte[] ipv6Bytes = new byte[16];
                    for (int i = 0; i < Math.Min(longArray.Length, 2); i++)
                    {
                        byte[] longBytes = BitConverter.GetBytes(longArray[i]);
                        Array.Copy(longBytes, 0, ipv6Bytes, i * 8, 8);
                    }
                    return new IPAddress(ipv6Bytes);
                }
                // For integer values (int)
                else if (addr is int intValue)
                {
                    byte[] bytes = BitConverter.GetBytes(intValue);
                    byte[] ipv6Bytes = new byte[16];
                    // Place the int value at the end of the IPv6 address
                    Array.Copy(bytes, 0, ipv6Bytes, 12, 4);
                    return new IPAddress(ipv6Bytes);
                }
                // For long integer values (long)
                else if (addr is long longValue)
                {
                    byte[] bytes = BitConverter.GetBytes(longValue);
                    byte[] ipv6Bytes = new byte[16];
                    // Place the long value at the end of the IPv6 address
                    Array.Copy(bytes, 0, ipv6Bytes, 8, 8);
                    return new IPAddress(ipv6Bytes);
                }
                // Directly parse strings
                else if (addr is string addrStr)
                {
                    if (IPAddress.TryParse(addrStr, out IPAddress? ipAddr))
                    {
                        return ipAddr;
                    }
                }
                // For other object types, try converting to string
                else
                {
                    string objStr = addr.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(objStr) && IPAddress.TryParse(objStr, out IPAddress? ipAddr))
                    {
                        return ipAddr;
                    }
                }

                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] IPv6 conversion: Unsupported type {addr.GetType().Name}, value={addr}");
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"[ERROR] IPv6 address conversion error (invalid argument): {ex.Message}");
            }
            catch (FormatException ex)
            {
                Console.WriteLine($"[ERROR] IPv6 address conversion error (invalid format): {ex.Message}");
            }
            catch (OverflowException ex)
            {
                Console.WriteLine($"[ERROR] IPv6 address conversion error (overflow): {ex.Message}");
            }
            return null;
        }

        /// <summary>
        /// Stops the ETW session with the specified name.
        /// </summary>
        /// <param name="sessionName">The name of the ETW session to stop.</param>
        [SupportedOSPlatform("windows")]
        public static void StopEtwDetection(string sessionName)
        {
            if (!TraceEventSession.GetActiveSessionNames().Contains(sessionName))
            {
                throw new InvalidOperationException($"[ERROR] ETW session '{sessionName}' is not started yet. Please start the session first using --session.");
            }
            using (var session = new TraceEventSession(sessionName))
            {
                session.Stop();
                Console.WriteLine($"[INFO] ETW session '{sessionName}' has been stopped.");
            }
        }

        /// <summary>
        /// Starts a real-time ETW session, loads rule files, and triggers detection.
        /// Default mode loads YAML rule files (Rule objects).
        /// If the "--sigma" option is specified, SIGMA rule files (SigmaRule objects) are loaded and evaluated.
        /// Verbose logs are output if --verbose is specified.
        /// Also sets up a Timer (in default mode) to reset rules if no new events arrive.
        /// </summary>
        /// <param name="folder">Folder path containing rule files.</param>
        /// <param name="args">Command-line arguments.</param>
        /// <param name="sessionName">ETW session name to attach.</param>
        /// <param name="token">Cancellation token to stop the detection.</param>
        [SupportedOSPlatform("windows")]
        public void StartEtwDetection(string folder, string[] args, string sessionName, CancellationToken token)
        {
            bool isVerbose = args.Contains("--verbose");
            if (isVerbose)
            {
                Config.logLevel = Config.LogLevel.Debug;
            }

            if (!TraceEventSession.GetActiveSessionNames().Contains(sessionName))
            {
                throw new InvalidOperationException($"[ERROR] ETW session '{sessionName}' is not started yet. Please start the session first using --session.");
            }

            // Load rule files based on mode.
            if (args.Contains("--sigma") || args.Contains("-si"))
            {
                Console.WriteLine("[INFO] Loading SIGMA rule files...");
                _sigmaRules = SigmaDetector.LoadSigmaRules(folder);
                Console.WriteLine($"[INFO] Loaded SIGMA rule count: {_sigmaRules.Count}");
            }
            else if (args.Contains("--detect") || args.Contains("-d"))
            {
                Console.WriteLine("[INFO] Loading YAML rule files...");
                _defaultRules = LoadDetectionRules(folder);
                Console.WriteLine($"[INFO] Loaded default rule count: {_defaultRules.Count}");

                // Set up timer to reset default rules.
                _resetTimer = new System.Timers.Timer(checkInterval * 1000)
                {
                    AutoReset = true,
                    Enabled = false
                };
                _resetTimer.Elapsed += (sender, e) => TimerCheckAndReset(_defaultRules);
                _resetTimer.Start();
            }

            // Setup FileSystemWatcher to monitor rule file changes
            _fileWatcher = new FileSystemWatcher(folder)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            if (args.Contains("--sigma") || args.Contains("-si"))
            {
                _fileWatcher.Filter = "*.yml";
                _fileWatcher.Created += ReloadSigmaRules;
                _fileWatcher.Changed += ReloadSigmaRules;
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine("[VERBOSE] FileSystemWatcher set up for SIGMA rule files (*.yml)");
            }
            else if (args.Contains("--detect") || args.Contains("-d"))
            {
                _fileWatcher.Filter = "*.yml";
                _fileWatcher.Created += ReloadDefaultRules;
                _fileWatcher.Changed += ReloadDefaultRules;
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine("[VERBOSE] FileSystemWatcher set up for default rule files (*.yml)");
            } 

            if (args.Contains("--yara") || args.Contains("-y"))
            {
                _fileWatcher.Filter = "*.yara";
                _fileWatcher.Created += ReloadYaraRules;
                _fileWatcher.Changed += ReloadYaraRules;
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine("[VERBOSE] FileSystemWatcher set up for YARA rule files (*.yara)");
            }

            // Load YARA rules.
            if (args.Contains("--yara") || args.Contains("-y"))
            {
                Console.WriteLine("[INFO] Loading YARA rule files...");
                string yaraRulesContent = YaraDetector.LoadYaraRules(folder);
                
                _yaraMemoryScanThread = new Thread(() => YaraDetector.StartMemoryScanTimer(yaraRulesContent));
                _yaraMemoryScanThread.Start();
                
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] Started YARA memory scanning with thread ID: {_yaraMemoryScanThread.ManagedThreadId}");
            }

            using (var session = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session))
            using (var Logger = new DualLogger())
            {
                Console.WriteLine("[INFO] Press Ctrl+C to stop.");

                if (args.Contains("--detect") || args.Contains("-d"))
                {
                    Console.WriteLine($"[INFO] Starting ETW detection (check interval: {checkInterval}s)...");
                }

                session.Dynamic.All += (TraceEvent data) =>
                {
                    DateTime now = DateTime.Now;

                    // SIGMA rule detection branch
                    if ((args.Contains("--sigma") || args.Contains("-si")) && _sigmaRules is not null && _sigmaRules?.Count > 0)
                    {
                        // Use static methods from SigmaDetector.
                        foreach (var sigma in _sigmaRules)
                        {
                            if (SigmaDetector.EvaluateSigmaDetection(data, sigma))
                            {
                                DualLogger.WriteDetectedMessage($"[INFO] {now} DETECTED (SIGMA): {sigma.Title} - {sigma.Description}");
                                Logger.Log($"DETECTED (SIGMA): {sigma.Title} - {sigma.Description}", Config.LogLevel.Info, 9001);
                                if (args.Contains("--kill") || args.Contains("-k"))
                                {
                                    int pid = data.ProcessID;
                                    if (pid != 0)
                                    {
                                        DualLogger.WriteDetectedMessage($"[INFO] {now} DETECTED: PID={pid}");
                                        Logger.Log($"DETECTED: PID={pid}", Config.LogLevel.Info, 9002);
                                        ProcessTerminator.TerminateProcess(pid);
                                    }
                                }
                            }
                        }
                    }
                    else if (_defaultRules?.Count > 0) // Default YAML rule detection branch
                    {   
                        foreach (var rule in _defaultRules)
                        {
                            for (int i = 0; i < rule.rules.Count; i++)
                            {
                                if (rule.matchedFlags[i])
                                    continue;
                                var item = rule.rules[i];
                                (string? matchedDetail, int pid) = IsMatched(data, item, args);
                                rule.pid = pid;
                                if (matchedDetail != null)
                                {
                                    if (rule.firstMatchTime == null)
                                    {
                                        rule.firstMatchTime = now;
                                    }
                                    else if ((now - rule.firstMatchTime.Value) > TimeSpan.FromSeconds(checkInterval))
                                    {
                                        rule.ResetMatchFlags();
                                        rule.firstMatchTime = now;
                                        if (Config.logLevel == Config.LogLevel.Debug)
                                            Console.WriteLine($"[VERBOSE] {now} >{checkInterval}s passed. Resetting match flags for rule '{rule.rulename}'.");
                                    }
                                    rule.matchedFlags[i] = true;
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                    {
                                        Console.WriteLine($"[VERBOSE] {now} Matched {rule.matchedFlags.Count(x => x)}/{rule.rules.Count} in '{rule.rulename}': {matchedDetail}");
                                        Logger.Log($"Matched {rule.matchedFlags.Count(x => x)}/{rule.rules.Count} in '{rule.rulename}': {matchedDetail}", Config.LogLevel.Info, 8002);
                                    }
                                }
                            }
                            if (rule.matchedFlags.All(x => x))
                            {
                                if (rule.firstMatchTime != null && (now - rule.firstMatchTime.Value) <= TimeSpan.FromSeconds(checkInterval))
                                {
                                    DualLogger.WriteDetectedMessage($"[INFO] {now} DETECTED: {rule.rulename} - {rule.description}");
                                    Logger.Log($"DETECTED: {rule.rulename} - {rule.description}", Config.LogLevel.Info, 8001);

                                    if (rule.pid != 0 && (args.Contains("--kill") || args.Contains("-k")))
                                    {
                                        DualLogger.WriteDetectedMessage($"[INFO] {now} DETECTED: PID={rule.pid}");
                                        Logger.Log($"DETECTED: PID={rule.pid}", Config.LogLevel.Info, 8003);
                                        ProcessTerminator.TerminateProcess(rule.pid);
                                    }
                                }
                                rule.ResetMatchFlags();
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] {now} Reset all matched flags for '{rule.rulename}' after detection.");
                            }
                        }
                    }

                    // ----------------------------------------------------
                    // Additional event detections (e.g. WinRM, WMI, SMBServer, Security events)
                    // ----------------------------------------------------
                    if (data.ProviderName == "Microsoft-Windows-WinRM")
                    {
                        if (data.ID == (TraceEventID)6)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string connection = data.PayloadStringByName("connection", null) ?? "";
                            Console.WriteLine($"[INFO] {now} WinRM Outbound event detected: ProcessID='{processId}' ProcessName='{processName}' connection='{connection}'");
                            Logger.Log($"WinRM Outbound event detected: ProcessID='{processId}' ProcessName='{processName}' connection='{connection}'", Config.LogLevel.Info, 8005);
                        }
                        else if (data.ID == (TraceEventID)91)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string resourceUri = data.PayloadStringByName("resourceUri", null) ?? "";
                            Console.WriteLine($"[INFO] {now} WinRM Inbound event detected: ProcessID='{processId}' ProcessName='{processName}' resourceUri='{resourceUri}'");
                            Logger.Log($"WinRM Inbound event detected: ProcessID='{processId}' ProcessName='{processName}' resourceUri='{resourceUri}'", Config.LogLevel.Info, 8006);
                        }
                    }

                    if (data.ProviderName == "Microsoft-Windows-SMBServer")
                    {
                        if (data.ID == (TraceEventID)552)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string userName = data.PayloadStringByName("UserName", null) ?? "";
                            string domainName = data.PayloadStringByName("DomainName", null) ?? "";
                            Console.WriteLine($"[INFO] {now} SMBServer authenticated detected: ProcessID='{processId}' ProcessName='{processName}' user='{userName}', domain='{domainName}'");
                            Logger.Log($"SMBServer authenticated detected: ProcessID='{processId}' ProcessName='{processName}' user='{userName}', domain='{domainName}'", Config.LogLevel.Info, 8012);
                        }
                        else if (data.ID == (TraceEventID)650)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string fileName = data.PayloadStringByName("Name", null) ?? "";
                            Console.WriteLine($"[INFO] {now} SMBServer file share detected: ProcessID='{processId}' ProcessName='{processName}' file='{fileName}'");
                            Logger.Log($"SMBServer file share detected: ProcessID='{processId}' ProcessName='{processName}' file='{fileName}'", Config.LogLevel.Info, 8013);
                        }
                        else if (data.ID == (TraceEventID)700)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string shareName = data.PayloadStringByName("ShareName", null) ?? "";
                            string serverName = data.PayloadStringByName("ServerName", null) ?? "";
                            string pathName = data.PayloadStringByName("PathName", null) ?? "";
                            Console.WriteLine($"[INFO] {now} SMBServer add share detected: ProcessID='{processId}' ProcessName='{processName}' share='{shareName}', server='{serverName}', path='{pathName}'");
                            Logger.Log($"SMBServer add share detected: ProcessID='{processId}' ProcessName='{processName}' share='{shareName}', server='{serverName}', path='{pathName}'", Config.LogLevel.Info, 8014);
                        }
                    }

                    if (data.ProviderName == "Microsoft-Windows-SMBClient")
                    {
                        if (data.ID == (TraceEventID)31010)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string shareName = data.PayloadStringByName("ShareName", null) ?? "";
                            string objectName = data.PayloadStringByName("ObjectName", null) ?? "";
                            Console.WriteLine($"[INFO] {now} SMB Client failed to connect share: ProcessID='{processId}' ProcessName='{processName}' share='{shareName}', object='{objectName}'");
                            Logger.Log($"SMB Client failed to connect share: ProcessID='{processId}' ProcessName='{processName}' share='{shareName}', object='{objectName}'", Config.LogLevel.Info, 8015);
                        }
                        else if (data.ID >= (TraceEventID)30501 && data.ID <= (TraceEventID)30508)
                        {
                            int processId = data.ProcessID;
                            string processName = data.ProcessName ?? "";
                            string fileName = data.PayloadStringByName("FileName", null) ?? "";
                            Console.WriteLine($"[INFO] {now} SMB Client file operation: ProcessID='{processId}' ProcessName='{processName}' file='{fileName}'");
                            Logger.Log($"SMB Client file operation: ProcessID='{processId}' ProcessName='{processName}' file='{fileName}'", Config.LogLevel.Info, 8016);
                        }
                    }

                    if (data.ProviderName == "Microsoft-Windows-Security-Mitigations")
                    {
                        int processId = data.ProcessID;
                        string processName = data.ProcessName ?? "";
                        string mitigation = data.PayloadStringByName("Mitigation", null) ?? "";
                        string processPath = data.PayloadStringByName("ProcessPath", null) ?? "";
                        string processCmdLine = data.PayloadStringByName("ProcessCommandLine", null) ?? "";
                        Console.WriteLine($"[INFO] {now} Security Mitigations event detected: ProcessID='{processId}' ProcessName='{processName}' process='{processPath}', cmd='{processCmdLine}', mitigation='{mitigation}'");
                        Logger.Log($"Security Mitigations event detected: ProcessID='{processId}' ProcessName='{processName}' process='{processPath}', cmd='{processCmdLine}', mitigation='{mitigation}'", Config.LogLevel.Info, 8008);
                    }

                    if (data.ProviderName == "Microsoft-Windows-Security-Adminless")
                    {
                        int processId = data.ProcessID;
                        string processName = data.ProcessName ?? "";
                        Console.WriteLine($"[INFO] {now} Security Adminless event detected.");
                        Logger.Log("Security Adminless event detected.", Config.LogLevel.Info, 8009);
                    }

                    if (data.ProviderName == "Microsoft-Windows-Audit-CVE")
                    {
                        int processId = data.ProcessID;
                        string processName = data.ProcessName ?? "";
                        string cve = data.PayloadStringByName("CVEID", null) ?? "";
                        string details = data.PayloadStringByName("AdditionalDetails", null) ?? "";
                        Console.WriteLine($"[INFO] {now} Security CVE event detected: ProcessID='{processId}' ProcessName='{processName}' CVE='{cve}', details='{details}'");
                        Logger.Log($"Security CVE event detected: ProcessID='{processId}' ProcessName='{processName}' CVE='{cve}', details='{details}'", Config.LogLevel.Info, 8011);
                    }

                    if (data.ProviderName == "Microsoft-Windows-Kernel-EventTracing")
                    {
                        if (data.ID == (TraceEventID)2 || data.ID == (TraceEventID)10)
                        {
                            Console.WriteLine($"[INFO] {now} ETW session started: {data.PayloadStringByName("SessionName", null)}");
                            Logger.Log($"ETW session started: {data.PayloadStringByName("SessionName", null)}", Config.LogLevel.Info, 8017);
                        }
                        else if (data.ID == (TraceEventID)3 || data.ID == (TraceEventID)11)
                        {
                            Console.WriteLine($"[INFO] {now} ETW session stopped: {data.PayloadStringByName("SessionName", null)}");
                            Logger.Log($"ETW session stopped: {data.PayloadStringByName("SessionName", null)}", Config.LogLevel.Info, 8018);
                        }
                    }

                    if (token.IsCancellationRequested)
                    {
                        Console.WriteLine("Stopping ETW detection...");
                        session.Dispose();
                    }
                };

                try
                {
                    session.Process();
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine($"Unauthorized access error: {ex.Message}");
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine($"Invalid operation error: {ex.Message}");
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"I/O error: {ex.Message}");
                }
                finally
                {
                    if (_resetTimer != null)
                    {
                        _resetTimer.Stop();
                        Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Reloads default YAML rules when changes are detected in the rules directory
        /// </summary>
        /// <param name="sender">Event sender object</param>
        /// <param name="e">Event arguments</param>
        private void ReloadDefaultRules(object sender, FileSystemEventArgs e)
        {
            // Skip if minimum interval has not passed since the last reload
            if ((DateTime.UtcNow - _lastDefaultRulesReload).TotalMilliseconds < MinReloadInterval)
            {
                return;
            }

            try
            {
                string folder = Path.GetDirectoryName(e.FullPath) ?? "";
                
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] {DateTime.Now} Rule file change detected. Reloading default rules...");
                
                var newRules = LoadDetectionRules(folder);
                
                // Replace rules with the new set
                _defaultRules = newRules;
                
                Console.WriteLine($"[INFO] {DateTime.Now} Successfully reloaded {_defaultRules.Count} default rules.");
                
                // Update last reload time
                _lastDefaultRulesReload = DateTime.UtcNow;
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload default rules (IO error): {ex.Message}");
            }
            catch (YamlException ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload default rules (YAML error): {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload default rules: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Reloads SIGMA rules when changes are detected in the rules directory
        /// </summary>
        /// <param name="sender">Event sender object</param>
        /// <param name="e">Event arguments</param>
        private void ReloadSigmaRules(object sender, FileSystemEventArgs e)
        {
            // Skip if minimum interval has not passed since the last reload
            if ((DateTime.UtcNow - _lastSigmaRulesReload).TotalMilliseconds < MinReloadInterval)
            {
                return;
            }

            try
            {
                string folder = Path.GetDirectoryName(e.FullPath) ?? "";
                
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] {DateTime.Now} Rule file change detected. Reloading SIGMA rules...");
                
                var newRules = SigmaDetector.LoadSigmaRules(folder);
                
                // Replace rules with the new set
                _sigmaRules = newRules;
                
                Console.WriteLine($"[INFO] {DateTime.Now} Successfully reloaded {_sigmaRules.Count} SIGMA rules.");
                
                // Update last reload time
                _lastSigmaRulesReload = DateTime.UtcNow;
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload SIGMA rules (IO error): {ex.Message}");
            }
            catch (YamlException ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload SIGMA rules (YAML error): {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload SIGMA rules: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Reloads YARA rules when changes are detected in the rules directory
        /// </summary>
        /// <param name="sender">Event sender object</param>
        /// <param name="e">Event arguments</param>
        private void ReloadYaraRules(object sender, FileSystemEventArgs e)
        {
            // Skip if minimum interval has not passed since the last reload
            if ((DateTime.UtcNow - _lastYaraRulesReload).TotalMilliseconds < MinReloadInterval)
            {
                return;
            }

            try
            {
                string folder = Path.GetDirectoryName(e.FullPath) ?? "";
                
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] {DateTime.Now} Rule file change detected. Reloading YARA rules...");
                
                var yaraRulesContent = YaraDetector.LoadYaraRules(folder);
                
                Console.WriteLine($"[INFO] {DateTime.Now} Successfully reloaded YARA rules.");
                
                // if a YARA scan thread is already running, stop it
                if (_yaraMemoryScanThread != null && _yaraCancellationSource != null)
                {
                    if (Config.logLevel == Config.LogLevel.Debug)
                        Console.WriteLine($"[VERBOSE] {DateTime.Now} Stopping existing YARA scan thread (ID: {_yaraMemoryScanThread.ManagedThreadId})");
                    
                    _yaraCancellationSource.Cancel();
                    
                    bool threadStopped = _yaraMemoryScanThread.Join(5000);
                    if (!threadStopped && Config.logLevel == Config.LogLevel.Debug)
                        Console.WriteLine($"[VERBOSE] {DateTime.Now} Warning: Failed to gracefully stop previous YARA scan thread");
                }
                
                _yaraCancellationSource = new CancellationTokenSource();
                
                _yaraMemoryScanThread = new Thread(() => YaraDetector.StartMemoryScanTimer(yaraRulesContent));
                _yaraMemoryScanThread.Start();
                
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] {DateTime.Now} Started new YARA memory scanning with thread ID: {_yaraMemoryScanThread.ManagedThreadId}");
                
                // Update last reload time
                _lastYaraRulesReload = DateTime.UtcNow;
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload YARA rules (IO error): {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now} Failed to reload YARA rules: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Timer callback method. It runs periodically (every checkInterval seconds)
        /// and resets default rules if they have exceeded the interval without new matches.
        /// </summary>
        /// <param name="ruleSet">The list of default rules.</param>
        private void TimerCheckAndReset(List<Rule> ruleSet)
        {
            var now = DateTime.Now;
            foreach (var rule in ruleSet)
            {
                if (rule.firstMatchTime == null) continue;
                if ((now - rule.firstMatchTime.Value) > TimeSpan.FromSeconds(checkInterval))
                {
                    rule.ResetMatchFlags();
                    if (Config.logLevel == Config.LogLevel.Debug)
                        Console.WriteLine($"[VERBOSE] {now} TimerCheckAndReset: forcibly reset rule '{rule.rulename}' because it exceeded {checkInterval}s without a new matching event.");
                }
            }
        }

        /// <summary>
        /// Determines if the given event matches the given RuleItem (based on target and ruletype).
        /// Returns a tuple with a string describing the match details if matched, and the associated process ID.
        /// </summary>
        /// <param name="data">The trace event data.</param>
        /// <param name="item">The rule item to evaluate.</param>
        /// <param name="args">The command-line arguments.</param>
        /// <returns>A tuple (match detail, process ID), or (null, 0) if not matched.</returns>
        private static (string? detail, int pid) IsMatched(TraceEvent data, RuleItem item, string[] args)
        {
            if (!IsCategoryEnabled(item.target, args))
                return (null, 0);

            string? detail = null;
            string? processName = null;
            int pid = 0;
            switch (item.target)
            {
                case "file":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-File")
                    {
                        int id = (int)data.ID;
                        if (id == 10 || id == 12 || id == 30)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string fileName = data.PayloadStringByName("FileName", null) ?? "";
                            if (item.ruletype == "regex" && Regex.IsMatch(fileName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' fileName='{fileName}' matched against /{item.rule}/";
                            }
                            else if (item.ruletype == "binary" && MatchBinary(fileName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' fileName='{fileName}' matched binary pattern {item.rule}";
                            }
                        }
                    }
                    break;
                case "delfile":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-File" && (int)data.ID == 11)
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string fileName = data.PayloadStringByName("FileName", null) ?? "";
                        if (item.ruletype == "regex" && Regex.IsMatch(fileName, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' fileName='{fileName}' matched against /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(fileName, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' fileName='{fileName}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "process":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Process" && (int)data.ID == 1)
                    {
                        // Try multiple possible field names for the image name
                        string imageName = data.PayloadStringByName("ImageName", null) ?? ""; // For some reason ImageName becomes null
                        int ProcessID = (int)data.PayloadByName("ProcessID");
                        
                        // If we still don't have the image name, try to get it from the Process API
                        if (string.IsNullOrEmpty(imageName) && ProcessID > 0)
                        {
                            try
                            {
                                using (var process = System.Diagnostics.Process.GetProcessById(ProcessID))
                                {
                                    imageName = process.MainModule?.FileName ?? "";
                                }
                            }
                            catch (ArgumentException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Invalid process ID {ProcessID}: {ex.Message}");
                            }
                            catch (InvalidOperationException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Process operation error for PID {ProcessID}: {ex.Message}");
                            }
                            catch (System.ComponentModel.Win32Exception ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Win32 error accessing process {ProcessID}: {ex.Message}");
                            }
                            catch (System.Security.SecurityException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Security error accessing process {ProcessID}: {ex.Message}");
                            }
                            catch (System.IO.FileNotFoundException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Process module file not found for PID {ProcessID}: {ex.Message}");
                            }
                        }
                        
                        // Debug output for troubleshooting
                        if (Config.logLevel == Config.LogLevel.Debug)
                            Console.WriteLine($"[VERBOSE] Process creation - PID: {ProcessID}, Image: {imageName}");
                            
                        if (item.ruletype == "regex" && Regex.IsMatch(imageName, item.rule))
                        {
                            detail = $"ProcessID='{ProcessID}' imageName='{imageName}' matched against /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(imageName, item.rule))
                        {
                            detail = $"ProcessID='{ProcessID}' imageName='{imageName}' matched binary pattern {item.rule}";
                        }
                        if (ProcessID != 0)
                        {
                            pid = ProcessID;
                        }
                    }
                    break;
                case "dll":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Process" && (int)data.ID == 5)
                    {
                        string imageName = data.PayloadStringByName("ImageName", null) ?? "";
                        int ProcessID = (int)data.PayloadByName("ProcessID");
                        processName = data.ProcessName ?? "";
                        if (item.ruletype == "regex" && Regex.IsMatch(imageName, item.rule))
                        {
                            detail = $"ProcessID='{ProcessID}' ProcessName='{processName}' dllName='{imageName}' matched against /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(imageName, item.rule))
                        {
                            detail = $"ProcessID='{ProcessID}' ProcessName='{processName}' dllName='{imageName}' matched binary pattern {item.rule}";
                        }
                        if (ProcessID != 0)
                        {
                            pid = ProcessID;
                        }
                    }
                    break;
                case "registry":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Registry")
                    {
                        int id = (int)data.ID;
                        if (id == 1 || id == 2 || id == 3 || id == 4)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string relativeName = data.PayloadStringByName("RelativeName", null) ?? "";
                            if (item.ruletype == "regex" && Regex.IsMatch(relativeName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' relativeName='{relativeName}' matched /{item.rule}/ (create/open)";
                            }
                            else if (item.ruletype == "binary" && MatchBinary(relativeName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' relativeName='{relativeName}' matched binary pattern {item.rule} (create/open)";
                            }
                        }
                        else if (id == 5 || id == 6 || id == 7)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string valueName = data.PayloadStringByName("ValueName", null) ?? "";
                            string keyName = data.PayloadStringByName("KeyName", null) ?? "";
                            if (item.ruletype == "regex" && (Regex.IsMatch(valueName, item.rule) || Regex.IsMatch(keyName, item.rule)))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' keyName='{keyName}' valueName='{valueName}' matched /{item.rule}/ (setvalue/query)";
                            }
                            else if (item.ruletype == "binary" && (MatchBinary(valueName, item.rule) || MatchBinary(keyName, item.rule)))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' keyName='{keyName}' valueName='{valueName}' matched binary pattern {item.rule} (setvalue/query)";
                            }
                        }
                    }
                    break;
                case "dns":
                    if (data.ProviderName == "Microsoft-Windows-DNS-Client")
                    {
                        int id = (int)data.ID;
                        if (id >= 3000 && id <= 3020)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string qName = data.PayloadStringByName("QueryName", null) ?? "";
                            if (item.ruletype == "regex" && Regex.IsMatch(qName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' DNS Query='{qName}' matched /{item.rule}/";
                            }
                            else if (item.ruletype == "binary" && MatchBinary(qName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' DNS Query='{qName}' matched binary pattern {item.rule}";
                            }
                        }
                    }
                    else if (data.ProviderName == "Microsoft-Windows-WinINet-Capture")
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string payload = Encoding.UTF8.GetString((byte[])data.PayloadByName("Payload") ?? Array.Empty<byte>());
                        if (item.ruletype == "regex" && Regex.IsMatch(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "ipv4":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Network")
                    {
                        int id = (int)data.ID;
                        if (id <= 16 || id == 18 || id == 42 || id == 43)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            var daddr = data.PayloadByName("daddr") ?? 0;
                            var saddr = data.PayloadByName("saddr") ?? 0;
                            if (IPAddress.TryParse(item.rule, out IPAddress? ruleIp))
                            {
                                var daddrIp = UInt32ToIPAddress(daddr);
                                var saddrIp = UInt32ToIPAddress(saddr);
                                if (daddrIp.Equals(ruleIp))
                                {
                                    detail = $"ProcessID='{pid}' ProcessName='{processName}' Network SorceIP='{saddrIp}' -> DestIP='{daddrIp}' matched rule='{ruleIp}'";
                                }
                            }
                        }
                    }
                    else if (data.ProviderName == "Microsoft-Windows-WinINet-Capture")
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string payload = Encoding.UTF8.GetString((byte[])data.PayloadByName("Payload") ?? Array.Empty<byte>());
                        if (item.ruletype == "regex" && Regex.IsMatch(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "ipv6":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Network")
                    {
                        int id = (int)data.ID;
                        if (id == 17 || id == 58 || id == 59 || (id >= 26 && id <= 34))
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            var daddrv6 = data.PayloadByName("daddr");
                            var saddrv6 = data.PayloadByName("saddr");
                            
                            if (IPAddress.TryParse(item.rule, out IPAddress? ruleIpv6))
                            {
                                if (daddrv6 is byte[] daddrBytes && daddrBytes.Length == 16)
                                {
                                    IPAddress daddrIP = new IPAddress(daddrBytes);
                                    if (daddrIP.Equals(ruleIpv6))
                                    {
                                        string saddrStr = "Unknown";
                                        if (saddrv6 is byte[] saddrBytes && saddrBytes.Length == 16)
                                        {
                                            IPAddress saddrIP = new IPAddress(saddrBytes);
                                            saddrStr = saddrIP.ToString();
                                        }
                                        detail = $"ProcessID='{pid}' ProcessName='{processName}' Network IPv6 Source='{saddrStr}' -> Dest='{daddrIP}' matched rule='{ruleIpv6}'";
                                    }
                                }
                                else if (saddrv6 is byte[] saddrBytes && saddrBytes.Length == 16)
                                {
                                    IPAddress saddrIP = new IPAddress(saddrBytes);
                                    if (saddrIP.Equals(ruleIpv6))
                                    {
                                        string daddrStr = "Unknown";
                                        if (daddrv6 is byte[] destBytes && destBytes.Length == 16)
                                        {
                                            IPAddress daddrIP = new IPAddress(destBytes);
                                            daddrStr = daddrIP.ToString();
                                        }
                                        detail = $"ProcessID='{pid}' ProcessName='{processName}' Network IPv6 Source='{saddrIP}' -> Dest='{daddrStr}' matched rule='{ruleIpv6}'";
                                    }
                                }
                            }
                        }
                    }
                    else if (data.ProviderName == "Microsoft-Windows-WinINet-Capture")
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string payload = Encoding.UTF8.GetString((byte[])data.PayloadByName("Payload") ?? Array.Empty<byte>());
                        if (item.ruletype == "regex" && Regex.IsMatch(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(payload, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' WinINet payload='{Truncate(payload, 50)}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "powershell":
                    if (data.ProviderName == "Microsoft-Windows-PowerShell" && (int)data.ID == 4104)
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string scriptText = data.PayloadStringByName("ScriptBlockText", null) ?? "";
                        if (item.ruletype == "regex" && Regex.IsMatch(scriptText, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' PowerShell script='{Truncate(scriptText, 50)}' matched /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(scriptText, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' PowerShell script='{Truncate(scriptText, 50)}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "shell":
                    if (data.ProviderName == "Microsoft-Windows-Shell-Core")
                    {
                        int sid = (int)data.ID;
                        // Wrire all data to Console
                        Console.WriteLine($"[DEBUG] {data.ProviderName} {sid} {data.ProcessID} {data.ProcessName} {data.PayloadStringByName("Command", null)}");
                        if (sid == 28115)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string shortcutName = data.PayloadStringByName("Name", null) ?? "";
                            if (item.ruletype == "regex" && Regex.IsMatch(shortcutName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' shortcutName='{shortcutName}' matched /{item.rule}/";
                            }
                            else if (item.ruletype == "binary" && MatchBinary(shortcutName, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' shortcutName='{shortcutName}' matched binary pattern {item.rule}";
                            }
                        }
                        if (sid == 9707)
                        {
                            pid = data.ProcessID;
                            processName = data.ProcessName ?? "";
                            string command = data.PayloadStringByName("Command", null) ?? "";
                            if (item.ruletype == "regex" && Regex.IsMatch(command, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' RunKey command='{command}' matched /{item.rule}/";
                            }
                            else if (item.ruletype == "binary" && MatchBinary(command, item.rule))
                            {
                                detail = $"ProcessID='{pid}' ProcessName='{processName}' RunKey command='{command}' matched binary pattern {item.rule}";
                            }
                        }
                    }
                    break;
                case "wmi":
                    if (data.ProviderName == "Microsoft-Windows-WMI-Activity" && (int)data.ID <= 50) //(int)data.ID == 11
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string Operation = data.PayloadStringByName("Operation", null) ?? "";
                        string namespaceName = data.PayloadStringByName("NamespaceName", null) ?? "";
                        string user = data.PayloadStringByName("User", null) ?? "";
                        string machineName = data.PayloadStringByName("ClientMachine", null) ?? "";
                        if (item.ruletype == "regex" && Regex.IsMatch(Operation, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' Operation='{Operation}', Namespace='{namespaceName}', user='{user}', machine='{machineName}' matched /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(Operation, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' Operation='{Operation}', Namespace='{namespaceName}', user='{user}', machine='{machineName}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
                case "open":
                    if (data.ProviderName == "Microsoft-Windows-Kernel-Audit-API-Calls" && (int)data.ID == 5)
                    {
                        pid = data.ProcessID;
                        processName = data.ProcessName ?? "";
                        string imageName = "";
                        int ProcessID = (int)data.PayloadByName("TargetProcessId");

                        // If we still don't have the image name, try to get it from the Process API
                        if (ProcessID > 0)
                        {
                            try
                            {
                                using (var process = System.Diagnostics.Process.GetProcessById(ProcessID))
                                {
                                    imageName = process.MainModule?.FileName ?? "";
                                }
                            }
                            catch (ArgumentException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Invalid process ID {ProcessID}: {ex.Message}");
                            }
                            catch (InvalidOperationException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Process operation error for PID {ProcessID}: {ex.Message}");
                            }
                            catch (System.ComponentModel.Win32Exception ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Win32 error accessing process {ProcessID}: {ex.Message}");
                            }
                            catch (System.Security.SecurityException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Security error accessing process {ProcessID}: {ex.Message}");
                            }
                            catch (System.IO.FileNotFoundException ex)
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                    Console.WriteLine($"[VERBOSE] Process module file not found for PID {ProcessID}: {ex.Message}");
                            }
                        }

                        if (item.ruletype == "regex" && Regex.IsMatch(imageName, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' OpenedProcessImage='{imageName}' matched against /{item.rule}/";
                        }
                        else if (item.ruletype == "binary" && MatchBinary(imageName, item.rule))
                        {
                            detail = $"ProcessID='{pid}' ProcessName='{processName}' OpenedProcessImage='{imageName}' matched binary pattern {item.rule}";
                        }
                    }
                    break;
            }
            return (detail, pid);
        }

        /// <summary>
        /// Checks if the data contains the specified binary pattern (partial match).
        /// The pattern is expected to be a space-separated hexadecimal string with optional wildcards (??).
        /// This method performs a partial match - the pattern can be found anywhere within the data.
        /// </summary>
        /// <param name="data">The data to check.</param>
        /// <param name="pattern">The binary pattern in hex format (e.g. "48 65 6C 6C 6F" or "48 ?? 6C ?? 6F").</param>
        /// <returns>True if the data contains the pattern anywhere; otherwise, false.</returns>
        private static bool MatchBinary(string data, string pattern)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(pattern))
                return false;

            // Convert data to byte array
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            
            // Parse the pattern
            string[] patternParts = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            List<byte?> patternBytes = new List<byte?>();
            
            foreach (var part in patternParts)
            {
                if (part == "??")
                {
                    patternBytes.Add(null); // null represents a wildcard
                }
                else if (byte.TryParse(part, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b))
                {
                    patternBytes.Add(b);
                }
                else
                {
                    return false; // Invalid pattern
                }
            }
            
            // If the pattern is longer than the data, it can't match
            if (patternBytes.Count > dataBytes.Length)
                return false;
            
            // Check for matches at any position in the data (partial match)
            for (int i = 0; i <= dataBytes.Length - patternBytes.Count; i++)
            {
                bool match = true;
                for (int j = 0; j < patternBytes.Count; j++)
                {
                    byte? patternByte = patternBytes[j];
                    // Skip comparison for wildcards (null values)
                    if (patternByte.HasValue && dataBytes[i + j] != patternByte.Value)
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return true; // Found a match at position i
            }
            
            return false;
        }

        /// <summary>
        /// Checks if detection is enabled for the specified target.
        /// </summary>
        /// <param name="target">The detection target (e.g. file, process, etc.).</param>
        /// <param name="args">The command-line arguments.</param>
        /// <returns>True if detection is enabled; otherwise, false.</returns>
        private static bool IsCategoryEnabled(string target, string[] args)
        {
            if (args.Contains("--all") || args.Contains("-a"))
                return true;
            switch (target)
            {
                case "file":
                    return (args.Contains("--file") || args.Contains("-f"));
                case "delfile":
                    return (args.Contains("--delfile") || args.Contains("-df"));
                case "process":
                    return (args.Contains("--process") || args.Contains("-p"));
                case "dll":
                    return (args.Contains("--dll") || args.Contains("-d"));
                case "registry":
                    return (args.Contains("--registry") || args.Contains("-r"));
                case "dns":
                    return (args.Contains("--dns") || args.Contains("-n"));
                case "ipv4":
                    return (args.Contains("--ipv4") || args.Contains("-i"));
                case "ipv6":
                    return (args.Contains("--ipv6") || args.Contains("-i6"));
                case "powershell":
                    return (args.Contains("--powershell") || args.Contains("-ps1"));
                case "wmi":
                    return (args.Contains("--wmi") || args.Contains("-w"));
                case "shell":
                    return (args.Contains("--shell") || args.Contains("-sh"));
                case "oepn":
                    return (args.Contains("--open") || args.Contains("-o"));
                default:
                    return false;
            }
        }

        /// <summary>
        /// Loads YAML rule files and initializes matched flags.
        /// </summary>
        /// <param name="folder">The folder containing YAML rule files.</param>
        /// <returns>A list of Rule objects.</returns>
        private static List<Rule> LoadDetectionRules(string folder)
        {
            var ruleSets = new List<Rule>();
            var yamlFiles = Directory.GetFiles(folder, "*.yaml", SearchOption.AllDirectories);
            if (yamlFiles.Length == 0)
            {
                yamlFiles = Directory.GetFiles(folder, "*.yml", SearchOption.AllDirectories);
            }
            if (yamlFiles.Length == 0)
            {
                throw new FileNotFoundException("[ERROR] No YAML rule files found in folder: " + folder);
            }
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
            
            int errorCount = 0;
            foreach (string filePath in yamlFiles)
            {
                try
                {
                    Console.WriteLine("[INFO] Loading detection rules from " + filePath);
                    string yamlContent = File.ReadAllText(filePath);
                    Rule? ruleObj = deserializer.Deserialize<Rule>(yamlContent);
                    if (ruleObj != null)
                    {
                        ruleObj.InitializeMatchedFlags();
                        ruleSets.Add(ruleObj);
                    }
                    else
                    {
                        Console.WriteLine($"[WARNING] Rule file '{filePath}' deserialized to null.");
                    }
                }
                catch (IOException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load rule file '{filePath}' (IO error): {ex.Message}");
                }
                catch (YamlDotNet.Core.YamlException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load rule file '{filePath}' (YAML parsing error): {ex.Message}");
                }
                catch (ArgumentException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load rule file '{filePath}' (argument error): {ex.Message}");
                }
                catch (InvalidOperationException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load rule file '{filePath}' (invalid operation): {ex.Message}");
                }
                // 予期しない例外は再スロー
            }
            
            Console.WriteLine($"[INFO] Successfully loaded {ruleSets.Count} rules. (Skipped {errorCount} files with errors)");
            return ruleSets;
        }

        /// <summary>
        /// Loads SIGMA rule files using SigmaDetector.
        /// </summary>
        /// <param name="folder">The folder containing SIGMA rule files.</param>
        /// <returns>A list of SigmaRule objects.</returns>
        private static List<SigmaRule> LoadSigmaRules(string folder)
        {
            // Call the static method from SigmaDetector.
            return SigmaDetector.LoadSigmaRules(folder);
        }

        /// <summary>
        /// Utility method to truncate a string for verbose logs.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="maxLen">Maximum length.</param>
        /// <returns>Truncated string if needed.</returns>
        private static string Truncate(string input, int maxLen)
        {
            if (input.Length <= maxLen) return input;
            return string.Concat(input.AsSpan(0, maxLen), "...(truncated)");
        }

        /// <summary>
        /// Dispose pattern to clean up timer resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose pattern implementation.
        /// </summary>
        /// <param name="disposing">Indicates whether managed resources should be disposed.</param>
        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                _resetTimer?.Dispose();
                
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = false;
                    
                    _fileWatcher.Created -= ReloadDefaultRules;
                    _fileWatcher.Changed -= ReloadDefaultRules;
                    _fileWatcher.Created -= ReloadSigmaRules;
                    _fileWatcher.Changed -= ReloadSigmaRules;
                    _fileWatcher.Created -= ReloadYaraRules;
                    _fileWatcher.Changed -= ReloadYaraRules;
                    
                    _fileWatcher.Dispose();
                    _fileWatcher = null;
                }
                
                if (_yaraCancellationSource != null)
                {
                    _yaraCancellationSource.Cancel();
                    _yaraCancellationSource.Dispose();
                    _yaraCancellationSource = null;
                }
                
                if (_yaraMemoryScanThread != null && _yaraMemoryScanThread.IsAlive)
                {
                    _yaraMemoryScanThread.Join(3000);
                    _yaraMemoryScanThread = null;
                }
            }
        }
    }
}
