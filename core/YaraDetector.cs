using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Timers;

namespace YAMAGoya.Core
{
    static class YaraDetector
    {

        public static string LoadYaraRules(string folder)
        {
            string[] yaraFiles = Directory.GetFiles(folder, "*.yar*");
            StringBuilder ruleContent = new StringBuilder();
            
            foreach (string file in yaraFiles)
            {
                try
                {
                    Console.WriteLine($"[INFO] Loading YARA rule file: {file}");
                    string fileContent = File.ReadAllText(file);
                    
                    if (string.IsNullOrWhiteSpace(fileContent))
                    {
                        Console.WriteLine($"[ERROR] Empty YARA rule file: {file}");
                        continue;
                    }
                    
                    // CA1307対応: StringComparisonを使用
                    if (!fileContent.Contains("rule ", StringComparison.Ordinal))
                    {
                        Console.WriteLine($"[ERROR] File may not contain valid YARA rules: {file}");
                    }
                    
                    ruleContent.Append(fileContent);
                    ruleContent.Append("\n\n");
                }
                catch (FileNotFoundException ex)
                {
                    Console.WriteLine($"[ERROR] YARA rule file not found {file}: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine($"[ERROR] Access denied to YARA rule file {file}: {ex.Message}");
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"[ERROR] IO error reading YARA rule file {file}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Unexpected error loading YARA rule file {file}: {ex.Message}");
                    throw;
                }
            }
            
            return ruleContent.ToString();
        }

        private static readonly object scanLock = new object();
        private static System.Timers.Timer? memoryScanTimer;

        public static void StartMemoryScanTimer(string ruleString)
        {
            int result = 0;
            double intervalMs = Config.memoryScanInterval * 3600000;
            
            memoryScanTimer?.Dispose();
            
            memoryScanTimer = new System.Timers.Timer(intervalMs);
            memoryScanTimer.Elapsed += (sender, e) =>
            {
                Console.WriteLine("[INFO] Memory scan started.");
                lock (scanLock)
                {
                    try
                    {
                        using (var yamaDll = new YamaDllWrapper())
                        {
                            result = yamaDll.ScanMemory(ruleString);
                        }
                    }
                    catch (InvalidOperationException ex)
                    {
                        Console.WriteLine($"[ERROR] Invalid operation during MemoryScan: {ex.Message}");
                    }
                    catch (DllNotFoundException ex)
                    {
                        Console.WriteLine($"[ERROR] DLL not found: {ex.Message}");
                    }
                    catch (EntryPointNotFoundException ex)
                    {
                        Console.WriteLine($"[ERROR] Entry point not found: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Unhandled exception during MemoryScan: {ex.Message}");
                        throw;
                    }
                }
            };
            memoryScanTimer.AutoReset = true;
            
            // first scan immediately
            Console.WriteLine("[INFO] Performing initial memory scan.");
            lock (scanLock)
            {
                try
                {
                    using (var yamaDll = new YamaDllWrapper())
                    {
                        result = yamaDll.ScanMemory(ruleString);
                    }
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine($"[ERROR] Invalid operation during initial MemoryScan: {ex.Message}");
                    return;
                }
                catch (DllNotFoundException ex)
                {
                    Console.WriteLine($"[ERROR] DLL not found: {ex.Message}");
                    return;
                }
                catch (EntryPointNotFoundException ex)
                {
                    Console.WriteLine($"[ERROR] Entry point not found: {ex.Message}");
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Unhandled exception during initial MemoryScan: {ex.Message}");
                    throw;
                }
            }
            
            memoryScanTimer.Start();
            Console.WriteLine($"[INFO] Memory scan timer started with interval {Config.memoryScanInterval} hour(s).");
        }

        public static void StopMemoryScanTimer()
        {
            memoryScanTimer?.Stop();
            memoryScanTimer?.Dispose();
            memoryScanTimer = null;
            Console.WriteLine("[INFO] Memory scan timer stopped.");
        }
    }
}
