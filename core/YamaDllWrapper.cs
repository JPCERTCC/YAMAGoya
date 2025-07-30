using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace YAMAGoya.Core
{
    internal sealed class YamaDllWrapper : IDisposable
    {
        private sealed class DetectionResult
        {
            public string? Rule { get; set; }
            public string? ProcessId { get; set; }
            public string? ProcessName { get; set; }
            public string? ImagePath { get; set; }
        }

        // Specify the absolute path to the DLL
        private static string GetDllPath()
        {
            string dllName = "YAMA.dll";
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string dllPath = Path.Combine(currentDir, dllName);
            
            // Convert to absolute path to prevent relative path attacks
            dllPath = Path.GetFullPath(dllPath);
            
            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException($"DLL not found: {dllPath}");
            }
            
            string expectedDir = Path.GetFullPath(currentDir.TrimEnd('\\'));
            string actualDir = Path.GetFullPath(Path.GetDirectoryName(dllPath) ?? "");
            
            if (!actualDir.Equals(expectedDir, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException($"[SECURITY] DLL path traversal detected. Expected: {expectedDir}, Actual: {actualDir}");
            }
            
            // Verify SHA256 hash to prevent DLL side-loading attacks
            if (!VerifyDllIntegrity(dllPath))
            {
                throw new UnauthorizedAccessException($"[SECURITY] DLL integrity verification failed. Potential DLL hijacking detected: {dllPath}");
            }
            
            // Output the DLL path to log for confirmation
            Console.WriteLine($"[INFO] DLL Path: {dllPath}");
            Console.WriteLine($"[INFO] DLL integrity verified successfully");
            return dllPath;
        }

        // DLL import settings
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern IntPtr LoadLibraryEx(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName, 
            IntPtr hFile, 
            uint dwFlags);

        private const uint LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010;
        private const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, 
                   BestFitMapping = false, ThrowOnUnmappableChar = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, 
                                                   [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        // Delegate definition - modified marshaling directives
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate int MemoryScanDelegate(
            [MarshalAs(UnmanagedType.LPStr)] string ruleString, 
            out IntPtr result);

        private IntPtr _dllHandle = IntPtr.Zero;
        private IntPtr _funcHandle = IntPtr.Zero;
        private MemoryScanDelegate? _memoryScan;
        private IntPtr _resultPtr = IntPtr.Zero;
        private bool _disposed;

        ~YamaDllWrapper()
        {
            Dispose(false);
        }

        public YamaDllWrapper()
        {
            try
            {
                string dllPath = GetDllPath();
                
                uint secureFlags = LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_IGNORE_CODE_AUTHZ_LEVEL;
                
                _dllHandle = LoadLibraryEx(dllPath, IntPtr.Zero, secureFlags);
                
                // If secure flags fail (older Windows versions), fallback to basic security
                if (_dllHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[WARNING] Secure DLL loading flags not supported, falling back to basic mode");
                    
                    // Use only LOAD_IGNORE_CODE_AUTHZ_LEVEL for older Windows versions
                    _dllHandle = LoadLibraryEx(dllPath, IntPtr.Zero, LOAD_IGNORE_CODE_AUTHZ_LEVEL);
                }
                
                if (_dllHandle == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    throw new DllNotFoundException($"[ERROR] Failed to load DLL: {dllPath}, Error code: {errorCode}");
                }
                                
                _funcHandle = GetProcAddress(_dllHandle, "MemoryScan");
                if (_funcHandle == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    throw new EntryPointNotFoundException($"[ERROR] Function 'MemoryScan' not found, Error code: {errorCode}");
                }

                // Create delegate
                _memoryScan = Marshal.GetDelegateForFunctionPointer<MemoryScanDelegate>(_funcHandle);
            }
            catch (MarshalDirectiveException ex)
            {
                Console.WriteLine($"[ERROR] Marshaling directive error: {ex.Message}");
                Dispose(true);
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] YamaDllWrapper initialization exception: {ex.Message}");
                Dispose(true);
                throw;
            }
        }

        public int ScanMemory(string yaraRule)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            
            if (_memoryScan == null)
                throw new InvalidOperationException("DLL function is not properly initialized");

            FreeResultPtr(); // Release previous pointer

            using (var Logger = new DualLogger())
            {
                try
                {
                    // Use custom marshaler to safely pass string to C++
                    string safeYaraRule = string.IsNullOrEmpty(yaraRule) ? string.Empty : yaraRule;
                    IntPtr resultPtr = IntPtr.Zero;
                    int success = 0;
                    string consoleOutput = string.Empty;
                    
                    // Guard process to more safely call the DLL
                    AppDomain.CurrentDomain.UnhandledException += (sender, e) => 
                    {
                        Console.WriteLine($"[ERROR] Unhandled exception: {e.ExceptionObject}");
                    };
                    
                    var stdoutCapture = Console.Out;
                    using var captureWriter = new StringWriter();
                    Console.SetOut(captureWriter);
                    
                    // DLL function call - catch extreme exceptions (CA1031 compliance)
                    try
                    {
                        success = _memoryScan(safeYaraRule, out resultPtr);
                    }
                    catch (SEHException ex) // Structured exception from native code
                    {
                        Console.SetOut(stdoutCapture);
                        Console.WriteLine($"[ERROR] Native code exception: {ex.Message}");
                        return -1;
                    }
                    catch (AccessViolationException ex) // Memory access violation
                    {
                        Console.SetOut(stdoutCapture);
                        Console.WriteLine($"[ERROR] Memory access violation: {ex.Message}");
                        return -1;
                    }
                    catch (MarshalDirectiveException ex) // Marshaling error
                    {
                        Console.SetOut(stdoutCapture);
                        Console.WriteLine($"[ERROR] Marshaling error: {ex.Message}");
                        return -1;
                    }
                    
                    consoleOutput = captureWriter.ToString();
                    Console.SetOut(stdoutCapture);
                                        
                    // Verify result
                    if (resultPtr == IntPtr.Zero)
                    {
                        Console.WriteLine("[ERROR] Return pointer is null");
                        return -2;
                    }
                    
                    // Store pointer in class member to protect from GC
                    _resultPtr = resultPtr;
                    
                    string? result;
                    // String conversion safety (CA1031 compliance)
                    try
                    {
                        result = Marshal.PtrToStringAnsi(_resultPtr);
                    }
                    catch (AccessViolationException ex) // Memory access violation
                    {
                        Console.WriteLine($"[ERROR] Memory access violation during string conversion: {ex.Message}");
                        return -2;
                    }
                    catch (ArgumentException ex) // Invalid argument
                    {
                        Console.WriteLine($"[ERROR] Argument error during string conversion: {ex.Message}");
                        return -2;
                    }
                    catch (SEHException ex) // Exception from native code
                    {
                        Console.WriteLine($"[ERROR] Native exception during string conversion: {ex.Message}");
                        return -2;
                    }

                    if (success > 0)
                    {
                        var detections = new List<DetectionResult>();
                        
                        if (!string.IsNullOrEmpty(result))
                        {
                            var matchRulePattern = new Regex(@"Matched Rules\s*:\s*(\w+)");
                            var matchPidPattern = new Regex(@"Process ID\s*:\s*(\d+)");
                            var matchProcessNamePattern = new Regex(@"Process Name\s*:\s*([\w\.\-]+)");
                            var matchImagePathPattern = new Regex(@"Image Path\s*:\s*([\w\.\-\\:]+)");
                            
                            var matchesRule = matchRulePattern.Matches(result);
                            var matchesPid = matchPidPattern.Matches(result);
                            var matchesProcessName = matchProcessNamePattern.Matches(result);
                            var matchesImagePath = matchImagePathPattern.Matches(result);
                            
                            int maxCount = Math.Max(
                                Math.Max(matchesRule.Count, matchesPid.Count),
                                Math.Max(matchesProcessName.Count, matchesImagePath.Count)
                            );
                            
                            for (int i = 0; i < maxCount; i++)
                            {
                                var detection = new DetectionResult();
                                
                                if (i < matchesRule.Count && matchesRule[i].Groups.Count > 1)
                                    detection.Rule = matchesRule[i].Groups[1].Value;
                                
                                if (i < matchesPid.Count && matchesPid[i].Groups.Count > 1)
                                    detection.ProcessId = matchesPid[i].Groups[1].Value;
                                
                                if (i < matchesProcessName.Count && matchesProcessName[i].Groups.Count > 1)
                                    detection.ProcessName = matchesProcessName[i].Groups[1].Value;
                                
                                if (i < matchesImagePath.Count && matchesImagePath[i].Groups.Count > 1)
                                    detection.ImagePath = matchesImagePath[i].Groups[1].Value;
                                
                                detections.Add(detection);
                            }
                        }
                        
                        if (detections.Count == 0)
                        {
                            Console.WriteLine($"[INFO] Memory scan result: {result}");
                            Logger.Log($"Memory scan result: {result}", Config.LogLevel.Info);
                        }
                        else
                        {
                            Console.WriteLine($"[INFO] Found {detections.Count} detection(s):");
                            Logger.Log($"Found {detections.Count} detection(s):", Config.LogLevel.Info);
                            
                            for (int i = 0; i < detections.Count; i++)
                            {
                                var detection = detections[i];
                                Console.WriteLine($"[INFO] === Detection on memory {i+1} ===");
                                Console.WriteLine($"[INFO] Matched Rule: {detection.Rule}");
                                Console.WriteLine($"[INFO] Process ID: {detection.ProcessId}");
                                Console.WriteLine($"[INFO] Process Name: {detection.ProcessName}");
                                Console.WriteLine($"[INFO] Image Path: {detection.ImagePath}");
                                
                                Logger.Log($"=== Detection on memory {i+1} ===", Config.LogLevel.Info);
                                Logger.Log($"Matched Rule: {detection.Rule}", Config.LogLevel.Info);
                                Logger.Log($"Process ID: {detection.ProcessId}", Config.LogLevel.Info);
                                Logger.Log($"Process Name: {detection.ProcessName}", Config.LogLevel.Info);
                                Logger.Log($"Image Path: {detection.ImagePath}", Config.LogLevel.Info);
                            }
                        }
                        
                        return 1;
                    } else if (success < 0) {
                        Console.WriteLine($"[ERROR] Memory scan failed with code: {success}");
                        Logger.Log($"Memory scan failed with code: {success}", Config.LogLevel.Error);
                        return -1;
                    } else {
                        Console.WriteLine($"[INFO] Memory scan completed with no matches.");
                        Logger.Log("Memory scan completed with no matches.", Config.LogLevel.Info);
                        return 0;
                    }
                }
                catch (SEHException ex)
                {
                    Console.WriteLine($"[ERROR] Native exception: {ex.Message}");
                    return -3;
                }
                catch (MarshalDirectiveException ex)
                {
                    Console.WriteLine($"[ERROR] Marshaling exception: {ex.Message}");
                    return -3;
                }
                catch (OutOfMemoryException ex)
                {
                    Console.WriteLine($"[ERROR] Out of memory exception: {ex.Message}");
                    return -3;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Unexpected exception: {ex.Message}");
                    Console.WriteLine($"[ERROR] Stack trace: {ex.StackTrace}");
                    throw; // Throw unexpected exceptions
                }
            }
        }

        private void FreeResultPtr()
        {
            if (_resultPtr != IntPtr.Zero)
            {
                try
                {
                    Marshal.FreeCoTaskMem(_resultPtr);
                }
                catch (AccessViolationException ex) 
                {
                    Console.WriteLine($"[ERROR] Access violation while releasing pointer: {ex.Message}");
                }
                catch (SEHException ex) 
                {
                    Console.WriteLine($"[ERROR] Native exception while releasing pointer: {ex.Message}");
                }
                _resultPtr = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    _memoryScan = null;
                    
                    // Unregister any event handlers if added in the future
                    AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
                }
                
                FreeResultPtr();
                
                if (_dllHandle != IntPtr.Zero)
                {
                    try
                    {
                        FreeLibrary(_dllHandle);
                    }
                    catch (SEHException ex)
                    {
                        Console.WriteLine($"[ERROR] Native exception while releasing DLL: {ex.Message}");
                    }
                    catch (AccessViolationException ex)
                    {
                        Console.WriteLine($"[ERROR] Access violation while releasing DLL: {ex.Message}");
                    }
                    _dllHandle = IntPtr.Zero;
                    _funcHandle = IntPtr.Zero;
                    _memoryScan = null;
                }
                
                _disposed = true;
            }
        }

        // Helper method for event handler (to be used if needed)
        private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Console.WriteLine($"[ERROR] Unhandled exception: {e.ExceptionObject}");
        }

        /// <summary>
        /// Verifies the SHA256 hash of the DLL file to prevent DLL side-loading attacks
        /// </summary>
        /// <param name="dllPath">Path to the DLL file to verify</param>
        /// <returns>True if hash matches, false otherwise</returns>
        private static bool VerifyDllIntegrity(string dllPath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var fileStream = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                
                byte[] hashBytes = sha256.ComputeHash(fileStream);
                string actualHash = Convert.ToHexString(hashBytes);
                
                Console.WriteLine($"[INFO] Expected DLL Hash: {Config.yamaDllSha256}");
                Console.WriteLine($"[INFO] Actual DLL Hash: {actualHash}");
                
                bool isValid = string.Equals(Config.yamaDllSha256, actualHash, StringComparison.OrdinalIgnoreCase);
                
                if (!isValid)
                {
                    Console.WriteLine($"[ERROR] DLL hash mismatch detected!");
                    Console.WriteLine($"[ERROR] This could indicate a DLL hijacking attack or corrupted file.");
                }
                
                return isValid;
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine($"[ERROR] DLL file not found during integrity verification: {ex.Message}");
                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[ERROR] Access denied during DLL integrity verification: {ex.Message}");
                return false;
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[ERROR] IO error during DLL integrity verification: {ex.Message}");
                return false;
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"[ERROR] Cryptographic error during DLL integrity verification: {ex.Message}");
                return false;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"[ERROR] Invalid argument during DLL integrity verification: {ex.Message}");
                return false;
            }
        }
    }
}
