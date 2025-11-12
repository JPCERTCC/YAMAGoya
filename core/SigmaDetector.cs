using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Antlr4.Runtime;
using DynamicExpresso;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Responsible for loading and evaluating Sigma rules.
    /// </summary>
    internal static class SigmaDetector
    {
        private static readonly string[] OrSeparators = new[] { "or", "OR" };

        // Mapping from Sigma categories to ETW providers
        private static readonly Dictionary<string, List<(string ProviderName, int[] EventIds)>> CategoryToProviderMapping = new()
        {
            { "create_remote_thread", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Audit-API-Calls", new[] { 5 }) } },
            { "dns_query", new List<(string, int[])> { ("Microsoft-Windows-DNS-Client", Enumerable.Range(3000, 21).ToArray()) } },
            { "file_access", new List<(string, int[])> { ("Microsoft-Windows-Kernel-File", new[] { 10, 12, 30 }) } },
            { "file_event", new List<(string, int[])> { ("Microsoft-Windows-Kernel-File", new[] { 10, 11, 12, 30 }) } },
            { "file_delete", new List<(string, int[])> { ("Microsoft-Windows-Kernel-File", new[] { 11 }) } },
            { "image_load", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Process", new[] { 5 }) } },
            { "network_connection", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Network", new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 42, 43 }) } },
            { "ps_script", new List<(string, int[])> { ("Microsoft-Windows-PowerShell", new[] { 4104 }) } },
            { "process_access", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Process", new[] { 1 }) } },
            { "process_creation", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Process", new[] { 1 }) } },
            { "registry_add", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Registry", new[] { 1 }) } },
            { "registry_delete", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Registry", new[] { 3, 6 }) } },
            { "registry_event", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Registry", new[] { 1, 2, 3, 4, 5, 6, 7 }) } },
            { "registry_set", new List<(string, int[])> { ("Microsoft-Windows-Kernel-Registry", new[] { 5 }) } },
            { "wmi_event", new List<(string, int[])> { ("Microsoft-Windows-WMI-Activity", Enumerable.Range(1, 50).ToArray()) } },
        };

        // Mapping ETW fields to Sigma fields (by category)
        private static readonly Dictionary<string, Dictionary<string, string>> CategoryFieldMapping = new()
        {
            { "process_creation", new Dictionary<string, string>
                {
                    { "Image", "ImageName" },
                    { "OriginalFileName", "OriginalFileName" },
                    { "TargetImage", "ImageName" },
                    { "CommandLine", "CommandLine" },
                    { "ProcessId", "ProcessID" },
                    { "ParentProcessId", "ParentProcessID" },
                    { "ParentImage", "ParentImageName" },
                    { "ParentCommandLine", "ParentCommandLine" },
                    { "CurrentDirectory", "CurrentDirectory" },
                    { "IntegrityLevel", "IntegrityLevel" },
                    { "User", "UserName" },
                    { "LogonId", "LogonID" },
                    { "LogonGuid", "LogonGUID" }
                }
            },
            { "process_access", new Dictionary<string, string>
                {
                    { "Image", "ImageName" },
                    { "OriginalFileName", "OriginalFileName" },
                    { "TargetImage", "ImageName" },
                    { "CommandLine", "CommandLine" },
                    { "ProcessId", "ProcessID" },
                    { "ParentProcessId", "ParentProcessID" },
                    { "ParentImage", "ParentImageName" },
                    { "ParentCommandLine", "ParentCommandLine" },
                    { "CurrentDirectory", "CurrentDirectory" },
                    { "IntegrityLevel", "IntegrityLevel" },
                    { "User", "UserName" },
                    { "LogonId", "LogonID" },
                    { "LogonGuid", "LogonGUID" }
                }
            },
            { "file_access", new Dictionary<string, string>
                {
                    { "TargetFilename", "FileName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "CreationUtcTime", "CreationTime" },
                    { "PreviousCreationUtcTime", "PreviousCreationTime" },
                    { "User", "UserName" }
                }
            },
            { "file_delete", new Dictionary<string, string>
                {
                    { "TargetFilename", "FileName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" }
                }
            },
            { "file_event", new Dictionary<string, string>
                {
                    { "TargetFilename", "FileName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "CreationUtcTime", "CreationTime" },
                    { "User", "UserName" }
                }
            },
            { "registry_event", new Dictionary<string, string>
                {
                    //{ "TargetObject", "RelativeName" },
                    { "Details", "ValueName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "EventType", "EventType" },
                    { "User", "UserName" },
                    { "TargetObject", "KeyName" }, // Supports multiple ETW fields
                    { "NewName", "NewName" }
                }
            },
            { "registry_add", new Dictionary<string, string>
                {
                    { "TargetObject", "RelativeName" },
                    { "Details", "ValueName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" }
                }
            },
            { "registry_delete", new Dictionary<string, string>
                {
                    { "TargetObject", "RelativeName" },
                    { "Details", "ValueName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" }
                }
            },
            { "registry_set", new Dictionary<string, string>
                {
                    { "TargetObject", "RelativeName" },
                    { "Details", "ValueName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" }
                }
            },
            { "dns_query", new Dictionary<string, string>
                {
                    { "QueryName", "QueryName" },
                    { "QueryResults", "QueryResults" },
                    { "QueryStatus", "QueryStatus" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" }
                }
            },
            { "network_connection", new Dictionary<string, string>
                {
                    { "DestinationIp", "daddr" },
                    { "SourceIp", "saddr" },
                    { "DestinationPort", "dport" },
                    { "SourcePort", "sport" },
                    { "Protocol", "proto" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" },
                    { "DestinationHostname", "DestinationHostname" }
                }
            },
            { "ps_script", new Dictionary<string, string>
                {
                    { "ScriptBlockText", "ScriptBlockText" },
                    { "ScriptBlockId", "ScriptBlockId" },
                    { "Path", "Path" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "User", "UserName" }
                }
            },
            { "image_load", new Dictionary<string, string>
                {
                    { "ImageLoaded", "ImageName" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ParentImageName" },
                    { "OriginalFileName", "OriginalFileName" },
                    { "Signed", "Signed" },
                    { "Signature", "Signature" },
                    { "User", "UserName" }
                }
            },
            { "create_remote_thread", new Dictionary<string, string>
                {
                    { "SourceProcessId", "ProcessID" },
                    { "SourceImage", "ImageName" },
                    { "TargetProcessId", "TargetProcessId" },
                    { "TargetImage", "TargetImage" },
                    { "StartAddress", "StartAddress" },
                    { "StartModule", "StartModule" },
                    { "StartFunction", "StartFunction" },
                    { "User", "UserName" }
                }
            },
            { "wmi_event", new Dictionary<string, string>
                {
                    { "Operation", "Operation" },
                    { "User", "User" },
                    { "Query", "Query" },
                    { "ProcessId", "ProcessID" },
                    { "Image", "ImageName" },
                    { "EventNamespace", "Namespace" },
                    { "EventType", "EventType" },
                    { "DestinationHostname", "DestinationHostname" }
                }
            }
        };

        /// <summary>
        /// Loads Sigma rule files from the specified folder, normalizing selectors.
        /// </summary>
        /// <param name="folder">Folder path containing Sigma rule files (YAML files).</param>
        /// <returns>List of SigmaRule objects.</returns>
        public static List<SigmaRule> LoadSigmaRules(string folder)
        {
            var yamlFiles = Directory.GetFiles(folder, "*.yaml", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(folder, "*.yml", SearchOption.AllDirectories)).ToArray();

            if (yamlFiles.Length == 0)
                throw new InvalidOperationException("[ERROR] No Sigma rule files found in folder: " + folder);

            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            var serializer = new SerializerBuilder().Build();

            var sigmaRules = new List<SigmaRule>();
            int errorCount = 0;

            foreach (var filePath in yamlFiles)
            {
                try
                {
                    string yamlContent = File.ReadAllText(filePath);
                    var yamlObject = deserializer.Deserialize<Dictionary<object, object>>(yamlContent);

                    if (yamlObject.TryGetValue("detection", out var detectionObj) && detectionObj is Dictionary<object, object> detectionDict)
                    {
                        var fixedDetection = new Dictionary<string, object>();
                        string originalCondition = detectionDict["condition"].ToString() ?? string.Empty;
                        string fixedCondition = originalCondition;

                        var selectorMapping = new Dictionary<string, string>();
                        int selectorCount = 1;

                        foreach (var kv in detectionDict)
                        {
                            var key = kv.Key?.ToString();
                            if (key == "condition" || key is null)
                                continue;

                            string fixedKey = $"selection_{selectorCount}";
                            fixedDetection[fixedKey] = kv.Value;
                            selectorMapping[key] = fixedKey;
                            selectorCount++;
                        }

                        fixedCondition = ReplaceWildcardSelectorsInCondition(originalCondition, selectorMapping);

                        fixedDetection["condition"] = fixedCondition;
                        yamlObject["detection"] = fixedDetection;
                    }

                    string fixedYamlContent = serializer.Serialize(yamlObject);
                    var rule = deserializer.Deserialize<SigmaRule>(fixedYamlContent);

                    if (rule != null)
                    {
                        sigmaRules.Add(rule);
                        Console.WriteLine("[INFO] Loading Sigma rule from " + filePath);
                    }
                    else
                    {
                        Console.WriteLine($"[WARNING] Sigma rule file '{filePath}' deserialized to null.");
                    }
                }
                catch (IOException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load Sigma rule file '{filePath}' (IO error): {ex.Message}");
                }
                catch (YamlDotNet.Core.YamlException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load Sigma rule file '{filePath}' (YAML parsing error): {ex.Message}");
                }
                catch (ArgumentException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load Sigma rule file '{filePath}' (argument error): {ex.Message}");
                }
                catch (InvalidOperationException ex)
                {
                    errorCount++;
                    Console.WriteLine($"[ERROR] Failed to load Sigma rule file '{filePath}' (invalid operation): {ex.Message}");
                }
                // Unexpected exceptions are rethrown
            }

            Console.WriteLine($"[INFO] Successfully loaded {sigmaRules.Count} Sigma rules. (Skipped {errorCount} files with errors)");
            return sigmaRules;
        }

        private static string ReplaceWildcardSelectorsInCondition(string condition, Dictionary<string, string> selectorMapping)
        {
            var wildcardPatterns = Regex.Matches(condition, @"\b(\w+\*)")
                .Cast<Match>()
                .Select(m => m.Value)
                .Distinct()
                .ToList();

            foreach (var wildcard in wildcardPatterns)
            {
                string wildcardPrefix = wildcard.TrimEnd('*');
                var matchingSelectors = selectorMapping.Keys
                    .Where(key => key.StartsWith(wildcardPrefix, StringComparison.Ordinal))
                    .Select(key => selectorMapping[key])
                    .ToList();

                string replacement = matchingSelectors.Count > 0
                    ? "(" + string.Join(" or ", matchingSelectors) + ")"
                    : "(false)";

                condition = condition.Replace(wildcard, replacement, StringComparison.Ordinal);
            }

            condition = Regex.Replace(condition, @"all of\s+\(([^)]+)\)", match =>
            {
                var items = match.Groups[1].Value.Split(OrSeparators, StringSplitOptions.RemoveEmptyEntries);
                var trimmedItems = items.Select(i => i.Trim(' ', '(', ')')).ToList();
                return "(" + string.Join(" and ", trimmedItems) + ")";
            }, RegexOptions.IgnoreCase);

            condition = Regex.Replace(condition, @"1 of\s+\(([^)]+)\)", match =>
            {
                var items = match.Groups[1].Value.Split(OrSeparators, StringSplitOptions.RemoveEmptyEntries);
                var trimmedItems = items.Select(i => i.Trim(' ', '(', ')')).ToList();
                return "(" + string.Join(" or ", trimmedItems) + ")";
            }, RegexOptions.IgnoreCase);

            foreach (var kv in selectorMapping)
            {
                condition = Regex.Replace(condition, $@"\b{Regex.Escape(kv.Key)}\b", kv.Value);
            }

            return condition;
        }

        /// <summary>
        /// Evaluates whether the specified Sigma rule matches the ETW event.
        /// </summary>
        public static bool EvaluateSigmaDetection(TraceEvent data, SigmaRule sigma)
        {
            // Check if the event is relevant based on the category
            if (!IsEventRelevantForRule(data, sigma))
            {
                return false;
            }

            var selectorsResults = new Dictionary<string, bool>();

            // Explicitly evaluate each defined selector
            EvaluateAndAddSelector(selectorsResults, "selection_1", sigma.Detection.Selection1, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_2", sigma.Detection.Selection2, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_3", sigma.Detection.Selection3, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_4", sigma.Detection.Selection4, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_5", sigma.Detection.Selection5, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_6", sigma.Detection.Selection6, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_7", sigma.Detection.Selection7, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_8", sigma.Detection.Selection8, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_9", sigma.Detection.Selection9, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_10", sigma.Detection.Selection10, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_11", sigma.Detection.Selection11, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_12", sigma.Detection.Selection12, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_13", sigma.Detection.Selection13, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_14", sigma.Detection.Selection14, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_15", sigma.Detection.Selection15, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_16", sigma.Detection.Selection16, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_17", sigma.Detection.Selection17, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_18", sigma.Detection.Selection18, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_19", sigma.Detection.Selection19, data, sigma.LogSource.Category);
            EvaluateAndAddSelector(selectorsResults, "selection_20", sigma.Detection.Selection20, data, sigma.LogSource.Category);

            // Parse the condition using ANTLR
            var inputStream = new AntlrInputStream(sigma.Detection.Condition);
            var lexer = new SigmaConditionLexer(inputStream);
            var tokens = new CommonTokenStream(lexer);
            var parser = new SigmaConditionParser(tokens);
            var tree = parser.expr();

            // Expand the condition
            var visitor = new SigmaConditionVisitorImpl(selectorsResults.Keys.ToList());
            var expandedCondition = visitor.Visit(tree);

            // Evaluate the expanded condition
            bool result = EvaluateExpandedCondition(expandedCondition, selectorsResults);
            
            if (result)
            {
                // Always display important detection information regardless of debug level
                Console.WriteLine($"[DETECTION] Sigma Rule '{sigma.Title}' (ID: {sigma.Id}) matched");
                Console.WriteLine($"[DETECTION] Description: {sigma.Description}");
                Console.WriteLine($"[DETECTION] Severity: {sigma.Level}");
                
                // Display ETW event details
                Console.WriteLine($"[DETECTION] ETW Event: Provider={data.ProviderName}, EventID={data.ID}, ProcessID={data.ProcessID}");
                Console.WriteLine($"[DETECTION] Timestamp: {data.TimeStamp:yyyy-MM-dd HH:mm:ss.fff}");
                
                // Display the process information when available
                if (data.ProcessID > 0)
                {
                    string processName = data.ProcessName ?? "Unknown";
                    Console.WriteLine($"[DETECTION] Process: {processName} (PID: {data.ProcessID})");
                }
                
                // Display payload information for more context
                DisplayEventPayload(data);
                
                // Display additional debug information if in debug mode
                if (Config.logLevel == Config.LogLevel.Debug)
                {
                    Console.WriteLine($"[DEBUG] Condition evaluated: {expandedCondition}");
                    Console.WriteLine($"[DEBUG] Selector results: {string.Join(", ", selectorsResults.Select(kv => $"{kv.Key}={kv.Value}"))}");
                }
                
                Console.WriteLine(""); // Add empty line for better readability
            }
            
            return result;
        }
        
        /// <summary>
        /// Displays relevant payload information from the ETW event
        /// </summary>
        private static void DisplayEventPayload(TraceEvent data)
        {
            try
            {
                if (data.PayloadNames == null || data.PayloadNames.Length == 0)
                {
                    Console.WriteLine("[DETECTION] Event has no payload data");
                    return;
                }
                
                Console.WriteLine("[DETECTION] Event Payload:");
                
                foreach (string fieldName in data.PayloadNames)
                {
                    object? value = data.PayloadByName(fieldName);
                    if (value != null)
                    {
                        // Format the value appropriately
                        string displayValue;
                        
                        if (value is byte[] byteArray)
                        {
                            // Convert byte array to hex string for better display
                            displayValue = BitConverter.ToString(byteArray).Replace("-", " ", StringComparison.Ordinal);
                            if (displayValue.Length > 100)
                            {
                                // Using span-based operations
                                displayValue = string.Concat(displayValue.AsSpan(0, 100), "... (truncated)");
                            }
                        }
                        else if (value is string strValue && strValue.Length > 100)
                        {
                            // Using span-based operations
                            displayValue = string.Concat(strValue.AsSpan(0, 100), "... (truncated)");
                        }
                        else
                        {
                            displayValue = value.ToString() ?? "null";
                        }
                        
                        Console.WriteLine($"    {fieldName}: {displayValue}");
                    }
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine($"[WARNING] Error accessing event payload: {ex.Message}");
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"[WARNING] Invalid argument in event payload: {ex.Message}");
            }
            catch (FormatException ex)
            {
                Console.WriteLine($"[WARNING] Format error in event payload: {ex.Message}");
            }
            catch (NullReferenceException ex)
            {
                Console.WriteLine($"[WARNING] Null reference in event payload: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if the ETW event is relevant to the Sigma rule's category.
        /// </summary>
        private static bool IsEventRelevantForRule(TraceEvent data, SigmaRule sigma)
        {
            string category = sigma.LogSource.Category;
            
            // Process all events if no category is specified
            if (string.IsNullOrEmpty(category))
            {
                return true;
            }

            // Check mapping between category and ETW provider
            if (CategoryToProviderMapping.TryGetValue(category, out var providerMappings))
            {
                foreach (var mapping in providerMappings)
                {
                    if (data.ProviderName == mapping.ProviderName && 
                        mapping.EventIds.Contains((int)data.ID))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Evaluates the selector and adds whether selection_X meets the conditions.
        /// </summary>
        private static void EvaluateAndAddSelector(Dictionary<string, bool> results, string selectorName, 
            Dictionary<string, object> selector, TraceEvent data, string category)
        {
            if (selector is not null && selector.Count > 0)
            {
                results[selectorName] = EvaluateSelector(data, selector, category);
            }
        }

        /// <summary>
        /// Evaluates selector conditions against ETW event.
        /// </summary>
        private static bool EvaluateSelector(TraceEvent data, Dictionary<string, object> conditions, string category)
        {
            foreach (var condition in conditions)
            {
                var parts = condition.Key.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var sigmaFieldName = parts[0];
                var operation = parts.Length > 1 ? parts[1] : "equals";

                // Map Sigma field name to ETW field name
                string etwFieldName = MapSigmaFieldToEtwField(sigmaFieldName, category);
                
                // Get the value from the corresponding ETW field
                object? fieldValue = GetFieldValueFromEtwEvent(data, etwFieldName, category);
                
                // If field value couldn't be retrieved
                if (fieldValue is null)
                    return false;

                string fieldValueStr = fieldValue.ToString() ?? string.Empty;

                bool result = false;
                string conditionValueStr = FormatConditionValue(condition.Value);

                switch (operation.ToUpperInvariant())
                {
                    case "ENDSWITH":
                        result = EvaluateEndsWith(fieldValueStr, condition.Value);
                        break;
                    case "STARTSWITH":
                        result = EvaluateStartsWith(fieldValueStr, condition.Value);
                        break;
                    case "CONTAINS":
                        result = EvaluateContains(fieldValueStr, condition.Value);
                        break;
                    case "ALL":
                        result = EvaluateAll(fieldValueStr, condition.Value);
                        break;
                    case "EQUALS":
                        result = EvaluateEquals(fieldValueStr, condition.Value);
                        break;
                    case "RE":
                        result = EvaluateRegex(fieldValueStr, condition.Value);
                        break;
                    case "CIDR":
                        result = EvaluateCidr(fieldValueStr, condition.Value);
                        break;
                    case "LT":
                        result = EvaluateLessThan(fieldValueStr, condition.Value);
                        break;
                    case "LTE":
                        result = EvaluateLessThanOrEqual(fieldValueStr, condition.Value);
                        break;
                    case "GT":
                        result = EvaluateGreaterThan(fieldValueStr, condition.Value);
                        break;
                    case "GTE":
                        result = EvaluateGreaterThanOrEqual(fieldValueStr, condition.Value);
                        break;
                    case "BASE64":
                        result = EvaluateBase64(fieldValueStr, condition.Value);
                        break;
                    case "BASE64OFFSET":
                        result = EvaluateBase64Offset(fieldValueStr, condition.Value);
                        break;
                    case "UTF16LE":
                        result = EvaluateUtf16Le(fieldValueStr, condition.Value);
                        break;
                    case "UTF16BE":
                        result = EvaluateUtf16Be(fieldValueStr, condition.Value);
                        break;
                    case "WIDE":
                        result = EvaluateWide(fieldValueStr, condition.Value);
                        break;
                    case "FIELDREF":
                        result = EvaluateFieldRef(fieldValueStr, condition.Value, data, category);
                        break;
                    case "CASED":
                        result = EvaluateCased(fieldValueStr, condition.Value);
                        break;
                    case "EXISTS":
                        // Return true if the field exists (regardless of value)
                        result = true; // At this point, we already know the field exists
                        break;
                    case "WINDASH":
                        result = EvaluateWinDash(fieldValueStr, condition.Value);
                        break;
                    default:
                        Console.WriteLine($"[WARNING] Unsupported operation: {operation}");
                        return false;
                }

                if (Config.logLevel == Config.LogLevel.Debug)
                {
                    if (result)
                    {
                        Console.WriteLine($"[DEBUG] Sigma Detection: Field '{sigmaFieldName}' with value '{fieldValueStr}' matched {operation} condition '{conditionValueStr}'");
                    }
                }

                if (!result)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Formats a condition value for debug display
        /// </summary>
        private static string FormatConditionValue(object conditionValue)
        {
            if (conditionValue is string str)
                return str;

            if (conditionValue is IEnumerable<object> values)
                return "[" + string.Join(", ", values.Select(v => v?.ToString() ?? "null")) + "]";

            return conditionValue?.ToString() ?? "null";
        }

        /// <summary>
        /// Maps Sigma rule field name to ETW event field name.
        /// </summary>
        private static string MapSigmaFieldToEtwField(string sigmaFieldName, string category)
        {
            // Check category-specific field mapping
            if (!string.IsNullOrEmpty(category) && 
                CategoryFieldMapping.TryGetValue(category, out var fieldMapping) && 
                fieldMapping.TryGetValue(sigmaFieldName, out var etwFieldName))
            {
                return etwFieldName;
            }

            // Use the original field name if no mapping is found
            return sigmaFieldName;
        }

        /// <summary>
        /// Gets a specific field value from an ETW event.
        /// Implements special handling based on category.
        /// </summary>
        private static object? GetFieldValueFromEtwEvent(TraceEvent data, string fieldName, string category)
        {
            // Try to get the basic field value
            object? value = data.PayloadByName(fieldName);
            
            // Some fields require special handling
            if (value == null)
            {
                // Special handling for process ID
                if (fieldName.Equals("ProcessID", StringComparison.OrdinalIgnoreCase))
                {
                    return data.ProcessID;
                }
                
                // Category-specific special handling
                switch (category)
                {
                    case "network_connection":
                        if (fieldName.Equals("daddr", StringComparison.OrdinalIgnoreCase))
                        {
                            var daddr = data.PayloadByName("daddr");
                            if (daddr != null)
                            {
                                try
                                {
                                    return Detect.UInt32ToIPAddress(daddr).ToString();
                                }
                                catch (ArgumentException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] daddr conversion error (argument): {ex.Message}");
                                }
                                catch (FormatException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] daddr conversion error (format): {ex.Message}");
                                }
                                catch (OverflowException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] daddr conversion error (overflow): {ex.Message}");
                                }
                            }
                        }
                        else if (fieldName.Equals("saddr", StringComparison.OrdinalIgnoreCase))
                        {
                            var saddr = data.PayloadByName("saddr");
                            if (saddr != null)
                            {
                                try
                                {
                                    return Detect.UInt32ToIPAddress(saddr).ToString();
                                }
                                catch (ArgumentException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] saddr conversion error (argument): {ex.Message}");
                                }
                                catch (FormatException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] saddr conversion error (format): {ex.Message}");
                                }
                                catch (OverflowException ex)
                                {
                                    if (Config.logLevel == Config.LogLevel.Debug)
                                        Console.WriteLine($"[VERBOSE] saddr conversion error (overflow): {ex.Message}");
                                }
                            }
                        }
                        break;
                }
            }
            
            return value;
        }

        private static bool EvaluateEndsWith(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.EndsWith(str, StringComparison.OrdinalIgnoreCase);

            if (conditionValue is IEnumerable<object> list)
                return list.Any(item => fieldValue.EndsWith(item?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static bool EvaluateStartsWith(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.StartsWith(str, StringComparison.OrdinalIgnoreCase);

            if (conditionValue is IEnumerable<object> values)
                return values.Any(v => fieldValue.StartsWith(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static bool EvaluateContains(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.Contains(str, StringComparison.OrdinalIgnoreCase);

            if (conditionValue is IEnumerable<object> values)
                return values.Any(v => fieldValue.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static bool EvaluateAll(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.Contains(str, StringComparison.OrdinalIgnoreCase);

            if (conditionValue is IEnumerable<object> values)
            {
                return values.All(v => fieldValue.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));
            }

            return false;
        }

        private static bool EvaluateEquals(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.Equals(str, StringComparison.OrdinalIgnoreCase);

            if (conditionValue is IEnumerable<object> values)
                return values.Any(v => fieldValue.Equals(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static bool EvaluateRegex(string fieldValue, object conditionValue)
        {
            if (conditionValue is string pattern)
                return Regex.IsMatch(fieldValue, pattern, RegexOptions.IgnoreCase);

            if (conditionValue is IEnumerable<object> patterns)
                return patterns.Any(p => Regex.IsMatch(fieldValue, p?.ToString() ?? "", RegexOptions.IgnoreCase));

            return false;
        }

        private static bool EvaluateCidr(string fieldValue, object conditionValue)
        {
            // Validate IP address
            if (!System.Net.IPAddress.TryParse(fieldValue, out var ipAddress))
                return false;

            // Only support IPv4 addresses
            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            bool EvaluateSingleCidr(string cidr)
            {
                try
                {
                    var parts = cidr.Split('/');
                    if (parts.Length != 2)
                        return false;

                    if (!System.Net.IPAddress.TryParse(parts[0], out var networkAddress))
                        return false;

                    if (!int.TryParse(parts[1], out var prefixLength) || prefixLength < 0 || prefixLength > 32)
                        return false;

                    // Convert IP addresses to numeric values
                    var ipBytes = ipAddress.GetAddressBytes();
                    var networkBytes = networkAddress.GetAddressBytes();

                    // Create network mask
                    uint mask = ~(uint.MaxValue >> prefixLength);

                    // Convert IP and network addresses to numeric values
                    uint ipValue = (uint)ipBytes[0] << 24 | (uint)ipBytes[1] << 16 | (uint)ipBytes[2] << 8 | ipBytes[3];
                    uint networkValue = (uint)networkBytes[0] << 24 | (uint)networkBytes[1] << 16 | (uint)networkBytes[2] << 8 | networkBytes[3];

                    // Apply mask and compare
                    return (ipValue & mask) == (networkValue & mask);
                }
                catch (FormatException ex)
                {
                    Console.WriteLine($"[WARNING] CIDR format error: {ex.Message}");
                    return false;
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"[WARNING] CIDR argument error: {ex.Message}");
                    return false;
                }
                catch (OverflowException ex)
                {
                    Console.WriteLine($"[WARNING] CIDR overflow error: {ex.Message}");
                    return false;
                }
            }

            if (conditionValue is string cidr)
                return EvaluateSingleCidr(cidr);

            if (conditionValue is IEnumerable<object> cidrs)
                return cidrs.Any(c => EvaluateSingleCidr(c?.ToString() ?? ""));

            return false;
        }

        // Numeric comparison: less than
        private static bool EvaluateLessThan(string fieldValue, object conditionValue)
        {
            if (!double.TryParse(fieldValue, out var fieldNumber))
                return false;

            if (conditionValue is string str && double.TryParse(str, out var compareNumber))
                return fieldNumber < compareNumber;

            if (conditionValue is IEnumerable<object> values)
            {
                foreach (var value in values)
                {
                    if (value is string valueStr && double.TryParse(valueStr, out var valueNumber))
                    {
                        if (fieldNumber < valueNumber)
                            return true;
                    }
                }
            }

            return false;
        }

        // Numeric comparison: less than or equal
        private static bool EvaluateLessThanOrEqual(string fieldValue, object conditionValue)
        {
            if (!double.TryParse(fieldValue, out var fieldNumber))
                return false;

            if (conditionValue is string str && double.TryParse(str, out var compareNumber))
                return fieldNumber <= compareNumber;

            if (conditionValue is IEnumerable<object> values)
            {
                foreach (var value in values)
                {
                    if (value is string valueStr && double.TryParse(valueStr, out var valueNumber))
                    {
                        if (fieldNumber <= valueNumber)
                            return true;
                    }
                }
            }

            return false;
        }

        // Numeric comparison: greater than
        private static bool EvaluateGreaterThan(string fieldValue, object conditionValue)
        {
            if (!double.TryParse(fieldValue, out var fieldNumber))
                return false;

            if (conditionValue is string str && double.TryParse(str, out var compareNumber))
                return fieldNumber > compareNumber;

            if (conditionValue is IEnumerable<object> values)
            {
                foreach (var value in values)
                {
                    if (value is string valueStr && double.TryParse(valueStr, out var valueNumber))
                    {
                        if (fieldNumber > valueNumber)
                            return true;
                    }
                }
            }

            return false;
        }

        // Numeric comparison: greater than or equal
        private static bool EvaluateGreaterThanOrEqual(string fieldValue, object conditionValue)
        {
            if (!double.TryParse(fieldValue, out var fieldNumber))
                return false;

            if (conditionValue is string str && double.TryParse(str, out var compareNumber))
                return fieldNumber >= compareNumber;

            if (conditionValue is IEnumerable<object> values)
            {
                foreach (var value in values)
                {
                    if (value is string valueStr && double.TryParse(valueStr, out var valueNumber))
                    {
                        if (fieldNumber >= valueNumber)
                            return true;
                    }
                }
            }

            return false;
        }

        // Base64 decode evaluation
        private static bool EvaluateBase64(string fieldValue, object conditionValue)
        {
            try
            {
                byte[] decodedBytes = Convert.FromBase64String(fieldValue);
                string decodedText = System.Text.Encoding.UTF8.GetString(decodedBytes);

                if (conditionValue is string str)
                    return decodedText.Contains(str, StringComparison.OrdinalIgnoreCase);

                if (conditionValue is IEnumerable<object> values)
                    return values.Any(v => decodedText.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

                return false;
            }
            catch (FormatException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] Base64 decode error (format): {ex.Message}");
                return false;
            }
            catch (ArgumentException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] Base64 decode error (argument): {ex.Message}");
                return false;
            }
        }

        // Base64 decode evaluation with different offsets
        private static bool EvaluateBase64Offset(string fieldValue, object conditionValue)
        {
            // Try up to 4 different offsets
            for (int offset = 0; offset < 4; offset++)
            {
                try
                {
                    string paddedValue = fieldValue;
                    if (offset > 0)
                    {
                        // Add offset in front if needed
                        paddedValue = new string('A', offset) + fieldValue;
                    }

                    // Add padding if needed
                    int mod4 = paddedValue.Length % 4;
                    if (mod4 > 0)
                    {
                        paddedValue += new string('=', 4 - mod4);
                    }

                    byte[] decodedBytes = Convert.FromBase64String(paddedValue);
                    string decodedText = System.Text.Encoding.UTF8.GetString(decodedBytes);

                    if (conditionValue is string str)
                    {
                        if (decodedText.Contains(str, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                    else if (conditionValue is IEnumerable<object> values)
                    {
                        if (values.Any(v => decodedText.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase)))
                            return true;
                    }
                }
                catch (FormatException)
                {
                    // Failed to decode at this offset
                    continue;
                }
                catch (ArgumentException)
                {
                    // Failed to decode at this offset
                    continue;
                }
            }

            return false;
        }

        // UTF-16LE (Little Endian) encoding evaluation
        private static bool EvaluateUtf16Le(string fieldValue, object conditionValue)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(fieldValue);
                string decodedText = System.Text.Encoding.Unicode.GetString(bytes);

                if (conditionValue is string str)
                    return decodedText.Contains(str, StringComparison.OrdinalIgnoreCase);

                if (conditionValue is IEnumerable<object> values)
                    return values.Any(v => decodedText.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

                return false;
            }
            catch (FormatException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] UTF16LE decode error (format): {ex.Message}");
                return false;
            }
            catch (ArgumentException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] UTF16LE decode error (argument): {ex.Message}");
                return false;
            }
        }

        // UTF-16BE (Big Endian) encoding evaluation
        private static bool EvaluateUtf16Be(string fieldValue, object conditionValue)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(fieldValue);
                string decodedText = System.Text.Encoding.BigEndianUnicode.GetString(bytes);

                if (conditionValue is string str)
                    return decodedText.Contains(str, StringComparison.OrdinalIgnoreCase);

                if (conditionValue is IEnumerable<object> values)
                    return values.Any(v => decodedText.Contains(v?.ToString() ?? "", StringComparison.OrdinalIgnoreCase));

                return false;
            }
            catch (FormatException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] UTF16BE decode error (format): {ex.Message}");
                return false;
            }
            catch (ArgumentException ex)
            {
                if (Config.logLevel == Config.LogLevel.Debug)
                    Console.WriteLine($"[VERBOSE] UTF16BE decode error (argument): {ex.Message}");
                return false;
            }
        }

        // WIDE (UTF-16LE) encoding evaluation - Windows wide string support
        private static bool EvaluateWide(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
            {
                string widePattern = string.Join("\0", str.ToCharArray()) + "\0";
                return fieldValue.Contains(widePattern, StringComparison.OrdinalIgnoreCase);
            }

            if (conditionValue is IEnumerable<object> values)
            {
                foreach (var value in values)
                {
                    if (value is string valueStr)
                    {
                        string widePattern = string.Join("\0", valueStr.ToCharArray()) + "\0";
                        if (fieldValue.Contains(widePattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }

            return false;
        }

        private static bool EvaluateFieldRef(string fieldValue, object conditionValue, TraceEvent data, string category)
        {
            if (conditionValue is string refFieldName)
            {
                string etwRefFieldName = MapSigmaFieldToEtwField(refFieldName, category);
                
                object? refFieldValue = GetFieldValueFromEtwEvent(data, etwRefFieldName, category);
                
                if (refFieldValue != null)
                {
                    string refFieldValueStr = refFieldValue.ToString() ?? string.Empty;
                    
                    if (Config.logLevel == Config.LogLevel.Debug)
                    {
                        Console.WriteLine($"[DEBUG] FieldRef: Comparing '{fieldValue}' with field '{refFieldName}' value '{refFieldValueStr}'");
                    }
                    
                    return fieldValue.Equals(refFieldValueStr, StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    if (Config.logLevel == Config.LogLevel.Debug)
                    {
                        Console.WriteLine($"[DEBUG] FieldRef: Referenced field '{refFieldName}' has null value");
                    }
                }
            }
            else if (conditionValue is IEnumerable<object> refFieldNames)
            {
                foreach (var item in refFieldNames)
                {
                    if (item is string innerRefFieldName)
                    {
                        string etwRefFieldName = MapSigmaFieldToEtwField(innerRefFieldName, category);
                        
                        object? refFieldValue = GetFieldValueFromEtwEvent(data, etwRefFieldName, category);
                        
                        if (refFieldValue != null)
                        {
                            string refFieldValueStr = refFieldValue.ToString() ?? string.Empty;
                            
                            if (fieldValue.Equals(refFieldValueStr, StringComparison.OrdinalIgnoreCase))
                            {
                                if (Config.logLevel == Config.LogLevel.Debug)
                                {
                                    Console.WriteLine($"[DEBUG] FieldRef: '{fieldValue}' matched with field '{innerRefFieldName}' value '{refFieldValueStr}'");
                                }
                                return true;
                            }
                        }
                    }
                }
            }
            
            return false;
        }

        // Case-sensitive string comparison
        private static bool EvaluateCased(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
                return fieldValue.Equals(str, StringComparison.Ordinal);

            if (conditionValue is IEnumerable<object> values)
                return values.Any(v => fieldValue.Equals(v?.ToString() ?? "", StringComparison.Ordinal));

            return false;
        }

        // Windows command-line switch evaluation supporting both / and -
        private static bool EvaluateWinDash(string fieldValue, object conditionValue)
        {
            if (conditionValue is string str)
            {
                // Check if the switch starts with / or -
                if (str.StartsWith('/') || str.StartsWith('-'))
                {
                    string switchName = str.Substring(1);
                    // Search for both prefix versions
                    return fieldValue.Contains("/" + switchName, StringComparison.OrdinalIgnoreCase) ||
                           fieldValue.Contains("-" + switchName, StringComparison.OrdinalIgnoreCase);
                }
                return fieldValue.Contains(str, StringComparison.OrdinalIgnoreCase);
            }

            if (conditionValue is IEnumerable<object> values)
            {
                return values.Any(v => 
                {
                    if (v is string valueStr)
                    {
                        // Check if the switch starts with / or -
                        if (valueStr.StartsWith('/') || valueStr.StartsWith('-'))
                        {
                            string switchName = valueStr.Substring(1);
                            // Search for both prefix versions
                            return fieldValue.Contains("/" + switchName, StringComparison.OrdinalIgnoreCase) ||
                                   fieldValue.Contains("-" + switchName, StringComparison.OrdinalIgnoreCase);
                        }
                        return fieldValue.Contains(valueStr, StringComparison.OrdinalIgnoreCase);
                    }
                    return false;
                });
            }

            return false;
        }

        private static bool EvaluateExpandedCondition(string expandedCondition, Dictionary<string, bool> selectorsResults)
        {
            var interpreter = new Interpreter();

            foreach (var selector in selectorsResults)
            {
                interpreter.SetVariable(selector.Key, selector.Value);
            }

            expandedCondition = expandedCondition
                .Replace("AND", "&&", StringComparison.InvariantCulture)
                .Replace("OR", "||", StringComparison.InvariantCulture)
                .Replace("NOT", "!", StringComparison.InvariantCulture);

            return interpreter.Eval<bool>(expandedCondition);
        }
    }
}
