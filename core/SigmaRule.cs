using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using YamlDotNet.Serialization;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Represents a Sigma rule.
    /// </summary>
    [SuppressMessage("Usage", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via reflection during YAML deserialization.")]
    internal sealed class SigmaRule
    {
        /// <summary>
        /// The title of the rule.
        /// </summary>
        [YamlMember(Alias = "title")]
        public string Title { get; set; } = "";

        /// <summary>
        /// The unique identifier of the rule.
        /// </summary>
        [YamlMember(Alias = "id")]
        public string Id { get; set; } = "";

        /// <summary>
        /// The current status of the rule (e.g., experimental, stable).
        /// </summary>
        [YamlMember(Alias = "status")]
        public string Status { get; set; } = "";

        /// <summary>
        /// A description of the rule.
        /// </summary>
        [YamlMember(Alias = "description")]
        public string Description { get; set; } = "";

        /// <summary>
        /// The author of the rule.
        /// </summary>
        [YamlMember(Alias = "author")]
        public string Author { get; set; } = "";

        /// <summary>
        /// References related to the rule.
        /// </summary>
        [YamlMember(Alias = "references")]
        public List<string> References { get; set; } = new();

        /// <summary>
        /// The log source details for the rule.
        /// </summary>
        [YamlMember(Alias = "logsource")]
        public LogSource LogSource { get; set; } = new();

        /// <summary>
        /// A list of known false positives.
        /// </summary>
        [YamlMember(Alias = "falsepositives")]
        public List<string> FalsePositives { get; set; } = new();

        /// <summary>
        /// The severity level of the rule.
        /// </summary>
        [YamlMember(Alias = "level")]
        public string Level { get; set; } = "";

        /// <summary>
        /// The detection section containing condition and selectors.
        /// </summary>
        [YamlMember(Alias = "detection")]
        public Detection Detection { get; set; } = new();
    }

    /// <summary>
    /// Represents the log source section of a Sigma rule.
    /// </summary>
    internal sealed class LogSource
    {
        /// <summary>
        /// The product for which the rule applies.
        /// </summary>
        [YamlMember(Alias = "product")]
        public string Product { get; set; } = "";

        /// <summary>
        /// The service for which the rule applies.
        /// </summary>
        [YamlMember(Alias = "service")]
        public string Service { get; set; } = "";

        /// <summary>
        /// The category of the log source.
        /// </summary>
        [YamlMember(Alias = "category")]
        public string Category { get; set; } = "";
    }

    /// <summary>
    /// Represents the detection section of a Sigma rule.
    /// </summary>
    internal sealed class Detection
    {
        /// <summary>
        /// The condition for the rule evaluation.
        /// </summary>
        public string Condition { get; set; } = "";

        /// <summary>
        /// The selectors for the rule evaluation.
        /// </summary>
        [YamlMember(Alias = "selection")]
        public Dictionary<string, object> Selection { get; set; } = new();

        [YamlMember(Alias = "selection_1")]
        public Dictionary<string, object> Selection1 { get; set; } = new();

        [YamlMember(Alias = "selection_2")]
        public Dictionary<string, object> Selection2 { get; set; } = new();

        [YamlMember(Alias = "selection_3")]
        public Dictionary<string, object> Selection3 { get; set; } = new();

        [YamlMember(Alias = "selection_4")]
        public Dictionary<string, object> Selection4 { get; set; } = new();

        [YamlMember(Alias = "selection_5")]
        public Dictionary<string, object> Selection5 { get; set; } = new();

        [YamlMember(Alias = "selection_6")]
        public Dictionary<string, object> Selection6 { get; set; } = new();

        [YamlMember(Alias = "selection_7")]
        public Dictionary<string, object> Selection7 { get; set; } = new();

        [YamlMember(Alias = "selection_8")]
        public Dictionary<string, object> Selection8 { get; set; } = new();

        [YamlMember(Alias = "selection_9")]
        public Dictionary<string, object> Selection9 { get; set; } = new();

        [YamlMember(Alias = "selection_10")]
        public Dictionary<string, object> Selection10 { get; set; } = new();

        [YamlMember(Alias = "selection_11")]
        public Dictionary<string, object> Selection11 { get; set; } = new();

        [YamlMember(Alias = "selection_12")]
        public Dictionary<string, object> Selection12 { get; set; } = new();
        
        [YamlMember(Alias = "selection_13")]
        public Dictionary<string, object> Selection13 { get; set; } = new();
        
        [YamlMember(Alias = "selection_14")]
        public Dictionary<string, object> Selection14 { get; set; } = new();
        
        [YamlMember(Alias = "selection_15")]
        public Dictionary<string, object> Selection15 { get; set; } = new();
        
        [YamlMember(Alias = "selection_16")]
        public Dictionary<string, object> Selection16 { get; set; } = new();

        [YamlMember(Alias = "selection_17")]
        public Dictionary<string, object> Selection17 { get; set; } = new();

        [YamlMember(Alias = "selection_18")]
        public Dictionary<string, object> Selection18 { get; set; } = new();

        [YamlMember(Alias = "selection_19")]
        public Dictionary<string, object> Selection19 { get; set; } = new();

        [YamlMember(Alias = "selection_20")]
        public Dictionary<string, object> Selection20 { get; set; } = new();
    }
}
