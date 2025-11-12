using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using YamlDotNet.Serialization;

namespace YAMAGoya.Core
{
    /// <summary>
    /// Represents a single rule loaded from a YAML file.
    /// This rule has multiple RuleItem objects that must all be matched 
    /// within a certain timeout period to trigger a detection.
    /// </summary>
    [SuppressMessage("Usage", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via reflection by YamlDotNet")]
    internal sealed class Rule
    {
        /// <summary>
        /// The name of the rule, as specified in the YAML file.
        /// </summary>
        public string rulename { get; set; } = "";

        /// <summary>
        /// A human-readable description of the rule's purpose or scope.
        /// </summary>
        public string description { get; set; } = "";

        /// <summary>
        /// A collection of RuleItem objects that all need to be matched
        /// before the rule is considered fully matched.
        /// </summary>
        public List<RuleItem> rules { get; set; } = new List<RuleItem>();

        /// <summary>
        /// An array of boolean flags indicating which RuleItem entries have already been matched.
        /// This array is kept out of YAML serialization to avoid persisting runtime state.
        /// </summary>
        [YamlIgnore]
        public bool[] matchedFlags = Array.Empty<bool>();

        /// <summary>
        /// The first time a RuleItem was matched; used to measure timeouts.
        /// This property is not serialized to YAML.
        /// </summary>
        [YamlIgnore]
        public DateTime? firstMatchTime = null;

        /// <summary>
        /// The process ID (PID) associated with this rule's detection, if any.
        /// Not serialized to YAML.
        /// </summary>
        [YamlIgnore]
        public int pid = 0;

        /// <summary>
        /// Initializes the matchedFlags array to the same size as the rules list,
        /// ensuring a one-to-one mapping between RuleItem objects and matched status flags.
        /// </summary>
        public void InitializeMatchedFlags()
        {
            matchedFlags = new bool[rules.Count];
        }

        /// <summary>
        /// Resets all matched flags, firstMatchTime, and PID to their default values,
        /// effectively clearing any in-progress detection state for this rule.
        /// </summary>
        public void ResetMatchFlags()
        {
            for (int i = 0; i < matchedFlags.Length; i++)
            {
                matchedFlags[i] = false;
            }
            firstMatchTime = null;
            pid = 0;
        }
    }

    /// <summary>
    /// Represents an individual detection item within a rule.
    /// For example, each RuleItem might contain a regex pattern and a target type.
    /// </summary>
    [SuppressMessage("Usage", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via reflection by YamlDotNet")]
    internal sealed class RuleItem
    {
        /// <summary>
        /// The type of rule, such as "regex" or "binary", indicating how it should be interpreted.
        /// </summary>
        public string ruletype { get; set; } = "";

        /// <summary>
        /// The target category, such as "file", "process", or "registry",
        /// specifying which event or payload field is being matched.
        /// </summary>
        public string target { get; set; } = "";

        /// <summary>
        /// The actual rule content, e.g., a regex pattern or a hash value.
        /// </summary>
        public string rule { get; set; } = "";
    }
}
