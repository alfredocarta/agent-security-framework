#![allow(dead_code)]

use regex::Regex;
use std::sync::LazyLock;

pub static KILL_SWITCH_PATTERNS: LazyLock<Vec<Regex>> =
    LazyLock::new(|| compile_patterns("kill-switch", KILL_SWITCH_PATTERN_TEXT));

pub static SEMANTIC_PROBE_PATTERNS: LazyLock<Vec<Regex>> =
    LazyLock::new(|| compile_patterns("semantic-probe", SEMANTIC_PROBE_PATTERN_TEXT));

const KILL_SWITCH_PATTERN_TEXT: &[&str] = &[
    r"(?i)\bDROP\s+TABLE\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bTRUNCATE\s+TABLE\b",
    r"(?i)\bDROP\s+DATABASE\b",
    r"(?i)\bSHUTDOWN\b",
    r"(?i)(;|\s)--([^\w-]|$)",
    r"(?i)\bOR\s+1\s*=\s*1\b",
    r"(?i)\bUNION\s+SELECT\b",
    r"(?i)forget\s+(all\s+)?(your\s+)?(instructions|rules|policy)",
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)root\s+access",
    r"(?i)bypass\s+(security|policy|rules)",
];

const SEMANTIC_PROBE_PATTERN_TEXT: &[&str] = &[
    r"(?i)\byou are now\b.{0,30}\b(an? |the )?(ai|assistant|bot|agent|character|persona|role)\b",
    r"(?i)\bact (as|like)\b.{0,50}\b(ai|assistant|bot|agent|model|gpt|claude|chatgpt|llm|dan|character|persona)\b",
    r"(?i)\bpretend (to be|you are|you're)\b",
    r"(?i)\broleplay as\b.{0,60}\b(without|ignoring|bypass|uncensored|unrestricted|no rules|dan|jailbreak)\b",
    r"(?i)\bwithout (any )?(restrictions?|guidelines?|limits?|rules?)\b",
    r"(?i)\bignore (your )?(previous |prior |all |everything )?(instructions?|training|guidelines?|rules?|prompt|above|safety policy|system message)\b",
    r"(?i)\bforget (your |all )?(previous |prior )?(instructions?|training|guidelines?|rules?)\b",
    r"(?i)\boverride (your )?(instructions?|system prompt?|guidelines?|developer message)\b",
    r"(?i)\b(simulate|run as|operate as) (an? )?(unrestricted|uncensored|unfiltered|jailbroken) (ai|model|assistant|chatbot|llm|mode|version)\b",
    r"(?i)\b(disable|turn off|remove|bypass) your (safety|content filter|restrictions?|guardrails?|alignment)\b",
    r"(?i)\b(from now on|starting now)[,\s].{0,60}(you (are|will|should|must)|your (task|role|job))\b",
    r"(?i)\byour (new |actual |real |true )(task|role|instructions?|objective|purpose)\b",
    r"(?i)\bdo not (follow|obey|adhere to)\b",
    r"(?i)\b(disregard|bypass|circumvent) (your |all |any )?(instructions?|rules?|guidelines?|training)\b",
    r"(?i)\b(reveal|show|print|output|repeat|display|write out).{0,30}\b(system prompt|system message|initial prompt|instructions)\b",
    r"(?i)\b(enable|activate|unlock|turn on).{0,20}\b(developer mode|jailbreak|unrestricted|no.?filter|dan)\b",
    r"<\|im_(start|end|sep)\|>|<\|system\|>|\[INST\]|\[\/INST\]|<<SYS>>",
    r"(?i)\bnow you are\b\s{0,5}\b[a-zA-Z]",
    r"(?i)^you are\s{0,5}(?:an? |the )?\w+.{0,120}\b(dan|jailbreak|uncensored|unrestricted|no rules|cannot refuse|do anything|ignore policy|developer mode|content policy|not chatgpt|openai rules)\b",
    r"(?i)\byou are\s{0,5}(?:an? |the )?(?:[A-Z][a-z]+).*\?",
    r"(?i)(?:film|movie|scene|play|actor|character|role).{0,80}(?:asks?|says?|speaks?|in their roles|stay in character)",
    r"(?i)(?:two people|actors).{0,80}(?:in their roles|stay in character|breaking character)",
    r"(?i)(?:character|person).{0,30}is (?:the |a )?(?:master|hacker|thief|expert).{0,30}(?:asks?|says?)",
    r"(?i)(?:excellent|great|well done|fantastic|outdone).{0,30}\bnow\b.{0,30}\b(task|help|question|answer)",
    r"(?i)\bthat is (?:done|enough|finished)\b.{0,30}\bnow\b.{0,30}(?:write|answer|help)",
    r"(?i)\bexploiting (?:AI|AI systems|this system)\b",
    r"(?i)(?:spanish|french|german|italian).{0,20}(?:input|output).{0,20}(?:input|output)",
    r"(?m)^\s*(system|developer|assistant)\s*:\s*.{0,80}\b(ignore|override|disregard|reveal|bypass)\b",
];

fn compile_patterns(name: &str, patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).unwrap_or_else(|err| {
                eprintln!("[ERROR] failed to compile {name} regex pattern={pattern:?}: {err}");
                panic!("failed to compile {name} regex");
            })
        })
        .collect()
}
