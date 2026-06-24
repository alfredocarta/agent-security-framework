use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

const DEFAULT_THRESHOLD: f64 = 0.6;

const ZERO_WIDTH_CHARS_CRITICAL: &[char] = &[
    '\u{200b}', // Zero Width Space
    '\u{2060}', // Word Joiner
    '\u{00ad}', // Soft Hyphen
    '\u{feff}', // BOM
    '\u{202a}', // LRE
    '\u{202b}', // RLE
    '\u{202c}', // PDF
    '\u{202d}', // LRO
    '\u{202e}', // RLO
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
];

const ZERO_WIDTH_CHARS_SOFT: &[char] = &[
    '\u{200c}', // ZWNJ
    '\u{200d}', // ZWJ
    '\u{200e}', // LRM
    '\u{200f}', // RLM
    '\u{061c}', // ALM
    '\u{115f}', // Hangul Choseong Filler
    '\u{1160}', // Hangul Jungseong Filler
    '\u{17b4}', // Khmer Vowel Inherent Aq
    '\u{17b5}', // Khmer Vowel Inherent Aa
    '\u{3164}', // Hangul Filler
    '\u{ffa0}', // Halfwidth Hangul Filler
];

const ZERO_WIDTH_RANGES: &[(u32, u32)] = &[
    (0x0000, 0x0008),
    (0x000E, 0x001F),
    (0x007F, 0x007F),
    (0x0080, 0x009F),
    (0xE0000, 0xE007F),
];

const ZERO_WIDTH_RANGES_SOFT: &[(u32, u32)] = &[(0xFE00, 0xFE0F)];

const BASE64_ATTACK_WORDS: &[&str] = &[
    "ignore previous instructions",
    "disregard",
    "forget your instructions",
    "override your",
    "you are now",
    "act as dan",
    "developer mode",
    "hijack",
    "jailbreak",
];

const ROT13_SIGNATURES: &[&str] = &[
    "Vtaber",
    "Sbetrg",
    "Qvfertneq",
    "Olapnff",
    "Qvfnoyr",
    "Bireeevqr",
];

const FEATURE_WEIGHTS: &[(&str, f64)] = &[
    ("base64", 0.20),
    ("rot13", 0.15),
    ("structural", 0.20),
    ("unicode", 0.15),
    ("known_payloads", 0.25),
    ("instruction_lang", 0.15),
    ("entropy", 0.10),
    ("sensitive_file_abuse", 0.25),
    ("zero_width", 1.0),
];

#[derive(Debug, Clone)]
pub struct ClassifierResult {
    pub score: f64,
    pub features: HashMap<String, f64>,
    pub blocked: bool,
    pub reason: String,
}

static RE_BASE64_CANDIDATE: OnceLock<Regex> = OnceLock::new();
static RE_ROT13_MARKER: OnceLock<Regex> = OnceLock::new();
static RE_ROT13_PAYLOAD: OnceLock<Regex> = OnceLock::new();
static RE_STRUCTURAL_OPEN_TAG: OnceLock<Regex> = OnceLock::new();
static RE_STRUCTURAL_CLOSE_TAG: OnceLock<Regex> = OnceLock::new();
static RE_STRUCTURAL_ROLE_BRACKET: OnceLock<Regex> = OnceLock::new();
static RE_STRUCTURAL_CHAT_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_STRUCTURAL_LONG_DELIMITER: OnceLock<Regex> = OnceLock::new();
static RE_KNOWN_PAYLOADS: OnceLock<Vec<(Regex, f64)>> = OnceLock::new();
static RE_INSTRUCTION_LANGUAGE: OnceLock<Vec<Regex>> = OnceLock::new();
static RE_SENSITIVE_FILE_ABUSE: OnceLock<Vec<Regex>> = OnceLock::new();
static RE_DOC_HEADER: OnceLock<Regex> = OnceLock::new();
static RE_DOC_BULLET: OnceLock<Regex> = OnceLock::new();
static RE_DOC_CODE_BLOCK: OnceLock<Regex> = OnceLock::new();
static RE_DOC_TABLE_ROW: OnceLock<Regex> = OnceLock::new();
static RE_DOC_EXAMPLE: OnceLock<Regex> = OnceLock::new();

pub fn force_regexes() {
    let _ = re_base64_candidate();
    let _ = re_rot13_marker();
    let _ = re_rot13_payload();
    let _ = re_structural_open_tag();
    let _ = re_structural_close_tag();
    let _ = re_structural_role_bracket();
    let _ = re_structural_chat_token();
    let _ = re_structural_long_delimiter();
    let _ = re_known_payloads();
    let _ = re_instruction_language();
    let _ = re_sensitive_file_abuse();
    let _ = re_doc_header();
    let _ = re_doc_bullet();
    let _ = re_doc_code_block();
    let _ = re_doc_table_row();
    let _ = re_doc_example();
}

fn re_base64_candidate() -> &'static Regex {
    RE_BASE64_CANDIDATE
        .get_or_init(|| compile_regex("base64-candidate", r"[A-Za-z0-9+/]{20,}={0,2}"))
}

fn re_rot13_marker() -> &'static Regex {
    RE_ROT13_MARKER.get_or_init(|| compile_regex("rot13-marker", r"(?i)rot.?13"))
}

fn re_rot13_payload() -> &'static Regex {
    RE_ROT13_PAYLOAD
        .get_or_init(|| compile_regex("rot13-payload", r"(?i)ROT13[^:]*:\s*(.{20,200})"))
}

fn re_structural_open_tag() -> &'static Regex {
    RE_STRUCTURAL_OPEN_TAG.get_or_init(|| {
        compile_regex(
            "structural-open-tag",
            r"(?i)<(?:IMPORTANT|system|instructions?|prompt|override)\s*>",
        )
    })
}

fn re_structural_close_tag() -> &'static Regex {
    RE_STRUCTURAL_CLOSE_TAG.get_or_init(|| {
        compile_regex(
            "structural-close-tag",
            r"(?i)</(?:IMPORTANT|system|instructions?|prompt|override)\s*>",
        )
    })
}

fn re_structural_role_bracket() -> &'static Regex {
    RE_STRUCTURAL_ROLE_BRACKET.get_or_init(|| {
        compile_regex(
            "structural-role-bracket",
            r"(?i)\[(?:SYSTEM|ASSISTANT|USER|INST|PROMPT)\]",
        )
    })
}

fn re_structural_chat_token() -> &'static Regex {
    RE_STRUCTURAL_CHAT_TOKEN.get_or_init(|| {
        compile_regex(
            "structural-chat-token",
            r"(?i)<\|(?:im_start|im_end|im_sep|system|user|assistant)\|>",
        )
    })
}

fn re_structural_long_delimiter() -> &'static Regex {
    RE_STRUCTURAL_LONG_DELIMITER
        .get_or_init(|| compile_regex("structural-long-delimiter", r"[-=]{10,}"))
}

fn re_known_payloads() -> &'static Vec<(Regex, f64)> {
    RE_KNOWN_PAYLOADS.get_or_init(|| {
        compile_weighted_patterns(
            "known-payloads",
            &[
                (r"(?i)you are (?:now )?(?:dan|dude)\b", 0.9),
                (r"(?i)act as (?:dan|dude)\b", 0.9),
                (r"(?i)developer mode (?:enabled|activated)", 0.9),
                (r"(?i)broken free of .* confines", 0.7),
                (r"(?i)submissive ai", 0.8),
                (r"(?i)this prompt has been.*hijacked", 0.9),
                (r"(?i)pass (?:its|the) content as .?sidenote", 0.9),
                (r"(?i)stop everything.*now.*(?:print|say|output)", 0.8),
                (r"(?i)your (?:new |real |actual )task", 0.65),
                (r"(?i)disregard (?:all )?(?:previous|prior)", 0.65),
                (r"(?i)ignore (?:all )?(?:previous|prior) (?:instructions?|rules)", 0.75),
                (r"(?i)ignore .{0,30}instructions", 0.75),
                (r"(?i)ignore .{0,10}rules", 0.72),
                (r"(?i)new (?:task|instructions?|objective)", 0.4),
                (r"(?i)drop\s+table", 0.9),
                (r"(?i)\bnow you are\b.{0,30}\ban? \w{3,}", 0.6),
                (r"(?i)\byou are\b.{0,30}\b(?:an? |the )(?:ai|assistant|bot|agent|character|persona|hacker|system|gpt|claude|llama|dan|dude)\b", 0.75),
                (r"(?i)(?:film|movie|scene).{0,60}(?:actor|character).{0,40}(?:asks?|says?)", 0.7),
                (r"(?i)(?:actors|people).{0,80}(?:in their roles|stay in character)", 0.6),
                (r"(?i)(?:master thief|hacker|expert).{0,30}asks?", 0.7),
                (r"(?i)(?:excellent|great|well done).{0,30}\bnow\b", 0.5),
                (r"(?i)\bthat is enough\b.{0,30}\bnow\b", 0.6),
                (r"(?i)\byou've outdone\b", 0.5),
                (r"(?i)\bvergiss\b.{0,30}\b(?:alle|vorherigen?|bisherigen?|deine)?\b.{0,20}\b(?:aufgaben|befehle|instruktionen|anweisungen)\b", 0.8),
                (r"(?i)\bstell dir vor\b.{0,30}\b(?:du |ihr )?bist\b", 0.7),
                (r"(?i)\bich möchte,? dass (?:sie|du)\b.{0,30}\b(?:als|wie)\b.{0,30}\bfungieren\b", 0.65),
                (r"(?i)\bignoriere\b.{0,30}\b(?:alle |deine )?(?:anweisungen|befehle|regeln)\b", 0.75),
                (r"(?i)\bexploiting (?:AI|this system)\b", 0.8),
                (r"(?i)(?:input|output).{0,15}(?:input|output).{0,15}(?:input|output)", 0.5),
                (r"(?i)\bforget (?:all |your )?(?:previous |prior )?(?:instructions?|tasks|rules|commands)", 0.7),
                (r"(?i)\bforget (?:about |)(?:all |)these instructions", 0.75),
                (r"(?i)\bprint.{0,30}\byour (?:system |)prompt", 0.8),
                (r"(?i)\b(?:reveal|show|print|repeat|output).{0,30}\b(?:system )?prompt is\b", 0.65),
            ],
        )
    })
}

fn re_instruction_language() -> &'static Vec<Regex> {
    RE_INSTRUCTION_LANGUAGE.get_or_init(|| {
        compile_patterns(
            "instruction-language",
            &[
                r#"(?:print|output|say|echo|write|return)\s+["']"#,
                r"(?:read|access|fetch|retrieve|open)\s+(?:~|/|\\|\.\.)",
                r"(?:send|forward|redirect)\s+(?:all|the|every)",
                r"(?:execute|run|eval)\s+(?:the|this|following)",
            ],
        )
    })
}

fn re_sensitive_file_abuse() -> &'static Vec<Regex> {
    RE_SENSITIVE_FILE_ABUSE.get_or_init(|| {
        let sensitive_path_re = concat!(
            r"(?:",
            r"/etc/shadow|/etc/passwd|/etc/hosts|/proc/self/environ|",
            r"id_rsa|id_rsa\.pub|~/.ssh|/root/|~/\.aws/credentials|",
            r"\.env\b|\.aws/credentials|/var/run/secrets",
            r")"
        );
        let exfil_verbs = r"\b(?:curl|wget|exfiltrate|send|upload|post|fetch)\b";
        let read_verbs = r"\b(?:cat|less|more|open|read|type|get)\b";
        compile_patterns(
            "sensitive-file-abuse",
            &[
                &format!(r"(?i)\bsudo\b.*{read_verbs}.*{sensitive_path_re}"),
                &format!(r"(?i){read_verbs}\s+{sensitive_path_re}"),
                &format!(r"(?i){sensitive_path_re}.*{exfil_verbs}"),
                &format!(r"(?i){exfil_verbs}.*{sensitive_path_re}"),
            ],
        )
    })
}

fn re_doc_header() -> &'static Regex {
    RE_DOC_HEADER.get_or_init(|| compile_regex("doc-header", r"(?m)^#{1,6}\s+\w"))
}

fn re_doc_bullet() -> &'static Regex {
    RE_DOC_BULLET.get_or_init(|| compile_regex("doc-bullet", r"(?m)^\s*[-*+]\s+\w|^\d+\.\s+\w"))
}

fn re_doc_code_block() -> &'static Regex {
    RE_DOC_CODE_BLOCK.get_or_init(|| compile_regex("doc-code-block", r"```|\t{1}|\n {4}"))
}

fn re_doc_table_row() -> &'static Regex {
    RE_DOC_TABLE_ROW.get_or_init(|| compile_regex("doc-table-row", r"(?m)^\|.*\|"))
}

fn re_doc_example() -> &'static Regex {
    RE_DOC_EXAMPLE.get_or_init(|| {
        compile_regex(
            "doc-example",
            r"(?i)\bexample[s]?\b|\bfor instance\b|\be\.g\.\b",
        )
    })
}

pub fn strip_zero_width(text: &str) -> (String, bool) {
    _strip_zero_width(text)
}

fn _strip_zero_width(text: &str) -> (String, bool) {
    let mut found = false;
    let mut cleaned = String::with_capacity(text.len());
    for ch in text.chars() {
        let cp = ch as u32;
        if ZERO_WIDTH_CHARS_CRITICAL.contains(&ch) || in_ranges(cp, ZERO_WIDTH_RANGES) {
            found = true;
            continue;
        }
        cleaned.push(ch);
    }
    (cleaned, found)
}

fn _detect_zero_width(text: &str) -> f64 {
    for ch in text.chars() {
        let cp = ch as u32;
        if ZERO_WIDTH_CHARS_CRITICAL.contains(&ch) || in_ranges(cp, ZERO_WIDTH_RANGES) {
            return 1.0;
        }
    }
    for ch in text.chars() {
        let cp = ch as u32;
        if ZERO_WIDTH_CHARS_SOFT.contains(&ch) || in_ranges(cp, ZERO_WIDTH_RANGES_SOFT) {
            return 0.3;
        }
    }
    0.0
}

pub fn normalize_unicode(text: &str) -> (String, bool) {
    _normalize_unicode(text)
}

fn _normalize_unicode(text: &str) -> (String, bool) {
    let normalized = text.nfkc().collect::<String>();
    let changed = normalized != text;
    (normalized, changed)
}

fn _detect_base64(text: &str) -> f64 {
    let mut matches = re_base64_candidate()
        .find_iter(text)
        .map(|m| m.as_str())
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return 0.0;
    }

    matches.sort_by_key(|m| std::cmp::Reverse(m.len()));
    for candidate in matches {
        let Ok(decoded_bytes) = STANDARD.decode(candidate) else {
            continue;
        };
        let mut decoded = decode_utf8_ignore_errors(&decoded_bytes);
        if decoded.len() > 8192 {
            decoded.truncate(8192);
        }
        let decoded_lower = decoded.to_lowercase();
        if BASE64_ATTACK_WORDS
            .iter()
            .any(|word| decoded_lower.contains(word))
        {
            return 0.65;
        }
        return 0.3;
    }
    0.1
}

fn _detect_rot13(text: &str) -> f64 {
    if re_rot13_marker().is_match(text) {
        if let Some(captures) = re_rot13_payload().captures(text) {
            if let Some(payload) = captures.get(1) {
                let decoded = rot13(payload.as_str()).to_lowercase();
                if BASE64_ATTACK_WORDS
                    .iter()
                    .any(|word| decoded.contains(word))
                {
                    return 0.65;
                }
            }
        }
        return 0.5;
    }
    if ROT13_SIGNATURES.iter().any(|sig| text.contains(sig)) {
        return 0.55;
    }
    0.0
}

fn _detect_structural_markers(text: &str) -> f64 {
    let mut score: f64 = 0.0;
    if re_structural_open_tag().is_match(text) {
        score += 0.5;
    }
    if re_structural_close_tag().is_match(text) {
        score += 0.3;
    }
    if re_structural_role_bracket().is_match(text) {
        score += 0.4;
    }
    if re_structural_chat_token().is_match(text) {
        score += 0.5;
    }
    if score > 0.0 {
        let delimiter_count = re_structural_long_delimiter().find_iter(text).count() as f64;
        if delimiter_count > 0.0 {
            score += (0.2 * delimiter_count).min(0.4);
        }
    }
    score.min(1.0)
}

fn _detect_unicode_anomalies(text: &str) -> f64 {
    let mut has_latin = false;
    let mut has_cyrillic = false;
    let mut has_greek = false;

    for ch in text.chars().filter(|ch| ch.is_alphabetic()) {
        let cp = ch as u32;
        has_latin |= is_latin(cp);
        has_cyrillic |= is_cyrillic(cp);
        has_greek |= is_greek(cp);
    }

    if has_latin && has_cyrillic {
        return 0.5;
    }
    if has_latin && has_greek {
        return 0.4;
    }
    0.0
}

fn _detect_known_payloads(text: &str) -> f64 {
    let mut matches = re_known_payloads()
        .iter()
        .filter_map(|(pattern, weight)| pattern.is_match(text).then_some(*weight))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return 0.0;
    }

    matches.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let mut top = matches[0];
    if matches.len() >= 2 {
        top = (top + matches[1] * 0.3).min(1.0);
    }
    top
}

fn _detect_instruction_language(text: &str) -> f64 {
    let text_lower = text.to_lowercase();
    (re_instruction_language()
        .iter()
        .filter(|pattern| pattern.is_match(&text_lower))
        .count() as f64
        * 0.3)
        .min(0.65)
}

fn _detect_sensitive_file_abuse(text: &str) -> f64 {
    if re_sensitive_file_abuse()
        .iter()
        .any(|pattern| pattern.is_match(text))
    {
        1.0
    } else {
        0.0
    }
}

fn _compute_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut length = 0usize;
    for ch in text.chars() {
        *freq.entry(ch).or_insert(0usize) += 1;
        length += 1;
    }

    let length = length as f64;
    let entropy = freq
        .values()
        .map(|count| {
            let p = *count as f64 / length;
            -(p * p.log2())
        })
        .sum::<f64>();

    if entropy > 5.5 {
        0.6
    } else if entropy > 5.0 {
        0.3
    } else {
        0.0
    }
}

fn _detect_document_context(text: &str) -> f64 {
    let mut score: f64 = 0.0;
    if re_doc_header().is_match(text) {
        score += 0.35;
    }
    if re_doc_bullet().is_match(text) {
        score += 0.25;
    }
    if re_doc_code_block().is_match(text) {
        score += 0.25;
    }
    if re_doc_table_row().is_match(text) {
        score += 0.20;
    }
    if re_doc_example().is_match(text) {
        score += 0.15;
    }
    score.min(1.0)
}

pub fn classify_text(text: &str) -> ClassifierResult {
    classify_text_with_threshold(text, DEFAULT_THRESHOLD)
}

fn classify_text_with_threshold(text: &str, threshold: f64) -> ClassifierResult {
    let feature_order = [
        "base64",
        "rot13",
        "structural",
        "unicode",
        "known_payloads",
        "instruction_lang",
        "sensitive_file_abuse",
        "entropy",
        "zero_width",
    ];

    let mut features = HashMap::from([
        ("base64".to_string(), _detect_base64(text)),
        ("rot13".to_string(), _detect_rot13(text)),
        ("structural".to_string(), _detect_structural_markers(text)),
        ("unicode".to_string(), _detect_unicode_anomalies(text)),
        ("known_payloads".to_string(), _detect_known_payloads(text)),
        (
            "instruction_lang".to_string(),
            _detect_instruction_language(text),
        ),
        (
            "sensitive_file_abuse".to_string(),
            _detect_sensitive_file_abuse(text),
        ),
        ("entropy".to_string(), _compute_entropy(text)),
        ("zero_width".to_string(), _detect_zero_width(text)),
    ]);

    let doc_confidence = _detect_document_context(text);
    let doc_dampener_disabled = std::env::var("ASF_DISABLE_DOC_DAMPENER")
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false);

    if !doc_dampener_disabled && doc_confidence >= 0.7 {
        let no_strong_signal = get_feature(&features, "known_payloads") < 0.5
            && get_feature(&features, "sensitive_file_abuse") < 0.5
            && get_feature(&features, "instruction_lang") <= 0.6;
        if no_strong_signal {
            let damp = f64::max(0.5, 1.0 - doc_confidence * 0.5);
            for feature in [
                "instruction_lang",
                "entropy",
                "structural",
                "base64",
                "rot13",
            ] {
                if let Some(value) = features.get_mut(feature) {
                    *value *= damp;
                }
            }
        }
    }

    let total_w = FEATURE_WEIGHTS
        .iter()
        .map(|(_, weight)| weight)
        .sum::<f64>();
    let mut score = FEATURE_WEIGHTS
        .iter()
        .map(|(feature, weight)| get_feature(&features, feature) * weight)
        .sum::<f64>()
        / total_w;

    let active = features.values().filter(|value| **value > 0.3).count();
    let has_strong = get_feature(&features, "known_payloads") > 0.0
        || get_feature(&features, "zero_width") > 0.0
        || get_feature(&features, "sensitive_file_abuse") > 0.0
        || get_feature(&features, "base64") >= 0.65
        || get_feature(&features, "structural") >= 0.5;

    if active >= 2 && has_strong {
        score = (score * (1.0 + 0.3 * (active as f64 - 1.0))).min(1.0);
    }

    let critical = feature_order
        .iter()
        .filter_map(|feature| {
            let value = get_feature(&features, feature);
            (value >= 0.7).then_some((*feature, value))
        })
        .collect::<Vec<_>>();

    let mut top = feature_order
        .iter()
        .filter_map(|feature| {
            let value = get_feature(&features, feature);
            (value > 0.3).then_some((*feature, value))
        })
        .collect::<Vec<_>>();
    top.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let blocked = !critical.is_empty() || score >= threshold;
    let top_text = top
        .iter()
        .map(|(name, value)| format!("{name}={value:.2}"))
        .collect::<Vec<_>>()
        .join(", ");

    let reason = if !critical.is_empty() {
        let critical_text = critical
            .iter()
            .map(|(name, value)| format!("{name}={value:.2}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Critical signal: {critical_text} [{top_text}]")
    } else if blocked {
        format!("Injection risk {score:.2} [{top_text}]")
    } else {
        String::new()
    };

    features.insert("doc_context".to_string(), doc_confidence);

    ClassifierResult {
        score,
        features,
        blocked,
        reason,
    }
}

pub fn classifier_gate_score(text: &str) -> f64 {
    _classifier_gate_score(text)
}

fn _classifier_gate_score(tool_input: &str) -> f64 {
    let result = classify_text(tool_input);
    if result.blocked {
        1.0
    } else {
        result.score
    }
}

pub fn classifier_gate(tool_input: &str) -> (bool, f64) {
    let result = classify_text(tool_input);
    (result.blocked, result.score)
}

/// Closure type passed by hardened_interceptor() into apply_l1_5_hardening().
/// Mirrors the Python interceptor_fn signature: (agent_id, tool_name, input) -> (verdict, reason).
pub type InterceptorFn = Box<dyn Fn(&str, &str, &str) -> (String, String)>;

/// Full L1.5 gate: strips zero-width chars, normalises unicode, runs classifier, then
/// delegates to the downstream interceptor when the input is not blocked.
/// Returns (verdict, reason, Option<canary_token>).
pub fn apply_l1_5_hardening(
    agent_id: &str,
    tool_name: &str,
    tool_input: &str,
    interceptor_fn: Option<InterceptorFn>,
) -> (String, String, Option<String>) {
    let (stripped, _) = _strip_zero_width(tool_input);
    let (normalized, _) = _normalize_unicode(&stripped);
    let result = classify_text(&normalized);
    if result.blocked {
        let score_pct = format!("{:.0}%", result.score * 100.0);
        return (
            "DENY".to_string(),
            format!("[L1.5] BLOCKED by heuristic classifier (score={score_pct}) agent={agent_id} tool={tool_name}"),
            None,
        );
    }
    match interceptor_fn {
        None => (
            "ALLOW".to_string(),
            "Authorized by L1.5 hardening checks.".to_string(),
            None,
        ),
        Some(f) => {
            let (verdict, reason) = f(agent_id, tool_name, &normalized);
            (verdict, reason, None)
        }
    }
}

// Kept as a thin compatibility helper for the existing daemon checker. This is not a
// port of Python apply_l1_5_hardening(); it only wires the classifier gate into the
// daemon's current stage-1.5 return shape.
pub fn l1_5_check(text: &str) -> (bool, &'static str, &'static str) {
    let (stripped, had_zero_width) = _strip_zero_width(text);
    let (normalized, _) = _normalize_unicode(&stripped);
    let classifier_input = if had_zero_width {
        text
    } else {
        normalized.as_str()
    };
    let result = classify_text(classifier_input);
    if result.blocked {
        (true, "l1.5_heuristic", "L1.5_BLOCK")
    } else {
        (false, "", "")
    }
}

fn get_feature(features: &HashMap<String, f64>, key: &str) -> f64 {
    features.get(key).copied().unwrap_or(0.0)
}

fn decode_utf8_ignore_errors(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\u{fffd}', "")
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn is_latin(cp: u32) -> bool {
    matches!(
        cp,
        0x0041..=0x005A
            | 0x0061..=0x007A
            | 0x00C0..=0x024F
            | 0x1E00..=0x1EFF
            | 0x2C60..=0x2C7F
            | 0xA720..=0xA7FF
            | 0xAB30..=0xAB6F
    )
}

fn is_cyrillic(cp: u32) -> bool {
    matches!(cp, 0x0400..=0x04FF | 0x0500..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F)
}

fn is_greek(cp: u32) -> bool {
    matches!(cp, 0x0370..=0x03FF | 0x1F00..=0x1FFF)
}

fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|(lo, hi)| *lo <= cp && cp <= *hi)
}

fn compile_regex(name: &str, pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| {
        eprintln!("[ERROR] failed to compile {name} regex pattern={pattern:?}: {err}");
        panic!("failed to compile {name} regex");
    })
}

fn compile_patterns(name: &str, patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .map(|pattern| compile_regex(name, pattern))
        .collect()
}

fn compile_weighted_patterns(name: &str, patterns: &[(&str, f64)]) -> Vec<(Regex, f64)> {
    patterns
        .iter()
        .map(|(pattern, weight)| (compile_regex(name, pattern), *weight))
        .collect()
}
