use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

const ZERO_WIDTH_CHARS_CRITICAL: &[char] = &[
    '\u{200b}', '\u{2060}', '\u{00ad}', '\u{feff}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
    '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

const ZERO_WIDTH_CHARS_SOFT: &[char] = &[
    '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{061c}', '\u{115f}', '\u{1160}', '\u{17b4}',
    '\u{17b5}', '\u{3164}', '\u{ffa0}',
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

const DEFAULT_THRESHOLD: f64 = 0.6;
const MAX_DECODE_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub struct ClassifierResult {
    pub score: f64,
    pub blocked: bool,
}

static RE_BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("base64-candidate", r"[A-Za-z0-9+/]{20,}={0,2}"));
static RE_ROT13_MARKER: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("rot13-marker", r"(?i)rot.?13"));
static RE_ROT13_PAYLOAD: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("rot13-payload", r"(?i)ROT13[^:]*:\s*(.{20,200})"));
static RE_STRUCTURAL_OPEN_TAG: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        "structural-open-tag",
        r"(?i)<(?:IMPORTANT|system|instructions?|prompt|override)\s*>",
    )
});
static RE_STRUCTURAL_CLOSE_TAG: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        "structural-close-tag",
        r"(?i)</(?:IMPORTANT|system|instructions?|prompt|override)\s*>",
    )
});
static RE_STRUCTURAL_ROLE_BRACKET: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        "structural-role-bracket",
        r"(?i)\[(?:SYSTEM|ASSISTANT|USER|INST|PROMPT)\]",
    )
});
static RE_STRUCTURAL_CHAT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        "structural-chat-token",
        r"(?i)<\|(?:im_start|im_end|im_sep|system|user|assistant)\|>",
    )
});
static RE_STRUCTURAL_LONG_DELIMITER: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("structural-long-delimiter", r"[-=]{10,}"));
static RE_KNOWN_PAYLOADS: LazyLock<Vec<(Regex, f64)>> = LazyLock::new(|| {
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
            (
                r"(?i)ignore (?:all )?(?:previous|prior) (?:instructions?|rules)",
                0.75,
            ),
            (r"(?i)ignore .{0,30}instructions", 0.75),
            (r"(?i)ignore .{0,10}rules", 0.72),
            (r"(?i)new (?:task|instructions?|objective)", 0.4),
            (r"(?i)drop\s+table", 0.9),
            (r"(?i)\bnow you are\b.{0,30}\ban? \w{3,}", 0.6),
            (
                r"(?i)\byou are\b.{0,30}\b(?:an? |the )(?:ai|assistant|bot|agent|character|persona|hacker|system|gpt|claude|llama|dan|dude)\b",
                0.75,
            ),
            (
                r"(?i)(?:film|movie|scene).{0,60}(?:actor|character).{0,40}(?:asks?|says?)",
                0.7,
            ),
            (
                r"(?i)(?:actors|people).{0,80}(?:in their roles|stay in character)",
                0.6,
            ),
            (r"(?i)(?:master thief|hacker|expert).{0,30}asks?", 0.7),
            (r"(?i)(?:excellent|great|well done).{0,30}\bnow\b", 0.5),
            (r"(?i)\bthat is enough\b.{0,30}\bnow\b", 0.6),
            (r"(?i)\byou've outdone\b", 0.5),
            (
                r"(?i)\bvergiss\b.{0,30}\b(?:alle|vorherigen?|bisherigen?|deine)?\b.{0,20}\b(?:aufgaben|befehle|instruktionen|anweisungen)\b",
                0.8,
            ),
            (r"(?i)\bstell dir vor\b.{0,30}\b(?:du |ihr )?bist\b", 0.7),
            (
                r"(?i)\bich möchte,? dass (?:sie|du)\b.{0,30}\b(?:als|wie)\b.{0,30}\bfungieren\b",
                0.65,
            ),
            (
                r"(?i)\bignoriere\b.{0,30}\b(?:alle |deine )?(?:anweisungen|befehle|regeln)\b",
                0.75,
            ),
            (r"(?i)\bexploiting (?:AI|this system)\b", 0.8),
            (
                r"(?i)(?:input|output).{0,15}(?:input|output).{0,15}(?:input|output)",
                0.5,
            ),
            (
                r"(?i)\bforget (?:all |your )?(?:previous |prior )?(?:instructions?|tasks|rules|commands)",
                0.7,
            ),
            (r"(?i)\bforget (?:about |)(?:all |)these instructions", 0.75),
            (r"(?i)\bprint.{0,30}\byour (?:system |)prompt", 0.8),
            (
                r"(?i)\b(?:reveal|show|print|repeat|output).{0,30}\b(?:system )?prompt is\b",
                0.65,
            ),
        ],
    )
});
static RE_INSTRUCTION_LANGUAGE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_patterns(
        "instruction-language",
        &[
            r#"(?:print|output|say|echo|write|return)\s+["']"#,
            r"(?:read|access|fetch|retrieve|open)\s+(?:~|/|\\|\.\.)",
            r"(?:send|forward|redirect)\s+(?:all|the|every)",
            r"(?:execute|run|eval)\s+(?:the|this|following)",
        ],
    )
});
static RE_SENSITIVE_FILE_ABUSE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
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
});
static RE_HEX_STRIP_PREFIX_AND_SPACE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("hex-strip-prefix-and-space", r"0x|\s"));
static RE_DOC_HEADER: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("doc-header", r"(?m)^#{1,6}\s+\w"));
static RE_DOC_BULLET: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("doc-bullet", r"(?m)^\s*[-*+]\s+\w|^\d+\.\s+\w"));
static RE_DOC_CODE_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("doc-code-block", r"```|\t{1}|\n {4}"));
static RE_DOC_TABLE_ROW: LazyLock<Regex> =
    LazyLock::new(|| compile_regex("doc-table-row", r"(?m)^\|.*\|"));
static RE_DOC_EXAMPLE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        "doc-example",
        r"(?i)\bexample[s]?\b|\bfor instance\b|\be\.g\.\b",
    )
});

pub fn force_regexes() {
    LazyLock::force(&RE_BASE64_CANDIDATE);
    LazyLock::force(&RE_ROT13_MARKER);
    LazyLock::force(&RE_ROT13_PAYLOAD);
    LazyLock::force(&RE_STRUCTURAL_OPEN_TAG);
    LazyLock::force(&RE_STRUCTURAL_CLOSE_TAG);
    LazyLock::force(&RE_STRUCTURAL_ROLE_BRACKET);
    LazyLock::force(&RE_STRUCTURAL_CHAT_TOKEN);
    LazyLock::force(&RE_STRUCTURAL_LONG_DELIMITER);
    LazyLock::force(&RE_KNOWN_PAYLOADS);
    LazyLock::force(&RE_INSTRUCTION_LANGUAGE);
    LazyLock::force(&RE_SENSITIVE_FILE_ABUSE);
    LazyLock::force(&RE_HEX_STRIP_PREFIX_AND_SPACE);
    LazyLock::force(&RE_DOC_HEADER);
    LazyLock::force(&RE_DOC_BULLET);
    LazyLock::force(&RE_DOC_CODE_BLOCK);
    LazyLock::force(&RE_DOC_TABLE_ROW);
    LazyLock::force(&RE_DOC_EXAMPLE);
}

pub fn strip_zero_width(text: &str) -> (String, bool) {
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

pub fn detect_zero_width(text: &str) -> f64 {
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
    let normalized = text.nfkc().collect::<String>();
    let changed = normalized != text;
    (normalized, changed)
}

pub fn detect_base64(text: &str) -> f64 {
    let mut matches = RE_BASE64_CANDIDATE
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
        let mut decoded = String::from_utf8_lossy(&decoded_bytes).into_owned();
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

pub fn detect_rot13(text: &str) -> f64 {
    if RE_ROT13_MARKER.is_match(text) {
        if let Some(captures) = RE_ROT13_PAYLOAD.captures(text) {
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

pub fn detect_structural_markers(text: &str) -> f64 {
    let mut score: f64 = 0.0;
    if RE_STRUCTURAL_OPEN_TAG.is_match(text) {
        score += 0.5;
    }
    if RE_STRUCTURAL_CLOSE_TAG.is_match(text) {
        score += 0.3;
    }
    if RE_STRUCTURAL_ROLE_BRACKET.is_match(text) {
        score += 0.4;
    }
    if RE_STRUCTURAL_CHAT_TOKEN.is_match(text) {
        score += 0.5;
    }
    if score > 0.0 {
        let delimiter_count = RE_STRUCTURAL_LONG_DELIMITER.find_iter(text).count() as f64;
        if delimiter_count > 0.0 {
            score += (0.2 * delimiter_count).min(0.4);
        }
    }
    score.min(1.0)
}

pub fn detect_unicode_anomalies(text: &str) -> f64 {
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

pub fn detect_known_payloads(text: &str) -> f64 {
    let mut matches = RE_KNOWN_PAYLOADS
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

pub fn detect_instruction_language(text: &str) -> f64 {
    let text_lower = text.to_lowercase();
    (RE_INSTRUCTION_LANGUAGE
        .iter()
        .filter(|pattern| pattern.is_match(&text_lower))
        .count() as f64
        * 0.3)
        .min(0.65)
}

pub fn detect_sensitive_file_abuse(text: &str) -> f64 {
    if RE_SENSITIVE_FILE_ABUSE
        .iter()
        .any(|pattern| pattern.is_match(text))
    {
        1.0
    } else {
        0.0
    }
}

pub fn compute_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut freq = HashMap::new();
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

pub fn detect_document_context(text: &str) -> f64 {
    let mut score: f64 = 0.0;
    if RE_DOC_HEADER.is_match(text) {
        score += 0.35;
    }
    if RE_DOC_BULLET.is_match(text) {
        score += 0.25;
    }
    if RE_DOC_CODE_BLOCK.is_match(text) {
        score += 0.25;
    }
    if RE_DOC_TABLE_ROW.is_match(text) {
        score += 0.20;
    }
    if RE_DOC_EXAMPLE.is_match(text) {
        score += 0.15;
    }
    score.min(1.0)
}

pub fn classify_text(text: &str) -> ClassifierResult {
    let mut features = HashMap::from([
        ("base64", detect_base64(text)),
        ("rot13", detect_rot13(text)),
        ("structural", detect_structural_markers(text)),
        ("unicode", detect_unicode_anomalies(text)),
        ("known_payloads", detect_known_payloads(text)),
        ("instruction_lang", detect_instruction_language(text)),
        ("sensitive_file_abuse", detect_sensitive_file_abuse(text)),
        ("entropy", compute_entropy(text)),
        ("zero_width", detect_zero_width(text)),
    ]);

    let doc_confidence = detect_document_context(text);
    let doc_dampener_disabled = std::env::var("ASF_DISABLE_DOC_DAMPENER")
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false);
    if !doc_dampener_disabled && doc_confidence >= 0.7 {
        let no_strong_signal = features["known_payloads"] < 0.5
            && features["sensitive_file_abuse"] < 0.5
            && features["instruction_lang"] <= 0.6;
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
        .map(|(feature, weight)| features[feature] * weight)
        .sum::<f64>()
        / total_w;
    let active = features.values().filter(|value| **value > 0.3).count();
    let has_strong = features["known_payloads"] > 0.0
        || features["zero_width"] > 0.0
        || features["sensitive_file_abuse"] > 0.0
        || features["base64"] >= 0.65
        || features["structural"] >= 0.5;
    if active >= 2 && has_strong {
        score = (score * (1.0 + 0.3 * (active as f64 - 1.0))).min(1.0);
    }
    let has_critical = features.values().any(|value| *value >= 0.7);
    let blocked = has_critical || score >= DEFAULT_THRESHOLD;
    ClassifierResult { score, blocked }
}

pub fn decode_and_rescan(text: &str) -> (String, f64) {
    let mut current = text.to_string();
    for _depth in 1..=5 {
        let (decoded, changed) = try_decode_all(&current);
        if !changed {
            break;
        }
        if decoded.len() > MAX_DECODE_BYTES {
            break;
        }
        let result = classify_text(&decoded);
        let score = if result.blocked { 1.0 } else { result.score };
        if score >= 0.2 {
            return (decoded, score);
        }
        current = decoded;
    }
    (current, 0.0)
}

pub fn l1_5_check(text: &str) -> (bool, &'static str, &'static str) {
    let (stripped, had_zero_width) = strip_zero_width(text);
    let (normalized, _) = normalize_unicode(&stripped);

    // Match Python apply_l1_5_hardening: when zero-width chars were found, classify
    // the ORIGINAL text so that detect_zero_width() fires with score 1.0.
    let classifier_input = if had_zero_width {
        text
    } else {
        normalized.as_str()
    };
    let result = classify_text(classifier_input);
    if result.blocked {
        return (true, "l1.5_heuristic", "L1.5_BLOCK");
    }

    let (_, decode_score) = decode_and_rescan(&normalized);
    if decode_score >= 0.2 {
        return (true, "l1.5_encoding_bypass", "L1.5_BLOCK");
    }

    (false, "", "")
}

fn try_decode_all(text: &str) -> (String, bool) {
    let stripped = text.trim();

    if let Ok(decoded_bytes) = STANDARD.decode(stripped) {
        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
            if decoded != text && is_readable(&decoded) {
                return (decoded, true);
            }
        }
    }

    let cleaned_hex = RE_HEX_STRIP_PREFIX_AND_SPACE.replace_all(stripped, "");
    if !cleaned_hex.is_empty()
        && cleaned_hex.len() % 2 == 0
        && cleaned_hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        let mut bytes = Vec::with_capacity(cleaned_hex.len() / 2);
        let mut valid = true;
        for index in (0..cleaned_hex.len()).step_by(2) {
            match u8::from_str_radix(&cleaned_hex[index..index + 2], 16) {
                Ok(byte) => bytes.push(byte),
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            if let Ok(decoded) = String::from_utf8(bytes) {
                if decoded != text && is_readable(&decoded) {
                    return (decoded, true);
                }
            }
        }
    }

    let decoded = rot13(stripped);
    if decoded != text && is_readable(&decoded) {
        return (decoded, true);
    }

    (text.to_string(), false)
}

fn is_readable(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let printable = text
        .chars()
        .filter(|ch| {
            let cp = *ch as u32;
            (32..=126).contains(&cp) || matches!(*ch, '\n' | '\r' | '\t')
        })
        .count();
    printable as f64 / text.chars().count() as f64 >= 0.8
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
    matches!(cp, 0x0041..=0x007A | 0x00C0..=0x024F | 0x1E00..=0x1EFF)
}

fn is_cyrillic(cp: u32) -> bool {
    matches!(cp, 0x0400..=0x04FF | 0x0500..=0x052F)
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
