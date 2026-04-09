// Password strength scoring copied from Proton Pass (proton-pass-common).
// Source: https://github.com/protonpass/proton-pass-common
//   proton-pass-common/src/password/scorer.rs
//   proton-pass-common/src/password/analyzer.rs
//
// Analyzer originally adapted from https://github.com/magiclen/passwords (MIT, Ron Li).

use std::collections::HashMap;
use std::sync::LazyLock;

use regex_lite::Regex;

// Generated at build time from passwords.txt
include!(concat!(env!("OUT_DIR"), "/common_passwords.rs"));

const SEPARATOR_SYMBOLS: &str = "[-,._@ ]";

static WORDLIST_PASSPHRASE_REGEX: LazyLock<Regex> = LazyLock::new(build_passphrase_regex);
static WORDLIST_PASSPHRASE_SEPARATOR_REGEX: LazyLock<Regex> =
    LazyLock::new(build_passphrase_separator_regex);

fn build_passphrase_regex() -> Regex {
    let separator = format!("(?:\\d|{SEPARATOR_SYMBOLS}|\\d{SEPARATOR_SYMBOLS})");
    let regex_str = format!("^([A-Z]?[a-z]{{1,9}}{separator})+([A-Z]?[a-z]{{1,9}})?$");
    Regex::new(&regex_str).unwrap()
}

fn build_passphrase_separator_regex() -> Regex {
    let separator_regex = format!("(?:\\d|{SEPARATOR_SYMBOLS}|\\d{SEPARATOR_SYMBOLS})");
    Regex::new(&separator_regex).unwrap()
}

const VULNERABLE_MAX_SCORE: f64 = 60.;
const WEAK_MAX_SCORE: f64 = 90.;

// ── Public API ──────────────────────────────────────────────────────────

// Password strength levels — must match the Slint password_strength property
pub const PW_EMPTY: i32 = 0;
pub const PW_WEAK: i32 = 1;
pub const PW_FAIR: i32 = 2;
pub const PW_GOOD: i32 = 3;
pub const PW_STRONG: i32 = 4;

/// Returns password strength as a named constant (`PW_EMPTY` .. `PW_STRONG`).
pub fn password_strength(password: &str) -> i32 {
    if password.is_empty() {
        return PW_EMPTY;
    }
    let result = inner_score_password(password);
    let score = result.numeric_score;
    match score {
        s if s <= VULNERABLE_MAX_SCORE => PW_WEAK,
        s if s < (VULNERABLE_MAX_SCORE + WEAK_MAX_SCORE) / 2.0 => PW_FAIR,
        s if s < WEAK_MAX_SCORE => PW_GOOD,
        _ => PW_STRONG,
    }
}

// ── Proton scorer (1:1) ─────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
struct PasswordScoreResult {
    numeric_score: f64,
    password_score: PasswordScore,
    penalties: Vec<PasswordPenalty>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum PasswordScore {
    Vulnerable,
    Weak,
    Strong,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum PasswordPenalty {
    NoLowercase,
    NoUppercase,
    NoNumbers,
    NoSymbols,
    Short,
    Consecutive,
    Progressive,
    ContainsCommonPassword,
    ShortWordList,
}

fn score_password(password: &str) -> f64 {
    let analyzed_password = analyze(password);
    let length_minus_other_chars =
        analyzed_password.length - analyzed_password.other_characters_count;
    let (max_score, return_original_score) = match length_minus_other_chars {
        0 => (0f64, false),
        1 => (2f64, false),
        2 => (5f64, false),
        3 => (9f64, false),
        4 => (16f64, false),
        5 => (24f64, false),
        6 => (30f64, false),
        7 => (45f64, false),
        8 => (51f64, false),
        9 => (60f64, false),
        10 => (69f64, false),
        11 => (75f64, false),
        12 => (80f64, false),
        13 => (86f64, false),
        14 => (91f64, false),
        15 => (95f64, false),
        16 => (100f64, false),
        _ => (100f64, true),
    };

    let initial_max_score = max_score;

    let mut score = max_score;

    if score > 0f64 {
        if analyzed_password.spaces_count >= 1 {
            score += analyzed_password.spaces_count as f64;
        }

        if analyzed_password.numbers_count == 0 {
            score -= max_score * 0.05;
        }

        if analyzed_password.lowercase_letters_count == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.uppercase_letters_count == 0 {
            score -= max_score * 0.1;
        }
        if analyzed_password.lowercase_letters_count >= 1
            && analyzed_password.uppercase_letters_count >= 1
        {
            score += 1f64;
        }
        if analyzed_password.symbols_count >= 1 {
            score += 1f64;
        }

        if analyzed_password.symbols_count == 0 {
            score -= max_score * 0.2;
        }

        let is_considered_strong = match analyzed_password.length {
            s if (0..13).contains(&s) => false,
            s if (13..20).contains(&s) => analyzed_password.symbols_count > 0,
            _ => true,
        };

        if !is_considered_strong {
            if analyzed_password.numbers_count == 0 {
                score -= max_score * 0.1;
            }

            if analyzed_password.uppercase_letters_count == 0 {
                score -= max_score * 0.1;
            }
        }

        if analyzed_password.consecutive_count > 0 {
            score -= max_score
                * (analyzed_password.consecutive_count as f64
                    / analyzed_password.length as f64
                    / 5f64);
        }

        if analyzed_password.progressive_count > 0 {
            score -= max_score
                * (analyzed_password.progressive_count as f64
                    / analyzed_password.length as f64
                    / 5f64);
        }

        score -= max_score
            * (analyzed_password.non_consecutive_count as f64
                / analyzed_password.length as f64
                / 10f64);
    }

    score = score.clamp(0f64, max_score);

    score += analyzed_password.other_characters_count as f64 * 20f64;

    if score > 100f64 {
        score = 100f64;
    }

    if return_original_score {
        initial_max_score
    } else {
        score
    }
}

fn password_penalties(password: &str) -> Vec<PasswordPenalty> {
    let analyzed_password = analyze(password);
    let mut penalties = vec![];

    if analyzed_password.numbers_count == 0 {
        penalties.push(PasswordPenalty::NoNumbers);
    }

    if analyzed_password.lowercase_letters_count == 0 {
        penalties.push(PasswordPenalty::NoLowercase);
    }
    if analyzed_password.uppercase_letters_count == 0 {
        penalties.push(PasswordPenalty::NoUppercase);
    }

    if analyzed_password.symbols_count == 0 {
        penalties.push(PasswordPenalty::NoSymbols);
    }

    if (0..13).contains(&analyzed_password.length) {
        penalties.push(PasswordPenalty::Short);
    }

    if analyzed_password.consecutive_count > 0 {
        penalties.push(PasswordPenalty::Consecutive);
    }

    if analyzed_password.progressive_count > 0 {
        penalties.push(PasswordPenalty::Progressive);
    }

    penalties
}

fn strip_common_passwords(password: &str) -> (String, bool) {
    let password_as_lowercase = password.to_lowercase();
    for common_password in COMMON_PASSWORDS {
        if password_as_lowercase.contains(common_password) {
            let pattern = match Regex::new(&format!("(?i){common_password}")) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let result = pattern.replace_all(password, "");
            return (result.to_string(), true);
        }
    }

    (password.to_string(), false)
}

fn inner_score_password(password: &str) -> PasswordScoreResult {
    let (strip_common_passwords, has_replaced) = strip_common_passwords(password);

    let mut penalties = vec![];
    if has_replaced {
        penalties.push(PasswordPenalty::ContainsCommonPassword);
    }

    let score = score_password(&strip_common_passwords);
    let scoring_penalties = password_penalties(password);
    penalties.extend(scoring_penalties);

    let final_score = if WORDLIST_PASSPHRASE_REGEX.is_match(password) {
        let groups = WORDLIST_PASSPHRASE_SEPARATOR_REGEX.split(password);
        let clean_groups: Vec<&str> = groups.filter(|str| !str.is_empty()).collect();
        match clean_groups.len() {
            1 | 2 => {
                penalties.push(PasswordPenalty::ShortWordList);
                score.min(VULNERABLE_MAX_SCORE - 1.)
            }
            3 => {
                penalties.push(PasswordPenalty::ShortWordList);
                score.min(WEAK_MAX_SCORE - 1.)
            }
            _ => score,
        }
    } else {
        score
    };

    PasswordScoreResult {
        numeric_score: final_score,
        password_score: proton_password_score(final_score),
        penalties,
    }
}

fn proton_password_score(score: f64) -> PasswordScore {
    match score {
        s if s <= VULNERABLE_MAX_SCORE => PasswordScore::Vulnerable,
        s if (VULNERABLE_MAX_SCORE..WEAK_MAX_SCORE).contains(&s) => PasswordScore::Weak,
        _ => PasswordScore::Strong,
    }
}

// ── Proton analyzer (1:1) ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
struct AnalyzedPassword {
    length: usize,
    spaces_count: usize,
    numbers_count: usize,
    lowercase_letters_count: usize,
    uppercase_letters_count: usize,
    symbols_count: usize,
    other_characters_count: usize,
    consecutive_count: usize,
    non_consecutive_count: usize,
    progressive_count: usize,
}

fn analyze(password: &str) -> AnalyzedPassword {
    let password_chars = password.chars();

    let mut spaces_count = 0usize;
    let mut numbers_count = 0usize;
    let mut lowercase_letters_count = 0usize;
    let mut uppercase_letters_count = 0usize;
    let mut symbols_count = 0usize;
    let mut other_characters_count = 0usize;
    let mut consecutive_count = 0usize;
    let mut non_consecutive_count = 0usize;
    let mut progressive_count = 0usize;

    let mut last_char_code = u32::MAX;
    let mut last_step = i32::MAX;
    let mut last_step_consecutive = false;
    let mut last_step_repeat = false;
    let mut last_char_code_consecutive = false;

    let mut count_map: HashMap<char, usize> = HashMap::new();

    let mut length = 0;

    for c in password_chars {
        let char_code = c as u32;

        if char_code <= 0x1F || char_code == 0x7F {
            continue;
        }

        length += 1;

        let count = count_map.entry(c).or_insert(0);
        *count += 1;

        if last_char_code == char_code {
            if last_char_code_consecutive {
                consecutive_count += 1;
            } else {
                consecutive_count += 2;
                last_char_code_consecutive = true;
            }
            last_step_consecutive = false;
        } else {
            last_char_code_consecutive = false;
            let step = last_char_code as i32 - char_code as i32;
            last_char_code = char_code;
            if last_step == step {
                if last_step_consecutive {
                    progressive_count += 1;
                } else {
                    last_step_consecutive = true;
                    if last_step_repeat {
                        progressive_count += 2;
                    } else {
                        progressive_count += 3;
                    }
                    last_step_repeat = true;
                }
            } else {
                last_step = step;
                if last_step_consecutive {
                    last_step_consecutive = false;
                } else {
                    last_step_repeat = false;
                }
            }
        }
        if (48..=57).contains(&char_code) {
            numbers_count += 1;
        } else if (65..=90).contains(&char_code) {
            uppercase_letters_count += 1;
        } else if (97..=122).contains(&char_code) {
            lowercase_letters_count += 1;
        } else if char_code == 32 {
            spaces_count += 1;
        } else if (33..=47).contains(&char_code)
            || (58..=64).contains(&char_code)
            || (91..=96).contains(&char_code)
            || (123..=126).contains(&char_code)
        {
            symbols_count += 1;
        } else {
            other_characters_count += 1;
        }
    }

    for (_, &a) in count_map.iter() {
        if a > 1 {
            non_consecutive_count += a;
        }
    }

    non_consecutive_count -= consecutive_count;

    AnalyzedPassword {
        length,
        spaces_count,
        numbers_count,
        lowercase_letters_count,
        uppercase_letters_count,
        symbols_count,
        other_characters_count,
        consecutive_count,
        non_consecutive_count,
        progressive_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strength_label(s: i32) -> &'static str {
        match s {
            0 => "Empty",
            1 => "Weak",
            2 => "Fair",
            3 => "Good",
            4 => "Strong",
            _ => "?",
        }
    }

    #[test]
    fn test_common_passwords_are_weak() {
        for pw in ["password", "abc123", "qwerty", "letmein", "123456"] {
            let s = password_strength(pw);
            assert_eq!(s, PW_WEAK, "{pw} should be Weak, got {}", strength_label(s));
        }
    }

    #[test]
    fn test_strong_passwords() {
        for pw in [
            "X#9kLm!pQ2vFw3Rn",
            "kj4$#hG8!mNpL2@x9Qw",
            "correct horse battery staple",
        ] {
            let s = password_strength(pw);
            assert_eq!(
                s,
                PW_STRONG,
                "{pw} should be Strong, got {}",
                strength_label(s)
            );
        }
    }

    #[test]
    fn test_proton_score_matches() {
        // These match Proton's 3-tier output
        let vulnerable = ["password", "abc123", "abcde", "Correct"];
        let strong = [
            "Correct3-horse@Battery8.staple8_Moon",
            "o4L7^_*[Ai!9Hf4-_5g^T",
        ];

        for pw in vulnerable {
            let r = inner_score_password(pw);
            assert_eq!(
                r.password_score,
                PasswordScore::Vulnerable,
                "{pw} should be Vulnerable, got {:?} (score={})",
                r.password_score,
                r.numeric_score,
            );
        }
        for pw in strong {
            let r = inner_score_password(pw);
            assert_eq!(
                r.password_score,
                PasswordScore::Strong,
                "{pw} should be Strong, got {:?} (score={})",
                r.password_score,
                r.numeric_score,
            );
        }
    }
}
