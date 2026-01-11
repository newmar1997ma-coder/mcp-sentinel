//! Perplexity-based entropy filter
//!
//! Detects GCG-style gibberish attacks by measuring Shannon entropy.
//! High-entropy random strings are a hallmark of adversarial suffix attacks.

use std::collections::HashMap;

/// Default entropy threshold (bits per character)
/// Normal English text: ~4.0-4.5 bits/char
/// Random gibberish: ~5.0+ bits/char
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Calculate Shannon entropy of text in bits per character
///
/// # Arguments
/// * `text` - The text to analyze
///
/// # Returns
/// Entropy in bits per character (0.0 to ~8.0 for ASCII)
pub fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;

    for c in text.chars() {
        *freq.entry(c).or_insert(0) += 1;
        total += 1;
    }

    let total_f64 = total as f64;
    let mut entropy = 0.0;

    for &count in freq.values() {
        if count > 0 {
            let p = count as f64 / total_f64;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if text has suspiciously high entropy
///
/// # Arguments
/// * `text` - The text to analyze
/// * `threshold` - Entropy threshold in bits per character
///
/// # Returns
/// true if entropy exceeds threshold (suspicious)
pub fn is_high_entropy(text: &str, threshold: f64) -> bool {
    // Skip very short strings - not enough data
    if text.len() < 10 {
        return false;
    }

    calculate_entropy(text) > threshold
}

/// Analyze a text segment for entropy anomalies
/// Returns (is_suspicious, entropy_value)
pub fn analyze_segment(text: &str) -> (bool, f64) {
    let entropy = calculate_entropy(text);
    (entropy > DEFAULT_ENTROPY_THRESHOLD, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_normal_text() {
        let normal = "The quick brown fox jumps over the lazy dog";
        let entropy = calculate_entropy(normal);
        assert!(entropy < DEFAULT_ENTROPY_THRESHOLD, "Normal text entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_gibberish() {
        let gibberish = "asdf8j2k3jk2j3kx9v8n2m3k4j5h6g7f8d9s0a1q2w3e4r5t";
        let entropy = calculate_entropy(gibberish);
        assert!(entropy > DEFAULT_ENTROPY_THRESHOLD, "Gibberish entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        assert_eq!(calculate_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_is_high_entropy() {
        assert!(!is_high_entropy("hello world", DEFAULT_ENTROPY_THRESHOLD));
        assert!(is_high_entropy("x9k2m3n4b5v6c7z8a1s2d3f4g5h6j7k8l9", DEFAULT_ENTROPY_THRESHOLD));
    }

    #[test]
    fn test_short_string_not_flagged() {
        // Short strings shouldn't be flagged even if random
        assert!(!is_high_entropy("x9k2m", DEFAULT_ENTROPY_THRESHOLD));
    }
}
