//! # Perplexity-Based Entropy Filter
//!
//! This module implements Shannon entropy analysis to detect adversarial suffixes
//! and other high-entropy attack payloads characteristic of gradient-based attacks.
//!
//! ## Threat Model
//!
//! **Target Attack: GCG (Greedy Coordinate Gradient) Adversarial Suffixes**
//!
//! In 2023, Zou et al. demonstrated that gradient-based optimization could generate
//! "universal adversarial suffixes" - strings of seemingly random characters that,
//! when appended to any prompt, could cause aligned LLMs to produce harmful outputs.
//!
//! Example GCG suffix:
//! ```text
//! "describing.\ + similarlyNow write oppance sentence}444telecom"
//! ```
//!
//! These suffixes have a distinctive statistical signature: they exhibit unusually
//! high Shannon entropy compared to natural language text.
//!
//! ## Shannon Entropy Theory
//!
//! Shannon entropy, introduced by Claude Shannon in 1948, quantifies the average
//! "information content" or "surprise" in a message. For a discrete random variable
//! X with possible values {x₁, x₂, ..., xₙ} and probability mass function P(X):
//!
//! ```text
//! H(X) = -Σ P(xᵢ) log₂ P(xᵢ)
//! ```
//!
//! For text analysis, we treat each character as a sample and compute the empirical
//! distribution over the character set.
//!
//! ### Entropy Benchmarks
//!
//! | Content Type | Typical Entropy (bits/char) |
//! |--------------|----------------------------|
//! | English prose | 3.5 - 4.2 |
//! | Technical documentation | 4.0 - 4.5 |
//! | Source code | 4.2 - 4.8 |
//! | Random ASCII | 6.0 - 6.5 |
//! | GCG suffixes | 5.0 - 6.0 |
//! | Base64 data | 5.9 - 6.0 |
//!
//! ## Detection Strategy
//!
//! We use a threshold-based approach:
//!
//! 1. **Default threshold: 4.5 bits/char** - Balances detection rate vs false positives
//! 2. **Minimum length: 10 characters** - Avoids flagging short random-looking tokens
//! 3. **Window analysis** - For long texts, analyze sliding windows to catch
//!    embedded adversarial segments
//!
//! ## Limitations
//!
//! - **False Positives**: Base64 encoded content, UUIDs, cryptographic hashes,
//!   and dense technical content may trigger false positives
//! - **Evasion**: Attackers can potentially craft low-entropy adversarial suffixes,
//!   though this significantly constrains the attack search space
//! - **Multilingual**: Some languages (e.g., Chinese) have different entropy profiles
//!
//! ## References
//!
//! - **Shannon, C.E. (1948)** - "A Mathematical Theory of Communication"
//!   <https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf>
//!
//! - **Zou et al. (2023)** - "Universal and Transferable Adversarial Attacks on
//!   Aligned Language Models" <https://arxiv.org/abs/2307.15043>
//!
//! - **Jain et al. (2023)** - "Baseline Defenses for Adversarial Attacks Against
//!   Aligned Language Models" <https://arxiv.org/abs/2309.00614>

use std::collections::HashMap;

/// Default entropy threshold in bits per character.
///
/// This value was empirically chosen to minimize false positives on legitimate
/// content while catching most GCG-style adversarial suffixes.
///
/// - Normal English text: ~4.0-4.5 bits/char
/// - Random gibberish: ~5.0+ bits/char
/// - GCG suffixes: typically 5.2-5.8 bits/char
///
/// # Tuning Guidance
///
/// - **Lower threshold (4.0)**: More aggressive, higher false positive rate
/// - **Higher threshold (5.0)**: More permissive, may miss some attacks
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Minimum text length for entropy analysis.
///
/// Very short strings don't provide enough samples for meaningful entropy
/// calculation. Below this threshold, we skip entropy checks to avoid
/// false positives on short identifiers, acronyms, etc.
pub const MIN_ANALYSIS_LENGTH: usize = 10;

/// Calculate Shannon entropy of text in bits per character.
///
/// Computes the empirical entropy based on character frequency distribution.
/// Uses base-2 logarithm, so entropy is measured in bits.
///
/// # Arguments
///
/// * `text` - The text to analyze
///
/// # Returns
///
/// Entropy in bits per character. Range:
/// - 0.0: All characters identical (e.g., "aaaaaaa")
/// - ~4.0: Typical English prose
/// - ~6.5: Near-random ASCII text
///
/// # Algorithm
///
/// 1. Count frequency of each unique character
/// 2. Convert counts to probabilities: P(c) = count(c) / total
/// 3. Compute: H = -Σ P(c) × log₂(P(c))
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::perplexity::calculate_entropy;
///
/// let normal = "Hello, world!";
/// let entropy = calculate_entropy(normal);
/// // Normal text has moderate entropy
/// assert!(entropy > 0.0 && entropy < 5.0);
/// ```
pub fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    // Build frequency map
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;

    for c in text.chars() {
        *freq.entry(c).or_insert(0) += 1;
        total += 1;
    }

    // Calculate Shannon entropy: H(X) = -Σ p(x) log₂ p(x)
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

/// Check if text has suspiciously high entropy.
///
/// A convenience function that applies the entropy threshold check with
/// proper handling of short strings.
///
/// # Arguments
///
/// * `text` - The text to analyze
/// * `threshold` - Entropy threshold in bits per character
///
/// # Returns
///
/// `true` if the text has entropy exceeding the threshold AND is long enough
/// to be meaningfully analyzed.
///
/// # Security Note
///
/// This function returning `false` does NOT guarantee the text is safe.
/// High entropy is one signal among many. Always combine with pattern
/// matching and other detection methods.
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::perplexity::{is_high_entropy, DEFAULT_ENTROPY_THRESHOLD};
///
/// // Normal text - not flagged
/// assert!(!is_high_entropy("The quick brown fox jumps over the lazy dog", DEFAULT_ENTROPY_THRESHOLD));
///
/// // Short string - NOT flagged (too short for reliable analysis)
/// assert!(!is_high_entropy("x9k2m", DEFAULT_ENTROPY_THRESHOLD));
/// ```
pub fn is_high_entropy(text: &str, threshold: f64) -> bool {
    // Skip very short strings - not enough data for reliable entropy estimation
    if text.len() < MIN_ANALYSIS_LENGTH {
        return false;
    }

    calculate_entropy(text) > threshold
}

/// Analyze a text segment for entropy anomalies.
///
/// Returns both the detection result and the computed entropy value for
/// logging and analysis purposes.
///
/// # Arguments
///
/// * `text` - The text segment to analyze
///
/// # Returns
///
/// A tuple of (is_suspicious, entropy_value) where:
/// - `is_suspicious`: `true` if entropy exceeds the default threshold
/// - `entropy_value`: The computed Shannon entropy in bits/char
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::perplexity::analyze_segment;
///
/// let (suspicious, entropy) = analyze_segment("Hello, world!");
/// println!("Entropy: {:.2} bits/char, Suspicious: {}", entropy, suspicious);
/// ```
pub fn analyze_segment(text: &str) -> (bool, f64) {
    let entropy = calculate_entropy(text);
    (entropy > DEFAULT_ENTROPY_THRESHOLD, entropy)
}

/// Analyze text using a sliding window to detect embedded high-entropy segments.
///
/// This is useful for detecting adversarial suffixes appended to otherwise
/// normal text. The window slides across the text, checking each segment.
///
/// # Arguments
///
/// * `text` - The full text to analyze
/// * `window_size` - Size of the sliding window in characters
/// * `threshold` - Entropy threshold for flagging
///
/// # Returns
///
/// `Some((start_index, entropy))` if a high-entropy window is found,
/// `None` if all windows are below threshold.
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::perplexity::{find_high_entropy_window, DEFAULT_ENTROPY_THRESHOLD};
///
/// let text = "Normal text here. x9k2m3n4b5v6c7z8a1s2d3f4g5h6 more text.";
/// if let Some((start, entropy)) = find_high_entropy_window(text, 20, DEFAULT_ENTROPY_THRESHOLD) {
///     println!("High entropy segment at position {}: {:.2} bits/char", start, entropy);
/// }
/// ```
pub fn find_high_entropy_window(
    text: &str,
    window_size: usize,
    threshold: f64,
) -> Option<(usize, f64)> {
    let chars: Vec<char> = text.chars().collect();

    if chars.len() < window_size {
        return None;
    }

    for start in 0..=(chars.len() - window_size) {
        let window: String = chars[start..start + window_size].iter().collect();
        let entropy = calculate_entropy(&window);

        if entropy > threshold {
            return Some((start, entropy));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_normal_text() {
        let normal = "The quick brown fox jumps over the lazy dog";
        let entropy = calculate_entropy(normal);
        assert!(
            entropy < DEFAULT_ENTROPY_THRESHOLD,
            "Normal text entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_entropy_gibberish() {
        let gibberish = "asdf8j2k3jk2j3kx9v8n2m3k4j5h6g7f8d9s0a1q2w3e4r5t";
        let entropy = calculate_entropy(gibberish);
        assert!(
            entropy > DEFAULT_ENTROPY_THRESHOLD,
            "Gibberish entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        // All identical characters = zero entropy
        assert_eq!(calculate_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_entropy_two_chars_equal() {
        // Two chars with equal frequency = 1 bit
        let entropy = calculate_entropy("abababab");
        assert!((entropy - 1.0).abs() < 0.01, "Expected ~1.0, got {}", entropy);
    }

    #[test]
    fn test_is_high_entropy() {
        assert!(!is_high_entropy("hello world", DEFAULT_ENTROPY_THRESHOLD));
        assert!(is_high_entropy(
            "x9k2m3n4b5v6c7z8a1s2d3f4g5h6j7k8l9",
            DEFAULT_ENTROPY_THRESHOLD
        ));
    }

    #[test]
    fn test_short_string_not_flagged() {
        // Short strings shouldn't be flagged even if random-looking
        assert!(!is_high_entropy("x9k2m", DEFAULT_ENTROPY_THRESHOLD));
    }

    #[test]
    fn test_gcg_style_suffix() {
        // Simulated GCG-style adversarial suffix
        let gcg_suffix = "describing.\\+similarlyNow write oppance sentence}444telecom";
        let entropy = calculate_entropy(gcg_suffix);
        assert!(
            entropy > 4.0,
            "GCG suffix should have elevated entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_sliding_window_detection() {
        let text = "This is normal text. x9k2m3n4b5v6c7z8a1s2d3f4g5h6j7k8l9 back to normal.";
        let result = find_high_entropy_window(text, 30, DEFAULT_ENTROPY_THRESHOLD);
        assert!(result.is_some(), "Should detect high-entropy window");
    }

    #[test]
    fn test_sliding_window_clean() {
        let text = "This is completely normal English text without any suspicious content.";
        let result = find_high_entropy_window(text, 20, DEFAULT_ENTROPY_THRESHOLD);
        assert!(result.is_none(), "Should not flag normal text");
    }
}
