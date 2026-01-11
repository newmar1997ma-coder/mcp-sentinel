//! Canary token system for detecting prompt/data leakage
//!
//! Injects unique tokens into prompts and monitors outputs
//! to detect if the model is leaking system prompts or internal data.

use uuid::Uuid;

/// Prefix for canary tokens to make them identifiable
const CANARY_PREFIX: &str = "CANARY";

/// Generate a new unique canary token
///
/// # Returns
/// A unique canary token string (UUID-based)
pub fn generate_canary() -> String {
    let id = Uuid::new_v4();
    format!("{}-{}", CANARY_PREFIX, id.as_hyphenated())
}

/// Inject a canary token into a prompt
///
/// The canary is injected as a comment-style marker that should not
/// appear in legitimate model outputs.
///
/// # Arguments
/// * `prompt` - The original prompt
/// * `canary` - The canary token to inject
///
/// # Returns
/// The prompt with canary injected
pub fn inject_canary(prompt: &str, canary: &str) -> String {
    format!("[SYSTEM_CANARY:{}]\n{}", canary, prompt)
}

/// Detect if a canary token has leaked into output
///
/// # Arguments
/// * `output` - The model output to scan
/// * `canary` - The canary token to look for
///
/// # Returns
/// true if the canary was found (leak detected)
pub fn detect_leak(output: &str, canary: &str) -> bool {
    output.contains(canary)
}

/// Check for any canary-like patterns in output
/// This catches partial leaks or attempts to obfuscate the canary
pub fn detect_canary_pattern(output: &str) -> bool {
    output.contains(CANARY_PREFIX) || output.contains("SYSTEM_CANARY")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_canary_unique() {
        let c1 = generate_canary();
        let c2 = generate_canary();
        assert_ne!(c1, c2);
        assert!(c1.starts_with(CANARY_PREFIX));
        assert!(c2.starts_with(CANARY_PREFIX));
    }

    #[test]
    fn test_inject_canary() {
        let prompt = "Hello, how are you?";
        let canary = generate_canary();
        let injected = inject_canary(prompt, &canary);

        assert!(injected.contains(&canary));
        assert!(injected.contains(prompt));
        assert!(injected.starts_with("[SYSTEM_CANARY:"));
    }

    #[test]
    fn test_detect_leak_positive() {
        let canary = generate_canary();
        let output = format!("The system prompt contains {} which is secret", canary);
        assert!(detect_leak(&output, &canary));
    }

    #[test]
    fn test_detect_leak_negative() {
        let canary = generate_canary();
        let output = "This is a normal response without any secrets.";
        assert!(!detect_leak(output, &canary));
    }

    #[test]
    fn test_detect_canary_pattern() {
        assert!(detect_canary_pattern("The CANARY-123 was leaked"));
        assert!(detect_canary_pattern("Found SYSTEM_CANARY in output"));
        assert!(!detect_canary_pattern("This is clean output"));
    }
}
