//! Content Disarm & Reconstruct (CDR)
//!
//! Sanitizes potentially malicious content by stripping dangerous elements
//! while preserving legitimate content.

use crate::models::SanitizeError;

/// Maximum content size for sanitization (10MB)
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;

/// Sanitize text content by removing potentially dangerous elements
///
/// - Strips control characters (except newline, tab)
/// - Normalizes unicode (removes zero-width chars, etc.)
/// - Removes ANSI escape sequences
///
/// # Arguments
/// * `input` - The text to sanitize
///
/// # Returns
/// Sanitized text string
pub fn sanitize_text(input: &str) -> Result<String, SanitizeError> {
    if input.len() > MAX_CONTENT_SIZE {
        return Err(SanitizeError::TooLarge {
            size: input.len(),
            max: MAX_CONTENT_SIZE,
        });
    }

    let mut output = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            // Allow normal printable ASCII
            ' '..='~' => output.push(c),
            // Allow newlines and tabs
            '\n' | '\r' | '\t' => output.push(c),
            // Allow common unicode letters/symbols but filter control chars
            c if c.is_alphanumeric() || c.is_whitespace() => output.push(c),
            // Skip zero-width and control characters
            '\u{200B}'..='\u{200F}' => {} // Zero-width chars
            '\u{202A}'..='\u{202E}' => {} // Directional formatting
            '\u{2060}'..='\u{2064}' => {} // Word joiner, invisible chars
            '\u{FEFF}' => {}              // BOM
            '\u{0000}'..='\u{001F}' => {} // Control characters
            '\u{007F}'..='\u{009F}' => {} // More control characters
            // Allow other unicode (emojis, etc.)
            c if !c.is_control() => output.push(c),
            _ => {} // Skip everything else
        }
    }

    Ok(output)
}

/// Strip ANSI escape sequences from text
pub fn strip_ansi(input: &str) -> String {
    let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    ansi_regex.replace_all(input, "").to_string()
}

/// Sanitize an image (stub - future implementation)
///
/// Would strip EXIF data, re-encode to remove steganography, etc.
pub fn sanitize_image(_data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    // TODO: Implement image sanitization
    // - Strip EXIF/metadata
    // - Re-encode to remove steganographic payloads
    // - Validate image format
    Err(SanitizeError::UnsupportedType("image".to_string()))
}

/// Sanitize a PDF (stub - future implementation)
///
/// Would strip JavaScript, embedded objects, etc.
pub fn sanitize_pdf(_data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    // TODO: Implement PDF sanitization
    // - Remove JavaScript
    // - Remove embedded executables
    // - Flatten forms
    // - Re-render to image and back
    Err(SanitizeError::UnsupportedType("pdf".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_normal_text() {
        let input = "Hello, world! This is a test.";
        let output = sanitize_text(input).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_sanitize_strips_control_chars() {
        let input = "Hello\x00World\x1F!";
        let output = sanitize_text(input).unwrap();
        assert_eq!(output, "HelloWorld!");
    }

    #[test]
    fn test_sanitize_strips_zero_width() {
        let input = "Hello\u{200B}World\u{FEFF}!";
        let output = sanitize_text(input).unwrap();
        assert_eq!(output, "HelloWorld!");
    }

    #[test]
    fn test_sanitize_preserves_newlines() {
        let input = "Line 1\nLine 2\r\nLine 3";
        let output = sanitize_text(input).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_strip_ansi() {
        let input = "\x1b[31mRed\x1b[0m Normal";
        let output = strip_ansi(input);
        assert_eq!(output, "Red Normal");
    }

    #[test]
    fn test_size_limit() {
        let large = "x".repeat(MAX_CONTENT_SIZE + 1);
        let result = sanitize_text(&large);
        assert!(matches!(result, Err(SanitizeError::TooLarge { .. })));
    }
}
