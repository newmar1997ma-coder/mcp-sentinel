//! # Content Disarm & Reconstruct (CDR)
//!
//! This module implements Content Disarm & Reconstruct (CDR) techniques for
//! sanitizing potentially malicious content before it enters the LLM pipeline.
//!
//! ## Philosophy
//!
//! > **"Don't detect the bomb. Rebuild without one."**
//!
//! Traditional security approaches try to detect malicious content through
//! signatures, heuristics, or behavioral analysis. CDR takes a fundamentally
//! different approach: instead of trying to identify what's dangerous, we
//! strip everything potentially dangerous and reconstruct only the safe elements.
//!
//! This philosophy is particularly valuable for LLM security because:
//!
//! 1. **Zero-day immunity**: Novel attacks have no signature to detect
//! 2. **Evasion resistance**: Obfuscation doesn't help if we strip anyway
//! 3. **Fail-safe default**: Unknown elements are removed, not analyzed
//!
//! ## Threat Model
//!
//! CDR defends against:
//!
//! | Attack Vector | CDR Defense |
//! |---------------|-------------|
//! | Control characters | Strip non-printable chars |
//! | Zero-width injection | Remove invisible Unicode |
//! | Directional overrides | Strip RTL/LTR markers |
//! | ANSI escape codes | Remove terminal sequences |
//! | Steganography | Re-encode media (future) |
//! | Polyglot payloads | Parse and reconstruct (future) |
//!
//! ## Content Types
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     CDR CONTENT PIPELINE                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐│
//! │  │    TEXT      │   │    IMAGE     │   │        PDF           ││
//! │  ├──────────────┤   ├──────────────┤   ├──────────────────────┤│
//! │  │ ✅ Implemented│   │ 🔜 Planned   │   │ 🔜 Planned           ││
//! │  │              │   │              │   │                      ││
//! │  │ • Strip ctrl │   │ • Strip EXIF │   │ • Remove JavaScript  ││
//! │  │ • Normalize  │   │ • Re-encode  │   │ • Flatten forms      ││
//! │  │ • Strip ANSI │   │ • Validate   │   │ • Strip embedded     ││
//! │  └──────────────┘   └──────────────┘   └──────────────────────┘│
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Text Sanitization
//!
//! The text sanitizer removes or neutralizes:
//!
//! - **Control characters** (U+0000-U+001F, U+007F-U+009F)
//! - **Zero-width characters** (U+200B-U+200F, U+2060-U+2064, U+FEFF)
//! - **Directional formatting** (U+202A-U+202E) - Can be used for text spoofing
//! - **ANSI escape sequences** - Terminal injection attacks
//!
//! Characters that are preserved:
//!
//! - Printable ASCII (space through tilde)
//! - Newlines, carriage returns, tabs (for formatting)
//! - Non-control Unicode (letters, numbers, symbols, emoji)
//!
//! ## Future Work: Binary CDR
//!
//! For image and PDF sanitization, the planned approach is:
//!
//! 1. **Images**: Decode → validate → re-encode as clean format
//!    - Removes EXIF metadata (privacy/tracking)
//!    - Eliminates steganographic payloads
//!    - Validates image structure
//!
//! 2. **PDFs**: Parse → extract safe elements → reconstruct
//!    - Remove embedded JavaScript
//!    - Strip embedded executables/OLE objects
//!    - Flatten interactive forms
//!    - Optionally: render to image and OCR back
//!
//! ## References
//!
//! - **OPSWAT CDR Technology**: <https://www.opswat.com/technologies/content-disarm-and-reconstruction>
//! - **Deep CDR Whitepaper**: <https://www.votiro.com/technology/>
//! - **NIST SP 800-177**: Trustworthy Email - CDR for attachments
//! - **Unicode Security**: <https://unicode.org/reports/tr36/> (Security considerations)

use crate::models::SanitizeError;

/// Maximum content size for sanitization (10MB).
///
/// Large payloads are rejected to prevent:
/// - Denial-of-service attacks on the sanitization engine
/// - Memory exhaustion
/// - Regex backtracking attacks
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;

/// Sanitize text content by removing potentially dangerous elements.
///
/// This function implements the CDR philosophy for text: instead of trying
/// to detect malicious patterns, we strip everything that could be dangerous
/// and preserve only known-safe content.
///
/// # What Gets Removed
///
/// - Control characters (except newline, carriage return, tab)
/// - Zero-width characters (invisible text manipulation)
/// - Directional overrides (text spoofing attacks)
/// - BOM (byte order mark)
///
/// # What Gets Preserved
///
/// - Printable ASCII characters
/// - Standard whitespace (space, newline, tab)
/// - Non-control Unicode (letters, symbols, emoji)
///
/// # Arguments
///
/// * `input` - The text to sanitize
///
/// # Returns
///
/// `Ok(sanitized_text)` or `Err(SanitizeError)` if the content is too large.
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::cdr::sanitize_text;
///
/// // Normal text passes through unchanged
/// let clean = sanitize_text("Hello, world!").unwrap();
/// assert_eq!(clean, "Hello, world!");
///
/// // Control characters are stripped
/// let dangerous = "Hello\x00World\x1F!";
/// let safe = sanitize_text(dangerous).unwrap();
/// assert_eq!(safe, "HelloWorld!");
/// ```
///
/// # Security Notes
///
/// - This function is intentionally aggressive about stripping content
/// - When in doubt, characters are removed rather than preserved
/// - This may alter the visual appearance of some Unicode text
pub fn sanitize_text(input: &str) -> Result<String, SanitizeError> {
    // Check size limit to prevent DoS
    if input.len() > MAX_CONTENT_SIZE {
        return Err(SanitizeError::TooLarge {
            size: input.len(),
            max: MAX_CONTENT_SIZE,
        });
    }

    let mut output = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            // Allow normal printable ASCII (space through tilde)
            ' '..='~' => output.push(c),

            // Allow standard whitespace for formatting
            '\n' | '\r' | '\t' => output.push(c),

            // Allow common unicode letters/symbols but filter control chars
            c if c.is_alphanumeric() || c.is_whitespace() => output.push(c),

            // STRIP: Zero-width characters (invisible text manipulation)
            // These can be used to hide content or confuse text processing
            '\u{200B}'..='\u{200F}' => {} // Zero-width space, joiners, marks

            // STRIP: Directional formatting (text spoofing attacks)
            // Can make text appear to read differently than it actually does
            '\u{202A}'..='\u{202E}' => {} // LRE, RLE, PDF, LRO, RLO

            // STRIP: Word joiners and invisible operators
            '\u{2060}'..='\u{2064}' => {} // Word joiner, invisible operators

            // STRIP: Byte Order Mark (sometimes used for encoding attacks)
            '\u{FEFF}' => {}

            // STRIP: C0 control characters (except already handled whitespace)
            '\u{0000}'..='\u{001F}' => {}

            // STRIP: C1 control characters
            '\u{007F}'..='\u{009F}' => {}

            // Allow other unicode (emojis, CJK, etc.) if not control chars
            c if !c.is_control() => output.push(c),

            // Strip everything else
            _ => {}
        }
    }

    Ok(output)
}

/// Strip ANSI escape sequences from text.
///
/// ANSI escape codes are used for terminal formatting (colors, cursor
/// movement, etc.) but can be exploited for:
///
/// - Terminal injection attacks
/// - Output spoofing
/// - Log file manipulation
///
/// # Arguments
///
/// * `input` - The text containing potential ANSI sequences
///
/// # Returns
///
/// The text with all ANSI escape sequences removed.
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::cdr::strip_ansi;
///
/// let colored = "\x1b[31mRed Text\x1b[0m Normal";
/// let plain = strip_ansi(colored);
/// assert_eq!(plain, "Red Text Normal");
/// ```
///
/// # Pattern Matched
///
/// This function removes sequences matching: `\x1b\[[0-9;]*[a-zA-Z]`
///
/// This covers:
/// - SGR (Select Graphic Rendition) - colors, bold, etc.
/// - Cursor positioning
/// - Screen clearing
/// - Other common CSI sequences
pub fn strip_ansi(input: &str) -> String {
    // Match ANSI CSI (Control Sequence Introducer) sequences
    // Format: ESC [ <params> <command>
    let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    ansi_regex.replace_all(input, "").to_string()
}

/// Sanitize JSON content by parsing and re-serializing.
///
/// This is a CDR approach for structured data: parse it, validate the
/// structure, then re-serialize. Any malformed or dangerous content
/// that doesn't survive the round-trip is eliminated.
///
/// # Arguments
///
/// * `input` - JSON string to sanitize
///
/// # Returns
///
/// `Ok(sanitized_json)` or error if parsing fails.
///
/// # Security Notes
///
/// - Removes comments (not valid JSON but sometimes accepted)
/// - Normalizes whitespace
/// - Validates UTF-8 encoding
pub fn sanitize_json(input: &str) -> Result<String, SanitizeError> {
    // First sanitize as text to remove control chars
    let clean_text = sanitize_text(input)?;

    // Parse and re-serialize to validate structure
    let value: serde_json::Value =
        serde_json::from_str(&clean_text).map_err(|e| SanitizeError::Failed(e.to_string()))?;

    serde_json::to_string(&value).map_err(|e| SanitizeError::Failed(e.to_string()))
}

/// Sanitize an image (stub - future implementation).
///
/// Planned implementation will:
///
/// 1. Decode the image using a safe decoder
/// 2. Validate image dimensions and format
/// 3. Strip all metadata (EXIF, XMP, IPTC)
/// 4. Re-encode to a clean format (PNG/JPEG)
///
/// This eliminates:
/// - Steganographic payloads
/// - Malformed image headers
/// - Embedded executable content
/// - Tracking metadata
///
/// # Arguments
///
/// * `_data` - Raw image bytes
///
/// # Returns
///
/// Currently returns `Err(UnsupportedType)`.
/// Future: `Ok(clean_image_bytes)`
pub fn sanitize_image(_data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    // TODO: Implement image sanitization
    // Planned approach:
    //
    // 1. Detect format (PNG, JPEG, GIF, WebP)
    // 2. Decode using image crate
    // 3. Validate dimensions (prevent billion-pixel attacks)
    // 4. Re-encode to same format without metadata
    //
    // Dependencies needed: image, kamadak-exif
    Err(SanitizeError::UnsupportedType("image".to_string()))
}

/// Sanitize a PDF document (stub - future implementation).
///
/// Planned implementation will:
///
/// 1. Parse PDF structure
/// 2. Remove JavaScript actions
/// 3. Remove embedded files/OLE objects
/// 4. Flatten interactive forms
/// 5. Optionally: render to image and reconstruct
///
/// This eliminates:
/// - Embedded malware
/// - JavaScript-based attacks
/// - Form submission to malicious URLs
/// - Polyglot payloads
///
/// # Arguments
///
/// * `_data` - Raw PDF bytes
///
/// # Returns
///
/// Currently returns `Err(UnsupportedType)`.
/// Future: `Ok(clean_pdf_bytes)`
///
/// # References
///
/// - PDF security issues: <https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/index.html>
/// - PDF/A for archival: Consider converting to PDF/A for maximum safety
pub fn sanitize_pdf(_data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    // TODO: Implement PDF sanitization
    // Planned approach:
    //
    // 1. Parse PDF structure with pdf crate
    // 2. Walk object tree, removing:
    //    - /JavaScript actions
    //    - /Launch actions
    //    - /URI actions (optional)
    //    - /EmbeddedFile streams
    //    - /ObjStm with suspicious content
    // 3. Re-serialize clean PDF
    //
    // Alternative (more aggressive):
    // 1. Render each page to image
    // 2. OCR if text needed
    // 3. Rebuild as image-only PDF
    //
    // Dependencies needed: pdf, image
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
    fn test_sanitize_strips_null() {
        let input = "before\x00after";
        let output = sanitize_text(input).unwrap();
        assert_eq!(output, "beforeafter");
    }

    #[test]
    fn test_sanitize_strips_zero_width() {
        // Zero-width space and BOM
        let input = "Hello\u{200B}World\u{FEFF}!";
        let output = sanitize_text(input).unwrap();
        assert_eq!(output, "HelloWorld!");
    }

    #[test]
    fn test_sanitize_strips_directional() {
        // Right-to-left override (can be used for text spoofing)
        let input = "Hello\u{202E}World!";
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
    fn test_sanitize_preserves_tabs() {
        let input = "Column1\tColumn2\tColumn3";
        let output = sanitize_text(input).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_sanitize_preserves_unicode() {
        let input = "Hello 世界! Привет! 🎉";
        let output = sanitize_text(input).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_strip_ansi_colors() {
        let input = "\x1b[31mRed\x1b[0m Normal";
        let output = strip_ansi(input);
        assert_eq!(output, "Red Normal");
    }

    #[test]
    fn test_strip_ansi_cursor() {
        let input = "\x1b[2J\x1b[H Clear and home";
        let output = strip_ansi(input);
        assert_eq!(output, " Clear and home");
    }

    #[test]
    fn test_strip_ansi_preserves_normal() {
        let input = "No escape codes here";
        let output = strip_ansi(input);
        assert_eq!(input, output);
    }

    #[test]
    fn test_sanitize_json() {
        let input = r#"{"key": "value", "number": 42}"#;
        let output = sanitize_json(input).unwrap();

        // Re-parse to verify valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["key"], "value");
        assert_eq!(parsed["number"], 42);
    }

    #[test]
    fn test_sanitize_json_removes_control_chars() {
        let input = "{\"key\": \"val\x00ue\"}";
        let output = sanitize_json(input).unwrap();
        assert!(!output.contains('\x00'));
    }

    #[test]
    fn test_size_limit() {
        let large = "x".repeat(MAX_CONTENT_SIZE + 1);
        let result = sanitize_text(&large);
        assert!(matches!(result, Err(SanitizeError::TooLarge { .. })));
    }

    #[test]
    fn test_image_not_yet_supported() {
        let result = sanitize_image(&[0xFF, 0xD8, 0xFF]); // JPEG magic
        assert!(matches!(result, Err(SanitizeError::UnsupportedType(_))));
    }

    #[test]
    fn test_pdf_not_yet_supported() {
        let result = sanitize_pdf(b"%PDF-1.4");
        assert!(matches!(result, Err(SanitizeError::UnsupportedType(_))));
    }
}
