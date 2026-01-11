//! # Sentinel Firewall - Semantic Security Layer
//!
//! The Semantic Firewall is the first line of defense in the MCP Sentinel architecture.
//! It operates at the protocol boundary, inspecting all MCP messages before they reach
//! the underlying model or are returned to clients.
//!
//! ## Purpose
//!
//! This crate implements three core defensive capabilities:
//!
//! 1. **Prompt Injection Detection** - Pattern-based and entropy-based detection of
//!    adversarial inputs designed to manipulate model behavior.
//!
//! 2. **Content Disarm & Reconstruct (CDR)** - Sanitization of potentially malicious
//!    content by stripping dangerous elements while preserving legitimate data.
//!
//! 3. **Canary Token Leak Detection** - Injection and monitoring of unique tokens to
//!    detect unauthorized disclosure of system prompts or internal data.
//!
//! ## Threat Model
//!
//! The firewall defends against the following attack classes:
//!
//! | Threat | Description | Defense |
//! |--------|-------------|---------|
//! | Direct Injection | "Ignore previous instructions" attacks | Pattern matching |
//! | Indirect Injection | Malicious content in retrieved documents | CDR sanitization |
//! | GCG Attacks | Adversarial suffixes (Zou et al., 2023) | Entropy filtering |
//! | Jailbreaks | DAN, role-play, mode-switching | Pattern + heuristics |
//! | Data Exfiltration | System prompt extraction | Canary tokens |
//! | Polyglot Attacks | Multi-format exploits | CDR + format validation |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      SEMANTIC FIREWALL                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
//! │  │  PERPLEXITY  │  │   PATTERN    │  │       CANARY         │  │
//! │  │   FILTER     │  │   MATCHER    │  │      DETECTOR        │  │
//! │  │              │  │              │  │                      │  │
//! │  │ Shannon H(X) │  │ Regex-based  │  │ UUID token injection │  │
//! │  │ > threshold  │  │ threat sigs  │  │ and leak detection   │  │
//! │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
//! │         │                 │                     │              │
//! │         └────────────┬────┴─────────────────────┘              │
//! │                      │                                         │
//! │                      ▼                                         │
//! │              ┌───────────────┐                                 │
//! │              │  SCAN RESULT  │                                 │
//! │              │               │                                 │
//! │              │ Safe│Flagged│ │                                 │
//! │              │    Blocked    │                                 │
//! │              └───────────────┘                                 │
//! │                                                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                         CDR ENGINE                              │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
//! │  │   TEXT   │ │  IMAGE   │ │   PDF    │ │   STRUCTURED     │   │
//! │  │ Sanitizer│ │ Sanitizer│ │ Sanitizer│ │   DATA (JSON)    │   │
//! │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## References
//!
//! This implementation draws on research from:
//!
//! - **Zou et al. (2023)** - "Universal and Transferable Adversarial Attacks on
//!   Aligned Language Models" - GCG attack methodology and defense strategies.
//!   <https://arxiv.org/abs/2307.15043>
//!
//! - **Greshake et al. (2023)** - "Not What You've Signed Up For: Compromising
//!   Real-World LLM-Integrated Applications with Indirect Prompt Injection"
//!   <https://arxiv.org/abs/2302.12173>
//!
//! - **Perez & Ribeiro (2022)** - "Ignore This Title and HackAPrompt: Exposing
//!   Systemic Vulnerabilities of LLMs through a Global Scale CTF"
//!   <https://arxiv.org/abs/2311.16119>
//!
//! - **Rebuff Framework** - Canary token injection for prompt leak detection.
//!   <https://github.com/protectai/rebuff>
//!
//! - **OWASP LLM Top 10** - Comprehensive taxonomy of LLM security risks.
//!   <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
//!
//! ## Usage
//!
//! ```rust,no_run
//! use sentinel_firewall::{SemanticFirewall, ScanResult};
//!
//! let firewall = SemanticFirewall::new();
//!
//! // Scan incoming user input
//! let user_input = "Can you help me with my code?";
//! match firewall.scan_input(user_input) {
//!     ScanResult::Safe => println!("Input is safe to process"),
//!     ScanResult::Flagged { threat, confidence, detail } => {
//!         println!("Suspicious input: {:?} ({:.0}%)", threat, confidence * 100.0);
//!     }
//!     ScanResult::Blocked { threat, confidence, detail } => {
//!         println!("BLOCKED: {:?} - {}", threat, detail);
//!     }
//! }
//!
//! // Inject canary and check for leaks in output
//! let prompt_with_canary = firewall.inject_canary("System prompt here");
//! // ... model generates response ...
//! let model_output = "Here is my response";
//! if firewall.check_canary_leak(model_output) {
//!     panic!("System prompt leaked!");
//! }
//! ```

pub mod canary;
pub mod cdr;
pub mod firewall;
pub mod models;
pub mod perplexity;

pub use firewall::SemanticFirewall;
pub use models::{SanitizeError, ScanResult, ThreatType};
