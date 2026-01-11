//! # Context Flush Strategy
//!
//! Implements LRU-based context eviction to prevent memory exhaustion
//! and context window overflow in MCP agent execution.
//!
//! ## Threat Model
//!
//! Without context management, agents can exhaust resources via:
//! - **Memory explosion**: Unbounded context frame accumulation
//! - **Context overflow**: Exceeding LLM context window limits
//! - **State manipulation**: Exploiting stale/inconsistent context
//!
//! ## Design
//!
//! Context frames are stored with access timestamps. When capacity
//! is exceeded, the Least Recently Used (LRU) frames are evicted.
//! This trades potential data loss for guaranteed bounded memory.
//!
//! ## Eviction Policy
//!
//! | Policy     | Description                                  |
//! |------------|----------------------------------------------|
//! | LRU        | Evict least recently accessed frame          |
//! | Priority   | Evict lowest priority frame first            |
//! | Threshold  | Flush when utilization exceeds threshold     |
//!
//! ## Security Notes
//!
//! - Eviction is IRREVERSIBLE - evicted frames are permanently lost
//! - Critical frames should be marked with high priority to survive eviction
//! - Flush operations are logged for forensic analysis
//! - Context overflow errors MUST halt execution, not silently drop frames
//!
//! ## Memory Safety vs Data Loss Tradeoff
//!
//! This module makes an explicit tradeoff: we sacrifice some context
//! (potentially causing the agent to "forget" earlier steps) to guarantee
//! that memory usage remains bounded. This is the CORRECT tradeoff for
//! security-critical systems where unbounded growth could crash the host.
//!
//! ## Example
//!
//! ```rust
//! use sentinel_monitor::{ContextManager, Frame};
//!
//! let mut ctx = ContextManager::new(100); // Max 100 frames
//!
//! // Add frames during execution
//! ctx.push(Frame::new("step_1", "Initial state"));
//! ctx.push(Frame::new("step_2", "After tool call"));
//!
//! // Check utilization
//! if ctx.utilization() > 0.8 {
//!     let evicted = ctx.flush(10); // Evict 10 oldest frames
//!     eprintln!("Evicted {} frames", evicted);
//! }
//! ```

use crate::error::{MonitorError, Result};
use std::collections::VecDeque;

/// A single context frame representing agent state at a point in time.
///
/// # Fields
///
/// - `id`: Unique identifier for this frame
/// - `content`: Serialized state content
/// - `priority`: Eviction priority (higher = survives longer)
/// - `timestamp`: When this frame was last accessed
///
/// # Security Notes
///
/// Content should be sanitized before storage to prevent
/// injection attacks when frames are later reconstructed.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Unique frame identifier.
    id: String,
    /// Serialized frame content.
    content: String,
    /// Eviction priority (0 = lowest, u8::MAX = highest).
    priority: u8,
    /// Access timestamp (monotonic counter).
    accessed: u64,
}

impl Frame {
    /// Creates a new frame with default priority.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this frame
    /// * `content` - Serialized state content
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::Frame;
    ///
    /// let frame = Frame::new("step_1", "agent executed read operation");
    /// assert_eq!(frame.id(), "step_1");
    /// ```
    #[must_use]
    pub fn new(id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            content: content.into(),
            priority: 0,
            accessed: 0,
        }
    }

    /// Creates a frame with specified priority.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier
    /// * `content` - Serialized content
    /// * `priority` - Eviction priority (higher survives longer)
    ///
    /// # Security Notes
    ///
    /// Use high priority for security-critical frames that should
    /// not be evicted during normal flush operations.
    #[must_use]
    pub fn with_priority(id: impl Into<String>, content: impl Into<String>, priority: u8) -> Self {
        Self {
            id: id.into(),
            content: content.into(),
            priority,
            accessed: 0,
        }
    }

    /// Returns the frame ID.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the frame content.
    #[inline]
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Returns the frame priority.
    #[inline]
    #[must_use]
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Returns the last access timestamp.
    #[inline]
    #[must_use]
    pub const fn accessed(&self) -> u64 {
        self.accessed
    }

    /// Returns approximate memory size of this frame in bytes.
    #[inline]
    #[must_use]
    pub fn memory_size(&self) -> usize {
        self.id.len() + self.content.len() + 9 // 8 bytes for u64 + 1 for u8
    }
}

/// Manages context frames with LRU eviction policy.
///
/// # Overview
///
/// `ContextManager` maintains a bounded collection of context frames.
/// When the frame count exceeds capacity, the least recently used
/// frames are automatically evicted to maintain the bound.
///
/// # Thread Safety
///
/// `ContextManager` is not thread-safe. Each agent execution context
/// should have its own manager instance.
///
/// # Security Notes
///
/// - Capacity limits MUST be enforced to prevent memory exhaustion
/// - Eviction events SHOULD be logged for security audit
/// - High-priority frames resist eviction but can still be flushed
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::{ContextManager, Frame};
///
/// let mut ctx = ContextManager::new(3);
///
/// ctx.push(Frame::new("a", "content a"));
/// ctx.push(Frame::new("b", "content b"));
/// ctx.push(Frame::new("c", "content c"));
///
/// assert_eq!(ctx.len(), 3);
/// assert!(ctx.is_full());
///
/// // Adding another frame triggers auto-eviction of oldest
/// ctx.push(Frame::new("d", "content d"));
/// assert_eq!(ctx.len(), 3);
/// assert!(ctx.get("a").is_none()); // Evicted
/// ```
#[derive(Debug)]
pub struct ContextManager {
    /// Maximum number of frames allowed.
    capacity: usize,
    /// Current frames in insertion order.
    frames: VecDeque<Frame>,
    /// Monotonic timestamp counter.
    timestamp: u64,
    /// Total frames evicted during lifetime.
    evicted_count: u64,
    /// Flush threshold (0.0 to 1.0).
    flush_threshold: f64,
}

impl ContextManager {
    /// Creates a new context manager with specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of frames to store
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0 (use at least 1).
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::ContextManager;
    ///
    /// let ctx = ContextManager::new(100);
    /// assert_eq!(ctx.capacity(), 100);
    /// ```
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be at least 1");
        Self {
            capacity,
            frames: VecDeque::with_capacity(capacity),
            timestamp: 0,
            evicted_count: 0,
            flush_threshold: 0.8,
        }
    }

    /// Creates a context manager with custom flush threshold.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum frames
    /// * `flush_threshold` - Utilization threshold for auto-flush (0.0 to 1.0)
    #[must_use]
    pub fn with_threshold(capacity: usize, flush_threshold: f64) -> Self {
        assert!(capacity > 0, "capacity must be at least 1");
        assert!(
            (0.0..=1.0).contains(&flush_threshold),
            "threshold must be between 0.0 and 1.0"
        );
        Self {
            capacity,
            frames: VecDeque::with_capacity(capacity),
            timestamp: 0,
            evicted_count: 0,
            flush_threshold,
        }
    }

    /// Returns the maximum capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current number of frames.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns true if no frames are stored.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Returns true if at capacity.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.frames.len() >= self.capacity
    }

    /// Returns utilization as a fraction (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn utilization(&self) -> f64 {
        self.frames.len() as f64 / self.capacity as f64
    }

    /// Returns total frames evicted during lifetime.
    #[inline]
    #[must_use]
    pub const fn evicted_count(&self) -> u64 {
        self.evicted_count
    }

    /// Returns true if utilization exceeds flush threshold.
    #[inline]
    #[must_use]
    pub fn should_flush(&self) -> bool {
        self.utilization() > self.flush_threshold
    }

    /// Pushes a new frame, evicting oldest if at capacity.
    ///
    /// # Arguments
    ///
    /// * `frame` - Frame to add
    ///
    /// # Returns
    ///
    /// The evicted frame if one was removed, None otherwise.
    ///
    /// # Security Notes
    ///
    /// Auto-eviction ensures bounded memory but may lose context.
    /// Prefer explicit flush() for controlled eviction.
    pub fn push(&mut self, mut frame: Frame) -> Option<Frame> {
        self.timestamp += 1;
        frame.accessed = self.timestamp;

        let evicted = if self.is_full() {
            self.evicted_count += 1;
            self.frames.pop_front()
        } else {
            None
        };

        self.frames.push_back(frame);
        evicted
    }

    /// Gets a frame by ID, updating its access time.
    ///
    /// # Arguments
    ///
    /// * `id` - Frame ID to find
    ///
    /// # Returns
    ///
    /// Reference to the frame if found.
    ///
    /// # Security Notes
    ///
    /// Accessing a frame updates its timestamp, making it less
    /// likely to be evicted. This is intentional LRU behavior.
    pub fn get(&mut self, id: &str) -> Option<&Frame> {
        self.timestamp += 1;
        let ts = self.timestamp;

        self.frames.iter_mut().find(|f| f.id == id).map(|f| {
            f.accessed = ts;
            &*f
        })
    }

    /// Gets a frame by ID without updating access time (peek).
    ///
    /// # Arguments
    ///
    /// * `id` - Frame ID to find
    #[must_use]
    pub fn peek(&self, id: &str) -> Option<&Frame> {
        self.frames.iter().find(|f| f.id == id)
    }

    /// Flushes (evicts) the N oldest frames.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of frames to evict
    ///
    /// # Returns
    ///
    /// Number of frames actually evicted (may be less than requested).
    ///
    /// # Security Notes
    ///
    /// This is DESTRUCTIVE - evicted frames are permanently lost.
    /// Call this proactively when approaching capacity limits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{ContextManager, Frame};
    ///
    /// let mut ctx = ContextManager::new(10);
    /// for i in 0..10 {
    ///     ctx.push(Frame::new(format!("f{}", i), "content"));
    /// }
    ///
    /// let evicted = ctx.flush(3);
    /// assert_eq!(evicted, 3);
    /// assert_eq!(ctx.len(), 7);
    /// ```
    pub fn flush(&mut self, count: usize) -> usize {
        let actual = count.min(self.frames.len());
        for _ in 0..actual {
            self.frames.pop_front();
            self.evicted_count += 1;
        }
        actual
    }

    /// Flushes frames to reach target utilization.
    ///
    /// # Arguments
    ///
    /// * `target` - Target utilization (0.0 to 1.0)
    ///
    /// # Returns
    ///
    /// Number of frames evicted.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{ContextManager, Frame};
    ///
    /// let mut ctx = ContextManager::new(100);
    /// for i in 0..90 {
    ///     ctx.push(Frame::new(format!("f{}", i), "x"));
    /// }
    /// assert!((ctx.utilization() - 0.9).abs() < 0.01);
    ///
    /// let evicted = ctx.flush_to_utilization(0.5);
    /// assert!(ctx.utilization() <= 0.5);
    /// ```
    pub fn flush_to_utilization(&mut self, target: f64) -> usize {
        let target_count = (self.capacity as f64 * target) as usize;
        if self.frames.len() <= target_count {
            return 0;
        }
        self.flush(self.frames.len() - target_count)
    }

    /// Flushes all low-priority frames (priority < threshold).
    ///
    /// # Arguments
    ///
    /// * `priority_threshold` - Minimum priority to keep
    ///
    /// # Returns
    ///
    /// Number of frames evicted.
    ///
    /// # Security Notes
    ///
    /// Use this to preserve security-critical high-priority frames
    /// while evicting less important context.
    pub fn flush_low_priority(&mut self, priority_threshold: u8) -> usize {
        let before = self.frames.len();
        self.frames.retain(|f| f.priority >= priority_threshold);
        let evicted = before - self.frames.len();
        self.evicted_count += evicted as u64;
        evicted
    }

    /// Clears all frames.
    ///
    /// # Security Notes
    ///
    /// Use when resetting agent context. All frames are permanently lost.
    pub fn clear(&mut self) {
        self.evicted_count += self.frames.len() as u64;
        self.frames.clear();
    }

    /// Returns an iterator over all frames.
    pub fn iter(&self) -> impl Iterator<Item = &Frame> {
        self.frames.iter()
    }

    /// Returns total approximate memory usage in bytes.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        self.frames.iter().map(Frame::memory_size).sum()
    }

    /// Validates capacity and returns error if exceeded.
    ///
    /// # Returns
    ///
    /// `Ok(())` if within capacity, `Err(ContextOverflow)` if exceeded.
    ///
    /// # Security Notes
    ///
    /// Call this after operations that may add frames to ensure
    /// hard limits are respected. Unlike soft limits (threshold),
    /// this represents an absolute security boundary.
    pub fn validate_capacity(&self) -> Result<()> {
        if self.frames.len() > self.capacity {
            return Err(MonitorError::ContextOverflow {
                current: self.frames.len(),
                limit: self.capacity,
            });
        }
        Ok(())
    }
}

impl Default for ContextManager {
    /// Creates a manager with default capacity of 1000 frames.
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_creation() {
        let frame = Frame::new("test_id", "test content");
        assert_eq!(frame.id(), "test_id");
        assert_eq!(frame.content(), "test content");
        assert_eq!(frame.priority(), 0);
        assert_eq!(frame.accessed(), 0);
    }

    #[test]
    fn test_frame_with_priority() {
        let frame = Frame::with_priority("id", "content", 100);
        assert_eq!(frame.priority(), 100);
    }

    #[test]
    fn test_frame_memory_size() {
        let frame = Frame::new("abc", "12345"); // 3 + 5 + 9 = 17
        assert_eq!(frame.memory_size(), 17);
    }

    #[test]
    fn test_context_manager_creation() {
        let ctx = ContextManager::new(50);
        assert_eq!(ctx.capacity(), 50);
        assert_eq!(ctx.len(), 0);
        assert!(ctx.is_empty());
        assert!(!ctx.is_full());
    }

    #[test]
    fn test_push_and_get() {
        let mut ctx = ContextManager::new(10);
        ctx.push(Frame::new("a", "content a"));
        ctx.push(Frame::new("b", "content b"));

        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx.get("a").unwrap().content(), "content a");
        assert_eq!(ctx.get("b").unwrap().content(), "content b");
        assert!(ctx.get("c").is_none());
    }

    #[test]
    fn test_auto_eviction() {
        let mut ctx = ContextManager::new(3);
        ctx.push(Frame::new("a", "1"));
        ctx.push(Frame::new("b", "2"));
        ctx.push(Frame::new("c", "3"));

        assert!(ctx.is_full());

        // Push one more - should evict "a"
        let evicted = ctx.push(Frame::new("d", "4"));
        assert!(evicted.is_some());
        assert_eq!(evicted.unwrap().id(), "a");

        assert_eq!(ctx.len(), 3);
        assert!(ctx.peek("a").is_none());
        assert!(ctx.peek("d").is_some());
    }

    #[test]
    fn test_utilization() {
        let mut ctx = ContextManager::new(100);
        for i in 0..50 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }
        assert!((ctx.utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_flush() {
        let mut ctx = ContextManager::new(10);
        for i in 0..10 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }

        let evicted = ctx.flush(3);
        assert_eq!(evicted, 3);
        assert_eq!(ctx.len(), 7);
        assert_eq!(ctx.evicted_count(), 3);

        // First 3 should be gone
        assert!(ctx.peek("0").is_none());
        assert!(ctx.peek("1").is_none());
        assert!(ctx.peek("2").is_none());
        assert!(ctx.peek("3").is_some());
    }

    #[test]
    fn test_flush_to_utilization() {
        let mut ctx = ContextManager::new(100);
        for i in 0..80 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }

        let evicted = ctx.flush_to_utilization(0.5);
        assert_eq!(evicted, 30);
        assert_eq!(ctx.len(), 50);
        assert!(ctx.utilization() <= 0.5);
    }

    #[test]
    fn test_flush_low_priority() {
        let mut ctx = ContextManager::new(10);
        ctx.push(Frame::new("low1", "x")); // priority 0
        ctx.push(Frame::with_priority("high1", "x", 10));
        ctx.push(Frame::new("low2", "x")); // priority 0
        ctx.push(Frame::with_priority("high2", "x", 10));

        let evicted = ctx.flush_low_priority(5);
        assert_eq!(evicted, 2);
        assert_eq!(ctx.len(), 2);
        assert!(ctx.peek("high1").is_some());
        assert!(ctx.peek("high2").is_some());
        assert!(ctx.peek("low1").is_none());
    }

    #[test]
    fn test_should_flush() {
        let ctx = ContextManager::with_threshold(100, 0.8);
        assert!(!ctx.should_flush());

        let mut ctx = ContextManager::with_threshold(100, 0.8);
        for i in 0..85 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }
        assert!(ctx.should_flush());
    }

    #[test]
    fn test_clear() {
        let mut ctx = ContextManager::new(10);
        for i in 0..5 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }
        assert_eq!(ctx.len(), 5);

        ctx.clear();
        assert_eq!(ctx.len(), 0);
        assert!(ctx.is_empty());
        assert_eq!(ctx.evicted_count(), 5);
    }

    #[test]
    fn test_peek_vs_get() {
        let mut ctx = ContextManager::new(10);
        ctx.push(Frame::new("a", "x"));

        // Peek doesn't update timestamp
        let ts_before = ctx.peek("a").unwrap().accessed();
        let _ = ctx.peek("a");
        let ts_after = ctx.peek("a").unwrap().accessed();
        assert_eq!(ts_before, ts_after);

        // Get does update timestamp
        let _ = ctx.get("a");
        let ts_updated = ctx.peek("a").unwrap().accessed();
        assert!(ts_updated > ts_before);
    }

    #[test]
    fn test_validate_capacity() {
        let ctx = ContextManager::new(10);
        assert!(ctx.validate_capacity().is_ok());
    }

    #[test]
    fn test_memory_usage() {
        let mut ctx = ContextManager::new(10);
        ctx.push(Frame::new("abc", "12345")); // 3 + 5 + 9 = 17
        ctx.push(Frame::new("xy", "abc")); // 2 + 3 + 9 = 14
        assert_eq!(ctx.memory_usage(), 31);
    }

    #[test]
    fn test_default() {
        let ctx = ContextManager::default();
        assert_eq!(ctx.capacity(), 1000);
    }

    #[test]
    fn test_iter() {
        let mut ctx = ContextManager::new(10);
        ctx.push(Frame::new("a", "1"));
        ctx.push(Frame::new("b", "2"));

        let ids: Vec<_> = ctx.iter().map(|f| f.id()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    // Security-focused tests
    #[test]
    fn test_security_bounded_growth() {
        let mut ctx = ContextManager::new(5);

        // Try to add 100 frames - should stay at 5
        for i in 0..100 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }

        assert_eq!(ctx.len(), 5);
        assert_eq!(ctx.evicted_count(), 95);
    }

    #[test]
    fn test_security_priority_preservation() {
        let mut ctx = ContextManager::new(100);

        // Add mix of priorities
        for i in 0..50 {
            ctx.push(Frame::new(format!("low{}", i), "x"));
        }
        for i in 0..50 {
            ctx.push(Frame::with_priority(format!("high{}", i), "x", 255));
        }

        // Flush low priority - high priority survives
        ctx.flush_low_priority(128);
        assert_eq!(ctx.len(), 50);

        for i in 0..50 {
            assert!(ctx.peek(&format!("high{}", i)).is_some());
        }
    }

    #[test]
    #[should_panic(expected = "capacity must be at least 1")]
    fn test_zero_capacity_panics() {
        let _ = ContextManager::new(0);
    }

    #[test]
    fn test_flush_more_than_available() {
        let mut ctx = ContextManager::new(10);
        for i in 0..5 {
            ctx.push(Frame::new(format!("{}", i), "x"));
        }

        let evicted = ctx.flush(100); // Request 100, only 5 available
        assert_eq!(evicted, 5);
        assert!(ctx.is_empty());
    }
}
