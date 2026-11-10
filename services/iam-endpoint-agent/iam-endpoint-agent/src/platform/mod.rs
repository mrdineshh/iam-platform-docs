//! OS-specific adapters for the platform-agnostic `agent_core` crate.
//! Windows-only in Phase 1 (spec Section 2.1) -- `windows.rs` is the real
//! implementation; `fallback.rs` exists only so this binary can still be
//! built and manually exercised on a non-Windows development machine (this
//! repository's own dev/CI environment has no Windows host available to
//! build or test the real path on -- see each module's own note on that).

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
mod fallback;
#[cfg(not(windows))]
pub use fallback::*;
