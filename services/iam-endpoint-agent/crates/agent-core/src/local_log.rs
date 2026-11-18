//! Local (on-device) event log (spec Section 14.1: "use ... Windows Event Log integrations"). Security-relevant
//! agent events are mirrored to the operating system's own log so an administrator can see them in Event Viewer
//! even when the backend is unreachable, which is exactly when they matter most.
//!
//! This module holds only the platform-agnostic parts: the sink trait and the stable event-id and severity
//! mappings (unit-tested). The Windows adapter that actually calls the Event Log API is in the binary crate.

/// Receives every event the agent raises. Implementations must never block or fail the caller.
pub trait LocalEventSink: Send + Sync {
    fn write(&self, severity: &str, event_type: &str, message: &str);
}

/// Stable numeric ids, so a SIEM rule or an admin's Event Viewer filter keeps working across versions.
pub fn event_id(event_type: &str) -> u32 {
    match event_type {
        "agent.started" => 1000,
        "agent.tamper_detected" => 1001,
        "agent.tamper_cleared" => 1002,
        "agent.policy_rejected" => 1003,
        "agent.clock_moved_backwards" => 1004,
        "agent.posture_collection_failed" => 1005,
        "agent.stopped" => 1006,
        "agent.browser_policy_applied" => 1010,
        "agent.update_installing" => 1020,
        "agent.update_rejected" => 1021,
        "agent.update_failed" => 1022,
        "agent.browser_policy_failed" => 1011,
        _ => 1999,
    }
}

/// Windows event types: 1 = error, 2 = warning, 4 = information.
pub fn windows_event_type(severity: &str) -> u16 {
    match severity {
        "CRITICAL" | "ERROR" => 1,
        "WARNING" => 2,
        _ => 4,
    }
}

/// The event log refuses very long strings; keep the useful start and say that it was cut.
pub fn clip(message: &str, max_chars: usize) -> String {
    if message.chars().count() <= max_chars {
        return message.to_string();
    }
    let mut out: String = message.chars().take(max_chars).collect();
    out.push_str("... (truncated)");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_events_have_stable_ids_and_unknown_ones_a_catch_all() {
        assert_eq!(event_id("agent.tamper_detected"), 1001);
        assert_eq!(event_id("agent.policy_rejected"), 1003);
        assert_eq!(event_id("something.new"), 1999);
    }

    #[test]
    fn ids_are_unique() {
        let all = [
            "agent.started",
            "agent.tamper_detected",
            "agent.tamper_cleared",
            "agent.policy_rejected",
            "agent.clock_moved_backwards",
            "agent.posture_collection_failed",
            "agent.stopped",
            "agent.browser_policy_applied",
            "agent.browser_policy_failed",
            "agent.update_installing",
            "agent.update_rejected",
            "agent.update_failed",
        ];
        let mut ids: Vec<u32> = all.iter().map(|e| event_id(e)).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
    }

    #[test]
    fn severity_maps_to_windows_event_types() {
        assert_eq!(windows_event_type("CRITICAL"), 1);
        assert_eq!(windows_event_type("WARNING"), 2);
        assert_eq!(windows_event_type("INFO"), 4);
        assert_eq!(windows_event_type("anything else"), 4);
    }

    #[test]
    fn clip_keeps_short_messages_and_cuts_long_ones() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("abcdefghij", 4), "abcd... (truncated)");
    }
}
