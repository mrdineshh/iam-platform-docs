//! Non-Windows development fallback ONLY -- never shipped. Phase 1 targets
//! Windows exclusively (spec Section 2.1); this exists purely so
//! `agent_core`'s logic can be built, unit-tested, and manually smoke-run
//! on this repository's own Linux dev/CI environment, which has no Windows
//! host to build or test the real `windows.rs` path on. Collecting real
//! hardware attributes and opening a real browser both degrade to
//! best-effort stand-ins here.

use agent_core::device_identity::HardwareAttributes;
use agent_core::enrollment::BrowserLauncher;

pub struct FallbackBrowserLauncher;

impl BrowserLauncher for FallbackBrowserLauncher {
    fn open(&self, url: &str) -> std::io::Result<()> {
        // Best-effort only: try xdg-open (Linux) then open (macOS); if neither exists, just log
        // the URL so a human can open it manually. The real Windows path (`cmd /C start`) is in
        // windows.rs and is what Phase 1 actually ships.
        for (cmd, args) in [("xdg-open", vec![url]), ("open", vec![url])] {
            if std::process::Command::new(cmd).args(&args).spawn().is_ok() {
                return Ok(());
            }
        }
        tracing::warn!(%url, "no browser launcher available on this platform; open this URL manually");
        Ok(())
    }
}

pub fn browser_launcher() -> Box<dyn BrowserLauncher> {
    Box::new(FallbackBrowserLauncher)
}

pub fn collect_hardware_attributes() -> HardwareAttributes {
    HardwareAttributes {
        manufacturer: None,
        model: None,
        os_version: Some(std::env::consts::OS.to_string()),
        hardware_uuid: None,
        serial_number: None,
    }
}

pub fn run_as_service<F>(run: F) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    tracing::info!("non-Windows fallback: running the agent loop directly in this process, not as an OS service");
    run()
}
