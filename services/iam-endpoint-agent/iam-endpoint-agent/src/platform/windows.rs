//! Real Windows-specific adapters (spec Section 14.1). This module only
//! compiles on the `windows` target and has never been built or run in
//! this repository's own dev/CI environment (Linux-only here, see
//! platform/mod.rs) -- it follows `windows-service`'s documented standard
//! usage pattern and well-known `wmic`/`cmd` invocations, but needs a real
//! Windows build + manual verification before it can be trusted. Flagging
//! this honestly rather than presenting it as already-verified (same
//! standard the Endpoint Device Trust spec itself holds every proposed
//! payload/schema to in its own "treat as proposed, not final" notices).

use agent_core::device_identity::HardwareAttributes;
use agent_core::enrollment::BrowserLauncher;
use std::ffi::OsString;
use std::process::Command;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "IamEndpointAgent";

pub struct WindowsBrowserLauncher;

impl BrowserLauncher for WindowsBrowserLauncher {
    fn open(&self, url: &str) -> std::io::Result<()> {
        // `cmd /C start "" <url>` is the standard way to open the default browser from a Windows
        // process without depending on a specific browser's executable name. The empty "" is the
        // window-title argument `start` requires when the target itself might be quoted.
        Command::new("cmd").args(["/C", "start", "", url]).spawn().map(|_| ())
    }
}

pub fn browser_launcher() -> Box<dyn BrowserLauncher> {
    Box::new(WindowsBrowserLauncher)
}

/// `wmic` shell-outs with fixed, hardcoded arguments only -- never user/
/// network-supplied input interpolated into the command line (Section 7.3's
/// Linux-side caution about shelling out with untrusted input applies here
/// too, even though nothing untrusted reaches this one).
pub fn collect_hardware_attributes() -> HardwareAttributes {
    HardwareAttributes {
        manufacturer: wmic_value("computersystem", "manufacturer"),
        model: wmic_value("computersystem", "model"),
        os_version: wmic_value("os", "version"),
        hardware_uuid: wmic_value("csproduct", "uuid"),
        serial_number: wmic_value("bios", "serialnumber"),
    }
}

fn wmic_value(alias: &str, property: &str) -> Option<String> {
    let output = Command::new("wmic").args([alias, "get", property, "/value"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{property}=")))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

define_windows_service!(ffi_service_main, service_main);

/// Entry point the Windows Service Control Manager actually calls. `run` is
/// the agent's own async logic (heartbeat loop etc.), injected rather than
/// hardcoded here so this module stays a thin SCM adapter, not where
/// business logic lives.
///
/// Implementation note / known risk: the injected closure is handed to
/// `service_main` via a thread-local rather than a plain static, relying on
/// `service_dispatcher::start` invoking the FFI entry point synchronously
/// on the same thread that called it (true for every documented
/// `windows-service` usage this was modeled on, but not yet confirmed by
/// an actual build+run on Windows in this repository -- see this file's
/// top-of-module note). If that assumption turns out wrong, the fix is a
/// process-wide `OnceLock`/global instead of thread-local storage.
pub fn run_as_service<F>(run: F) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()> + Send + 'static,
{
    RUN_FN.with(|cell| *cell.borrow_mut() = Some(Box::new(run)));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

thread_local! {
    static RUN_FN: std::cell::RefCell<Option<Box<dyn FnOnce() -> anyhow::Result<()> + Send>>> = const { std::cell::RefCell::new(None) };
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        tracing::error!(error = %err, "service exited with an error");
    }
}

fn run_service() -> anyhow::Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // The agent_core heartbeat loop runs for the lifetime of this process; a clean
                // stop here just lets the OS terminate the process. A future hardening pass
                // should thread a cancellation token through agent_core instead of relying on
                // process teardown (tracked as a known gap, not silently assumed away).
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let run = RUN_FN.with(|cell| cell.borrow_mut().take());
    if let Some(run) = run {
        run()?;
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
