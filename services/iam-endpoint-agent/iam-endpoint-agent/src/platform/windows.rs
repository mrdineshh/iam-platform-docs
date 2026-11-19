//! Real Windows-specific adapters (spec Section 14.1). Compiled for the Windows target and smoke-tested
//! under Wine, but the Windows-only behavior (Service Control Manager, ShellExecuteW, the PowerShell probes)
//! has never run on a real Windows machine; treat it as unverified until it has. The PowerShell scripts in
//! `scripts/` are syntax-checked by the PowerShell parser, which proves they parse, not that every probe
//! returns what is expected on every edition of Windows.

use agent_core::device_identity::HardwareAttributes;
use agent_core::enrollment::BrowserLauncher;
use agent_core::posture::{PostureCollector, PostureError, PostureSignals};
use std::ffi::OsString;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "IamEndpointAgent";

pub struct WindowsBrowserLauncher;

impl BrowserLauncher for WindowsBrowserLauncher {
    /// Opens `url` in the user's default browser through the Windows shell API (`ShellExecuteW`), the same
    /// call Explorer uses for a double-clicked link.
    ///
    /// This deliberately does NOT go through `cmd.exe`. The first version ran `cmd /C start "" <url>`, and
    /// `cmd` treats every `&` as "run another command": the sign-in URL (which carries three `&`-separated
    /// parameters) was cut off after the first one and the remainder was executed as commands. Found by
    /// running the real .exe under Wine; ShellExecuteW takes the URL as data, so nothing in it is interpreted.
    fn open(&self, url: &str) -> std::io::Result<()> {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        // Defense in depth: agent-core already refuses non-http(s) URLs, but this is the last stop before
        // the OS acts on the string, so it checks too (never file:, ms-msdt:, javascript:, ...).
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "refusing to open a non-http(s) URL"));
        }
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (verb, target) = (wide("open"), wide(url));

        // SAFETY: both strings are NUL-terminated UTF-16 that outlive the call; the remaining arguments
        // are documented as optional and passed as null/zero (windows-sys 0.52: HWND and HINSTANCE are isize).
        let result = unsafe { ShellExecuteW(0, verb.as_ptr(), target.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
        // ShellExecuteW returns a value greater than 32 on success, an error code (<= 32) otherwise.
        if result > 32 {
            Ok(())
        } else {
            Err(std::io::Error::other(format!("ShellExecuteW could not open the browser (code {result})")))
        }
    }
}

pub fn browser_launcher() -> Box<dyn BrowserLauncher> {
    Box::new(WindowsBrowserLauncher)
}

/// Fixed, input-free scripts (see their headers). `include_str!`, so the exact text that was reviewed and
/// syntax-checked is what ships -- nothing is assembled at run time.
const POSTURE_SCRIPT: &str = include_str!("scripts/posture.ps1");
const HARDWARE_SCRIPT: &str = include_str!("scripts/hardware.ps1");

/// Generous: a cold PowerShell start plus the WMI queries takes several seconds on a slow machine.
const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs a script in Windows PowerShell and returns its stdout.
///
/// - Launched by **full path** under `%SystemRoot%`, never by searching `PATH`: the agent runs as SYSTEM, and a
///   `powershell.exe` planted earlier on `PATH` would otherwise run with those privileges.
/// - Passed as `-EncodedCommand` (base64 of UTF-16LE), which sidesteps every quoting problem -- the same class
///   of bug that broke the browser launch (`cmd.exe` and `&`).
/// - Bounded by a timeout, and killed if it hangs (`kill_on_drop`), so a wedged WMI query cannot stall the agent.
async fn run_powershell(script: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let system_root = std::env::var_os("SystemRoot").ok_or("the SystemRoot environment variable is not set")?;
    let exe = std::path::Path::new(&system_root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let encoded = STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());

    let mut command = tokio::process::Command::new(exe);
    command
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);

    let output = tokio::time::timeout(POWERSHELL_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("PowerShell did not finish within {POWERSHELL_TIMEOUT:?}"))?
        .map_err(|e| format!("could not start PowerShell: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() && !stdout.contains('{') {
        let stderr: String = String::from_utf8_lossy(&output.stderr).chars().take(300).collect();
        return Err(format!("PowerShell exited with {}: {stderr}", output.status));
    }
    Ok(stdout)
}

/// Hardware facts for enrollment. A failure degrades to "nothing known" (logged), not a failed enrollment:
/// these attributes are correlation context only and never proof of identity (PDF Section 5.2).
pub async fn collect_hardware_attributes() -> HardwareAttributes {
    let collected = match run_powershell(HARDWARE_SCRIPT).await {
        Ok(output) => HardwareAttributes::from_collector_output(&output).map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    collected.unwrap_or_else(|reason| {
        tracing::warn!(%reason, "could not read hardware attributes; enrolling without them");
        HardwareAttributes::default()
    })
}

pub struct WindowsPostureCollector;

impl PostureCollector for WindowsPostureCollector {
    fn collect(&self) -> impl Future<Output = Result<PostureSignals, PostureError>> + Send {
        async {
            let output = run_powershell(POSTURE_SCRIPT).await.map_err(PostureError::Collect)?;
            PostureSignals::from_collector_output(&output)
        }
    }
}

pub fn posture_collector() -> WindowsPostureCollector {
    WindowsPostureCollector
}

define_windows_service!(ffi_service_main, service_main);

type RunFn = Box<dyn FnOnce(watch::Receiver<bool>) -> anyhow::Result<()> + Send>;

// A process-wide slot, NOT a thread-local: `StartServiceCtrlDispatcherW` runs `ServiceMain` on a *new
// thread* created by the service control dispatcher (Microsoft docs, "ServiceMain"), so anything stored
// in thread-local storage by `run_as_service` would simply not exist there.
static RUN_FN: Mutex<Option<RunFn>> = Mutex::new(None);

/// Hands control to the Windows Service Control Manager. `run` is the agent's own logic, injected so this
/// module stays a thin SCM adapter. It receives a shutdown signal that fires when the SCM sends Stop or
/// Shutdown, and is expected to return promptly after it does.
pub fn run_as_service<F>(run: F) -> anyhow::Result<()>
where
    F: FnOnce(watch::Receiver<bool>) -> anyhow::Result<()> + Send + 'static,
{
    *RUN_FN.lock().map_err(|_| anyhow::anyhow!("service entry point lock poisoned"))? = Some(Box::new(run));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        // Goes nowhere visible under the SCM (no console); routing this to the Windows Event Log is a
        // known gap (spec Section 14.1), tracked rather than hidden.
        tracing::error!(error = %err, "service exited with an error");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // Wakes the sync loop out of its sleep; `run_service` reports Stopped once it returns.
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let report = |state: ServiceState, accepted: ServiceControlAccept, exit_code: ServiceExitCode| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };

    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0))?;

    // A missing entry point must be a failure the SCM can see, never a silent clean exit.
    let result = match RUN_FN.lock().map_err(|_| anyhow::anyhow!("service entry point lock poisoned"))?.take() {
        Some(run) => run(shutdown_rx),
        None => Err(anyhow::anyhow!("service started without an agent entry point")),
    };

    let exit_code = if result.is_ok() { ServiceExitCode::Win32(0) } else { ServiceExitCode::ServiceSpecific(1) };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), exit_code)?;
    result
}

/// Writes browser policy values under HKEY_LOCAL_MACHINE (admin/SYSTEM only, so a standard user cannot undo them).
/// The agent service runs as LocalSystem. `apply` touches only the values it is given. `merge_url_blocklist` is the one
/// place that also READS: a block list is a set of numbered values that a company's own group policy may share, so it
/// is read, merged with ours and written back, and entries that are not ours are kept.
pub struct RegistryBrowserPolicy;

impl agent_core::browser_policy::BrowserPolicyApplier for RegistryBrowserPolicy {
    fn apply(&self, entries: &[agent_core::browser_policy::PolicyEntry]) -> Result<(), agent_core::browser_policy::BrowserPolicyError> {
        use agent_core::browser_policy::{BrowserPolicyError, PolicyValue};
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
        };

        fn wide(s: &str) -> Vec<u16> {
            std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
        }

        for entry in entries {
            let mut key: HKEY = 0;
            let path = wide(entry.key_path);
            // SAFETY: all pointers refer to live, NUL-terminated buffers owned by this scope.
            let rc = unsafe {
                RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, std::ptr::null(), &mut key, std::ptr::null_mut())
            };
            if rc != 0 {
                return Err(BrowserPolicyError::Apply(format!("opening HKLM\\{} failed (Win32 error {rc})", entry.key_path)));
            }
            let PolicyValue::String(value) = &entry.value;
            let name = wide(entry.name);
            let data = wide(value);
            let bytes = (data.len() * 2) as u32;
            // SAFETY: `data` outlives the call and `bytes` is its exact length in bytes, including the NUL.
            let rc = unsafe { RegSetValueExW(key, name.as_ptr(), 0, REG_SZ, data.as_ptr() as *const u8, bytes) };
            unsafe { RegCloseKey(key) };
            if rc != 0 {
                return Err(BrowserPolicyError::Apply(format!("writing {} failed (Win32 error {rc})", entry.name)));
            }
        }
        Ok(())
    }

    fn merge_url_blocklist(&self, list: &agent_core::browser_policy::UrlBlockList) -> Result<(), agent_core::browser_policy::BrowserPolicyError> {
        rewrite_block_list(list, true, |current| agent_core::browser_policy::merge_block_list(current, &list.urls))
    }

    fn remove_url_blocklist(&self, list: &agent_core::browser_policy::UrlBlockList) -> Result<(), agent_core::browser_policy::BrowserPolicyError> {
        // Nothing to take off a browser that has no list at all: do not create one just to leave it empty.
        rewrite_block_list(list, false, |current| agent_core::browser_policy::remove_from_block_list(current, &list.urls))
    }
}

/// Reads a browser's URL block list (numbered string values "1","2",... under `<policy key>\URLBlocklist`), lets `compute` decide
/// what it should hold, and writes that back as consecutive "1".."N" (a browser stops reading at the first gap), deleting any
/// numbered value beyond the end. Values that are not numbered strings are left alone. With `create` false a missing list is
/// success: there is nothing to rewrite.
fn rewrite_block_list(
    list: &agent_core::browser_policy::UrlBlockList,
    create: bool,
    compute: impl Fn(&[String]) -> Vec<String>,
) -> Result<(), agent_core::browser_policy::BrowserPolicyError> {
    use agent_core::browser_policy::BrowserPolicyError;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_NO_MORE_ITEMS: u32 = 259;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    let list_key = format!("{}\\URLBlocklist", list.key_path);
    let path = wide(&list_key);
    let mut key: HKEY = 0;
    // SAFETY: all pointers refer to live, NUL-terminated buffers owned by this scope.
    let rc = unsafe {
        if create {
            RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, std::ptr::null(), &mut key, std::ptr::null_mut())
        } else {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ | KEY_WRITE, &mut key)
        }
    };
    if rc == ERROR_FILE_NOT_FOUND && !create {
        return Ok(());
    }
    if rc != 0 {
        return Err(BrowserPolicyError::Apply(format!("opening HKLM\\{list_key} failed (Win32 error {rc})")));
    }

    // What is there now. Only string values named with a positive number are list entries.
    let mut existing: Vec<(u32, String)> = Vec::new();
    let mut index = 0u32;
    let read: Result<(), BrowserPolicyError> = loop {
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 4096];
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        // SAFETY: the buffers are live for the call and the lengths passed are exactly their sizes (name in characters,
        // data in bytes).
        let rc = unsafe { RegEnumValueW(key, index, name.as_mut_ptr(), &mut name_len, std::ptr::null(), &mut kind, data.as_mut_ptr(), &mut data_len) };
        index += 1;
        match rc {
            0 => {
                if kind == REG_SZ {
                    let entry_name = String::from_utf16_lossy(&name[..name_len as usize]);
                    if let Ok(n) = entry_name.parse::<u32>() {
                        if n >= 1 {
                            let units: Vec<u16> = data[..data_len as usize].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
                            existing.push((n, String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()));
                        }
                    }
                }
            }
            ERROR_MORE_DATA => continue, // far too long to be a URL pattern: not ours, left alone
            ERROR_NO_MORE_ITEMS => break Ok(()),
            other => break Err(BrowserPolicyError::Apply(format!("reading HKLM\\{list_key} failed (Win32 error {other})"))),
        }
    };
    if let Err(err) = read {
        unsafe { RegCloseKey(key) };
        return Err(err);
    }

    existing.sort_by_key(|(n, _)| *n);
    let current: Vec<String> = existing.iter().map(|(_, v)| v.clone()).collect();
    let wanted = compute(&current);

    let mut result: Result<(), BrowserPolicyError> = Ok(());
    for (i, url) in wanted.iter().enumerate() {
        let name = wide(&(i + 1).to_string());
        let data = wide(url);
        let bytes = (data.len() * 2) as u32;
        // SAFETY: `data` outlives the call and `bytes` is its exact length in bytes, including the NUL.
        let rc = unsafe { RegSetValueExW(key, name.as_ptr(), 0, REG_SZ, data.as_ptr() as *const u8, bytes) };
        if rc != 0 {
            result = Err(BrowserPolicyError::Apply(format!("writing block list entry {} failed (Win32 error {rc})", i + 1)));
            break;
        }
    }
    if result.is_ok() {
        // The list may have got shorter: remove numbered entries beyond the new end.
        for (n, _) in existing.iter().filter(|(n, _)| *n as usize > wanted.len()) {
            let name = wide(&n.to_string());
            // SAFETY: `name` is a live, NUL-terminated buffer.
            let rc = unsafe { RegDeleteValueW(key, name.as_ptr()) };
            if rc != 0 && rc != ERROR_FILE_NOT_FOUND {
                result = Err(BrowserPolicyError::Apply(format!("removing block list entry {n} failed (Win32 error {rc})")));
                break;
            }
        }
    }
    unsafe { RegCloseKey(key) };
    result
}

pub fn browser_policy_applier() -> RegistryBrowserPolicy {
    RegistryBrowserPolicy
}

/// Writes agent events to the Windows Application event log under the source "IamEndpointAgent"
/// (Event Viewer > Windows Logs > Application). The source is not registered with a message file, so Event
/// Viewer shows its usual "description cannot be found" preamble followed by the agent's own text; the event
/// ids, levels and text are all there. If the log cannot be opened the events go to tracing instead.
pub struct WindowsEventLog {
    handle: Option<isize>,
}

pub fn local_event_log() -> WindowsEventLog {
    use windows_sys::Win32::System::EventLog::RegisterEventSourceW;
    let source: Vec<u16> = "IamEndpointAgent".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `source` is a live NUL-terminated buffer; a null server name means the local machine.
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    WindowsEventLog { handle: if handle == 0 { None } else { Some(handle) } }
}

impl agent_core::local_log::LocalEventSink for WindowsEventLog {
    fn write(&self, severity: &str, event_type: &str, message: &str) {
        use windows_sys::Win32::System::EventLog::ReportEventW;
        let Some(handle) = self.handle else {
            tracing::info!(severity, event_type, message, "agent event (event log unavailable)");
            return;
        };
        let text: Vec<u16> = format!("{event_type}: {}", agent_core::local_log::clip(message, 4000)).encode_utf16().chain(std::iter::once(0)).collect();
        let strings = [text.as_ptr()];
        // SAFETY: `handle` came from RegisterEventSourceW; `strings` holds one live NUL-terminated string.
        let ok = unsafe {
            ReportEventW(
                handle,
                agent_core::local_log::windows_event_type(severity),
                0,
                agent_core::local_log::event_id(event_type),
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            tracing::warn!(event_type, "could not write to the Windows event log");
        }
    }
}

impl Drop for WindowsEventLog {
    fn drop(&mut self) {
        if let Some(handle) = self.handle {
            // SAFETY: the handle is valid and is closed exactly once.
            unsafe { windows_sys::Win32::System::EventLog::DeregisterEventSource(handle) };
        }
    }
}

/// True while the IamEndpointAgent service is anything but stopped. Used to refuse a re-enrolment reset while the
/// running service still holds the old identity in memory. If the state cannot be read, assume "not running" only when
/// the service does not exist at all.
pub fn service_is_running() -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false;
    };
    service.query_status().map(|s| s.current_state != ServiceState::Stopped).unwrap_or(true)
}

/// Starts the installer for a VERIFIED update package (agent-core has already checked the signature and the hash, twice).
/// `msiexec` is launched detached and silent: the MSI's upgrade stops this very service, replaces its files and starts it
/// again, so the installer must outlive the process that launched it. msiexec is run by its full System32 path, never found
/// through PATH, and only for a `.msi` file.
pub struct MsiInstaller;

impl agent_core::update::UpdateInstaller for MsiInstaller {
    fn install(&self, package: &std::path::Path) -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        if !package.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")) || !package.is_file() {
            return Err("not an .msi file".to_string());
        }
        let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
        let msiexec = std::path::PathBuf::from(system_root).join("System32").join("msiexec.exe");
        let log = package.with_file_name("install.log");
        std::process::Command::new(msiexec)
            .arg("/i")
            .arg(package)
            .args(["/qn", "/norestart", "/l*v"])
            .arg(log)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

pub fn update_installer() -> Option<std::sync::Arc<dyn agent_core::update::UpdateInstaller>> {
    Some(std::sync::Arc::new(MsiInstaller))
}
