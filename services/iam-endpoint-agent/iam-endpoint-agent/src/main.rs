mod platform;

use agent_core::config::AgentConfig;
use agent_core::device_identity::HardwareAttributes;
use agent_core::{Agent, AgentError};
use std::path::PathBuf;
use tokio::sync::watch;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "IAM Endpoint Agent

USAGE:
    iam-endpoint-agent --enroll [--ownership=BYOD]   Register this device (opens your browser to sign in). Run once.
    iam-endpoint-agent --reset-enrollment --confirm  Forget this device's identity so it can enroll again (stop the service first).
    iam-endpoint-agent --tpm-selftest [--user]       Check that this machine can make and use a TPM-protected key (creates and deletes a throwaway key).
    iam-endpoint-agent --status                      Show enrollment, policy, offline behaviour and the local decision (read-only).
    iam-endpoint-agent --console                     Run in this window until Ctrl-C (for testing and demos).
    iam-endpoint-agent                               Run as the Windows service (started by the Service Control Manager).
    iam-endpoint-agent --version | --help

Configuration is read from %PROGRAMDATA%\\IamEndpointAgent\\config.json, or the path in IAM_AGENT_CONFIG.
Set RUST_LOG=info (or debug) to see what the agent is doing.";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("iam-endpoint-agent {AGENT_VERSION}");
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();

    if args.iter().any(|a| a == "--tpm-selftest") {
        return platform::tpm_selftest(args.iter().any(|a| a == "--user"));
    }

    if args.iter().any(|a| a == "--status") {
        // Read-only: loads the same files the service uses (an administrator can read them) and prints a summary.
        let config = load_config(&config_path())?;
        println!("{}", Agent::new(config, data_dir(), AGENT_VERSION).status_report()?);
        return Ok(());
    }

    if args.iter().any(|a| a == "--reset-enrollment") {
        if !args.iter().any(|a| a == "--confirm") {
            eprintln!("This deletes this device's identity and key. Run again with --confirm to proceed.");
            std::process::exit(2);
        }
        if platform::service_is_running() {
            eprintln!("Stop the agent service first:  Stop-Service IamEndpointAgent");
            std::process::exit(2);
        }
        let config = load_config(&config_path())?;
        match new_agent(config, data_dir()).reset_enrollment()? {
            Some(old) => println!(
                "Device identity removed. The old device ({old}) is still listed in the Admin Console: an administrator should revoke it.\nNow run:  iam-endpoint-agent --enroll"
            ),
            None => println!("This device was not enrolled. Nothing to remove."),
        }
        return Ok(());
    }

    let enroll_mode = args.iter().any(|a| a == "--enroll");
    let console_mode = args.iter().any(|a| a == "--console");
    let config = load_config(&config_path())?;
    let data_dir = data_dir();

    if console_mode {
        // Same agent loop as the service, but in the foreground: the service dispatcher refuses to start
        // outside the Service Control Manager (Windows error 1063), so this is the way to run and debug
        // the agent by hand. Ctrl-C triggers the same graceful shutdown the SCM's Stop does.
        return tokio::runtime::Runtime::new()?.block_on(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("Stopping...");
                let _ = shutdown_tx.send(true);
            });
            run_agent(config, data_dir, shutdown_rx).await
        });
    }

    if enroll_mode {
        // Enrollment is a one-shot, interactive operation (it opens a browser and waits for the user to
        // sign in), so it runs directly on a fresh runtime rather than through the Windows Service
        // dispatcher, which expects a long-running background process. An admin or the installer runs
        // `iam-endpoint-agent --enroll` once per machine; the service itself only runs the sync loop.
        return tokio::runtime::Runtime::new()?.block_on(run_enrollment(config, data_dir));
    }

    platform::run_as_service(move |shutdown| tokio::runtime::Runtime::new()?.block_on(run_agent(config, data_dir, shutdown)))
}

async fn run_enrollment(config: AgentConfig, data_dir: PathBuf) -> anyhow::Result<()> {
    let hardware: HardwareAttributes = platform::collect_hardware_attributes().await;
    let launcher = platform::browser_launcher();
    let agent = new_agent(config, data_dir);

    // CORPORATE unless told otherwise. Phase 1 has no installer-time prompt for ownership, so a BYOD
    // rollout must pass --ownership=BYOD explicitly (tracked gap, not silently decided for the admin).
    // A CORPORATE device is approved automatically, so an unrecognised value (a typo such as "byd") must never fall
    // through to CORPORATE: it is refused instead.
    let ownership = match std::env::args().find_map(|a| a.strip_prefix("--ownership=").map(str::to_ascii_uppercase)).as_deref() {
        None | Some("CORPORATE") => "CORPORATE",
        Some("BYOD") => "BYOD",
        Some(other) => {
            eprintln!("Unknown --ownership value {other:?}: use CORPORATE or BYOD.");
            std::process::exit(2);
        }
    };

    // Checked before anything is printed or opened, so an already-registered machine is told so straight away.
    if let Some(device_id) = agent.enrolled_device()? {
        already_enrolled(device_id);
    }

    println!("Opening your browser so you can sign in and register this device.");
    println!("Finish signing in there; this window continues by itself (it gives up after 5 minutes).");
    match agent.enroll(hardware, ownership, launcher.as_ref()).await {
        Ok(device_id) => {
            println!("Enrolled successfully. Device id: {device_id}");
            Ok(())
        }
        // Not a failure: the machine is already registered. Exit code 3 lets installers and Enroll-Device.cmd
        // carry on (start the service) instead of reporting an error.
        Err(AgentError::AlreadyEnrolled(device_id)) => already_enrolled(device_id),
        Err(err) => {
            eprintln!("Enrollment failed: {err}");
            Err(err.into())
        }
    }
}

/// The agent, offered this machine's TPM key store when it has one.
fn new_agent(config: AgentConfig, data_dir: PathBuf) -> Agent {
    let agent = Agent::new(config, data_dir, AGENT_VERSION);
    let agent = match platform::hardware_key_store() {
        Some(store) => agent.with_hardware_keys(store),
        None => agent,
    };
    match platform::update_installer() {
        Some(installer) => agent.with_update_installer(installer),
        None => agent,
    }
}

fn already_enrolled(device_id: impl std::fmt::Display) -> ! {
    println!("This device is already enrolled (device id {device_id}). Nothing to do.");
    println!("To register it again as a new device: stop the service, then run  iam-endpoint-agent --reset-enrollment --confirm");
    std::process::exit(3);
}

async fn run_agent(config: AgentConfig, data_dir: PathBuf, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let log: std::sync::Arc<dyn agent_core::local_log::LocalEventSink> = std::sync::Arc::new(platform::local_event_log());
    log.write("INFO", "agent.started", &format!("IAM endpoint agent {AGENT_VERSION} started"));
    // Browser identity restriction (P1-19/20/23): applied at every start so a changed or tampered value is put
    // back. A failure is logged loudly but does not stop posture reporting and heartbeats.
    match agent_core::browser_policy::chromium_entries(&config.allowed_identity_domains) {
        Ok(entries) if entries.is_empty() => {}
        Ok(entries) => match agent_core::browser_policy::BrowserPolicyApplier::apply(&platform::browser_policy_applier(), &entries) {
            Ok(()) => {
                tracing::info!(count = entries.len(), "browser sign-in restriction applied (Chrome, Edge)");
                log.write("INFO", "agent.browser_policy_applied", "browser sign-in restriction applied (Chrome, Edge)");
            }
            Err(err) => {
                tracing::error!(%err, "could not apply the browser sign-in restriction");
                log.write("ERROR", "agent.browser_policy_failed", &err.to_string());
            }
        },
        Err(err) => tracing::error!(%err, "browser sign-in restriction not applied"),
    }
    // Personal Microsoft accounts (outlook.com, hotmail.com, live.com): the sign-in pages are put on each browser's URL block
    // list, keeping whatever else is on it. A lower-assurance domain control (spec 8.2), applied at every start like the above.
    match agent_core::browser_policy::personal_microsoft_block(&config.allowed_identity_domains) {
        Ok(lists) if lists.is_empty() => {}
        Ok(lists) => {
            for list in &lists {
                match agent_core::browser_policy::BrowserPolicyApplier::merge_url_blocklist(&platform::browser_policy_applier(), list) {
                    Ok(()) => {
                        tracing::info!(browser = list.browser, "personal Microsoft sign-in blocked");
                        log.write("INFO", "agent.browser_block_applied", &format!("personal Microsoft account sign-in blocked in {}", list.browser));
                    }
                    Err(err) => {
                        tracing::error!(browser = list.browser, %err, "could not block personal Microsoft sign-in");
                        log.write("ERROR", "agent.browser_block_failed", &format!("{}: {err}", list.browser));
                    }
                }
            }
        }
        Err(err) => tracing::error!(%err, "personal Microsoft sign-in block not applied"),
    }
    let result = new_agent(config, data_dir).with_local_log(log.clone()).run(platform::posture_collector(), shutdown).await;
    log.write("INFO", "agent.stopped", "IAM endpoint agent stopped");
    result?;
    Ok(())
}

fn config_path() -> PathBuf {
    std::env::var("IAM_AGENT_CONFIG").map(PathBuf::from).unwrap_or_else(|_| data_dir().join("config.json"))
}

/// `%PROGRAMDATA%\IamEndpointAgent` on Windows -- machine-wide rather than per-user, since the privileged
/// service process (not the interactive user) owns this data (spec Section 7.1: privileged background
/// component, separate from any user-facing component).
fn data_dir() -> PathBuf {
    std::env::var("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")).join("IamEndpointAgent")
}

fn load_config(path: &PathBuf) -> anyhow::Result<AgentConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("could not read agent config at {}: {e}. An admin must provision this file before the agent can run -- see AgentConfig's doc comments for what it must contain.", path.display())
    })?;
    let config: AgentConfig = serde_json::from_str(&contents).map_err(|e| anyhow::anyhow!("{} is not a valid agent config: {e}", path.display()))?;
    config.validate().map_err(|e| anyhow::anyhow!("invalid agent configuration in {}: {e}", path.display()))?;
    Ok(config)
}
