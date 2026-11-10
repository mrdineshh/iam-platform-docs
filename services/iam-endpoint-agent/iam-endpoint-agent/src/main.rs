mod platform;

use agent_core::config::AgentConfig;
use agent_core::device_identity::HardwareAttributes;
use agent_core::Agent;
use std::path::PathBuf;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();

    let args: Vec<String> = std::env::args().collect();
    let enroll_mode = args.iter().any(|a| a == "--enroll");

    let config_path = config_path();
    let config = load_config(&config_path)?;
    let state_path = state_path();

    if enroll_mode {
        // Enrollment is a one-shot, interactive operation (it opens a browser and waits for the
        // user to sign in) -- run it directly on a fresh runtime rather than going through the
        // Windows Service dispatcher, which expects a long-running background process, not a
        // console-driven one-time setup step. An admin or the installer runs `iam-endpoint-agent
        // --enroll` once per machine; the service itself only ever runs the heartbeat loop below.
        let runtime = tokio::runtime::Runtime::new()?;
        return runtime.block_on(run_enrollment(config, state_path));
    }

    platform::run_as_service(move || {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(run_heartbeat_loop(config, state_path))
    })
}

async fn run_enrollment(config: AgentConfig, state_path: PathBuf) -> anyhow::Result<()> {
    let hardware: HardwareAttributes = platform::collect_hardware_attributes();
    let launcher = platform::browser_launcher();
    let agent = Agent::new(config, state_path, AGENT_VERSION);

    // CORPORATE by default -- Phase 1 ships without an installer-time prompt for BYOD vs.
    // corporate ownership; an admin deploying to BYOD fleets needs to pass --ownership BYOD
    // explicitly until that prompt exists (tracked gap, not silently decided for them).
    let ownership = if std::env::args().any(|a| a == "--ownership=BYOD") { "BYOD" } else { "CORPORATE" };

    match agent.enroll(hardware, ownership, launcher.as_ref()).await {
        Ok(device_id) => {
            println!("Enrolled successfully. Device id: {device_id}");
            Ok(())
        }
        Err(err) => {
            eprintln!("Enrollment failed: {err}");
            Err(err.into())
        }
    }
}

async fn run_heartbeat_loop(config: AgentConfig, state_path: PathBuf) -> anyhow::Result<()> {
    let agent = Agent::new(config, state_path, AGENT_VERSION);
    agent.run_heartbeat_loop().await?;
    Ok(())
}

fn config_path() -> PathBuf {
    std::env::var("IAM_AGENT_CONFIG").map(PathBuf::from).unwrap_or_else(|_| default_data_dir().join("config.json"))
}

fn state_path() -> PathBuf {
    default_data_dir().join("state.json")
}

fn default_data_dir() -> PathBuf {
    // %PROGRAMDATA%\IamEndpointAgent on Windows -- a machine-wide, not per-user, location, since
    // the privileged service process (not the interactive user) owns this data (spec Section 7.1
    // process model: privileged background component separate from any user-facing component).
    std::env::var("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")).join("IamEndpointAgent")
}

fn load_config(path: &PathBuf) -> anyhow::Result<AgentConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read agent config at {}: {e}. An admin must provision this file before the agent can run -- see AgentConfig's own doc comment for what it must contain.", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}
