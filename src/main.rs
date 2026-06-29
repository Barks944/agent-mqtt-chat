//! agentmsg binary entry point.

use clap::Parser;

use agentmsg::cli::{self, Cli};

fn main() {
    // The background daemon (`daemon run`) installs its own file-backed tracing
    // subscriber to daemon.log (its stdio is nulled). Skip the stderr subscriber
    // in that case so the daemon's subscriber is the one that wins.
    if !is_daemon_run() {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("AGENTMSG_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    let cli = Cli::parse();
    cli::run(cli);
}

/// True if the process was invoked as `agentmsg daemon run` (the foreground
/// daemon entry point spawned by `daemon start`).
fn is_daemon_run() -> bool {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    matches!(args.as_slice(), [first, second, ..] if first == "daemon" && second == "run")
}
