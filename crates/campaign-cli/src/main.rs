//! sumo-campaign — CLI tool for deploying SUIT firmware campaigns via SOVD.
//!
//! Deploy an L1 campaign manifest (multi-ECU):
//!   sumo-campaign deploy campaign.suit --server http://localhost:4000 \
//!     --trust-anchor keys/signing.pub --gateway vehicle_gateway \
//!     --sovd-ecus vm1 --sovd-token <jwt>
//!
//! Flash a single L2 image manifest:
//!   sumo-campaign flash vm1 manifest.suit --server http://localhost:4000 \
//!     --gateway vehicle_gateway --sovd-token <jwt>
//!
//! SOVD writes carry the JWT bearer; UDS session/security unlock happens
//! transparently server-side in the SOVD server.

use std::process;

use clap::{Parser, Subcommand};
use tracing::{error, info};

use sumo_sovd_orchestrator::campaign::{CampaignConfig, CampaignOrchestrator, EcuTarget};
use sumo_sovd_orchestrator::targets::{parse_l1_campaign_with_payloads, MultiflashSpec};

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(
    name = "sumo-campaign",
    about = "Deploy SUIT firmware campaigns via SOVD"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// SOVD server URL
    #[arg(long, default_value = "http://localhost:4000", global = true)]
    server: String,

    /// Path to trust anchor (signing public key, COSE_Key CBOR)
    #[arg(long, global = true)]
    trust_anchor: Option<String>,

    /// Gateway component ID (if ECUs are behind a gateway)
    #[arg(long, global = true)]
    gateway: Option<String>,

    /// SOVD bearer JWT for the flash engine (operator-supplied). Omitted →
    /// unauthenticated (the device may not enforce auth yet).
    #[arg(long, global = true)]
    sovd_token: Option<String>,

    /// Drive each ECU through the Validated state explicitly via
    /// validate() → activate() after transfer_exit. Demonstrates the
    /// new opt-in lifecycle; default is the classic flow.
    #[arg(long, global = true)]
    validated: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Deploy an L1 campaign manifest (parse → flash all ECUs → commit/rollback)
    Deploy {
        /// Path to L1 campaign SUIT envelope
        manifest: String,

        /// ECU IDs that accept SUIT envelopes (vm-mgr ECUs). Others get raw firmware extracted from L2.
        #[arg(long, value_delimiter = ',')]
        sovd_ecus: Vec<String>,

        /// Detached payload files: "URI=path" (repeatable, e.g., "#container-image"=image.tar.gz)
        #[arg(long, short)]
        payload: Vec<String>,

        /// Don't commit after flash — leave ECUs in trial mode
        #[arg(long)]
        no_commit: bool,

        /// Stop after staging, before ECU reset/activation
        #[arg(long)]
        staging_only: bool,

        /// Rollback after flash instead of committing
        #[arg(long)]
        rollback: bool,
    },

    /// Flash a single ECU with manifest + payload(s)
    Flash {
        /// Target ECU component ID
        component_id: String,

        /// Path to SUIT manifest (small, no integrated payloads)
        manifest: String,

        /// Payload files: "URI=path" (repeatable, e.g., "#kernel"=kernel.bin)
        #[arg(long, short)]
        payload: Vec<String>,

        /// Don't commit after flash
        #[arg(long)]
        no_commit: bool,

        /// Stop after staging, before ECU reset/activation
        #[arg(long)]
        staging_only: bool,

        /// Rollback after flash
        #[arg(long)]
        rollback: bool,
    },

    /// Flash multiple ECUs in one campaign — stages all, resets all
    /// in parallel, then commits. Avoids embedding L2 payloads in an
    /// L1 envelope (which would be impractical for large rootfs
    /// images) by reading a small JSON spec listing per-ECU
    /// manifests and payload paths.
    ///
    /// Spec format:
    /// {
    ///   "ecus": [
    ///     {
    ///       "component_id": "vm1",
    ///       "manifest": "/tmp/vm1.suit",
    ///       "payloads": [
    ///         ["#kernel",   "/path/to/kernel.bin"],
    ///         ["#firmware", "/path/to/rootfs.bin"],
    ///         ["#config",   "/path/to/config.bin"]
    ///       ]
    ///     },
    ///     { "component_id": "vm2", "manifest": "...", "payloads": [...] }
    ///   ]
    /// }
    Multiflash {
        /// Path to JSON spec describing the ECUs in the campaign
        config: String,

        /// Don't commit after flash
        #[arg(long)]
        no_commit: bool,

        /// Stop after staging, before ECU reset/activation
        #[arg(long)]
        staging_only: bool,

        /// Rollback after flash
        #[arg(long)]
        rollback: bool,
    },
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let orchestrator = CampaignOrchestrator::new(CampaignConfig {
        server_url: cli.server,
        trust_anchor: cli
            .trust_anchor
            .as_ref()
            .map(|p| {
                std::fs::read(p).unwrap_or_else(|e| {
                    eprintln!("error: read trust anchor {p}: {e}");
                    process::exit(1);
                })
            })
            .unwrap_or_default(),
        use_validated_flow: cli.validated,
        sovd_token: cli.sovd_token,
        // The workshop campaign-cli talks plain HTTP today; no --insecure flag
        // is exposed here. The orchestrator is insecure-capable (see
        // CampaignConfig::insecure) when a future flag wants it.
        insecure: false,
    });

    let result = match cli.command {
        Command::Deploy {
            manifest,
            sovd_ecus,
            payload,
            no_commit,
            staging_only,
            rollback,
        } => {
            run_deploy(
                &orchestrator,
                &manifest,
                cli.trust_anchor.as_deref(),
                cli.gateway,
                &sovd_ecus,
                &payload,
                no_commit,
                staging_only,
                rollback,
            )
            .await
        }
        Command::Flash {
            component_id,
            manifest,
            payload,
            no_commit,
            staging_only,
            rollback,
        } => {
            run_flash(
                &orchestrator,
                &component_id,
                &manifest,
                &payload,
                cli.gateway,
                no_commit,
                staging_only,
                rollback,
            )
            .await
        }
        Command::Multiflash {
            config,
            no_commit,
            staging_only,
            rollback,
        } => {
            run_multiflash(
                &orchestrator,
                &config,
                cli.gateway,
                no_commit,
                staging_only,
                rollback,
            )
            .await
        }
    };

    if let Err(e) = result {
        error!("{e}");
        process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_deploy(
    orchestrator: &CampaignOrchestrator,
    manifest_path: &str,
    trust_anchor_path: Option<&str>,
    gateway: Option<String>,
    sovd_ecus: &[String],
    payload_args: &[String],
    no_commit: bool,
    staging_only: bool,
    rollback: bool,
) -> Result<(), String> {
    let trust_anchor_path = trust_anchor_path.ok_or("--trust-anchor required for deploy")?;
    let trust_anchor =
        std::fs::read(trust_anchor_path).map_err(|e| format!("read trust anchor: {e}"))?;

    let envelope =
        std::fs::read(manifest_path).map_err(|e| format!("read {manifest_path}: {e}"))?;
    let payloads = parse_payload_args(payload_args)?;

    info!("parsing L1 campaign from {manifest_path}");
    let targets =
        parse_l1_campaign_with_payloads(&envelope, &trust_anchor, gateway, sovd_ecus, &payloads)
            .map_err(|e| format!("{e}"))?;

    info!("campaign has {} target(s):", targets.len());
    for t in &targets {
        info!(
            "  {} ({}B manifest, {} payloads)",
            t.component_id,
            t.manifest.len(),
            t.payloads.len()
        );
    }

    if staging_only {
        info!("staging all ECUs (--staging-only)...");
        let phase = orchestrator
            .stage_all(targets)
            .await
            .map_err(|e| format!("stage failed: {e}"))?;

        for ecu in &phase.ecus {
            info!("  {} → {:?}", ecu.component_id, ecu.state);
        }

        info!("ECUs staged (--staging-only). Reset/activation/commit skipped.");
        return Ok(());
    }

    info!("flashing all ECUs...");
    let phase = orchestrator
        .flash_all(targets)
        .await
        .map_err(|e| format!("flash failed: {e}"))?;

    for ecu in &phase.ecus {
        info!("  {} → {:?}", ecu.component_id, ecu.state);
    }

    if no_commit {
        info!("ECUs in trial mode (--no-commit). Use commit/rollback externally.");
        return Ok(());
    }

    if rollback {
        info!("rolling back...");
        orchestrator
            .rollback_all(&phase.ecus)
            .await
            .map_err(|e| format!("rollback failed: {e}"))?;
        info!("rollback complete");
    } else {
        info!("committing...");
        orchestrator
            .commit_all(&phase.ecus)
            .await
            .map_err(|e| format!("commit failed: {e}"))?;
        info!("campaign committed successfully");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_flash(
    orchestrator: &CampaignOrchestrator,
    component_id: &str,
    manifest_path: &str,
    payload_args: &[String],
    gateway: Option<String>,
    no_commit: bool,
    staging_only: bool,
    rollback: bool,
) -> Result<(), String> {
    let manifest =
        std::fs::read(manifest_path).map_err(|e| format!("read {manifest_path}: {e}"))?;

    let payloads = parse_payload_args(payload_args)?;

    info!(
        "flashing {component_id} with {manifest_path} ({}B manifest, {} payloads)",
        manifest.len(),
        payloads.len()
    );

    let targets = vec![EcuTarget {
        component_id: component_id.into(),
        gateway_id: gateway,
        manifest,
        payloads,
    }];

    if staging_only {
        let phase = orchestrator
            .stage_all(targets)
            .await
            .map_err(|e| format!("stage failed: {e}"))?;

        for ecu in &phase.ecus {
            info!("  {} → {:?}", ecu.component_id, ecu.state);
        }

        info!("{component_id} staged (--staging-only). Reset/activation/commit skipped.");
        return Ok(());
    }

    let phase = orchestrator
        .flash_all(targets)
        .await
        .map_err(|e| format!("flash failed: {e}"))?;

    for ecu in &phase.ecus {
        info!("  {} → {:?}", ecu.component_id, ecu.state);
    }

    if no_commit {
        info!("{component_id} in trial mode (--no-commit).");
        return Ok(());
    }

    if rollback {
        info!("rolling back {component_id}...");
        orchestrator
            .rollback_all(&phase.ecus)
            .await
            .map_err(|e| format!("rollback failed: {e}"))?;
        info!("rollback complete");
    } else {
        info!("committing {component_id}...");
        orchestrator
            .commit_all(&phase.ecus)
            .await
            .map_err(|e| format!("commit failed: {e}"))?;
        info!("{component_id} committed");
    }

    Ok(())
}

fn parse_payload_args(
    payload_args: &[String],
) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    let mut payloads = Vec::new();
    for arg in payload_args {
        let (uri, path) = arg
            .split_once('=')
            .ok_or_else(|| format!("invalid --payload: {arg} (expected URI=path)"))?;
        payloads.push((uri.to_string(), std::path::PathBuf::from(path)));
    }
    Ok(payloads)
}

async fn run_multiflash(
    orchestrator: &CampaignOrchestrator,
    config_path: &str,
    gateway: Option<String>,
    no_commit: bool,
    staging_only: bool,
    rollback: bool,
) -> Result<(), String> {
    let config_bytes =
        std::fs::read(config_path).map_err(|e| format!("read {config_path}: {e}"))?;
    let spec: MultiflashSpec =
        serde_json::from_slice(&config_bytes).map_err(|e| format!("parse {config_path}: {e}"))?;

    if spec.ecus.is_empty() {
        return Err("multiflash spec has no ECUs".into());
    }

    let targets = spec
        .into_targets(gateway)
        .map_err(|e| format!("read multiflash artefacts: {e}"))?;
    for t in &targets {
        info!(
            "  {} ({}B manifest, {} payloads)",
            t.component_id,
            t.manifest.len(),
            t.payloads.len()
        );
    }

    if staging_only {
        info!(
            "staging {} ECUs in one campaign (--staging-only)...",
            targets.len()
        );
        let phase = orchestrator
            .stage_all(targets)
            .await
            .map_err(|e| format!("stage failed: {e}"))?;

        for ecu in &phase.ecus {
            info!("  {} → {:?}", ecu.component_id, ecu.state);
        }

        info!("ECUs staged (--staging-only). Reset/activation/commit skipped.");
        return Ok(());
    }

    info!("flashing {} ECUs in one campaign...", targets.len());
    let phase = orchestrator
        .flash_all(targets)
        .await
        .map_err(|e| format!("flash failed: {e}"))?;

    for ecu in &phase.ecus {
        info!("  {} → {:?}", ecu.component_id, ecu.state);
    }

    if no_commit {
        info!("ECUs in trial mode (--no-commit). Use commit/rollback externally.");
        return Ok(());
    }

    if rollback {
        info!("rolling back...");
        orchestrator
            .rollback_all(&phase.ecus)
            .await
            .map_err(|e| format!("rollback failed: {e}"))?;
        info!("rollback complete");
    } else {
        info!("committing...");
        orchestrator
            .commit_all(&phase.ecus)
            .await
            .map_err(|e| format!("commit failed: {e}"))?;
        info!("campaign committed successfully");
    }

    Ok(())
}
