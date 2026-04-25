//! sumo-campaign — CLI tool for deploying SUIT firmware campaigns via SOVD.
//!
//! Deploy an L1 campaign manifest (multi-ECU):
//!   sumo-campaign deploy campaign.suit --server http://localhost:4000 \
//!     --trust-anchor keys/signing.pub --gateway vehicle_gateway \
//!     --sovd-ecus os1 --helper-url http://localhost:9100 --helper-token dev-secret-123
//!
//! Flash a single L2 image manifest:
//!   sumo-campaign flash os1 manifest.suit --server http://localhost:4000 \
//!     --gateway vehicle_gateway --helper-url http://localhost:9100 --helper-token dev-secret-123

use std::process;

use clap::{Parser, Subcommand};
use tracing::{info, error};

use sumo_sovd_orchestrator::campaign::{
    CampaignConfig, CampaignOrchestrator, EcuTarget,
};
use sumo_sovd_orchestrator::security_helper::SecurityHelperConfig;
use sumo_onboard::Validator;
use sumo_crypto::RustCryptoBackend;

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(name = "sumo-campaign", about = "Deploy SUIT firmware campaigns via SOVD")]
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

    /// UDS security access level
    #[arg(long, default_value = "1", global = true)]
    security_level: u8,

    /// Security helper URL
    #[arg(long, default_value = "http://localhost:9100", global = true)]
    helper_url: String,

    /// Security helper bearer token
    #[arg(long, default_value = "dev-secret-123", global = true)]
    helper_token: String,

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

        /// Don't commit after flash — leave ECUs in trial mode
        #[arg(long)]
        no_commit: bool,

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

        /// Rollback after flash
        #[arg(long)]
        rollback: bool,
    },
}

// =============================================================================
// Campaign parsing
// =============================================================================

fn parse_campaign(
    envelope: &[u8],
    trust_anchor: &[u8],
    gateway_id: Option<String>,
    sovd_ecus: &[String],
) -> Result<Vec<EcuTarget>, String> {
    let crypto = RustCryptoBackend::new();
    let validator = Validator::new(trust_anchor, None);

    let manifest = validator
        .validate_envelope(envelope, &crypto, 0)
        .map_err(|e| format!("validate L1 envelope: {e:?}"))?;

    if !manifest.is_campaign() {
        return Err("not a campaign manifest (no dependencies)".into());
    }

    let dep_count = manifest.dependency_count();
    let mut targets = Vec::new();

    for i in 0..dep_count {
        let dep_uri = manifest.dependency_uri(i)
            .ok_or_else(|| format!("no URI for dependency {i}"))?;

        let l2_envelope = if dep_uri.starts_with('#') {
            manifest.integrated_payload(dep_uri)
                .ok_or_else(|| format!("payload not found: {dep_uri}"))?
                .to_vec()
        } else {
            return Err(format!("external dependency URIs not yet supported: {dep_uri}"));
        };

        let l2_manifest = validator
            .validate_envelope(&l2_envelope, &crypto, 0)
            .map_err(|e| format!("validate L2 dep {i}: {e:?}"))?;

        let component_id = l2_manifest
            .component_id(0)
            .and_then(|segs| segs.last())
            .and_then(|s| std::str::from_utf8(s).ok())
            .ok_or_else(|| format!("L2 dep {i}: no component ID"))?
            .to_string();

        // SOVD ECUs (vm-mgr) get the full L2 SUIT envelope;
        // UDS ECUs get raw firmware extracted from the L2
        let package = if sovd_ecus.iter().any(|e| e == &component_id) {
            l2_envelope
        } else {
            l2_manifest.integrated_payload("#firmware")
                .ok_or_else(|| format!("L2 dep {i} ({component_id}): no integrated firmware"))?
                .to_vec()
        };

        targets.push(EcuTarget {
            component_id,
            gateway_id: gateway_id.clone(),
            manifest: package, // deploy path: integrated envelope
            payloads: Vec::new(),
        });
    }

    Ok(targets)
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
        trust_anchor: cli.trust_anchor.as_ref()
            .map(|p| std::fs::read(p).unwrap_or_else(|e| {
                eprintln!("error: read trust anchor {p}: {e}");
                process::exit(1);
            }))
            .unwrap_or_default(),
        security_level: cli.security_level,
        security_helper: SecurityHelperConfig {
            url: cli.helper_url,
            token: cli.helper_token,
        },
        use_validated_flow: cli.validated,
    });

    let result = match cli.command {
        Command::Deploy { manifest, sovd_ecus, no_commit, rollback } => {
            run_deploy(&orchestrator, &manifest, cli.trust_anchor.as_deref(),
                       cli.gateway, &sovd_ecus, no_commit, rollback).await
        }
        Command::Flash { component_id, manifest, payload, no_commit, rollback } => {
            run_flash(&orchestrator, &component_id, &manifest, &payload,
                      cli.gateway, no_commit, rollback).await
        }
    };

    if let Err(e) = result {
        error!("{e}");
        process::exit(1);
    }
}

async fn run_deploy(
    orchestrator: &CampaignOrchestrator,
    manifest_path: &str,
    trust_anchor_path: Option<&str>,
    gateway: Option<String>,
    sovd_ecus: &[String],
    no_commit: bool,
    rollback: bool,
) -> Result<(), String> {
    let trust_anchor_path = trust_anchor_path
        .ok_or("--trust-anchor required for deploy")?;
    let trust_anchor = std::fs::read(trust_anchor_path)
        .map_err(|e| format!("read trust anchor: {e}"))?;

    let envelope = std::fs::read(manifest_path)
        .map_err(|e| format!("read {manifest_path}: {e}"))?;

    info!("parsing L1 campaign from {manifest_path}");
    let targets = parse_campaign(&envelope, &trust_anchor, gateway, sovd_ecus)?;

    info!("campaign has {} target(s):", targets.len());
    for t in &targets {
        info!("  {} ({}B manifest, {} payloads)", t.component_id, t.manifest.len(), t.payloads.len());
    }

    info!("flashing all ECUs...");
    let phase = orchestrator.flash_all(targets).await
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
        orchestrator.rollback_all(&phase.ecus).await
            .map_err(|e| format!("rollback failed: {e}"))?;
        info!("rollback complete");
    } else {
        info!("committing...");
        orchestrator.commit_all(&phase.ecus).await
            .map_err(|e| format!("commit failed: {e}"))?;
        info!("campaign committed successfully");
    }

    Ok(())
}

async fn run_flash(
    orchestrator: &CampaignOrchestrator,
    component_id: &str,
    manifest_path: &str,
    payload_args: &[String],
    gateway: Option<String>,
    no_commit: bool,
    rollback: bool,
) -> Result<(), String> {
    let manifest = std::fs::read(manifest_path)
        .map_err(|e| format!("read {manifest_path}: {e}"))?;

    // Parse payload args: "URI=path" pairs (order matters — must match manifest components)
    let mut payloads = Vec::new();
    for arg in payload_args {
        let (uri, path) = arg.split_once('=')
            .ok_or_else(|| format!("invalid --payload: {arg} (expected URI=path)"))?;
        payloads.push((uri.to_string(), std::path::PathBuf::from(path)));
    }

    info!(
        "flashing {component_id} with {manifest_path} ({}B manifest, {} payloads)",
        manifest.len(), payloads.len()
    );

    let phase = orchestrator.flash_all(vec![EcuTarget {
        component_id: component_id.into(),
        gateway_id: gateway,
        manifest,
        payloads,
    }]).await.map_err(|e| format!("flash failed: {e}"))?;

    for ecu in &phase.ecus {
        info!("  {} → {:?}", ecu.component_id, ecu.state);
    }

    if no_commit {
        info!("{component_id} in trial mode (--no-commit).");
        return Ok(());
    }

    if rollback {
        info!("rolling back {component_id}...");
        orchestrator.rollback_all(&phase.ecus).await
            .map_err(|e| format!("rollback failed: {e}"))?;
        info!("rollback complete");
    } else {
        info!("committing {component_id}...");
        orchestrator.commit_all(&phase.ecus).await
            .map_err(|e| format!("commit failed: {e}"))?;
        info!("{component_id} committed");
    }

    Ok(())
}
