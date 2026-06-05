//! `sumo-map` — inventory installed software across a device's VMs.
//!
//! Reads the `x-sumo-installed-manifest` SOVD vendor data point per VM
//! (the running/committed bank's signed IVD manifest), optionally verifies its
//! `ivd-signing` signature, prints the per-file inventory, and can diff the
//! installed set against a release to show the "what to flash" view.
//!
//! Contract: `sumo-machine-manager/specs/sovd-vm-app-installation.md` §17.

mod manifest;

use anyhow::{Context, Result};
use clap::Parser;
use manifest::{diff_inventory, load_pubkey, Diff, InstalledManifest, Release, VerifyStatus};
use serde::Serialize;
use sovd_client::{SovdClient, SovdClientError};

/// The SOVD vendor data point that carries the committed bank's signed IVD
/// manifest (§17). Vendor-namespaced; lives entirely in vm-mgr.
const INSTALLED_MANIFEST_PARAM_ID: &str = "x-sumo-installed-manifest";

#[derive(Parser, Debug)]
#[command(
    name = "sumo-map",
    about = "Inventory installed software per VM via the x-sumo-installed-manifest SOVD read",
    long_about = "Reads the signed IVD manifest each VM serves at \
        GET /vehicle/v1/components/{vm}/data/x-sumo-installed-manifest, verifies it \
        against the device's ivd-signing public key, prints the per-file inventory, \
        and (with --release) diffs the installed set against a release to show what \
        would need flashing. Contract: sovd-vm-app-installation.md §17."
)]
struct Cli {
    /// SOVD server base URL (e.g. http://device:9080).
    #[arg(long)]
    server: String,

    /// Narrow to a single component / VM id (default: all components).
    #[arg(long)]
    component: Option<String>,

    /// `ivd-signing` public key (PEM or DER) to verify the manifest signature.
    #[arg(long)]
    pubkey: Option<std::path::PathBuf>,

    /// Release file (`{ "files": [ { "path", "sha256" }, … ] }`) to diff against.
    #[arg(long)]
    release: Option<std::path::PathBuf>,

    /// Emit the whole result as JSON instead of human-readable tables.
    #[arg(long)]
    json: bool,
}

/// Per-VM result, whether the manifest was present, verified, and any diff.
#[derive(Debug, Serialize)]
struct VmReport {
    component: String,
    /// `None` when the VM has no committed manifest (404 / never flashed).
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<InstalledManifest>,
    verify: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<Diff>,
    /// Set when the VM has no signed manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let client = SovdClient::new(&cli.server)
        .with_context(|| format!("create SOVD client for {}", cli.server))?;

    // --pubkey: load the ivd-signing public key once, up front.
    let pubkey = match &cli.pubkey {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read public key {}", path.display()))?;
            Some(
                load_pubkey(&bytes)
                    .with_context(|| format!("load public key {}", path.display()))?,
            )
        }
        None => None,
    };

    // --release: load the release inventory once, up front.
    let release = match &cli.release {
        Some(path) => {
            let bytes =
                std::fs::read(path).with_context(|| format!("read release {}", path.display()))?;
            let release: Release = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse release JSON {}", path.display()))?;
            Some(release)
        }
        None => None,
    };

    // Resolve the component list (1 — narrowed, or all).
    let components: Vec<String> = match &cli.component {
        Some(c) => vec![c.clone()],
        None => client
            .list_components()
            .await
            .context("list components")?
            .into_iter()
            .map(|c| c.id)
            .collect(),
    };

    let mut reports = Vec::with_capacity(components.len());
    for component in &components {
        reports.push(build_report(&client, component, pubkey.as_ref(), release.as_ref()).await?);
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        print_human(&reports, pubkey.is_some(), release.is_some());
    }

    Ok(())
}

/// Read + (optionally) verify + diff one VM's installed manifest.
async fn build_report(
    client: &SovdClient,
    component: &str,
    pubkey: Option<&p256::ecdsa::VerifyingKey>,
    release: Option<&Release>,
) -> Result<VmReport> {
    let value = match client
        .read_data(component, INSTALLED_MANIFEST_PARAM_ID)
        .await
    {
        Ok(resp) => resp.value,
        // No committed manifest (never flashed / no-HSM smoke path) — not an error.
        Err(e) if is_not_found(&e) => {
            return Ok(VmReport {
                component: component.to_string(),
                manifest: None,
                verify: VerifyStatus::Unverified,
                diff: None,
                note: Some("no signed manifest (never flashed?)".to_string()),
            });
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "read {INSTALLED_MANIFEST_PARAM_ID} for {component}"
            )))
        }
    };

    let manifest: InstalledManifest = serde_json::from_value(value)
        .with_context(|| format!("parse {INSTALLED_MANIFEST_PARAM_ID} value for {component}"))?;

    let verify = match pubkey {
        Some(pk) => manifest
            .verify(pk)
            .with_context(|| format!("verify manifest for {component}"))?,
        None => VerifyStatus::Unverified,
    };

    let diff = release.map(|r| diff_inventory(&manifest.files, &r.files));

    Ok(VmReport {
        component: component.to_string(),
        manifest: Some(manifest),
        verify,
        diff,
        note: None,
    })
}

/// Treat 404 / not-found in any of its sovd-client shapes as "no manifest".
fn is_not_found(err: &SovdClientError) -> bool {
    matches!(
        err,
        SovdClientError::ParameterNotFound(_)
            | SovdClientError::ComponentNotFound(_)
            | SovdClientError::ServerError { status: 404, .. }
    )
}

// =============================================================================
// Human-readable output
// =============================================================================

fn print_human(reports: &[VmReport], have_pubkey: bool, have_release: bool) {
    for (i, r) in reports.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let Some(manifest) = &r.manifest else {
            // §17: 404 → print the note and continue, don't error.
            let note = r.note.as_deref().unwrap_or("no signed manifest");
            println!("{}: {note}", r.component);
            continue;
        };

        let id = &manifest.identity;
        println!("=== {} ===", r.component);
        println!(
            "  {} {}   {}   gen {} · ivd v{}",
            none_if_empty(&id.name),
            none_if_empty(&id.version),
            verify_badge(r.verify, have_pubkey),
            manifest.gen,
            manifest.ivd_version,
        );
        print_identity(id);

        // Files table.
        println!("  files ({}):", manifest.files.len());
        for f in &manifest.files {
            println!("    {:<24} {}", f.path, short_sha(&f.sha256));
        }

        // Diff against the release, when requested.
        if have_release {
            if let Some(diff) = &r.diff {
                print_diff(diff);
            }
        }
    }
}

/// Compact F18x identity numbers (only the non-empty ones).
fn print_identity(id: &manifest::Identity) {
    let pairs = [
        ("ecu_sw", &id.ecu_sw_number),
        ("supplier_sw", &id.supplier_sw_number),
        ("supplier_ver", &id.supplier_sw_version),
        ("spare_part", &id.spare_part_number),
        ("odx_file", &id.odx_file_id),
        ("system", &id.system_name),
        ("prog_date", &id.programming_date),
        ("tester", &id.tester_serial),
    ];
    let shown: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if !shown.is_empty() {
        println!("  {}", shown.join("  "));
    }
}

fn print_diff(diff: &Diff) {
    if diff.is_empty() {
        println!("  vs release: up to date");
        return;
    }
    println!("  vs release (what to flash):");
    for e in &diff.added {
        println!("    + {:<24} {}", e.path, short_opt(&e.release_sha256));
    }
    for e in &diff.removed {
        println!("    - {:<24} {}", e.path, short_opt(&e.installed_sha256));
    }
    for e in &diff.changed {
        println!(
            "    ~ {:<24} {} -> {}",
            e.path,
            short_opt(&e.installed_sha256),
            short_opt(&e.release_sha256),
        );
    }
}

fn verify_badge(status: VerifyStatus, have_pubkey: bool) -> String {
    match status {
        VerifyStatus::Verified => "\u{2713} verified".to_string(),
        VerifyStatus::Invalid => "\u{2717} SIGNATURE INVALID".to_string(),
        VerifyStatus::Unverified => {
            if have_pubkey {
                // Shouldn't happen (pubkey present ⇒ verified/invalid), but be safe.
                "(unverified)".to_string()
            } else {
                "(unverified — pass --pubkey)".to_string()
            }
        }
    }
}

/// First 12 hex chars of a sha256, for a compact table.
fn short_sha(sha: &str) -> String {
    let lower = sha.to_lowercase();
    if lower.len() > 12 {
        format!("{}…", &lower[..12])
    } else {
        lower
    }
}

fn short_opt(sha: &Option<String>) -> String {
    sha.as_deref().map(short_sha).unwrap_or_else(|| "—".into())
}

fn none_if_empty(s: &str) -> &str {
    if s.is_empty() {
        "<unnamed>"
    } else {
        s
    }
}
