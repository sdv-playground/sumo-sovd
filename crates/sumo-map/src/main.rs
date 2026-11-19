//! `sumo-map` — inventory installed software across a device's VMs.
//!
//! Reads the `x-ota-installed-manifest` SOVD vendor data point per VM
//! (the running/committed bank's signed IVD manifest), optionally verifies its
//! `ivd-signing` signature, prints the per-file inventory, and can diff the
//! installed set against a release to show the "what to flash" view.
//!
//! Contract: `sumo-machine-manager/specs/sovd-vm-app-installation.md` §17.
//!
//! A server in SOVD node topology (supernova with `sovd_node`) lists only its node
//! at `/vehicle/v1/components` and serves the VMs as the node's subcomponents
//! (`/vehicle/v1/components/{node}/subcomponents/{vm}/…`); see [`discover_node`].

mod manifest;

use anyhow::{Context, Result};
use clap::Parser;
use manifest::{diff_inventory, load_pubkey, Diff, InstalledManifest, Release, VerifyStatus};
use serde::Serialize;
use sovd_client::{SovdClient, SovdClientError};

/// The SOVD vendor data point that carries the committed bank's signed IVD
/// manifest (§17). Vendor-namespaced; lives entirely in vm-mgr.
const INSTALLED_MANIFEST_PARAM_ID: &str = "x-ota-installed-manifest";

#[derive(Parser, Debug)]
#[command(
    name = "sumo-map",
    about = "Inventory installed software per VM via the x-ota-installed-manifest SOVD read",
    long_about = "Reads the signed IVD manifest each VM serves at \
        GET /vehicle/v1/components/{vm}/data/x-ota-installed-manifest (on a SOVD \
        node: components/{node}/subcomponents/{vm}/data/…), verifies it \
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

    // Resolve the component list (1 — narrowed, or all) — the node's
    // subcomponents on a node-topology server.
    let node = discover_node(&client).await?;
    let components: Vec<String> = match (&cli.component, &node) {
        (Some(c), _) => vec![c.clone()],
        (None, Some(node)) => {
            let body = get_json(
                &client,
                &format!("/vehicle/v1/components/{node}/subcomponents"),
            )
            .await
            .with_context(|| format!("list the subcomponents of node {node}"))?
            .with_context(|| format!("list the subcomponents of node {node}: not served"))?;
            item_ids(&body)
        }
        (None, None) => client
            .list_components()
            .await
            .context("list components")?
            .into_iter()
            .map(|c| c.id)
            .collect(),
    };

    let mut reports = Vec::with_capacity(components.len());
    for component in &components {
        let path = component_path(node.as_deref(), component);
        reports.push(
            build_report(&client, component, &path, pubkey.as_ref(), release.as_ref()).await?,
        );
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        print_human(&reports, pubkey.is_some(), release.is_some());
    }

    Ok(())
}

/// The SOVD node a node-topology server serves its components under: its
/// `/components` lists exactly one item AND that item is a node — its document
/// links `subcomponents`, or its `subcomponents` collection answers 2xx. `None`
/// (the flat form) otherwise, including a flat server with a single component.
async fn discover_node(client: &SovdClient) -> Result<Option<String>> {
    let components = client.list_components().await.context("list components")?;
    let [only] = components.as_slice() else {
        return Ok(None);
    };
    let id = &only.id;
    let doc = get_json(client, &format!("/vehicle/v1/components/{id}")).await?;
    if doc.as_ref().is_some_and(is_node_document) {
        return Ok(Some(id.clone()));
    }
    let subs = get_json(
        client,
        &format!("/vehicle/v1/components/{id}/subcomponents"),
    )
    .await?;
    Ok(subs.map(|_| id.clone()))
}

/// `GET {server}{path}` as JSON: `Some` on a 2xx, `None` when the server does not
/// serve it (404 or 405, what a flat server answers for a node's paths), an error
/// on any other status: a failing server must not read as a flat one.
async fn get_json(client: &SovdClient, path: &str) -> Result<Option<serde_json::Value>> {
    let url = client.base_url().join(path).context("build URL")?;
    let resp = client
        .http_client()
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    if matches!(status.as_u16(), 404 | 405) {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!("GET {path}: HTTP {status}");
    }
    let text = resp.text().await.with_context(|| format!("GET {path}"))?;
    Ok(Some(
        serde_json::from_str(&text).with_context(|| format!("parse GET {path}"))?,
    ))
}

/// Does a component document describe a node (link a `subcomponents` collection)?
fn is_node_document(doc: &serde_json::Value) -> bool {
    doc.get("subcomponents").is_some_and(|v| !v.is_null())
}

/// The `items[].id`s of a SOVD collection body.
fn item_ids(body: &serde_json::Value) -> Vec<String> {
    body.get("items")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|i| i.get("id").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

/// A component's path below `/vehicle/v1/components/`: `{component}` (flat) or
/// `{node}/subcomponents/{component}` (node topology). `SovdClient::read_data`
/// splices it in verbatim.
fn component_path(node: Option<&str>, component: &str) -> String {
    match node {
        Some(node) => format!("{node}/subcomponents/{component}"),
        None => component.to_string(),
    }
}

/// Read + (optionally) verify + diff one VM's installed manifest. `path` is the
/// component's path below `/components` ([`component_path`]).
async fn build_report(
    client: &SovdClient,
    component: &str,
    path: &str,
    pubkey: Option<&p256::ecdsa::VerifyingKey>,
    release: Option<&Release>,
) -> Result<VmReport> {
    let value = match client.read_data(path, INSTALLED_MANIFEST_PARAM_ID).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_document_linking_subcomponents_is_a_node() {
        assert!(is_node_document(&serde_json::json!({
            "id": "cvc",
            "subcomponents": "/vehicle/v1/components/cvc/subcomponents",
        })));
        assert!(!is_node_document(&serde_json::json!({ "id": "vm1" })));
        assert!(!is_node_document(
            &serde_json::json!({ "id": "vm1", "subcomponents": null })
        ));
    }

    #[test]
    fn component_paths_per_topology() {
        assert_eq!(component_path(None, "vm1"), "vm1");
        assert_eq!(component_path(Some("cvc"), "vm1"), "cvc/subcomponents/vm1");
    }

    #[test]
    fn item_ids_reads_a_collection() {
        let body = serde_json::json!({ "items": [{ "id": "host" }, { "id": "vm1" }, {}] });
        assert_eq!(item_ids(&body), ["host", "vm1"]);
        assert!(item_ids(&serde_json::json!({})).is_empty());
    }
}
