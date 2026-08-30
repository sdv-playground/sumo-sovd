//! Per-ECU update primitives — inspect a SUIT manifest to pick the flow
//! (firmware flash vs application vs policy), drive the SOVD `/updates` wire,
//! and poll activation. Auth is a resolved bearer `token` (`""` ⇒ unauthed);
//! the caller ([`FlashEngine`](crate::FlashEngine)) owns the `TokenSource`.
//!
//! This module is the SOVD flash protocol only — it does **not** touch session
//! or security state. The driver unlocks the ECU (UDS) before staging.

use sovd_client::flash::{FlashClient, FlashConfig, FlashError};
use sovd_client::{OperationExecution, OperationStatus, SovdClient, SovdClientError};
use sovd_core::EntityStatus;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{debug, info, warn};

use crate::error::EngineError;
use crate::types::{FlashJob, PayloadSource, UpdateType};

/// Open a fresh `/updates` session. On the device's in-trial refusal, roll back
/// the pending trial and retry — but ONLY after `x-ota-update-state` positively
/// confirms this component is genuinely mid-trial. `force_rollback` is
/// destructive, so an unconfirmed state (phase not `Trial`, the component absent,
/// or an unreadable probe) must NOT trigger it: the refusal is surfaced with the
/// observed state instead. A blind rollback against a committed/absent component
/// fails device-side (`NotInTrial`) and masks the true cause. Returns the new
/// update_id.
async fn open_update_or_rollback_pending(
    flash_client: &FlashClient,
    comp: &str,
    name: &str,
    version: &str,
) -> Result<String, EngineError> {
    match flash_client.open_update_with(name, version).await {
        Ok(id) => Ok(id),
        Err(FlashError::Server { ref message, .. }) if message.contains("trial mode") => {
            // Positive confirmation gates the destructive rollback: read the node's
            // update-state off the wire (connection recovered from the flash client).
            let cfg = flash_client.config();
            let state = read_node_update_state(
                &cfg.connection.base_url,
                cfg.connection.bearer.as_deref().unwrap_or(""),
                cfg.insecure,
                cfg.ca_cert_pem.as_deref(),
            )
            .await;
            match state {
                // `acted_matches` carries the one-way host-os→host bank-set alias.
                Ok(s)
                    if s.phase == "Trial"
                        && s.components.iter().any(|c| acted_matches(comp, c)) =>
                {
                    tracing::info!(
                        component = %comp,
                        detail = %message,
                        "previous upgrade still in trial — auto-rolling back before new flash"
                    );
                    flash_client
                        .force_rollback()
                        .await
                        .map_err(|e| EngineError::FlashFailed {
                            component: comp.to_string(),
                            message: format!("force_rollback of pending trial: {e}"),
                        })?;
                    flash_client
                        .open_update_with(name, version)
                        .await
                        .map_err(|e| EngineError::FlashFailed {
                            component: comp.to_string(),
                            message: format!("open_update after rollback: {e}"),
                        })
                }
                Ok(s) => Err(EngineError::FlashFailed {
                    component: comp.to_string(),
                    message: format!(
                        "device refused open as in-trial but x-ota-update-state reports \
                         phase={} (components={:?}) — not auto-rolling back; inspect device \
                         state: {message}",
                        s.phase, s.components
                    ),
                }),
                Err(e) => Err(EngineError::FlashFailed {
                    component: comp.to_string(),
                    message: format!(
                        "device refused open as in-trial but the x-ota-update-state probe \
                         failed ({e}) — not auto-rolling back; inspect device state: {message}"
                    ),
                }),
            }
        }
        Err(e) => Err(EngineError::FlashFailed {
            component: comp.to_string(),
            message: format!("open_update: {e}"),
        }),
    }
}

/// The node's `x-ota-update-state` — the update-transaction `phase` plus the
/// component ids it covers (component-mgr `sovd/routes.rs` `UpdateStateResponse`).
#[derive(serde::Deserialize)]
struct NodeUpdateStateProbe {
    phase: String,
    #[serde(default)]
    components: Vec<String>,
}

/// `GET /vehicle/v1/data/x-ota-update-state` — a NODE-level vendor resource at
/// the vehicle root, so it is read with a direct GET (not the per-component
/// `SovdClient::read_data`). `Err` when the resource is unreachable/absent (an
/// older device predating the field) or the body will not parse — the caller
/// treats any failure as unconfirmed and refuses the destructive rollback.
async fn read_node_update_state(
    server_url: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<NodeUpdateStateProbe, EngineError> {
    let url = format!(
        "{}/vehicle/v1/data/x-ota-update-state",
        server_url.trim_end_matches('/')
    );
    // Same one-off CA-trust seam as the node-verdict POST.
    let client = build_verdict_client(insecure, ca_cert_pem, "x-ota-update-state")?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| EngineError::FlashFailed {
        component: "node".to_string(),
        message: format!("x-ota-update-state: {e}"),
    })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(EngineError::FlashFailed {
            component: "node".to_string(),
            message: format!("x-ota-update-state: HTTP {status}: {body}"),
        });
    }
    serde_json::from_str(&body).map_err(|e| EngineError::FlashFailed {
        component: "node".to_string(),
        message: format!("x-ota-update-state: unparseable body ({e}): {body}"),
    })
}

/// Result of staging one ECU (before reset).
pub struct EcuFlashResult {
    /// The `/updates` package id opened for this stage — captured so the
    /// engine can re-`attach` a fresh post-reset FlashClient.
    pub update_id: String,
    pub update_type: UpdateType,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    /// `true` when `execute()` paused at `substate=awaiting-verdict` (banked +
    /// orchestrated) — reset then `spec_commit`/`spec_rollback` follow.
    pub awaiting_verdict: bool,
}

/// Classify a manifest by inspecting its SUIT command sequences.
fn classify_manifest(
    envelope: &[u8],
    trust_anchor: &[u8],
) -> Result<(UpdateType, sumo_onboard::Manifest), EngineError> {
    let crypto = RustCryptoBackend::new();
    let validator = Validator::new(trust_anchor, None);
    let manifest = validator
        .validate_envelope(envelope, &crypto, 0)
        .map_err(|e| EngineError::Manifest(format!("{e:?}")))?;

    let update_type = if is_container_image_manifest(&manifest) {
        UpdateType::Application
    } else if manifest.disable_target().is_some() {
        // A signed SUIT *disable* manifest carries no install/invoke and no
        // payload — without this it would fall through to Policy (a no-op) and
        // the device would never enact the deactivation.
        UpdateType::Removal
    } else if manifest.has_install() || manifest.has_invoke() {
        UpdateType::Firmware
    } else {
        UpdateType::Policy
    };

    Ok((update_type, manifest))
}

fn is_container_image_manifest(manifest: &sumo_onboard::Manifest) -> bool {
    manifest
        .component_id(0)
        .is_some_and(|segments| match segments {
            [_, component, ..] => component.as_slice() == b"container_image",
            _ => false,
        })
}

/// Flash one job to staging — ends at AwaitingReboot for firmware updates.
/// Does NOT reset the ECU (a campaign-level decision). **Precondition:** the
/// driver has already unlocked the ECU (programming session + security).
pub async fn flash_ecu_to_staging(
    job: &FlashJob,
    server_url: &str,
    trust_anchor: &[u8],
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<EcuFlashResult, EngineError> {
    let comp = &job.component_id;
    let gw = job.gateway_id.as_deref();

    // Classify the manifest (keep the parsed envelope to name the package).
    let (update_type, opaque_firmware, manifest) = match classify_manifest(
        &job.envelope,
        trust_anchor,
    ) {
        Ok((ut, m)) => (ut, false, Some(m)),
        Err(_) => {
            debug!(component = %comp, "package is not a SUIT envelope — treating as opaque firmware");
            (UpdateType::Firmware, true, None)
        }
    };

    // Derive a meaningful /updates package identity from the SUIT model/vendor
    // name + text-version, falling back to the component id.
    let pkg_name = manifest
        .as_ref()
        .and_then(|m| m.text_model_name(0).or_else(|| m.text_vendor_name(0)))
        .unwrap_or(comp.as_str())
        .to_string();
    let pkg_version = manifest
        .as_ref()
        .and_then(|m| m.text_version(0))
        .unwrap_or_default()
        .to_string();
    info!(component = %comp, gateway = ?gw, update_type = ?update_type, "starting ECU flash (assumes already unlocked)");

    let flash_client = build_flash_client(server_url, comp, gw, token, insecure, ca_cert_pem)?;

    let update_id =
        open_update_or_rollback_pending(&flash_client, comp, &pkg_name, &pkg_version).await?;
    info!(component = %comp, update_id = %update_id, "opened /updates session");

    info!(component = %comp, size = job.envelope.len(), "uploading manifest");
    flash_client
        .upload_part("manifest", &job.envelope)
        .await
        .map_err(|e| EngineError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload: {e}"),
        })?;

    if !opaque_firmware {
        // SUIT-backed: upload detached payloads in component order, streaming
        // files so a multi-hundred-MB image never lands in RAM.
        for payload in &job.payloads {
            // Size up front so the per-payload log reports it *before* a big
            // (hundreds-of-MB) upload starts, then throughput after it finishes.
            let size: u64 = match &payload.source {
                PayloadSource::File(path) => tokio::fs::metadata(path)
                    .await
                    .map_err(|e| EngineError::FlashFailed {
                        component: comp.clone(),
                        message: format!("stat payload {}: {e}", path.display()),
                    })?
                    .len(),
                PayloadSource::Bytes(bytes) => bytes.len() as u64,
            };
            let mb = size as f64 / 1_048_576.0;
            info!(component = %comp, uri = %payload.uri, "uploading payload ({mb:.2} MB)");
            let started = std::time::Instant::now();
            match &payload.source {
                PayloadSource::File(path) => {
                    let file = tokio::fs::File::open(path).await.map_err(|e| {
                        EngineError::FlashFailed {
                            component: comp.clone(),
                            message: format!("open payload {}: {e}", path.display()),
                        }
                    })?;
                    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
                    flash_client
                        .upload_part_stream(&payload.uri, body, Some(size))
                        .await
                        .map_err(|e| EngineError::FlashFailed {
                            component: comp.clone(),
                            message: format!("payload upload ({}): {e}", payload.uri),
                        })?;
                }
                PayloadSource::Bytes(bytes) => {
                    flash_client
                        .upload_part(&payload.uri, bytes)
                        .await
                        .map_err(|e| EngineError::FlashFailed {
                            component: comp.clone(),
                            message: format!("payload upload ({}): {e}", payload.uri),
                        })?;
                }
            }
            let secs = started.elapsed().as_secs_f64();
            let rate = if secs > 0.0 { mb / secs } else { 0.0 };
            info!(
                component = %comp,
                uri = %payload.uri,
                "uploaded payload: {mb:.2} MB in {secs:.2}s ({rate:.2} MB/s)"
            );
        }
    }

    match update_type {
        UpdateType::Firmware | UpdateType::Application | UpdateType::Removal => {
            // §7.18.5 prepare: server runs verify_part + waits for staging.
            info!(component = %comp, "running PUT /prepare");
            let prepared = flash_client
                .prepare()
                .await
                .map_err(|e| EngineError::FlashFailed {
                    component: comp.clone(),
                    message: format!("prepare: {e}"),
                })?;
            if prepared.status != "completed" {
                return Err(EngineError::FlashFailed {
                    component: comp.clone(),
                    message: format!(
                        "prepare ended at {}/{}: {}",
                        prepared.phase,
                        prepared.status,
                        prepared
                            .error
                            .map(|e| e.message)
                            .unwrap_or_else(|| "no error detail".into())
                    ),
                });
            }

            // §7.18.6 execute. Firmware opts into orchestrated mode (banked
            // pauses at awaiting-verdict; singleshot ignores the flag and
            // auto-completes). Application and Removal have no trial phase —
            // Removal (disable) is irreversible, so it never orchestrates.
            let want_orchestrated = matches!(update_type, UpdateType::Firmware);
            info!(component = %comp, orchestrated = want_orchestrated, "running PUT /execute");
            let executed = flash_client.execute(want_orchestrated).await.map_err(|e| {
                EngineError::FlashFailed {
                    component: comp.clone(),
                    message: format!("execute: {e}"),
                }
            })?;
            let awaiting_verdict = match (executed.status.as_str(), executed.substate.as_deref()) {
                ("completed", _) => {
                    info!(component = %comp, "execute completed (singleshot or unorchestrated)");
                    false
                }
                ("inProgress", Some("awaiting-verdict")) => {
                    info!(component = %comp, "execute paused at awaiting-verdict");
                    true
                }
                _ => {
                    return Err(EngineError::FlashFailed {
                        component: comp.clone(),
                        message: format!(
                            "execute ended at {}/{} substate={:?}: {}",
                            executed.phase,
                            executed.status,
                            executed.substate,
                            executed
                                .error
                                .map(|e| e.message)
                                .unwrap_or_else(|| "no error detail".into())
                        ),
                    });
                }
            };

            return Ok(EcuFlashResult {
                update_id,
                update_type,
                active_version: None,
                previous_version: None,
                awaiting_verdict,
            });
        }
        UpdateType::Policy => {
            info!(component = %comp, "policy applied (no flash/reset needed)");
        }
    }

    Ok(EcuFlashResult {
        update_id,
        update_type,
        active_version: None,
        previous_version: None,
        awaiting_verdict: false,
    })
}

/// Build a base-URL `SovdClient` for reading `/status` (bearer token when
/// non-empty). Cheap to construct per call.
fn status_client(
    server_url: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<SovdClient, EngineError> {
    let client = if token.is_empty() {
        SovdClient::new_verifying(server_url, insecure, ca_cert_pem)
    } else {
        SovdClient::with_bearer_token_verifying(server_url, token, insecure, ca_cert_pem)
    };
    client.map_err(|e| EngineError::Sovd {
        component: String::new(),
        message: format!("sovd client: {e}"),
    })
}

/// Read a component's heartbeat `boot_id` from `/status` `x-runtime`.
/// `None` when the component reports no heartbeat (offline, or a non-heartbeat
/// component like host-os) or `/status` is unreachable — callers treat absence
/// as "no boot_id witness" and fall back to the observed server down→up.
pub async fn read_boot_id(
    server_url: &str,
    component_id: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Option<u32> {
    let client = status_client(server_url, token, insecure, ca_cert_pem).ok()?;
    // (ii) `/status` unreadable → no heartbeat baseline. Stay quiet: the
    // connect-level down→up witness in `wait_activated` (which classifies its own
    // read errors) covers the reboot signal; here it is simply "no baseline".
    let body = match client.read_status(component_id).await {
        Ok(b) => b,
        Err(_) => return None,
    };
    // (i) `/status` readable but no heartbeat `boot_id`. Absence is *legitimate*
    // for non-heartbeat components (e.g. host-os), so this is a debug trace, not a
    // warning — the heartbeatless node path must not cry wolf on every baseline
    // capture. (The node-wide witness is `node_boot_id`; see `read_node_boot_id`.)
    match body
        .extensions
        .get("x-runtime")
        .and_then(|r| r.get("boot_id"))
        .and_then(|v| v.as_u64())
    {
        Some(v) => Some(v as u32),
        None => {
            debug!(component = %component_id, "x-runtime.boot_id absent — no heartbeat (or wire mismatch)");
            None
        }
    }
}

/// Read the NODE per-boot nonce from `/status` `x-runtime.node_boot_id` — a
/// string (UUID) the machine-manager stamps on EVERY component's status, changing
/// on every node reboot. This is the UNMISSABLE reboot witness for components with
/// no per-component heartbeat (`host-os`): unlike the transient SOVD down→up window
/// (which a fast reboot slips through), a changed `node_boot_id` is durable state
/// the poll can always observe. `None` when unreachable or the MM predates the
/// field (callers then fall back to the down→up witness). See the machine-manager
/// `read_entity_status` (component-mgr backend) which emits it.
pub async fn read_node_boot_id(
    server_url: &str,
    component_id: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Option<String> {
    let client = status_client(server_url, token, insecure, ca_cert_pem).ok()?;
    // (ii) `/status` unreadable → no node baseline; the down→up witness covers the
    // reboot. Quiet (the connect-level signal is `wait_activated`'s job).
    let body = match client.read_status(component_id).await {
        Ok(b) => b,
        Err(_) => return None,
    };
    // (i) `/status` readable but `node_boot_id` missing. Unlike heartbeat
    // `boot_id`, the MM stamps `node_boot_id` on EVERY component's status — its
    // absence means a wire-shape mismatch or an MM that predates the field, and
    // the reboot witness silently loses its unmissable signal. Say so loudly
    // (once per baseline capture, i.e. once per component per wait).
    match body
        .extensions
        .get("x-runtime")
        .and_then(|r| r.get("node_boot_id"))
        .and_then(|v| v.as_str())
    {
        Some(s) => Some(s.to_string()),
        None => {
            warn!(
                component = %component_id,
                "x-runtime.node_boot_id absent — wire mismatch or MM predates it"
            );
            None
        }
    }
}

/// The reboot-witness verdict — factored **pure** so the fail-closed decision is
/// unit-testable in isolation. See [`witness_decision`] / [`wait_activated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Witness {
    /// `node_boot_id` rotated (baseline `Some`, current `Some`, and they differ)
    /// — the unmissable node-reboot signal, valid even for no-heartbeat components.
    PassNodeBootId,
    /// Heartbeat `boot_id` rotated (baseline `Some`, current `Some`, and they
    /// differ) — a fresh guest lifetime.
    PassHeartbeatBootId,
    /// An OBSERVED connect-level down→up transition: the node was seen unreachable
    /// earlier this wait, and is now `ready`.
    PassDownUp,
    /// No witness yet — keep polling until the deadline.
    NotYet,
}

/// Pure, fail-closed reboot-witness decision. Passes ONLY on:
/// - (a) a positive boot-id transition — `node_boot_id` OR heartbeat `boot_id`
///   with BOTH baseline and current present and differing; OR
/// - (b) an observed down→up transition — `saw_down` was set by an earlier
///   connect-level poll THIS wait, and the node is now `ready`.
///
/// Every other input yields [`Witness::NotYet`] (times out): both baselines
/// `None` with no down→up, unchanged boot ids, or a boot id that merely
/// *appeared* (`None`→`Some`) — none of which prove a reboot. A pass ALWAYS
/// requires `ready`; a rebooted-but-not-yet-ready node keeps waiting.
fn witness_decision(
    node_baseline: Option<&str>,
    cur_node: Option<&str>,
    hb_baseline: Option<u32>,
    cur_hb: Option<u32>,
    ready: bool,
    saw_down: bool,
) -> Witness {
    if !ready {
        return Witness::NotYet;
    }
    if let (Some(b), Some(c)) = (node_baseline, cur_node) {
        if b != c {
            return Witness::PassNodeBootId;
        }
    }
    if let (Some(b), Some(c)) = (hb_baseline, cur_hb) {
        if b != c {
            return Witness::PassHeartbeatBootId;
        }
    }
    if saw_down {
        return Witness::PassDownUp;
    }
    Witness::NotYet
}

/// Classify a `/status` read failure: `true` iff the server did NOT answer at the
/// connect level (connection refused / timeout / io) — the DOWN half of a down→up
/// reboot witness. An HTTP status *response* (4xx/5xx → [`SovdClientError::ServerError`])
/// or a body that will not parse ([`SovdClientError::ParseError`]) proves the
/// server is UP, so it is NEVER a down observation (that conflation was the old
/// vacuous-pass hole).
fn is_connect_level(e: &SovdClientError) -> bool {
    matches!(
        e,
        SovdClientError::HttpError(_)
            | SovdClientError::ConnectionFailed(_)
            | SovdClientError::IoError(_)
            | SovdClientError::Timeout
    )
}

/// Name what the witness never saw, for the timeout error (fix: "an error that
/// names what was missing").
fn witness_timeout_reason(had_boot_baseline: bool, saw_down: bool) -> String {
    let boot = if had_boot_baseline {
        "boot id(s) captured but never rotated"
    } else {
        "node_boot_id absent on the wire"
    };
    let downup = if saw_down {
        "down observed but the node never came back ready"
    } else {
        "no down→up transition observed"
    };
    format!("no reboot witness: {boot} and {downup}")
}

/// Wait until a component is **rebooted and ready** — the converged verify the
/// orchestrator uses for every reset kind. Polls `/status` (tolerating the server
/// being unreachable mid-reboot) and passes ONLY when a reboot is genuinely
/// witnessed AND `status == ready` (see [`witness_decision`]):
/// - a rotated `node_boot_id` (unmissable, works for no-heartbeat host-os) or a
///   rotated heartbeat `boot_id` (a fresh guest lifetime); OR
/// - an OBSERVED connect-level down→up transition (the node was seen unreachable,
///   then answered ready) — the fallback for components with no boot-id witness.
///
/// Fail-closed: if the deadline expires with none of the above, it errors naming
/// the missing witness. A boot id that merely *appears* (`None`→`Some`), an HTTP
/// error response, or a transient non-connect read error do **not** pass — only a
/// real reboot does.
#[allow(clippy::too_many_arguments)]
pub async fn wait_activated(
    server_url: &str,
    component_id: &str,
    baseline: Option<u32>,
    node_baseline: Option<String>,
    timeout_secs: u64,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let client = status_client(server_url, token, insecure, ca_cert_pem)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    // The DOWN half of a down→up transition (1b): set once a poll fails at the
    // CONNECT level (the node is unreachable, i.e. rebooting), so a later ready
    // read completes the transition. Local to this wait — NOT a permanent latch —
    // and set ONLY by a connect-level failure (an HTTP status response proves the
    // server is up and must not count).
    let mut saw_down = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match client.read_status(component_id).await {
            Ok(body) => {
                let ready = matches!(body.status, EntityStatus::Ready);
                let runtime = body.extensions.get("x-runtime");
                let cur = runtime
                    .and_then(|r| r.get("boot_id"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let cur_node = runtime
                    .and_then(|r| r.get("node_boot_id"))
                    .and_then(|v| v.as_str());
                match witness_decision(
                    node_baseline.as_deref(),
                    cur_node,
                    baseline,
                    cur,
                    ready,
                    saw_down,
                ) {
                    Witness::NotYet => {}
                    pass => {
                        info!(component = %component_id, witness = ?pass, "reboot witnessed — component ready");
                        return Ok(());
                    }
                }
            }
            // Classify the read failure: only a CONNECT-level failure (node
            // unreachable) is the DOWN half of the witness. An HTTP status
            // response (4xx/5xx) or an unparseable body proves the server is UP,
            // so it never counts as down — that was the vacuous-pass hole.
            Err(e) => {
                if is_connect_level(&e) {
                    saw_down = true;
                } else {
                    debug!(component = %component_id, error = %e, "status poll: server answered, no witness yet");
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(EngineError::Timeout {
                component: component_id.to_string(),
                operation: witness_timeout_reason(
                    node_baseline.is_some() || baseline.is_some(),
                    saw_down,
                ),
            });
        }
    }
}

/// Local reset of one component: capture its boot_id, restart it, and wait for a
/// fresh, ready lifetime — the per-component analogue of the node path, same
/// `/status` boot_id witness, just a per-component `status/restart` instead of a
/// coalesced node reboot.
pub async fn restart_and_verify(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    timeout_secs: u64,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let baseline = read_boot_id(server_url, component_id, token, insecure, ca_cert_pem).await;
    trigger_local_restart(
        server_url,
        component_id,
        gateway_id,
        token,
        insecure,
        ca_cert_pem,
    )
    .await?;
    wait_activated(
        server_url,
        component_id,
        baseline,
        // Local per-component restart (not a node reboot) — the node_boot_id
        // doesn't change, so no node witness here; the heartbeat/down witness
        // applies as before.
        None,
        timeout_secs,
        token,
        insecure,
        ca_cert_pem,
    )
    .await
}

/// The components a verdict record reports it acted on — the `committed` set for a
/// commit, `rolled_back` for a rollback (`op_id` selects the key). `None` when the
/// record does not report the set at all.
fn acted_components(record: &OperationExecution, op_id: &str) -> Option<Vec<String>> {
    let key = if op_id.contains("rollback") {
        "rolled_back"
    } else {
        "committed"
    };
    record.result.as_ref()?.get(key)?.as_array().map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    })
}

/// Validate a §7.14 node-verdict execution record's CONTENT — clock-free. Requires
/// `status == completed` and, when the record reports the acted-on set, that every
/// `expected` component appears in it (catches a verdict that acted on a stale/empty
/// in-trial set — those show up under `skipped`, not `committed`). `op_id` selects the
/// result key.
///
/// Freshness/replay is deliberately NOT judged here: device clocks are not comparable
/// across boots or machines (every boot starts at a floor and ticks, so stamps from
/// different boots overlap and are unordered; a fully-synced device can even lag the
/// orchestrator), so ANY wall-clock comparison false-fails an honest commit — a field
/// occurrence. Tying a record to our request is [`check_verdict`]'s job, by response
/// CORRELATION (nonce echo / unique execution id), never by time. Returns
/// `Err(compact-echo-of-record)` on a content violation.
///
/// Pure (all inputs are values) so the content rules are unit-testable.
fn validate_verdict_record(
    record: &OperationExecution,
    op_id: &str,
    expected: &[String],
) -> Result<(), String> {
    if record.status != OperationStatus::Completed {
        return Err(format!(
            "verdict not completed (status={}): {}",
            record.status,
            compact_record(record)
        ));
    }
    // Content check: when the record reports the acted-on set, the components we asked
    // to commit must appear there — catches a verdict that acted on a stale or empty
    // in-trial set (they would show up under `skipped`, not `committed`).
    if let Some(acted) = acted_components(record, op_id) {
        let acted_key = if op_id.contains("rollback") {
            "rolled_back"
        } else {
            "committed"
        };
        for comp in expected {
            if !acted.iter().any(|a| acted_matches(comp, a)) {
                return Err(format!(
                    "expected component {comp:?} absent from {acted_key} {acted:?}: {}",
                    compact_record(record)
                ));
            }
        }
    }
    Ok(())
}

/// Does an acted-on name in a verdict result satisfy an expected SOVD component id?
/// Fielded machine-managers (≤ 2026-08) report the OS BANK-SET id "host-os" where the
/// SOVD component id is "host" — the other bank sets reuse their component id verbatim,
/// so only that one alias exists. Kept until fleet verdicts speak SOVD component ids
/// (the device-side fix); a fixed device reports "host" and never takes the alias arm.
fn acted_matches(expected: &str, acted: &str) -> bool {
    acted == expected || (expected == "host" && acted == "host-os")
}

/// One-line echo of an execution record for error messages (no pretty-print).
fn compact_record(r: &OperationExecution) -> String {
    format!(
        "{{status={}, started_at={}, completed_at={:?}, result={}}}",
        r.status,
        r.started_at,
        r.completed_at,
        r.result
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string())
    )
}

/// The client replay nonce the device echoed in its verdict record, read from the
/// RAW response JSON — [`OperationExecution`] has no `nonce` field, so component-mgr
/// appends it as a flattened top-level `nonce` (its `sovd/routes.rs` `VerdictExecution`).
/// `None` = an older device that ignores the POST body (no echo).
fn echoed_nonce(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("nonce")?
        .as_str()
        .map(str::to_string)
}

/// Whether a verdict response is trustworthy — CORRELATION (does this record answer
/// OUR request?) layered over the content check. Three-way so [`node_verdict`] knows
/// when a virgin-connection retry could help ([`Retry`](VerdictOutcome::Retry)) versus
/// a terminal outcome ([`Fail`](VerdictOutcome::Fail)).
#[derive(Debug, PartialEq, Eq)]
enum VerdictOutcome {
    /// Correlated to OUR request and content-valid — the commit is real.
    /// `adopted_uncorrelated` marks the old-device fallback (no nonce echo, non-unique
    /// execution id) accepted ONLY on an exact content match; the caller warns.
    Valid { adopted_uncorrelated: bool },
    /// The device echoed a *different* nonce than we sent — a stale/replayed response.
    /// A virgin connection sidesteps a transport-level replay, so retry once.
    Retry(String),
    /// Terminal refusal: a genuinely bad verdict (wrong status / missing component), or
    /// an UNCORRELATED response we cannot tie to our request and cannot adopt.
    Fail(String),
}

/// Decide whether a verdict response answers OUR request — clock-free CORRELATION,
/// then the content check. Device clocks are not comparable across boots/machines, so
/// NO wall-clock comparison is used (that false-failed an honest commit in the field).
///
/// Accept, in order: (1) the device echoed back the `nonce` we sent; (2) a UNIQUE
/// per-POST `execution_id` (it differs from the constant `operation_id`) — the device
/// minted a fresh id for this execution, read as the direct response of our
/// virgin-connection POST. A *mismatched* nonce echo is a replay → retry. Otherwise the
/// response is UNCORRELATED (an old constant-id device that does not echo): with no
/// clock to fall back on, adopt ONLY when the acted-on set EXACTLY equals `expected`
/// (and the caller says so loudly), else refuse and name the missing discriminator.
/// Pure, so the correlation/content rules are unit-testable.
fn check_verdict(
    record: &OperationExecution,
    echoed: Option<&str>,
    sent_nonce: &str,
    op_id: &str,
    expected: &[String],
) -> VerdictOutcome {
    // A mismatched nonce echo is the replay symptom — a virgin connection sidesteps the
    // transport-level replay, so retry (never accept a differently-nonced record).
    if matches!(echoed, Some(n) if n != sent_nonce) {
        return VerdictOutcome::Retry(
            "verdict nonce mismatched (stale or replayed response)".to_string(),
        );
    }
    // Correlated iff (1) our nonce echoed back, or (2) a unique per-POST execution id
    // (≠ the constant operation_id) — either ties this record to our request,
    // clock-free (a fresh device mints a fresh id per POST; constant-id devices reuse
    // operation_id). We read the direct response of a virgin-connection POST.
    let nonce_correlated = echoed == Some(sent_nonce);
    let execid_correlated = record.execution_id != record.operation_id;
    if nonce_correlated || execid_correlated {
        return match validate_verdict_record(record, op_id, expected) {
            Ok(()) => VerdictOutcome::Valid {
                adopted_uncorrelated: false,
            },
            Err(e) => VerdictOutcome::Fail(e),
        };
    }
    // Uncorrelated: an old constant-id device that does not echo the nonce. No clock to
    // judge freshness. Adopt ONLY on an exact content match — the acted-on set equals
    // the requested set — leaving the caller to warn; otherwise refuse, naming the
    // missing discriminator.
    let acted = acted_components(record, op_id).unwrap_or_default();
    let exact_match = !expected.is_empty()
        && acted.len() == expected.len()
        && expected
            .iter()
            .all(|e| acted.iter().any(|a| acted_matches(e, a)));
    if record.status == OperationStatus::Completed && exact_match {
        VerdictOutcome::Valid {
            adopted_uncorrelated: true,
        }
    } else {
        VerdictOutcome::Fail(format!(
            "uncorrelated verdict — no nonce echo and a non-unique execution id \
             (execution_id == operation_id), so this record cannot be tied to our \
             request; not adopting (acted-on set is not an exact match): {}",
            compact_record(record)
        ))
    }
}

/// Issue a node-level verdict — the entity-root vendor operation that commits
/// (or rolls back) **every component currently in trial on the node** in one
/// call. This is how a node-reboot campaign step finalizes: the per-component
/// `/updates` sessions are gone after the reboot, so the orchestrator never
/// re-attaches per component — it issues ONE verdict and the node fans it out
/// from NV (the update *session* is the commit unit). Wire:
/// `POST /vehicle/v1/operations/{op_id}/executions` (ISO 17978-3 §7.14, at the
/// entity root).
///
/// A 2xx is necessary but NOT sufficient: the §7.14 execution record in the body is
/// parsed and [`check_verdict`]-checked — clock-free response CORRELATION (the device
/// echoed OUR `nonce`, or minted a unique per-POST `execution_id`) plus the content
/// check ([`validate_verdict_record`]: completed + acted on the `expected` components).
/// Each POST carries a fresh uuid4 `nonce` on a fresh one-off client (a virgin
/// connection), and a nonce-mismatched response is retried ONCE on another fresh
/// connection before failing — the field bug was a transport-level replay a virgin
/// connection sidesteps. An uncorrelated response from an old constant-id device is
/// adopted only on an exact content match (with a warning), else refused. A failed
/// fan-out returns 5xx with the per-component errors; an unparseable body is an error,
/// never a silent log.
async fn node_verdict(
    server_url: &str,
    op_id: &str,
    expected: &[String],
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let url = format!(
        "{}/vehicle/v1/operations/{op_id}/executions",
        server_url.trim_end_matches('/')
    );
    // Two attempts max: the field bug was a transport-level replay (a pooled
    // connection answering with a PRIOR execution's record). A VIRGIN connection
    // sidesteps it, so a stale/nonce-mismatched first response is retried ONCE.
    const MAX_ATTEMPTS: usize = 2;
    let mut last_retry_reason = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        // A fresh one-off client per attempt = a virgin connection pool: no
        // pooled/desynced connection is reused (the retry's whole point).
        let client = build_verdict_client(insecure, ca_cert_pem, op_id)?;
        // Unique per POST — the device echoes it verbatim in the execution record,
        // so a matching echo proves the record answers THIS request, not a replay.
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut req = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({ "nonce": nonce }).to_string());
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(|e| EngineError::FlashFailed {
            component: "node".to_string(),
            message: format!("{op_id}: {e}"),
        })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EngineError::FlashFailed {
                component: "node".to_string(),
                message: format!("{op_id}: HTTP {status}: {body}"),
            });
        }
        let record: OperationExecution =
            serde_json::from_str(&body).map_err(|e| EngineError::FlashFailed {
                component: "node".to_string(),
                message: format!(
                    "{op_id}: verdict response is not an execution record ({e}): {body}"
                ),
            })?;
        let echoed = echoed_nonce(&body);
        match check_verdict(&record, echoed.as_deref(), &nonce, op_id, expected) {
            VerdictOutcome::Valid {
                adopted_uncorrelated,
            } => {
                if adopted_uncorrelated {
                    warn!(
                        op = op_id,
                        "adopted an UNCORRELATED verdict on exact content match (device does not \
                         echo nonces and reuses the execution id) — upgrade the device for \
                         replay-proof commits"
                    );
                } else {
                    info!(op = op_id, "node-level verdict correlated and applied");
                }
                return Ok(());
            }
            VerdictOutcome::Fail(message) => {
                return Err(EngineError::FlashFailed {
                    component: "node".to_string(),
                    message: format!("{op_id}: {message}"),
                });
            }
            VerdictOutcome::Retry(reason) => {
                last_retry_reason = reason;
                if attempt < MAX_ATTEMPTS {
                    warn!(
                        op = op_id,
                        reason = %last_retry_reason,
                        "verdict nonce mismatched (likely replayed) — retrying once on a fresh connection"
                    );
                }
            }
        }
    }
    Err(EngineError::FlashFailed {
        component: "node".to_string(),
        message: format!("{op_id}: {last_retry_reason} (persisted after a fresh-connection retry)"),
    })
}

/// Build a one-off reqwest client for a node-verdict POST — the same CA-trust seam
/// as the SovdClient/FlashClient builders: pin the given root when set, else fall
/// back to skip-verify (`insecure`). One fresh client per verdict attempt yields a
/// virgin connection pool, the retry's defence against a pooled-connection replay.
fn build_verdict_client(
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
    op_id: &str,
) -> Result<reqwest::Client, EngineError> {
    let builder = reqwest::Client::builder();
    let builder = match ca_cert_pem {
        Some(pem) => {
            builder.add_root_certificate(reqwest::Certificate::from_pem(pem).map_err(|e| {
                EngineError::FlashFailed {
                    component: "node".to_string(),
                    message: format!("{op_id}: parse ca_cert_pem: {e}"),
                }
            })?)
        }
        None => builder.danger_accept_invalid_certs(insecure),
    };
    builder.build().map_err(|e| EngineError::FlashFailed {
        component: "node".to_string(),
        message: format!("{op_id}: build client: {e}"),
    })
}

/// Commit every in-trial component on the node in one verdict. `expected` are the
/// component ids that must appear in the record's `committed` set (empty ⇒ the manual
/// verb, correlation + completed status still enforced, no per-component content).
pub async fn commit_node_trials(
    server_url: &str,
    expected: &[String],
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    node_verdict(
        server_url,
        "x-ota-commit-trials",
        expected,
        token,
        insecure,
        ca_cert_pem,
    )
    .await
}

/// Roll back every in-trial component on the node in one verdict. `expected` are
/// the component ids that must appear in the record's `rolled_back` set.
pub async fn rollback_node_trials(
    server_url: &str,
    expected: &[String],
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    node_verdict(
        server_url,
        "x-ota-rollback-trials",
        expected,
        token,
        insecure,
        ca_cert_pem,
    )
    .await
}

/// Trigger a per-component restart via `PUT components/{id}/status/restart`
/// (used for `ResetKind::Local`). Does NOT wait for activation.
pub async fn trigger_local_restart(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let flash_client = build_flash_client(
        server_url,
        component_id,
        gateway_id,
        token,
        insecure,
        ca_cert_pem,
    )?;
    info!(component = %component_id, "resetting ECU");
    flash_client
        .ecu_reset("hard")
        .await
        .map_err(|e| EngineError::FlashFailed {
            component: component_id.to_string(),
            message: format!("reset: {e}"),
        })?;
    Ok(())
}

/// Read a component's declared `reset_kind` off the `/updates` wire (the
/// `x-ota-reset-kind` vendor field SOVDd captures at register time). Servers
/// that omit it deserialise to `Local`.
pub async fn fetch_reset_kind(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<sovd_core::ResetKind, EngineError> {
    let flash_client = build_flash_client(
        server_url,
        component_id,
        gateway_id,
        token,
        insecure,
        ca_cert_pem,
    )?;
    flash_client
        .attach(update_id)
        .await
        .map_err(|e| EngineError::FlashFailed {
            component: component_id.to_string(),
            message: format!("attach: {e}"),
        })?;
    let status = flash_client
        .spec_status()
        .await
        .map_err(|e| EngineError::FlashFailed {
            component: component_id.to_string(),
            message: format!("spec_status: {e}"),
        })?;
    Ok(status.reset_kind.unwrap_or_default())
}

/// Build a `FlashClient` for a component, bearing `token` when non-empty.
/// `insecure` skips TLS certificate verification on the device endpoint (the
/// `curl -k` equivalent); `false` is byte-identical to the prior `for_sovd*`
/// constructors (full verification). `ca_cert_pem`, when `Some`, instead pins
/// that PEM CA root for the device leaf (the verifying counterpart to
/// `insecure`); `None` keeps the `insecure` behaviour.
pub(crate) fn build_flash_client(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<FlashClient, EngineError> {
    let mut builder = FlashConfig::builder(server_url)
        .component_id(component_id)
        .insecure(insecure)
        .ca_cert_pem(ca_cert_pem.map(|c| c.to_vec()));
    if let Some(gw) = gateway_id {
        builder = builder.gateway_id(gw);
    }
    if !token.is_empty() {
        builder = builder.bearer(token);
    }
    FlashClient::new(builder.build()).map_err(|e| EngineError::Sovd {
        component: component_id.to_string(),
        message: format!("flash client: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- witness_decision: the pure, fail-closed reboot-witness verdict -------

    #[test]
    fn node_boot_id_transition_passes() {
        assert_eq!(
            witness_decision(Some("A"), Some("B"), None, None, true, false),
            Witness::PassNodeBootId
        );
    }

    #[test]
    fn heartbeat_boot_id_transition_passes() {
        assert_eq!(
            witness_decision(None, None, Some(1), Some(2), true, false),
            Witness::PassHeartbeatBootId
        );
    }

    #[test]
    fn both_baselines_none_and_no_transition_never_passes() {
        // The vacuous-pass hole, closed: no boot-id baseline, server up, no
        // down→up ⇒ keep waiting (times out) — never a pass.
        assert_eq!(
            witness_decision(None, None, None, None, true, false),
            Witness::NotYet
        );
        // A boot id that merely *appears* (None→Some) is not a transition either.
        assert_eq!(
            witness_decision(None, Some("A"), None, Some(1), true, false),
            Witness::NotYet
        );
    }

    #[test]
    fn unchanged_boot_ids_do_not_pass() {
        assert_eq!(
            witness_decision(Some("A"), Some("A"), Some(1), Some(1), true, false),
            Witness::NotYet
        );
    }

    #[test]
    fn connect_fail_then_up_passes_but_only_when_ready() {
        // down observed earlier this wait + now ready ⇒ down→up pass.
        assert_eq!(
            witness_decision(None, None, None, None, true, true),
            Witness::PassDownUp
        );
        // down observed but not yet ready ⇒ keep waiting (no vacuous pass).
        assert_eq!(
            witness_decision(None, None, None, None, false, true),
            Witness::NotYet
        );
    }

    #[test]
    fn not_ready_never_passes_even_with_a_boot_id_transition() {
        assert_eq!(
            witness_decision(Some("A"), Some("B"), Some(1), Some(2), false, true),
            Witness::NotYet
        );
    }

    #[test]
    fn post_202_connect_fail_then_node_rotation_passes() {
        // The field sequence: a first post-202 poll fails at the connect level
        // (server mid-respawn) ⇒ saw_down; a later poll answers ready with a
        // rotated node_boot_id ⇒ PassNodeBootId (the stronger witness wins over
        // the down→up fallback). The loop continues across the down-window.
        assert_eq!(
            witness_decision(Some("old"), Some("new"), None, None, true, true),
            Witness::PassNodeBootId
        );
    }

    #[test]
    fn witness_timeout_reason_names_the_missing_witness() {
        // Repeated connect-fail-until-deadline ends the wait with a NAMED reason,
        // never a propagated read error.
        let no_baseline = witness_timeout_reason(false, false);
        assert!(no_baseline.contains("node_boot_id absent on the wire"));
        assert!(no_baseline.contains("no down→up transition observed"));
        let down_but_not_ready = witness_timeout_reason(true, true);
        assert!(down_but_not_ready.contains("never rotated"));
        assert!(down_but_not_ready.contains("never came back ready"));
    }

    // --- is_connect_level: the down-half classifier ---------------------------

    #[test]
    fn connect_level_errors_count_as_down() {
        assert!(is_connect_level(&SovdClientError::ConnectionFailed(
            "refused".into()
        )));
        assert!(is_connect_level(&SovdClientError::Timeout));
        assert!(is_connect_level(&SovdClientError::IoError(
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused")
        )));
    }

    #[test]
    fn a_5xx_response_does_not_count_as_down() {
        // A 5xx is a RESPONSE — the server is up, just erroring. NOT down.
        assert!(!is_connect_level(&SovdClientError::ServerError {
            status: 503,
            message: "unavailable".into()
        }));
        // A body that will not parse is also a response ⇒ up, not down.
        assert!(!is_connect_level(&SovdClientError::ParseError(
            "bad json".into()
        )));
    }

    // --- validate_verdict_record: CONTENT only (status + acted-on set), no clock ----

    fn record(status: OperationStatus, result: Option<serde_json::Value>) -> OperationExecution {
        OperationExecution {
            // execution_id == operation_id ⇒ a constant-id device (pre-3b436b3); the
            // correlation tests set a distinct execution_id for the unique-id case.
            execution_id: "x-ota-commit-trials".into(),
            operation_id: "x-ota-commit-trials".into(),
            status,
            result,
            error: None,
            started_at: "2026-01-01T00:00:00Z".into(),
            // Timestamps are display-only now — they never gate acceptance.
            completed_at: Some("2026-01-01T00:00:00Z".into()),
        }
    }

    #[test]
    fn completed_verdict_with_expected_committed_passes() {
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm1", "vm2"], "skipped": [] })),
        );
        assert!(validate_verdict_record(&rec, "x-ota-commit-trials", &["vm1".to_string()]).is_ok());
    }

    #[test]
    fn wrong_status_fails() {
        let rec = record(OperationStatus::Failed, None);
        let err = validate_verdict_record(&rec, "x-ota-commit-trials", &[]).unwrap_err();
        assert!(err.contains("not completed"), "got: {err}");
    }

    #[test]
    fn missing_component_in_committed_fails() {
        // vm1 was skipped, not committed — a stale/empty in-trial set.
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm2"], "skipped": ["vm1"] })),
        );
        let err =
            validate_verdict_record(&rec, "x-ota-commit-trials", &["vm1".to_string()]).unwrap_err();
        assert!(
            err.contains("vm1") && err.contains("committed"),
            "got: {err}"
        );
    }

    // --- check_verdict: clock-free response correlation ----------------------------

    /// A record with a UNIQUE per-POST execution id (≠ operation_id) — a 3b436b3+
    /// device. `committed` carries the acted-on set.
    fn unique_record(committed: &[&str]) -> OperationExecution {
        let mut rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": committed, "skipped": [] })),
        );
        rec.execution_id = "a3f1e9c2-unique-per-post".into();
        rec
    }

    #[test]
    fn nonce_echoed_and_matching_is_valid() {
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm1"], "skipped": [] })),
        );
        assert_eq!(
            check_verdict(
                &rec,
                Some("n1"),
                "n1",
                "x-ota-commit-trials",
                &["vm1".to_string()]
            ),
            VerdictOutcome::Valid {
                adopted_uncorrelated: false
            }
        );
    }

    #[test]
    fn nonce_echoed_but_mismatched_retries() {
        // A DIFFERENT echoed nonce is a replayed response → retry, even though status +
        // content would otherwise pass. This is the transport-replay field bug.
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm1"], "skipped": [] })),
        );
        assert!(matches!(
            check_verdict(
                &rec,
                Some("other"),
                "n1",
                "x-ota-commit-trials",
                &["vm1".to_string()]
            ),
            VerdictOutcome::Retry(_)
        ));
    }

    #[test]
    fn unique_execution_id_correlates_without_a_nonce_echo() {
        // No nonce echo, but the device minted a unique per-POST execution id → the
        // record is our direct response (rule 2), accepted on content.
        let rec = unique_record(&["vm1"]);
        assert_eq!(
            check_verdict(
                &rec,
                None,
                "n1",
                "x-ota-commit-trials",
                &["vm1".to_string()]
            ),
            VerdictOutcome::Valid {
                adopted_uncorrelated: false
            }
        );
    }

    #[test]
    fn host_os_bank_set_alias_satisfies_expected_host() {
        // Fielded machine-managers report the OS BANK-SET id "host-os" where the SOVD
        // component id is "host" (the field failure of 2026-08-17). The dated alias
        // accepts it — on a correlated record and on the uncorrelated exact-match path.
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["host-os"], "skipped": ["vm1"] })),
        );
        assert_eq!(
            check_verdict(
                &rec,
                Some("n1"),
                "n1",
                "x-ota-commit-trials",
                &["host".to_string()]
            ),
            VerdictOutcome::Valid {
                adopted_uncorrelated: false
            }
        );
        // Uncorrelated old device, exact set via the alias: adopted (loudly).
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["host-os"], "skipped": [] })),
        );
        assert_eq!(
            check_verdict(
                &rec,
                None,
                "n1",
                "x-ota-commit-trials",
                &["host".to_string()]
            ),
            VerdictOutcome::Valid {
                adopted_uncorrelated: true
            }
        );
        // The alias is one-way and specific: "host-os" expected is NOT satisfied by
        // "host", and no other component gets an alias.
        assert!(!acted_matches("host-os", "host"));
        assert!(!acted_matches("vm1", "vm1-os"));
    }

    #[test]
    fn uncorrelated_constant_id_is_adopted_only_on_exact_content_match() {
        // Old constant-id device (execution_id == operation_id), no nonce echo → cannot
        // be correlated. Adopt ONLY when the acted-on set EXACTLY equals the request.
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm1", "vm2"], "skipped": [] })),
        );
        assert_eq!(
            check_verdict(
                &rec,
                None,
                "n1",
                "x-ota-commit-trials",
                &["vm1".to_string(), "vm2".to_string()],
            ),
            VerdictOutcome::Valid {
                adopted_uncorrelated: true
            }
        );
    }

    #[test]
    fn uncorrelated_constant_id_without_exact_match_is_refused() {
        // Uncorrelated + the acted-on set is not an exact match ⇒ refuse, naming the gap.
        let rec = record(
            OperationStatus::Completed,
            // committed a DIFFERENT set than requested.
            Some(serde_json::json!({ "committed": ["vm2"], "skipped": ["vm1"] })),
        );
        match check_verdict(
            &rec,
            None,
            "n1",
            "x-ota-commit-trials",
            &["vm1".to_string()],
        ) {
            VerdictOutcome::Fail(msg) => assert!(msg.contains("uncorrelated"), "got: {msg}"),
            other => panic!("expected Fail(uncorrelated), got {other:?}"),
        }
    }

    #[test]
    fn nonce_match_but_bad_status_is_a_hard_fail() {
        // A matching nonce correlates, but a non-completed verdict is still a genuine
        // failure — Fail, never Retry (a fresh connection can't fix it).
        let rec = record(OperationStatus::Failed, None);
        assert!(matches!(
            check_verdict(&rec, Some("n1"), "n1", "x-ota-commit-trials", &[]),
            VerdictOutcome::Fail(_)
        ));
    }

    #[test]
    fn correlated_but_missing_expected_component_fails_on_content() {
        // Correlated (nonce match), but the expected component is absent from committed
        // → a hard content failure, never accepted.
        let rec = record(
            OperationStatus::Completed,
            Some(serde_json::json!({ "committed": ["vm2"], "skipped": ["vm1"] })),
        );
        assert!(matches!(
            check_verdict(
                &rec,
                Some("n1"),
                "n1",
                "x-ota-commit-trials",
                &["vm1".to_string()]
            ),
            VerdictOutcome::Fail(_)
        ));
    }

    #[test]
    fn echoed_nonce_reads_the_flattened_top_level_field() {
        // component-mgr flattens OperationExecution + appends a top-level `nonce`.
        let body = r#"{"execution_id":"e","operation_id":"o","status":"completed","started_at":"t","nonce":"abc"}"#;
        assert_eq!(echoed_nonce(body).as_deref(), Some("abc"));
        // No nonce field (old device) → None.
        let body_no =
            r#"{"execution_id":"e","operation_id":"o","status":"completed","started_at":"t"}"#;
        assert_eq!(echoed_nonce(body_no), None);
    }
}
