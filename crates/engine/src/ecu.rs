//! Per-ECU update primitives — inspect a SUIT manifest to pick the flow
//! (firmware flash vs application vs policy), drive the SOVD `/updates` wire,
//! and poll activation. Auth is a resolved bearer `token` (`""` ⇒ unauthed);
//! the caller ([`FlashEngine`](crate::FlashEngine)) owns the `TokenSource`.
//!
//! This module is the SOVD flash protocol only — it does **not** touch session
//! or security state. The driver unlocks the ECU (UDS) before staging.

use sovd_client::flash::{FlashClient, FlashConfig, FlashError};
use sovd_client::SovdClient;
use sovd_core::EntityStatus;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{debug, info};

use crate::error::EngineError;
use crate::types::{FlashJob, PayloadSource, UpdateType};

/// Open a fresh `/updates` session, auto-rolling back any pending trial the
/// backend may still be holding (vm-mgr refuses `start_flash` while the bank
/// set is mid-trial). Returns the new update_id.
async fn open_update_or_rollback_pending(
    flash_client: &FlashClient,
    comp: &str,
    name: &str,
    version: &str,
) -> Result<String, EngineError> {
    match flash_client.open_update_with(name, version).await {
        Ok(id) => Ok(id),
        Err(FlashError::Server { ref message, .. }) if message.contains("trial mode") => {
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
        Err(e) => Err(EngineError::FlashFailed {
            component: comp.to_string(),
            message: format!("open_update: {e}"),
        }),
    }
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
        UpdateType::Firmware | UpdateType::Application => {
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
            // auto-completes). Application updates have no trial phase.
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
pub(crate) fn status_client(
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

/// Swap a URL's scheme between `http://` and `https://` (prefix only); returns
/// `None` when the URL begins with neither prefix. Used to recover when a device
/// flips scheme across a reset: its `tls-identity` goes live on the first
/// post-provision restart, turning `http://host:port` into `https://host:port`.
pub(crate) fn flip_scheme(url: &str) -> Option<String> {
    if let Some(rest) = url.strip_prefix("https://") {
        Some(format!("http://{rest}"))
    } else {
        url.strip_prefix("http://")
            .map(|rest| format!("https://{rest}"))
    }
}

/// Read a component's heartbeat `boot_id` from `/status` `x-sumo-runtime`.
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
    let body = client.read_status(component_id).await.ok()?;
    body.extensions
        .get("x-sumo-runtime")?
        .get("boot_id")?
        .as_u64()
        .map(|v| v as u32)
}

/// Wait until a component is **rebooted and ready** — the converged verify the
/// orchestrator uses for every reset kind. Polls `/status` (tolerating the
/// server being unreachable mid-reboot) until `status == ready` AND a reboot is
/// witnessed:
/// - the heartbeat `boot_id` changed from `baseline` — a fresh guest lifetime,
///   the primary witness for heartbeat components (works for a node reboot AND a
///   per-VM relaunch; a stale heartbeat carries the OLD boot_id so it can't fool
///   us); OR
/// - the component reports no `boot_id` at all (non-heartbeat, e.g. host-os) and
///   the SOVD server was seen to go down→up (the node restarted).
///
/// `baseline == None` (the component was offline pre-reset, e.g. factory
/// provision) accepts the first heartbeat that appears.
pub async fn wait_activated(
    server_url: &str,
    component_id: &str,
    baseline: Option<u32>,
    timeout_secs: u64,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let mut base = server_url.to_string();
    let mut client = status_client(&base, token, insecure, ca_cert_pem)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut saw_down = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match client.read_status(component_id).await {
            Ok(body) => {
                let ready = matches!(body.status, EntityStatus::Ready);
                let cur = body
                    .extensions
                    .get("x-sumo-runtime")
                    .and_then(|r| r.get("boot_id"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let rebooted = match (baseline, cur) {
                    (Some(b), Some(c)) => c != b, // heartbeat: a new guest lifetime
                    (None, Some(_)) => true,      // was offline: first lifetime is the boot
                    (_, None) => saw_down,        // no heartbeat: node down→up witness
                };
                if ready && rebooted {
                    return Ok(());
                }
            }
            // Unreachable mid-reboot (the node went down) — record it as a
            // fallback witness for non-heartbeat components and keep polling.
            // The device may also flip http<->https across the reset (its
            // tls-identity goes live); if the opposite scheme now answers,
            // adopt it so the next poll proceeds on the live endpoint.
            Err(_) => {
                saw_down = true;
                if let Some(f) = flip_scheme(&base) {
                    if let Ok(c) = status_client(&f, token, insecure, ca_cert_pem) {
                        if c.read_status(component_id).await.is_ok() {
                            base = f;
                            client = c;
                        }
                    }
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(EngineError::Timeout {
                component: component_id.to_string(),
                operation: "reboot+ready (/status boot_id)".into(),
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
        timeout_secs,
        token,
        insecure,
        ca_cert_pem,
    )
    .await
}

/// Issue a node-level verdict — the entity-root vendor operation that commits
/// (or rolls back) **every component currently in trial on the node** in one
/// call. This is how a node-reboot campaign step finalizes: the per-component
/// `/updates` sessions are gone after the reboot, so the orchestrator never
/// re-attaches per component — it issues ONE verdict and the node fans it out
/// from NV (the update *session* is the commit unit). The op is synchronous;
/// a 2xx is success, a failed fan-out returns 5xx with the per-component
/// errors in the body. Wire: `POST /vehicle/v1/operations/{op_id}/executions`
/// (ISO 17978-3 §7.14, at the entity root).
async fn node_verdict(
    server_url: &str,
    op_id: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    let url = format!(
        "{}/vehicle/v1/operations/{op_id}/executions",
        server_url.trim_end_matches('/')
    );
    // Same CA-trust seam as the SovdClient/FlashClient builders: pin the given
    // root when set, else fall back to skip-verify (`insecure`).
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
    let client = builder.build().map_err(|e| EngineError::FlashFailed {
        component: "node".to_string(),
        message: format!("{op_id}: build client: {e}"),
    })?;
    let mut req = client.post(&url);
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
    info!(op = op_id, %body, "node-level verdict applied");
    Ok(())
}

/// Commit every in-trial component on the node in one verdict.
pub async fn commit_node_trials(
    server_url: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    node_verdict(
        server_url,
        "x-sumo-commit-trials",
        token,
        insecure,
        ca_cert_pem,
    )
    .await
}

/// Roll back every in-trial component on the node in one verdict.
pub async fn rollback_node_trials(
    server_url: &str,
    token: &str,
    insecure: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<(), EngineError> {
    node_verdict(
        server_url,
        "x-sumo-rollback-trials",
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
/// `x-sumo-reset-kind` vendor field SOVDd captures at register time). Servers
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

    #[test]
    fn flip_scheme_swaps_http_and_https() {
        assert_eq!(
            flip_scheme("http://host:8080/x").as_deref(),
            Some("https://host:8080/x")
        );
        assert_eq!(
            flip_scheme("https://host:8080/x").as_deref(),
            Some("http://host:8080/x")
        );
        assert_eq!(flip_scheme("ftp://x"), None);
    }
}
