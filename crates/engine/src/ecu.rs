//! Per-ECU update primitives — inspect a SUIT manifest to pick the flow
//! (firmware flash vs application vs policy), drive the SOVD `/updates` wire,
//! and poll activation. Auth is a resolved bearer `token` (`""` ⇒ unauthed);
//! the caller ([`FlashEngine`](crate::FlashEngine)) owns the `TokenSource`.
//!
//! This module is the SOVD flash protocol only — it does **not** touch session
//! or security state. The driver unlocks the ECU (UDS) before staging.

use sovd_client::flash::{FlashClient, FlashError};
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

    let flash_client = build_flash_client(server_url, comp, gw, token)?;

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
            info!(component = %comp, uri = %payload.uri, "uploading payload");
            match &payload.source {
                PayloadSource::File(path) => {
                    let len = tokio::fs::metadata(path)
                        .await
                        .map_err(|e| EngineError::FlashFailed {
                            component: comp.clone(),
                            message: format!("stat payload {}: {e}", path.display()),
                        })?
                        .len();
                    let file = tokio::fs::File::open(path).await.map_err(|e| {
                        EngineError::FlashFailed {
                            component: comp.clone(),
                            message: format!("open payload {}: {e}", path.display()),
                        }
                    })?;
                    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
                    flash_client
                        .upload_part_stream(&payload.uri, body, Some(len))
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

/// Reset one ECU and wait until it reaches `Activated`.
pub async fn reset_and_activate(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
    timeout_secs: u64,
    token: &str,
) -> Result<(), EngineError> {
    trigger_local_restart(server_url, component_id, gateway_id, token).await?;
    wait_for_activation(
        server_url,
        component_id,
        gateway_id,
        update_id,
        timeout_secs,
        token,
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
) -> Result<(), EngineError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id, token)?;
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

/// Poll `/updates` status until the component reaches a terminal `execute`
/// state (`awaiting-verdict` ready-to-commit, or `completed`). Survives the
/// ECU being unreachable during reboot — transient poll errors are retried.
pub async fn wait_for_activation(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
    timeout_secs: u64,
    token: &str,
) -> Result<(), EngineError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id, token)?;
    info!(component = %component_id, update_id = %update_id, "waiting for activation");
    flash_client
        .attach(update_id)
        .await
        .map_err(|e| EngineError::FlashFailed {
            component: component_id.to_string(),
            message: format!("attach: {e}"),
        })?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match flash_client.spec_status().await {
            Ok(body) => match (
                body.phase.as_str(),
                body.status.as_str(),
                body.substate.as_deref(),
            ) {
                ("execute", "inProgress", Some("awaiting-verdict")) => {
                    info!(component = %component_id, "execute paused at awaiting-verdict — ready to commit");
                    return Ok(());
                }
                ("execute", "completed", _) => {
                    info!(component = %component_id, "execute completed (auto-committed)");
                    return Ok(());
                }
                ("execute", "failed", _) => {
                    return Err(EngineError::FlashFailed {
                        component: component_id.to_string(),
                        message: format!(
                            "execute failed during/after reset: {}",
                            body.error.map(|e| e.message).unwrap_or_default()
                        ),
                    });
                }
                _ => {
                    debug!(
                        component = %component_id,
                        phase = %body.phase,
                        status = %body.status,
                        substate = ?body.substate,
                        "wait_for_activation: still in flight"
                    );
                }
            },
            Err(_) => {
                debug!(component = %component_id, "spec_status poll failed, retrying");
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(EngineError::Timeout {
                component: component_id.to_string(),
                operation: "activation".into(),
            });
        }
    }
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
) -> Result<sovd_core::ResetKind, EngineError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id, token)?;
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
pub(crate) fn build_flash_client(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    token: &str,
) -> Result<FlashClient, EngineError> {
    let result = match (gateway_id, token.is_empty()) {
        (Some(gw), false) => {
            FlashClient::for_sovd_sub_entity_bearer(server_url, gw, component_id, token)
        }
        (Some(gw), true) => FlashClient::for_sovd_sub_entity(server_url, gw, component_id),
        (None, false) => FlashClient::for_sovd_bearer(server_url, component_id, token),
        (None, true) => FlashClient::for_sovd(server_url, component_id),
    };
    result.map_err(|e| EngineError::Sovd {
        component: component_id.to_string(),
        message: format!("flash client: {e}"),
    })
}
