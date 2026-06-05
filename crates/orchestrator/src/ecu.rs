//! Per-ECU update — inspects SUIT manifest command sequences to determine
//! the update flow: firmware flash (full lifecycle) vs policy-only (immediate).
//!
//! Firmware: session → security → upload → flash → finalize → AwaitingReboot
//!           (reset is a campaign-level decision, not per-ECU)
//! Policy:   session → security → upload → apply (immediate, no trial)

use sovd_client::flash::{FlashClient, FlashError};
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{debug, info};

use crate::error::OrchestratorError;

/// Start a flash session, auto-rolling-back any pending trial first.
///
/// The vm-mgr backend refuses `start_flash` while the bank set is in
/// trial mode (uncommitted), to keep the state machine consistent — a
/// new upgrade would otherwise clobber the in-trial bank. When the
/// orchestrator sees the resulting server error containing "trial
/// mode" in the body, we treat it as "the previous trial wasn't
/// committed; abort it and start fresh" and retry once. Any other
/// error propagates.
///
/// Match by message content, not status code: the server error round-
/// trips through Machine-adapter as `PolicyRejected` and lands as
/// HTTP 400 "bad_request" rather than the 409 you'd expect for a
/// Busy semantic, so the only stable signal is the message text.
/// Open a fresh /updates session, auto-rolling back any pending trial
/// the backend may still be holding (vm-mgr refuses `start_flash`
/// while the bank set is mid-trial).  Returns the new update_id.
async fn open_update_or_rollback_pending(
    flash_client: &FlashClient,
    comp: &str,
    name: &str,
    version: &str,
) -> Result<String, OrchestratorError> {
    // Declare a meaningful package identity (name + version from the SUIT
    // manifest) so `GET /updates` lists a spec-exemplar id and §7.18 Table 261
    // carries a human name. The returned id is deterministic and is captured
    // into `EcuStatus.update_id` for the post-reset `attach()`.
    match flash_client.open_update_with(name, version).await {
        Ok(id) => Ok(id),
        Err(FlashError::Server { ref message, .. }) if message.contains("trial mode") => {
            tracing::info!(
                component = %comp,
                detail = %message,
                "previous upgrade still in trial — auto-rolling back before new flash"
            );
            // Auto-recovery: the previous trial's wire entry is past
            // awaiting-verdict (left at finalized or similar), so
            // spec_rollback's 409-unless-paused guard would reject.
            // force_rollback is the dedicated vendor verb for this
            // edge case — it unconditionally calls
            // backend.rollback_flash() to unstick the bank.
            flash_client
                .force_rollback()
                .await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.to_string(),
                    message: format!("force_rollback of pending trial: {e}"),
                })?;
            flash_client
                .open_update_with(name, version)
                .await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.to_string(),
                    message: format!("open_update after rollback: {e}"),
                })
        }
        Err(e) => Err(OrchestratorError::FlashFailed {
            component: comp.to_string(),
            message: format!("open_update: {e}"),
        }),
    }
}

/// Configuration for a single ECU update.
///
/// The ECU module is the SOVD flash protocol — it does **not** touch
/// session or security state. The caller (orchestrator) is responsible
/// for putting the ECU into a programming session with security
/// unlocked before invoking [`flash_ecu_to_staging`].
pub struct EcuFlashConfig {
    pub component_id: String,
    pub server_url: String,
    pub gateway_id: Option<String>,
    /// SUIT manifest bytes (small, ~1KB, no integrated payloads).
    pub manifest: Vec<u8>,
    /// Payload files in component order: [(URI, path), ...].
    /// Order must match the manifest's component sequence.
    pub payloads: Vec<(String, std::path::PathBuf)>,
    /// If true, after `transfer_exit` the orchestrator drives the ECU
    /// through `validate()` → `activate()` so the lifecycle visibly
    /// passes through the `Validated` checkpoint. Useful for multi-cycle
    /// campaigns where re-validation across power cycles is desired.
    /// Default false → classic flow (`transfer_exit` lands at
    /// `AwaitingReboot` directly).
    pub use_validated_flow: bool,
}

/// What kind of update this manifest represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    /// Full firmware update — needs flash + reset + trial + commit
    Firmware,
    /// Application/container update — needs upload + finalize, but no ECU reset/trial
    Application,
    /// Policy-only (CRL, config) — applied immediately, no trial
    Policy,
}

/// Result of staging one ECU (before reset).
pub struct EcuFlashResult {
    pub component_id: String,
    /// The `/updates` package id opened for this stage.  Captured so the
    /// campaign can re-`attach` a fresh post-reset FlashClient to the
    /// surviving server-side entry for commit/rollback.
    pub update_id: String,
    pub update_type: UpdateType,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    /// `true` when `execute()` paused at `substate=awaiting-verdict`
    /// (banked + orchestrated mode) — the campaign must drive reset
    /// then `spec_commit`/`spec_rollback`.  `false` when execute
    /// auto-completed (singleshot, application, or Phase A
    /// unorchestrated banked) — no further action needed.
    pub awaiting_verdict: bool,
}

/// Classify a manifest by inspecting its SUIT command sequences.
fn classify_manifest(
    envelope: &[u8],
    trust_anchor: &[u8],
) -> Result<(UpdateType, sumo_onboard::Manifest), OrchestratorError> {
    let crypto = RustCryptoBackend::new();
    let validator = Validator::new(trust_anchor, None);
    let manifest = validator
        .validate_envelope(envelope, &crypto, 0)
        .map_err(|e| OrchestratorError::Manifest(format!("{e:?}")))?;

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

/// Flash one ECU to staging — ends at AwaitingReboot for firmware updates.
///
/// Does NOT reset the ECU. The orchestrator decides when to reset
/// (e.g. after all ECUs are staged, or waiting for external power cycle).
///
/// **Precondition:** the caller (orchestrator) has already put the ECU
/// into a programming session with security access unlocked. This
/// module is the SOVD flash protocol; it does not touch session or
/// security state.
///
/// For Policy updates: applied immediately (no staging/reset needed).
pub async fn flash_ecu_to_staging(
    config: EcuFlashConfig,
    trust_anchor: &[u8],
) -> Result<EcuFlashResult, OrchestratorError> {
    let comp = &config.component_id;
    let gw = config.gateway_id.as_deref();

    // Classify the manifest (keep the parsed envelope to name the package).
    let (update_type, opaque_firmware, manifest) = match classify_manifest(
        &config.manifest,
        trust_anchor,
    ) {
        Ok((ut, m)) => (ut, false, Some(m)),
        Err(_) => {
            debug!(component = %comp, "package is not a SUIT envelope — treating as opaque firmware");
            (UpdateType::Firmware, true, None)
        }
    };

    // Derive a meaningful package identity for the /updates catalog from the
    // SUIT model/vendor name + text-version, falling back to the component id
    // and an empty version (opaque firmware carries no SUIT text).
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

    // Create flash client (session/security unlock is the orchestrator's job)
    let flash_client = if let Some(gw_id) = gw {
        FlashClient::for_sovd_sub_entity(&config.server_url, gw_id, comp)
    } else {
        FlashClient::for_sovd(&config.server_url, comp)
    }
    .map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("flash client: {e}"),
    })?;

    // /updates flow: open session → upload all parts → /executions
    // verify → /executions finalize.  Same shape for opaque firmware
    // (single "manifest" part) and SUIT-backed (manifest + payload
    // parts).
    let update_id =
        open_update_or_rollback_pending(&flash_client, comp, &pkg_name, &pkg_version).await?;
    info!(component = %comp, update_id = %update_id, "opened /updates session");

    info!(component = %comp, size = config.manifest.len(), "uploading manifest");
    let manifest_started = std::time::Instant::now();
    flash_client
        .upload_part("manifest", &config.manifest)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload: {e}"),
        })?;
    info!(
        component = %comp,
        bytes = config.manifest.len(),
        elapsed_ms = manifest_started.elapsed().as_millis() as u64,
        "manifest uploaded"
    );

    if !opaque_firmware {
        // SUIT-backed: also upload detached payloads in component order.
        for (uri, path) in &config.payloads {
            let data = std::fs::read(path).map_err(|e| OrchestratorError::FlashFailed {
                component: comp.clone(),
                message: format!("read payload {}: {e}", path.display()),
            })?;
            let bytes = data.len();
            info!(component = %comp, uri = %uri, size = bytes, "uploading payload");
            let started = std::time::Instant::now();
            flash_client.upload_part(uri, &data).await.map_err(|e| {
                OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("payload upload ({uri}): {e}"),
                }
            })?;
            let elapsed = started.elapsed();
            let mb = bytes as f64 / 1_048_576.0;
            let secs = elapsed.as_secs_f64();
            let mb_per_sec = if secs > 0.0 { mb / secs } else { 0.0 };
            info!(
                component = %comp, uri = %uri,
                elapsed_ms = elapsed.as_millis() as u64,
                "payload uploaded: {:.2} MB at {:.2} MB/s",
                mb, mb_per_sec
            );
        }
    }

    match update_type {
        UpdateType::Firmware | UpdateType::Application => {
            // ISO 17978-3 §7.18.5 prepare: server runs verify_part per
            // part + waits for the staging pipeline to settle.  Async
            // 202+poll — FlashClient.prepare() blocks until the wire
            // status reaches prepare/completed.
            info!(component = %comp, "running PUT /prepare");
            let prepared =
                flash_client
                    .prepare()
                    .await
                    .map_err(|e| OrchestratorError::FlashFailed {
                        component: comp.clone(),
                        message: format!("prepare: {e}"),
                    })?;
            if prepared.status != "completed" {
                return Err(OrchestratorError::FlashFailed {
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

            // ISO 17978-3 §7.18.6 execute: server-side
            // finalize_flash (+validate+activate for banked).
            //
            // Always opt into orchestrated mode for Firmware updates.
            // The server enforces shape semantics: banked components
            // pause at substate=awaiting-verdict; singleshot
            // components silently ignore the flag and auto-complete
            // (commit_flash included).  Application updates use
            // unorchestrated mode — they have no trial phase.
            let want_orchestrated = matches!(update_type, UpdateType::Firmware);
            info!(
                component = %comp,
                orchestrated = want_orchestrated,
                "running PUT /execute"
            );
            let executed = flash_client.execute(want_orchestrated).await.map_err(|e| {
                OrchestratorError::FlashFailed {
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
                    return Err(OrchestratorError::FlashFailed {
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

            match update_type {
                UpdateType::Firmware => info!(component = %comp, "staged — awaiting reset"),
                UpdateType::Application => {
                    info!(component = %comp, "application update applied (no reset needed)")
                }
                UpdateType::Policy => unreachable!("handled in separate match arm"),
            }

            return Ok(EcuFlashResult {
                component_id: comp.clone(),
                update_id,
                update_type,
                active_version: None,
                previous_version: None,
                awaiting_verdict,
            });
        }
        UpdateType::Policy => {
            // Policy-only: applied on start_flash, nothing more to do
            info!(component = %comp, "policy applied (no flash/reset needed)");
        }
    }

    Ok(EcuFlashResult {
        component_id: comp.clone(),
        update_id,
        update_type,
        active_version: None,
        previous_version: None,
        awaiting_verdict: false,
    })
}

/// Reset one ECU and wait until it actually reaches `Activated`.
///
/// `Activated` is now the component's own assertion that the new firmware
/// is up — for dual-bank VM components the backend stays in `Verifying`
/// across the post-reset health check and only promotes once its guest
/// reports healthy. The orchestrator therefore polls activation_state
/// straight through and no longer needs a separate guest-up heuristic.
pub async fn reset_and_activate(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
    timeout_secs: u64,
) -> Result<(), OrchestratorError> {
    trigger_local_restart(server_url, component_id, gateway_id).await?;
    wait_for_activation(
        server_url,
        component_id,
        gateway_id,
        update_id,
        timeout_secs,
    )
    .await
}

/// Trigger a per-component restart via the spec's `PUT
/// components/{id}/status/restart`. Used by `reset_and_activate` for
/// `ResetKind::Local` components and standalone callers.
///
/// Does NOT wait for activation — pair with `wait_for_activation` if you
/// need the full lifecycle.
pub async fn trigger_local_restart(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
) -> Result<(), OrchestratorError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id)?;
    info!(component = %component_id, "resetting ECU");
    flash_client
        .ecu_reset("hard")
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("reset: {e}"),
        })?;
    Ok(())
}

/// Poll `activation_state` until a component reports `activated` or
/// `committed`, or until the timeout elapses. Returns `Ok(())` on
/// success; `FlashFailed` if activation reaches `rolled_back`/`failed`;
/// `Timeout` after `timeout_secs`.
///
/// Survives the ECU being unreachable during reboot — transient poll
/// errors are logged at debug and retried.
pub async fn wait_for_activation(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
    timeout_secs: u64,
) -> Result<(), OrchestratorError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id)?;
    info!(component = %component_id, update_id = %update_id, "waiting for activation");
    // Bind the fresh client to the update_id captured at staging so
    // spec_status has an entry to query.  attach is local/infallible;
    // the device-reachability wait happens in the spec_status poll
    // below (the server-side entry survives the reset).
    flash_client
        .attach(update_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
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
                // Orchestrated banked: pause point post-activate.  Once
                // we observe this, the device is reachable and the
                // execute task is alive — ready to commit.
                ("execute", "inProgress", Some("awaiting-verdict")) => {
                    info!(component = %component_id, "execute paused at awaiting-verdict — ready to commit");
                    return Ok(());
                }
                // Standard banked (auto-commit) or singleshot: already
                // terminal-completed.  Nothing to wait for; the campaign
                // commit_all step becomes a no-op or hits 409 (handled
                // upstream).
                ("execute", "completed", _) => {
                    info!(component = %component_id, "execute completed (auto-committed)");
                    return Ok(());
                }
                ("execute", "failed", _) => {
                    return Err(OrchestratorError::FlashFailed {
                        component: component_id.to_string(),
                        message: format!(
                            "execute failed during/after reset: {}",
                            body.error.map(|e| e.message).unwrap_or_default()
                        ),
                    });
                }
                _ => {
                    // Still in earlier phase (prepare/uploading/etc) —
                    // shouldn't normally happen after execute() returned,
                    // but tolerate it during the device-rebooting window.
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
                // ECU may be rebooting — retry
                debug!(component = %component_id, "spec_status poll failed, retrying");
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(OrchestratorError::Timeout {
                component: component_id.to_string(),
                operation: "activation".into(),
            });
        }
    }
}

/// Read a component's declared reset_kind off the `/updates` wire.
///
/// SOVDd captures each component's `ActivationState.reset_kind` at
/// register time and surfaces it as the `x-sumo-reset-kind` vendor field
/// on the update's status body (ISO 17978-3 §5.4.5 permits `x-<ext>-`
/// fields).  We attach a fresh `FlashClient` to the staged `update_id`
/// and read it back via `spec_status()`.  Servers that haven't migrated
/// omit the field → `unwrap_or_default()` yields `Local`, matching their
/// pre-existing behaviour.
pub async fn fetch_reset_kind(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    update_id: &str,
) -> Result<sovd_core::ResetKind, OrchestratorError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id)?;
    flash_client
        .attach(update_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("attach: {e}"),
        })?;
    let status = flash_client
        .spec_status()
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("spec_status: {e}"),
        })?;
    Ok(status.reset_kind.unwrap_or_default())
}

fn build_flash_client(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
) -> Result<FlashClient, OrchestratorError> {
    if let Some(gw) = gateway_id {
        FlashClient::for_sovd_sub_entity(server_url, gw, component_id)
    } else {
        FlashClient::for_sovd(server_url, component_id)
    }
    .map_err(|e| OrchestratorError::Sovd {
        component: component_id.to_string(),
        message: format!("flash client: {e}"),
    })
}
