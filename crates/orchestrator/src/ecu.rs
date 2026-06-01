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
) -> Result<String, OrchestratorError> {
    match flash_client.open_update().await {
        Ok(t) => Ok(t.update_id),
        Err(FlashError::Server { ref message, .. }) if message.contains("trial mode") => {
            tracing::info!(
                component = %comp,
                detail = %message,
                "previous upgrade still in trial — auto-rolling back before new flash"
            );
            flash_client
                .rollback()
                .await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.to_string(),
                    message: format!("auto-rollback of pending trial: {e}"),
                })?;
            flash_client
                .open_update()
                .await
                .map(|t| t.update_id)
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
    pub update_type: UpdateType,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
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

    // Classify the manifest
    let (update_type, opaque_firmware) = match classify_manifest(&config.manifest, trust_anchor) {
        Ok((ut, _)) => (ut, false),
        Err(_) => {
            debug!(component = %comp, "package is not a SUIT envelope — treating as opaque firmware");
            (UpdateType::Firmware, true)
        }
    };
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
    let update_id = open_update_or_rollback_pending(&flash_client, comp).await?;
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
            // /updates verify: server runs verify_package per part +
            // backend.start_flash and waits for the UDS download to
            // settle.  After this returns, /updates state is
            // "verified" and the backend is at AwaitingActivation.
            info!(component = %comp, "running /executions{{verify}}");
            flash_client
                .verify()
                .await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("verify: {e}"),
                })?;

            // /executions{finalize}: server chains finalize_flash +
            // validate + activate.  After this returns, the backend
            // is at AwaitingReboot (dual-bank) or Activated
            // (single-bank).  `use_validated_flow` is a no-op now —
            // /updates always sequences validate inside finalize.
            info!(component = %comp, "running /executions{{finalize}}");
            flash_client
                .finalize()
                .await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("finalize: {e}"),
                })?;

            match update_type {
                UpdateType::Firmware => info!(component = %comp, "staged — awaiting reset"),
                UpdateType::Application => {
                    info!(component = %comp, "application update applied (no reset needed)")
                }
                UpdateType::Policy => unreachable!("handled in separate match arm"),
            }
        }
        UpdateType::Policy => {
            // Policy-only: applied on start_flash, nothing more to do
            info!(component = %comp, "policy applied (no flash/reset needed)");
        }
    }

    Ok(EcuFlashResult {
        component_id: comp.clone(),
        update_type,
        active_version: None,
        previous_version: None,
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
    timeout_secs: u64,
) -> Result<(), OrchestratorError> {
    trigger_local_restart(server_url, component_id, gateway_id).await?;
    wait_for_activation(server_url, component_id, gateway_id, timeout_secs).await
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
    timeout_secs: u64,
) -> Result<(), OrchestratorError> {
    let flash_client = build_flash_client(server_url, component_id, gateway_id)?;
    info!(component = %component_id, "waiting for activation");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // Use `latest_status` rather than `status`: the FlashClient
        // built here doesn't carry the update_id from the original
        // flash session (the caller may be a freshly-constructed
        // orchestrator task after reboot).  `latest_status` re-derives
        // it from the server's /updates collection.
        match flash_client.latest_status().await {
            Ok(status) => match status.state.as_str() {
                // /updates "finalized" + "committed" both mean the new
                // image is active on the device.
                "finalized" | "committed" => {
                    info!(component = %component_id, state = %status.state, "flash state activated");
                    return Ok(());
                }
                "rolledback" | "failed" | "aborted" => {
                    return Err(OrchestratorError::FlashFailed {
                        component: component_id.to_string(),
                        message: format!("activation reached {} after reset", status.state),
                    });
                }
                // verified / uploading / registered → keep polling
                _ => {}
            },
            Err(_) => {
                // ECU may be rebooting — retry
                debug!(component = %component_id, "status poll failed, retrying");
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

/// Read a component's `ActivationState` and return its declared reset_kind.
///
/// F.D8b: /updates doesn't surface reset_kind on the wire — that lives
/// on the legacy `/flash/activation` endpoint which is retired.  Until
/// `/updates` adds a `reset_kind` field (it should — campaign work
/// needs it), default to `Local`.  Callers that need the real value
/// should query the per-component status sub-resource directly.
pub async fn fetch_reset_kind(
    _server_url: &str,
    _component_id: &str,
    _gateway_id: Option<&str>,
) -> Result<sovd_core::ResetKind, OrchestratorError> {
    Ok(sovd_core::ResetKind::default())
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
