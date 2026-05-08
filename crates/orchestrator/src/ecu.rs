//! Per-ECU update — inspects SUIT manifest command sequences to determine
//! the update flow: firmware flash (full lifecycle) vs policy-only (immediate).
//!
//! Firmware: session → security → upload → flash → finalize → AwaitingReboot
//!           (reset is a campaign-level decision, not per-ECU)
//! Policy:   session → security → upload → apply (immediate, no trial)

use sovd_client::flash::FlashClient;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{info, debug};

use crate::error::OrchestratorError;

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

    let update_type = if manifest.has_install() || manifest.has_invoke() {
        UpdateType::Firmware
    } else {
        UpdateType::Policy
    };

    Ok((update_type, manifest))
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
    let update_type = match classify_manifest(&config.manifest, trust_anchor) {
        Ok((ut, _)) => ut,
        Err(_) => {
            debug!(component = %comp, "package is not a SUIT envelope — treating as opaque firmware");
            UpdateType::Firmware
        }
    };
    info!(component = %comp, gateway = ?gw, update_type = ?update_type, "starting ECU flash (assumes already unlocked)");

    // Create flash client (session/security unlock is the orchestrator's job)
    let flash_client = if let Some(gw_id) = gw {
        FlashClient::for_sovd_sub_entity(&config.server_url, gw_id, comp)
    } else {
        FlashClient::for_sovd(&config.server_url, comp)
    }.map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("flash client: {e}"),
    })?;

    // 1. Start flash session
    info!(component = %comp, "starting flash session");
    let transfer = flash_client.start_flash().await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("start flash: {e}"),
        })?;

    // 2. Upload manifest (tiny, first in sequence; processed synchronously)
    info!(component = %comp, size = config.manifest.len(), "uploading manifest");
    flash_client.upload_file(&config.manifest).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload: {e}"),
        })?;

    // 3. Upload each payload in component order (each streamed to bank synchronously)
    for (uri, path) in &config.payloads {
        let data = std::fs::read(path).map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("read payload {}: {e}", path.display()),
        })?;
        info!(component = %comp, uri = %uri, size = data.len(), "uploading payload");
        flash_client.upload_file(&data).await
            .map_err(|e| OrchestratorError::FlashFailed {
                component: comp.clone(),
                message: format!("payload upload ({uri}): {e}"),
            })?;
    }

    match update_type {
        UpdateType::Firmware => {
            // Flash → finalize → stop here (AwaitingReboot)
            flash_client.poll_flash_complete_simple(&transfer.transfer_id).await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("flash progress: {e}"),
                })?;

            info!(component = %comp, "finalizing transfer");
            flash_client.transfer_exit().await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("finalize: {e}"),
                })?;

            if config.use_validated_flow {
                // Drive lifecycle through Validated as a checkpoint —
                // backend.validate() accepts AwaitingReboot and downshifts,
                // backend.activate() then returns to AwaitingReboot. Useful
                // for multi-cycle campaigns; backends that don't support
                // the new ops will surface an HTTP error here so the caller
                // knows to either upgrade them or disable the flag.
                info!(component = %comp, "validating staged artifact");
                flash_client.validate_flash().await
                    .map_err(|e| OrchestratorError::FlashFailed {
                        component: comp.clone(),
                        message: format!("validate: {e}"),
                    })?;

                info!(component = %comp, "activating");
                flash_client.activate_flash().await
                    .map_err(|e| OrchestratorError::FlashFailed {
                        component: comp.clone(),
                        message: format!("activate: {e}"),
                    })?;
            }

            info!(component = %comp, "staged — awaiting reset");
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
    let flash_client = if let Some(gw) = gateway_id {
        FlashClient::for_sovd_sub_entity(server_url, gw, component_id)
    } else {
        FlashClient::for_sovd(server_url, component_id)
    }.map_err(|e| OrchestratorError::Sovd {
        component: component_id.to_string(),
        message: format!("flash client: {e}"),
    })?;

    info!(component = %component_id, "resetting ECU");
    flash_client.ecu_reset().await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("reset: {e}"),
        })?;

    info!(component = %component_id, "waiting for activation");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match flash_client.get_activation_state().await {
            Ok(state) => {
                let s = state.state.to_lowercase().replace('_', "");
                match s.as_str() {
                    "activated" | "committed" => {
                        info!(component = %component_id, state = %state.state, "flash state activated");
                        return Ok(());
                    }
                    "rolledback" | "failed" => {
                        return Err(OrchestratorError::FlashFailed {
                            component: component_id.to_string(),
                            message: format!("activation reached {} after reset", state.state),
                        });
                    }
                    // awaitingreboot / verifying / awaitingreset → keep polling
                    _ => {}
                }
            }
            Err(_) => {
                // ECU may be rebooting — retry
                debug!(component = %component_id, "activation poll failed, retrying");
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
