/// Per-ECU update — inspects SUIT manifest command sequences to determine
/// the update flow: firmware flash (full lifecycle) vs policy-only (immediate).
///
/// Firmware: session → security → upload → flash → finalize → AwaitingReset
///           (reset is a campaign-level decision, not per-ECU)
/// Policy:   session → security → upload → apply (immediate, no trial)

use sovd_client::flash::FlashClient;
use sovd_client::SovdClient;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{info, debug};

use crate::error::OrchestratorError;
use crate::security_helper::{self, SecurityHelperConfig};

/// Configuration for a single ECU update.
pub struct EcuFlashConfig {
    pub component_id: String,
    pub server_url: String,
    pub gateway_id: Option<String>,
    pub security_level: u8,
    /// SUIT manifest bytes (small, ~1KB, no integrated payloads).
    pub manifest: Vec<u8>,
    /// Payload files in component order: [(URI, path), ...].
    /// Order must match the manifest's component sequence.
    pub payloads: Vec<(String, std::path::PathBuf)>,
    pub security_helper: SecurityHelperConfig,
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

/// Flash one ECU to staging — ends at AwaitingReset for firmware updates.
///
/// Does NOT reset the ECU. The orchestrator decides when to reset
/// (e.g. after all ECUs are staged, or waiting for external power cycle).
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
    info!(component = %comp, gateway = ?gw, update_type = ?update_type, "starting ECU update");

    let client = SovdClient::new(&config.server_url)
        .map_err(|e| OrchestratorError::Sovd {
            component: comp.clone(),
            message: format!("connect: {e}"),
        })?;

    let (mode_component, mode_target) = if let Some(gw_id) = gw {
        (gw_id, Some(comp.as_str()))
    } else {
        (comp.as_str(), None)
    };

    // 1. Switch to programming session
    info!(component = %comp, "switching to programming session");
    client.set_mode_targeted(
        mode_component, "session",
        serde_json::json!({"value": "programming"}),
        mode_target,
    ).await.map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("set_session: {e}"),
    })?;

    // 2. Security unlock
    info!(component = %comp, level = config.security_level, "requesting security seed");
    let seed_resp = client.set_mode_targeted(
        mode_component, "security",
        serde_json::json!({"value": format!("level{}_requestseed", config.security_level)}),
        mode_target,
    ).await.map_err(|e| OrchestratorError::SecurityFailed {
        component: comp.clone(),
        message: format!("request seed: {e}"),
    })?;

    if let Some(seed_val) = seed_resp.seed.as_ref() {
        let seed_str = seed_val
            .get("Request_Seed")
            .and_then(|s| s.as_str())
            .or_else(|| seed_val.as_str())
            .unwrap_or("");

        // Compute key via security helper
        let key_hex = security_helper::compute_key(
            &config.security_helper, seed_str, config.security_level, comp,
        )
        .await?;

        info!(component = %comp, "sending security key");
        client.set_mode_targeted(
            mode_component, "security",
            serde_json::json!({"value": format!("level{}", config.security_level), "key": key_hex}),
            mode_target,
        ).await.map_err(|e| OrchestratorError::SecurityFailed {
            component: comp.clone(),
            message: format!("send key: {e}"),
        })?;
    }

    // 3. Create flash client
    let flash_client = if let Some(gw_id) = gw {
        FlashClient::for_sovd_sub_entity(&config.server_url, gw_id, comp)
    } else {
        FlashClient::for_sovd(&config.server_url, comp)
    }.map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("flash client: {e}"),
    })?;

    // 4. Start flash session
    info!(component = %comp, "starting flash session");
    let transfer = flash_client.start_flash().await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("start flash: {e}"),
        })?;

    // 5. Upload manifest (tiny, first in sequence)
    info!(component = %comp, size = config.manifest.len(), "uploading manifest");
    let manifest_upload = flash_client.upload_file(&config.manifest).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload: {e}"),
        })?;
    flash_client.poll_upload_complete(&manifest_upload.upload_id).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload poll: {e}"),
        })?;

    // 6. Upload each payload in component order (streamed to bank)
    for (uri, path) in &config.payloads {
        let data = std::fs::read(path).map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("read payload {}: {e}", path.display()),
        })?;
        info!(component = %comp, uri = %uri, size = data.len(), "uploading payload");
        let upload = flash_client.upload_file(&data).await
            .map_err(|e| OrchestratorError::FlashFailed {
                component: comp.clone(),
                message: format!("payload upload ({uri}): {e}"),
            })?;
        flash_client.poll_upload_complete(&upload.upload_id).await
            .map_err(|e| OrchestratorError::FlashFailed {
                component: comp.clone(),
                message: format!("payload upload poll ({uri}): {e}"),
            })?;
    }

    match update_type {
        UpdateType::Firmware => {
            // Flash → finalize → stop here (AwaitingReset)
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

/// Reset one ECU and wait for it to reach trial (Activated) state.
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

    // Wait for activation — poll until not awaiting_reset
    info!(component = %component_id, "waiting for activation");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match flash_client.get_activation_state().await {
            Ok(state) => {
                let s = state.state.to_lowercase().replace('_', "");
                if s != "awaitingreset" {
                    info!(component = %component_id, state = %state.state, "ECU activated");
                    return Ok(());
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
