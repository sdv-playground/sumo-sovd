/// Per-ECU update — inspects SUIT manifest command sequences to determine
/// the update flow: firmware flash (full lifecycle) vs policy-only (immediate).
///
/// Firmware: session → security → upload → flash → finalize → reset → trial
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
    pub package: Vec<u8>,
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

/// Result of updating one ECU.
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

/// Update one ECU — flow determined by manifest command sequences.
///
/// For Firmware: puts ECU in trial mode (NOT committed).
/// For Policy: applied immediately (no trial).
pub async fn flash_ecu_to_trial(
    config: EcuFlashConfig,
    trust_anchor: &[u8],
) -> Result<EcuFlashResult, OrchestratorError> {
    let comp = &config.component_id;
    let gw = config.gateway_id.as_deref();

    // Classify the manifest (if it's a SUIT envelope; non-SUIT packages are treated as firmware)
    let update_type = match classify_manifest(&config.package, trust_anchor) {
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

    // 4. Upload
    info!(component = %comp, size = config.package.len(), "uploading package");
    let upload = flash_client.upload_file(&config.package).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("upload: {e}"),
        })?;
    let file_id = upload.upload_id;

    let status = flash_client.poll_upload_complete(&file_id).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("upload poll: {e}"),
        })?;
    let file_id = status.file_id.unwrap_or(file_id);

    // 5. Verify
    info!(component = %comp, "verifying package");
    flash_client.verify_file(&file_id).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("verify: {e}"),
        })?;

    // 6. Start flash
    info!(component = %comp, "starting flash transfer");
    let transfer = flash_client.start_flash(&file_id).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("start flash: {e}"),
        })?;

    match update_type {
        UpdateType::Firmware => {
            // Full firmware lifecycle: poll → finalize → reset → wait for trial
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

            info!(component = %comp, "resetting ECU");
            flash_client.ecu_reset().await
                .map_err(|e| OrchestratorError::FlashFailed {
                    component: comp.clone(),
                    message: format!("reset: {e}"),
                })?;

            // Wait for activation — poll until not awaiting_reset
            info!(component = %comp, "waiting for activation");
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                match flash_client.get_activation_state().await {
                    Ok(state) => {
                        let s = state.state.to_lowercase().replace('_', "");
                        if s != "awaitingreset" {
                            info!(component = %comp, state = %state.state, "ECU activated");
                            break;
                        }
                    }
                    Err(_) => {
                        // ECU may be rebooting — retry
                        debug!(component = %comp, "activation poll failed, retrying");
                    }
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(OrchestratorError::Timeout {
                        component: comp.clone(),
                        operation: "activation".into(),
                    });
                }
            }
        }
        UpdateType::Policy => {
            // Policy-only: floor applied on start_flash, nothing more to do
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
