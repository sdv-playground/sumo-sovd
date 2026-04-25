//! Per-ECU update — inspects SUIT manifest command sequences to determine
//! the update flow: firmware flash (full lifecycle) vs policy-only (immediate).
//!
//! Firmware: session → security → upload → flash → finalize → AwaitingReboot
//!           (reset is a campaign-level decision, not per-ECU)
//! Policy:   session → security → upload → apply (immediate, no trial)

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
    // 5. Upload manifest (processed synchronously — no poll needed)
    flash_client.upload_file(&config.manifest).await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("manifest upload: {e}"),
        })?;

    // 6. Upload each payload in component order (each streamed to bank synchronously)
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

/// Reset one ECU and wait for it to reach trial (Activated) state, then
/// (best-effort) wait for the guest VM to actually come up before returning.
///
/// The "Activated" flash state only confirms the bank pointer flipped — for
/// VM-style components there's still a several-second gap before the new
/// guest is actually running. If we hand off to commit/rollback during that
/// gap we have no way to tell whether the new firmware is healthy. Polling
/// the `guest_state` DID until it reaches "running" closes that window for
/// VM components; for non-VM components (HSM, hypervisor host) the DID is
/// absent and we fall through after a single attempt.
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

    // Wait for activation — poll until not awaiting_reboot
    info!(component = %component_id, "waiting for activation");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match flash_client.get_activation_state().await {
            Ok(state) => {
                let s = state.state.to_lowercase().replace('_', "");
                if s != "awaitingreset" && s != "awaitingreboot" {
                    info!(component = %component_id, state = %state.state, "flash state activated");
                    break;
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

    // Best-effort guest-up check. Reads `guest_state` DID; if the component
    // doesn't expose one (HSM, hypervisor host) we skip after a couple of
    // failed reads. If it's exposed, wait for "running" before returning so
    // the caller doesn't commit/rollback on a still-booting VM.
    wait_for_guest_running(server_url, component_id, gateway_id, deadline).await?;

    info!(component = %component_id, "ECU activated and guest running");
    Ok(())
}

/// Poll the `guest_state` DID until it reads "running", giving up if the
/// DID isn't exposed (e.g. for HSM / hypervisor host).
async fn wait_for_guest_running(
    server_url: &str,
    component_id: &str,
    gateway_id: Option<&str>,
    deadline: tokio::time::Instant,
) -> Result<(), OrchestratorError> {
    let url = match gateway_id {
        Some(gw) => format!(
            "{server_url}/vehicle/v1/components/{gw}/apps/{component_id}/data/guest_state"
        ),
        None => format!("{server_url}/vehicle/v1/components/{component_id}/data/guest_state"),
    };

    let http = reqwest::Client::new();
    let mut not_found_count = 0u32;

    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(OrchestratorError::Timeout {
                component: component_id.to_string(),
                operation: "guest_state=running".into(),
            });
        }

        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = match resp.json().await {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                };
                // sovd-api wraps DID values as { "value": ..., ... };
                // value can be a string or a JSON object — check both.
                let v = body.get("value").unwrap_or(&body);
                let s = v.as_str().unwrap_or("").to_lowercase();
                debug!(component = %component_id, guest_state = %s, "polling guest_state");
                if s == "running" {
                    return Ok(());
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                // Component doesn't expose guest_state — skip after a
                // small number of confirmations to avoid skipping early
                // during ECU reset window.
                not_found_count += 1;
                if not_found_count >= 3 {
                    debug!(
                        component = %component_id,
                        "no guest_state DID — skipping guest-up check"
                    );
                    return Ok(());
                }
            }
            Ok(_) | Err(_) => {
                // ECU still rebooting / proxy not ready — retry
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
