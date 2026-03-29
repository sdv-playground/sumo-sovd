/// Per-ECU flash — drives one ECU through SOVD flash lifecycle
/// up to trial mode (activated, NOT committed).
///
/// Handles both direct components and gateway sub-entities.
/// Commit/rollback is the campaign's responsibility.

use sovd_client::flash::FlashClient;
use sovd_client::SovdClient;
use tracing::info;

use crate::error::OrchestratorError;

/// Configuration for a single ECU flash operation.
pub struct EcuFlashConfig {
    pub component_id: String,
    pub server_url: String,
    pub gateway_id: Option<String>,
    pub security_level: u8,
    pub package: Vec<u8>,
}

/// Result of flashing one ECU (in trial mode, not committed).
pub struct EcuFlashResult {
    pub component_id: String,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
}

/// Flash one ECU to trial mode: session → security → upload → flash → reset → activated.
pub async fn flash_ecu_to_trial(config: EcuFlashConfig) -> Result<EcuFlashResult, OrchestratorError> {
    let comp = &config.component_id;
    let gw = config.gateway_id.as_deref();
    info!(component = %comp, gateway = ?gw, "starting ECU flash (to trial)");

    let client = SovdClient::new(&config.server_url)
        .map_err(|e| OrchestratorError::Sovd {
            component: comp.clone(),
            message: format!("connect: {e}"),
        })?;

    // For sub-entities, the mode target is "component_id" routed through the gateway.
    // For direct components, target is None.
    let (mode_component, mode_target) = if let Some(gw_id) = gw {
        (gw_id, Some(comp.as_str()))
    } else {
        (comp.as_str(), None)
    };

    // 1. Switch to programming session
    info!(component = %comp, "switching to programming session");
    client.set_mode_targeted(
        mode_component,
        "session",
        serde_json::json!({"value": "programming"}),
        mode_target,
    )
    .await
    .map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("set_session: {e}"),
    })?;

    // 2. Security unlock — request seed
    info!(component = %comp, level = config.security_level, "requesting security seed");
    let seed_resp = client.set_mode_targeted(
        mode_component,
        "security",
        serde_json::json!({"value": format!("level{}_requestseed", config.security_level)}),
        mode_target,
    )
    .await
    .map_err(|e| OrchestratorError::SecurityFailed {
        component: comp.clone(),
        message: format!("request seed: {e}"),
    })?;

    // Extract seed and compute key
    // TODO: use security helper instead of hardcoded XOR
    if let Some(seed_val) = seed_resp.seed.as_ref() {
        let seed_str = seed_val
            .get("Request_Seed")
            .and_then(|s| s.as_str())
            .or_else(|| seed_val.as_str())
            .unwrap_or("");
        let seed_bytes: Vec<u8> = seed_str
            .split_whitespace()
            .filter_map(|s: &str| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .collect();
        let key_hex: String = seed_bytes.iter().map(|b| format!("{:02x}", b ^ 0xFF)).collect();

        info!(component = %comp, "sending security key");
        client.set_mode_targeted(
            mode_component,
            "security",
            serde_json::json!({"value": format!("level{}", config.security_level), "key": key_hex}),
            mode_target,
        )
        .await
        .map_err(|e| OrchestratorError::SecurityFailed {
            component: comp.clone(),
            message: format!("send key: {e}"),
        })?;
    }

    // 3. Create flash client
    let flash_client = if let Some(gw_id) = gw {
        FlashClient::for_sovd_sub_entity(&config.server_url, gw_id, comp)
    } else {
        FlashClient::for_sovd(&config.server_url, comp)
    }
    .map_err(|e| OrchestratorError::Sovd {
        component: comp.clone(),
        message: format!("flash client: {e}"),
    })?;

    // 4. Upload
    info!(component = %comp, size = config.package.len(), "uploading package");
    let upload = flash_client.upload_file(&config.package)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("upload: {e}"),
        })?;
    let file_id = upload.upload_id;

    // 5. Poll upload complete
    let status = flash_client.poll_upload_complete(&file_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("upload poll: {e}"),
        })?;
    let file_id = status.file_id.unwrap_or(file_id);

    // 6. Verify
    info!(component = %comp, "verifying package");
    flash_client.verify_file(&file_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("verify: {e}"),
        })?;

    // 7. Start flash
    info!(component = %comp, "starting flash transfer");
    let transfer = flash_client.start_flash(&file_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("start flash: {e}"),
        })?;

    // 8. Poll flash progress
    flash_client.poll_flash_complete_simple(&transfer.transfer_id)
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("flash progress: {e}"),
        })?;

    // 9. Finalize
    info!(component = %comp, "finalizing transfer");
    flash_client.transfer_exit()
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("finalize: {e}"),
        })?;

    // 10. Reset ECU
    info!(component = %comp, "resetting ECU");
    flash_client.ecu_reset()
        .await
        .map_err(|e| OrchestratorError::FlashFailed {
            component: comp.clone(),
            message: format!("reset: {e}"),
        })?;

    // 11. Wait for activation
    info!(component = %comp, "waiting for activation");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // TODO: poll activation state with timeout

    info!(component = %comp, "ECU in trial mode (activated, not committed)");

    Ok(EcuFlashResult {
        component_id: comp.clone(),
        active_version: None,
        previous_version: None,
    })
}
