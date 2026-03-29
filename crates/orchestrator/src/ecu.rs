/// Per-ECU flash — drives one ECU through SOVD flash lifecycle
/// up to trial mode (activated, NOT committed).
///
/// Commit/rollback is the campaign's responsibility, not per-ECU.

use sovd_client::flash::FlashClient;
use sovd_client::SessionType;
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
///
/// Does NOT commit. The caller (campaign orchestrator) decides when to commit
/// after all ECUs are in trial and system health is verified.
pub async fn flash_ecu_to_trial(config: EcuFlashConfig) -> Result<EcuFlashResult, OrchestratorError> {
    let comp = &config.component_id;
    info!(component = %comp, "starting ECU flash (to trial)");

    let client = SovdClient::new(&config.server_url)
        .map_err(|e| OrchestratorError::Sovd {
            component: comp.clone(),
            message: format!("connect: {e}"),
        })?;

    // 1. Switch to programming session
    info!(component = %comp, "switching to programming session");
    client.set_session(comp, SessionType::Programming)
        .await
        .map_err(|e| OrchestratorError::Sovd {
            component: comp.clone(),
            message: format!("set_session: {e}"),
        })?;

    // 2. Security unlock
    // TODO: integrate with security helper for key computation
    info!(component = %comp, level = config.security_level, "security unlock");

    // 3. Create flash client
    let flash_client = if let Some(ref gw) = config.gateway_id {
        FlashClient::for_sovd_sub_entity(&config.server_url, gw, comp)
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

    // 11. Wait for activation (poll until not awaiting_reset)
    // TODO: poll activation state with timeout
    info!(component = %comp, "waiting for activation");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // ECU is now in trial mode — NOT committed
    info!(component = %comp, "ECU in trial mode (activated, not committed)");

    Ok(EcuFlashResult {
        component_id: comp.clone(),
        active_version: None, // TODO: read from activation state
        previous_version: None,
    })
}
