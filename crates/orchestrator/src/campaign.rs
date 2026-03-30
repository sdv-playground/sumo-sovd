/// Campaign orchestrator — sequence-driven multi-ECU updates via SOVD.
///
/// Reads the L1 campaign manifest's SUIT command sequences to determine
/// the execution flow. The manifest declares what to do; the orchestrator
/// executes it via SOVD REST calls.
///
/// Lifecycle:
/// 1. Install phase (L1 install sequence): flash all ECUs to staging
/// 2. All ECUs in trial — system health check (caller decides)
/// 3. Commit all or rollback all

use async_trait::async_trait;
use sumo_codec::commands::CommandValue;
use sumo_codec::labels::*;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use sovd_client::flash::FlashClient;
use sovd_client::SovdClient;
use tracing::{info, error, warn};

use crate::ecu::{self, EcuFlashConfig, UpdateType};
use crate::error::OrchestratorError;
use crate::security_helper::SecurityHelperConfig;

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    pub server_url: String,
    pub trust_anchor: Vec<u8>,
    pub security_level: u8,
    pub security_helper: SecurityHelperConfig,
}

/// State of individual ECUs within a campaign.
#[derive(Debug, Clone)]
pub struct EcuStatus {
    pub component_id: String,
    pub gateway_id: Option<String>,
    pub state: EcuState,
    pub update_type: UpdateType,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcuState {
    Pending,
    Flashing,
    Activated,  // Trial mode
    Committed,
    RolledBack,
    Failed,
}

/// Result of the flash phase.
pub struct FlashPhaseResult {
    pub ecus: Vec<EcuStatus>,
}

/// Target ECU for a campaign.
#[derive(Clone)]
pub struct EcuTarget {
    pub component_id: String,
    pub gateway_id: Option<String>,
    pub package: Vec<u8>,
}

/// Orchestrates multi-ECU firmware campaigns.
pub struct CampaignOrchestrator {
    config: CampaignConfig,
}

impl CampaignOrchestrator {
    pub fn new(config: CampaignConfig) -> Self {
        Self { config }
    }

    /// Flash all ECU targets — puts each in trial mode (not committed).
    ///
    /// Reads the update type from each manifest's SUIT command sequences:
    /// - has install+invoke → Firmware (full flash lifecycle, trial mode)
    /// - no install/invoke → Policy (immediate apply, no trial)
    ///
    /// On failure, automatically rolls back already-activated ECUs.
    pub async fn flash_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<FlashPhaseResult, OrchestratorError> {
        let total = targets.len();
        info!(ecus = total, "starting campaign — install phase");

        let mut statuses: Vec<EcuStatus> = targets
            .iter()
            .map(|t| EcuStatus {
                component_id: t.component_id.clone(),
                gateway_id: t.gateway_id.clone(),
                state: EcuState::Pending,
                update_type: UpdateType::Firmware,
                active_version: None,
                previous_version: None,
                error: None,
            })
            .collect();

        let mut activated: Vec<String> = Vec::new();

        // Install phase: flash each ECU
        for (i, target) in targets.iter().enumerate() {
            let comp = &target.component_id;
            info!(component = %comp, progress = format!("{}/{}", i + 1, total), "installing ECU");
            statuses[i].state = EcuState::Flashing;

            match ecu::flash_ecu_to_trial(
                EcuFlashConfig {
                    component_id: comp.clone(),
                    server_url: self.config.server_url.clone(),
                    gateway_id: target.gateway_id.clone(),
                    security_level: self.config.security_level,
                    package: target.package.clone(),
                    security_helper: self.config.security_helper.clone(),
                },
                &self.config.trust_anchor,
            )
            .await
            {
                Ok(result) => {
                    statuses[i].update_type = result.update_type;
                    statuses[i].state = match result.update_type {
                        UpdateType::Firmware => EcuState::Activated,
                        UpdateType::Policy => EcuState::Committed,
                    };
                    statuses[i].active_version = result.active_version;
                    statuses[i].previous_version = result.previous_version;
                    if result.update_type == UpdateType::Firmware {
                        activated.push(comp.clone());
                    }
                    info!(component = %comp, update_type = ?result.update_type, "ECU installed");
                }
                Err(e) => {
                    statuses[i].state = EcuState::Failed;
                    statuses[i].error = Some(format!("{e}"));
                    error!(component = %comp, error = %e, "ECU install failed");

                    // Rollback already-activated ECUs
                    if !activated.is_empty() {
                        warn!(count = activated.len(), "rolling back activated ECUs");
                        for rc in &activated {
                            let gw = statuses.iter()
                                .find(|s| &s.component_id == rc)
                                .and_then(|s| s.gateway_id.as_deref());
                            match self.rollback_one(rc, gw).await {
                                Ok(()) => {
                                    if let Some(s) = statuses.iter_mut().find(|s| &s.component_id == rc) {
                                        s.state = EcuState::RolledBack;
                                    }
                                }
                                Err(re) => warn!(component = %rc, error = %re, "rollback failed"),
                            }
                        }
                    }

                    return Err(OrchestratorError::FlashFailed {
                        component: comp.clone(),
                        message: format!("{e}"),
                    });
                }
            }
        }

        let fw_count = activated.len();
        let policy_count = statuses.iter().filter(|e| e.update_type == UpdateType::Policy).count();
        info!(firmware = fw_count, policy = policy_count, "install phase complete — awaiting commit decision");

        Ok(FlashPhaseResult { ecus: statuses })
    }

    /// Commit all firmware ECUs — makes trial firmware permanent.
    pub async fn commit_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
        let to_commit: Vec<&EcuStatus> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
            .collect();

        info!(ecus = to_commit.len(), "committing campaign");

        for ecu in &to_commit {
            info!(component = %ecu.component_id, "committing");
            self.commit_one(&ecu.component_id, ecu.gateway_id.as_deref()).await?;
        }

        info!("campaign committed");
        Ok(())
    }

    /// Rollback all firmware ECUs — reverts to previous firmware.
    pub async fn rollback_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
        let to_rollback: Vec<&EcuStatus> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
            .collect();

        warn!(ecus = to_rollback.len(), "rolling back campaign");

        for ecu in &to_rollback {
            warn!(component = %ecu.component_id, "rolling back");
            match self.rollback_one(&ecu.component_id, ecu.gateway_id.as_deref()).await {
                Ok(()) => info!(component = %ecu.component_id, "rolled back"),
                Err(e) => error!(component = %ecu.component_id, error = %e, "rollback failed"),
            }
        }

        Ok(())
    }

    /// Deploy an L1 campaign manifest.
    ///
    /// Reads the manifest's command sequences to determine which ECUs to update:
    /// - dependency_resolution → resolve L2 manifests
    /// - install (process-dependency) → flash each ECU
    /// - validate → verify (done during install)
    /// - invoke → deferred (commit_all triggers activation)
    pub async fn deploy_campaign(
        &self,
        campaign_envelope: &[u8],
        resolver: &dyn FirmwareResolver,
    ) -> Result<FlashPhaseResult, OrchestratorError> {
        let crypto = RustCryptoBackend::new();
        let validator = Validator::new(&self.config.trust_anchor, None);

        let manifest = validator
            .validate_envelope(campaign_envelope, &crypto, 0)
            .map_err(|e| OrchestratorError::Manifest(format!("{e:?}")))?;

        if !manifest.is_campaign() {
            return Err(OrchestratorError::Manifest("not a campaign manifest".into()));
        }

        // Read install sequence to determine ECU ordering
        let envelope = manifest.envelope();
        let install_seq = envelope.manifest.severable.install.as_ref()
            .ok_or_else(|| OrchestratorError::Manifest("campaign has no install sequence".into()))?;

        // Extract component indices from install sequence's process-dependency directives
        let mut dep_indices: Vec<usize> = Vec::new();
        let mut current_idx = 0usize;
        for item in &install_seq.items {
            match (item.label, &item.value) {
                (SUIT_DIRECTIVE_SET_COMPONENT_INDEX, CommandValue::ComponentIndex(idx)) => {
                    current_idx = *idx;
                }
                (SUIT_DIRECTIVE_PROCESS_DEPENDENCY, _) => {
                    dep_indices.push(current_idx);
                }
                _ => {}
            }
        }

        info!(
            dependencies = dep_indices.len(),
            has_validate = envelope.manifest.validate.is_some(),
            has_invoke = envelope.manifest.invoke.is_some(),
            "campaign: install sequence declares {} ECUs", dep_indices.len()
        );

        // Resolve each dependency into an EcuTarget
        let mut targets = Vec::new();
        for dep_idx in &dep_indices {
            let dep_uri = manifest.dependency_uri(*dep_idx).ok_or_else(|| {
                OrchestratorError::Manifest(format!("no URI for dependency {dep_idx}"))
            })?;

            let l2_envelope = if dep_uri.starts_with('#') {
                manifest.integrated_payload(dep_uri)
                    .ok_or_else(|| OrchestratorError::Manifest(format!("payload not found: {dep_uri}")))?
                    .to_vec()
            } else {
                resolver.fetch_manifest(dep_uri).await?
            };

            let l2_manifest = validator
                .validate_envelope(&l2_envelope, &crypto, 0)
                .map_err(|e| OrchestratorError::Manifest(format!("L2 dep {dep_idx}: {e:?}")))?;

            let component_id = l2_manifest
                .component_id(0)
                .and_then(|segs| segs.last())
                .and_then(|s| std::str::from_utf8(s).ok())
                .ok_or_else(|| OrchestratorError::Manifest(format!("L2 dep {dep_idx}: no component ID")))?
                .to_string();

            let package = resolver
                .resolve_package(&component_id, &l2_envelope, &l2_manifest)
                .await?;

            targets.push(EcuTarget {
                component_id,
                gateway_id: None,
                package,
            });
        }

        // Execute: install all ECUs (flash_all handles per-ECU lifecycle)
        // The L1 validate + invoke sequences are handled implicitly:
        // - validate: each ECU validates during its flash process
        // - invoke: deferred to commit_all (ECU reset + activation)
        self.flash_all(targets).await
    }

    fn make_flash_client(&self, component_id: &str, gateway_id: Option<&str>) -> Result<FlashClient, OrchestratorError> {
        let client = if let Some(gw) = gateway_id {
            FlashClient::for_sovd_sub_entity(&self.config.server_url, gw, component_id)
        } else {
            FlashClient::for_sovd(&self.config.server_url, component_id)
        };
        client.map_err(|e| OrchestratorError::Sovd {
            component: component_id.to_string(),
            message: format!("{e}"),
        })
    }

    /// Re-establish programming session + security unlock for an ECU.
    /// Needed after ECU reset (ISO 14229 resets session to default).
    async fn ensure_access(&self, component_id: &str, gateway_id: Option<&str>) -> Result<(), OrchestratorError> {
        let client = SovdClient::new(&self.config.server_url)
            .map_err(|e| OrchestratorError::Sovd {
                component: component_id.to_string(),
                message: format!("{e}"),
            })?;

        let (mode_component, mode_target) = if let Some(gw) = gateway_id {
            (gw, Some(component_id))
        } else {
            (component_id, None)
        };

        // Session → programming
        client.set_mode_targeted(
            mode_component, "session",
            serde_json::json!({"value": "programming"}),
            mode_target,
        ).await.map_err(|e| OrchestratorError::Sovd {
            component: component_id.to_string(),
            message: format!("set_session: {e}"),
        })?;

        // Security unlock
        let seed_resp = client.set_mode_targeted(
            mode_component, "security",
            serde_json::json!({"value": format!("level{}_requestseed", self.config.security_level)}),
            mode_target,
        ).await.map_err(|e| OrchestratorError::SecurityFailed {
            component: component_id.to_string(),
            message: format!("seed: {e}"),
        })?;

        if let Some(seed_val) = seed_resp.seed.as_ref() {
            let seed_str = seed_val
                .get("Request_Seed")
                .and_then(|s| s.as_str())
                .or_else(|| seed_val.as_str())
                .unwrap_or("");
            let key_hex = crate::security_helper::compute_key(
                &self.config.security_helper, seed_str, self.config.security_level, component_id,
            ).await?;
            client.set_mode_targeted(
                mode_component, "security",
                serde_json::json!({"value": format!("level{}", self.config.security_level), "key": key_hex}),
                mode_target,
            ).await.map_err(|e| OrchestratorError::SecurityFailed {
                component: component_id.to_string(),
                message: format!("key: {e}"),
            })?;
        }

        Ok(())
    }

    async fn commit_one(&self, component_id: &str, gateway_id: Option<&str>) -> Result<(), OrchestratorError> {
        // Re-establish access (ECU reset clears session per ISO 14229)
        self.ensure_access(component_id, gateway_id).await?;
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        flash_client.commit_flash().await.map(|_| ()).map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("commit: {e}"),
        })
    }

    async fn rollback_one(&self, component_id: &str, gateway_id: Option<&str>) -> Result<(), OrchestratorError> {
        self.ensure_access(component_id, gateway_id).await?;
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        flash_client.rollback_flash().await.map(|_| ()).map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("rollback: {e}"),
        })
    }
}

/// Resolves firmware packages for the orchestrator.
#[async_trait]
pub trait FirmwareResolver: Send + Sync {
    async fn fetch_manifest(&self, uri: &str) -> Result<Vec<u8>, OrchestratorError>;
    async fn resolve_package(
        &self,
        component_id: &str,
        l2_envelope: &[u8],
        l2_manifest: &sumo_onboard::Manifest,
    ) -> Result<Vec<u8>, OrchestratorError>;
}
