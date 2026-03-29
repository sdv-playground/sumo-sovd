/// Campaign orchestrator — processes L1 campaign manifests and
/// coordinates multi-ECU firmware updates via SOVD.
///
/// Campaign lifecycle:
/// 1. Flash all ECUs → all enter trial mode (activated, not committed)
/// 2. System health check (caller decides — soak period, integration test, etc.)
/// 3. Commit all or rollback all (atomic at campaign level)

use async_trait::async_trait;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{info, error, warn};

use crate::ecu::{self, EcuFlashConfig, EcuFlashResult, UpdateType};
use crate::error::OrchestratorError;

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    pub server_url: String,
    pub trust_anchor: Vec<u8>,
    pub security_level: u8,
}

/// State of a campaign deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignState {
    /// Campaign created, not started
    Pending,
    /// Flashing ECUs (some may be done, some in progress)
    Flashing { completed: usize, total: usize },
    /// All ECUs in trial — waiting for health check / commit decision
    AwaitingCommit,
    /// All ECUs committed — campaign complete
    Committed,
    /// All ECUs rolled back — campaign aborted
    RolledBack,
    /// Campaign failed — partial state, manual intervention needed
    Failed { message: String },
}

/// Status of a single ECU within a campaign.
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
    Activated,  // Trial mode — not yet committed
    Committed,
    RolledBack,
    Failed,
}

/// Result of the flash phase (all ECUs in trial).
pub struct FlashPhaseResult {
    pub ecus: Vec<EcuStatus>,
}

/// Orchestrates a multi-ECU firmware campaign.
pub struct CampaignOrchestrator {
    config: CampaignConfig,
}

impl CampaignOrchestrator {
    pub fn new(config: CampaignConfig) -> Self {
        Self { config }
    }

    /// Phase 1: Flash all ECUs — puts each in trial mode (activated, not committed).
    ///
    /// Returns the list of ECU statuses. All ECUs should be in Activated state.
    /// If any ECU fails, the already-activated ones are rolled back automatically.
    pub async fn flash_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<FlashPhaseResult, OrchestratorError> {
        let total = targets.len();
        info!(ecus = total, "starting campaign flash phase");

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

        for (i, target) in targets.iter().enumerate() {
            let comp = &target.component_id;
            info!(component = %comp, progress = format!("{}/{}", i + 1, total), "flashing ECU");
            statuses[i].state = EcuState::Flashing;

            match ecu::flash_ecu_to_trial(
                EcuFlashConfig {
                    component_id: comp.clone(),
                    server_url: self.config.server_url.clone(),
                    gateway_id: target.gateway_id.clone(),
                    security_level: self.config.security_level,
                    package: target.package.clone(),
                },
                &self.config.trust_anchor,
            )
            .await
            {
                Ok(result) => {
                    statuses[i].update_type = result.update_type;
                    statuses[i].state = match result.update_type {
                        UpdateType::Firmware => EcuState::Activated, // trial
                        UpdateType::Policy => EcuState::Committed,   // immediate
                    };
                    statuses[i].active_version = result.active_version;
                    statuses[i].previous_version = result.previous_version;
                    if result.update_type == UpdateType::Firmware {
                        activated.push(comp.clone());
                    }
                    info!(component = %comp, update_type = ?result.update_type, "ECU update complete");
                }
                Err(e) => {
                    statuses[i].state = EcuState::Failed;
                    statuses[i].error = Some(format!("{e}"));
                    error!(component = %comp, error = %e, "ECU flash failed");

                    // Rollback all already-activated ECUs
                    if !activated.is_empty() {
                        warn!(count = activated.len(), "rolling back activated ECUs due to failure");
                        for rollback_comp in &activated {
                            let rollback_gw = statuses.iter().find(|s| &s.component_id == rollback_comp).and_then(|s| s.gateway_id.as_deref());
                        match self.rollback_one(rollback_comp, rollback_gw).await {
                                Ok(()) => {
                                    if let Some(s) = statuses.iter_mut().find(|s| &s.component_id == rollback_comp) {
                                        s.state = EcuState::RolledBack;
                                    }
                                    info!(component = %rollback_comp, "rolled back");
                                }
                                Err(re) => {
                                    warn!(component = %rollback_comp, error = %re, "rollback failed");
                                }
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

        info!(ecus = activated.len(), "all ECUs activated — awaiting commit decision");
        Ok(FlashPhaseResult { ecus: statuses })
    }

    /// Phase 2: Commit all ECUs — makes the trial firmware permanent.
    ///
    /// Call this after health checks pass during the soak period.
    pub async fn commit_all(
        &self,
        ecus: &[EcuStatus],
    ) -> Result<(), OrchestratorError> {
        let to_commit: Vec<&EcuStatus> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
            .collect();

        let policy_count = ecus.iter().filter(|e| e.update_type == UpdateType::Policy).count();

        info!(firmware = to_commit.len(), policy = policy_count, "committing campaign");

        for ecu in &to_commit {
            info!(component = %ecu.component_id, "committing");
            self.commit_one(&ecu.component_id, ecu.gateway_id.as_deref()).await?;
        }

        info!("campaign committed");
        Ok(())
    }

    /// Phase 2 (alternative): Rollback all ECUs — reverts to previous firmware.
    ///
    /// Call this if health checks fail during the soak period.
    pub async fn rollback_all(
        &self,
        ecus: &[EcuStatus],
    ) -> Result<(), OrchestratorError> {
        let activated: Vec<&EcuStatus> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated)
            .collect();

        warn!(ecus = activated.len(), "rolling back all ECUs");

        for ecu in &activated {
            warn!(component = %ecu.component_id, "rolling back");
            match self.rollback_one(&ecu.component_id, ecu.gateway_id.as_deref()).await {
                Ok(()) => info!(component = %ecu.component_id, "rolled back"),
                Err(e) => error!(component = %ecu.component_id, error = %e, "rollback failed"),
            }
        }

        Ok(())
    }

    /// Deploy an L1 campaign manifest — flash all dependencies.
    ///
    /// Returns FlashPhaseResult with all ECUs in trial. Caller must then
    /// call commit_all() or rollback_all() after health checks.
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

        let dep_count = manifest.dependency_count();
        info!(dependencies = dep_count, "processing campaign manifest");

        let mut targets = Vec::new();

        for dep_idx in 0..dep_count {
            let dep_uri = manifest.dependency_uri(dep_idx).ok_or_else(|| {
                OrchestratorError::Manifest(format!("no URI for dependency {dep_idx}"))
            })?;

            let l2_envelope = if dep_uri.starts_with('#') {
                manifest
                    .integrated_payload(dep_uri)
                    .ok_or_else(|| {
                        OrchestratorError::Manifest(format!("payload not found: {dep_uri}"))
                    })?
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
                .ok_or_else(|| {
                    OrchestratorError::Manifest(format!("L2 dep {dep_idx}: no component ID"))
                })?
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

    async fn commit_one(&self, component_id: &str, gateway_id: Option<&str>) -> Result<(), OrchestratorError> {
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        flash_client.commit_flash().await.map(|_| ()).map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("commit: {e}"),
        })
    }

    async fn rollback_one(&self, component_id: &str, gateway_id: Option<&str>) -> Result<(), OrchestratorError> {
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        flash_client.rollback_flash().await.map(|_| ()).map_err(|e| OrchestratorError::FlashFailed {
            component: component_id.to_string(),
            message: format!("rollback: {e}"),
        })
    }
}

use sovd_client::flash::FlashClient;

/// Target ECU for a campaign deployment.
pub struct EcuTarget {
    pub component_id: String,
    pub gateway_id: Option<String>,
    pub package: Vec<u8>,
}

/// Resolves firmware packages for the orchestrator.
#[async_trait]
pub trait FirmwareResolver: Send + Sync {
    /// Fetch an L2 manifest by URI.
    async fn fetch_manifest(&self, uri: &str) -> Result<Vec<u8>, OrchestratorError>;

    /// Resolve a complete package (manifest + firmware) for an ECU.
    async fn resolve_package(
        &self,
        component_id: &str,
        l2_envelope: &[u8],
        l2_manifest: &sumo_onboard::Manifest,
    ) -> Result<Vec<u8>, OrchestratorError>;
}
