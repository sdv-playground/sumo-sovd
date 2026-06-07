//! Campaign orchestrator — the offboard adapter over the shared `FlashEngine`.
//!
//! Resolves an L1 campaign manifest into a `FlashPlan`, owns UDS unlock (the
//! engine assumes already-unlocked), and delegates the stage → reset → commit
//! lifecycle to `sumo_sovd_flash_engine::FlashEngine`. The reset is a
//! campaign-level decision: stage all ECUs, then reset them together.

use std::sync::Arc;

use async_trait::async_trait;
use sovd_client::SovdClient;
use sumo_codec::commands::CommandValue;
use sumo_codec::labels::*;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::info;

use crate::error::OrchestratorError;
use crate::security_helper::{ComputeKeyRequest, SecurityHelperClient, SecurityHelperConfig};

pub use sumo_sovd_flash_engine::{EcuState, EcuStatus, UpdateType};
use sumo_sovd_flash_engine::{
    EngineTimeouts, FlashEngine, FlashJob, FlashPlan, NoAuth, Payload, PayloadSource,
};

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    pub server_url: String,
    pub trust_anchor: Vec<u8>,
    pub security_level: u8,
    pub security_helper: SecurityHelperConfig,
    /// If true, drive each ECU through `validate()` → `activate()` so the
    /// lifecycle visibly passes through `Validated` (reserved; the current
    /// /updates execute flow lands at AwaitingReboot directly).
    pub use_validated_flow: bool,
}

/// Target ECU for a campaign.
#[derive(Clone)]
pub struct EcuTarget {
    pub component_id: String,
    pub gateway_id: Option<String>,
    /// SUIT manifest bytes (small, no integrated payloads).
    pub manifest: Vec<u8>,
    /// Payload files in component order: [(URI, path), ...].
    pub payloads: Vec<(String, std::path::PathBuf)>,
}

/// Result of the stage phase (all ECUs flashed, awaiting reset).
pub struct StagePhaseResult {
    pub ecus: Vec<EcuStatus>,
}

/// Result of the full flash phase (stage + reset + activate).
pub struct FlashPhaseResult {
    pub ecus: Vec<EcuStatus>,
}

/// Campaign's file-path payloads become engine `PayloadSource::File` jobs.
fn target_to_job(t: EcuTarget) -> FlashJob {
    FlashJob {
        component_id: t.component_id,
        gateway_id: t.gateway_id,
        envelope: t.manifest,
        payloads: t
            .payloads
            .into_iter()
            .map(|(uri, path)| Payload {
                uri,
                source: PayloadSource::File(path),
            })
            .collect(),
    }
}

/// Orchestrates multi-ECU firmware campaigns over SOVD.
pub struct CampaignOrchestrator {
    config: CampaignConfig,
    helper: SecurityHelperClient,
    engine: FlashEngine,
}

impl CampaignOrchestrator {
    pub fn new(config: CampaignConfig) -> Self {
        let helper = SecurityHelperClient::new(config.security_helper.clone());
        // Campaign drives a device SOVD that doesn't enforce auth yet → NoAuth.
        let engine = FlashEngine::new(
            config.server_url.clone(),
            Arc::new(NoAuth),
            config.trust_anchor.clone(),
            EngineTimeouts::default(),
        );
        Self {
            config,
            helper,
            engine,
        }
    }

    /// Pooled security-helper client. Used internally for unlock and exposed so
    /// callers (e.g. sumo-deploy) can probe `/info` or perform extra unlocks.
    pub fn helper(&self) -> &SecurityHelperClient {
        &self.helper
    }

    /// Stage all ECU targets — unlock each (UDS), then flash to AwaitingReboot
    /// via the engine. Does NOT reset. On flash failure the engine rolls back
    /// already-staged ECUs.
    pub async fn stage_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<StagePhaseResult, OrchestratorError> {
        // The engine assumes already-unlocked — unlock every target up front.
        for t in &targets {
            self.unlock_for_flash(&t.component_id, t.gateway_id.as_deref())
                .await?;
        }
        let plan = FlashPlan {
            jobs: targets.into_iter().map(target_to_job).collect(),
        };
        let ecus = self.engine.stage_all(&plan).await?;
        Ok(StagePhaseResult { ecus })
    }

    /// Reset all staged ECUs and wait for activation (trial mode). Coalesces
    /// `RequiresEcuReset` components into one node reboot per parent ECU.
    pub async fn reset_all(&self, ecus: &mut [EcuStatus]) -> Result<(), OrchestratorError> {
        self.engine.reset_all(ecus).await.map_err(Into::into)
    }

    /// Flash all ECU targets — stage + reset + activate.
    pub async fn flash_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<FlashPhaseResult, OrchestratorError> {
        let mut ecus = self.stage_all(targets).await?.ecus;
        self.reset_all(&mut ecus).await?;
        Ok(FlashPhaseResult { ecus })
    }

    /// Commit all activated firmware ECUs. Re-unlocks each first (the ECU reset
    /// cleared the session per ISO 14229), then the engine posts the verdict.
    pub async fn commit_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
        for e in ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
        {
            self.unlock_for_flash(&e.component_id, e.gateway_id.as_deref())
                .await?;
        }
        let mut owned = ecus.to_vec();
        self.engine.commit_all(&mut owned).await.map_err(Into::into)
    }

    /// Rollback all activated firmware ECUs. Best-effort re-unlock per ECU.
    pub async fn rollback_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
        for e in ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
        {
            let _ = self
                .unlock_for_flash(&e.component_id, e.gateway_id.as_deref())
                .await;
        }
        let mut owned = ecus.to_vec();
        self.engine
            .rollback_all(&mut owned)
            .await
            .map_err(Into::into)
    }

    /// Deploy an L1 campaign manifest.
    ///
    /// Reads the install command sequence to determine which ECUs to update
    /// (process-dependency directives), resolves each L2 manifest into an
    /// [`EcuTarget`], then runs the full flash lifecycle.
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
            return Err(OrchestratorError::Manifest(
                "not a campaign manifest".into(),
            ));
        }

        let envelope = manifest.envelope();
        let install_seq = envelope
            .manifest
            .severable
            .install
            .as_ref()
            .ok_or_else(|| {
                OrchestratorError::Manifest("campaign has no install sequence".into())
            })?;

        // Extract component indices from the install sequence's
        // process-dependency directives.
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
            "campaign: install sequence declares {} ECUs",
            dep_indices.len()
        );

        // Resolve each dependency into an EcuTarget.
        let mut targets = Vec::new();
        for dep_idx in &dep_indices {
            let dep_uri = manifest.dependency_uri(*dep_idx).ok_or_else(|| {
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
                manifest: package, // L1 deploy: integrated envelope as manifest
                payloads: Vec::new(),
            });
        }

        self.flash_all(targets).await
    }

    /// Establish programming session + security unlock for an ECU.
    ///
    /// Called before staging and after each ECU reset (ISO 14229 resets session
    /// and security to default — needed before commit/rollback). The engine
    /// never touches session/security; that's the campaign's concern.
    async fn unlock_for_flash(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
    ) -> Result<(), OrchestratorError> {
        let client =
            SovdClient::new(&self.config.server_url).map_err(|e| OrchestratorError::Sovd {
                component: component_id.to_string(),
                message: format!("{e}"),
            })?;

        let (mode_component, mode_target) = if let Some(gw) = gateway_id {
            (gw, Some(component_id))
        } else {
            (component_id, None)
        };

        // Session → programming
        client
            .set_mode_targeted(
                mode_component,
                "session",
                serde_json::json!({"value": "programming"}),
                mode_target,
            )
            .await
            .map_err(|e| OrchestratorError::Sovd {
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
            let key_hex = self
                .helper()
                .compute_key(&ComputeKeyRequest::new(
                    seed_str,
                    self.config.security_level,
                    component_id,
                ))
                .await?;
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
