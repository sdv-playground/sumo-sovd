//! Campaign orchestrator — the offboard adapter over the shared `FlashEngine`.
//!
//! Resolves an L1 campaign manifest into a `FlashPlan` and delegates the
//! stage → reset → commit lifecycle to `sumo_sovd_flash_engine::FlashEngine`.
//! UDS session/security is the SOVD server's concern: writes carry a JWT
//! bearer (the engine's [`TokenSource`] seam) and the server unlocks itself
//! on a valid token — no client-side unlock choreography. The reset is a
//! campaign-level decision: stage all ECUs, then reset them together.

use std::sync::Arc;

use async_trait::async_trait;
use sumo_codec::commands::CommandValue;
use sumo_codec::labels::*;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::info;

use crate::error::OrchestratorError;

pub use sumo_sovd_flash_engine::{
    EcuState, EcuStatus, NoAuth, StaticToken, TokenSource, UpdateType,
};
use sumo_sovd_flash_engine::{
    EngineTimeouts, FlashEngine, FlashJob, FlashPlan, Payload, PayloadSource,
};

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    pub server_url: String,
    pub trust_anchor: Vec<u8>,
    /// If true, drive each ECU through `validate()` → `activate()` so the
    /// lifecycle visibly passes through `Validated` (reserved; the current
    /// /updates execute flow lands at AwaitingReboot directly).
    pub use_validated_flow: bool,
    /// Operator-supplied SOVD bearer JWT for the flash engine's calls — the
    /// simple, config-driven path: `Some(jwt)` → a fixed bearer, `None`/empty →
    /// unauthenticated (the device may not enforce auth yet). For a *minting*
    /// token source (resolve the device's `aud`/`boot_id` and mint per flash, like
    /// the rig's `RigToken::Mint`, or an onboard minter), inject it via
    /// [`CampaignOrchestrator::with_token_source`] instead.
    pub sovd_token: Option<String>,
    /// Skip TLS certificate verification on the device's SOVD endpoint (the
    /// `curl -k` equivalent), threaded into the flash engine. `false`
    /// (default) = full verification, byte-identical to before this knob.
    /// Set when the device leaf SAN won't match the dialled host.
    pub insecure: bool,
}

/// The config-driven default [`TokenSource`]: a fixed bearer when `sovd_token` is a
/// non-empty JWT, else unauthenticated. Callers needing per-device minting inject
/// their own source via [`CampaignOrchestrator::with_token_source`].
fn default_token_source(sovd_token: Option<&str>) -> Arc<dyn TokenSource> {
    match sovd_token {
        Some(jwt) if !jwt.is_empty() => Arc::new(StaticToken(jwt.to_string())),
        _ => Arc::new(NoAuth),
    }
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
    engine: FlashEngine,
}

impl CampaignOrchestrator {
    /// Construct with the **config-driven** token source — a fixed bearer from
    /// `config.sovd_token`, or unauthenticated. For per-device minting use
    /// [`Self::with_token_source`].
    pub fn new(config: CampaignConfig) -> Self {
        let token = default_token_source(config.sovd_token.as_deref());
        Self::with_token_source(config, token)
    }

    /// Construct with a caller-supplied [`TokenSource`] — the injection seam. The
    /// driver decides where the bearer comes from: a minting source that resolves
    /// the device's `aud`/`boot_id` and mints per flash (the workshop minter
    /// offboard, the onboard `jwt-mgr` in-vehicle), or a fixed/`NoAuth` for tests.
    /// The flash engine, and thus the device, sees only the resulting bearer — the
    /// campaign itself stays agnostic to how it was obtained.
    pub fn with_token_source(config: CampaignConfig, token: Arc<dyn TokenSource>) -> Self {
        let engine = FlashEngine::new(
            config.server_url.clone(),
            token,
            config.trust_anchor.clone(),
            EngineTimeouts::default(),
            config.insecure,
            None,
        );
        Self { config, engine }
    }

    /// Stage all ECU targets — flash each to AwaitingReboot via the engine.
    /// Does NOT reset. On flash failure the engine rolls back already-staged
    /// ECUs. The SOVD server handles UDS session/security itself on a valid
    /// bearer.
    pub async fn stage_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<StagePhaseResult, OrchestratorError> {
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

    /// Commit all activated firmware ECUs — the engine posts the verdict.
    /// (The post-reset UDS session/security re-establishment is the SOVD
    /// server's concern, not the campaign's.)
    pub async fn commit_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
        let mut owned = ecus.to_vec();
        self.engine.commit_all(&mut owned).await.map_err(Into::into)
    }

    /// Rollback all activated firmware ECUs.
    pub async fn rollback_all(&self, ecus: &[EcuStatus]) -> Result<(), OrchestratorError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The config-driven default maps `sovd_token` → a fixed bearer or
    /// unauthenticated — observed by what the source actually emits.
    #[tokio::test]
    async fn default_token_source_maps_config() {
        // A non-empty JWT → that exact bearer.
        let s = default_token_source(Some("jwt-abc"));
        assert_eq!(s.token("vm1").await.unwrap(), "jwt-abc");

        // None → unauthenticated (empty bearer; the engine sends no header).
        let s = default_token_source(None);
        assert_eq!(s.token("vm1").await.unwrap(), "");

        // An empty string is treated as no token, not a literal empty bearer.
        let s = default_token_source(Some(""));
        assert_eq!(s.token("vm1").await.unwrap(), "");
    }

    /// A minting-style source: proves the injection seam — any `TokenSource`,
    /// including one that mints a *different per-component* token, drops in as
    /// `Arc<dyn TokenSource>` exactly where `default_token_source` would.
    struct PerComponentMinter;

    #[async_trait]
    impl TokenSource for PerComponentMinter {
        async fn token(
            &self,
            component_id: &str,
        ) -> Result<String, sumo_sovd_flash_engine::EngineError> {
            Ok(format!("minted-for-{component_id}"))
        }
    }

    #[tokio::test]
    async fn a_custom_minting_source_injects() {
        // The seam accepts any TokenSource; the campaign is agnostic to how the
        // bearer is obtained (here, minted per component).
        let injected: Arc<dyn TokenSource> = Arc::new(PerComponentMinter);
        assert_eq!(injected.token("vm1").await.unwrap(), "minted-for-vm1");
        assert_eq!(injected.token("hsm").await.unwrap(), "minted-for-hsm");
    }
}
