/// Campaign orchestrator — processes L1 campaign manifests and
/// coordinates per-ECU updates via SOVD.

use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{info, error};

use crate::ecu::{self, EcuFlashConfig, EcuFlashResult};
use crate::error::OrchestratorError;

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    /// SOVD server base URL
    pub server_url: String,
    /// Trust anchor for manifest validation (COSE_Key public key, CBOR)
    pub trust_anchor: Vec<u8>,
    /// Security level to use for ECU unlock
    pub security_level: u8,
}

/// Orchestrates a multi-ECU firmware campaign.
pub struct CampaignOrchestrator {
    config: CampaignConfig,
}

impl CampaignOrchestrator {
    pub fn new(config: CampaignConfig) -> Self {
        Self { config }
    }

    /// Deploy a single L2 image manifest to one ECU.
    ///
    /// The package should be a complete SUIT envelope (integrated payload).
    pub async fn deploy_single(
        &self,
        component_id: &str,
        package: Vec<u8>,
    ) -> Result<EcuFlashResult, OrchestratorError> {
        // Validate the manifest first
        let crypto = RustCryptoBackend::new();
        let validator = Validator::new(&self.config.trust_anchor, None);
        let _manifest = validator
            .validate_envelope(&package, &crypto, 0)
            .map_err(|e| OrchestratorError::Manifest(format!("{e:?}")))?;

        info!(component = %component_id, "deploying single image");

        ecu::flash_ecu(EcuFlashConfig {
            component_id: component_id.to_string(),
            server_url: self.config.server_url.clone(),
            gateway_id: None,
            security_level: self.config.security_level,
            package,
        })
        .await
    }

    /// Deploy an L1 campaign manifest with multiple L2 dependencies.
    ///
    /// Processes dependencies in order, rolling back all on failure.
    pub async fn deploy_campaign(
        &self,
        campaign_envelope: &[u8],
        firmware_resolver: &dyn FirmwareResolver,
    ) -> Result<Vec<EcuFlashResult>, OrchestratorError> {
        let crypto = RustCryptoBackend::new();
        let validator = Validator::new(&self.config.trust_anchor, None);

        let manifest = validator
            .validate_envelope(campaign_envelope, &crypto, 0)
            .map_err(|e| OrchestratorError::Manifest(format!("{e:?}")))?;

        if !manifest.is_campaign() {
            return Err(OrchestratorError::Manifest(
                "not a campaign manifest (no dependencies)".into(),
            ));
        }

        let dep_count = manifest.dependency_count();
        info!(dependencies = dep_count, "processing campaign");

        let mut results = Vec::new();
        let mut committed = Vec::new();

        for dep_idx in 0..dep_count {
            // Get L2 manifest for this dependency
            let dep_uri = manifest.dependency_uri(dep_idx).ok_or_else(|| {
                OrchestratorError::Manifest(format!("no URI for dependency {dep_idx}"))
            })?;

            let l2_envelope = if dep_uri.starts_with('#') {
                // Integrated L2 manifest
                manifest
                    .integrated_payload(dep_uri)
                    .ok_or_else(|| {
                        OrchestratorError::Manifest(format!("integrated payload not found: {dep_uri}"))
                    })?
                    .to_vec()
            } else {
                // Fetch L2 manifest from resolver
                firmware_resolver.fetch_manifest(dep_uri).await?
            };

            // Validate L2 manifest and extract component info
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

            // Resolve firmware payload (may need to combine with L2 manifest)
            let package = firmware_resolver
                .resolve_package(&component_id, &l2_envelope, &l2_manifest)
                .await?;

            info!(component = %component_id, dep = dep_idx, "flashing ECU");

            match ecu::flash_ecu(EcuFlashConfig {
                component_id: component_id.clone(),
                server_url: self.config.server_url.clone(),
                gateway_id: None,
                security_level: self.config.security_level,
                package,
            })
            .await
            {
                Ok(result) => {
                    committed.push(component_id.clone());
                    results.push(result);
                }
                Err(e) => {
                    error!(component = %component_id, error = %e, "ECU flash failed, initiating rollback");
                    // TODO: rollback committed ECUs
                    return Err(e);
                }
            }
        }

        info!(ecus = committed.len(), "campaign complete");
        Ok(results)
    }
}

/// Resolves firmware packages for the orchestrator.
///
/// Implementations can fetch from CDN, local cache, content-addressable store, etc.
use async_trait::async_trait;

#[async_trait]
pub trait FirmwareResolver: Send + Sync {
    /// Fetch an L2 manifest by URI.
    async fn fetch_manifest(&self, uri: &str) -> Result<Vec<u8>, OrchestratorError>;

    /// Resolve a complete package (manifest + firmware) for an ECU.
    /// May combine a reference manifest with firmware from a content-addressable store.
    async fn resolve_package(
        &self,
        component_id: &str,
        l2_envelope: &[u8],
        l2_manifest: &sumo_onboard::Manifest,
    ) -> Result<Vec<u8>, OrchestratorError>;
}
