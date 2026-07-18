//! Builders for [`EcuTarget`] lists.
//!
//! Two ways to express what a campaign should flash:
//!
//! - **L1 envelope**: a signed SUIT campaign manifest with per-ECU
//!   dependencies as integrated payloads. Use [`parse_l1_campaign`] —
//!   walks the dependency URIs, validates each L2, builds one
//!   [`EcuTarget`] per dependency.
//!
//! - **Multiflash spec**: a small JSON file naming per-ECU manifests +
//!   payload files on disk. Use [`MultiflashSpec`] — convenient when
//!   you've built artefacts separately and want to flash a coordinated
//!   set without an L1 envelope. Used by `sumo-campaign multiflash`.

use serde::Deserialize;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Manifest;
use sumo_onboard::Validator;

use crate::campaign::EcuTarget;
use crate::error::OrchestratorError;

// ---------------------------------------------------------------------------
// L1 envelope → Vec<EcuTarget>
// ---------------------------------------------------------------------------

/// Parse a signed L1 campaign envelope into per-ECU targets.
///
/// Validates the L1 against `trust_anchor`, then walks each dependency:
/// validates the L2 envelope, identifies the target component (first
/// segment of the SUIT component-id, e.g. `["vm1", "kernel"]` → `vm1`),
/// and routes the package:
///
/// - SOVD ECUs (in `sovd_ecus`) receive the **full L2 envelope** — the
///   ECU's vm-mgr does its own SUIT validation + decryption.
/// - Other ECUs receive the **raw firmware** extracted from the L2's
///   `#firmware` integrated payload.
///
/// `gateway_id` is stamped onto every produced target (campaign-level,
/// not per-ECU today).
pub fn parse_l1_campaign(
    envelope: &[u8],
    trust_anchor: &[u8],
    gateway_id: Option<String>,
    sovd_ecus: &[String],
) -> Result<Vec<EcuTarget>, OrchestratorError> {
    parse_l1_campaign_with_payloads(envelope, trust_anchor, gateway_id, sovd_ecus, &[])
}

/// Parse a signed L1 campaign envelope and attach explicit detached payload files
/// to SOVD-backed targets whose L2 manifests reference matching payload URIs.
pub fn parse_l1_campaign_with_payloads(
    envelope: &[u8],
    trust_anchor: &[u8],
    gateway_id: Option<String>,
    sovd_ecus: &[String],
    detached_payloads: &[(String, std::path::PathBuf)],
) -> Result<Vec<EcuTarget>, OrchestratorError> {
    let crypto = RustCryptoBackend::new();
    let validator = Validator::new(trust_anchor, None);

    let manifest = validator
        .validate_envelope(envelope, &crypto, 0)
        .map_err(|e| OrchestratorError::Manifest(format!("validate L1 envelope: {e:?}")))?;

    if !manifest.is_campaign() {
        return Err(OrchestratorError::Manifest(
            "not a campaign manifest (no dependencies)".into(),
        ));
    }

    let dep_count = manifest.dependency_count();
    let mut targets = Vec::with_capacity(dep_count);

    for i in 0..dep_count {
        let dep_uri = manifest
            .dependency_uri(i)
            .ok_or_else(|| OrchestratorError::Manifest(format!("no URI for dependency {i}")))?;

        let l2_envelope = if dep_uri.starts_with('#') {
            manifest
                .integrated_payload(dep_uri)
                .ok_or_else(|| {
                    OrchestratorError::Manifest(format!("payload not found: {dep_uri}"))
                })?
                .to_vec()
        } else {
            return Err(OrchestratorError::Manifest(format!(
                "external dependency URIs not yet supported: {dep_uri}"
            )));
        };

        let l2_manifest = validator
            .validate_envelope(&l2_envelope, &crypto, 0)
            .map_err(|e| OrchestratorError::Manifest(format!("validate L2 dep {i}: {e:?}")))?;

        // SUIT manifests for our ECUs use ["<ecu>", "<sub>"]
        // (e.g. ["vm1", "kernel"]) — first segment is the ECU id.
        let component_id = l2_manifest
            .component_id(0)
            .and_then(|segs| segs.first())
            .and_then(|s| std::str::from_utf8(s).ok())
            .ok_or_else(|| OrchestratorError::Manifest(format!("L2 dep {i}: no component ID")))?
            .to_string();

        let is_sovd_ecu = sovd_ecus.iter().any(|e| e == &component_id);
        let package = if is_sovd_ecu {
            l2_envelope
        } else {
            l2_manifest
                .integrated_payload("#firmware")
                .ok_or_else(|| {
                    OrchestratorError::Manifest(format!(
                        "L2 dep {i} ({component_id}): no integrated firmware"
                    ))
                })?
                .to_vec()
        };
        let payloads = if is_sovd_ecu {
            detached_payloads_for_manifest(&l2_manifest, detached_payloads)
        } else {
            Vec::new()
        };

        targets.push(EcuTarget {
            component_id,
            gateway_id: gateway_id.clone(),
            manifest: package,
            payloads,
        });
    }

    Ok(targets)
}

fn detached_payloads_for_manifest(
    manifest: &Manifest,
    detached_payloads: &[(String, std::path::PathBuf)],
) -> Vec<(String, std::path::PathBuf)> {
    let mut payloads = Vec::new();
    for component in 0..manifest.component_count() {
        if let Some(uri) = manifest.uri(component) {
            if let Some((_, path)) = detached_payloads
                .iter()
                .find(|(candidate, _)| candidate == uri)
            {
                payloads.push((uri.to_string(), path.clone()));
            }
        }
    }
    payloads
}

// ---------------------------------------------------------------------------
// Multiflash spec → Vec<EcuTarget>
// ---------------------------------------------------------------------------

/// JSON spec for [`MultiflashSpec::into_targets`]. Lists per-ECU
/// manifests and payload paths so a multi-ECU campaign can be assembled
/// from artefacts on disk without an L1 envelope.
#[derive(Deserialize, Debug, Clone)]
pub struct MultiflashSpec {
    pub ecus: Vec<MultiflashEcu>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MultiflashEcu {
    pub component_id: String,
    /// Path to an L2 SUIT manifest (small).
    pub manifest: String,
    /// Payload files: `[uri, path]` pairs in component order.
    #[serde(default)]
    pub payloads: Vec<(String, String)>,
}

impl MultiflashSpec {
    /// Read the manifest file for each ECU and produce the matching
    /// [`EcuTarget`] list. Payload paths are not read here (per-ECU
    /// flash logic streams them at upload time).
    ///
    /// `gateway_id` is stamped onto every target — campaign-level.
    pub fn into_targets(self, gateway_id: Option<String>) -> std::io::Result<Vec<EcuTarget>> {
        let mut targets = Vec::with_capacity(self.ecus.len());
        for ecu in self.ecus {
            let manifest = std::fs::read(&ecu.manifest)?;
            let payloads = ecu
                .payloads
                .into_iter()
                .map(|(uri, path)| (uri, std::path::PathBuf::from(path)))
                .collect();
            targets.push(EcuTarget {
                component_id: ecu.component_id,
                gateway_id: gateway_id.clone(),
                manifest,
                payloads,
            });
        }
        Ok(targets)
    }
}
