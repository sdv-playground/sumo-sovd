//! Campaign orchestrator — sequence-driven multi-ECU updates via SOVD.
//!
//! Reads the L1 campaign manifest's SUIT command sequences to determine
//! the execution flow. The manifest declares what to do; the orchestrator
//! executes it via SOVD REST calls.
//!
//! Lifecycle:
//! 1. Stage phase: flash all ECUs to staging (AwaitingReboot)
//! 2. Reset phase: reset all ECUs (orchestrator decides when)
//! 3. All ECUs in trial — system health check (caller decides)
//! 4. Commit all or rollback all

use async_trait::async_trait;
use sovd_client::flash::FlashClient;
use sovd_client::SovdClient;
use sumo_codec::commands::CommandValue;
use sumo_codec::labels::*;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::Validator;
use tracing::{error, info, warn};

use crate::ecu::{self, EcuFlashConfig, UpdateType};
use crate::error::OrchestratorError;
use crate::security_helper::{ComputeKeyRequest, SecurityHelperClient, SecurityHelperConfig};

/// Configuration for a campaign deployment.
pub struct CampaignConfig {
    pub server_url: String,
    pub trust_anchor: Vec<u8>,
    pub security_level: u8,
    pub security_helper: SecurityHelperConfig,
    /// If true, after each ECU's `transfer_exit` the orchestrator drives
    /// it through `validate()` → `activate()` so the lifecycle visibly
    /// passes through `Validated`. Default false (classic flow).
    pub use_validated_flow: bool,
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
    /// The `/updates` package id opened when this ECU was staged.
    /// `None` until staging produces it; carried so reset/commit/
    /// rollback can re-`attach` a post-reset FlashClient to the
    /// surviving server-side entry.
    pub update_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcuState {
    Pending,
    Flashing,
    Staged, // AwaitingReboot — flash done, waiting for reset
    /// Flash finalised + an ECU-level restart has been issued for the
    /// parent ECU (because at least one staged component declared
    /// `reset_kind: requires_ecu_reset`). Polling for `Activated`.
    AwaitingSystemReboot,
    Activated, // Trial mode — reset done, running new firmware
    Committed,
    RolledBack,
    Failed,
}

/// Result of the stage phase (all ECUs flashed, awaiting reset).
pub struct StagePhaseResult {
    pub ecus: Vec<EcuStatus>,
}

/// Result of the full flash phase (stage + reset + activate).
pub struct FlashPhaseResult {
    pub ecus: Vec<EcuStatus>,
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

/// Orchestrates multi-ECU firmware campaigns.
pub struct CampaignOrchestrator {
    config: CampaignConfig,
    helper: SecurityHelperClient,
}

impl CampaignOrchestrator {
    pub fn new(config: CampaignConfig) -> Self {
        let helper = SecurityHelperClient::new(config.security_helper.clone());
        Self { config, helper }
    }

    /// Pooled security-helper client. Used internally for unlock during
    /// commit/rollback; exposed publicly so callers (e.g. `sumo-deploy`)
    /// can probe `/info` or perform extra unlocks without spinning up
    /// their own client.
    pub fn helper(&self) -> &SecurityHelperClient {
        &self.helper
    }

    /// Stage all ECU targets — flash each to staging (AwaitingReboot).
    ///
    /// Does NOT reset ECUs. Call `reset_all` when ready.
    /// On failure, automatically rolls back already-staged ECUs.
    pub async fn stage_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<StagePhaseResult, OrchestratorError> {
        let total = targets.len();
        info!(ecus = total, "starting campaign — stage phase");

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
                update_id: None,
            })
            .collect();

        let mut staged: Vec<String> = Vec::new();

        for (i, target) in targets.iter().enumerate() {
            let comp = &target.component_id;
            info!(component = %comp, progress = format!("{}/{}", i + 1, total), "staging ECU");
            statuses[i].state = EcuState::Flashing;

            // Unlock first — orchestrator owns session/security state.
            // The ECU module's flash protocol assumes already-unlocked.
            if let Err(e) = self
                .unlock_for_flash(comp, target.gateway_id.as_deref())
                .await
            {
                statuses[i].state = EcuState::Failed;
                statuses[i].error = Some(format!("{e}"));
                error!(component = %comp, error = %e, "ECU unlock failed");
                if !staged.is_empty() {
                    warn!(count = staged.len(), "rolling back staged ECUs");
                    for rc in &staged {
                        let (gw, update_id) = statuses
                            .iter()
                            .find(|s| &s.component_id == rc)
                            .map(|s| (s.gateway_id.clone(), s.update_id.clone()))
                            .unwrap_or((None, None));
                        let Some(update_id) = update_id else {
                            warn!(component = %rc, "rollback skipped — no update_id");
                            continue;
                        };
                        if self
                            .rollback_one(rc, gw.as_deref(), &update_id)
                            .await
                            .is_ok()
                        {
                            if let Some(s) = statuses.iter_mut().find(|s| &s.component_id == rc) {
                                s.state = EcuState::RolledBack;
                            }
                        }
                    }
                }
                return Err(e);
            }

            match ecu::flash_ecu_to_staging(
                EcuFlashConfig {
                    component_id: comp.clone(),
                    server_url: self.config.server_url.clone(),
                    gateway_id: target.gateway_id.clone(),
                    manifest: target.manifest.clone(),
                    payloads: target.payloads.clone(),
                    use_validated_flow: self.config.use_validated_flow,
                },
                &self.config.trust_anchor,
            )
            .await
            {
                Ok(result) => {
                    statuses[i].update_type = result.update_type;
                    statuses[i].update_id = Some(result.update_id.clone());
                    // If execute auto-completed (singleshot, or the
                    // server's standard banked auto-commit branch),
                    // there's nothing left for reset_all / commit_all
                    // to do — record Committed directly so they skip.
                    // Only banked components that paused at
                    // awaiting-verdict enter the Staged → reset →
                    // commit pipeline.
                    statuses[i].state = match (result.update_type, result.awaiting_verdict) {
                        (UpdateType::Firmware, true) => EcuState::Staged,
                        (UpdateType::Firmware, false) => EcuState::Committed,
                        (UpdateType::Application, _) | (UpdateType::Policy, _) => {
                            EcuState::Committed
                        }
                    };
                    statuses[i].active_version = result.active_version;
                    statuses[i].previous_version = result.previous_version;
                    if result.update_type == UpdateType::Firmware && result.awaiting_verdict {
                        staged.push(comp.clone());
                    }
                    info!(
                        component = %comp,
                        update_type = ?result.update_type,
                        awaiting_verdict = result.awaiting_verdict,
                        "ECU staged"
                    );
                }
                Err(e) => {
                    statuses[i].state = EcuState::Failed;
                    statuses[i].error = Some(format!("{e}"));
                    error!(component = %comp, error = %e, "ECU staging failed");

                    // Rollback already-staged ECUs
                    if !staged.is_empty() {
                        warn!(count = staged.len(), "rolling back staged ECUs");
                        for rc in &staged {
                            let (gw, update_id) = statuses
                                .iter()
                                .find(|s| &s.component_id == rc)
                                .map(|s| (s.gateway_id.clone(), s.update_id.clone()))
                                .unwrap_or((None, None));
                            let Some(update_id) = update_id else {
                                warn!(component = %rc, "rollback skipped — no update_id");
                                continue;
                            };
                            match self.rollback_one(rc, gw.as_deref(), &update_id).await {
                                Ok(()) => {
                                    if let Some(s) =
                                        statuses.iter_mut().find(|s| &s.component_id == rc)
                                    {
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

        let fw_count = staged.len();
        let immediate_count = statuses
            .iter()
            .filter(|e| matches!(e.update_type, UpdateType::Application | UpdateType::Policy))
            .count();
        info!(
            firmware = fw_count,
            immediate = immediate_count,
            "stage phase complete"
        );

        Ok(StagePhaseResult { ecus: statuses })
    }

    /// Reset all staged ECUs and wait for activation (trial mode).
    ///
    /// Per ISO 17978-3 §7.19 the orchestrator partitions the staged set
    /// by `(parent_ECU, reset_kind)`:
    ///
    /// - `ResetKind::Local`   → `PUT components/{id}/status/restart` per
    ///   component, fanned out in parallel.
    /// - `ResetKind::RequiresEcuReset` → ONE `PUT {ecu-path}/status/restart`
    ///   per affected parent ECU, then poll all `RequiresEcuReset`
    ///   components in parallel. (M7 firmware via m7loader; host-OS IFS.)
    ///
    /// Components own their post-reset health gating via the
    /// `Verifying → Activated` transition, so wall-clock time is
    /// `max(activation)`, not `sum(activation)`.
    pub async fn reset_all(&self, ecus: &mut [EcuStatus]) -> Result<(), OrchestratorError> {
        // 1. Find staged components.  A staged firmware component always
        //    carries the update_id stage_all captured; surface a clear
        //    error rather than silently dropping it (post-reset commit
        //    needs it to re-attach).
        let mut staged: Vec<(String, Option<String>, String)> = Vec::new();
        for e in ecus.iter().filter(|e| e.state == EcuState::Staged) {
            let update_id = e
                .update_id
                .clone()
                .ok_or_else(|| OrchestratorError::FlashFailed {
                    component: e.component_id.clone(),
                    message: "staged component has no update_id (staging bug)".into(),
                })?;
            staged.push((e.component_id.clone(), e.gateway_id.clone(), update_id));
        }

        if staged.is_empty() {
            info!("no ECUs need reset");
            return Ok(());
        }

        // 2. Fetch each staged component's declared reset_kind from
        //    ActivationState (added to the wire in SOVDd 7245abc). Older
        //    servers that omit the field deserialise to Local.
        let server_url = self.config.server_url.clone();
        let mut local: Vec<(String, Option<String>, String)> = Vec::new();
        // gateway → [(component, update_id)]
        let mut by_ecu: std::collections::BTreeMap<Option<String>, Vec<(String, String)>> =
            std::collections::BTreeMap::new();
        for (comp, gw, update_id) in &staged {
            let kind = ecu::fetch_reset_kind(&server_url, comp, gw.as_deref()).await?;
            match kind {
                sovd_core::ResetKind::None | sovd_core::ResetKind::Local => {
                    local.push((comp.clone(), gw.clone(), update_id.clone()));
                }
                sovd_core::ResetKind::RequiresEcuReset => {
                    by_ecu
                        .entry(gw.clone())
                        .or_default()
                        .push((comp.clone(), update_id.clone()));
                }
            }
        }

        info!(
            local = local.len(),
            requires_ecu_reset = by_ecu.values().map(|v| v.len()).sum::<usize>(),
            ecus_to_reboot = by_ecu.len(),
            "resetting all staged ECUs"
        );

        // 3. Local: existing concurrent per-component restart.
        let mut first_err: Option<OrchestratorError> = None;
        if !local.is_empty() {
            let mut set = tokio::task::JoinSet::new();
            for (comp, gw, update_id) in local {
                let url = server_url.clone();
                set.spawn(async move {
                    // 180s budget covers managed-cvc's worst-case
                    // per-VM reset → verify → Activated cycle.
                    let result =
                        ecu::reset_and_activate(&url, &comp, gw.as_deref(), &update_id, 180).await;
                    (comp, result)
                });
            }
            collect_results(&mut set, ecus, EcuState::Activated, &mut first_err).await;
        }

        // 4. RequiresEcuReset: one entity-root restart per affected ECU,
        //    then poll all RequiresEcuReset components in that ECU group
        //    in parallel with a longer timeout (the host reboot + supernova
        //    respawn + VMs auto-start typically takes ~120-180s on a CVC).
        for (gateway_id, comps) in by_ecu {
            // Mark affected components AwaitingSystemReboot so any
            // observer of `EcuStatus` sees the intent before the host
            // goes down.
            for (comp_id, _) in &comps {
                if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                    s.state = EcuState::AwaitingSystemReboot;
                }
            }
            info!(
                gateway = ?gateway_id,
                components = ?comps.iter().map(|(c, _)| c).collect::<Vec<_>>(),
                "issuing ECU-level restart (coalesced for RequiresEcuReset)"
            );
            if let Err(e) =
                sovd_client::flash::system_restart(&server_url, gateway_id.as_deref(), "hard").await
            {
                let err = OrchestratorError::FlashFailed {
                    component: comps.first().map(|(c, _)| c.clone()).unwrap_or_default(),
                    message: format!("ECU restart: {e}"),
                };
                error!(error = %err, "ECU-level restart failed — staged components remain unactivated");
                if first_err.is_none() {
                    first_err = Some(err);
                }
                // Mark all in this group as Failed so the campaign report is accurate.
                for (comp_id, _) in &comps {
                    if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                        s.state = EcuState::Failed;
                        s.error = Some(format!("ECU restart failed: {e}"));
                    }
                }
                continue;
            }

            // Poll all components in this ECU group concurrently.
            let mut set = tokio::task::JoinSet::new();
            for (comp_id, update_id) in comps {
                let url = server_url.clone();
                let gw = gateway_id.clone();
                set.spawn(async move {
                    let result =
                        ecu::wait_for_activation(&url, &comp_id, gw.as_deref(), &update_id, 300)
                            .await;
                    (comp_id, result)
                });
            }
            collect_results(&mut set, ecus, EcuState::Activated, &mut first_err).await;
        }

        if let Some(e) = first_err {
            return Err(e);
        }

        info!("all ECUs activated (trial mode)");
        Ok(())
    }

    /// Flash all ECU targets — stage + reset + activate.
    ///
    /// Convenience method that runs the full lifecycle. Use `stage_all` +
    /// `reset_all` separately if you need to pause between phases.
    pub async fn flash_all(
        &self,
        targets: Vec<EcuTarget>,
    ) -> Result<FlashPhaseResult, OrchestratorError> {
        let stage_result = self.stage_all(targets).await?;
        let mut ecus = stage_result.ecus;
        self.reset_all(&mut ecus).await?;
        Ok(FlashPhaseResult { ecus })
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
            let update_id =
                ecu.update_id
                    .as_deref()
                    .ok_or_else(|| OrchestratorError::FlashFailed {
                        component: ecu.component_id.clone(),
                        message: "commit: component has no update_id (staging bug)".into(),
                    })?;
            self.commit_one(&ecu.component_id, ecu.gateway_id.as_deref(), update_id)
                .await?;
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
            let Some(update_id) = ecu.update_id.as_deref() else {
                error!(component = %ecu.component_id, "rollback: component has no update_id (staging bug)");
                continue;
            };
            match self
                .rollback_one(&ecu.component_id, ecu.gateway_id.as_deref(), update_id)
                .await
            {
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
            return Err(OrchestratorError::Manifest(
                "not a campaign manifest".into(),
            ));
        }

        // Read install sequence to determine ECU ordering
        let envelope = manifest.envelope();
        let install_seq = envelope
            .manifest
            .severable
            .install
            .as_ref()
            .ok_or_else(|| {
                OrchestratorError::Manifest("campaign has no install sequence".into())
            })?;

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
            "campaign: install sequence declares {} ECUs",
            dep_indices.len()
        );

        // Resolve each dependency into an EcuTarget
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

        // Execute: stage all ECUs, then reset all, then activate
        self.flash_all(targets).await
    }

    fn make_flash_client(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
    ) -> Result<FlashClient, OrchestratorError> {
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

    /// Establish programming session + security unlock for an ECU.
    ///
    /// Called both before staging (initial unlock) and after each ECU
    /// reset (ISO 14229 resets session/security to default — needed
    /// before commit/rollback). The ECU module never touches session
    /// or security state itself; that's an orchestrator concern.
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

    async fn commit_one(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
        update_id: &str,
    ) -> Result<(), OrchestratorError> {
        // Re-establish access (ECU reset clears session per ISO 14229)
        self.unlock_for_flash(component_id, gateway_id).await?;
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        // The FlashClient is fresh — the post-reset orchestrator
        // doesn't carry the original session.  Re-attach to the
        // server-side /updates entry (by the id captured at staging)
        // before committing.
        flash_client
            .attach(update_id)
            .await
            .map_err(|e| OrchestratorError::FlashFailed {
                component: component_id.to_string(),
                message: format!("attach: {e}"),
            })?;
        // ISO 17978-3 spec wire (Phase B vendor verb):
        // `PUT /updates/{id}/x-sumo-commit` posts the verdict to the
        // paused execute task; FlashClient.spec_commit polls /status
        // until the entry reaches execute/completed.
        flash_client
            .spec_commit()
            .await
            .map(|_| ())
            .map_err(|e| OrchestratorError::FlashFailed {
                component: component_id.to_string(),
                message: format!("spec_commit: {e}"),
            })
    }

    async fn rollback_one(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
        update_id: &str,
    ) -> Result<(), OrchestratorError> {
        self.unlock_for_flash(component_id, gateway_id).await?;
        let flash_client = self.make_flash_client(component_id, gateway_id)?;
        flash_client
            .attach(update_id)
            .await
            .map_err(|e| OrchestratorError::FlashFailed {
                component: component_id.to_string(),
                message: format!("attach: {e}"),
            })?;
        flash_client
            .spec_rollback()
            .await
            .map(|_| ())
            .map_err(|e| OrchestratorError::FlashFailed {
                component: component_id.to_string(),
                message: format!("spec_rollback: {e}"),
            })
    }
}

/// Drain a JoinSet of `(component_id, Result)` tuples produced by the
/// reset_all parallel loops, updating each component's `EcuStatus` and
/// surfacing the first error seen.
async fn collect_results(
    set: &mut tokio::task::JoinSet<(String, Result<(), OrchestratorError>)>,
    ecus: &mut [EcuStatus],
    on_success: EcuState,
    first_err: &mut Option<OrchestratorError>,
) {
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((comp, Ok(()))) => {
                if let Some(s) = ecus.iter_mut().find(|s| s.component_id == comp) {
                    s.state = on_success.clone();
                }
            }
            Ok((comp, Err(e))) => {
                error!(component = %comp, error = %e, "ECU activation failed");
                if let Some(s) = ecus.iter_mut().find(|s| s.component_id == comp) {
                    s.state = EcuState::Failed;
                    s.error = Some(format!("{e}"));
                }
                if first_err.is_none() {
                    *first_err = Some(e);
                }
            }
            Err(join_err) => {
                error!(error = %join_err, "ECU activation task panicked");
                if first_err.is_none() {
                    *first_err = Some(OrchestratorError::Internal(format!(
                        "task panic: {join_err}"
                    )));
                }
            }
        }
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
