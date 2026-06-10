//! `FlashEngine` — the shared SOVD flash execution core: `guard → stage →
//! reset (coalesced) → commit | rollback`, driven by a normalized [`FlashPlan`]
//! and an injected [`TokenSource`]. Campaign and rig are thin adapters that
//! produce a plan and supply a token; the device is the single source of truth
//! for `reset_kind` / `update_mode` (read off the wire here, never in the plan).

use std::collections::BTreeMap;
use std::sync::Arc;

use sovd_client::SovdClient;
use tracing::{error, info, warn};

use crate::ecu;
use crate::error::EngineError;
use crate::types::{
    CampaignReport, EcuState, EcuStatus, EngineTimeouts, FlashPlan, TokenSource, UpdateType,
};

/// Subset of the device's `x-sumo-update-mode` payload the engine reads: the
/// no-mix guard uses `supports_rollback`; the singleshot reset uses `reset_kind`.
#[derive(serde::Deserialize)]
struct UpdateModeProbe {
    #[serde(default)]
    supports_rollback: bool,
    #[serde(default)]
    reset_kind: String,
}

pub struct FlashEngine {
    server_url: String,
    token: Arc<dyn TokenSource>,
    trust_anchor: Vec<u8>,
    timeouts: EngineTimeouts,
    /// Force every staged component through the ONE-node-reboot activation path
    /// (`RequiresEcuReset`) instead of each component's declared reset_kind. The
    /// workshop campaign sets this so a banked step activates via a single node
    /// reboot — both banks boot their new images together via the boot selector,
    /// rather than racy per-component relaunches. Field/OTA leaves it false: the
    /// onboard orchestrator never reboots a moving vehicle; activation waits for
    /// the next power cycle.
    force_ecu_reset: bool,
}

impl FlashEngine {
    pub fn new(
        server_url: impl Into<String>,
        token: Arc<dyn TokenSource>,
        trust_anchor: Vec<u8>,
        timeouts: EngineTimeouts,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            token,
            trust_anchor,
            timeouts,
            force_ecu_reset: false,
        }
    }

    /// Activate every staged component via one coalesced node reboot rather than
    /// its declared reset_kind — see [`force_ecu_reset`](Self::force_ecu_reset).
    pub fn with_force_ecu_reset(mut self, force: bool) -> Self {
        self.force_ecu_reset = force;
        self
    }

    /// No-mix guard: read each component's `x-sumo-update-mode` and reject a
    /// plan that mixes rollbackable (banked) + irreversible (singleshot, e.g.
    /// the HSM keystore) components — a rollback would leave the device
    /// undefined. Components the device doesn't report are skipped (graceful on
    /// older firmware). Reads at the top-level component id (`read_data` has no
    /// sub-entity form) — correct for campaign + rig's top-level components.
    pub async fn guard(&self, plan: &FlashPlan) -> Result<(), EngineError> {
        let mut rollbackable = Vec::new();
        let mut irreversible = Vec::new();
        for job in &plan.jobs {
            let client = self.sovd_client(&job.component_id).await?;
            if let Ok(resp) = client
                .read_data(&job.component_id, "x-sumo-update-mode")
                .await
            {
                if let Ok(mode) = serde_json::from_value::<UpdateModeProbe>(resp.value) {
                    if mode.supports_rollback {
                        rollbackable.push(job.component_id.clone());
                    } else {
                        irreversible.push(job.component_id.clone());
                    }
                }
            }
        }
        if !rollbackable.is_empty() && !irreversible.is_empty() {
            return Err(EngineError::MixedUpdateModes {
                rollbackable,
                irreversible,
            });
        }
        Ok(())
    }

    /// Stage every job to AwaitingReboot. Does NOT reset. On failure, rolls
    /// back already-staged components (pure SOVD). **Precondition:** the driver
    /// has unlocked each component (UDS) before this call.
    pub async fn stage_all(&self, plan: &FlashPlan) -> Result<Vec<EcuStatus>, EngineError> {
        let total = plan.jobs.len();
        info!(ecus = total, "starting flash — stage phase");

        let mut statuses: Vec<EcuStatus> = plan
            .jobs
            .iter()
            .map(|j| EcuStatus {
                component_id: j.component_id.clone(),
                gateway_id: j.gateway_id.clone(),
                state: EcuState::Pending,
                update_type: UpdateType::Firmware,
                active_version: None,
                previous_version: None,
                error: None,
                update_id: None,
            })
            .collect();

        let mut staged: Vec<String> = Vec::new();

        for (i, job) in plan.jobs.iter().enumerate() {
            let comp = &job.component_id;
            info!(component = %comp, progress = format!("{}/{}", i + 1, total), "staging ECU");
            statuses[i].state = EcuState::Flashing;

            let token = self.token.token(comp).await?;
            match ecu::flash_ecu_to_staging(job, &self.server_url, &self.trust_anchor, &token).await
            {
                Ok(result) => {
                    statuses[i].update_type = result.update_type;
                    statuses[i].update_id = Some(result.update_id.clone());
                    // Banked components paused at awaiting-verdict enter the
                    // Staged → reset → commit pipeline; everything else (auto-
                    // completed singleshot, application, policy) is done.
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
                    self.rollback_staged(&staged, &mut statuses).await;
                    return Err(EngineError::FlashFailed {
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
        Ok(statuses)
    }

    /// Reset all staged ECUs and wait for activation (trial mode), partitioning
    /// by `(parent ECU, reset_kind)` per ISO 17978-3 §7.19:
    /// - `Local` → `PUT components/{id}/status/restart` per component, parallel.
    /// - `RequiresEcuReset` → ONE entity/gateway restart per parent ECU, then
    ///   poll that group in parallel. Coalesces RT + host-OS into one reboot.
    pub async fn reset_all(&self, ecus: &mut [EcuStatus]) -> Result<(), EngineError> {
        // 1. Staged firmware components carry the update_id captured at staging.
        let mut staged: Vec<(String, Option<String>, String)> = Vec::new();
        for e in ecus.iter().filter(|e| e.state == EcuState::Staged) {
            let update_id = e
                .update_id
                .clone()
                .ok_or_else(|| EngineError::FlashFailed {
                    component: e.component_id.clone(),
                    message: "staged component has no update_id (staging bug)".into(),
                })?;
            staged.push((e.component_id.clone(), e.gateway_id.clone(), update_id));
        }

        // Committed singleshot components (e.g. RT/M7) still need a reboot to RUN
        // the firmware just written, when they declare a reset_kind — there is no
        // trial/verdict (already committed). reset_kind comes off the stable
        // `x-sumo-update-mode` (no live update to attach for a committed component).
        let mut ss_local: Vec<(String, Option<String>)> = Vec::new();
        let mut ss_by_ecu: BTreeMap<Option<String>, Vec<String>> = BTreeMap::new();
        for e in ecus.iter().filter(|e| e.state == EcuState::Committed) {
            match self.component_reset_kind(&e.component_id).await {
                sovd_core::ResetKind::Local => {
                    ss_local.push((e.component_id.clone(), e.gateway_id.clone()))
                }
                sovd_core::ResetKind::RequiresEcuReset => ss_by_ecu
                    .entry(e.gateway_id.clone())
                    .or_default()
                    .push(e.component_id.clone()),
                sovd_core::ResetKind::None => {}
            }
        }

        if staged.is_empty() && ss_local.is_empty() && ss_by_ecu.is_empty() {
            info!("no ECUs need reset");
            return Ok(());
        }

        // 2. Read each staged component's declared reset_kind off the wire.
        let mut local: Vec<(String, Option<String>, String)> = Vec::new();
        let mut by_ecu: BTreeMap<Option<String>, Vec<(String, String)>> = BTreeMap::new();
        for (comp, gw, update_id) in &staged {
            let kind = if self.force_ecu_reset {
                // Workshop campaign: activate the whole step with ONE node reboot,
                // regardless of each component's declared (e.g. Local) reset_kind.
                sovd_core::ResetKind::RequiresEcuReset
            } else {
                let token = self.token.token(comp).await?;
                ecu::fetch_reset_kind(&self.server_url, comp, gw.as_deref(), update_id, &token)
                    .await?
            };
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

        let mut first_err: Option<EngineError> = None;

        // 3. Local: concurrent per-component restart.
        if !local.is_empty() {
            let mut set = tokio::task::JoinSet::new();
            for (comp, gw, update_id) in local {
                let url = self.server_url.clone();
                let token = self.token.token(&comp).await?;
                let secs = self.timeouts.local_reset_secs;
                set.spawn(async move {
                    let result = ecu::reset_and_activate(
                        &url,
                        &comp,
                        gw.as_deref(),
                        &update_id,
                        secs,
                        &token,
                    )
                    .await;
                    (comp, result)
                });
            }
            collect_results(&mut set, ecus, EcuState::Activated, &mut first_err).await;
        }

        // 4. RequiresEcuReset: one restart per affected ECU, then poll the group.
        for (gateway_id, comps) in by_ecu {
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
            let restart_key = gateway_id.as_deref().unwrap_or("");
            let restart = match self.sovd_client(restart_key).await {
                Ok(client) => client
                    .system_restart(gateway_id.as_deref(), "hard")
                    .await
                    .map_err(|e| EngineError::FlashFailed {
                        component: comps.first().map(|(c, _)| c.clone()).unwrap_or_default(),
                        message: format!("ECU restart: {e}"),
                    }),
                Err(e) => Err(e),
            };
            if let Err(err) = restart {
                error!(error = %err, "ECU-level restart failed — staged components remain unactivated");
                for (comp_id, _) in &comps {
                    if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                        s.state = EcuState::Failed;
                        s.error = Some(format!("{err}"));
                    }
                }
                if first_err.is_none() {
                    first_err = Some(err);
                }
                continue;
            }

            // Confirm the NODE actually rebooted: its SOVD server restarts WITH
            // the node, so observe the server go unreachable then reachable
            // again. The orchestrator witnesses that transition directly, so it
            // can't be faked by a stale pre-reset answer ("rebooted too soon").
            // The per-component `boot_count` is NOT a usable witness here: it is
            // bumped only by a per-component `ecu_reset`, never by a node reboot,
            // so it stays flat across the reboot. Done once for the node via a
            // representative component's `/status`.
            let probe = comps
                .first()
                .map(|(c, _)| c.clone())
                .unwrap_or_else(|| restart_key.to_string());
            if let Err(err) = self
                .wait_node_rebooted(&probe, self.timeouts.ecu_reset_activation_secs)
                .await
            {
                error!(error = %err, "node reboot not observed — SOVD server never went down then up");
                for (comp_id, _) in &comps {
                    if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                        s.state = EcuState::Failed;
                        s.error = Some(format!("{err}"));
                    }
                }
                if first_err.is_none() {
                    first_err = Some(err);
                }
                continue;
            }

            // The node is back. Each staged component → `ready` (its guest booted
            // the new bank and reports healthy) ⇒ Activated; `commit_all`'s
            // node-level verdict then commits the whole in-trial set at once (the
            // update *session* is the commit unit) — there is no per-component
            // `/updates` session to re-attach (the reboot wiped it).
            for (comp_id, _update_id) in &comps {
                match self
                    .wait_ready(comp_id, self.timeouts.ecu_reset_activation_secs)
                    .await
                {
                    Ok(()) => {
                        info!(component = %comp_id, "ready after node reboot — activated");
                        if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                            s.state = EcuState::Activated;
                        }
                    }
                    Err(err) => {
                        error!(component = %comp_id, error = %err, "component not ready after node reboot");
                        if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                            s.state = EcuState::Failed;
                            s.error = Some(format!("{err}"));
                        }
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            }
        }

        // 5. Reboot committed singleshot components that declared a reset_kind,
        //    then confirm the node is reachable again — no trial/verdict (the
        //    write is already committed; there is nothing to roll back).
        if !ss_local.is_empty() || !ss_by_ecu.is_empty() {
            info!(
                local = ss_local.len(),
                requires_ecu_reset = ss_by_ecu.values().map(|v| v.len()).sum::<usize>(),
                "rebooting committed singleshot components to run new firmware"
            );
        }
        for (comp, gw) in ss_local {
            let token = self.token.token(&comp).await?;
            let outcome =
                match ecu::trigger_local_restart(&self.server_url, &comp, gw.as_deref(), &token)
                    .await
                {
                    Ok(()) => {
                        self.wait_reachable(&comp, self.timeouts.local_reset_secs)
                            .await
                    }
                    Err(e) => Err(e),
                };
            if let Err(err) = outcome {
                if let Some(s) = ecus.iter_mut().find(|s| s.component_id == comp) {
                    s.state = EcuState::Failed;
                    s.error = Some(format!("{err}"));
                }
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        for (gateway_id, comps) in ss_by_ecu {
            let restart_key = gateway_id.as_deref().unwrap_or("");
            info!(gateway = ?gateway_id, components = ?comps, "rebooting node for committed singleshot (RequiresEcuReset)");
            let outcome = match self.sovd_client(restart_key).await {
                Ok(client) => match client.system_restart(gateway_id.as_deref(), "hard").await {
                    Ok(_) => {
                        self.wait_reachable(restart_key, self.timeouts.ecu_reset_activation_secs)
                            .await
                    }
                    Err(e) => Err(EngineError::FlashFailed {
                        component: comps.first().cloned().unwrap_or_default(),
                        message: format!("ECU restart: {e}"),
                    }),
                },
                Err(e) => Err(e),
            };
            if let Err(err) = outcome {
                for comp_id in &comps {
                    if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp_id) {
                        s.state = EcuState::Failed;
                        s.error = Some(format!("{err}"));
                    }
                }
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }

        if let Some(e) = first_err {
            return Err(e);
        }
        info!("all ECUs reset");
        Ok(())
    }

    /// Issue the node-level **commit** verdict directly: commit every component
    /// currently in trial on the node, in ONE call (the update *session* is the
    /// commit unit). The device resolves the in-trial set from NV, so this is
    /// reboot-safe and needs no per-component `/updates` session — it is how a
    /// node-reboot step finalizes. Used by `commit_all`'s node path and exposed
    /// for the manual `commit-trials` verb (no component list required).
    pub async fn commit_node_trials(&self) -> Result<(), EngineError> {
        let token = self.token.token("").await?;
        ecu::commit_node_trials(&self.server_url, &token).await
    }

    /// Issue the node-level **rollback** verdict directly — see
    /// [`commit_node_trials`](Self::commit_node_trials).
    pub async fn rollback_node_trials(&self) -> Result<(), EngineError> {
        let token = self.token.token("").await?;
        ecu::rollback_node_trials(&self.server_url, &token).await
    }

    /// Commit all activated firmware components — makes the trial permanent.
    ///
    /// On the node-reboot path (`force_ecu_reset`), the per-component `/updates`
    /// sessions were destroyed by the reboot, and the orchestrator must never
    /// commit a single component anyway — the update *session* is the commit
    /// unit. So ONE node-level verdict commits every in-trial component at once
    /// (resolved from NV by the device). The per-component path stays for local
    /// resets, where the paused execute task is still alive to release.
    pub async fn commit_all(&self, ecus: &mut [EcuStatus]) -> Result<(), EngineError> {
        let to_commit: Vec<(String, Option<String>, String)> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
            .filter_map(|e| {
                e.update_id
                    .clone()
                    .map(|id| (e.component_id.clone(), e.gateway_id.clone(), id))
            })
            .collect();

        if to_commit.is_empty() {
            return Ok(());
        }

        if self.force_ecu_reset {
            info!(ecus = to_commit.len(), "committing (node-level verdict)");
            self.commit_node_trials().await?;
            for (comp, _, _) in &to_commit {
                if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp) {
                    s.state = EcuState::Committed;
                }
            }
            info!("commit complete (node-level)");
            return Ok(());
        }

        info!(ecus = to_commit.len(), "committing");
        for (comp, gw, update_id) in &to_commit {
            info!(component = %comp, "committing");
            self.commit_one(comp, gw.as_deref(), update_id).await?;
            if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp) {
                s.state = EcuState::Committed;
            }
        }
        info!("commit complete");
        Ok(())
    }

    /// Rollback all activated firmware components — reverts to the prior bank.
    ///
    /// Same node-reboot vs local-reset split as [`commit_all`]: on
    /// `force_ecu_reset` a single node-level verdict rolls back the whole
    /// in-trial set; otherwise the per-component path releases each live task.
    pub async fn rollback_all(&self, ecus: &mut [EcuStatus]) -> Result<(), EngineError> {
        let to_rollback: Vec<(String, Option<String>, String)> = ecus
            .iter()
            .filter(|e| e.state == EcuState::Activated && e.update_type == UpdateType::Firmware)
            .filter_map(|e| {
                e.update_id
                    .clone()
                    .map(|id| (e.component_id.clone(), e.gateway_id.clone(), id))
            })
            .collect();

        if to_rollback.is_empty() {
            return Ok(());
        }

        if self.force_ecu_reset {
            warn!(
                ecus = to_rollback.len(),
                "rolling back (node-level verdict)"
            );
            self.rollback_node_trials().await?;
            for (comp, _, _) in &to_rollback {
                if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp) {
                    s.state = EcuState::RolledBack;
                }
            }
            return Ok(());
        }

        warn!(ecus = to_rollback.len(), "rolling back");
        for (comp, gw, update_id) in &to_rollback {
            warn!(component = %comp, "rolling back");
            match self.rollback_one(comp, gw.as_deref(), update_id).await {
                Ok(()) => {
                    if let Some(s) = ecus.iter_mut().find(|s| &s.component_id == comp) {
                        s.state = EcuState::RolledBack;
                    }
                    info!(component = %comp, "rolled back");
                }
                Err(e) => error!(component = %comp, error = %e, "rollback failed"),
            }
        }
        Ok(())
    }

    /// Convenience for automated drivers: guard → stage → reset → commit.
    /// Manual drivers (e.g. rig's CLI, campaign-cli's `--no-commit`) call the
    /// phase methods individually and own the trial-health decision.
    pub async fn run(&self, plan: FlashPlan) -> Result<CampaignReport, EngineError> {
        self.guard(&plan).await?;
        let mut ecus = self.stage_all(&plan).await?;
        self.reset_all(&mut ecus).await?;
        self.commit_all(&mut ecus).await?;
        Ok(CampaignReport { ecus })
    }

    // --- internals ---------------------------------------------------------

    /// Commit one component — pure SOVD (attach + spec_commit). The driver
    /// re-unlocks (UDS) before calling, if its security model needs it.
    async fn commit_one(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
        update_id: &str,
    ) -> Result<(), EngineError> {
        let token = self.token.token(component_id).await?;
        let flash_client =
            ecu::build_flash_client(&self.server_url, component_id, gateway_id, &token)?;
        flash_client
            .attach(update_id)
            .await
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("attach: {e}"),
            })?;
        flash_client
            .spec_commit()
            .await
            .map(|_| ())
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("spec_commit: {e}"),
            })
    }

    /// Rollback one component — pure SOVD (attach + spec_rollback).
    async fn rollback_one(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
        update_id: &str,
    ) -> Result<(), EngineError> {
        let token = self.token.token(component_id).await?;
        let flash_client =
            ecu::build_flash_client(&self.server_url, component_id, gateway_id, &token)?;
        flash_client
            .attach(update_id)
            .await
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("attach: {e}"),
            })?;
        flash_client
            .spec_rollback()
            .await
            .map(|_| ())
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("spec_rollback: {e}"),
            })
    }

    /// Roll back already-staged components after a mid-stage failure.
    async fn rollback_staged(&self, staged: &[String], statuses: &mut [EcuStatus]) {
        if staged.is_empty() {
            return;
        }
        warn!(count = staged.len(), "rolling back staged ECUs");
        for rc in staged {
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
                    if let Some(s) = statuses.iter_mut().find(|s| &s.component_id == rc) {
                        s.state = EcuState::RolledBack;
                    }
                }
                Err(re) => warn!(component = %rc, error = %re, "rollback failed"),
            }
        }
    }

    /// Read a component's `reset_kind` from the stable `x-sumo-update-mode`
    /// capability — available without a live update (unlike the per-update
    /// `/updates` status that `fetch_reset_kind` reads). Unknown / unreported /
    /// unreachable → `None` (no reboot).
    async fn component_reset_kind(&self, comp: &str) -> sovd_core::ResetKind {
        let Ok(client) = self.sovd_client(comp).await else {
            return sovd_core::ResetKind::None;
        };
        let Ok(resp) = client.read_data(comp, "x-sumo-update-mode").await else {
            return sovd_core::ResetKind::None;
        };
        match serde_json::from_value::<UpdateModeProbe>(resp.value) {
            Ok(mode) => match mode.reset_kind.as_str() {
                "requires_ecu_reset" => sovd_core::ResetKind::RequiresEcuReset,
                "local" => sovd_core::ResetKind::Local,
                _ => sovd_core::ResetKind::None,
            },
            Err(_) => sovd_core::ResetKind::None,
        }
    }

    /// Poll the device's SOVD API until it answers again after a reboot. A
    /// committed singleshot reset has no trial/verdict to wait on — this just
    /// confirms the node came back (its API serves `/components`).
    async fn wait_reachable(&self, key: &str, timeout_secs: u64) -> Result<(), EngineError> {
        let client = self.sovd_client(key).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if client.list_components().await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                return Err(EngineError::Timeout {
                    component: key.to_string(),
                    operation: "reboot (singleshot)".into(),
                });
            }
        }
    }

    /// Whether the node's SOVD server currently answers `GET {comp}/status`.
    /// A liveness probe for the node-reboot observation — only reachability
    /// matters, not the body.
    async fn node_reachable(&self, comp: &str) -> bool {
        match self.sovd_client(comp).await {
            Ok(client) => client.read_status(comp).await.is_ok(),
            Err(_) => false,
        }
    }

    /// Confirm the node rebooted by observing its SOVD server go UNREACHABLE
    /// then REACHABLE again — the server restarts with the node, so this
    /// down→up transition is a reboot proof the orchestrator witnesses
    /// directly. It can't be faked by a stale pre-reset answer ("rebooted too
    /// soon"): no `/status` answer is trusted until the server has been seen
    /// down at least once and then up again. This replaces the per-component
    /// `boot_count` witness, which a node reboot never bumps (only a
    /// per-component `ecu_reset` does). Polls a representative component.
    async fn wait_node_rebooted(&self, probe: &str, timeout_secs: u64) -> Result<(), EngineError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let mut saw_down = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if self.node_reachable(probe).await {
                if saw_down {
                    return Ok(());
                }
            } else {
                saw_down = true;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(EngineError::Timeout {
                    component: probe.to_string(),
                    operation: "node reboot (SOVD server down→up)".into(),
                });
            }
        }
    }

    /// Wait until a component reports `ready` (its guest booted the new bank and
    /// is healthy). The node is already back up (see [`wait_node_rebooted`]), so
    /// this only waits on guest boot. Reads `/status` — never the wiped
    /// `/updates` session.
    async fn wait_ready(&self, comp: &str, timeout_secs: u64) -> Result<(), EngineError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Ok(client) = self.sovd_client(comp).await {
                if let Ok(body) = client.read_status(comp).await {
                    if matches!(body.status, sovd_core::EntityStatus::Ready) {
                        return Ok(());
                    }
                }
            }
            if tokio::time::Instant::now() > deadline {
                return Err(EngineError::Timeout {
                    component: comp.to_string(),
                    operation: "ready after node reboot".into(),
                });
            }
        }
    }

    /// Build a base-URL `SovdClient` for `key` (a component or gateway id),
    /// bearing that key's token when non-empty. Used for entity-root restart
    /// and the update-mode guard.
    async fn sovd_client(&self, key: &str) -> Result<SovdClient, EngineError> {
        let token = self.token.token(key).await?;
        let client = if token.is_empty() {
            SovdClient::new(&self.server_url)
        } else {
            SovdClient::with_bearer_token(&self.server_url, &token)
        };
        client.map_err(|e| EngineError::Sovd {
            component: key.to_string(),
            message: format!("sovd client: {e}"),
        })
    }
}

/// Drain a JoinSet of `(component_id, Result)` tuples, updating each
/// component's `EcuStatus` and surfacing the first error seen.
async fn collect_results(
    set: &mut tokio::task::JoinSet<(String, Result<(), EngineError>)>,
    ecus: &mut [EcuStatus],
    on_success: EcuState,
    first_err: &mut Option<EngineError>,
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
                    *first_err = Some(EngineError::Internal(format!("task panic: {join_err}")));
                }
            }
        }
    }
}
