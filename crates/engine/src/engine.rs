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
    CampaignReport, CampaignStep, EcuState, EcuStatus, EngineTimeouts, FlashPlan, HealthCheck,
    TokenSource, UpdateType,
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

#[derive(Clone)]
pub struct FlashEngine {
    server_url: String,
    token: Arc<dyn TokenSource>,
    trust_anchor: Vec<u8>,
    timeouts: EngineTimeouts,
    /// Skip TLS certificate verification on the device endpoint (the `curl -k`
    /// equivalent), threaded into every device-facing `SovdClient`/`FlashClient`
    /// the engine builds. `false` (the default) is full verification —
    /// byte-identical to before this knob existed. Set when the device's leaf
    /// SAN won't match the dialled host (e.g. a `127.0.0.1` rig over HTTPS).
    insecure: bool,
    /// PEM-encoded CA root to pin the device endpoint's TLS cert against — the
    /// verifying alternative to [`insecure`](Self::insecure), threaded into every
    /// device-facing `SovdClient`/`FlashClient` the engine builds. `Some` pins
    /// that CA (the leaf must chain to it); `None` (the default) falls back to
    /// the `insecure` behaviour — byte-identical to before this knob existed.
    ca_cert_pem: Option<Vec<u8>>,
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
        insecure: bool,
        ca_cert_pem: Option<Vec<u8>>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            token,
            trust_anchor,
            timeouts,
            insecure,
            ca_cert_pem,
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
            match ecu::flash_ecu_to_staging(
                job,
                &self.server_url,
                &self.trust_anchor,
                &token,
                self.insecure,
                self.ca_cert_pem.as_deref(),
            )
            .await
            {
                Ok(result) => {
                    statuses[i].update_type = result.update_type;
                    statuses[i].update_id = Some(result.update_id.clone());
                    // Banked components paused at awaiting-verdict enter the
                    // Staged → reset → commit pipeline; everything else (auto-
                    // completed singleshot, application, policy, removal) is done.
                    statuses[i].state = match (result.update_type, result.awaiting_verdict) {
                        (UpdateType::Firmware, true) => EcuState::Staged,
                        (UpdateType::Firmware, false) => EcuState::Committed,
                        // Disable/removal is singleshot-irreversible: it auto-
                        // commits like singleshot firmware (never orchestrates, so
                        // awaiting_verdict is always false), then reset_all reboots
                        // it if it declares a reset_kind.
                        (UpdateType::Removal, _) => EcuState::Committed,
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
            let kind = self.component_reset_kind(&e.component_id).await.unwrap_or_else(|| {
                // Fail CLOSED: this component was just written irreversibly. If we
                // cannot read whether it needs a reboot, reboot — an unnecessary
                // node reset is bounded and observable; skipping it leaves
                // unverified firmware armed for the next power cycle and lets the
                // step pass a vacuous health gate (exactly what happened when the
                // rig's RT probe failed silently and the M7 reboot was skipped).
                warn!(
                    component = %e.component_id,
                    "update-mode unreadable for committed singleshot — defaulting to requires_ecu_reset"
                );
                sovd_core::ResetKind::RequiresEcuReset
            });
            match kind {
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
                ecu::fetch_reset_kind(
                    &self.server_url,
                    comp,
                    gw.as_deref(),
                    update_id,
                    &token,
                    self.insecure,
                    self.ca_cert_pem.as_deref(),
                )
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

        // 3. Local: concurrent per-component restart + boot_id verify.
        if !local.is_empty() {
            let mut set = tokio::task::JoinSet::new();
            for (comp, gw, _update_id) in local {
                let url = self.server_url.clone();
                let token = self.token.token(&comp).await?;
                let secs = self.timeouts.local_reset_secs;
                let insecure = self.insecure;
                let ca_cert_pem = self.ca_cert_pem.clone();
                set.spawn(async move {
                    let result = ecu::restart_and_verify(
                        &url,
                        &comp,
                        gw.as_deref(),
                        secs,
                        &token,
                        insecure,
                        ca_cert_pem.as_deref(),
                    )
                    .await;
                    (comp, result)
                });
            }
            collect_results(&mut set, ecus, EcuState::Activated, &mut first_err).await;
        }

        // 4. RequiresEcuReset: one coalesced node restart, then verify each
        //    staged component rebooted-and-ready via /status (boot_id changed).
        for (gateway_id, comps) in by_ecu {
            // Capture each component's heartbeat boot_id BEFORE the reboot — a
            // *changed* boot_id afterwards proves a fresh guest lifetime (the
            // reboot took effect). Absent for offline/non-heartbeat components →
            // wait_activated falls back to the observed server down→up.
            let mut baselines: BTreeMap<String, Option<u32>> = BTreeMap::new();
            // ALSO capture the NODE boot_id baseline per component (the MM stamps
            // the same node nonce on every component's status). A changed
            // node_boot_id after the reboot is the unmissable witness for
            // no-heartbeat components (host-os) — see ecu::wait_activated.
            let mut node_baselines: BTreeMap<String, Option<String>> = BTreeMap::new();
            for (comp_id, _) in &comps {
                let token = self.token.token(comp_id).await?;
                baselines.insert(
                    comp_id.clone(),
                    ecu::read_boot_id(
                        &self.server_url,
                        comp_id,
                        &token,
                        self.insecure,
                        self.ca_cert_pem.as_deref(),
                    )
                    .await,
                );
                node_baselines.insert(
                    comp_id.clone(),
                    ecu::read_node_boot_id(
                        &self.server_url,
                        comp_id,
                        &token,
                        self.insecure,
                        self.ca_cert_pem.as_deref(),
                    )
                    .await,
                );
            }
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

            // Verify each staged component rebooted-and-ready, concurrently so
            // all observe the node-down window together. A changed heartbeat
            // boot_id + status==ready ⇒ Activated (the reboot took effect and the
            // guest is healthy); `commit_all`'s node verdict then commits the
            // whole in-trial set at once (the update *session* is the commit
            // unit) — no per-component `/updates` session to re-attach (the
            // reboot wiped it).
            let mut set = tokio::task::JoinSet::new();
            for (comp_id, _update_id) in comps {
                let url = self.server_url.clone();
                let secs = self.timeouts.ecu_reset_activation_secs;
                // Post-202 token: the device is mid-respawn, so a *minting*
                // TokenSource (which reads the device boot_id to bind the token to
                // the current boot) can transiently fail at the connect level. That
                // is the reboot's down-window, NOT a fatal error — retry to a fresh
                // post-reboot token within the activation budget instead of aborting
                // the flash. (Field bug: this read PROPAGATED and killed the
                // campaign. The pre-restart baseline token can't be reused — it is
                // boot-bound and invalid once the boot moves.)
                let token = self.token_through_reboot(&comp_id, secs).await?;
                let baseline = baselines.get(&comp_id).copied().flatten();
                let node_baseline = node_baselines.get(&comp_id).cloned().flatten();
                let insecure = self.insecure;
                let ca_cert_pem = self.ca_cert_pem.clone();
                set.spawn(async move {
                    let result = ecu::wait_activated(
                        &url,
                        &comp_id,
                        baseline,
                        node_baseline,
                        secs,
                        &token,
                        insecure,
                        ca_cert_pem.as_deref(),
                    )
                    .await;
                    (comp_id, result)
                });
            }
            collect_results(&mut set, ecus, EcuState::Activated, &mut first_err).await;
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
            // Use restart_and_verify (capture boot_id → restart → wait for a fresh
            // ready lifetime) rather than trigger + a bare reachability ping: the
            // ping returns on the still-alive pre-restart instance, letting the
            // next step race a not-yet-restarted component (same class of bug as
            // the node path above). restart_and_verify waits for the reboot to be
            // WITNESSED before we proceed.
            let outcome = ecu::restart_and_verify(
                &self.server_url,
                &comp,
                gw.as_deref(),
                self.timeouts.local_reset_secs,
                &token,
                self.insecure,
                self.ca_cert_pem.as_deref(),
            )
            .await;
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
            // Witness the reboot, don't just ping. `system_restart` is async — it
            // returns 202 while the OLD supernova is still up, and the actual
            // restart fires seconds later (esp. behind the reboot_host VM/loopback
            // teardown). A bare reachability ping (`wait_reachable`) returns on that
            // still-alive old instance, so the campaign races into the NEXT step,
            // opens a /updates session, and the delayed restart then wipes the
            // in-memory session → `prepare` 404 (reliably, on high-latency links).
            // So: capture the node per-boot nonce BEFORE the restart, then wait for
            // it to CHANGE (+ status ready) via wait_activated — the same
            // reboot-witnessed converge the banked/trial path uses. The next step
            // only starts once the node is genuinely back on a fresh boot. Use the
            // first component as the witness (node_boot_id is node-wide).
            let witness = comps.first().cloned().unwrap_or_default();
            let witness_token = self.token.token(&witness).await.unwrap_or_default();
            // Capture BOTH baselines before the restart (mirror the banked path):
            // the node per-boot nonce (the unmissable no-heartbeat witness) AND the
            // witness component's heartbeat boot_id if it has one. With the
            // fail-closed `wait_activated`, hard-coding `None` here would leave the
            // reboot unwitnessed unless node_boot_id/down→up fired — so pass the
            // heartbeat baseline too and require a REAL witness.
            let hb_baseline = ecu::read_boot_id(
                &self.server_url,
                &witness,
                &witness_token,
                self.insecure,
                self.ca_cert_pem.as_deref(),
            )
            .await;
            let node_baseline = ecu::read_node_boot_id(
                &self.server_url,
                &witness,
                &witness_token,
                self.insecure,
                self.ca_cert_pem.as_deref(),
            )
            .await;
            let outcome = match self.sovd_client(restart_key).await {
                Ok(client) => match client.system_restart(gateway_id.as_deref(), "hard").await {
                    Ok(_) => {
                        ecu::wait_activated(
                            &self.server_url,
                            &witness,
                            hb_baseline,
                            node_baseline,
                            self.timeouts.ecu_reset_activation_secs,
                            &witness_token,
                            self.insecure,
                            self.ca_cert_pem.as_deref(),
                        )
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
        // Manual `commit-trials` verb: no component list, so the verdict is correlated
        // (nonce / unique execution id) and its completed status enforced, but no
        // per-component content is checked. An old constant-id device that cannot be
        // correlated (and has no `expected` set to content-match) is refused.
        self.commit_node_trials_for(&[]).await
    }

    /// [`commit_node_trials`](Self::commit_node_trials) with the components the
    /// caller expects the verdict to have committed — they must appear in the
    /// record's `committed` set (else a verdict that acted on a stale/empty
    /// in-trial set would pass). Empty ⇒ correlation + completed status only, and an
    /// uncorrelated old-device response has nothing to exact-match, so it is refused.
    async fn commit_node_trials_for(&self, expected: &[String]) -> Result<(), EngineError> {
        let token = self.token.token("").await?;
        ecu::commit_node_trials(
            &self.server_url,
            expected,
            &token,
            self.insecure,
            self.ca_cert_pem.as_deref(),
        )
        .await
    }

    /// Issue the node-level **rollback** verdict directly — see
    /// [`commit_node_trials`](Self::commit_node_trials).
    pub async fn rollback_node_trials(&self) -> Result<(), EngineError> {
        self.rollback_node_trials_for(&[]).await
    }

    /// [`rollback_node_trials`](Self::rollback_node_trials) with the components the
    /// caller expects in the record's `rolled_back` set.
    async fn rollback_node_trials_for(&self, expected: &[String]) -> Result<(), EngineError> {
        let token = self.token.token("").await?;
        ecu::rollback_node_trials(
            &self.server_url,
            expected,
            &token,
            self.insecure,
            self.ca_cert_pem.as_deref(),
        )
        .await
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
            let expected: Vec<String> = to_commit.iter().map(|(c, _, _)| c.clone()).collect();
            self.commit_node_trials_for(&expected).await?;
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
            let expected: Vec<String> = to_rollback.iter().map(|(c, _, _)| c.clone()).collect();
            self.rollback_node_trials_for(&expected).await?;
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

    /// Run a multi-step campaign on **one committed baseline**: for each step in
    /// order, `guard → stage → reset → health-gate → commit | rollback + abort`.
    /// A healthy step commits its trial (unless `no_commit`) so the next step
    /// builds on a committed baseline; an unhealthy step rolls its trial back and
    /// **aborts the chain** (returns [`EngineError::CampaignAborted`]) — never
    /// proceed on a bad baseline. `health` is the injected gate (default
    /// [`CameUp`]); each step's `force_ecu_reset` sets its activation mode (a
    /// banked group = one coalesced node reboot). `no_commit` leaves healthy
    /// banked steps in trial (`Activated`) for a manual verdict.
    ///
    /// This is the shared per-step lifecycle both front-ends use: the campaign and
    /// the rig produce the ordered steps + supply a token / health probe; the loop
    /// lives here, once.
    pub async fn run_campaign(
        &self,
        steps: Vec<CampaignStep>,
        health: &dyn HealthCheck,
        no_commit: bool,
    ) -> Result<CampaignReport, EngineError> {
        let mut committed: Vec<EcuStatus> = Vec::new();
        for (idx, step) in steps.into_iter().enumerate() {
            // Each step activates in its own mode — a banked group coalesces into
            // one node reboot — so reconfigure force per step (cheap clone; shares
            // the token Arc).
            let eng = self.clone().with_force_ecu_reset(step.force_ecu_reset);
            let plan = FlashPlan { jobs: step.jobs };
            eng.guard(&plan).await?;
            let mut ecus = eng.stage_all(&plan).await?;
            eng.reset_all(&mut ecus).await?;

            if !health.is_healthy(&ecus).await? {
                // Unhealthy: roll this step's trial back, then abort — don't commit
                // a bad baseline, and don't run later steps on top of it.
                warn!(
                    step = idx,
                    "campaign step unhealthy after reset — rolling back + aborting"
                );
                if let Err(e) = eng.rollback_all(&mut ecus).await {
                    warn!(step = idx, error = %e, "rollback of unhealthy step also failed");
                }
                return Err(EngineError::CampaignAborted {
                    step: idx,
                    reason: "system did not come up healthy after reset".to_string(),
                });
            }

            if !no_commit {
                eng.commit_all(&mut ecus).await?;
            }
            committed.extend(ecus);
        }
        Ok(CampaignReport { ecus: committed })
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
        let flash_client = ecu::build_flash_client(
            &self.server_url,
            component_id,
            gateway_id,
            &token,
            self.insecure,
            self.ca_cert_pem.as_deref(),
        )?;
        flash_client
            .attach(update_id)
            .await
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("attach: {e}"),
            })?;
        let body = flash_client
            .spec_commit()
            .await
            .map_err(|e| EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!("spec_commit: {e}"),
            })?;
        // spec_commit polls until the execute phase is *terminal* — but "terminal"
        // includes `failed`, which the poll returns as Ok(body). A bare terminal
        // is not success: require the verdict to have actually completed. (The
        // §7.14 execution-record correlation + `result` fields validated on the node
        // path are NOT part of the spec `UpdateStatusBody`; `status` is the
        // strongest check this per-component spec wire exposes.)
        if body.status != "completed" {
            return Err(EngineError::FlashFailed {
                component: component_id.to_string(),
                message: format!(
                    "spec_commit ended at {}/{}{}",
                    body.phase,
                    body.status,
                    body.error
                        .map(|e| format!(": {}", e.message))
                        .unwrap_or_default()
                ),
            });
        }
        Ok(())
    }

    /// Rollback one component — pure SOVD (attach + spec_rollback).
    async fn rollback_one(
        &self,
        component_id: &str,
        gateway_id: Option<&str>,
        update_id: &str,
    ) -> Result<(), EngineError> {
        let token = self.token.token(component_id).await?;
        let flash_client = ecu::build_flash_client(
            &self.server_url,
            component_id,
            gateway_id,
            &token,
            self.insecure,
            self.ca_cert_pem.as_deref(),
        )?;
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
    /// The component's declared reset kind, off the stable `x-sumo-update-mode`
    /// data param. `None` = the probe FAILED (client/read/parse — each logged);
    /// the caller picks the safe default. A device legitimately declaring "no
    /// reset needed" comes back as `Some(ResetKind::None)` — the two must not
    /// be conflated (a silent fallback here once skipped the RT/M7 reboot).
    async fn component_reset_kind(&self, comp: &str) -> Option<sovd_core::ResetKind> {
        let client = match self.sovd_client(comp).await {
            Ok(c) => c,
            Err(e) => {
                warn!(component = %comp, error = %e, "update-mode probe: no SOVD client/token");
                return None;
            }
        };
        let resp = match client.read_data(comp, "x-sumo-update-mode").await {
            Ok(r) => r,
            Err(e) => {
                warn!(component = %comp, error = %e, "update-mode probe: read failed");
                return None;
            }
        };
        match serde_json::from_value::<UpdateModeProbe>(resp.value) {
            Ok(mode) => Some(match mode.reset_kind.as_str() {
                "requires_ecu_reset" => sovd_core::ResetKind::RequiresEcuReset,
                "local" => sovd_core::ResetKind::Local,
                _ => sovd_core::ResetKind::None,
            }),
            Err(e) => {
                warn!(component = %comp, error = %e, "update-mode probe: unparseable payload");
                None
            }
        }
    }

    /// Acquire `component_id`'s token, tolerating the device being transiently
    /// unreachable — used ONLY on the witness path AFTER a restart 202. A minting
    /// [`TokenSource`](crate::TokenSource) reads the device boot_id to bind the
    /// token to the current boot; mid-respawn that read fails, which is the
    /// reboot's down-window, NOT a fatal campaign error (the field abort this
    /// guards). The token error is opaque, so ANY failure is retried within
    /// `budget_secs` — by reset time staging has already minted tokens
    /// successfully, so a failure here is the reboot window, not a config error.
    /// Returns a FRESH post-reboot token once the node answers; only the deadline
    /// surfaces the failure. Tokens minted BEFORE the restart stay fatal-on-error
    /// (the device must be up to stage) and are never reused here — they are
    /// boot-bound and rejected once the boot moves.
    async fn token_through_reboot(
        &self,
        component_id: &str,
        budget_secs: u64,
    ) -> Result<String, EngineError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(budget_secs);
        loop {
            match self.token.token(component_id).await {
                Ok(token) => return Ok(token),
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    warn!(
                        component = %component_id,
                        error = %e,
                        "token unavailable (device likely mid-reboot) — retrying within the activation budget"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Build a base-URL `SovdClient` for `key` (a component or gateway id),
    /// bearing that key's token when non-empty. Used for entity-root restart
    /// and the update-mode guard.
    async fn sovd_client(&self, key: &str) -> Result<SovdClient, EngineError> {
        let token = self.token.token(key).await?;
        let ca = self.ca_cert_pem.as_deref();
        let client = if token.is_empty() {
            SovdClient::new_verifying(&self.server_url, self.insecure, ca)
        } else {
            SovdClient::with_bearer_token_verifying(&self.server_url, &token, self.insecure, ca)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn engine_with(token: Arc<dyn TokenSource>) -> FlashEngine {
        FlashEngine::new(
            "http://127.0.0.1:0",
            token,
            Vec::new(),
            EngineTimeouts::default(),
            false,
            None,
        )
    }

    /// A minting TokenSource that fails its first `fail_n` calls (the device
    /// unreachable mid-respawn — the field error was a boot-id GET that could not
    /// connect), then mints a token once the node answers.
    struct FlakyToken {
        calls: AtomicU32,
        fail_n: u32,
    }
    #[async_trait::async_trait]
    impl TokenSource for FlakyToken {
        async fn token(&self, _component_id: &str) -> Result<String, EngineError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_n {
                Err(EngineError::Internal(
                    "read boot id from https://dev/vehicle/v1/status/x-sumo-boot-id: \
                     error sending request"
                        .into(),
                ))
            } else {
                Ok("fresh-post-reboot-token".into())
            }
        }
    }

    struct AlwaysFail;
    #[async_trait::async_trait]
    impl TokenSource for AlwaysFail {
        async fn token(&self, _component_id: &str) -> Result<String, EngineError> {
            Err(EngineError::Internal(
                "read boot id: error sending request".into(),
            ))
        }
    }

    // A post-202 token read that fails while the device is mid-reboot must NOT
    // abort the flash — retry through the down-window and return the FRESH token
    // once the node answers.
    #[tokio::test(start_paused = true)]
    async fn token_through_reboot_recovers_after_transient_failure() {
        let src = Arc::new(FlakyToken {
            calls: AtomicU32::new(0),
            fail_n: 3,
        });
        let eng = engine_with(src.clone());
        let token = eng.token_through_reboot("vm1", 300).await.unwrap();
        assert_eq!(token, "fresh-post-reboot-token");
        assert!(
            src.calls.load(Ordering::SeqCst) >= 4,
            "should have retried through the down-window"
        );
    }

    // A device that never comes back ends the wait at the DEADLINE with the token
    // error — bounded, never a hang and never an immediate abort.
    #[tokio::test(start_paused = true)]
    async fn token_through_reboot_errors_at_deadline_not_immediately() {
        let eng = engine_with(Arc::new(AlwaysFail));
        let err = eng.token_through_reboot("vm1", 10).await.unwrap_err();
        assert!(matches!(err, EngineError::Internal(_)), "got: {err:?}");
    }
}
