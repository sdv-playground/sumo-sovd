//! Engine-level integration tests: drive `FlashEngine` directly (NoAuth) against
//! an in-process sovd-api server with a simulated flash backend. Mirrors
//! `orchestrator/tests/campaign_tests.rs` but exercises the lifted execution
//! core without the campaign adapter or UDS unlock (the test backend doesn't
//! enforce security, exactly as the engine's `NoAuth` path assumes).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::{
    Capabilities, DataValue, EntityInfo, FaultFilter, FaultsResult, OperationExecution,
    OperationInfo, ParameterInfo, SecurityMode, SecurityState, SessionMode,
};
use sovd_core::{
    ActivationState, DiagnosticBackend, EntityStatus, EntityStatusBody, FlashProgress, FlashState,
    FlashStatus, PackageInfo, PackageStatus, VerifyResult,
};

use sumo_sovd_flash_engine::{
    CameUp, CampaignStep, EcuState, EcuStatus, EngineError, EngineTimeouts, FlashEngine, FlashJob,
    FlashPlan, HealthCheck, NoAuth, UpdateType,
};

// Off-board toolkit — builds + signs a real SUIT disable envelope so the
// engine's own validate/classify path (not the opaque-firmware fallback) runs.
use sumo_offboard::image_builder::ImageManifestBuilder;
use sumo_offboard::keygen;

// =============================================================================
// Test backend — simulates the flash lifecycle in-memory.
// =============================================================================

struct TestBackend {
    info: EntityInfo,
    caps: Capabilities,
    session: RwLock<String>,
    security_unlocked: RwLock<bool>,
    packages: RwLock<Vec<(String, Vec<u8>)>>,
    flash_state: RwLock<FlashState>,
    transfer_counter: AtomicU32,
    reset_count: AtomicU32,
    /// Heartbeat boot_id surfaced in `/status`; `ecu_reset` bumps it to simulate
    /// a fresh guest lifetime (the reboot the orchestrator witnesses).
    boot_id: AtomicU32,
    update_mode: RwLock<Option<(bool, String)>>,
    fail_flash: RwLock<Option<String>>,
}

impl TestBackend {
    fn new(id: &str) -> Self {
        Self {
            info: EntityInfo {
                id: id.to_string(),
                name: id.to_string(),
                entity_type: "ecu".to_string(),
                description: None,
                href: format!("/vehicle/v1/components/{id}"),
                status: None,
            },
            caps: Capabilities {
                software_update: true,
                sessions: true,
                security: true,
                ..Default::default()
            },
            session: RwLock::new("default".into()),
            security_unlocked: RwLock::new(false),
            packages: RwLock::new(Vec::new()),
            flash_state: RwLock::new(FlashState::Complete),
            transfer_counter: AtomicU32::new(0),
            reset_count: AtomicU32::new(0),
            boot_id: AtomicU32::new(1),
            update_mode: RwLock::new(None),
            fail_flash: RwLock::new(None),
        }
    }

    /// Make this backend report `x-ota-update-mode` (supports_rollback +
    /// reset_kind) — for the no-mix guard + committed-singleshot reset tests.
    fn set_update_mode(&self, supports_rollback: bool, reset_kind: &str) {
        *self.update_mode.write() = Some((supports_rollback, reset_kind.to_string()));
    }

    fn reset_count(&self) -> u32 {
        self.reset_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DiagnosticBackend for TestBackend {
    fn entity_info(&self) -> &EntityInfo {
        &self.info
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        Ok(vec![])
    }
    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        if param_ids.iter().any(|p| p == "x-ota-update-mode") {
            if let Some((supports_rollback, reset_kind)) = self.update_mode.read().clone() {
                return Ok(vec![DataValue::new(
                    "x-ota-update-mode",
                    "x-ota-update-mode",
                    serde_json::json!({
                        "update_mode": if supports_rollback { "banked" } else { "singleshot" },
                        "supports_rollback": supports_rollback,
                        "reset_kind": reset_kind,
                    }),
                )]);
            }
        }
        Ok(vec![])
    }
    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        Ok(FaultsResult {
            faults: vec![],
            status_availability_mask: None,
        })
    }
    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        Ok(vec![])
    }
    async fn start_operation(
        &self,
        _op_id: &str,
        _params: &[u8],
    ) -> BackendResult<OperationExecution> {
        Err(BackendError::NotSupported("start_operation".into()))
    }
    async fn set_session_mode(&self, session: &str) -> BackendResult<SessionMode> {
        *self.session.write() = session.to_string();
        Ok(SessionMode {
            mode: "session".into(),
            session: session.to_string(),
            session_id: if session == "programming" { 2 } else { 1 },
        })
    }
    async fn get_session_mode(&self) -> BackendResult<SessionMode> {
        let current = self.session.read().clone();
        let id = if current == "programming" { 2 } else { 1 };
        Ok(SessionMode {
            mode: "session".into(),
            session: current,
            session_id: id,
        })
    }
    async fn set_security_mode(
        &self,
        value: &str,
        key: Option<&[u8]>,
    ) -> BackendResult<SecurityMode> {
        if value.contains("requestseed") {
            Ok(SecurityMode {
                mode: "security".into(),
                state: SecurityState::SeedAvailable,
                level: Some(1),
                available_levels: Some(vec![1]),
                seed: Some("aabb".into()),
            })
        } else if key.is_some() {
            *self.security_unlocked.write() = true;
            Ok(SecurityMode {
                mode: "security".into(),
                state: SecurityState::Unlocked,
                level: Some(1),
                available_levels: Some(vec![1]),
                seed: None,
            })
        } else {
            Err(BackendError::InvalidRequest("bad security request".into()))
        }
    }
    async fn get_security_mode(&self) -> BackendResult<SecurityMode> {
        let unlocked = *self.security_unlocked.read();
        Ok(SecurityMode {
            mode: "security".into(),
            state: if unlocked {
                SecurityState::Unlocked
            } else {
                SecurityState::Locked
            },
            level: if unlocked { Some(1) } else { None },
            available_levels: Some(vec![1]),
            seed: None,
        })
    }
    async fn receive_package(&self, data: &[u8]) -> BackendResult<String> {
        let id = format!("pkg-{}", self.packages.read().len());
        self.packages.write().push((id.clone(), data.to_vec()));
        Ok(id)
    }
    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        let packages = self.packages.read();
        let (id, data) = packages
            .iter()
            .find(|(id, _)| id == package_id)
            .ok_or_else(|| {
                BackendError::InvalidRequest(format!("package not found: {package_id}"))
            })?;
        Ok(PackageInfo {
            id: id.clone(),
            size: data.len(),
            target_ecu: None,
            version: None,
            status: PackageStatus::Pending,
            created_at: None,
        })
    }
    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        let packages = self.packages.read();
        if packages.iter().any(|(id, _)| id == package_id) {
            Ok(VerifyResult {
                valid: true,
                checksum: Some("deadbeef".into()),
                algorithm: Some("crc32".into()),
                error: None,
            })
        } else {
            Err(BackendError::InvalidRequest(format!(
                "package not found: {package_id}"
            )))
        }
    }
    async fn start_flash(&self) -> BackendResult<String> {
        if let Some(msg) = self.fail_flash.read().as_ref() {
            return Err(BackendError::Internal(msg.clone()));
        }
        let tid = format!(
            "xfer-{}",
            self.transfer_counter.fetch_add(1, Ordering::SeqCst)
        );
        *self.flash_state.write() = FlashState::AwaitingActivation;
        Ok(tid)
    }
    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let state = *self.flash_state.read();
        Ok(FlashStatus {
            transfer_id: transfer_id.to_string(),
            package_id: "pkg-0".into(),
            state,
            progress: Some(FlashProgress {
                bytes_transferred: 100,
                bytes_total: 100,
                blocks_transferred: 1,
                blocks_total: 1,
                percent: 100.0,
            }),
            error: None,
        })
    }
    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        Ok(vec![])
    }
    async fn finalize_flash(&self) -> BackendResult<()> {
        *self.flash_state.write() = FlashState::AwaitingReboot;
        Ok(())
    }
    async fn ecu_reset(&self, _reset_type: u8) -> BackendResult<Option<u8>> {
        self.reset_count.fetch_add(1, Ordering::SeqCst);
        // New guest lifetime → a fresh boot_id the orchestrator witnesses via /status.
        self.boot_id.fetch_add(1, Ordering::SeqCst);
        *self.session.write() = "default".into();
        *self.security_unlocked.write() = false;
        *self.flash_state.write() = FlashState::Activated;
        Ok(None)
    }
    async fn read_entity_status(&self) -> BackendResult<EntityStatusBody> {
        let mut runtime = serde_json::Map::new();
        runtime.insert(
            "boot_id".into(),
            serde_json::json!(self.boot_id.load(Ordering::SeqCst)),
        );
        let mut extensions = serde_json::Map::new();
        extensions.insert("x-runtime".into(), serde_json::Value::Object(runtime));
        Ok(EntityStatusBody {
            status: EntityStatus::Ready,
            extensions,
            ..Default::default()
        })
    }
    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        Ok(ActivationState {
            supports_rollback: true,
            state: *self.flash_state.read(),
            active_version: Some("1.0.0".into()),
            previous_version: Some("0.9.0".into()),
            reset_kind: sovd_core::ResetKind::Local,
        })
    }
    async fn commit_flash(&self) -> BackendResult<()> {
        *self.flash_state.write() = FlashState::Committed;
        Ok(())
    }
    async fn rollback_flash(&self) -> BackendResult<()> {
        *self.flash_state.write() = FlashState::RolledBack;
        Ok(())
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Minimal COSE_Key CBOR — Validator::new requires valid CBOR; validate_envelope
/// then returns Err on our non-SUIT test packages (caught as opaque firmware).
fn dummy_trust_anchor() -> Vec<u8> {
    let mut key = vec![0xA3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[0u8; 32]);
    key
}

async fn serve(
    backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = sovd_api::AppState::new(backends);
    let app = sovd_api::create_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{port}"), handle)
}

fn engine(server_url: &str) -> FlashEngine {
    FlashEngine::new(
        server_url.to_string(),
        Arc::new(NoAuth),
        dummy_trust_anchor(),
        EngineTimeouts::default(),
        false,
        None,
    )
}

fn plan(jobs: &[(&str, &[u8])]) -> FlashPlan {
    FlashPlan {
        jobs: jobs
            .iter()
            .map(|(id, env)| FlashJob {
                component_id: id.to_string(),
                gateway_id: None,
                envelope: env.to_vec(),
                payloads: vec![],
            })
            .collect(),
    }
}

async fn stage_and_reset(eng: &FlashEngine, p: &FlashPlan) -> Vec<EcuStatus> {
    let mut ecus = eng.stage_all(p).await.unwrap();
    eng.reset_all(&mut ecus).await.unwrap();
    ecus
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn engine_flash_and_commit() {
    let backend = Arc::new(TestBackend::new("ecu1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), backend.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let mut ecus = stage_and_reset(&eng, &plan(&[("ecu1", &[0xDE, 0xAD])])).await;
    assert_eq!(ecus.len(), 1);
    assert_eq!(ecus[0].state, EcuState::Activated);
    assert_eq!(ecus[0].component_id, "ecu1");

    eng.commit_all(&mut ecus).await.unwrap();
    assert_eq!(*backend.flash_state.read(), FlashState::Committed);
    assert_eq!(ecus[0].state, EcuState::Committed);
}

#[tokio::test]
async fn engine_flash_and_rollback() {
    let backend = Arc::new(TestBackend::new("ecu1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), backend.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let mut ecus = stage_and_reset(&eng, &plan(&[("ecu1", &[0xDE, 0xAD])])).await;
    assert_eq!(ecus[0].state, EcuState::Activated);

    eng.rollback_all(&mut ecus).await.unwrap();
    assert_eq!(*backend.flash_state.read(), FlashState::RolledBack);
}

#[tokio::test]
async fn engine_multi_ecu_flash_and_commit() {
    let b1 = Arc::new(TestBackend::new("ecu1"));
    let b2 = Arc::new(TestBackend::new("ecu2"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), b1.clone());
    backends.insert("ecu2".into(), b2.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let mut ecus = stage_and_reset(&eng, &plan(&[("ecu1", &[0x01]), ("ecu2", &[0x02])])).await;
    assert_eq!(ecus.len(), 2);
    assert!(ecus.iter().all(|e| e.state == EcuState::Activated));

    eng.commit_all(&mut ecus).await.unwrap();
    assert_eq!(*b1.flash_state.read(), FlashState::Committed);
    assert_eq!(*b2.flash_state.read(), FlashState::Committed);
}

#[tokio::test]
async fn engine_stage_failure_triggers_rollback() {
    let b1 = Arc::new(TestBackend::new("ecu1"));
    let b2 = Arc::new(TestBackend::new("ecu2"));
    *b2.fail_flash.write() = Some("simulated flash failure".into());
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), b1.clone());
    backends.insert("ecu2".into(), b2.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let err = eng
        .stage_all(&plan(&[("ecu1", &[0x01]), ("ecu2", &[0x02])]))
        .await;
    assert!(err.is_err(), "stage_all should fail when ecu2 fails");
    // ecu1 staged first, then the engine rolled it back when ecu2 failed.
    assert_eq!(*b1.flash_state.read(), FlashState::RolledBack);
}

#[tokio::test]
async fn stage_all_stages_node_reboot_component_last_to_clear_owed_reboot_gate() {
    // Field bug (autoloader, 2026-08-21): one step carried host
    // (requires_ecu_reset, banked) + vm1 (local, banked). Staged in plan order,
    // host went FIRST; its execute armed the device's owed-reboot gate, and vm1's
    // open_update was then refused 409 precondition-not-fulfilled — the engine
    // rolled the whole step back. The fix stages the node-arming component LAST,
    // so every non-arming open lands before the node bank is armed.
    //
    // The plan lists host FIRST on purpose: the OLD (unordered) staging trips the
    // gate here; the fix must reorder to [vm1, host].
    let host = Arc::new(TestBackend::new("host"));
    host.set_update_mode(true, "requires_ecu_reset");
    let vm1 = Arc::new(TestBackend::new("vm1"));
    vm1.set_update_mode(true, "local");
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("host".into(), host);
    backends.insert("vm1".into(), vm1);

    // Mirror the device's per-NODE owed-reboot gate as a router layer over the
    // real sovd-api: once the reboot-owing component (host) has executed, refuse
    // any further `/updates` open with 409. Record the open order to prove the
    // reorder, not merely that nothing failed.
    use axum::response::IntoResponse;
    let armed = Arc::new(AtomicBool::new(false));
    let opens = Arc::new(RwLock::new(Vec::<String>::new()));
    let (armed_l, opens_l) = (armed.clone(), opens.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = sovd_api::create_router(sovd_api::AppState::new(backends)).layer(
        axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let (armed, opens) = (armed_l.clone(), opens_l.clone());
                async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let is_open = method == axum::http::Method::POST && path.ends_with("/updates");
                    if is_open {
                        if armed.load(Ordering::SeqCst) {
                            // The device gate: no new flash while a reboot is owed.
                            return (
                                axum::http::StatusCode::CONFLICT,
                                "node owes an activation reboot for [\"host\"] — reboot or \
                                 roll back before starting a new flash",
                            )
                                .into_response();
                        }
                        if let Some(id) = path
                            .strip_prefix("/vehicle/v1/components/")
                            .and_then(|s| s.strip_suffix("/updates"))
                        {
                            opens.write().push(id.to_string());
                        }
                    }
                    let resp = next.run(req).await;
                    // host's execute (requires_ecu_reset, banked) arms the node.
                    if path.starts_with("/vehicle/v1/components/host/updates/")
                        && path.ends_with("/execute")
                    {
                        armed.store(true, Ordering::SeqCst);
                    }
                    resp
                }
            },
        ),
    );
    let _h = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let url = format!("http://127.0.0.1:{port}");
    let eng = engine(&url);

    // Plan lists host first; the fix must stage it last.
    let statuses = eng
        .stage_all(&plan(&[("host", &[0x01]), ("vm1", &[0x02])]))
        .await
        .expect("staging the arming component last clears the owed-reboot gate");

    // Both banked components reach Staged (awaiting-verdict) — none Failed.
    assert!(
        statuses.iter().all(|e| e.state == EcuState::Staged),
        "every component staged to awaiting-verdict, got {statuses:?}"
    );
    // The gate armed (host executed) and vm1 opened BEFORE host — the reorder.
    assert!(armed.load(Ordering::SeqCst), "host must have executed");
    assert_eq!(
        *opens.read(),
        vec!["vm1".to_string(), "host".to_string()],
        "the local-reset component must open before the node-arming one"
    );
}

/// Serve the real sovd-api with a middleware that reproduces the trial-recovery
/// wire: the FIRST `/updates` open is refused "in trial mode"; the NODE-level
/// `x-ota-update-state` probe answers `state_reply` (`Some(json)` ⇒ 200, `None`
/// ⇒ 404); `x-ota-force-rollback` is counted and answered 204; every later open
/// passes through to the real router. Returns `(url, force_rollback_hits,
/// open_attempts, handle)`.
async fn serve_trial_recovery(
    state_reply: Option<serde_json::Value>,
) -> (
    String,
    Arc<AtomicU32>,
    Arc<AtomicU32>,
    tokio::task::JoinHandle<()>,
) {
    use axum::response::IntoResponse;
    let backend = Arc::new(TestBackend::new("vm1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), backend);

    let rollbacks = Arc::new(AtomicU32::new(0));
    let opens = Arc::new(AtomicU32::new(0));
    let state_reply = Arc::new(state_reply);
    let (rollbacks_l, opens_l, state_l) = (rollbacks.clone(), opens.clone(), state_reply.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = sovd_api::create_router(sovd_api::AppState::new(backends)).layer(
        axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let (rollbacks, opens, state) =
                    (rollbacks_l.clone(), opens_l.clone(), state_l.clone());
                async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    // NODE-level update-state probe — a sumo-mm vendor route the
                    // reference sovd-api doesn't carry, served here.
                    if method == axum::http::Method::GET
                        && path == "/vehicle/v1/data/x-ota-update-state"
                    {
                        return match &*state {
                            Some(v) => axum::Json(v.clone()).into_response(),
                            None => (axum::http::StatusCode::NOT_FOUND, "no such resource")
                                .into_response(),
                        };
                    }
                    // Count + answer the trial-recovery rollback (204, like the device).
                    if method == axum::http::Method::PUT && path.ends_with("/x-ota-force-rollback")
                    {
                        rollbacks.fetch_add(1, Ordering::SeqCst);
                        return axum::http::StatusCode::NO_CONTENT.into_response();
                    }
                    // First open refused "in trial mode" (drives the recovery path);
                    // any later open passes through to the real router. `fetch_add`
                    // counts every open POST; only the first (== 0) is refused.
                    if method == axum::http::Method::POST
                        && path.ends_with("/updates")
                        && opens.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        return (
                            axum::http::StatusCode::CONFLICT,
                            "start_flash refused: bank set is in trial mode",
                        )
                            .into_response();
                    }
                    next.run(req).await
                }
            },
        ),
    );
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{port}"), rollbacks, opens, handle)
}

#[tokio::test]
async fn open_refused_in_trial_with_confirming_state_rolls_back_and_retries() {
    // x-ota-update-state confirms vm1 is genuinely mid-trial ⇒ the EXISTING
    // recovery fires: force_rollback once, then the open is retried and staging
    // completes.
    let (url, rollbacks, opens, _h) = serve_trial_recovery(Some(serde_json::json!({
        "phase": "Trial",
        "components": ["vm1"],
    })))
    .await;
    let eng = engine(&url);

    let statuses = eng
        .stage_all(&plan(&[("vm1", &[0xDE, 0xAD])]))
        .await
        .expect("confirmed in-trial ⇒ rollback + reopen succeeds");

    assert_eq!(
        rollbacks.load(Ordering::SeqCst),
        1,
        "force_rollback must fire exactly once on a confirmed trial"
    );
    assert!(
        opens.load(Ordering::SeqCst) >= 2,
        "open must be retried after the rollback"
    );
    assert_ne!(
        statuses[0].state,
        EcuState::Failed,
        "staging succeeds after recovery, got {statuses:?}"
    );
}

#[tokio::test]
async fn open_refused_in_trial_but_state_idle_does_not_roll_back() {
    // The refusal said "trial mode" but x-ota-update-state reports Idle (nothing
    // in trial) — a stale message / different gate. Rollback is destructive, so it
    // must NOT fire; the refusal is surfaced with the observed state.
    let (url, rollbacks, _opens, _h) = serve_trial_recovery(Some(serde_json::json!({
        "phase": "Idle",
        "components": [],
    })))
    .await;
    let eng = engine(&url);

    let err = eng
        .stage_all(&plan(&[("vm1", &[0xDE, 0xAD])]))
        .await
        .unwrap_err();

    assert_eq!(
        rollbacks.load(Ordering::SeqCst),
        0,
        "no rollback when the observed state is not an open trial"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("phase=Idle") && msg.contains("not auto-rolling back"),
        "error must carry the observed state: {msg}"
    );
}

#[tokio::test]
async fn open_refused_in_trial_but_state_probe_fails_does_not_roll_back() {
    // The update-state probe 404s (an older device lacking the resource). Without
    // positive confirmation the destructive rollback must NOT fire — the recovery
    // no longer auto-triggers for such devices (deliberate); the error notes the
    // failed probe.
    let (url, rollbacks, _opens, _h) = serve_trial_recovery(None).await;
    let eng = engine(&url);

    let err = eng
        .stage_all(&plan(&[("vm1", &[0xDE, 0xAD])]))
        .await
        .unwrap_err();

    assert_eq!(
        rollbacks.load(Ordering::SeqCst),
        0,
        "no rollback when the state probe fails"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("probe") && msg.contains("not auto-rolling back"),
        "error must note the failed state probe: {msg}"
    );
}

#[tokio::test]
async fn engine_reboots_committed_singleshot_with_reset_kind() {
    // A singleshot component (e.g. RT/M7) commits in stage_all but still needs a
    // reboot to RUN the new firmware. reset_all must reset it — driven by the
    // reset_kind it declares on x-ota-update-mode — with no trial/verdict.
    let backend = Arc::new(TestBackend::new("rt"));
    backend.set_update_mode(false, "local");
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("rt".into(), backend.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    // As stage_all leaves a singleshot component: Committed, carrying its update_id.
    let mut ecus = vec![EcuStatus {
        component_id: "rt".into(),
        gateway_id: None,
        state: EcuState::Committed,
        update_type: UpdateType::Firmware,
        active_version: None,
        previous_version: None,
        error: None,
        update_id: Some("xfer-0".into()),
    }];
    eng.reset_all(&mut ecus).await.unwrap();

    assert!(
        backend.reset_count() >= 1,
        "committed singleshot with reset_kind must be rebooted by reset_all"
    );
    assert_eq!(
        ecus[0].state,
        EcuState::Committed,
        "singleshot stays committed — no trial/verdict"
    );
}

#[tokio::test]
async fn engine_disable_manifest_is_removal_and_commits_via_execute() {
    // A signed SUIT *disable* manifest (no install/invoke, no payload) must
    // classify as Removal — NOT the Policy no-op — and route through
    // prepare/execute so the device enacts the deactivation, reaching Committed
    // with no trial/verdict (singleshot-irreversible).
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let trust_anchor = signing_key.public_key_bytes();
    let disable_envelope = ImageManifestBuilder::new()
        .component_id(vec!["rt".to_string()])
        .sequence_number(1)
        // Fixed iat (2023-11-14T22:13:20Z) — a constant, not now(), for reproducibility.
        .signing_time(1_700_000_000)
        .build_disable(&signing_key)
        .unwrap();

    let backend = Arc::new(TestBackend::new("rt"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("rt".into(), backend.clone());
    let (url, _h) = serve(backends).await;

    // The engine must trust the manifest's signing key — the dummy anchor the
    // other tests use makes validation fail (opaque-firmware fallback), which
    // would never reach `disable_target()`.
    let eng = FlashEngine::new(
        url,
        Arc::new(NoAuth),
        trust_anchor,
        EngineTimeouts::default(),
        false,
        None,
    );

    let ecus = eng
        .stage_all(&plan(&[("rt", disable_envelope.as_slice())]))
        .await
        .unwrap();
    assert_eq!(ecus.len(), 1);
    assert_eq!(
        ecus[0].update_type,
        UpdateType::Removal,
        "a disable manifest must classify as Removal, not Policy"
    );
    assert_eq!(
        ecus[0].state,
        EcuState::Committed,
        "a singleshot Removal auto-commits — irreversible, no trial/verdict"
    );
    // The Policy no-op path never calls prepare/execute, so the backend's flash
    // lifecycle would stay at its initial `Complete`. Removal drives it forward.
    assert_ne!(
        *backend.flash_state.read(),
        FlashState::Complete,
        "Removal must route through prepare/execute (device enacted the disable), \
         not the Policy no-op"
    );
}

#[tokio::test]
async fn engine_guard_rejects_mixed_rollbackable_and_irreversible() {
    // A banked (rollbackable) component bundled with a singleshot (irreversible)
    // one — a partial rollback would strand the irreversible write. guard rejects.
    let banked = Arc::new(TestBackend::new("vm1"));
    banked.set_update_mode(true, "requires_ecu_reset");
    let singleshot = Arc::new(TestBackend::new("rt"));
    singleshot.set_update_mode(false, "requires_ecu_reset");
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), banked);
    backends.insert("rt".into(), singleshot);
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let err = eng.guard(&plan(&[("vm1", &[0x01]), ("rt", &[0x02])])).await;
    assert!(
        matches!(err, Err(EngineError::MixedUpdateModes { .. })),
        "guard must reject a mixed banked + singleshot plan, got {err:?}"
    );
}

#[tokio::test]
async fn engine_guard_allows_all_rollbackable() {
    let b1 = Arc::new(TestBackend::new("vm1"));
    b1.set_update_mode(true, "local");
    let b2 = Arc::new(TestBackend::new("vm2"));
    b2.set_update_mode(true, "local");
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), b1);
    backends.insert("vm2".into(), b2);
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    assert!(eng
        .guard(&plan(&[("vm1", &[0x01]), ("vm2", &[0x02])]))
        .await
        .is_ok());
}

#[tokio::test]
async fn node_reboot_step_commits_via_node_verdict_not_per_component() {
    // saka's directive: on a node-reboot step the orchestrator must NOT commit
    // each component — the per-component `/updates` session is wiped by the
    // reboot, and the update *session* is the commit unit. `commit_all` under
    // `force_ecu_reset` must issue ONE entity-root node verdict and never touch
    // the per-component commit path (`attach` + `spec_commit` → `commit_flash`).
    let backend = Arc::new(TestBackend::new("vm1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), backend.clone());

    // Mock = the real sovd-api router + a stub for the node verdict op (the
    // real fan-out lives in vm-mgr; here we only assert the engine targets it).
    let hits = Arc::new(AtomicU32::new(0));
    let hits_route = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let node_op = axum::Router::new().route(
        "/vehicle/v1/operations/x-ota-commit-trials/executions",
        axum::routing::post(move || {
            let hits = hits_route.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                // A fresh, complete §7.14 execution record — what a real device
                // returns. The engine now validates completed status + freshness +
                // that the expected component (vm1) landed in `committed`.
                let now = chrono::Utc::now().to_rfc3339();
                axum::Json(serde_json::json!({
                    "execution_id": "x-ota-commit-trials",
                    "operation_id": "x-ota-commit-trials",
                    "status": "completed",
                    "result": { "committed": ["vm1"], "skipped": [] },
                    "started_at": now,
                    "completed_at": now,
                }))
            }
        }),
    );
    let app = sovd_api::create_router(sovd_api::AppState::new(backends)).merge(node_op);
    let _h = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let url = format!("http://127.0.0.1:{port}");

    let eng = FlashEngine::new(
        url,
        Arc::new(NoAuth),
        dummy_trust_anchor(),
        EngineTimeouts::default(),
        false,
        None,
    )
    .with_force_ecu_reset(true);

    // A firmware component already Activated by the (separately exercised)
    // node-reboot reset path.
    let mut ecus = vec![EcuStatus {
        component_id: "vm1".into(),
        gateway_id: None,
        state: EcuState::Activated,
        update_type: UpdateType::Firmware,
        active_version: None,
        previous_version: None,
        error: None,
        update_id: Some("vm1".into()),
    }];

    eng.commit_all(&mut ecus).await.unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "exactly one node-level verdict must be issued"
    );
    assert_eq!(ecus[0].state, EcuState::Committed);
    // The per-component commit path was bypassed — `commit_flash` would have
    // moved the backend to `Committed`; it stays at its construction state.
    assert_eq!(*backend.flash_state.read(), FlashState::Complete);
}

/// Build a node-verdict mock whose commit handler echoes a nonce chosen by
/// `echo_for(attempt_index, sent_nonce)` and counts hits — for the replay-retry
/// tests. Returns the base URL + the hit counter.
async fn serve_nonce_echo_verdict(
    backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    echo_for: impl Fn(u32, String) -> String + Clone + Send + Sync + 'static,
) -> (String, Arc<AtomicU32>) {
    let hits = Arc::new(AtomicU32::new(0));
    let hits_route = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let node_op = axum::Router::new().route(
        "/vehicle/v1/operations/x-ota-commit-trials/executions",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let hits = hits_route.clone();
            let echo_for = echo_for.clone();
            async move {
                let n = hits.fetch_add(1, Ordering::SeqCst);
                let sent = body
                    .get("nonce")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // A fresh, complete §7.14 record; the echoed nonce is what varies.
                let now = chrono::Utc::now().to_rfc3339();
                axum::Json(serde_json::json!({
                    "execution_id": format!("exec-{n}"),
                    "operation_id": "x-ota-commit-trials",
                    "status": "completed",
                    "result": { "committed": ["vm1"], "skipped": [] },
                    "started_at": now,
                    "completed_at": now,
                    "nonce": echo_for(n, sent),
                }))
            }
        }),
    );
    let app = sovd_api::create_router(sovd_api::AppState::new(backends)).merge(node_op);
    let _h = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{port}"), hits)
}

fn force_reset_engine(url: String) -> FlashEngine {
    FlashEngine::new(
        url,
        Arc::new(NoAuth),
        dummy_trust_anchor(),
        EngineTimeouts::default(),
        false,
        None,
    )
    .with_force_ecu_reset(true)
}

fn activated_vm1() -> Vec<EcuStatus> {
    vec![EcuStatus {
        component_id: "vm1".into(),
        gateway_id: None,
        state: EcuState::Activated,
        update_type: UpdateType::Firmware,
        active_version: None,
        previous_version: None,
        error: None,
        update_id: Some("vm1".into()),
    }]
}

#[tokio::test]
async fn node_verdict_retries_once_on_nonce_mismatch_then_succeeds() {
    // The field bug: a pooled connection answered a verdict POST with a PRIOR
    // execution's record. The engine now sends a fresh uuid4 nonce per POST and, on
    // a mismatched echo (the replay symptom), retries ONCE on a fresh connection.
    // Attempt 0 echoes a WRONG nonce → retry; attempt 1 echoes the sent nonce → ok.
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), Arc::new(TestBackend::new("vm1")));
    let (url, hits) = serve_nonce_echo_verdict(backends, |n, sent| {
        if n == 0 {
            "stale-prior-nonce".to_string()
        } else {
            sent
        }
    })
    .await;

    let eng = force_reset_engine(url);
    let mut ecus = activated_vm1();
    eng.commit_all(&mut ecus).await.unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "must retry exactly once on the nonce mismatch"
    );
    assert_eq!(ecus[0].state, EcuState::Committed);
}

#[tokio::test]
async fn node_verdict_fails_after_one_retry_on_persistent_replay() {
    // A persistent replay (every response echoes a WRONG nonce) fails after the
    // single retry — the engine never commits on an unverifiable verdict.
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("vm1".into(), Arc::new(TestBackend::new("vm1")));
    let (url, hits) =
        serve_nonce_echo_verdict(backends, |_n, _sent| "always-wrong".to_string()).await;

    let eng = force_reset_engine(url);
    let mut ecus = activated_vm1();
    let err = eng.commit_all(&mut ecus).await.unwrap_err();

    assert!(
        matches!(err, EngineError::FlashFailed { .. }),
        "got {err:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "one initial POST + exactly one retry, then fail"
    );
    assert_ne!(
        ecus[0].state,
        EcuState::Committed,
        "must not commit on an unverifiable verdict"
    );
}

#[tokio::test]
async fn commit_trials_does_not_clear_owed_reboot_gate_reflash_refused_cleanly() {
    // Field scenario: campaign 1 flashes "host" (banked, requires_ecu_reset) and
    // commits its trial via the node-verdict path (x-ota-commit-trials). Commit
    // makes the trial PERMANENT, but — mirroring the real device — does NOT clear
    // the node's owed-activation-reboot gate: that gate arms at `execute`
    // (staging-time; see
    // `stage_all_stages_node_reboot_component_last_to_clear_owed_reboot_gate`) and
    // only an actual reboot clears it. This test never calls `reset_all` — no
    // reboot happens anywhere in it — so campaign 2's IMMEDIATE re-flash of the
    // same node must still find the gate armed and be refused 409. The engine must
    // fail cleanly (FlashFailed), fire no rollback remedy, never reset the device
    // itself, and its stage_all abort-unwind must behave on the refusal.
    use axum::response::IntoResponse;

    let backend = Arc::new(TestBackend::new("host"));
    backend.set_update_mode(true, "requires_ecu_reset");
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("host".into(), backend.clone());

    // Node-verdict stub for x-ota-commit-trials — same uncorrelated-but-exact-
    // content-match shape as `node_reboot_step_commits_via_node_verdict_not_per_component`.
    let commit_hits = Arc::new(AtomicU32::new(0));
    let commit_hits_route = commit_hits.clone();
    let node_op = axum::Router::new().route(
        "/vehicle/v1/operations/x-ota-commit-trials/executions",
        axum::routing::post(move || {
            let commit_hits = commit_hits_route.clone();
            async move {
                commit_hits.fetch_add(1, Ordering::SeqCst);
                let now = chrono::Utc::now().to_rfc3339();
                axum::Json(serde_json::json!({
                    "execution_id": "x-ota-commit-trials",
                    "operation_id": "x-ota-commit-trials",
                    "status": "completed",
                    "result": { "committed": ["host"], "skipped": [] },
                    "started_at": now,
                    "completed_at": now,
                }))
            }
        }),
    );

    // The device's owed-reboot gate — same middleware pattern (and exact 409 wire
    // text) as `stage_all_stages_node_reboot_component_last_to_clear_owed_reboot_gate`:
    // armed once host's `execute` lands; while armed, any new `/updates` open is
    // refused. Also counts any rollback-shaped request (force-rollback, or the
    // per-component spec rollback) — must stay at 0 through campaign 2.
    let armed = Arc::new(AtomicBool::new(false));
    let opens = Arc::new(RwLock::new(Vec::<String>::new()));
    let rollback_hits = Arc::new(AtomicU32::new(0));
    let (armed_l, opens_l, rollback_hits_l) = (armed.clone(), opens.clone(), rollback_hits.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = sovd_api::create_router(sovd_api::AppState::new(backends))
        .merge(node_op)
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let (armed, opens, rollback_hits) =
                    (armed_l.clone(), opens_l.clone(), rollback_hits_l.clone());
                async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    if path.contains("rollback") {
                        rollback_hits.fetch_add(1, Ordering::SeqCst);
                    }
                    let is_open = method == axum::http::Method::POST && path.ends_with("/updates");
                    if is_open {
                        if armed.load(Ordering::SeqCst) {
                            // The device gate: no new flash while a reboot is owed.
                            // Only a reboot clears this — commit-trials does NOT.
                            return (
                                axum::http::StatusCode::CONFLICT,
                                "node owes an activation reboot for [\"host\"] — reboot or \
                                 roll back before starting a new flash",
                            )
                                .into_response();
                        }
                        if let Some(id) = path
                            .strip_prefix("/vehicle/v1/components/")
                            .and_then(|s| s.strip_suffix("/updates"))
                        {
                            opens.write().push(id.to_string());
                        }
                    }
                    let resp = next.run(req).await;
                    if path.starts_with("/vehicle/v1/components/host/updates/")
                        && path.ends_with("/execute")
                    {
                        armed.store(true, Ordering::SeqCst);
                    }
                    resp
                }
            },
        ));
    let _h = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let url = format!("http://127.0.0.1:{port}");
    let eng = force_reset_engine(url);

    // --- Campaign 1: stage host (arms the gate at execute), then commit via the
    // node-verdict path. No `reset_all` call anywhere in this test — campaign 1's
    // activation is set directly on the status (as
    // `node_reboot_step_commits_via_node_verdict_not_per_component` also does), so
    // `commit_all`'s node path has an Activated component to commit WITHOUT the
    // engine ever issuing a real device reboot. That isolates exactly the
    // distinction under test: commit succeeding is not the same as a reboot.
    let mut ecus = eng
        .stage_all(&plan(&[("host", &[0x01])]))
        .await
        .expect("campaign 1 staging succeeds — the gate isn't armed yet");
    assert_eq!(ecus[0].state, EcuState::Staged);
    assert!(
        armed.load(Ordering::SeqCst),
        "host's execute must arm the owed-reboot gate"
    );

    ecus[0].state = EcuState::Activated;
    eng.commit_all(&mut ecus)
        .await
        .expect("commit-trials succeeds");
    assert_eq!(ecus[0].state, EcuState::Committed);
    assert_eq!(
        commit_hits.load(Ordering::SeqCst),
        1,
        "commit-trials must have been issued exactly once"
    );
    let reset_count_after_c1 = backend.reset_count();
    assert_eq!(
        reset_count_after_c1, 0,
        "no reboot occurs anywhere in this test, campaign 1 included"
    );

    // --- Campaign 2: an IMMEDIATE re-flash of the same node, no reboot in between.
    let err = eng
        .stage_all(&plan(&[("host", &[0x02])]))
        .await
        .expect_err("commit does not clear the owed-reboot gate — the reopen must be refused");

    // (a) A clean FlashFailed outcome for the right component — not a hang, not a
    // misrouted success.
    assert!(
        matches!(&err, EngineError::FlashFailed { component, .. } if component.as_str() == "host"),
        "expected FlashFailed for host, got {err:?}"
    );
    let msg = err.to_string();
    // (e) The owed-reboot refusal text, NOT the trial-recovery text — the
    // "trial mode" special case (ecu.rs open_update_or_rollback_pending) must not
    // trigger on this message.
    assert!(
        msg.contains("owes an activation reboot"),
        "must surface the owed-reboot refusal, got: {msg}"
    );
    assert!(
        !msg.contains("trial mode"),
        "must NOT be misclassified as the trial-recovery path, got: {msg}"
    );

    // (b) No rollback of any kind was issued by the engine.
    assert_eq!(
        rollback_hits.load(Ordering::SeqCst),
        0,
        "the engine must not fire any rollback/force-rollback remedy"
    );
    // (d) Nothing from campaign 2 ever reached a successful open — the recorded
    // open order stops at campaign 1's single entry, proving stage_all's abort
    // unwind had nothing staged from campaign 2 to roll back (consistent with the
    // 0 rollback calls above).
    assert_eq!(
        *opens.read(),
        vec!["host".to_string()],
        "campaign 2's open must be refused before it is ever recorded as opened"
    );

    // (c) The device itself was never reset/rebooted, in either campaign.
    assert_eq!(
        backend.reset_count(),
        reset_count_after_c1,
        "the engine must not reset the device itself on this refusal"
    );
}

// =============================================================================
// run_campaign — the shared multi-step loop (health-gate + per-step commit/abort)
// =============================================================================

fn job(id: &str, env: &[u8]) -> FlashJob {
    FlashJob {
        component_id: id.to_string(),
        gateway_id: None,
        envelope: env.to_vec(),
        payloads: vec![],
    }
}

fn status(id: &str, state: EcuState) -> EcuStatus {
    EcuStatus {
        component_id: id.to_string(),
        gateway_id: None,
        state,
        update_type: UpdateType::Firmware,
        active_version: None,
        previous_version: None,
        error: None,
        update_id: None,
    }
}

#[tokio::test]
async fn cameup_is_healthy_only_when_all_came_up() {
    // Every component Activated/Committed → healthy.
    assert!(CameUp
        .is_healthy(&[
            status("a", EcuState::Activated),
            status("b", EcuState::Committed),
        ])
        .await
        .unwrap());
    // Any component Failed → unhealthy.
    assert!(!CameUp
        .is_healthy(&[
            status("a", EcuState::Activated),
            status("b", EcuState::Failed),
        ])
        .await
        .unwrap());
    // A component that never came up (still Staged) → unhealthy.
    assert!(!CameUp
        .is_healthy(&[status("a", EcuState::Staged)])
        .await
        .unwrap());
    // Empty set → NOT healthy (nothing came up is no baseline to commit).
    assert!(!CameUp.is_healthy(&[]).await.unwrap());
}

/// A gate that always reports unhealthy — drives the abort/rollback path.
struct Unhealthy;
#[async_trait]
impl HealthCheck for Unhealthy {
    async fn is_healthy(&self, _ecus: &[EcuStatus]) -> Result<bool, EngineError> {
        Ok(false)
    }
}

#[tokio::test]
async fn run_campaign_commits_each_healthy_step() {
    let b1 = Arc::new(TestBackend::new("ecu1"));
    let b2 = Arc::new(TestBackend::new("ecu2"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), b1.clone());
    backends.insert("ecu2".into(), b2.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    // Two ordered steps; each healthy → committed, so the next builds on a
    // committed baseline. (force=false: the per-component path; banked coalescing
    // is exercised on the rig.)
    let steps = vec![
        CampaignStep {
            jobs: vec![job("ecu1", &[0x01])],
            force_ecu_reset: false,
        },
        CampaignStep {
            jobs: vec![job("ecu2", &[0x02])],
            force_ecu_reset: false,
        },
    ];
    let report = eng.run_campaign(steps, &CameUp, false).await.unwrap();
    assert_eq!(report.ecus.len(), 2);
    assert!(report.ecus.iter().all(|e| e.state == EcuState::Committed));
    assert_eq!(*b1.flash_state.read(), FlashState::Committed);
    assert_eq!(*b2.flash_state.read(), FlashState::Committed);
}

#[tokio::test]
async fn run_campaign_no_commit_leaves_the_trial() {
    let b1 = Arc::new(TestBackend::new("ecu1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), b1.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let steps = vec![CampaignStep {
        jobs: vec![job("ecu1", &[0x01])],
        force_ecu_reset: false,
    }];
    let report = eng.run_campaign(steps, &CameUp, true).await.unwrap();
    // Healthy but no_commit → left in trial (Activated), not committed.
    assert!(report.ecus.iter().all(|e| e.state == EcuState::Activated));
    assert_ne!(*b1.flash_state.read(), FlashState::Committed);
}

#[tokio::test]
async fn run_campaign_unhealthy_step_rolls_back_and_aborts() {
    let b1 = Arc::new(TestBackend::new("ecu1"));
    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert("ecu1".into(), b1.clone());
    let (url, _h) = serve(backends).await;
    let eng = engine(&url);

    let steps = vec![CampaignStep {
        jobs: vec![job("ecu1", &[0x01])],
        force_ecu_reset: false,
    }];
    let err = eng
        .run_campaign(steps, &Unhealthy, false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EngineError::CampaignAborted { step: 0, .. }),
        "expected CampaignAborted at step 0, got {err:?}"
    );
    // The step's trial was rolled back — never left committed on a bad baseline.
    assert_eq!(*b1.flash_state.read(), FlashState::RolledBack);
}
