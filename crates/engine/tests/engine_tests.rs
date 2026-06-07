//! Engine-level integration tests: drive `FlashEngine` directly (NoAuth) against
//! an in-process sovd-api server with a simulated flash backend. Mirrors
//! `orchestrator/tests/campaign_tests.rs` but exercises the lifted execution
//! core without the campaign adapter or UDS unlock (the test backend doesn't
//! enforce security, exactly as the engine's `NoAuth` path assumes).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::{
    Capabilities, DataValue, EntityInfo, FaultFilter, FaultsResult, OperationExecution,
    OperationInfo, ParameterInfo, SecurityMode, SecurityState, SessionMode,
};
use sovd_core::{
    ActivationState, DiagnosticBackend, FlashProgress, FlashState, FlashStatus, PackageInfo,
    PackageStatus, VerifyResult,
};

use sumo_sovd_flash_engine::{
    EcuState, EcuStatus, EngineTimeouts, FlashEngine, FlashJob, FlashPlan, NoAuth,
};

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
            fail_flash: RwLock::new(None),
        }
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
    async fn read_data(&self, _param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
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
        *self.session.write() = "default".into();
        *self.security_unlocked.write() = false;
        *self.flash_state.write() = FlashState::Activated;
        Ok(None)
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
