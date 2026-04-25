/// Integration tests for the campaign orchestrator using an in-process SOVD server.
///
/// Uses sovd-api + sovd-core to spin up a real HTTP server with a test backend
/// that simulates the flash lifecycle. The orchestrator talks to it via sovd-client
/// over localhost — no mocks of the client layer.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::{
    ActivationState, DiagnosticBackend, FlashProgress, FlashState, FlashStatus,
    PackageInfo, PackageStatus, VerifyResult,
};
use sovd_core::models::{
    Capabilities, DataValue, EntityInfo, FaultFilter, FaultsResult, OperationExecution,
    OperationInfo, ParameterInfo, SecurityMode, SecurityState, SessionMode,
};

use sumo_sovd_orchestrator::campaign::{
    CampaignConfig, CampaignOrchestrator, EcuState, EcuTarget,
};
use sumo_sovd_orchestrator::security_helper::SecurityHelperConfig;

// =============================================================================
// Test Backend — simulates flash lifecycle in-memory
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
        Ok(FaultsResult { faults: vec![], status_availability_mask: None })
    }

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        Ok(vec![])
    }

    async fn start_operation(&self, _op_id: &str, _params: &[u8]) -> BackendResult<OperationExecution> {
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
            state: if unlocked { SecurityState::Unlocked } else { SecurityState::Locked },
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
        let (id, data) = packages.iter()
            .find(|(id, _)| id == package_id)
            .ok_or_else(|| BackendError::InvalidRequest(format!("package not found: {package_id}")))?;
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
            Err(BackendError::InvalidRequest(format!("package not found: {package_id}")))
        }
    }

    async fn start_flash(&self) -> BackendResult<String> {
        if let Some(msg) = self.fail_flash.read().as_ref() {
            return Err(BackendError::Internal(msg.clone()));
        }
        let tid = format!("xfer-{}", self.transfer_counter.fetch_add(1, Ordering::SeqCst));
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

/// Minimal valid COSE_Key CBOR (Ed25519 OKP with dummy 32-byte x coordinate).
/// Needed because Validator::new panics on invalid CBOR — but validate_envelope
/// will return Err on our non-SUIT test packages, which is caught gracefully.
fn dummy_trust_anchor() -> Vec<u8> {
    let mut key = vec![
        0xA3,       // map(3)
        0x01, 0x01, // kty: OKP (1)
        0x20, 0x06, // crv: Ed25519 (6)
        0x21, 0x58, 0x20, // x: bstr(32)
    ];
    key.extend_from_slice(&[0u8; 32]);
    key
}

struct TestFixture {
    orchestrator: CampaignOrchestrator,
    _sovd_handle: tokio::task::JoinHandle<()>,
    _helper_handle: tokio::task::JoinHandle<()>,
}

async fn setup(backend: Arc<dyn DiagnosticBackend>) -> TestFixture {
    let sovd_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sovd_port = sovd_listener.local_addr().unwrap().port();

    let helper_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let helper_port = helper_listener.local_addr().unwrap().port();

    let id = backend.entity_info().id.clone();
    let state = sovd_api::AppState::single(&id, backend);
    let app = sovd_api::create_router(state);
    let sovd_handle = tokio::spawn(async move {
        axum::serve(sovd_listener, app).await.unwrap();
    });

    let helper_app = {
        use axum::{routing::post, Json, Router};
        Router::new().route("/calculate", post(|Json(_body): Json<serde_json::Value>| async move {
            Json(serde_json::json!({"key": "aabb"}))
        }))
    };
    let helper_handle = tokio::spawn(async move {
        axum::serve(helper_listener, helper_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let orchestrator = CampaignOrchestrator::new(CampaignConfig {
        server_url: format!("http://127.0.0.1:{sovd_port}"),
        trust_anchor: dummy_trust_anchor(),
        security_level: 1,
        security_helper: SecurityHelperConfig {
            url: format!("http://127.0.0.1:{helper_port}"),
            token: "test".into(),
        },
        use_validated_flow: false,
    });

    TestFixture {
        orchestrator,
        _sovd_handle: sovd_handle,
        _helper_handle: helper_handle,
    }
}

async fn setup_multi(backends: HashMap<String, Arc<dyn DiagnosticBackend>>) -> TestFixture {
    let sovd_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sovd_port = sovd_listener.local_addr().unwrap().port();

    let helper_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let helper_port = helper_listener.local_addr().unwrap().port();

    let state = sovd_api::AppState::new(backends);
    let app = sovd_api::create_router(state);
    let sovd_handle = tokio::spawn(async move {
        axum::serve(sovd_listener, app).await.unwrap();
    });

    let helper_app = {
        use axum::{routing::post, Json, Router};
        Router::new().route("/calculate", post(|Json(_body): Json<serde_json::Value>| async move {
            Json(serde_json::json!({"key": "aabb"}))
        }))
    };
    let helper_handle = tokio::spawn(async move {
        axum::serve(helper_listener, helper_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let orchestrator = CampaignOrchestrator::new(CampaignConfig {
        server_url: format!("http://127.0.0.1:{sovd_port}"),
        trust_anchor: dummy_trust_anchor(),
        security_level: 1,
        security_helper: SecurityHelperConfig {
            url: format!("http://127.0.0.1:{helper_port}"),
            token: "test".into(),
        },
        use_validated_flow: false,
    });

    TestFixture {
        orchestrator,
        _sovd_handle: sovd_handle,
        _helper_handle: helper_handle,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn test_flash_and_commit() {
    let backend = Arc::new(TestBackend::new("ecu1"));
    let fix = setup(backend.clone()).await;

    let result = fix.orchestrator.flash_all(vec![EcuTarget {
        component_id: "ecu1".into(),
        gateway_id: None,
        manifest: vec![0xDE, 0xAD],
        payloads: vec![],
    }]).await.unwrap();

    assert_eq!(result.ecus.len(), 1);
    assert_eq!(result.ecus[0].state, EcuState::Activated);
    assert_eq!(result.ecus[0].component_id, "ecu1");

    fix.orchestrator.commit_all(&result.ecus).await.unwrap();
    assert_eq!(*backend.flash_state.read(), FlashState::Committed);
}

#[tokio::test]
async fn test_flash_and_rollback() {
    let backend = Arc::new(TestBackend::new("ecu1"));
    let fix = setup(backend.clone()).await;

    let result = fix.orchestrator.flash_all(vec![EcuTarget {
        component_id: "ecu1".into(),
        gateway_id: None,
        manifest: vec![0xDE, 0xAD],
        payloads: vec![],
    }]).await.unwrap();

    assert_eq!(result.ecus[0].state, EcuState::Activated);
    fix.orchestrator.rollback_all(&result.ecus).await.unwrap();
    assert_eq!(*backend.flash_state.read(), FlashState::RolledBack);
}

#[tokio::test]
async fn test_multi_ecu_flash_and_commit() {
    let backend1 = Arc::new(TestBackend::new("ecu1"));
    let backend2 = Arc::new(TestBackend::new("ecu2"));

    let mut backends = HashMap::new();
    backends.insert("ecu1".to_string(), backend1.clone() as Arc<dyn DiagnosticBackend>);
    backends.insert("ecu2".to_string(), backend2.clone() as Arc<dyn DiagnosticBackend>);
    let fix = setup_multi(backends).await;

    let result = fix.orchestrator.flash_all(vec![
        EcuTarget { component_id: "ecu1".into(), gateway_id: None, manifest: vec![0x01], payloads: vec![] },
        EcuTarget { component_id: "ecu2".into(), gateway_id: None, manifest: vec![0x02], payloads: vec![] },
    ]).await.unwrap();

    assert_eq!(result.ecus.len(), 2);
    assert_eq!(result.ecus[0].state, EcuState::Activated);
    assert_eq!(result.ecus[1].state, EcuState::Activated);

    fix.orchestrator.commit_all(&result.ecus).await.unwrap();
    assert_eq!(*backend1.flash_state.read(), FlashState::Committed);
    assert_eq!(*backend2.flash_state.read(), FlashState::Committed);
}

#[tokio::test]
async fn test_flash_failure_triggers_rollback() {
    let backend1 = Arc::new(TestBackend::new("ecu1"));
    let backend2 = Arc::new(TestBackend::new("ecu2"));
    *backend2.fail_flash.write() = Some("simulated flash failure".into());

    let mut backends = HashMap::new();
    backends.insert("ecu1".to_string(), backend1.clone() as Arc<dyn DiagnosticBackend>);
    backends.insert("ecu2".to_string(), backend2.clone() as Arc<dyn DiagnosticBackend>);
    let fix = setup_multi(backends).await;

    let err = fix.orchestrator.flash_all(vec![
        EcuTarget { component_id: "ecu1".into(), gateway_id: None, manifest: vec![0x01], payloads: vec![] },
        EcuTarget { component_id: "ecu2".into(), gateway_id: None, manifest: vec![0x02], payloads: vec![] },
    ]).await;

    assert!(err.is_err(), "flash_all should fail when ecu2 fails");
    assert_eq!(*backend1.flash_state.read(), FlashState::RolledBack);
}

#[tokio::test]
async fn test_commit_skips_already_committed() {
    let backend = Arc::new(TestBackend::new("ecu1"));
    let fix = setup(backend.clone()).await;

    let result = fix.orchestrator.flash_all(vec![EcuTarget {
        component_id: "ecu1".into(),
        gateway_id: None,
        manifest: vec![0xDE, 0xAD],
        payloads: vec![],
    }]).await.unwrap();

    let mut ecus = result.ecus;
    ecus[0].state = EcuState::Committed;

    fix.orchestrator.commit_all(&ecus).await.unwrap();
    // Backend should still be Activated — commit_all skipped the already-committed ECU
    assert_eq!(*backend.flash_state.read(), FlashState::Activated);
}
