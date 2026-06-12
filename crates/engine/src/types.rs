//! Normalized engine inputs (`FlashPlan`) + injected auth (`TokenSource`) +
//! the per-component status types the phases read and mutate.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::EngineError;

/// A whole-vehicle update as per-component jobs. Adapter-produced (campaign,
/// rig, onboard), engine-consumed. `jobs` is staged in order; the phases
/// (stage → reset → commit) are global.
pub struct FlashPlan {
    pub jobs: Vec<FlashJob>,
}

/// One component's update: a signed SUIT envelope + its (streamed) payloads.
pub struct FlashJob {
    /// SOVD component id, e.g. `"rt"`, `"vm1"`.
    pub component_id: String,
    /// Parent ECU for reset coalescing; `None` = flat device (entity-root reset).
    pub gateway_id: Option<String>,
    /// Signed SUIT manifest bytes — opaque to the engine; the device validates.
    pub envelope: Vec<u8>,
    /// Encrypted images, referenced by SUIT `#uri`. Streamed, never buffered whole.
    pub payloads: Vec<Payload>,
}

/// A payload referenced by the manifest, with where its bytes come from.
pub struct Payload {
    /// SUIT component URI, e.g. `"#rootfs"`.
    pub uri: String,
    pub source: PayloadSource,
}

/// Where a payload's bytes come from. Covers local files (campaign / rig blob
/// cache) and in-memory buffers today; `#[non_exhaustive]` leaves room for an
/// async reader (Tower-2 blob) or a remote URI the device dereferences itself
/// (onboard manifest-only push) without a breaking change.
#[non_exhaustive]
pub enum PayloadSource {
    /// Local file, streamed at upload time (constant memory).
    File(PathBuf),
    /// In-memory bytes — escape hatch for tiny payloads / tests.
    Bytes(Vec<u8>),
}

/// Bearer-token provider for SOVD calls. Auth is injected, not baked: campaign
/// uses [`NoAuth`], rig mints a per-device JWT, onboard a vehicle-scoped JWT.
#[async_trait]
pub trait TokenSource: Send + Sync {
    /// Bearer token (no `"Bearer "` prefix) for calls against `component_id`.
    /// An empty string ⇒ the engine builds an unauthenticated client.
    async fn token(&self, component_id: &str) -> Result<String, EngineError>;
}

/// No-op token source: every token is empty, so the engine builds
/// unauthenticated clients — exactly campaign's behaviour against a device
/// SOVD that doesn't enforce auth.
pub struct NoAuth;

#[async_trait]
impl TokenSource for NoAuth {
    async fn token(&self, _component_id: &str) -> Result<String, EngineError> {
        Ok(String::new())
    }
}

/// A fixed operator-supplied bearer JWT, used verbatim for every component — the
/// campaign counterpart of the rig's `RigToken::Static`. (Auto-minting a
/// per-device JWT via `sovd-token-helper`, like `RigToken::Mint`, is a follow-up.)
pub struct StaticToken(pub String);

#[async_trait]
impl TokenSource for StaticToken {
    async fn token(&self, _component_id: &str) -> Result<String, EngineError> {
        Ok(self.0.clone())
    }
}

/// What kind of update a manifest represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    /// Full firmware update — flash + reset + trial + commit.
    Firmware,
    /// Application/container update — upload + finalize, no ECU reset/trial.
    Application,
    /// Policy-only (CRL, config) — applied immediately, no trial.
    Policy,
}

/// State of one component within a flash run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcuState {
    Pending,
    Flashing,
    /// AwaitingReboot — flash done, waiting for reset.
    Staged,
    /// Flash finalised + an ECU-level restart issued for the parent ECU
    /// (a staged component declared `reset_kind: requires_ecu_reset`).
    /// Polling for `Activated`.
    AwaitingSystemReboot,
    /// Trial mode — reset done, running new firmware.
    Activated,
    Committed,
    RolledBack,
    Failed,
}

/// Per-component status, carried across the stage → reset → commit phases.
#[derive(Debug, Clone)]
pub struct EcuStatus {
    pub component_id: String,
    pub gateway_id: Option<String>,
    pub state: EcuState,
    pub update_type: UpdateType,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    pub error: Option<String>,
    /// The `/updates` package id opened at staging; carried so reset/commit/
    /// rollback can re-`attach` a post-reset FlashClient to the surviving
    /// server-side entry. `None` until staging produces it.
    pub update_id: Option<String>,
}

/// Result of [`FlashEngine::run`](crate::FlashEngine::run): the final
/// per-component status set.
pub struct CampaignReport {
    pub ecus: Vec<EcuStatus>,
}

/// Per-phase wall-clock budgets.
#[derive(Clone)]
pub struct EngineTimeouts {
    /// Budget for a `Local` per-component reset → `Activated`.
    pub local_reset_secs: u64,
    /// Budget for a coalesced `RequiresEcuReset` group → `Activated` (covers
    /// host reboot + supernova respawn + VM auto-start).
    pub ecu_reset_activation_secs: u64,
}

impl Default for EngineTimeouts {
    fn default() -> Self {
        Self {
            local_reset_secs: 180,
            ecu_reset_activation_secs: 300,
        }
    }
}
