//! Device-buildable SOVD flash execution engine.
//!
//! One shared core — `guard → stage → reset (coalesced) → commit | rollback` —
//! driven by a normalized [`FlashPlan`] and an injected [`TokenSource`]. The
//! adapters (campaign, rig, onboard) produce a plan and supply a token; the
//! engine reads `reset_kind` / `update_mode` off the device, the single source
//! of truth. See `tasks/orchestrator-convergence.md`.

mod ecu;
mod engine;
pub mod error;
pub mod types;

pub use engine::FlashEngine;
pub use error::EngineError;
pub use types::{
    CameUp, CampaignReport, CampaignStep, EcuState, EcuStatus, EngineTimeouts, FlashJob, FlashPlan,
    HealthCheck, NoAuth, NoPrepare, Payload, PayloadSource, Prepare, StaticToken, TokenSource,
    UpdateType,
};
