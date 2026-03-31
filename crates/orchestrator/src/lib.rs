//! SUIT Campaign Orchestrator over SOVD
//!
//! Bridges the SUIT manifest ecosystem (sumo-rs) with SOVD diagnostic servers
//! (SOVDd, vm-mgr). Processes L1 campaign manifests and coordinates per-ECU
//! firmware updates via the SOVD REST API.
//!
//! # Architecture
//!
//! ```text
//! Fleet Backend → [L1 campaign manifest + L2 image manifests + firmware]
//!      ↓
//! CampaignOrchestrator
//!      ↓
//!  Stage phase (per-ECU):        Reset phase (campaign-level):
//!   1. Programming session        8. Reset all staged ECUs
//!   2. Security unlock             9. Wait for activation (trial)
//!   3. Upload package
//!   4. Verify                    Commit phase (campaign-level):
//!   5. Start flash transfer       10. Commit all or rollback all
//!   6. Monitor progress
//!   7. Finalize → AwaitingReset
//!      ↓
//! SOVD Servers (vm-mgr, SOVDd, etc.)
//! ```
//!
//! The reset is a campaign-level decision, not per-ECU. The orchestrator
//! stages all ECUs first, then resets them together when ready. This
//! supports vehicles that need coordinated reboot or external power cycle.
//!
//! # Key Concepts
//!
//! - **Campaign manifest (L1)**: Declares which ECUs get which firmware,
//!   in what order. Signed by fleet operator.
//! - **Image manifest (L2)**: Per-ECU firmware package with digest,
//!   encryption info, security_version. Signed by firmware author.
//! - **SOVD API**: Standard REST interface for diagnostic operations.
//!   The orchestrator uses sovd-client to drive each ECU.
//! - **Security helper**: External service that computes security keys
//!   from seeds (pluggable per deployment).

pub mod campaign;
pub mod error;
pub mod ecu;
pub mod security_helper;
pub mod sovd_ops;

pub use campaign::CampaignOrchestrator;
pub use ecu::UpdateType;
pub use error::OrchestratorError;
