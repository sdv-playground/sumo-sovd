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
//!      ↓ for each dependency (ECU):
//!      ↓   1. Switch to programming session
//!      ↓   2. Unlock security (via security helper)
//!      ↓   3. Upload manifest + firmware
//!      ↓   4. Verify package
//!      ↓   5. Start flash transfer
//!      ↓   6. Monitor progress
//!      ↓   7. Finalize transfer
//!      ↓   8. Reset ECU
//!      ↓   9. Wait for activation
//!      ↓  10. Commit or rollback
//!      ↓
//! SOVD Servers (vm-mgr, SOVDd, etc.)
//! ```
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

pub use campaign::CampaignOrchestrator;
pub use ecu::UpdateType;
pub use error::OrchestratorError;
