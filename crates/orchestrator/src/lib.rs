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
//!   1. Upload package             6. Reset all staged ECUs
//!   2. Verify                     7. Wait for activation (trial)
//!   3. Start flash transfer
//!   4. Monitor progress          Commit phase (campaign-level):
//!   5. Finalize → AwaitingReboot  8. Commit all or rollback all
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
//! - **Auth**: SOVD writes carry a JWT bearer (see the engine's
//!   [`TokenSource`](sumo_sovd_flash_engine::TokenSource) seam). UDS
//!   session/security unlock happens transparently server-side in the
//!   SOVD server — there is no client-side unlock choreography.

pub mod campaign;
pub mod error;
pub mod sovd_ops;
pub mod targets;

pub use campaign::CampaignOrchestrator;
pub use error::OrchestratorError;
pub use sumo_sovd_flash_engine::UpdateType;
pub use targets::{parse_l1_campaign, MultiflashEcu, MultiflashSpec};
