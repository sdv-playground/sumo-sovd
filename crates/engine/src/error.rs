//! Flash engine error types.

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("manifest error: {0}")]
    Manifest(String),

    #[error("SOVD API error for {component}: {message}")]
    Sovd { component: String, message: String },

    #[error("flash failed for {component}: {message}")]
    FlashFailed { component: String, message: String },

    #[error("timeout waiting for {component}: {operation}")]
    Timeout {
        component: String,
        operation: String,
    },

    /// The plan mixes rollbackable (banked) and irreversible (singleshot, e.g.
    /// the HSM keystore) components — a rollback would leave the device
    /// undefined. Caught by [`FlashEngine::guard`](crate::FlashEngine::guard).
    #[error("plan mixes rollbackable {rollbackable:?} with irreversible {irreversible:?}")]
    MixedUpdateModes {
        rollbackable: Vec<String>,
        irreversible: Vec<String>,
    },

    /// A campaign step's system-health gate failed: the step's trial was rolled
    /// back and the campaign aborted rather than build on an unhealthy baseline.
    #[error("campaign aborted at step {step}: {reason}")]
    CampaignAborted { step: usize, reason: String },

    #[error("{0}")]
    Internal(String),
}
