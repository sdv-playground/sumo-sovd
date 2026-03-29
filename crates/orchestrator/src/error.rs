/// Orchestrator error types.

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("manifest error: {0}")]
    Manifest(String),

    #[error("SOVD API error for {component}: {message}")]
    Sovd { component: String, message: String },

    #[error("security unlock failed for {component}: {message}")]
    SecurityFailed { component: String, message: String },

    #[error("flash failed for {component}: {message}")]
    FlashFailed { component: String, message: String },

    #[error("timeout waiting for {component}: {operation}")]
    Timeout { component: String, operation: String },

    #[error("rollback triggered for {component}: {reason}")]
    RollbackTriggered { component: String, reason: String },

    #[error("{0}")]
    Internal(String),
}
