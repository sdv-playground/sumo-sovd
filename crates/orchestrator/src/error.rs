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
    Timeout {
        component: String,
        operation: String,
    },

    #[error("rollback triggered for {component}: {reason}")]
    RollbackTriggered { component: String, reason: String },

    #[error("{0}")]
    Internal(String),
}

impl From<sumo_sovd_flash_engine::EngineError> for OrchestratorError {
    fn from(e: sumo_sovd_flash_engine::EngineError) -> Self {
        use sumo_sovd_flash_engine::EngineError as E;
        match e {
            E::Manifest(m) => OrchestratorError::Manifest(m),
            E::Sovd { component, message } => OrchestratorError::Sovd { component, message },
            E::FlashFailed { component, message } => {
                OrchestratorError::FlashFailed { component, message }
            }
            E::Timeout {
                component,
                operation,
            } => OrchestratorError::Timeout {
                component,
                operation,
            },
            E::MixedUpdateModes {
                rollbackable,
                irreversible,
            } => OrchestratorError::Internal(format!(
                "plan mixes rollbackable {rollbackable:?} with irreversible {irreversible:?}"
            )),
            E::CampaignAborted { step, reason } => OrchestratorError::Internal(format!(
                "campaign aborted at step {step}: {reason}"
            )),
            E::Internal(m) => OrchestratorError::Internal(m),
        }
    }
}
