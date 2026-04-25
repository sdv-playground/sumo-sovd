//! Security helper client — computes security keys from seeds.
//!
//! Calls the SOVD security helper HTTP API to derive keys for
//! ECU security unlock. Pluggable: production can use HSM, testing
//! uses the XOR-based helper.

use crate::error::OrchestratorError;
use tracing::debug;

/// Security helper configuration.
#[derive(Clone)]
pub struct SecurityHelperConfig {
    pub url: String,
    pub token: String,
}

/// Compute a security key from a seed via the security helper.
pub async fn compute_key(
    config: &SecurityHelperConfig,
    seed_hex: &str,
    level: u8,
    component_id: &str,
) -> Result<String, OrchestratorError> {
    let client = reqwest::Client::new();

    // Convert "0xaa 0xbb 0xcc" to "aabbcc" (compact hex, no prefix/spaces)
    let compact_seed: String = seed_hex
        .split_whitespace()
        .map(|s| s.trim_start_matches("0x"))
        .collect();

    let body = serde_json::json!({
        "seed": compact_seed,
        "level": level,
        "ecu": { "component_id": component_id },
    });

    debug!(url = %config.url, component = %component_id, "calling security helper");

    let resp = client
        .post(format!("{}/calculate", config.url.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {}", config.token))
        .json(&body)
        .send()
        .await
        .map_err(|e| OrchestratorError::SecurityFailed {
            component: component_id.to_string(),
            message: format!("helper request: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(OrchestratorError::SecurityFailed {
            component: component_id.to_string(),
            message: format!("helper returned {status}: {text}"),
        });
    }

    let result: serde_json::Value = resp.json().await.map_err(|e| {
        OrchestratorError::SecurityFailed {
            component: component_id.to_string(),
            message: format!("helper response: {e}"),
        }
    })?;

    result
        .get("key")
        .and_then(|k| k.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrchestratorError::SecurityFailed {
            component: component_id.to_string(),
            message: "helper response missing 'key' field".into(),
        })
}

