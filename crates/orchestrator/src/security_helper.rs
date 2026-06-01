//! Security helper client — derives UDS Security Access keys from seeds.
//!
//! Calls the SOVD security-helper HTTP API to compute the key response for
//! a device-issued seed. Pluggable: production runs an OEM helper backed
//! by an HSM, dev/CI runs the bundled `sovd-security-helper` daemon.
//!
//! The helper is the **device-unlock** authority — it holds per-ECU
//! Security Access secrets server-side. It is **not** the SUIT signing
//! authority (that's offline, held by the firmware-build operator).

use crate::error::OrchestratorError;
use serde::Deserialize;
use tracing::debug;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Where the security helper lives + the bearer token to authenticate with it.
///
/// Holds no secrets itself — the actual derivation key is server-side at
/// the helper. The token only authorises this client to *call* the helper.
#[derive(Clone, Debug)]
pub struct SecurityHelperConfig {
    pub url: String,
    pub token: String,
}

// ---------------------------------------------------------------------------
// Typed client
// ---------------------------------------------------------------------------

/// Pooled, reusable helper client. Build once per orchestrator and clone
/// freely — `reqwest::Client` is Arc-internal, so clones share the connection
/// pool.
#[derive(Clone)]
pub struct SecurityHelperClient {
    config: SecurityHelperConfig,
    http: reqwest::Client,
}

/// Per-call payload for [`SecurityHelperClient::compute_key`].
///
/// `seed_hex` accepts either compact hex (`"aabbccdd"`) or the SOVD wire
/// format (`"0xaa 0xbb 0xcc 0xdd"`); the client normalises to compact
/// hex before sending.
///
/// The optional context fields (`vin`, `part_number`, etc.) match the
/// helper's `ecu`/`vehicle` JSON shape. The reference helper ignores
/// them, but production helpers may use them for routing — populate
/// what you know, leave the rest `None`.
pub struct ComputeKeyRequest<'a> {
    pub seed_hex: &'a str,
    pub level: u8,
    pub component_id: &'a str,
    pub vin: Option<&'a str>,
    pub logical_address: Option<&'a str>,
    pub part_number: Option<&'a str>,
    pub hw_version: Option<&'a str>,
    pub sw_version: Option<&'a str>,
    pub supplier: Option<&'a str>,
}

impl<'a> ComputeKeyRequest<'a> {
    /// Minimal constructor — only the fields every caller has.
    pub fn new(seed_hex: &'a str, level: u8, component_id: &'a str) -> Self {
        Self {
            seed_hex,
            level,
            component_id,
            vin: None,
            logical_address: None,
            part_number: None,
            hw_version: None,
            sw_version: None,
            supplier: None,
        }
    }
}

/// Helper's `/info` response — what ECUs the helper knows about + auth mode.
#[derive(Deserialize, Debug, Clone)]
pub struct HelperInfo {
    pub name: String,
    pub version: String,
    pub auth_mode: String,
    pub supported_ecus: Vec<String>,
}

impl SecurityHelperClient {
    /// Build a client with a pooled `reqwest::Client`. Cheap to call;
    /// cheaper to clone the resulting client. Panics only on TLS-init
    /// failure, which would prevent any HTTP from working.
    pub fn new(config: SecurityHelperConfig) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("reqwest::Client::builder().build() — TLS init failure");
        Self { config, http }
    }

    /// `POST /calculate` — derives the Security Access key for a given seed.
    pub async fn compute_key(
        &self,
        req: &ComputeKeyRequest<'_>,
    ) -> Result<String, OrchestratorError> {
        // Normalise "0xaa 0xbb cc" → "aabbcc"
        let compact_seed: String = req
            .seed_hex
            .split_whitespace()
            .map(|s| s.trim_start_matches("0x"))
            .collect();

        let mut ecu = serde_json::Map::new();
        ecu.insert(
            "component_id".into(),
            serde_json::Value::String(req.component_id.to_string()),
        );
        if let Some(v) = req.logical_address {
            ecu.insert("logical_address".into(), v.into());
        }
        if let Some(v) = req.part_number {
            ecu.insert("part_number".into(), v.into());
        }
        if let Some(v) = req.hw_version {
            ecu.insert("hw_version".into(), v.into());
        }
        if let Some(v) = req.sw_version {
            ecu.insert("sw_version".into(), v.into());
        }
        if let Some(v) = req.supplier {
            ecu.insert("supplier".into(), v.into());
        }

        let mut body = serde_json::Map::new();
        body.insert("seed".into(), compact_seed.into());
        body.insert("level".into(), req.level.into());
        body.insert("ecu".into(), serde_json::Value::Object(ecu));
        if let Some(vin) = req.vin {
            body.insert("vehicle".into(), serde_json::json!({ "vin": vin }));
        }

        debug!(url = %self.config.url, component = %req.component_id, "calling security helper");

        let url = format!("{}/calculate", self.config.url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.token))
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|e| OrchestratorError::SecurityFailed {
                component: req.component_id.to_string(),
                message: format!("helper request: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::SecurityFailed {
                component: req.component_id.to_string(),
                message: format!("helper returned {status}: {text}"),
            });
        }

        let result: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| OrchestratorError::SecurityFailed {
                    component: req.component_id.to_string(),
                    message: format!("helper response: {e}"),
                })?;

        // Helper protocol can return {"success": false, "error": "..."} with a 200.
        if result.get("success") == Some(&serde_json::Value::Bool(false)) {
            let msg = result
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("helper reported failure")
                .to_string();
            return Err(OrchestratorError::SecurityFailed {
                component: req.component_id.to_string(),
                message: msg,
            });
        }

        result
            .get("key")
            .and_then(|k| k.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| OrchestratorError::SecurityFailed {
                component: req.component_id.to_string(),
                message: "helper response missing 'key' field".into(),
            })
    }

    /// `GET /info` — pre-flight probe of helper liveness + capability.
    pub async fn info(&self) -> Result<HelperInfo, OrchestratorError> {
        let url = format!("{}/info", self.config.url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| OrchestratorError::Internal(format!("helper /info request: {e}")))?;
        if !resp.status().is_success() {
            return Err(OrchestratorError::Internal(format!(
                "helper /info returned {}",
                resp.status()
            )));
        }
        resp.json::<HelperInfo>()
            .await
            .map_err(|e| OrchestratorError::Internal(format!("helper /info parse: {e}")))
    }

    pub fn config(&self) -> &SecurityHelperConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible free function (deprecated)
// ---------------------------------------------------------------------------

/// Compute a security key from a seed via the security helper.
///
/// Builds a fresh `reqwest::Client` per call. Kept as a compat shim — new
/// code should construct a [`SecurityHelperClient`] once and reuse it.
#[deprecated(note = "construct a SecurityHelperClient once and call compute_key on it")]
pub async fn compute_key(
    config: &SecurityHelperConfig,
    seed_hex: &str,
    level: u8,
    component_id: &str,
) -> Result<String, OrchestratorError> {
    SecurityHelperClient::new(config.clone())
        .compute_key(&ComputeKeyRequest::new(seed_hex, level, component_id))
        .await
}
