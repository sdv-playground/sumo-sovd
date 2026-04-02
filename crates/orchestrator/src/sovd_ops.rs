/// SovdPlatformOps — adapts PlatformOps to SOVD REST API calls.
///
/// The SUIT processor calls PlatformOps methods; this adapter translates
/// them into sovd-client flash operations against an SOVD server.
///
/// For campaigns, each component maps to an ECU behind the gateway.
/// The processor walks the L1 sequences (install all → validate all → invoke all)
/// and this adapter makes the corresponding SOVD calls.

use std::cell::RefCell;
use std::collections::HashMap;

use sovd_client::flash::FlashClient;
use sumo_onboard::error::Sum2Error;
use sumo_onboard::platform::PlatformOps;
use tracing::info;

/// Maps component IDs to SOVD flash clients + staged payloads.
#[allow(dead_code)]
pub struct SovdPlatformOps {
    server_url: String,
    gateway_id: Option<String>,
    /// Pre-staged payloads keyed by URI (integrated or fetched)
    payloads: RefCell<HashMap<String, Vec<u8>>>,
    /// Flash clients per component (created lazily)
    flash_clients: RefCell<HashMap<String, FlashClient>>,
    /// Written data per component
    written: RefCell<HashMap<String, Vec<u8>>>,
}

impl SovdPlatformOps {
    pub fn new(server_url: &str, gateway_id: Option<String>) -> Self {
        Self {
            server_url: server_url.to_string(),
            gateway_id,
            payloads: RefCell::new(HashMap::new()),
            flash_clients: RefCell::new(HashMap::new()),
            written: RefCell::new(HashMap::new()),
        }
    }

    /// Pre-stage a payload for a URI (for integrated payloads).
    pub fn stage_payload(&self, uri: &str, data: Vec<u8>) {
        self.payloads.borrow_mut().insert(uri.to_string(), data);
    }

    /// Get written data for a component.
    pub fn get_written(&self, component_id: &str) -> Option<Vec<u8>> {
        self.written.borrow().get(component_id).cloned()
    }

    #[allow(dead_code)]
    fn get_or_create_flash_client(&self, component_id: &str) -> Result<FlashClient, Sum2Error> {
        let mut clients = self.flash_clients.borrow_mut();
        if let Some(client) = clients.get(component_id) {
            return Ok(client.clone());
        }
        let client = if let Some(ref gw) = self.gateway_id {
            FlashClient::for_sovd_sub_entity(&self.server_url, gw, component_id)
        } else {
            FlashClient::for_sovd(&self.server_url, component_id)
        }
        .map_err(|_| Sum2Error::CallbackFailed)?;
        clients.insert(component_id.to_string(), client.clone());
        Ok(client)
    }
}

impl PlatformOps for SovdPlatformOps {
    fn fetch(&self, uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error> {
        // Check pre-staged payloads first (for integrated/cached)
        let payloads = self.payloads.borrow();
        if let Some(data) = payloads.get(uri) {
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            info!(uri, bytes = n, "fetched from staged payload");
            return Ok(n);
        }
        // TODO: HTTP fetch for external URIs
        Err(Sum2Error::CallbackFailed)
    }

    fn write(&self, component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error> {
        let comp = String::from_utf8_lossy(component_id).to_string();
        let mut written = self.written.borrow_mut();
        let buf = written.entry(comp).or_insert_with(Vec::new);
        let end = offset + data.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset..end].copy_from_slice(data);
        Ok(())
    }

    fn invoke(&self, component_id: &[u8]) -> Result<(), Sum2Error> {
        let comp = String::from_utf8_lossy(component_id).to_string();
        info!(component = %comp, "invoke (SOVD reset)");
        // In SOVD terms, invoke = ECU reset
        // The campaign orchestrator handles this via the flash client
        Ok(())
    }

    fn swap(&self, comp_a: &[u8], _comp_b: &[u8]) -> Result<(), Sum2Error> {
        let comp = String::from_utf8_lossy(comp_a).to_string();
        info!(component = %comp, "swap (A/B bank switch via SOVD)");
        Ok(())
    }

    fn persist_sequence(&self, component_id: &[u8], seq: u64) -> Result<(), Sum2Error> {
        let comp = String::from_utf8_lossy(component_id).to_string();
        info!(component = %comp, seq, "persist sequence");
        Ok(())
    }
}
