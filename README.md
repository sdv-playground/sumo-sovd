# sumo-sovd — SUIT Campaign Orchestrator over SOVD

Bridges the [SUIT manifest ecosystem](https://github.com/tr-sdv-sandbox/sumo-rs) with [SOVD diagnostic servers](https://github.com/sdv-playground/SOVDd) for multi-ECU firmware update campaigns.

## Architecture

```
Fleet Backend → [L1 campaign manifest + L2 image manifests + firmware]
     ↓
sumo-sovd-orchestrator
     ↓ for each ECU (manifest-driven ordering):
     ↓   1. Upload firmware package
     ↓   2. Verify package integrity
     ↓   3. Start flash transfer
     ↓   4. Monitor progress
     ↓   5. Finalize transfer
     ↓   6. Reset ECU
     ↓   7. Wait for activation (poll)
     ↓
     ↓ All ECUs in trial → health check → commit all or rollback all
     ↓
SOVD Servers (vm-mgr, SOVDd, etc.)
```

SOVD writes carry a JWT bearer (the flash engine's `TokenSource` seam);
UDS session/security unlock happens transparently server-side in the
SOVD server. There is no client-side seed/key choreography.

## Key Concepts

- **Campaign manifest (L1)**: Declares which ECUs get which firmware, in what order. The manifest's SUIT command sequences (`install`, `validate`, `invoke`) program the update flow.
- **Image manifest (L2)**: Per-ECU firmware with digest, encryption info, security_version. Can be SUIT envelopes or opaque firmware binaries.
- **Security version**: Separate from sequence number. Enables A/B fleet testing — different versions with the same security floor are freely interchangeable. Only security-critical updates bump the floor.
- **CRL manifests**: Policy-only manifests (no firmware) that raise the security floor, permanently blocking vulnerable versions.
- **Atomic campaign**: All ECUs flash to trial before any commits. On failure, already-activated ECUs are automatically rolled back.

## Manifest-Driven Flow

The orchestrator reads the L1 manifest's SUIT command sequences to determine behavior:

| Manifest type | install seq | invoke seq | Orchestrator flow |
|---|---|---|---|
| Firmware campaign | process-dependency per ECU | directive-invoke per ECU | Flash all → trial → commit/rollback |
| CRL / policy | — | — | Apply floor immediately |

## Usage

### Run campaign tests

```bash
# Requires vm-mgr and SOVDd built
./run-tests.sh
```

### Programmatic

```rust
use sumo_sovd_orchestrator::campaign::*;

let orchestrator = CampaignOrchestrator::new(CampaignConfig {
    server_url: "http://localhost:4000".into(),
    trust_anchor: std::fs::read("signing.pub")?,
    use_validated_flow: false,
    // SOVD writes carry a JWT bearer; the server unlocks itself (UDS) on a
    // valid token. None → unauthenticated (device may not enforce auth yet).
    sovd_token: Some(jwt),
    insecure: false,
});

// Flash all ECUs to trial
let result = orchestrator.flash_all(vec![
    EcuTarget {
        component_id: "os1".into(),
        gateway_id: Some("vehicle_gateway".into()),
        manifest: suit_envelope,
        payloads: vec![],
    },
]).await?;

// Health check... then commit or rollback
orchestrator.commit_all(&result.ecus).await?;
```

## Multi-ECU Simulation

```bash
cd simulations/multi-ecu && ./start.sh
```

Launches:
- SOVDd gateway (port 4000) aggregating:
  - `os1` → vm-mgr SOVD proxy (port 4001)
  - `engine_ecu` → UDS ECU on vcan1
  - `body_ecu` → UDS ECU on vcan1

## Test Results (6/6 passing)

| Test | Description |
|------|-------------|
| 1 | Flash os1 v1.0.0 and commit |
| 2 | A/B test — v1.1.0 then downgrade to v1.0.0 (same security floor) |
| 3 | Flash v1.2.0 then rollback (no commit) |
| 4 | Reinstall same version |
| 5 | Multi-ECU campaign: os1 (SUIT) + engine_ecu (UDS) together |
| 6 | CRL floor bump → v1.0.0 rejected → v1.2.0-secver2 accepted |

## Related Projects

- [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs) — SUIT manifest library (codec, crypto, onboard, offboard, processor)
- [SOVDd](https://github.com/sdv-playground/SOVDd) — SOVD diagnostic server
- [vm-mgr](https://github.com/sdv-playground/vm-mgr) — VM lifecycle manager with SUIT + SOVD
- [SOVD Explorer](https://github.com/skarlsson/SOVD-explorer) — Diagnostic GUI
- [SUMO specs](https://github.com/tr-sdv-sandbox/sumo) — Specifications and test vectors
