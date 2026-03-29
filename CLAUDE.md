# CLAUDE.md — sumo-sovd

## Project Overview

SUIT Campaign Orchestrator over SOVD. Bridges the SUIT manifest ecosystem
(sumo-rs) with SOVD diagnostic servers (SOVDd, vm-mgr) for multi-ECU
firmware update campaigns.

### Architecture

```
Fleet Backend → [L1 campaign + L2 manifests + firmware]
     ↓
sumo-sovd-orchestrator
     ↓ per-ECU via SOVD API:
     ↓   session → security → upload → flash → reset → commit
     ↓
SOVD Servers (vm-mgr, SOVDd, etc.)
```

### Key Concepts

- L1 campaign manifest: which ECUs, what order, signed by fleet operator
- L2 image manifest: per-ECU firmware with digest, encryption, security_version
- FirmwareResolver trait: pluggable firmware source (CDN, local cache, CAS)
- Per-ECU flash lifecycle driven by SOVD REST API via sovd-client

## Build & Test

```bash
cargo build
cargo test
```

## Related Projects

- [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs) — SUIT manifest library
- [SOVDd](https://github.com/sdv-playground/SOVDd) — SOVD diagnostic server
- [vm-mgr](https://github.com/sdv-playground/vm-mgr) — VM lifecycle manager
- [SOVD Explorer](https://github.com/skarlsson/SOVD-explorer) — Diagnostic GUI
