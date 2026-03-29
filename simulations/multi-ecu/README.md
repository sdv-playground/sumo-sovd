# Multi-ECU Campaign Simulation

Tests the full campaign lifecycle across heterogeneous ECUs:
- vm-mgr (VM bank sets via SOVD)
- SOVDd example-ecus (UDS ECUs on vCAN)
- SOVDd gateway (aggregates all ECUs)

## Architecture

```
sumo-sovd-orchestrator
    ↓ L1 campaign manifest
    ↓
SOVDd gateway (port 4000)
    ├── os1 → vm-mgr (port 4001)
    ├── engine_ecu → example-ecu on vcan0
    └── body_ecu → example-ecu on vcan0
```

## Test Campaigns

1. **Normal** — update os1 + engine_ecu + body_ecu, commit all
2. **CRL** — bump security floor on os1 only
3. **Partial failure** — body_ecu flash fails, verify os1 + engine_ecu rollback
