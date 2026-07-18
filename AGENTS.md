# sumo-sovd Index

Rust campaign orchestrator that drives SUIT multi-ECU updates through SOVD servers.

## Where to look

- `README.md` — orchestration model, usage, simulation flow.
- `CLAUDE.md` — compact architecture and build/test notes.
- `Cargo.toml` — workspace packages.
- `crates/orchestrator/` — campaign orchestration library.
- `crates/campaign-cli/` — command-line campaign driver.
- `crates/engine/` — orchestration engine internals.
- `crates/sumo-map/` — SUMO mapping helpers and README.

## Essential commands

No component-local `mise` file is present; use Cargo and repo scripts from this submodule root.

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Finding commands:

```bash
rg --files -g 'Cargo.toml' -g 'README*' -g 'CLAUDE.md'
rg -n "CampaignOrchestrator|FirmwareResolver|TokenSource|flash_all|commit_all|rollback" crates README.md CLAUDE.md
```

## Stack

- Rust 2021 Cargo workspace.
- Depends on `sumo-rs` for SUIT and `sovd-client`/SOVD servers for flashing.

## Guardrails

- Keep L1 campaign ordering and L2 image semantics manifest-driven.
- SOVD upload/flash/reset/commit flow belongs in orchestration code, not hard-coded test scripts. UDS session/security unlock is the SOVD server's job (writes carry a JWT bearer), never a client step.
- Preserve atomic campaign behavior: trial all targets before commit; rollback on failure.

## Gotchas

- README references `./run-tests.sh` and `simulations/multi-ecu`, but those paths are absent in this checkout.

## Missing docs/specs to watch

- CLI command reference is limited.
- Simulation/test script documentation appears stale relative to this checkout.
