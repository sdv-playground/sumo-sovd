# sumo-map

Inventory the software **actually installed** on a device's VMs, file by file —
straight from each VM's committed bank — verify the inventory's signature, and
diff it against a release to see "what to flash".

`sumo-map` is the read side of SW mapping. It is a focused starting-point stub;
extend it as your mapping workflow grows.

## What it reads

For each VM (SOVD component) it issues the vendor SOVD data read

```
GET /vehicle/v1/components/{vm}/data/x-ota-installed-manifest
```

whose `value` is the running/committed bank's **signed IVD manifest**:

```json
{
  "ivd_version": 3, "gen": 5, "signed_at_unix": 1733000000,
  "identity": { "name", "version", "ecu_sw_number", "supplier_sw_number",
                "supplier_sw_version", "spare_part_number", "odx_file_id",
                "system_name", "programming_date", "tester_serial" },
  "files": [ { "path": "kernel",     "sha256": "<64-hex>" },
             { "path": "rootfs.img", "sha256": "<64-hex>" } ],
  "signature_b64": "<DER ECDSA-SHA256 over manifest_b64>",
  "manifest_b64":  "<exact ivd-manifest.cbor bytes the signature covers>"
}
```

This is served from the same source as the F187–F19E identData DIDs, so the
manifest and the DIDs can never disagree. A VM with no committed manifest
(never flashed / no-HSM smoke path) returns **404**; `sumo-map` prints
`"<vm>: no signed manifest (never flashed?)"` and moves on.

**Contract:** `sumo-machine-manager/specs/sovd-vm-app-installation.md` §17.

## Usage

```
sumo-map --server <sovd-url> [--component <id>] [--pubkey <p256-pub.pem|der>] \
         [--release <release.json>] [--json]
```

| Flag | Meaning |
|------|---------|
| `--server <url>`    | SOVD server base URL (e.g. `http://device:9080`). Required. |
| `--component <id>`  | Narrow to one VM; default is every component. |
| `--pubkey <file>`   | `ivd-signing` public key (PEM or DER) — verifies each manifest's signature. |
| `--release <file>`  | Release JSON `{ "files": [ { "path", "sha256" }, … ] }` to diff against. |
| `--json`            | Emit the whole result as JSON instead of the human tables. |

### Verification

`signature_b64` is a **DER ECDSA-SHA256** signature over the exact
`manifest_b64` bytes. With `--pubkey`, `sumo-map` re-verifies it independently
and prints `✓ verified` or `✗ SIGNATURE INVALID`; without it,
`(unverified — pass --pubkey)`.

`--pubkey` is the device's **`ivd-signing`** public half — the key the device
signs its banks with at provision/flash time (it has the matching private half
in its HSM). `files[]` then proves the exact installed bits.

### Diff against a release

With `--release`, `sumo-map` compares the installed `files[]` against the
release's `files[]` and reports, per VM:

- **added** — in the release, not installed
- **removed** — installed, not in the release
- **changed** — present in both but `sha256` differs

i.e. the set of files an update to that release would touch. sha comparison is
case-insensitive.

### Examples

```bash
# Inventory every VM, verified, in JSON:
sumo-map --server http://device:9080 --pubkey ivd-signing-pub.pem --json

# One VM, human tables, diffed against a release:
sumo-map --server http://device:9080 --component vm1 \
         --pubkey ivd-signing-pub.der --release vm1-1.3.0.json
```

## Build & test

```bash
cargo build   -p sumo-map
cargo clippy  -p sumo-map -- -D warnings
cargo test    -p sumo-map      # diff + signature-verify unit tests
sumo-map --help
```
