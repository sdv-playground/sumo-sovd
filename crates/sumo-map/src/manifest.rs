//! Typed model of the `x-sumo-installed-manifest` SOVD vendor read, plus the
//! signature-verify and release-diff logic.
//!
//! Contract: `sumo-machine-manager/specs/sovd-vm-app-installation.md` §17.
//! The device serves the running/committed bank's signed IVD manifest as a
//! single SOVD data read; a consumer re-verifies `signature_b64` over
//! `manifest_b64` with the `ivd-signing` public key. `files[]` then proves the
//! exact installed bits; `identity.version` is the release tag to diff against.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Firmware SW identity carried inside the signed IVD manifest (F187–F19E DIDs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ecu_sw_number: String,
    #[serde(default)]
    pub supplier_sw_number: String,
    #[serde(default)]
    pub supplier_sw_version: String,
    #[serde(default)]
    pub spare_part_number: String,
    #[serde(default)]
    pub odx_file_id: String,
    #[serde(default)]
    pub system_name: String,
    #[serde(default)]
    pub programming_date: String,
    #[serde(default)]
    pub tester_serial: String,
}

/// One installed file: its bank-relative path and the sha256 of its contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    /// Lowercase 64-hex sha256 of the file contents.
    pub sha256: String,
}

/// The full `x-sumo-installed-manifest` read value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledManifest {
    #[serde(default)]
    pub ivd_version: u32,
    #[serde(default)]
    pub gen: u32,
    #[serde(default)]
    pub signed_at_unix: u64,
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub files: Vec<FileEntry>,
    /// Base64 DER ECDSA-SHA256 signature over `manifest_b64`.
    #[serde(default)]
    pub signature_b64: String,
    /// Base64 of the exact `ivd-manifest.cbor` bytes the signature covers.
    #[serde(default)]
    pub manifest_b64: String,
}

/// Outcome of an independent signature check against the `ivd-signing` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    /// `--pubkey` given and the DER ECDSA-SHA256 signature checks out.
    Verified,
    /// `--pubkey` given but the signature did not verify.
    Invalid,
    /// No `--pubkey` supplied — signature not checked.
    Unverified,
}

impl InstalledManifest {
    /// Re-verify `signature_b64` over `manifest_b64` with a P-256 verifying key.
    ///
    /// Mirrors the device side: the IVD signature is a raw DER-encoded
    /// ECDSA-SHA256 over the exact CBOR manifest bytes (SHA-256 applied
    /// internally by ECDSA), so we verify the full message — not a pre-hash.
    pub fn verify(&self, pubkey: &p256::ecdsa::VerifyingKey) -> Result<VerifyStatus> {
        use p256::ecdsa::{signature::Verifier as _, Signature};

        let engine = base64::engine::general_purpose::STANDARD;
        let sig_der = engine
            .decode(self.signature_b64.trim())
            .context("decode signature_b64")?;
        let manifest_bytes = engine
            .decode(self.manifest_b64.trim())
            .context("decode manifest_b64")?;

        let sig = match Signature::from_der(&sig_der) {
            Ok(s) => s,
            // A malformed signature is a verification failure, not a tool error.
            Err(_) => return Ok(VerifyStatus::Invalid),
        };

        match pubkey.verify(&manifest_bytes, &sig) {
            Ok(()) => Ok(VerifyStatus::Verified),
            Err(_) => Ok(VerifyStatus::Invalid),
        }
    }
}

/// A release the installed inventory is diffed against:
/// `{ "files": [ { "path", "sha256" }, … ] }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

/// One file that differs between installed and release inventories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffEntry {
    pub path: String,
    /// sha on the installed side (`None` for `Added`).
    pub installed_sha256: Option<String>,
    /// sha on the release side (`None` for `Removed`).
    pub release_sha256: Option<String>,
}

/// The "what to flash" view: files added by, removed by, or changed against a
/// release, relative to what is currently installed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// In the release but not installed.
    pub added: Vec<DiffEntry>,
    /// Installed but absent from the release.
    pub removed: Vec<DiffEntry>,
    /// Present in both, but the sha256 differs.
    pub changed: Vec<DiffEntry>,
}

impl Diff {
    /// True when installed and release inventories match file-for-file.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Diff the installed file set against a release file set.
///
/// - `added`: in `release` but not `installed`.
/// - `removed`: in `installed` but not `release`.
/// - `changed`: in both, `sha256` differs.
///
/// sha comparison is case-insensitive on the hex; paths are sorted for a
/// stable, reproducible report.
pub fn diff_inventory(installed: &[FileEntry], release: &[FileEntry]) -> Diff {
    let installed: BTreeMap<&str, String> = installed
        .iter()
        .map(|f| (f.path.as_str(), f.sha256.to_lowercase()))
        .collect();
    let release: BTreeMap<&str, String> = release
        .iter()
        .map(|f| (f.path.as_str(), f.sha256.to_lowercase()))
        .collect();

    let mut diff = Diff::default();

    for (path, rel_sha) in &release {
        match installed.get(path) {
            None => diff.added.push(DiffEntry {
                path: (*path).to_string(),
                installed_sha256: None,
                release_sha256: Some(rel_sha.clone()),
            }),
            Some(inst_sha) if inst_sha != rel_sha => diff.changed.push(DiffEntry {
                path: (*path).to_string(),
                installed_sha256: Some(inst_sha.clone()),
                release_sha256: Some(rel_sha.clone()),
            }),
            Some(_) => {}
        }
    }

    for (path, inst_sha) in &installed {
        if !release.contains_key(path) {
            diff.removed.push(DiffEntry {
                path: (*path).to_string(),
                installed_sha256: Some(inst_sha.clone()),
                release_sha256: None,
            });
        }
    }

    diff
}

/// Load a P-256 verifying key from PEM (`-----BEGIN PUBLIC KEY-----`) or DER
/// `SubjectPublicKeyInfo` bytes — this is the device's `ivd-signing` public
/// half. PEM is detected by its armor; otherwise the bytes are treated as DER.
pub fn load_pubkey(bytes: &[u8]) -> Result<p256::ecdsa::VerifyingKey> {
    use p256::pkcs8::DecodePublicKey;

    let public_key = if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        let pem = std::str::from_utf8(bytes).context("public key PEM is not UTF-8")?;
        p256::PublicKey::from_public_key_pem(pem)
            .map_err(|e| anyhow!("parse public key PEM: {e}"))?
    } else {
        p256::PublicKey::from_public_key_der(bytes)
            .map_err(|e| anyhow!("parse public key DER: {e}"))?
    };

    Ok(p256::ecdsa::VerifyingKey::from(&public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey;

    fn fe(path: &str, sha: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            sha256: sha.to_string(),
        }
    }

    // ---- diff logic ----

    #[test]
    fn diff_detects_added_removed_changed() {
        let installed = vec![
            fe("kernel", "aa"),
            fe("rootfs.img", "bb"),
            fe("vm-config.yaml", "cc"),
        ];
        let release = vec![
            fe("kernel", "aa"),     // unchanged
            fe("rootfs.img", "b9"), // changed
            fe("qvm.conf", "dd"),   // added (release-only)
                                    // vm-config.yaml removed (installed-only)
        ];

        let diff = diff_inventory(&installed, &release);

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].path, "qvm.conf");
        assert_eq!(diff.added[0].release_sha256.as_deref(), Some("dd"));
        assert_eq!(diff.added[0].installed_sha256, None);

        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].path, "vm-config.yaml");
        assert_eq!(diff.removed[0].installed_sha256.as_deref(), Some("cc"));
        assert_eq!(diff.removed[0].release_sha256, None);

        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].path, "rootfs.img");
        assert_eq!(diff.changed[0].installed_sha256.as_deref(), Some("bb"));
        assert_eq!(diff.changed[0].release_sha256.as_deref(), Some("b9"));

        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_identical_inventories_is_empty() {
        let files = vec![fe("kernel", "aa"), fe("rootfs.img", "bb")];
        let diff = diff_inventory(&files, &files);
        assert!(diff.is_empty());
        assert_eq!(diff, Diff::default());
    }

    #[test]
    fn diff_sha_compare_is_case_insensitive() {
        let installed = vec![fe("kernel", "ABCDEF")];
        let release = vec![fe("kernel", "abcdef")];
        let diff = diff_inventory(&installed, &release);
        assert!(diff.is_empty(), "uppercase vs lowercase hex must match");
    }

    // ---- signature verify ----

    /// Build a manifest signed over its own `manifest_b64` with `sk`.
    fn signed_manifest(sk: &SigningKey, manifest_bytes: &[u8]) -> InstalledManifest {
        let sig: Signature = sk.sign(manifest_bytes);
        let engine = base64::engine::general_purpose::STANDARD;
        InstalledManifest {
            ivd_version: 3,
            gen: 5,
            signed_at_unix: 1_733_000_000,
            identity: Identity {
                name: "vm1-os".into(),
                version: "1.2.3".into(),
                ..Default::default()
            },
            files: vec![fe("kernel", "00"), fe("rootfs.img", "11")],
            signature_b64: engine.encode(sig.to_der().as_bytes()),
            manifest_b64: engine.encode(manifest_bytes),
        }
    }

    #[test]
    fn verify_accepts_a_good_signature() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let manifest_bytes = b"the exact ivd-manifest.cbor bytes";

        let m = signed_manifest(&sk, manifest_bytes);
        assert_eq!(m.verify(&vk).unwrap(), VerifyStatus::Verified);
    }

    #[test]
    fn verify_rejects_tampered_manifest_bytes() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let manifest_bytes = b"the exact ivd-manifest.cbor bytes";

        let mut m = signed_manifest(&sk, manifest_bytes);
        // Tamper: re-point manifest_b64 at different bytes the sig doesn't cover.
        m.manifest_b64 = base64::engine::general_purpose::STANDARD.encode(b"TAMPERED bytes!!!");
        assert_eq!(m.verify(&vk).unwrap(), VerifyStatus::Invalid);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let other_vk = VerifyingKey::from(&SigningKey::from_bytes(&[9u8; 32].into()).unwrap());
        let manifest_bytes = b"the exact ivd-manifest.cbor bytes";

        let m = signed_manifest(&sk, manifest_bytes);
        assert_eq!(m.verify(&other_vk).unwrap(), VerifyStatus::Invalid);
    }

    #[test]
    fn verify_rejects_garbage_signature_without_erroring() {
        let vk = VerifyingKey::from(&SigningKey::from_bytes(&[7u8; 32].into()).unwrap());
        let engine = base64::engine::general_purpose::STANDARD;
        let m = InstalledManifest {
            signature_b64: engine.encode(b"not-a-der-signature"),
            manifest_b64: engine.encode(b"some bytes"),
            ..Default_manifest()
        };
        // Malformed DER must surface as Invalid, not a tool error.
        assert_eq!(m.verify(&vk).unwrap(), VerifyStatus::Invalid);
    }

    // ---- pubkey loading round-trips through the verify path ----

    #[test]
    fn load_pubkey_roundtrips_pem_and_der() {
        let sk = SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let pk = p256::PublicKey::from(&VerifyingKey::from(&sk));
        let manifest_bytes = b"bytes under signature";
        let m = signed_manifest(&sk, manifest_bytes);

        let pem = pk.to_public_key_pem(Default::default()).unwrap();
        let loaded_pem = load_pubkey(pem.as_bytes()).unwrap();
        assert_eq!(m.verify(&loaded_pem).unwrap(), VerifyStatus::Verified);

        let der = pk.to_public_key_der().unwrap();
        let loaded_der = load_pubkey(der.as_bytes()).unwrap();
        assert_eq!(m.verify(&loaded_der).unwrap(), VerifyStatus::Verified);
    }

    // Helper: a minimal manifest with default (empty) crypto fields.
    #[allow(non_snake_case)]
    fn Default_manifest() -> InstalledManifest {
        InstalledManifest {
            ivd_version: 0,
            gen: 0,
            signed_at_unix: 0,
            identity: Identity::default(),
            files: vec![],
            signature_b64: String::new(),
            manifest_b64: String::new(),
        }
    }
}
