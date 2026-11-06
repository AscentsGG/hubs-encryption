//! The native core of Hubs private messages: MLS (RFC 9420) on mls-rs with
//! the same settings as the website, the Hubs device credential, message
//! franking and the key package lifetime policy. The iPhone and Mac apps call
//! it through UniFFI (Swift), and the same interface can be generated for
//! Kotlin. The Windows app calls it through `hubs-mls-ffi`.
//!
//! It interoperates byte for byte with the TypeScript implementation that the
//! website uses (`typescript/` at the root of this repository, on ts-mls
//! 1.6.4, ciphersuite 1). `tests/vectors.rs` and `tests/e2ee_vectors.rs`
//! replay fixed vectors made by the TypeScript side, and
//! `tests/live_ts_mls.rs` runs ts-mls live in both directions.
//!
//! Library types never cross the boundary: the app sees bytes, records and
//! two objects (`MlsDevice`, `MlsGroup`), so the MLS library can change
//! behind this interface. The core keeps nothing on disk; the app stores
//! key package private halves and group snapshots in its encrypted store.

uniffi::setup_scaffolding!();

mod device;
mod error;
mod hubs;
mod identity;
mod interop;
mod missing;
mod policy;
mod removal;
mod storage;

pub use device::{
    create_device, create_identity, import_key_package, new_device_id, DeviceKeyPackage,
    DeviceKeys, EncryptedMessage, GroupMember, IdentityKeys, Incoming, MessageHeader, MlsDevice,
    MlsGroup, PendingChange,
};
pub use error::HubsMlsError;
pub use hubs::{
    DeviceCredential, MemberIdentity, MessageDraft, MessagePayload, MAX_BODY_UTF16, TIMERS,
};
pub use missing::{
    due_generations, missing_message_grace_ms, track_generation, DueGenerations, GenerationGap,
    GenerationTrack, ToldGeneration, TrackedArrival, MAX_GENERATION_GAP, MISSING_MESSAGE_GRACE_MS,
};
pub use policy::{
    check_key_package, key_package_credential, key_package_needs_refresh, key_package_policy,
    lifetime_problem, read_key_package, KeyPackageInfo, KeyPackagePolicy,
    KEY_PACKAGE_CLOCK_SKEW_SECONDS, KEY_PACKAGE_LIFETIME_SECONDS, KEY_PACKAGE_REFRESH_SECONDS,
    KEY_PACKAGE_TARGET,
};
pub use removal::{
    device_removal_body, read_signed_removals_note, removal_counts, removal_proof_state,
    self_remove_body, signed_removals_body, signed_removals_note, verify_removal,
    verify_removal_statement, RemovalProof, RemovalProofState,
};
pub use storage::EPOCH_RETENTION;

use mls_rs::{CipherSuite, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// MLS ciphersuite 1: X25519, AES-128-GCM, SHA-256, Ed25519
/// (`PRIVATE_DM_CIPHERSUITE` in the TypeScript implementation).
pub const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

pub(crate) fn suite() -> <RustCryptoProvider as CryptoProvider>::CipherSuiteProvider {
    RustCryptoProvider::with_enabled_cipher_suites(vec![CIPHER_SUITE])
        .cipher_suite_provider(CIPHER_SUITE)
        .expect("ciphersuite 1 is built in")
}

/// The core's version and the libraries behind it, for diagnostics.
#[uniffi::export]
pub fn core_version() -> String {
    format!(
        "hubs-mls {} (mls-rs 0.56.0, mls-rs-crypto-rustcrypto 0.22.1, ciphersuite 1)",
        env!("CARGO_PKG_VERSION")
    )
}

/// What the account identity key signs for one device key.
#[uniffi::export]
pub fn device_certificate_body(
    user_id: String,
    device_id: String,
    device_public_key: Vec<u8>,
) -> Vec<u8> {
    hubs::device_certificate_body(&user_id, &device_id, &device_public_key)
}

/// The MLS credential identity bytes, in the exact JSON the TypeScript
/// implementation writes.
#[uniffi::export]
pub fn credential_identity(credential: DeviceCredential) -> Vec<u8> {
    hubs::credential_identity(&credential)
}

/// Read a credential identity; `None` when it is not a Hubs credential.
#[uniffi::export]
pub fn read_credential_identity(identity: Vec<u8>) -> Option<DeviceCredential> {
    hubs::read_credential_identity(&identity)
}

/// Check a device certificate (strict Ed25519).
#[uniffi::export]
pub fn verify_device_certificate(credential: DeviceCredential, device_public_key: Vec<u8>) -> bool {
    hubs::verify_device_certificate(&credential, &device_public_key)
}

/// The bytes the franking commitment covers.
#[uniffi::export]
pub fn canonical_payload_bytes(payload: MessagePayload) -> Vec<u8> {
    hubs::canonical_payload_bytes(&payload)
}

/// HMAC-SHA256(frankingKey, canonical bytes).
#[uniffi::export]
pub fn franking_commitment(payload: MessagePayload) -> Result<Vec<u8>, HubsMlsError> {
    hubs::franking_commitment(&payload.franking_key, &payload)
}

/// The payload JSON exactly as the TypeScript implementation writes it
/// (used for reports).
#[uniffi::export]
pub fn payload_json(payload: MessagePayload) -> Vec<u8> {
    hubs::payload_json(&payload)
}

/// Read a payload JSON.
#[uniffi::export]
pub fn parse_payload(bytes: Vec<u8>) -> Result<MessagePayload, HubsMlsError> {
    hubs::parse_payload(&bytes)
}

/// Why a decrypted payload (its bytes) may not be shown, or `None`. The
/// bytes must be strict UTF-8 JSON that passes the rule every device applies
/// (`privateDmPayloadProblem` in the TypeScript implementation, with the same
/// wording).
#[uniffi::export]
pub fn payload_problem(bytes: Vec<u8>) -> Option<String> {
    hubs::payload_problem(&bytes)
}

/// The payload limits: the longest text in UTF-16 units, and the timers.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PayloadLimits {
    pub max_body_utf16: u32,
    pub timers: Vec<i64>,
}

#[uniffi::export]
pub fn payload_limits() -> PayloadLimits {
    PayloadLimits {
        max_body_utf16: MAX_BODY_UTF16,
        timers: TIMERS.to_vec(),
    }
}

/// An Ed25519 signature (RFC 8032, deterministic) with a signing key in
/// either form the TypeScript implementation writes (a 32-byte seed or the
/// 48-byte PKCS#8).
#[uniffi::export]
pub fn sign_ed25519(signing_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, HubsMlsError> {
    use ed25519_dalek::Signer;
    Ok(hubs::signing_key(&signing_key)?
        .sign(&message)
        .to_bytes()
        .to_vec())
}

/// Strict Ed25519 verification (RFC 8032): `false` for a key of small
/// order, a non-canonical signature, bytes of the wrong size, or a
/// signature that does not cover `message`. For signatures the core does
/// not check itself, such as call connection bindings and roster
/// statements.
#[uniffi::export]
pub fn verify_ed25519(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    hubs::verify_ed25519(&public_key, &message, &signature)
}

/// The passkey backup rule (`backupRollbackProblem`): why a backup whose
/// bundle carries `counter` (`None` when it has none) may not be restored
/// on a device that has seen counters up to `seen`, in the web's own
/// words, or `None`. A counter that is present but not a whole number is
/// not valid either: pass `Some(-1)` for it.
#[uniffi::export]
pub fn backup_rollback_problem(counter: Option<i64>, seen: u64) -> Option<String> {
    hubs::backup_rollback_problem(counter, seen).map(str::to_owned)
}

/// Why a key package lifetime is outside the policy at `now`, or `None`
/// (the adder's rule, `keyPackageLifetimeProblem`).
#[uniffi::export]
pub fn key_package_lifetime_problem(
    not_before: u64,
    not_after: u64,
    now_seconds: u64,
) -> Option<String> {
    policy::lifetime_problem(not_before, not_after, now_seconds).map(str::to_owned)
}

/// For tests only. It reads a group state saved by the TypeScript
/// implementation (`receiverStateHex` in the cross-platform vectors) into a
/// snapshot that `MlsDevice::load_group` reads, so a test can replay the
/// vectors as the TypeScript device. It stays exported because the apps'
/// vector tests call it through the bindings. An app must never call it: a
/// device only ever loads snapshots it saved itself (see `interop.rs`).
#[uniffi::export]
pub fn import_web_group_state(state: Vec<u8>) -> Result<Vec<u8>, HubsMlsError> {
    interop::import_web_group_state(&state)
}

/// The membership rule: why this device must refuse a group with these
/// members, or `None` (`membershipProblem` in the TypeScript implementation,
/// with the same wording). `peer` is the other person once pinned.
#[uniffi::export]
pub fn membership_problem(
    members: Vec<MemberIdentity>,
    self_user_id: String,
    self_identity_public_key: Vec<u8>,
    peer: Option<String>,
) -> Option<String> {
    hubs::membership_problem(
        &members,
        &self_user_id,
        &self_identity_public_key,
        peer.as_deref(),
    )
    .map(str::to_owned)
}
