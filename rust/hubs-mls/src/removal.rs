//! Signed device removals, byte for byte the web's (`deviceRemovalBody`,
//! `selfRemoveBody`, `signedRemovalsBody`, `verifyRemoval`,
//! `verifyRemovalStatement` and `removalCounts`).
//!
//! When the server stops listing a device, every other device decides on
//! its own whether to remove it from a conversation. A removal counts when
//! the account's identity key signed it, or the device signed its own. An
//! unsigned one counts only when the person started over in the same
//! commit, or while this device has not seen the account say, with its
//! identity key, that all its removals are signed. So the server alone
//! cannot make anyone drop a device of an account that made that statement.
//!
//! Every signature is a raw Ed25519 signature over the body (the same call
//! that signs a device certificate, `sign_ed25519`), never MLS
//! SignWithLabel, and is verified strictly. `at` is the signer's clock in
//! milliseconds since 1970, written in decimal with no leading zeros; a
//! proof whose time is not a safe JavaScript integer never verifies.

use crate::device::GroupMember;
use crate::hubs::{verify_ed25519, MAX_SAFE_INTEGER};

/// What the account identity key signs to remove one of its devices:
/// `"hubs private dms remove device v1\0" ‖ userId ‖ "\0" ‖ deviceId ‖
/// "\0" ‖ at ‖ "\0"`, then the removed device's 32-byte public key.
#[uniffi::export]
pub fn device_removal_body(
    user_id: String,
    device_id: String,
    device_public_key: Vec<u8>,
    at: i64,
) -> Vec<u8> {
    let mut body =
        format!("hubs private dms remove device v1\0{user_id}\0{device_id}\0{at}\0").into_bytes();
    body.extend_from_slice(&device_public_key);
    body
}

/// What a device signs with its own device key to remove itself (for
/// example when the app signs out): `"hubs private dms self-remove v1\0" ‖
/// userId ‖ "\0" ‖ deviceId ‖ "\0" ‖ at`, with no NUL at the end.
#[uniffi::export]
pub fn self_remove_body(user_id: String, device_id: String, at: i64) -> Vec<u8> {
    format!("hubs private dms self-remove v1\0{user_id}\0{device_id}\0{at}").into_bytes()
}

/// What the account identity key signs to say that every removal of its
/// devices is signed from now on: `"hubs private dms signed removals v1\0"
/// ‖ userId ‖ "\0"`, then the identity public key (32 bytes).
#[uniffi::export]
pub fn signed_removals_body(user_id: String, identity_public_key: Vec<u8>) -> Vec<u8> {
    let mut body = format!("hubs private dms signed removals v1\0{user_id}\0").into_bytes();
    body.extend_from_slice(&identity_public_key);
    body
}

/// What marks a commit's authenticated data as carrying the account's
/// statement, so a contact learns it from the group itself.
const SIGNED_REMOVALS_NOTE_LABEL: &[u8] = b"hubs private dms signed removals note v1\0";

/// A commit's authenticated data once the sender's account has made the
/// statement: the label, then the 64-byte signature over
/// `signed_removals_body`, as the web's `signedRemovalsNote`.
#[uniffi::export]
pub fn signed_removals_note(signature: Vec<u8>) -> Vec<u8> {
    let mut note = SIGNED_REMOVALS_NOTE_LABEL.to_vec();
    note.extend_from_slice(&signature);
    note
}

/// The signature inside a commit's authenticated data, or `None` for
/// anything else (`readSignedRemovalsNote`).
#[uniffi::export]
pub fn read_signed_removals_note(data: Vec<u8>) -> Option<Vec<u8>> {
    let signature = data.strip_prefix(SIGNED_REMOVALS_NOTE_LABEL)?;
    (signature.len() == 64).then(|| signature.to_vec())
}

/// A removed device's proof, as the server lists it for a conversation
/// (its `revoked` entry), with the signature decoded from base64.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemovalProof {
    /// "identity" (the identity key signed `device_removal_body`) or "self"
    /// (the device signed `self_remove_body`). Other kinds ("reset",
    /// "unsigned", "session") carry no proof that verifies.
    pub kind: String,
    /// The time in the signed bytes (milliseconds), `None` when absent.
    pub at: Option<i64>,
    /// The raw Ed25519 signature, 64 bytes.
    pub signature: Vec<u8>,
}

fn verify(member: &GroupMember, proof: &RemovalProof) -> bool {
    let Some(at) = proof
        .at
        .filter(|at| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(at))
    else {
        return false;
    };
    match proof.kind.as_str() {
        "identity" => verify_ed25519(
            &member.identity_public_key,
            &device_removal_body(
                member.user_id.clone(),
                member.device_id.clone(),
                member.device_public_key.clone(),
                at,
            ),
            &proof.signature,
        ),
        "self" => verify_ed25519(
            &member.device_public_key,
            &self_remove_body(member.user_id.clone(), member.device_id.clone(), at),
            &proof.signature,
        ),
        _ => false,
    }
}

/// Whether a removal proof covers this exact group member: the identity key
/// in its credential signed its removal over its device key (kind
/// "identity"), or its own device key signed its self-removal (kind
/// "self"). Check it against the member as the group has it (its leaf),
/// never against keys the server lists.
#[uniffi::export]
pub fn verify_removal(member: GroupMember, proof: RemovalProof) -> bool {
    verify(&member, &proof)
}

/// Whether an identity key signed the statement that its account's
/// removals are signed (`signed_removals_body`).
#[uniffi::export]
pub fn verify_removal_statement(
    user_id: String,
    identity_public_key: Vec<u8>,
    signature: Vec<u8>,
) -> bool {
    verify_ed25519(
        &identity_public_key,
        &signed_removals_body(user_id, identity_public_key.clone()),
        &signature,
    )
}

/// The proof the removal rule weighs (the web's "valid", "invalid" and
/// "none").
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemovalProofState {
    /// A signature that verifies for this member.
    Valid,
    /// A signature that does not verify. Such a removal never counts.
    Invalid,
    /// No removal listed for the device, or one without a signature.
    NoProof,
}

/// The proof state for one member the server no longer lists as active.
/// Pass `None` when the server lists no removal for this device id and
/// user id, or the entry's signature is null or empty. When the entry's
/// signature does not decode as base64, pass the proof with an empty
/// signature: it counts as `Invalid`, as on the web.
#[uniffi::export]
pub fn removal_proof_state(member: GroupMember, proof: Option<RemovalProof>) -> RemovalProofState {
    match proof {
        None => RemovalProofState::NoProof,
        Some(proof) if verify(&member, &proof) => RemovalProofState::Valid,
        Some(_) => RemovalProofState::Invalid,
    }
}

/// The removal rule (`removalCounts`): whether a device the server no
/// longer lists may be removed from a conversation.
///
/// - `Valid`: the proof verifies, so the removal counts.
/// - `Invalid`: a proof is present and does not verify, so the removal never
///   counts, whatever the other two inputs say.
/// - `NoProof`: the removal counts only when `started_over` is true or
///   `signed_removals` is false.
///
/// `started_over` is true only when a key package claimed for this same
/// commit (read with `key_package_credential`) carries a credential with a
/// valid certificate for that same person under a different identity key
/// than the member's, which every device shows as a safety code change. A
/// device the server merely lists under another key is not a start over,
/// since the server writes that list.
///
/// `signed_removals` is true when this device has seen the person's signed
/// removals statement (`verify_removal_statement`) for exactly the member's
/// identity key: pinned from the person's devices, or read from a signed
/// removals note in a commit (`read_signed_removals_note`).
///
/// Otherwise the member stays in the group.
#[uniffi::export]
pub fn removal_counts(proof: RemovalProofState, started_over: bool, signed_removals: bool) -> bool {
    match proof {
        RemovalProofState::Valid => true,
        RemovalProofState::Invalid => false,
        RemovalProofState::NoProof => started_over || !signed_removals,
    }
}
