//! A JSON C ABI over the private messages core (`hubs-mls`), for the Hubs
//! Windows app, which loads this library from .NET.
//!
//! One call: `hubs_mls_call` takes a UTF-8 JSON request `{"op": ..., ...}`
//! and returns a UTF-8 JSON answer, `{"ok": ...}` or `{"error": {"kind",
//! "reason"}}`, which the caller frees with `hubs_mls_free`. Bytes travel as
//! standard base64, as on the wire. Devices and conversations stay inside
//! the core as handles; the app keeps only their snapshots, in its
//! protected store. A panic is caught here and answered as an error.
//!
//! Nothing here is cryptography of its own: MLS, HPKE, the signatures and
//! the Hubs constructions come from hubs-mls, mls-rs and the RustCrypto
//! crates it already uses.
//!
//! Requests and answers carry secrets (keys, snapshots, message text), so
//! wiping here is best effort, and narrow: the request's and the answer's
//! JSON trees are wiped once a call is done, the answer is written into a
//! buffer of its exact size, and `hubs_mls_free` wipes that buffer before
//! freeing it. The working copies a call makes of a value (a decoded key, a
//! snapshot, message text) and what the core holds are not wiped here, and a
//! request a panic stopped is not wiped at all. Counts a caller passes are
//! capped.

use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
};

use base64ct::{Base64, Encoding};
use hubs_mls::{
    DeviceCredential, DeviceKeyPackage, DeviceKeys, GenerationGap, GenerationTrack, GroupMember,
    HubsMlsError, IdentityKeys, Incoming, KeyPackageInfo, MessageDraft, MessagePayload, MlsDevice,
    MlsGroup, RemovalProof, RemovalProofState, ToldGeneration,
};
use mls_rs::{
    crypto::{HpkeCiphertext, HpkePublicKey, HpkeSecretKey},
    mls_rs_codec::{byte_vec, MlsDecode},
    CipherSuiteProvider, CryptoProvider, MlsMessage, WireFormat,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

type Answer = Result<Value, (String, String)>;

/// The most random bytes one `random` call returns.
pub const MAX_RANDOM_BYTES: u64 = 1024;
/// The most key packages one `createKeyPackages` call makes (a device keeps 20).
pub const MAX_KEY_PACKAGES: u64 = 100;

/// Wipes every string in a JSON value (keys and values alike), leaving it empty.
pub fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => {
            for (mut key, mut item) in std::mem::take(fields) {
                key.zeroize();
                wipe(&mut item);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

/// A count from the request, refused above `max` (and at 0).
fn capped(request: &Value, key: &str, max: u64) -> Result<u64, (String, String)> {
    match number(request, key)? {
        n @ 1.. if n <= max => Ok(n),
        _ => Err(fail("request", format!("{key} must be from 1 to {max}"))),
    }
}

fn fail(kind: &str, reason: impl Into<String>) -> (String, String) {
    (kind.to_owned(), reason.into())
}

fn core_error(error: HubsMlsError) -> (String, String) {
    let kind = match &error {
        HubsMlsError::Malformed { .. } => "malformed",
        HubsMlsError::Credential { .. } => "credential",
        HubsMlsError::KeyPackageLifetime { .. } => "keyPackageLifetime",
        HubsMlsError::WrongConversation => "wrongConversation",
        HubsMlsError::NotEncrypted => "notEncrypted",
        HubsMlsError::Payload { .. } => "payload",
        HubsMlsError::FrankingMismatch => "frankingMismatch",
        HubsMlsError::SenderMismatch => "senderMismatch",
        HubsMlsError::PendingCommit { .. } => "pendingCommit",
        HubsMlsError::WrongDevice => "wrongDevice",
        HubsMlsError::Mls { .. } => "mls",
    };
    (kind.to_owned(), error.to_string())
}

// Handles.

#[derive(Default)]
struct Handles {
    devices: HashMap<u64, Arc<MlsDevice>>,
    groups: HashMap<u64, Arc<MlsGroup>>,
}

static NEXT: AtomicU64 = AtomicU64::new(1);

fn handles() -> std::sync::MutexGuard<'static, Handles> {
    static HANDLES: LazyLock<Mutex<Handles>> = LazyLock::new(Mutex::default);
    HANDLES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn device(request: &Value) -> Result<Arc<MlsDevice>, (String, String)> {
    let id = number(request, "device")?;
    handles()
        .devices
        .get(&id)
        .cloned()
        .ok_or_else(|| fail("handle", "no such device"))
}

fn group(request: &Value) -> Result<Arc<MlsGroup>, (String, String)> {
    let id = number(request, "group")?;
    handles()
        .groups
        .get(&id)
        .cloned()
        .ok_or_else(|| fail("handle", "no such conversation"))
}

fn keep_group(group: Arc<MlsGroup>) -> Value {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    handles().groups.insert(id, group);
    json!({ "group": id })
}

// Reading.

fn text(request: &Value, key: &str) -> Result<String, (String, String)> {
    request
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| fail("request", format!("{key} must be text")))
}

fn number(request: &Value, key: &str) -> Result<u64, (String, String)> {
    request
        .get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| fail("request", format!("{key} must be a whole number")))
}

fn integer(request: &Value, key: &str) -> Result<i64, (String, String)> {
    request
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| fail("request", format!("{key} must be a whole number")))
}

fn bytes(request: &Value, key: &str) -> Result<Vec<u8>, (String, String)> {
    let encoded = text(request, key)?;
    Base64::decode_vec(&encoded).map_err(|_| fail("request", format!("{key} must be base64")))
}

fn b64(data: &[u8]) -> Value {
    Value::String(Base64::encode_string(data))
}

fn identity_keys(value: &Value) -> Result<IdentityKeys, (String, String)> {
    Ok(IdentityKeys {
        public_key: bytes(value, "publicKey")?,
        signing_key: bytes(value, "signingKey")?,
    })
}

fn device_keys(value: &Value) -> Result<DeviceKeys, (String, String)> {
    Ok(DeviceKeys {
        user_id: text(value, "userId")?,
        device_id: text(value, "deviceId")?,
        identity_public_key: bytes(value, "identityPublicKey")?,
        device_public_key: bytes(value, "devicePublicKey")?,
        device_signing_key: bytes(value, "deviceSigningKey")?,
        certificate: bytes(value, "certificate")?,
    })
}

fn device_keys_value(keys: &DeviceKeys) -> Value {
    json!({
        "userId": keys.user_id,
        "deviceId": keys.device_id,
        "identityPublicKey": b64(&keys.identity_public_key),
        "devicePublicKey": b64(&keys.device_public_key),
        "deviceSigningKey": b64(&keys.device_signing_key),
        "certificate": b64(&keys.certificate),
    })
}

fn key_package(value: &Value) -> Result<DeviceKeyPackage, (String, String)> {
    Ok(DeviceKeyPackage {
        id: text(value, "id")?,
        public_package: bytes(value, "publicPackage")?,
        private_package: bytes(value, "privatePackage")?,
        created_at: number(value, "createdAt")?,
        not_after: number(value, "notAfter")?,
    })
}

fn key_package_value(package: &DeviceKeyPackage) -> Value {
    json!({
        "id": package.id,
        "publicPackage": b64(&package.public_package),
        "privatePackage": b64(&package.private_package),
        "createdAt": package.created_at,
        "notAfter": package.not_after,
    })
}

fn info_value(info: &KeyPackageInfo) -> Value {
    json!({
        "userId": info.user_id,
        "deviceId": info.device_id,
        "identityPublicKey": b64(&info.identity_public_key),
        "devicePublicKey": b64(&info.device_public_key),
        "notBefore": info.not_before.to_string(),
        "notAfter": info.not_after.to_string(),
    })
}

fn member_value(member: &GroupMember) -> Value {
    json!({
        "leafIndex": member.leaf_index,
        "userId": member.user_id,
        "deviceId": member.device_id,
        "identityPublicKey": b64(&member.identity_public_key),
        "devicePublicKey": b64(&member.device_public_key),
    })
}

fn members_value(members: &[GroupMember]) -> Value {
    Value::Array(members.iter().map(member_value).collect())
}

fn credential(value: &Value) -> Result<DeviceCredential, (String, String)> {
    Ok(DeviceCredential {
        user_id: text(value, "userId")?,
        device_id: text(value, "deviceId")?,
        identity_public_key: bytes(value, "identityPublicKey")?,
        certificate: bytes(value, "certificate")?,
    })
}

fn credential_value(credential: &DeviceCredential) -> Value {
    json!({
        "userId": credential.user_id,
        "deviceId": credential.device_id,
        "identityPublicKey": b64(&credential.identity_public_key),
        "certificate": b64(&credential.certificate),
    })
}

fn payload(value: &Value) -> Result<MessagePayload, (String, String)> {
    Ok(MessagePayload {
        id: text(value, "id")?,
        kind: text(value, "kind")?,
        body: text(value, "body")?,
        sent_at: integer(value, "sentAt")?,
        expires_in_seconds: integer(value, "expiresInSeconds")?,
        user_id: text(value, "userId")?,
        device_id: text(value, "deviceId")?,
        franking_key: bytes(value, "frankingKey")?,
    })
}

fn payload_value(payload: &MessagePayload) -> Value {
    json!({
        "v": 1,
        "id": payload.id,
        "kind": payload.kind,
        "body": payload.body,
        "sentAt": payload.sent_at,
        "expiresInSeconds": payload.expires_in_seconds,
        "userId": payload.user_id,
        "deviceId": payload.device_id,
        "frankingKey": b64(&payload.franking_key),
    })
}

/// A group member for the removal rule: `leafIndex` may be left out.
fn removal_member(value: &Value) -> Result<GroupMember, (String, String)> {
    Ok(GroupMember {
        leaf_index: value.get("leafIndex").and_then(Value::as_u64).unwrap_or(0) as u32,
        user_id: text(value, "userId")?,
        device_id: text(value, "deviceId")?,
        identity_public_key: bytes(value, "identityPublicKey")?,
        device_public_key: bytes(value, "devicePublicKey")?,
    })
}

/// A server `revoked` entry as the core weighs it: `None` without one or
/// without a signature; a signature that is not base64 is kept as empty, so
/// it counts as invalid (the core's `removal_proof_state` rule).
fn removal_proof(value: Option<&Value>) -> Option<RemovalProof> {
    let value = value.filter(|v| v.is_object())?;
    let signature = value
        .get("signature")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    Some(RemovalProof {
        kind: value
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        at: value.get("at").and_then(Value::as_i64),
        signature: Base64::decode_vec(signature).unwrap_or_default(),
    })
}

fn proof_state_value(state: RemovalProofState) -> Value {
    Value::String(
        match state {
            RemovalProofState::Valid => "valid",
            RemovalProofState::Invalid => "invalid",
            RemovalProofState::NoProof => "none",
        }
        .to_owned(),
    )
}

fn proof_state(value: &Value) -> Result<RemovalProofState, (String, String)> {
    match value.as_str() {
        Some("valid") => Ok(RemovalProofState::Valid),
        Some("invalid") => Ok(RemovalProofState::Invalid),
        Some("none") => Ok(RemovalProofState::NoProof),
        _ => Err(fail("request", "proof must be valid, invalid or none")),
    }
}

fn flag(request: &Value, key: &str) -> Result<bool, (String, String)> {
    request
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| fail("request", format!("{key} must be true or false")))
}

fn generation_track(value: &Value) -> Result<GenerationTrack, (String, String)> {
    let list = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let gaps = list("gaps")
        .iter()
        .map(|gap| {
            Ok(GenerationGap {
                generation: whole32(gap, "generation")?,
                at: integer(gap, "at")?,
                before: integer(gap, "before")?,
            })
        })
        .collect::<Result<Vec<_>, (String, String)>>()?;
    let told = list("told")
        .iter()
        .map(|item| {
            Ok(ToldGeneration {
                generation: whole32(item, "generation")?,
                notice: text(item, "notice")?,
            })
        })
        .collect::<Result<Vec<_>, (String, String)>>()?;
    Ok(GenerationTrack {
        user_id: text(value, "userId")?,
        next: whole32(value, "next")?,
        gaps,
        told,
    })
}

/// A whole number that fits in 32 bits.
fn whole32(request: &Value, key: &str) -> Result<u32, (String, String)> {
    u32::try_from(number(request, key)?)
        .map_err(|_| fail("request", format!("{key} must fit in 32 bits")))
}

fn gap_value(gap: &GenerationGap) -> Value {
    json!({ "generation": gap.generation, "at": gap.at, "before": gap.before })
}

fn track_value(track: &GenerationTrack) -> Value {
    json!({
        "userId": track.user_id,
        "next": track.next,
        "gaps": track.gaps.iter().map(gap_value).collect::<Vec<_>>(),
        "told": track
            .told
            .iter()
            .map(|t| json!({ "generation": t.generation, "notice": t.notice }))
            .collect::<Vec<_>>(),
    })
}

// Keys.

const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// An Ed25519 signing key from a 32-byte seed or a 48-byte PKCS#8.
fn ed25519(bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, (String, String)> {
    let seed: [u8; 32] = match bytes.len() {
        32 => bytes.try_into().expect("32 bytes"),
        48 if bytes[..16] == PKCS8_ED25519_PREFIX => bytes[16..].try_into().expect("32 bytes"),
        _ => return Err(fail("malformed", "not an Ed25519 signing key")),
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn x25519_secret(bytes: &[u8]) -> Result<x25519_dalek::StaticSecret, (String, String)> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fail("malformed", "an X25519 key is 32 bytes"))?;
    Ok(x25519_dalek::StaticSecret::from(raw))
}

fn suite() -> <RustCryptoProvider as CryptoProvider>::CipherSuiteProvider {
    RustCryptoProvider::with_enabled_cipher_suites(vec![hubs_mls::CIPHER_SUITE])
        .cipher_suite_provider(hubs_mls::CIPHER_SUITE)
        .expect("ciphersuite 1 is built in")
}

fn crypto_error<E: std::fmt::Debug>(error: E) -> (String, String) {
    fail("crypto", format!("{error:?}"))
}

/// RFC 9420 PrivateMessage up to its authenticated data: group_id<V>,
/// epoch (u64), content_type (u8), authenticated_data<V>.
fn private_authenticated_data(reader: &mut &[u8]) -> Option<Vec<u8>> {
    let _group_id: Vec<u8> = byte_vec::mls_decode(reader).ok()?;
    let _epoch = u64::mls_decode(reader).ok()?;
    let _content_type = u8::mls_decode(reader).ok()?;
    byte_vec::mls_decode(reader).ok()
}

// Calls.

fn run(request: &Value) -> Answer {
    let op = text(request, "op")?;
    match op.as_str() {
        "version" => Ok(json!({ "version": hubs_mls::core_version() })),

        // Identity and device keys.
        "createIdentity" => {
            let keys = hubs_mls::create_identity().map_err(core_error)?;
            Ok(json!({ "publicKey": b64(&keys.public_key), "signingKey": b64(&keys.signing_key) }))
        }
        "createDevice" => {
            let identity = identity_keys(request.get("identity").unwrap_or(&Value::Null))?;
            let keys = hubs_mls::create_device(
                identity,
                text(request, "userId")?,
                text(request, "deviceId")?,
            )
            .map_err(core_error)?;
            Ok(device_keys_value(&keys))
        }
        "newDeviceId" => Ok(json!({ "id": hubs_mls::new_device_id().map_err(core_error)? })),
        "deviceOpen" => {
            let keys = device_keys(request.get("keys").unwrap_or(&Value::Null))?;
            let device = MlsDevice::new(keys).map_err(core_error)?;
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            handles().devices.insert(id, device);
            Ok(json!({ "device": id }))
        }
        "release" => {
            let mut all = handles();
            if let Ok(id) = number(request, "device") {
                all.devices.remove(&id);
            }
            if let Ok(id) = number(request, "group") {
                all.groups.remove(&id);
            }
            Ok(Value::Null)
        }

        // Key packages.
        "createKeyPackages" => {
            let made = device(request)?
                .create_key_packages(
                    capped(request, "count", MAX_KEY_PACKAGES)? as u32,
                    number(request, "now")?,
                )
                .map_err(core_error)?;
            Ok(Value::Array(made.iter().map(key_package_value).collect()))
        }
        "importKeyPackage" => {
            let made = hubs_mls::import_key_package(
                text(request, "id")?,
                bytes(request, "publicPackage")?,
                bytes(request, "initPrivateKey")?,
                bytes(request, "encryptionPrivateKey")?,
                number(request, "createdAt")?,
            )
            .map_err(core_error)?;
            Ok(key_package_value(&made))
        }
        "readKeyPackage" => Ok(info_value(
            &hubs_mls::read_key_package(bytes(request, "keyPackage")?).map_err(core_error)?,
        )),
        "checkKeyPackage" => Ok(info_value(
            &hubs_mls::check_key_package(bytes(request, "keyPackage")?, number(request, "now")?)
                .map_err(core_error)?,
        )),
        // Who a published key package names, or null when it can't be read.
        // This only reads it: checkKeyPackage is what verifies a package.
        "keyPackageCredential" => Ok(hubs_mls::key_package_credential(bytes(
            request,
            "keyPackage",
        )?)
        .map(|c| credential_value(&c))
        .unwrap_or(Value::Null)),
        "lifetimeProblem" => Ok(json!({
            "problem": hubs_mls::lifetime_problem(
                number(request, "notBefore")?,
                number(request, "notAfter")?,
                number(request, "now")?,
            )
        })),

        // Conversations.
        "startGroup" => {
            let made = device(request)?
                .start_group(text(request, "conversationId")?, number(request, "now")?)
                .map_err(core_error)?;
            Ok(keep_group(made))
        }
        "joinFromWelcome" => {
            let made = device(request)?
                .join_from_welcome(
                    bytes(request, "welcome")?,
                    key_package(request.get("keyPackage").unwrap_or(&Value::Null))?,
                    text(request, "conversationId")?,
                )
                .map_err(core_error)?;
            Ok(keep_group(made))
        }
        "loadGroup" => {
            let made = device(request)?
                .load_group(bytes(request, "snapshot")?)
                .map_err(core_error)?;
            Ok(keep_group(made))
        }
        "groupState" => {
            let group = group(request)?;
            Ok(json!({
                "conversationId": group.conversation_id(),
                "epoch": group.epoch(),
                "ownLeaf": group.own_leaf_index(),
                "members": members_value(&group.members()),
                "pending": group.has_pending_commit(),
            }))
        }
        "changeDevices" => {
            let add = request
                .get("add")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .and_then(|s| Base64::decode_vec(s).ok())
                                .ok_or_else(|| fail("request", "add holds base64 key packages"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            // A bad entry refuses the request, as in `add`: dropped or cut
            // down, it would make a commit that removes nobody or the wrong leaf.
            let remove = request
                .get("removeLeaves")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_u64()
                                .and_then(|n| u32::try_from(n).ok())
                                .ok_or_else(|| fail("request", "removeLeaves holds leaf numbers"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            // The signed removals note, carried in the commit's authenticated data.
            let note = match request.get("note") {
                None | Some(Value::Null) => None,
                Some(_) => Some(bytes(request, "note")?),
            };
            let change = group(request)?
                .change_devices(add, remove, number(request, "now")?, note)
                .map_err(core_error)?;
            Ok(json!({
                "commit": b64(&change.commit),
                "welcome": change.welcome.as_deref().map(b64),
                "epoch": change.epoch,
                "added": change.added.iter().map(info_value).collect::<Vec<_>>(),
                "removedLeaves": change.removed_leaves,
            }))
        }
        "mergePending" => Ok(json!({
            "members": members_value(&group(request)?.merge_pending_commit().map_err(core_error)?)
        })),
        "clearPending" => {
            group(request)?.clear_pending_commit();
            Ok(Value::Null)
        }
        "encrypt" => {
            let draft = request.get("draft").unwrap_or(&Value::Null);
            let sent = group(request)?
                .encrypt_message(MessageDraft {
                    id: text(draft, "id")?,
                    kind: text(draft, "kind")?,
                    body: text(draft, "body")?,
                    sent_at: integer(draft, "sentAt")?,
                    expires_in_seconds: integer(draft, "expiresInSeconds")?,
                })
                .map_err(core_error)?;
            Ok(json!({
                "ciphertext": b64(&sent.ciphertext),
                "commitment": b64(&sent.commitment),
                "payload": payload_value(&sent.payload),
                "epoch": sent.epoch,
            }))
        }
        "receive" => match group(request)?
            .receive(bytes(request, "message")?)
            .map_err(core_error)?
        {
            Incoming::Message {
                payload,
                commitment,
                sender,
                epoch,
            } => Ok(json!({
                "type": "message",
                "payload": payload_value(&payload),
                "commitment": b64(&commitment),
                "sender": member_value(&sender),
                "epoch": epoch,
            })),
            Incoming::Change {
                members,
                committer,
                committer_member,
                removal_statement,
                epoch,
            } => Ok(json!({
                "type": "change",
                "members": members_value(&members),
                "committer": committer,
                "committerMember": committer_member.as_ref().map(member_value),
                "removalStatement": removal_statement.as_deref().map(b64),
                "epoch": epoch,
            })),
            Incoming::Removed { epoch } => Ok(json!({ "type": "removed", "epoch": epoch })),
        },
        "snapshot" => Ok(json!({
            "snapshot": b64(&group(request)?.snapshot().map_err(core_error)?)
        })),
        "inspectMessage" => {
            let raw = bytes(request, "message")?;
            let message =
                MlsMessage::from_bytes(&raw).map_err(|e| fail("malformed", e.to_string()))?;
            // A private message's authenticated data travels in the clear. For Hubs it
            // is the franking commitment the server stamps. It starts after the
            // version and wire format.
            let authenticated = match message.wire_format() {
                WireFormat::PrivateMessage => raw
                    .get(4..)
                    .and_then(|mut rest| private_authenticated_data(&mut rest))
                    .map(|data| b64(&data)),
                _ => None,
            };
            let wire = match message.wire_format() {
                WireFormat::PublicMessage => "publicMessage",
                WireFormat::PrivateMessage => "privateMessage",
                WireFormat::Welcome => "welcome",
                WireFormat::GroupInfo => "groupInfo",
                WireFormat::KeyPackage => "keyPackage",
                _ => "other",
            };
            Ok(json!({
                "wireFormat": wire,
                "groupId": message.group_id().map(b64),
                "epoch": message.epoch(),
                "authenticatedData": authenticated,
            }))
        }

        // The Hubs layer.
        "deviceCertificateBody" => Ok(b64(&hubs_mls::device_certificate_body(
            text(request, "userId")?,
            text(request, "deviceId")?,
            bytes(request, "devicePublicKey")?,
        ))),
        "credentialIdentity" => Ok(b64(&hubs_mls::credential_identity(credential(
            request.get("credential").unwrap_or(&Value::Null),
        )?))),
        "readCredentialIdentity" => Ok(hubs_mls::read_credential_identity(bytes(
            request, "identity",
        )?)
        .map(|c| credential_value(&c))
        .unwrap_or(Value::Null)),
        "verifyDeviceCertificate" => Ok(Value::Bool(hubs_mls::verify_device_certificate(
            credential(request.get("credential").unwrap_or(&Value::Null))?,
            bytes(request, "devicePublicKey")?,
        ))),
        // The core reads the bytes as a decrypted payload: strict UTF-8 JSON, then the rule.
        "payloadProblem" => Ok(json!({
            "problem": hubs_mls::payload_problem(bytes(request, "payload")?)
        })),
        "parsePayload" => Ok(payload_value(
            &hubs_mls::parse_payload(bytes(request, "payload")?).map_err(core_error)?,
        )),
        "payloadJson" => Ok(b64(&hubs_mls::payload_json(payload(
            request.get("payload").unwrap_or(&Value::Null),
        )?))),
        "canonicalPayloadBytes" => Ok(b64(&hubs_mls::canonical_payload_bytes(payload(
            request.get("payload").unwrap_or(&Value::Null),
        )?))),
        "frankingCommitment" => Ok(b64(&hubs_mls::franking_commitment(payload(
            request.get("payload").unwrap_or(&Value::Null),
        )?)
        .map_err(core_error)?)),

        // Signed device removals: the exact bytes, and the rule.
        "deviceRemovalBody" => Ok(b64(&hubs_mls::device_removal_body(
            text(request, "userId")?,
            text(request, "deviceId")?,
            bytes(request, "devicePublicKey")?,
            integer(request, "at")?,
        ))),
        "selfRemoveBody" => Ok(b64(&hubs_mls::self_remove_body(
            text(request, "userId")?,
            text(request, "deviceId")?,
            integer(request, "at")?,
        ))),
        "signedRemovalsBody" => Ok(b64(&hubs_mls::signed_removals_body(
            text(request, "userId")?,
            bytes(request, "identityPublicKey")?,
        ))),
        // The statement as a commit carries it: bytes that are not a note read as null.
        "signedRemovalsNote" => Ok(b64(&hubs_mls::signed_removals_note(bytes(
            request,
            "signature",
        )?))),
        "readSignedRemovalsNote" => Ok(hubs_mls::read_signed_removals_note(bytes(request, "data")?)
            .as_deref()
            .map(b64)
            .unwrap_or(Value::Null)),
        // A proof with no signature never verifies.
        "verifyRemoval" => Ok(Value::Bool(
            removal_proof(request.get("proof")).is_some_and(|proof| {
                removal_member(request.get("member").unwrap_or(&Value::Null))
                    .is_ok_and(|member| hubs_mls::verify_removal(member, proof))
            }),
        )),
        "verifyRemovalStatement" => Ok(Value::Bool(hubs_mls::verify_removal_statement(
            text(request, "userId")?,
            bytes(request, "identityPublicKey")?,
            bytes(request, "signature").unwrap_or_default(),
        ))),
        // `proof` is the server's revoked entry as listed, or null.
        "removalProofState" => Ok(proof_state_value(hubs_mls::removal_proof_state(
            removal_member(request.get("member").unwrap_or(&Value::Null))?,
            removal_proof(request.get("proof")),
        ))),
        "removalCounts" => Ok(Value::Bool(hubs_mls::removal_counts(
            proof_state(request.get("proof").unwrap_or(&Value::Null))?,
            flag(request, "startedOver")?,
            flag(request, "signedRemovals")?,
        ))),

        // The passkey backup counter: null for no counter; anything
        // that is not a whole number is not valid.
        "backupRollbackProblem" => {
            let counter = match request.get("counter") {
                None | Some(Value::Null) => None,
                Some(value) => Some(value.as_i64().unwrap_or(-1)),
            };
            Ok(json!({
                "problem": hubs_mls::backup_rollback_problem(counter, number(request, "seen")?)
            }))
        }

        // Missing messages: read before receive, so one that
        // does not open still counts. Null for commits, other groups and
        // epochs this device does not hold.
        "messageHeader" => Ok(group(request)?
            .message_header(bytes(request, "message")?)
            .map(|header| {
                json!({
                    "epoch": header.epoch,
                    "senderLeafIndex": header.sender_leaf_index,
                    "generation": header.generation,
                })
            })
            .unwrap_or(Value::Null)),
        "trackGeneration" => {
            let arrival = hubs_mls::track_generation(
                generation_track(request.get("track").unwrap_or(&Value::Null))?,
                whole32(request, "generation")?,
                integer(request, "now")?,
                integer(request, "shownAt")?,
            );
            Ok(json!({ "track": track_value(&arrival.track), "settled": arrival.settled }))
        }
        "dueGenerations" => {
            let checked = hubs_mls::due_generations(
                generation_track(request.get("track").unwrap_or(&Value::Null))?,
                integer(request, "now")?,
                text(request, "notice")?,
            );
            Ok(json!({
                "track": track_value(&checked.track),
                "due": checked.due.iter().map(gap_value).collect::<Vec<_>>(),
            }))
        }
        "missingMessageGraceMs" => Ok(json!(hubs_mls::missing_message_grace_ms())),

        // Primitives .NET does not have, from the core's own crates.
        "ed25519PublicKey" => Ok(b64(ed25519(&bytes(request, "signingKey")?)?
            .verifying_key()
            .as_bytes())),
        "ed25519Sign" => {
            use ed25519_dalek::Signer;
            Ok(b64(&ed25519(&bytes(request, "signingKey")?)?
                .sign(&bytes(request, "message")?)
                .to_bytes()))
        }
        "ed25519Verify" => {
            let key: [u8; 32] = bytes(request, "publicKey")?
                .try_into()
                .map_err(|_| fail("malformed", "an Ed25519 public key is 32 bytes"))?;
            let ok = ed25519_dalek::VerifyingKey::from_bytes(&key)
                .ok()
                .zip(ed25519_dalek::Signature::from_slice(&bytes(request, "signature")?).ok())
                .is_some_and(|(key, signature)| {
                    key.verify_strict(&bytes(request, "message").unwrap_or_default(), &signature)
                        .is_ok()
                });
            Ok(Value::Bool(ok))
        }
        // Strict Ed25519 that answers false for any size or encoding problem
        // (call bindings, roster statements); ed25519Verify refuses a short key.
        "verifyEd25519" => Ok(Value::Bool(hubs_mls::verify_ed25519(
            bytes(request, "publicKey").unwrap_or_default(),
            bytes(request, "message").unwrap_or_default(),
            bytes(request, "signature").unwrap_or_default(),
        ))),
        "x25519PublicKey" => Ok(b64(x25519_dalek::PublicKey::from(&x25519_secret(&bytes(
            request,
            "privateKey",
        )?)?)
        .as_bytes())),
        "x25519Shared" => {
            let public: [u8; 32] = bytes(request, "publicKey")?
                .try_into()
                .map_err(|_| fail("malformed", "an X25519 key is 32 bytes"))?;
            Ok(b64(x25519_secret(&bytes(request, "privateKey")?)?
                .diffie_hellman(&x25519_dalek::PublicKey::from(public))
                .as_bytes()))
        }
        // RFC 9180 base mode with the ciphersuite's HPKE (DHKEM X25519,
        // HKDF-SHA256, AES-128-GCM), used to hand keys to a newly linked device.
        "hpkeGenerate" => {
            let (secret, public) = suite().kem_generate().map_err(crypto_error)?;
            Ok(json!({ "privateKey": b64(&secret), "publicKey": b64(&public) }))
        }
        "hpkeSeal" => {
            let public = HpkePublicKey::from(bytes(request, "publicKey")?);
            suite()
                .kem_public_key_validate(&public)
                .map_err(crypto_error)?;
            let aad = bytes(request, "aad").unwrap_or_default();
            let sealed = suite()
                .hpke_seal(
                    &public,
                    &bytes(request, "info")?,
                    (!aad.is_empty()).then_some(aad.as_slice()),
                    &bytes(request, "plaintext")?,
                )
                .map_err(crypto_error)?;
            Ok(json!({ "enc": b64(&sealed.kem_output), "ciphertext": b64(&sealed.ciphertext) }))
        }
        "hpkeOpen" => {
            let private = bytes(request, "privateKey")?;
            let public = x25519_dalek::PublicKey::from(&x25519_secret(&private)?);
            let aad = bytes(request, "aad").unwrap_or_default();
            let opened = suite()
                .hpke_open(
                    &HpkeCiphertext {
                        kem_output: bytes(request, "enc")?,
                        ciphertext: bytes(request, "ciphertext")?,
                    },
                    &HpkeSecretKey::from(private),
                    &HpkePublicKey::from(public.as_bytes().to_vec()),
                    &bytes(request, "info")?,
                    (!aad.is_empty()).then_some(aad.as_slice()),
                )
                .map_err(crypto_error)?;
            Ok(b64(&opened))
        }
        "random" => {
            let mut made = suite()
                .random_bytes_vec(capped(request, "count", MAX_RANDOM_BYTES)? as usize)
                .map_err(crypto_error)?;
            let answer = b64(&made);
            made.zeroize();
            Ok(answer)
        }
        _ => Err(fail("request", format!("unknown op {op}"))),
    }
}

/// Counts the bytes written, so the answer's buffer is made once at its exact size.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The answer for one request, as JSON bytes in a buffer of their exact
/// size. The strings in the request's and the answer's JSON trees are wiped
/// before it returns, unless a panic stopped the call.
pub fn call_bytes(request: &[u8]) -> Box<[u8]> {
    let answer = catch_unwind(AssertUnwindSafe(|| {
        let mut request: Value = serde_json::from_slice(request)
            .map_err(|_| fail("request", "the request is not JSON"))?;
        let answer = run(&request);
        wipe(&mut request);
        answer
    }))
    .unwrap_or_else(|_| Err(fail("panic", "the core stopped on this request")));
    let mut out = Map::new();
    match answer {
        Ok(value) => {
            out.insert("ok".into(), value);
        }
        Err((kind, reason)) => {
            out.insert("error".into(), json!({ "kind": kind, "reason": reason }));
        }
    }
    let mut value = Value::Object(out);
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, &value).expect("JSON values always serialize");
    let mut buffer = vec![0u8; counter.0].into_boxed_slice();
    serde_json::to_writer(&mut buffer[..], &value).expect("the buffer is the answer's size");
    wipe(&mut value);
    buffer
}

/// The answer for one request, as JSON text (tests and tools).
pub fn call(request: &[u8]) -> String {
    let mut bytes = call_bytes(request);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    bytes.zeroize();
    text
}

/// Answers one JSON request. The answer is `*out_len` bytes of UTF-8 JSON;
/// free it with `hubs_mls_free`.
///
/// # Safety
/// `request` points at `request_len` readable bytes and `out_len` at a
/// writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn hubs_mls_call(
    request: *const u8,
    request_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let input = if request.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(request, request_len)
    };
    let answer = call_bytes(input);
    *out_len = answer.len();
    Box::into_raw(answer) as *mut u8
}

/// Wipes and frees an answer from `hubs_mls_call`.
///
/// # Safety
/// `answer` and `len` are exactly what `hubs_mls_call` returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn hubs_mls_free(answer: *mut u8, len: usize) {
    if !answer.is_null() {
        let mut owned = Box::from_raw(std::ptr::slice_from_raw_parts_mut(answer, len));
        owned.zeroize();
        drop(owned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(request: Value) -> Value {
        serde_json::from_str(&call(request.to_string().as_bytes())).unwrap()
    }

    #[test]
    fn counts_are_capped() {
        let refused = ask(json!({ "op": "random", "count": MAX_RANDOM_BYTES + 1 }));
        assert_eq!(refused["error"]["kind"], "request");
        assert_eq!(
            ask(json!({ "op": "random", "count": 0 }))["error"]["kind"],
            "request"
        );
        let made = ask(json!({ "op": "random", "count": 32 }));
        assert_eq!(
            Base64::decode_vec(made["ok"].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn wipe_clears_every_string() {
        let mut text = String::from("c2VjcmV0");
        text.zeroize();
        assert!(text.is_empty());
        let mut value = json!({ "signingKey": "c2VjcmV0", "list": ["a", { "b": "c" }], "n": 1 });
        wipe(&mut value);
        assert_eq!(value, Value::Null);
    }

    fn ok(request: Value) -> Value {
        let answer = ask(request);
        assert!(answer.get("error").is_none(), "refused: {answer}");
        answer["ok"].clone()
    }

    /// A device with one conversation of its own, as (device, group) handles.
    fn conversation() -> (Value, Value) {
        let identity = ok(json!({ "op": "createIdentity" }));
        let keys = ok(json!({
            "op": "createDevice", "identity": identity, "userId": "u_ffi", "deviceId": "d_ffi"
        }));
        let device = ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone();
        let group = ok(json!({
            "op": "startGroup", "device": device, "conversationId": "c_ffi", "now": 1_760_000_000u64
        }))["group"]
            .clone();
        (device, group)
    }

    fn draft(id: &str, kind: &str, body: &str) -> Value {
        json!({ "id": id, "kind": kind, "body": body, "sentAt": 1_760_000_000_000i64, "expiresInSeconds": 0 })
    }

    /// The core pads like the website (ts-mls padUntilLength 256, through
    /// PadUntil256 in the vendored mls-rs): content under 256 bytes is filled
    /// up to 256, and longer content gets nothing, so each character more is
    /// exactly one byte more on the wire. (The short ids here keep a short
    /// body under 256 bytes; real Hubs ids are longer.) mls-rs's own
    /// StepFunction mode would grow in 32-byte steps below 256 and in 64-byte
    /// steps at these sizes.
    #[test]
    fn messages_are_padded_like_the_web() {
        let (device, group) = conversation();
        let size = |n: usize| {
            let sent = ok(json!({
                "op": "encrypt", "group": group, "draft": draft(&format!("m{n:03}"), "text", &"a".repeat(n))
            }));
            Base64::decode_vec(sent["ciphertext"].as_str().unwrap())
                .unwrap()
                .len()
        };
        let sizes: Vec<usize> = (0..=200).map(size).collect();
        let floor = sizes[0];
        let over = sizes
            .iter()
            .position(|&s| s > floor)
            .expect("a body long enough to pass 256 bytes");
        assert!(over > 1, "short bodies share the 256-byte floor");
        assert!(sizes[..over].iter().all(|&s| s == floor));
        for n in over..sizes.len() {
            assert_eq!(sizes[n], sizes[n - 1] + 1, "a body of {n} characters");
        }
        ok(json!({ "op": "release", "device": device, "group": group }));
    }

    /// payload_problem reads the decrypted bytes, and a payload the shared
    /// rule refuses comes back as kind "payload", on receive and on send.
    #[test]
    fn the_payload_rule_reads_bytes_and_refuses_as_payload() {
        let unreadable = ok(json!({ "op": "payloadProblem", "payload": b64(b"not json") }));
        assert_eq!(unreadable["problem"], "This message could not be read.");
        let payload = json!({
            "id": "m1", "kind": "text", "body": "hi", "sentAt": 1_760_000_000_000i64,
            "expiresInSeconds": 0, "userId": "u1", "deviceId": "d1", "frankingKey": b64(&[7; 32])
        });
        let bytes = ok(json!({ "op": "payloadJson", "payload": payload }));
        assert_eq!(
            ok(json!({ "op": "payloadProblem", "payload": bytes }))["problem"],
            Value::Null
        );
        let refused = ask(json!({ "op": "parsePayload", "payload": b64(b"{}") }));
        assert_eq!(refused["error"]["kind"], "payload");

        // Nothing goes out that a receiver would refuse (check_outgoing).
        let (device, group) = conversation();
        for bad in [
            draft("m_timer", "timer", "text in a timer change"),
            draft(
                "m_long",
                "text",
                &"a".repeat(hubs_mls::MAX_BODY_UTF16 as usize + 1),
            ),
            draft("not an id", "text", "hi"),
        ] {
            let refused = ask(json!({ "op": "encrypt", "group": group, "draft": bad }));
            assert_eq!(refused["error"]["kind"], "payload", "{refused}");
        }
        ok(json!({ "op": "release", "device": device, "group": group }));
    }

    /// The shared vectors (`test-vectors/e2ee-test-vectors.json` at the root of
    /// this repository).
    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/e2ee-test-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("the vectors")).unwrap()
    }

    fn hex(text: &Value) -> Vec<u8> {
        let text = text.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_of(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unb64(value: &Value) -> Vec<u8> {
        Base64::decode_vec(value.as_str().unwrap()).unwrap()
    }

    /// Bob's device from the vectors, opened in the core.
    fn bob(v: &Value) -> Value {
        let d = &v["hubs"]["devices"]["bob"];
        ok(json!({ "op": "deviceOpen", "keys": {
            "userId": d["userId"], "deviceId": d["deviceId"],
            "identityPublicKey": b64(&hex(&d["identityPublicKeyHex"])),
            "devicePublicKey": b64(&hex(&d["devicePublicKeyHex"])),
            "deviceSigningKey": b64(&hex(&d["deviceSeedHex"])),
            "certificate": b64(&hex(&d["certificateHex"])),
        }}))["device"]
            .clone()
    }

    fn imported(v: &Value, k: &Value) -> Value {
        ok(json!({
            "op": "importKeyPackage", "id": k["id"],
            "publicPackage": b64(&hex(&k["mlsMessageHex"])),
            "initPrivateKey": b64(&hex(&k["initPrivateKeyHex"])),
            "encryptionPrivateKey": b64(&hex(&k["encryptionPrivateKeyHex"])),
            "createdAt": v["generator"]["nowSeconds"],
        }))
    }

    /// Signed removals: the exact bytes, the signatures, every verify case and
    /// every row of the rule, as the web wrote them (hubs.deviceRemoval).
    #[test]
    fn device_removals_match_the_web() {
        let v = vectors();
        let r = &v["hubs"]["deviceRemoval"];
        let alice = &v["hubs"]["devices"]["alice"];
        let identity_seed = b64(&hex(&alice["identitySeedHex"]));
        let device_seed = b64(&hex(&alice["deviceSeedHex"]));

        let removal = &r["identityRemoval"];
        let body = ok(json!({
            "op": "deviceRemovalBody", "userId": removal["userId"], "deviceId": removal["deviceId"],
            "devicePublicKey": b64(&hex(&removal["devicePublicKeyHex"])), "at": removal["at"],
        }));
        assert_eq!(hex_of(&unb64(&body)), removal["bodyHex"].as_str().unwrap());
        let signed =
            ok(json!({ "op": "ed25519Sign", "signingKey": identity_seed, "message": body }));
        assert_eq!(
            hex_of(&unb64(&signed)),
            removal["signatureHex"].as_str().unwrap()
        );

        let own = &r["selfRemoval"];
        let body = ok(json!({
            "op": "selfRemoveBody", "userId": own["userId"], "deviceId": own["deviceId"], "at": own["at"],
        }));
        assert_eq!(hex_of(&unb64(&body)), own["bodyHex"].as_str().unwrap());
        let signed = ok(json!({ "op": "ed25519Sign", "signingKey": device_seed, "message": body }));
        assert_eq!(
            hex_of(&unb64(&signed)),
            own["signatureHex"].as_str().unwrap()
        );

        let statement = &r["signedRemovalsStatement"];
        let key = b64(&hex(&statement["identityPublicKeyHex"]));
        let body = ok(
            json!({ "op": "signedRemovalsBody", "userId": statement["userId"], "identityPublicKey": key }),
        );
        assert_eq!(
            hex_of(&unb64(&body)),
            statement["bodyHex"].as_str().unwrap()
        );
        let signature = b64(&hex(&statement["signatureHex"]));
        assert_eq!(
            ok(
                json!({ "op": "verifyRemovalStatement", "userId": statement["userId"], "identityPublicKey": key, "signature": signature })
            ),
            statement["verifies"]
        );
        assert_eq!(
            ok(
                json!({ "op": "verifyRemovalStatement", "userId": "u_bob", "identityPublicKey": key, "signature": signature })
            ),
            false
        );

        for case in r["verifyCases"].as_array().unwrap() {
            let valid = case["valid"].as_bool().unwrap();
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                ok(
                    json!({ "op": "verifyRemoval", "member": case["member"], "proof": case["proof"] })
                ),
                valid,
                "{name}"
            );
            let state = ok(
                json!({ "op": "removalProofState", "member": case["member"], "proof": case["proof"] }),
            );
            let has_signature = case["proof"]["signature"]
                .as_str()
                .is_some_and(|s| !s.is_empty());
            let expected = if valid {
                "valid"
            } else if has_signature {
                "invalid"
            } else {
                "none"
            };
            assert_eq!(state, expected, "{name}");
        }
        // No entry, and an entry with a signature that is not base64.
        let member = &r["verifyCases"][0]["member"];
        assert_eq!(
            ok(json!({ "op": "removalProofState", "member": member, "proof": null })),
            "none"
        );
        assert_eq!(
            ok(
                json!({ "op": "removalProofState", "member": member, "proof": { "kind": "identity", "at": 1, "signature": "not base64!" } })
            ),
            "invalid"
        );

        for row in r["rule"].as_array().unwrap() {
            assert_eq!(
                ok(json!({
                    "op": "removalCounts", "proof": row["proof"],
                    "startedOver": row["startedOver"], "signedRemovals": row["signedRemovals"],
                })),
                row["removes"],
                "{row}"
            );
        }
        assert_eq!(
            ask(
                json!({ "op": "removalCounts", "proof": "maybe", "startedOver": false, "signedRemovals": false })
            )["error"]["kind"],
            "request"
        );
    }

    /// The passkey backup counter rule (hubs.backupCounter), with a counter
    /// that is not a whole number refused.
    #[test]
    fn backup_counters_match_the_web() {
        let v = vectors();
        for row in v["hubs"]["backupCounter"]["rule"].as_array().unwrap() {
            let problem = ok(json!({ "op": "backupRollbackProblem", "counter": row["counter"], "seen": row["seen"] }))["problem"].clone();
            assert_eq!(
                problem.is_null(),
                row["restores"].as_bool().unwrap(),
                "{row}"
            );
        }
        let older = ok(json!({ "op": "backupRollbackProblem", "counter": 2, "seen": 3 }));
        assert_eq!(
            older["problem"],
            "This backup is older than one this device has already seen, so it was not used."
        );
        for bad in [json!(2.5), json!("3"), json!(-1)] {
            let answer = ok(json!({ "op": "backupRollbackProblem", "counter": bad, "seen": 0 }));
            assert_eq!(answer["problem"], "This backup's counter is not valid.");
        }
    }

    /// The missing message rule step by step (hubs.missingMessages).
    #[test]
    fn missing_messages_match_the_web() {
        let v = vectors();
        let mm = &v["hubs"]["missingMessages"];
        assert_eq!(ok(json!({ "op": "missingMessageGraceMs" })), mm["graceMs"]);
        for case in mm["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let mut track = json!({ "userId": "u_alice", "next": 0, "gaps": [], "told": [] });
            for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
                if step.get("arrive").is_some() {
                    let arrival = ok(json!({
                        "op": "trackGeneration", "track": track, "generation": step["arrive"],
                        "now": step["at"], "shownAt": step["at"],
                    }));
                    assert_eq!(
                        !arrival["settled"].is_null(),
                        step["settles"].as_bool().unwrap(),
                        "{name} {index}"
                    );
                    track = arrival["track"].clone();
                } else {
                    let due = ok(json!({
                        "op": "dueGenerations", "track": track, "now": step["tell"], "notice": format!("n{index}"),
                    }));
                    let generations: Vec<Value> = due["due"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|g| g["generation"].clone())
                        .collect();
                    assert_eq!(Value::Array(generations), step["missing"], "{name} {index}");
                    track = due["track"].clone();
                }
            }
        }
        // A generation that does not fit in 32 bits is a request error, not a wrap.
        let refused = ask(json!({
            "op": "trackGeneration", "track": { "userId": "u", "next": 0, "gaps": [], "told": [] },
            "generation": 1u64 << 33, "now": 0, "shownAt": 0,
        }));
        assert_eq!(refused["error"]["kind"], "request");
    }

    /// One last-resort private half opens two welcomes, and each message's
    /// epoch, sender leaf and generation read before opening (mls.lastResort,
    /// mls.generations).
    #[test]
    fn last_resort_and_message_headers() {
        let v = vectors();
        let device = bob(&v);
        let lr = &v["mls"]["lastResort"];
        let package = imported(&v, &lr["keyPackage"]);
        for w in lr["welcomes"].as_array().unwrap() {
            let group = ok(json!({
                "op": "joinFromWelcome", "device": device, "welcome": b64(&hex(&w["welcomeHex"])),
                "keyPackage": package, "conversationId": w["conversationId"],
            }))["group"]
                .clone();
            let state = ok(json!({ "op": "groupState", "group": group }));
            assert_eq!(state["epoch"], w["epochAfter"]);
            let members: Vec<String> = state["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    format!(
                        "{}/{}@{}",
                        m["userId"].as_str().unwrap(),
                        m["deviceId"].as_str().unwrap(),
                        m["leafIndex"]
                    )
                })
                .collect();
            assert_eq!(json!(members), w["membersAfter"]);
            ok(json!({ "op": "release", "group": group }));
        }

        let g = &v["mls"]["generations"];
        let package = imported(&v, &g["keyPackage"]);
        let group = ok(json!({
            "op": "joinFromWelcome", "device": device, "welcome": b64(&hex(&g["welcomeHex"])),
            "keyPackage": package, "conversationId": g["conversationId"],
        }))["group"]
            .clone();
        for m in g["messages"].as_array().unwrap() {
            let header = ok(
                json!({ "op": "messageHeader", "group": group, "message": b64(&hex(&m["mlsMessageHex"])) }),
            );
            assert_eq!(header["epoch"], m["epoch"]);
            assert_eq!(header["senderLeafIndex"], m["senderLeafIndex"]);
            assert_eq!(header["generation"], m["generation"]);
        }
        // Reading opened nothing: the messages still open, out of order.
        for index in [2, 0, 1] {
            let m = &g["messages"][index];
            let got = ok(
                json!({ "op": "receive", "group": group, "message": b64(&hex(&m["mlsMessageHex"])) }),
            );
            assert_eq!(got["type"], "message");
        }
        // A commit, or bytes that are not MLS, have no header.
        let welcome = b64(&hex(&g["welcomeHex"]));
        assert_eq!(
            ok(json!({ "op": "messageHeader", "group": group, "message": welcome })),
            Value::Null
        );
        assert_eq!(
            ask(json!({ "op": "messageHeader", "group": group, "message": "%%" }))["error"]["kind"],
            "request"
        );
        ok(json!({ "op": "release", "device": device, "group": group }));
    }

    /// Strict Ed25519 that answers false, never an error, for keys and
    /// signatures of the wrong size (the calls' bindings, hubs.calls).
    #[test]
    fn verify_ed25519_is_strict_and_never_refuses() {
        let v = vectors();
        let alice = &v["calls"]["bindings"]["alice"];
        let device = b64(&hex(&alice["devicePublicKeyHex"]));
        let body = b64(&hex(&alice["bindingBodyHex"]));
        let signature = b64(&hex(&alice["signatureHex"]));
        let check = |key: &Value, message: &Value, signature: &Value| {
            ok(
                json!({ "op": "verifyEd25519", "publicKey": key, "message": message, "signature": signature }),
            )
        };
        assert_eq!(check(&device, &body, &signature), true);
        let mut forged = hex(&alice["signatureHex"]);
        forged[5] ^= 1;
        assert_eq!(check(&device, &body, &b64(&forged)), false);
        assert_eq!(check(&b64(&[1; 31]), &body, &signature), false);
        assert_eq!(check(&device, &body, &b64(&[0; 63])), false);
        assert_eq!(check(&json!("not base64"), &body, &signature), false);
        // The certificate under the identity key, too.
        let identity = b64(&hex(&alice["identityPublicKeyHex"]));
        assert_eq!(
            check(
                &identity,
                &b64(&hex(&alice["certificateBodyHex"])),
                &b64(&hex(&alice["certificateHex"]))
            ),
            true
        );
        // The older verify still refuses a key of the wrong size.
        assert_eq!(
            ask(
                json!({ "op": "ed25519Verify", "publicKey": b64(&[1; 31]), "message": body, "signature": signature })
            )["error"]["kind"],
            "malformed"
        );
    }

    #[test]
    fn an_answer_is_exactly_its_json_and_frees_wiped() {
        let request = json!({ "op": "version" }).to_string();
        let mut length = 0usize;
        // SAFETY: a valid request and length, and the answer is freed once below.
        unsafe {
            let answer = hubs_mls_call(request.as_ptr(), request.len(), &mut length);
            let text = std::str::from_utf8(std::slice::from_raw_parts(answer, length)).unwrap();
            let parsed: Value = serde_json::from_str(text).unwrap();
            assert!(parsed["ok"]["version"].is_string());
            hubs_mls_free(answer, length);
        }
    }
}
