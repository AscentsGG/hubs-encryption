//! The Hubs layer on top of MLS, byte for byte the same as the TypeScript
//! implementation: the device certificate, the credential inside every MLS
//! leaf, the message payload and its franking commitment. The test vectors
//! pin every format.

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use mls_rs::CipherSuiteProvider;
use serde_json::Value;

use crate::error::{malformed, HubsMlsError, Result};
use crate::suite;

/// What the account identity key signs to vouch for one device key.
pub fn device_certificate_body(
    user_id: &str,
    device_id: &str,
    device_public_key: &[u8],
) -> Vec<u8> {
    let mut body = format!("hubs private dms device v1\0{user_id}\0{device_id}\0").into_bytes();
    body.extend_from_slice(device_public_key);
    body
}

/// The identity a device's MLS credential carries.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceCredential {
    pub user_id: String,
    pub device_id: String,
    /// Raw Ed25519 public key, 32 bytes.
    pub identity_public_key: Vec<u8>,
    /// Ed25519 signature over the certificate body, 64 bytes.
    pub certificate: Vec<u8>,
}

/// A JSON string exactly as `JSON.stringify` writes it.
pub(crate) fn json_string(text: &str) -> String {
    // serde_json escapes `"`, `\` and control characters the way
    // JSON.stringify does (short forms for \b \f \n \r \t, lowercase \u00xx
    // otherwise) and leaves `/` and non-ASCII alone.
    serde_json::to_string(text).expect("a string always serializes")
}

/// The credential identity bytes, with the keys in this order:
/// `{"v":1,"userId","deviceId","identityPublicKey","certificate"}`.
pub fn credential_identity(credential: &DeviceCredential) -> Vec<u8> {
    format!(
        "{{\"v\":1,\"userId\":{},\"deviceId\":{},\"identityPublicKey\":{},\"certificate\":{}}}",
        json_string(&credential.user_id),
        json_string(&credential.device_id),
        json_string(&Base64::encode_string(&credential.identity_public_key)),
        json_string(&Base64::encode_string(&credential.certificate)),
    )
    .into_bytes()
}

/// Read a credential identity. `None` when it is not a Hubs credential, as
/// `readCredential` in the TypeScript implementation does.
pub fn read_credential_identity(identity: &[u8]) -> Option<DeviceCredential> {
    let value: Value = serde_json::from_slice(identity).ok()?;
    let object = value.as_object()?;
    // `value?.v === 1`: any JSON number equal to 1.
    if object.get("v")?.as_f64()? != 1.0 {
        return None;
    }
    let text = |key: &str| object.get(key)?.as_str().map(str::to_owned);
    Some(DeviceCredential {
        user_id: text("userId")?,
        device_id: text("deviceId")?,
        identity_public_key: Base64::decode_vec(&text("identityPublicKey")?).ok()?,
        certificate: Base64::decode_vec(&text("certificate")?).ok()?,
    })
}

/// Strict Ed25519 (RFC 8032): a 32-byte public key that is not of small
/// order, a 64-byte signature with a canonical S, and the signature over
/// exactly `message`. Anything else, including bytes of the wrong size, is
/// `false`. Every Hubs signature (device certificates, removals, call
/// bindings) is checked this way.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

/// Check that a device key was signed by the identity key its credential
/// names. Strict Ed25519 (no small-order keys, canonical signatures only).
pub fn verify_device_certificate(credential: &DeviceCredential, device_public_key: &[u8]) -> bool {
    // MLS checks every signature by this key with the provider's plain
    // verify, which a small-order key passes for any message.
    let usable = <[u8; 32]>::try_from(device_public_key)
        .ok()
        .and_then(|key| VerifyingKey::from_bytes(&key).ok())
        .is_some_and(|key| !key.is_weak());
    usable
        && verify_ed25519(
            &credential.identity_public_key,
            &device_certificate_body(
                &credential.user_id,
                &credential.device_id,
                device_public_key,
            ),
            &credential.certificate,
        )
}

/// The fixed DER prefix of an Ed25519 PKCS#8 private key (RFC 8410), the
/// form WebCrypto exports and the website stores.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// An Ed25519 signing key in any form the website or this core writes: the
/// 32-byte seed, the 48-byte PKCS#8, or the 64-byte seed and public key the
/// RustCrypto provider uses.
pub(crate) fn signing_key(bytes: &[u8]) -> Result<SigningKey> {
    match bytes.len() {
        32 => Ok(SigningKey::from_bytes(bytes.try_into().expect("32 bytes"))),
        48 if bytes[..16] == PKCS8_ED25519_PREFIX => Ok(SigningKey::from_bytes(
            bytes[16..].try_into().expect("32 bytes"),
        )),
        64 => SigningKey::from_keypair_bytes(bytes.try_into().expect("64 bytes"))
            .map_err(|_| malformed("the signing key's public half does not match")),
        _ => Err(malformed("not an Ed25519 signing key")),
    }
}

/// PKCS#8, so the website can read a key this core made as it is.
pub(crate) fn pkcs8(key: &SigningKey) -> Vec<u8> {
    let mut out = PKCS8_ED25519_PREFIX.to_vec();
    out.extend_from_slice(key.as_bytes());
    out
}

/// What travels inside the encryption (`PrivateDmPayload`). `v` is always 1.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessagePayload {
    pub id: String,
    /// "text" or "timer".
    pub kind: String,
    pub body: String,
    /// Milliseconds since 1970, as `Date.now()`.
    pub sent_at: i64,
    pub expires_in_seconds: i64,
    pub user_id: String,
    pub device_id: String,
    /// 32 random bytes; base64 inside the JSON.
    pub franking_key: Vec<u8>,
}

/// What the app hands the core to send. The sender's user and device come
/// from the device itself; the franking key is made fresh.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageDraft {
    pub id: String,
    pub kind: String,
    pub body: String,
    pub sent_at: i64,
    pub expires_in_seconds: i64,
}

/// JavaScript's safe integers: what `JSON.stringify` writes as plain digits.
pub(crate) const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
/// Longest message text, in UTF-16 code units, a device sends or accepts
/// (`PRIVATE_DM_MAX_BODY`).
pub const MAX_BODY_UTF16: u32 = 4000;
/// The disappearing timers, in seconds, 0 for off (`PRIVATE_DM_TIMERS`).
pub const TIMERS: [i64; 7] = [300, 3600, 28800, 86400, 604800, 2419200, 0];
/// Exactly the fields a payload carries.
const PAYLOAD_KEYS: [&str; 9] = [
    "v",
    "id",
    "kind",
    "body",
    "sentAt",
    "expiresInSeconds",
    "userId",
    "deviceId",
    "frankingKey",
];
/// What a payload that is not JSON (or not strict UTF-8) is refused with.
pub(crate) const UNREADABLE: &str = "This message could not be read.";

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `^[A-Za-z0-9_-]{1,64}$`: a message id can never collide with the
/// device's own notice ids (they carry a colon).
fn valid_message_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A JSON number that `Number.isSafeInteger` accepts, as an integer.
fn safe_integer(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    if let Some(integer) = number.as_i64() {
        return (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER)
            .contains(&integer)
            .then_some(integer);
    }
    if number.as_u64().is_some() {
        return None;
    }
    // A number written with a fraction or exponent ("1.0", "3e2") that is
    // still a whole number counts, as it does in JavaScript.
    let float = number.as_f64()?;
    (float.is_finite() && float.fract() == 0.0 && float.abs() <= MAX_SAFE_INTEGER as f64)
        .then_some(float as i64)
}

/// The exact bytes the franking commitment covers (`canonicalPayloadBytes`):
/// `JSON.stringify(["hubs private dms message v1", v, id, kind, body,
/// sentAt, expiresInSeconds, userId, deviceId])`.
pub fn canonical_payload_bytes(payload: &MessagePayload) -> Vec<u8> {
    format!(
        "[\"hubs private dms message v1\",1,{},{},{},{},{},{},{}]",
        json_string(&payload.id),
        json_string(&payload.kind),
        json_string(&payload.body),
        payload.sent_at,
        payload.expires_in_seconds,
        json_string(&payload.user_id),
        json_string(&payload.device_id),
    )
    .into_bytes()
}

/// The payload as the website sends it: `JSON.stringify` of the payload
/// object, with the keys in this order.
pub fn payload_json(payload: &MessagePayload) -> Vec<u8> {
    format!(
        "{{\"v\":1,\"id\":{},\"kind\":{},\"body\":{},\"sentAt\":{},\"expiresInSeconds\":{},\"userId\":{},\"deviceId\":{},\"frankingKey\":{}}}",
        json_string(&payload.id),
        json_string(&payload.kind),
        json_string(&payload.body),
        payload.sent_at,
        payload.expires_in_seconds,
        json_string(&payload.user_id),
        json_string(&payload.device_id),
        json_string(&Base64::encode_string(&payload.franking_key)),
    )
    .into_bytes()
}

/// The shared payload rule (`privateDmPayloadProblem` in the TypeScript
/// implementation) on a parsed JSON value: exactly the nine fields, version
/// 1, an id of letters, digits, "-" and "_", text or timer only, a timer
/// from the list, safe integers, text up to 4000 UTF-16 units (empty for a
/// timer), a user id up to 128 and a device id up to 64, and a 32-byte
/// franking key in standard base64. Every receiving device runs it before
/// anything is shown, and the server runs it before it verifies a report.
/// Returns the payload, or the problem in the same words as the TypeScript
/// implementation.
pub(crate) fn payload_rule(value: &Value) -> std::result::Result<MessagePayload, &'static str> {
    let Some(object) = value.as_object() else {
        return Err("The payload is not an object.");
    };
    if object.len() != PAYLOAD_KEYS.len()
        || !PAYLOAD_KEYS.iter().all(|key| object.contains_key(*key))
    {
        return Err("The payload has unknown or missing fields.");
    }
    if object["v"].as_f64() != Some(1.0) {
        return Err("Unknown payload version.");
    }
    let id = match object["id"].as_str() {
        Some(id) if valid_message_id(id) => id,
        _ => return Err("The message id is not valid."),
    };
    let kind = match object["kind"].as_str() {
        Some(kind @ ("text" | "timer")) => kind,
        _ => return Err("Messages are text or timer changes."),
    };
    // Rust strings are always well-formed: a lone surrogate never parses.
    let body = match object["body"].as_str() {
        Some(body) if utf16_len(body) <= MAX_BODY_UTF16 as usize => body,
        _ => return Err("The message text is not valid."),
    };
    if kind == "timer" && !body.is_empty() {
        return Err("A timer change carries no text.");
    }
    let sent_at = match safe_integer(&object["sentAt"]) {
        Some(sent_at) if sent_at >= 0 => sent_at,
        _ => return Err("The message time is not valid."),
    };
    let expires_in_seconds = match safe_integer(&object["expiresInSeconds"]) {
        Some(seconds) if TIMERS.contains(&seconds) => seconds,
        _ => return Err("The disappearing timer is not one of the choices."),
    };
    let user_id = match object["userId"].as_str() {
        Some(user) if !user.is_empty() && utf16_len(user) <= 128 => user,
        _ => return Err("The payload's userId is not valid."),
    };
    let device_id = match object["deviceId"].as_str() {
        Some(device) if !device.is_empty() && utf16_len(device) <= 64 => device,
        _ => return Err("The payload's deviceId is not valid."),
    };
    // `^[A-Za-z0-9+/]{43}=$`, then a strict decode: 32 bytes exactly.
    let franking_key = object["frankingKey"]
        .as_str()
        .filter(|key| {
            key.len() == 44
                && key.ends_with('=')
                && key[..43]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        })
        .and_then(|key| Base64::decode_vec(key).ok())
        .filter(|key| key.len() == 32)
        .ok_or("The franking key must be 32 bytes.")?;
    Ok(MessagePayload {
        id: id.to_owned(),
        kind: kind.to_owned(),
        body: body.to_owned(),
        sent_at,
        expires_in_seconds,
        user_id: user_id.to_owned(),
        device_id: device_id.to_owned(),
        franking_key,
    })
}

/// Why a decrypted payload (its bytes) may not be shown, or `None`: strict
/// UTF-8 JSON, then the shared rule.
pub fn payload_problem(bytes: &[u8]) -> Option<String> {
    match serde_json::from_slice::<Value>(bytes) {
        Err(_) => Some(UNREADABLE.to_owned()),
        Ok(value) => payload_rule(&value).err().map(str::to_owned),
    }
}

/// Read a payload another device sent: strict UTF-8 JSON that passes the
/// shared rule (`payload_rule`). The canonical bytes recomputed from it are
/// the ones the sender committed to.
pub fn parse_payload(bytes: &[u8]) -> Result<MessagePayload> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| HubsMlsError::Payload {
        reason: UNREADABLE.to_owned(),
    })?;
    payload_rule(&value).map_err(|reason| HubsMlsError::Payload {
        reason: reason.to_owned(),
    })
}

/// What this device sends passes the same rule every receiver applies.
pub(crate) fn check_outgoing(payload: &MessagePayload) -> Result<()> {
    parse_payload(&payload_json(payload)).map(|_| ())
}

/// HMAC-SHA256(frankingKey, canonical bytes), the ciphersuite's own MAC.
pub fn franking_commitment(franking_key: &[u8], payload: &MessagePayload) -> Result<Vec<u8>> {
    suite()
        .mac(franking_key, &canonical_payload_bytes(payload))
        .map_err(|error| HubsMlsError::Mls {
            reason: format!("mac: {error:?}"),
        })
}

/// Random bytes from the ciphersuite's generator.
pub(crate) fn random_bytes(count: usize) -> Result<Vec<u8>> {
    suite()
        .random_bytes_vec(count)
        .map_err(|error| HubsMlsError::Mls {
            reason: format!("random: {error:?}"),
        })
}

/// An id in the same form the website uses: random bytes, base64url, no
/// padding.
pub(crate) fn random_id(bytes: usize) -> Result<String> {
    Ok(Base64UrlUnpadded::encode_string(&random_bytes(bytes)?))
}

/// One member as the membership rule sees it: the account and the identity
/// key its device certificate names.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MemberIdentity {
    pub user_id: String,
    /// Raw Ed25519 public key, 32 bytes.
    pub identity_public_key: Vec<u8>,
}

/// The membership rule every device applies to a group before it accepts
/// it (a welcome, someone else's commit, or its own commit),
/// `membershipProblem` in the TypeScript implementation. A private
/// conversation is one-to-one:
///
/// - every device of this account carries this device's identity key;
/// - at most one other account, and the pinned person once one is pinned;
/// - the other person's devices all carry one identity key, so a matching
///   safety code means there is no hidden device.
///
/// Returns the problem in the same words as the TypeScript implementation,
/// or `None`.
pub fn membership_problem(
    members: &[MemberIdentity],
    self_user_id: &str,
    self_identity_public_key: &[u8],
    peer: Option<&str>,
) -> Option<&'static str> {
    let mut others: Vec<&str> = Vec::new();
    let mut other_keys: Vec<&[u8]> = Vec::new();
    for member in members {
        if member.user_id == self_user_id {
            if member.identity_public_key != self_identity_public_key {
                return Some("A device of this account carries a different identity key.");
            }
        } else {
            if !others.contains(&member.user_id.as_str()) {
                others.push(&member.user_id);
            }
            if !other_keys.contains(&member.identity_public_key.as_slice()) {
                other_keys.push(&member.identity_public_key);
            }
        }
    }
    if others.len() > 1 {
        return Some("A third account would join.");
    }
    if let (Some(other), Some(peer)) = (others.first(), peer) {
        if *other != peer {
            return Some("Someone other than the pinned person would join.");
        }
    }
    if other_keys.len() > 1 {
        return Some("The other person's devices carry two identity keys.");
    }
    None
}

/// The passkey backup rule (`backupRollbackProblem`): why a backup whose
/// sealed bundle carries `counter` may not be restored on a device that has
/// seen backup counters up to `seen`, or `None`.
///
/// Each backup is saved with a counter one above any this device or the
/// server knew of, sealed with the rest, so the server cannot change it. A
/// server that serves an older backup (an older identity, or fewer pinned
/// contacts) is refused by every device that saw a newer one. A backup
/// made before counters has none and counts as 0. A counter must be a safe
/// integer of 0 or more.
pub fn backup_rollback_problem(counter: Option<i64>, seen: u64) -> Option<&'static str> {
    let value = counter.unwrap_or(0);
    if !(0..=MAX_SAFE_INTEGER).contains(&value) {
        return Some("This backup's counter is not valid.");
    }
    ((value as u64) < seen).then_some(
        "This backup is older than one this device has already seen, so it was not used.",
    )
}
