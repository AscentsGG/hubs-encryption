//! The key package lifetime policy, the same on the website, the server and
//! the native apps: a key package is valid for 90 days, and each device
//! replaces its own every 30 days. The TypeScript implementation has the
//! same constants (`PRIVATE_DM_KEY_PACKAGE_*`).
//!
//! - Made: `notBefore = now - 1 hour` (clock skew), `notAfter = now + 90 days`.
//! - Accepted by an adder: valid now (with the hour of skew for `notBefore`)
//!   and a total range of at most 90 days and 1 hour, so a key package that
//!   never expires (`0` to `2^63 - 1`, the ts-mls default lifetime) is
//!   refused.
//! - Published (server): the same, and at least 60 days left, so what sits
//!   on the server was made recently.
//! - Refreshed (device): any key package of its own older than 30 days is
//!   replaced; the private half is kept until `notAfter` plus the server's
//!   30-day queue, in case a welcome for it is still on its way.
//! - Last resort (device): besides the one-time key packages, each device
//!   keeps one last-resort key package on the server (RFC 9420, section
//!   16.8), handed out only when the one-time ones run out. It is an
//!   ordinary key package made by `MlsDevice::create_key_packages`, with no
//!   extension and the same lifetime, replaced on the same 30-day rule.
//!   More than one welcome may use it, so its private half stays after a
//!   join (`join_from_welcome` never consumes the app's copy) and goes only
//!   at `notAfter` plus the queue time, like any other half.

use mls_rs::{
    group::{LeafNode, LeafNodeSource},
    identity::SigningIdentity,
    mls_rs_codec::MlsDecode,
    CipherSuite, MlsMessage, ProtocolVersion,
};
use mls_rs_core::crypto::HpkePublicKey;

use crate::error::{malformed, HubsMlsError, Result};
use crate::hubs::{read_credential_identity, verify_device_certificate, DeviceCredential};
use crate::CIPHER_SUITE;

pub const KEY_PACKAGE_LIFETIME_SECONDS: u64 = 90 * 86_400;
pub const KEY_PACKAGE_REFRESH_SECONDS: u64 = 30 * 86_400;
pub const KEY_PACKAGE_CLOCK_SKEW_SECONDS: u64 = 3_600;
/// Fresh key packages each device keeps on the server.
pub const KEY_PACKAGE_TARGET: u32 = 20;
/// How long the server keeps an envelope (a welcome) for an offline device.
pub const MAX_QUEUE_SECONDS: u64 = 30 * 86_400;

/// The policy, for the app.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyPackagePolicy {
    pub lifetime_seconds: u64,
    pub refresh_seconds: u64,
    pub clock_skew_seconds: u64,
    pub target_count: u32,
    /// Keep a key package's private half until `not_after` plus this.
    pub keep_private_after_expiry_seconds: u64,
}

#[uniffi::export]
pub fn key_package_policy() -> KeyPackagePolicy {
    KeyPackagePolicy {
        lifetime_seconds: KEY_PACKAGE_LIFETIME_SECONDS,
        refresh_seconds: KEY_PACKAGE_REFRESH_SECONDS,
        clock_skew_seconds: KEY_PACKAGE_CLOCK_SKEW_SECONDS,
        target_count: KEY_PACKAGE_TARGET,
        keep_private_after_expiry_seconds: MAX_QUEUE_SECONDS,
    }
}

/// The `notBefore` a key package made now carries (the library adds the
/// lifetime plus the skew to it, which lands `notAfter` at now + 90 days).
pub(crate) fn not_before_for(now_seconds: u64) -> u64 {
    now_seconds.saturating_sub(KEY_PACKAGE_CLOCK_SKEW_SECONDS)
}

/// Why a lifetime is outside the policy at `now`, or `None`.
pub fn lifetime_problem(not_before: u64, not_after: u64, now_seconds: u64) -> Option<&'static str> {
    if not_after <= not_before {
        return Some("the lifetime is empty");
    }
    if not_after - not_before > KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS {
        return Some("the lifetime is longer than 90 days");
    }
    if not_before > now_seconds.saturating_add(KEY_PACKAGE_CLOCK_SKEW_SECONDS) {
        return Some("the key package is not valid yet");
    }
    if not_after <= now_seconds {
        return Some("the key package has expired");
    }
    None
}

/// True when a device should replace a key package it made at `created_at`.
#[uniffi::export]
pub fn key_package_needs_refresh(created_at_seconds: u64, now_seconds: u64) -> bool {
    now_seconds.saturating_sub(created_at_seconds) >= KEY_PACKAGE_REFRESH_SECONDS
}

/// What a key package says about itself, after the Hubs checks.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyPackageInfo {
    pub user_id: String,
    pub device_id: String,
    pub identity_public_key: Vec<u8>,
    pub device_public_key: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
}

/// Read a key package (a complete MLSMessage) without the lifetime check:
/// protocol version, ciphersuite 1, a Hubs credential whose device
/// certificate verifies, and its lifetime.
#[uniffi::export]
pub fn read_key_package(message: Vec<u8>) -> Result<KeyPackageInfo> {
    let key_package = MlsMessage::from_bytes(&message)?
        .into_key_package()
        .ok_or_else(|| malformed("not a key package"))?;
    if key_package.version() != ProtocolVersion::MLS_10 {
        return Err(malformed("not MLS 1.0"));
    }
    if key_package.cipher_suite() != CIPHER_SUITE {
        return Err(malformed("not ciphersuite 1"));
    }
    // The lifetime sits in the leaf node, which mls-rs keeps private on a
    // KeyPackage: read the encoding up to it with the library's own types.
    let encoded = mls_rs::mls_rs_codec::MlsEncode::mls_encode_to_vec(&key_package)?;
    let reader = &mut encoded.as_slice();
    ProtocolVersion::mls_decode(reader)?;
    CipherSuite::mls_decode(reader)?;
    HpkePublicKey::mls_decode(reader)?;
    let leaf = LeafNode::mls_decode(reader)?;
    let LeafNodeSource::KeyPackage(lifetime) = &leaf.leaf_node_source else {
        return Err(malformed("the leaf is not from a key package"));
    };
    let info = identity_info(&leaf.signing_identity)?;
    Ok(KeyPackageInfo {
        not_before: lifetime.not_before.seconds_since_epoch(),
        not_after: lifetime.not_after.seconds_since_epoch(),
        ..info
    })
}

/// `read_key_package` plus the lifetime policy at `now`: what an adder
/// checks before it adds a device.
#[uniffi::export]
pub fn check_key_package(message: Vec<u8>, now_seconds: u64) -> Result<KeyPackageInfo> {
    let info = read_key_package(message)?;
    if let Some(problem) = lifetime_problem(info.not_before, info.not_after, now_seconds) {
        return Err(HubsMlsError::KeyPackageLifetime {
            reason: problem.to_owned(),
        });
    }
    Ok(info)
}

/// Who a published key package says it belongs to, or `None` when it
/// cannot be read (`keyPackageCredential`). This only reads it:
/// `check_key_package` is what verifies a package.
#[uniffi::export]
pub fn key_package_credential(public_package: Vec<u8>) -> Option<DeviceCredential> {
    let key_package = MlsMessage::from_bytes(&public_package)
        .ok()?
        .into_key_package()?;
    let basic = key_package.signing_identity().credential.as_basic()?;
    read_credential_identity(&basic.identifier)
}

pub(crate) fn identity_info(identity: &SigningIdentity) -> Result<KeyPackageInfo> {
    let basic = identity
        .credential
        .as_basic()
        .ok_or_else(|| HubsMlsError::Credential {
            reason: "not a basic credential".into(),
        })?;
    let credential =
        read_credential_identity(&basic.identifier).ok_or_else(|| HubsMlsError::Credential {
            reason: "not a Hubs device credential".into(),
        })?;
    if !verify_device_certificate(&credential, &identity.signature_key) {
        return Err(HubsMlsError::Credential {
            reason: "the device certificate does not verify".into(),
        });
    }
    Ok(KeyPackageInfo {
        user_id: credential.user_id,
        device_id: credential.device_id,
        identity_public_key: credential.identity_public_key,
        device_public_key: identity.signature_key.to_vec(),
        not_before: 0,
        not_after: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    #[test]
    fn made_now_is_inside_the_policy() {
        let not_before = not_before_for(NOW);
        let not_after = not_before + KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS;
        assert_eq!(not_after, NOW + KEY_PACKAGE_LIFETIME_SECONDS);
        assert_eq!(lifetime_problem(not_before, not_after, NOW), None);
        // Still fine on the last day, gone after it.
        assert_eq!(lifetime_problem(not_before, not_after, not_after - 1), None);
        assert!(lifetime_problem(not_before, not_after, not_after).is_some());
    }

    #[test]
    fn never_expiring_and_long_lifetimes_are_refused() {
        assert_eq!(
            lifetime_problem(0, i64::MAX as u64, NOW),
            Some("the lifetime is longer than 90 days")
        );
        let not_before = not_before_for(NOW);
        let too_long =
            not_before + KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS + 1;
        assert!(lifetime_problem(not_before, too_long, NOW).is_some());
    }

    #[test]
    fn future_and_empty_lifetimes_are_refused() {
        assert!(lifetime_problem(NOW + 2 * 3_600, NOW + 80 * 86_400, NOW).is_some());
        // An hour of skew is allowed.
        assert_eq!(lifetime_problem(NOW + 3_600, NOW + 80 * 86_400, NOW), None);
        assert!(lifetime_problem(NOW, NOW, NOW).is_some());
    }

    #[test]
    fn refresh_after_thirty_days() {
        assert!(!key_package_needs_refresh(NOW, NOW + 29 * 86_400));
        assert!(key_package_needs_refresh(NOW, NOW + 30 * 86_400));
        assert!(!key_package_needs_refresh(NOW + 10, NOW));
    }
}
