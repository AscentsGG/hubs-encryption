//! Which layer's Ed25519 check is strict (RF-5 in docs/reviews.md).
use ed25519_dalek::{Signer, SigningKey};
use hubs_mls::*;
use mls_rs::{crypto::SignaturePublicKey, CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// The identity point (order 1). For this key [k]A is the identity, so
/// (R = [s]B, S = s) passes the plain equation for every message.
const IDENTITY_POINT: [u8; 32] = {
    let mut key = [0u8; 32];
    key[0] = 1;
    key
};

fn forged() -> [u8; 64] {
    // A key pair's public key is [s]B for its scalar s.
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(key.verifying_key().as_bytes());
    signature[32..].copy_from_slice(&key.to_scalar().to_bytes());
    signature
}

#[test]
fn the_hubs_layer_is_strict() {
    assert!(!verify_ed25519(
        IDENTITY_POINT.to_vec(),
        b"any message".to_vec(),
        forged().to_vec()
    ));
}

/// Records the state of the provider, which is not ours to change: it calls
/// dalek's plain verify for every MLS signature. This passes before and
/// after the fix; it is here to show why the certificate check matters.
#[test]
fn the_mls_provider_is_not_strict() {
    let cs = RustCryptoProvider::with_enabled_cipher_suites(vec![CipherSuite::CURVE25519_AES128])
        .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
        .unwrap();
    assert!(cs
        .verify(
            &SignaturePublicKey::from(IDENTITY_POINT.to_vec()),
            &forged(),
            b"any message"
        )
        .is_ok());
}

/// So a device key of small order must not get a leaf at all. Every leaf
/// passes verify_device_certificate (policy.rs identity_info), which
/// refuses a key of small order.
#[test]
fn a_small_order_device_key_is_refused() {
    let identity = create_identity().unwrap();
    let certificate = sign_ed25519(
        identity.signing_key.clone(),
        device_certificate_body("u_a".into(), "d_a".into(), IDENTITY_POINT.to_vec()),
    )
    .unwrap();
    let credential = DeviceCredential {
        user_id: "u_a".into(),
        device_id: "d_a".into(),
        identity_public_key: identity.public_key,
        certificate,
    };
    assert!(!verify_device_certificate(
        credential,
        IDENTITY_POINT.to_vec()
    ));
}

#[test]
fn honest_keys_still_pass() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let signature = key.sign(b"m").to_bytes();
    assert!(verify_ed25519(
        key.verifying_key().as_bytes().to_vec(),
        b"m".to_vec(),
        signature.to_vec()
    ));
}
