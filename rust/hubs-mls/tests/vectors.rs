//! MLS interop vectors made by the TypeScript implementation on ts-mls with
//! fixed keys and seeded randomness (`tests/mls-vectors.mts` writes
//! `test-vectors/mls-interop-vectors.json` at the root of this repository),
//! read by the native core.

use hubs_mls::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/mls-interop-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the vectors file")).expect("JSON")
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut at = v;
    for key in path {
        at = &at[*key];
    }
    at.as_str()
        .unwrap_or_else(|| panic!("{path:?} is a string"))
}

fn h(v: &Value, path: &[&str]) -> Vec<u8> {
    hex::decode(s(v, path)).expect("hex")
}

/// A vector time inside the key packages' lifetimes.
fn now(v: &Value) -> u64 {
    v["generator"]["nowSeconds"]
        .as_u64()
        .unwrap_or(1_760_000_000)
        + 600
}

fn device(v: &Value, who: &str) -> DeviceKeys {
    DeviceKeys {
        user_id: s(v, &[who, "userId"]).into(),
        device_id: s(v, &[who, "deviceId"]).into(),
        identity_public_key: h(v, &[who, "identityPublicKeyHex"]),
        device_public_key: h(v, &[who, "devicePublicKeyHex"]),
        device_signing_key: h(v, &[who, "deviceSeedHex"]),
        certificate: h(v, &[who, "certificateHex"]),
    }
}

fn imported(v: &Value, name: &str) -> DeviceKeyPackage {
    import_key_package(
        s(v, &[name, "id"]).into(),
        h(v, &[name, "mlsMessageHex"]),
        h(v, &[name, "initPrivateKeyHex"]),
        h(v, &[name, "encryptionPrivateKeyHex"]),
        now(v),
    )
    .expect("import")
}

fn payload_of(v: &Value, message: &str) -> MessagePayload {
    let p = &v[message]["payload"];
    MessagePayload {
        id: p["id"].as_str().unwrap().into(),
        kind: p["kind"].as_str().unwrap().into(),
        body: p["body"].as_str().unwrap().into(),
        sent_at: p["sentAt"].as_i64().unwrap(),
        expires_in_seconds: p["expiresInSeconds"].as_i64().unwrap(),
        user_id: p["userId"].as_str().unwrap().into(),
        device_id: p["deviceId"].as_str().unwrap().into(),
        franking_key: base64_decode(p["frankingKey"].as_str().unwrap()),
    }
}

fn base64_decode(text: &str) -> Vec<u8> {
    // Decodes through the core's own strict payload reader.
    let json = format!(
        "{{\"v\":1,\"id\":\"x\",\"kind\":\"text\",\"body\":\"\",\"sentAt\":0,\"expiresInSeconds\":0,\"userId\":\"u\",\"deviceId\":\"d\",\"frankingKey\":\"{text}\"}}"
    );
    parse_payload(json.into_bytes()).unwrap().franking_key
}

/// Bob joins from the ts-mls welcome, with the keys of his device in the
/// vectors.
fn bob_joins(v: &Value) -> (std::sync::Arc<MlsDevice>, std::sync::Arc<MlsGroup>) {
    let bob = MlsDevice::new(device(v, "bob")).expect("bob's keys");
    let group = bob
        .join_from_welcome(
            h(v, &["addBob", "welcomeHex"]),
            imported(v, "bobKeyPackage"),
            s(v, &["conversationId"]).into(),
        )
        .expect("join from the ts-mls welcome");
    (bob, group)
}

#[test]
fn the_hubs_layer_matches_the_web_byte_for_byte() {
    let v = vectors();
    assert_eq!(v["generator"]["ciphersuiteId"], 1);
    for who in ["alice", "bob"] {
        let keys = device(&v, who);
        let credential = DeviceCredential {
            user_id: keys.user_id.clone(),
            device_id: keys.device_id.clone(),
            identity_public_key: keys.identity_public_key.clone(),
            certificate: keys.certificate.clone(),
        };
        assert!(verify_device_certificate(
            credential.clone(),
            keys.device_public_key.clone()
        ));
        // The credential the TypeScript implementation puts in every leaf.
        assert_eq!(
            String::from_utf8(credential_identity(credential.clone())).unwrap(),
            s(&v, &[who, "credentialIdentityUtf8"])
        );
        assert_eq!(
            read_credential_identity(credential_identity(credential.clone())),
            Some(credential.clone())
        );
        // Another device key does not verify.
        let mut other = keys.device_public_key.clone();
        other[31] ^= 1;
        assert!(!verify_device_certificate(credential, other));
    }
    for message in ["message1", "message2"] {
        let payload = payload_of(&v, message);
        assert_eq!(
            String::from_utf8(canonical_payload_bytes(payload.clone())).unwrap(),
            s(&v, &[message, "canonicalBytesUtf8"])
        );
        assert_eq!(
            franking_commitment(payload.clone()).unwrap(),
            h(&v, &[message, "authenticatedDataHex"])
        );
        // The plaintext the TypeScript implementation encrypts, byte for byte.
        assert_eq!(
            String::from_utf8(payload_json(payload.clone())).unwrap(),
            s(&v, &[message, "plaintextUtf8"])
        );
        assert_eq!(
            parse_payload(s(&v, &[message, "plaintextUtf8"]).as_bytes().to_vec()).unwrap(),
            payload
        );
    }
}

#[test]
fn the_web_key_packages_read_with_the_hubs_checks() {
    let v = vectors();
    for name in ["aliceKeyPackage", "bobKeyPackage", "bobSpareKeyPackage"] {
        let info = read_key_package(h(&v, &[name, "mlsMessageHex"])).expect(name);
        let who = if name.starts_with("alice") {
            "alice"
        } else {
            "bob"
        };
        assert_eq!(info.user_id, s(&v, &[who, "userId"]));
        assert_eq!(info.device_id, s(&v, &[who, "deviceId"]));
        assert_eq!(info.device_public_key, h(&v, &[who, "devicePublicKeyHex"]));
    }
}

#[test]
fn joins_from_the_web_welcome_and_opens_everything() {
    let v = vectors();
    let (_bob, group) = bob_joins(&v);
    assert_eq!(group.conversation_id(), s(&v, &["conversationId"]));
    assert_eq!(group.epoch(), v["addBob"]["epochAfter"].as_u64().unwrap());
    let members = group.members();
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.user_id == "u_alice" && m.device_id == s(&v, &["alice", "deviceId"])));
    assert!(members.iter().any(|m| m.user_id == "u_bob"));

    match group
        .receive(h(&v, &["message1", "mlsMessageHex"]))
        .expect("message1")
    {
        Incoming::Message {
            payload,
            commitment,
            sender,
            epoch,
        } => {
            assert_eq!(payload, payload_of(&v, "message1"));
            assert_eq!(commitment, h(&v, &["message1", "authenticatedDataHex"]));
            assert_eq!(sender.user_id, "u_alice");
            assert_eq!(epoch, 1);
        }
        other => panic!("expected a message, got {other:?}"),
    }
    match group
        .receive(h(&v, &["updateCommit", "commitHex"]))
        .expect("update commit")
    {
        Incoming::Change { members, epoch, .. } => {
            assert_eq!(epoch, v["updateCommit"]["epochAfter"].as_u64().unwrap());
            assert_eq!(members.len(), 2);
        }
        other => panic!("expected a change, got {other:?}"),
    }
    match group
        .receive(h(&v, &["message2", "mlsMessageHex"]))
        .expect("message2")
    {
        Incoming::Message { payload, .. } => {
            assert_eq!(
                payload.body,
                "Bring the blue folder. 🗂️ \"quoted\" and a\nnew line."
            );
            assert_eq!(payload, payload_of(&v, "message2"));
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[test]
fn a_saved_conversation_reloads_and_keeps_reading() {
    let v = vectors();
    let (bob, group) = bob_joins(&v);
    group
        .receive(h(&v, &["message1", "mlsMessageHex"]))
        .unwrap();
    let saved = group.snapshot().expect("snapshot");
    drop(group);
    // A fresh device object from the same keys, as after an app restart.
    let bob_again = MlsDevice::new(device(&v, "bob")).unwrap();
    let group = bob_again.load_group(saved.clone()).expect("load");
    assert_eq!(group.epoch(), 1);
    group
        .receive(h(&v, &["updateCommit", "commitHex"]))
        .unwrap();
    assert!(matches!(
        group
            .receive(h(&v, &["message2", "mlsMessageHex"]))
            .unwrap(),
        Incoming::Message { .. }
    ));
    // Another device cannot load Bob's state.
    let alice = MlsDevice::new(device(&v, "alice")).unwrap();
    assert_eq!(
        alice.load_group(saved).unwrap_err(),
        HubsMlsError::WrongDevice
    );
    drop(bob);
}

#[test]
fn a_welcome_for_another_conversation_is_refused() {
    let v = vectors();
    let bob = MlsDevice::new(device(&v, "bob")).unwrap();
    let error = bob
        .join_from_welcome(
            h(&v, &["addBob", "welcomeHex"]),
            imported(&v, "bobKeyPackage"),
            "00000000-0000-4000-8000-000000000000".into(),
        )
        .unwrap_err();
    assert_eq!(error, HubsMlsError::WrongConversation);
    // A welcome is refused with the private half of a different key package.
    let error = bob
        .join_from_welcome(
            h(&v, &["addBob", "welcomeHex"]),
            imported(&v, "bobSpareKeyPackage"),
            s(&v, &["conversationId"]).into(),
        )
        .unwrap_err();
    assert!(matches!(error, HubsMlsError::Mls { .. }), "{error:?}");
}

#[test]
fn a_tampered_message_is_refused_and_changes_nothing() {
    let v = vectors();
    let (_bob, group) = bob_joins(&v);
    let mut tampered = h(&v, &["message1", "mlsMessageHex"]);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x40;
    assert!(group.receive(tampered).is_err());
    // The ratchet did not move: the real message still opens.
    assert!(matches!(
        group
            .receive(h(&v, &["message1", "mlsMessageHex"]))
            .unwrap(),
        Incoming::Message { .. }
    ));
    // A message cannot be opened twice (its key is gone).
    assert!(group
        .receive(h(&v, &["message1", "mlsMessageHex"]))
        .is_err());
}

#[test]
fn plaintext_mls_messages_are_refused() {
    let v = vectors();
    let (_bob, group) = bob_joins(&v);
    // A key package is an MLS message too, but not a private message.
    assert_eq!(
        group
            .receive(h(&v, &["bobSpareKeyPackage", "mlsMessageHex"]))
            .unwrap_err(),
        HubsMlsError::NotEncrypted
    );
    assert_eq!(
        group.receive(h(&v, &["addBob", "welcomeHex"])).unwrap_err(),
        HubsMlsError::NotEncrypted
    );
}

#[test]
fn keys_in_every_form_the_web_writes() {
    let v = vectors();
    let mut keys = device(&v, "bob");
    // The PKCS#8 signing key works the same as the seed.
    keys.device_signing_key = h(&v, &["bobKeyPackage", "signaturePrivateKeyPkcs8Hex"]);
    assert_eq!(keys.device_signing_key.len(), 48);
    let bob = MlsDevice::new(keys.clone()).expect("pkcs8");
    assert_eq!(bob.device_id(), s(&v, &["bob", "deviceId"]));
    // A certificate from the wrong identity key is refused.
    let mut forged = keys.clone();
    forged.identity_public_key = h(&v, &["alice", "identityPublicKeyHex"]);
    assert!(matches!(
        MlsDevice::new(forged).unwrap_err(),
        HubsMlsError::Credential { .. }
    ));
    // A signing key that does not match the public key is refused.
    let mut mismatched = keys;
    mismatched.device_signing_key = h(&v, &["alice", "deviceSeedHex"]);
    assert!(matches!(
        MlsDevice::new(mismatched).unwrap_err(),
        HubsMlsError::Malformed { .. }
    ));
}

/// Native Alice and native Bob with the keys from the vectors: make, add,
/// join, talk, refresh, remove. Everything here goes through the same calls
/// the apps make; the live ts-mls tests run the same flows against ts-mls.
#[test]
fn native_to_native_with_the_web_keys() {
    let v = vectors();
    let now = now(&v);
    let alice = MlsDevice::new(device(&v, "alice")).unwrap();
    let bob = MlsDevice::new(device(&v, "bob")).unwrap();
    let conversation = "5c2b8e1a-7d4f-4a3b-9e6c-1f0a2b3c4d5e".to_string();
    let a = alice.start_group(conversation.clone(), now).unwrap();
    assert_eq!(a.epoch(), 0);
    let packages = bob.create_key_packages(2, now).unwrap();
    assert_eq!(packages.len(), 2);
    assert_ne!(packages[0].id, packages[1].id);
    assert_eq!(packages[0].id.len(), 16);
    let info = read_key_package(packages[0].public_package.clone()).unwrap();
    assert_eq!(info.not_after, now + KEY_PACKAGE_LIFETIME_SECONDS);
    assert_eq!(info.not_before, now - KEY_PACKAGE_CLOCK_SKEW_SECONDS);
    assert_eq!(packages[0].not_after, info.not_after);

    let change = a
        .change_devices(vec![packages[0].public_package.clone()], vec![], now, None)
        .unwrap();
    assert_eq!(change.epoch, 0);
    assert_eq!(change.added[0].user_id, "u_bob");
    assert!(a.has_pending_commit());
    // Nothing else can happen until the server answers.
    assert!(matches!(
        a.change_devices(vec![], vec![], now, None).unwrap_err(),
        HubsMlsError::PendingCommit { .. }
    ));
    a.merge_pending_commit().unwrap();
    assert_eq!(a.epoch(), 1);
    let b = bob
        .join_from_welcome(
            change.welcome.clone().unwrap(),
            packages[0].clone(),
            conversation.clone(),
        )
        .unwrap();
    assert_eq!(b.epoch(), 1);

    let sent = a
        .encrypt_message(MessageDraft {
            id: "m_native_1".into(),
            kind: "text".into(),
            body: "Tab\there, slash / and \u{1} control, \u{2028} separator.".into(),
            sent_at: 1_760_000_100_000,
            expires_in_seconds: 604_800,
        })
        .unwrap();
    assert_eq!(sent.commitment.len(), 32);
    assert_eq!(sent.payload.user_id, "u_alice");
    match b.receive(sent.ciphertext.clone()).unwrap() {
        Incoming::Message {
            payload, sender, ..
        } => {
            assert_eq!(payload, sent.payload);
            assert_eq!(sender.device_id, s(&v, &["alice", "deviceId"]));
        }
        other => panic!("{other:?}"),
    }

    // Bob's weekly refresh, then a message after it.
    let update = b.change_devices(vec![], vec![], now, None).unwrap();
    assert!(update.welcome.is_none());
    b.merge_pending_commit().unwrap();
    assert!(matches!(
        a.receive(update.commit).unwrap(),
        Incoming::Change { epoch: 2, .. }
    ));

    // The epoch race: both commit from epoch 2, the server takes Bob's.
    let mine = a.change_devices(vec![], vec![], now, None).unwrap();
    let theirs = b.change_devices(vec![], vec![], now, None).unwrap();
    assert_eq!(mine.epoch, theirs.epoch);
    b.merge_pending_commit().unwrap();
    a.clear_pending_commit();
    assert!(matches!(
        a.receive(theirs.commit).unwrap(),
        Incoming::Change { epoch: 3, .. }
    ));

    // Alice removes Bob's device; Bob learns he is out.
    let bob_leaf = a
        .members()
        .iter()
        .find(|m| m.user_id == "u_bob")
        .unwrap()
        .leaf_index;
    let removal = a.change_devices(vec![], vec![bob_leaf], now, None).unwrap();
    a.merge_pending_commit().unwrap();
    assert_eq!(a.members().len(), 1);
    assert!(matches!(
        b.receive(removal.commit).unwrap(),
        Incoming::Removed { .. }
    ));
}

#[test]
fn identities_and_devices_made_here_verify() {
    let identity = create_identity().unwrap();
    assert_eq!(identity.signing_key.len(), 48);
    let id = new_device_id().unwrap();
    assert_eq!(id.len(), 22);
    let keys = create_device(identity.clone(), "u_native".into(), id.clone()).unwrap();
    assert!(verify_device_certificate(
        DeviceCredential {
            user_id: "u_native".into(),
            device_id: id,
            identity_public_key: identity.public_key,
            certificate: keys.certificate.clone(),
        },
        keys.device_public_key.clone(),
    ));
    let device = MlsDevice::new(keys).unwrap();
    assert_eq!(device.user_id(), "u_native");
}

#[test]
fn the_web_key_packages_carry_the_90_day_lifetime() {
    let v = vectors();
    let made = v["generator"]["nowSeconds"]
        .as_u64()
        .expect("the vectors' clock");
    for name in ["aliceKeyPackage", "bobKeyPackage", "bobSpareKeyPackage"] {
        let info = read_key_package(h(&v, &[name, "mlsMessageHex"])).unwrap();
        assert_eq!(
            info.not_before,
            made - KEY_PACKAGE_CLOCK_SKEW_SECONDS,
            "{name}"
        );
        assert_eq!(
            info.not_after,
            made + KEY_PACKAGE_LIFETIME_SECONDS,
            "{name}"
        );
        assert_eq!(
            info.not_before.to_string(),
            s(&v, &["settings", "lifetime", "notBefore"])
        );
        assert_eq!(
            info.not_after.to_string(),
            s(&v, &["settings", "lifetime", "notAfter"])
        );
        // Inside the policy for its 90 days, and not after.
        assert!(check_key_package(h(&v, &[name, "mlsMessageHex"]), made + 89 * 86_400).is_ok());
        let expired =
            check_key_package(h(&v, &[name, "mlsMessageHex"]), made + 90 * 86_400).unwrap_err();
        assert!(
            matches!(expired, HubsMlsError::KeyPackageLifetime { .. }),
            "{expired:?}"
        );
    }
    let policy = key_package_policy();
    assert_eq!(
        policy.lifetime_seconds,
        v["settings"]["lifetime"]["lifetimeSeconds"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        policy.refresh_seconds,
        v["settings"]["lifetime"]["refreshSeconds"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(policy.target_count, 20);
}

#[test]
fn a_never_expiring_key_package_is_refused_and_nothing_is_staged() {
    let v = vectors();
    let now = now(&v);
    let legacy = h(&v, &["legacyKeyPackageHex"]);
    // It is a real Hubs key package for Bob's device...
    let info = read_key_package(legacy.clone()).unwrap();
    assert_eq!(info.user_id, "u_bob");
    assert_eq!(info.not_before, 0);
    // ...but valid for longer than 90 days, so no adder takes it.
    let error = check_key_package(legacy.clone(), now).unwrap_err();
    assert_eq!(
        error,
        HubsMlsError::KeyPackageLifetime {
            reason: "the lifetime is longer than 90 days".into()
        }
    );
    let alice = MlsDevice::new(device(&v, "alice")).unwrap();
    let group = alice
        .start_group("0f1e2d3c-4b5a-4968-8776-655443322110".into(), now)
        .unwrap();
    let error = group
        .change_devices(
            vec![h(&v, &["bobSpareKeyPackage", "mlsMessageHex"]), legacy],
            vec![],
            now,
            None,
        )
        .unwrap_err();
    assert!(
        matches!(error, HubsMlsError::KeyPackageLifetime { .. }),
        "{error:?}"
    );
    assert!(!group.has_pending_commit());
    assert_eq!(group.epoch(), 0);
    // The policy-made spare alone is fine.
    group
        .change_devices(
            vec![h(&v, &["bobSpareKeyPackage", "mlsMessageHex"])],
            vec![],
            now,
            None,
        )
        .unwrap();
    // Ninety days on, the same key package is refused as expired.
    group.clear_pending_commit();
    let late = now + KEY_PACKAGE_LIFETIME_SECONDS + 1;
    let error = group
        .change_devices(
            vec![h(&v, &["bobSpareKeyPackage", "mlsMessageHex"])],
            vec![],
            late,
            None,
        )
        .unwrap_err();
    assert!(
        matches!(error, HubsMlsError::KeyPackageLifetime { .. }),
        "{error:?}"
    );
}

#[test]
fn key_packages_made_here_follow_the_policy() {
    let v = vectors();
    let now = now(&v);
    let bob = MlsDevice::new(device(&v, "bob")).unwrap();
    let made = bob.create_key_packages(1, now).unwrap().remove(0);
    assert_eq!(made.created_at, now);
    assert_eq!(made.not_after, now + KEY_PACKAGE_LIFETIME_SECONDS);
    let info = check_key_package(made.public_package.clone(), now).unwrap();
    assert_eq!(
        info.not_after - info.not_before,
        KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS
    );
    assert!(!key_package_needs_refresh(
        made.created_at,
        now + 29 * 86_400
    ));
    assert!(key_package_needs_refresh(
        made.created_at,
        now + KEY_PACKAGE_REFRESH_SECONDS
    ));
}
