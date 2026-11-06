//! The cross-platform vectors (`test-vectors/e2ee-test-vectors.json` at the
//! root of this repository, made by the TypeScript implementation with
//! ts-mls 1.6.4), replayed through the core the same way the TypeScript
//! tests (`typescript/test/e2ee-vectors.test.ts`) replay them. Newer sections
//! only add to the file; every older one stays byte for byte the same.

use std::{collections::HashMap, sync::Arc};

use base64ct::{Base64, Encoding};
use hubs_mls::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/e2ee-test-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the vectors file")).expect("JSON")
}

/// Standard base64, strict (the wire's form).
fn b64_bytes(text: &str) -> Vec<u8> {
    Base64::decode_vec(text).expect("base64")
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn h(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).expect("hex")
}

fn b64(text: &str) -> Vec<u8> {
    // Base64 through the core's own strict reader (the payload JSON).
    let json = format!(
        "{{\"v\":1,\"id\":\"x\",\"kind\":\"text\",\"body\":\"\",\"sentAt\":0,\"expiresInSeconds\":0,\"userId\":\"u\",\"deviceId\":\"d\",\"frankingKey\":\"{text}\"}}"
    );
    parse_payload(json.into_bytes())
        .expect("32 bytes")
        .franking_key
}

fn now(v: &Value) -> u64 {
    v["generator"]["nowSeconds"].as_u64().unwrap() + 600
}

fn device_keys(d: &Value) -> DeviceKeys {
    DeviceKeys {
        user_id: s(d, "userId").into(),
        device_id: s(d, "deviceId").into(),
        identity_public_key: h(d, "identityPublicKeyHex"),
        device_public_key: h(d, "devicePublicKeyHex"),
        device_signing_key: h(d, "deviceSeedHex"),
        certificate: h(d, "certificateHex"),
    }
}

fn key_package(v: &Value, name: &str) -> DeviceKeyPackage {
    let k = &v["mls"]["keyPackages"][name];
    import_key_package(
        s(k, "id").into(),
        h(k, "mlsMessageHex"),
        h(k, "initPrivateKeyHex"),
        h(k, "encryptionPrivateKeyHex"),
        now(v),
    )
    .expect("import")
}

fn members_of(group: &MlsGroup) -> Vec<String> {
    group
        .members()
        .into_iter()
        .map(|m| format!("{}/{}@{}", m.user_id, m.device_id, m.leaf_index))
        .collect()
}

fn expected_members(step: &Value) -> Vec<String> {
    step["membersAfter"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_owned())
        .collect()
}

fn identities(group: &MlsGroup) -> Vec<MemberIdentity> {
    group
        .members()
        .into_iter()
        .map(|m| MemberIdentity {
            user_id: m.user_id,
            identity_public_key: m.identity_public_key,
        })
        .collect()
}

#[test]
fn rule_tables_match_the_web() {
    let v = vectors();
    let h = &v["hubs"];
    for case in h["payloadRules"].as_array().unwrap() {
        let problem = payload_problem(s(case, "payloadJson").as_bytes().to_vec());
        assert_eq!(
            problem.is_none(),
            case["valid"].as_bool().unwrap(),
            "{}: {problem:?}",
            s(case, "name")
        );
    }
    let to_member = |m: &Value| MemberIdentity {
        user_id: s(m, "userId").into(),
        identity_public_key: b64(s(m, "identityPublicKey")),
    };
    for case in h["membership"].as_array().unwrap() {
        let members: Vec<_> = case["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(to_member)
            .collect();
        let me = to_member(&case["self"]);
        let problem = membership_problem(
            members,
            me.user_id,
            me.identity_public_key,
            case["peer"].as_str().map(str::to_owned),
        );
        assert_eq!(
            problem.is_none(),
            case["accepted"].as_bool().unwrap(),
            "{}",
            s(case, "name")
        );
    }
    for case in h["keyPackageLifetime"]["cases"].as_array().unwrap() {
        let problem = key_package_lifetime_problem(
            s(case, "notBefore").parse().unwrap(),
            s(case, "notAfter").parse().unwrap(),
            case["atSeconds"].as_u64().unwrap(),
        );
        assert_eq!(
            problem.is_none(),
            case["adderAccepts"].as_bool().unwrap(),
            "{}",
            s(case, "name")
        );
    }
    let limits = payload_limits();
    let timers: Vec<i64> = h["timers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_i64().unwrap())
        .collect();
    assert_eq!(limits.timers, timers);
    assert_eq!(limits.max_body_utf16, 4000);
}

#[test]
fn hubs_constructions_match_the_web() {
    let v = vectors();
    for (_, d) in v["hubs"]["devices"].as_object().unwrap() {
        assert_eq!(
            device_certificate_body(
                s(d, "userId").into(),
                s(d, "deviceId").into(),
                h(d, "devicePublicKeyHex")
            ),
            h(d, "certificateBodyHex")
        );
        assert_eq!(
            sign_ed25519(h(d, "identitySeedHex"), h(d, "certificateBodyHex")).unwrap(),
            h(d, "certificateHex")
        );
        let credential = DeviceCredential {
            user_id: s(d, "userId").into(),
            device_id: s(d, "deviceId").into(),
            identity_public_key: h(d, "identityPublicKeyHex"),
            certificate: h(d, "certificateHex"),
        };
        assert_eq!(
            String::from_utf8(credential_identity(credential.clone())).unwrap(),
            s(d, "credentialIdentityUtf8")
        );
        assert!(verify_device_certificate(
            credential,
            h(d, "devicePublicKeyHex")
        ));
        // Each device's keys load as a device.
        MlsDevice::new(device_keys(d)).expect("device keys");
    }
    let p = &v["primitives"]["ed25519"];
    let message = s(p, "messageUtf8").as_bytes().to_vec();
    assert_eq!(
        sign_ed25519(h(p, "seedHex"), message.clone()).unwrap(),
        h(p, "signatureHex")
    );
    assert_eq!(
        sign_ed25519(h(p, "pkcs8Hex"), message).unwrap(),
        h(p, "signatureHex")
    );

    let fr = &v["hubs"]["franking"];
    let payload = parse_payload(s(fr, "payloadJsonUtf8").as_bytes().to_vec()).unwrap();
    assert_eq!(
        String::from_utf8(payload_json(payload.clone())).unwrap(),
        s(fr, "payloadJsonUtf8")
    );
    assert_eq!(
        canonical_payload_bytes(payload.clone()),
        h(fr, "canonicalBytesHex")
    );
    assert_eq!(
        franking_commitment(payload).unwrap(),
        h(fr, "commitmentHex")
    );
}

/// Every MLS step, in order, as each receiver named, the web's way:
/// receivers with `receiverStateHex` load the web's saved state for it.
#[test]
fn every_mls_step_replays() {
    let v = vectors();
    let m = &v["mls"];
    let at = now(&v);
    let conversation: String = s(m, "conversationId").into();
    for (name, k) in m["keyPackages"].as_object().unwrap() {
        check_key_package(h(k, "mlsMessageHex"), at).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let devices = &v["hubs"]["devices"];
    let mut device: HashMap<&str, Arc<MlsDevice>> = HashMap::new();
    device.insert(
        "device_alice_1",
        MlsDevice::new(device_keys(&devices["alice"])).unwrap(),
    );
    device.insert(
        "device_bob_1",
        MlsDevice::new(device_keys(&devices["bob"])).unwrap(),
    );
    device.insert(
        "device_bob_2",
        MlsDevice::new(device_keys(&devices["bob2"])).unwrap(),
    );
    let me = |who: &str| -> (String, Vec<u8>, String) {
        match who {
            "device_alice_1" => (
                "u_alice".into(),
                h(&devices["alice"], "identityPublicKeyHex"),
                "u_bob".into(),
            ),
            _ => (
                "u_bob".into(),
                h(&devices["bob"], "identityPublicKeyHex"),
                "u_alice".into(),
            ),
        }
    };
    let rule = |who: &str, group: &MlsGroup| {
        let (user, key, peer) = me(who);
        membership_problem(identities(group), user, key, Some(peer))
    };
    let mut groups: HashMap<String, Arc<MlsGroup>> = HashMap::new();
    let mut checked = 0;
    let mut passed: Vec<String> = Vec::new();

    for step in m["steps"].as_array().unwrap() {
        let name = s(step, "step");
        let kind = s(step, "type");
        for receiver in step["receivers"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let receiver = receiver.as_str().unwrap();
            if kind == "refuseWelcome" {
                // The welcome opens with Bob's spare key package, but its
                // group is another conversation: refused.
                let bob = &device["device_bob_1"];
                let refused = bob.join_from_welcome(
                    h(step, "welcomeHex"),
                    key_package(&v, "bobSpare"),
                    conversation.clone(),
                );
                assert_eq!(
                    refused.unwrap_err(),
                    HubsMlsError::WrongConversation,
                    "{name}"
                );
                let other = MlsDevice::new(device_keys(&devices["bob"])).unwrap();
                let stray = other
                    .join_from_welcome(
                        h(step, "welcomeHex"),
                        key_package(&v, "bobSpare"),
                        s(step, "groupIdUtf8").into(),
                    )
                    .expect("it opens as the other group");
                assert_eq!(stray.conversation_id(), s(step, "groupIdUtf8"));
                checked += 1;
                continue;
            }
            if let Some(state) = step["receiverStateHex"].as_str() {
                let snapshot = import_web_group_state(hex::decode(state).unwrap())
                    .expect("the web state reads");
                let group = device[receiver]
                    .load_group(snapshot)
                    .expect("the web state is this device's");
                groups.insert(receiver.into(), group);
            }
            let group = groups
                .get(receiver)
                .unwrap_or_else(|| panic!("{name}: {receiver} has joined"))
                .clone();
            match kind {
                "message" => {
                    let incoming = group
                        .receive(h(step, "mlsMessageHex"))
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    let Incoming::Message {
                        payload,
                        commitment,
                        sender,
                        epoch,
                    } = incoming
                    else {
                        panic!("{name}: not a message")
                    };
                    assert_eq!(
                        String::from_utf8(payload_json(payload.clone())).unwrap(),
                        s(step, "plaintextUtf8"),
                        "{name}"
                    );
                    assert_eq!(
                        String::from_utf8(canonical_payload_bytes(payload)).unwrap(),
                        s(step, "canonicalBytesUtf8")
                    );
                    assert_eq!(commitment, h(step, "authenticatedDataHex"));
                    assert_eq!(sender.device_id, s(step, "sender"));
                    assert_eq!(epoch, step["epoch"].as_u64().unwrap());
                }
                "commit" | "commit+welcome" => {
                    let incoming = group
                        .receive(h(step, "commitHex"))
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    let Incoming::Change { epoch, .. } = incoming else {
                        panic!("{name}: not a change")
                    };
                    assert_eq!(epoch, step["epochAfter"].as_u64().unwrap(), "{name}");
                    assert_eq!(rule(receiver, &group), None, "{name}");
                    if step.get("membersAfter").is_some() {
                        assert_eq!(members_of(&group), expected_members(step), "{name}");
                    }
                }
                "refuse" => {
                    let before = group.snapshot().unwrap();
                    let epoch = group.epoch();
                    assert!(
                        group.receive(h(step, "mlsMessageHex")).is_err(),
                        "{name} must be refused"
                    );
                    // Nothing changed: same epoch, same saved state.
                    assert_eq!(group.epoch(), epoch);
                    assert_eq!(
                        group.snapshot().unwrap(),
                        before,
                        "{name} changed the state"
                    );
                }
                "refuseMembership" => {
                    let before = group.snapshot().unwrap();
                    let incoming = group
                        .receive(h(step, "commitHex"))
                        .expect("MLS processes it");
                    assert!(matches!(incoming, Incoming::Change { .. }), "{name}");
                    assert_eq!(members_of(&group), expected_members(step), "{name}");
                    assert_eq!(
                        rule(receiver, &group).as_deref(),
                        Some(s(step, "membershipError")),
                        "{name}"
                    );
                    // Refused: the device goes back to the state it kept.
                    let kept = device[receiver].load_group(before).unwrap();
                    assert_eq!(kept.epoch(), step["epochBefore"].as_u64().unwrap());
                    groups.insert(receiver.into(), kept);
                }
                other => panic!("unknown step type {other}"),
            }
            checked += 1;
        }
        if kind == "commit+welcome" {
            let joiner = s(&step["welcomeFor"], "device");
            let package = if joiner == "device_bob_1" {
                "bob"
            } else {
                "bob2"
            };
            let joined = device[joiner]
                .join_from_welcome(
                    h(step, "welcomeHex"),
                    key_package(&v, package),
                    conversation.clone(),
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hex::encode(joined.conversation_id()), s(m, "groupIdHex"));
            assert_eq!(members_of(&joined), expected_members(step), "{name}");
            assert_eq!(rule(joiner, &joined), None);
            groups.insert(joiner.into(), joined);
            checked += 1;
        }
        for receiver in step["notReadableBy"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let group = &groups[receiver.as_str().unwrap()];
            assert!(
                group.receive(h(step, "mlsMessageHex")).is_err(),
                "{name}: a removed device read it"
            );
            checked += 1;
        }
        passed.push(name.to_owned());
    }
    assert_eq!(passed.len(), m["steps"].as_array().unwrap().len());
    assert!(checked >= 25, "checked {checked} receives");
}

/// The web's saved state, imported, sits at the same epoch as native Bob:
/// the same members and the same epoch authenticator.
#[test]
fn the_imported_web_state_matches_native_bob() {
    let v = vectors();
    let m = &v["mls"];
    let devices = &v["hubs"]["devices"];
    let steps = m["steps"].as_array().unwrap();
    let step = |name: &str| steps.iter().find(|s| s["step"] == name).unwrap();
    let bob = MlsDevice::new(device_keys(&devices["bob"])).unwrap();
    let group = bob
        .join_from_welcome(
            h(step("addBob"), "welcomeHex"),
            key_package(&v, "bob"),
            s(m, "conversationId").into(),
        )
        .unwrap();
    group.receive(h(step("m1"), "mlsMessageHex")).unwrap();
    group.receive(h(step("m2Timer"), "mlsMessageHex")).unwrap();
    let alice = MlsDevice::new(device_keys(&devices["alice"])).unwrap();
    let imported = alice
        .load_group(import_web_group_state(h(step("m3FromBob"), "receiverStateHex")).unwrap())
        .unwrap();
    assert_eq!(imported.epoch(), group.epoch());
    assert_eq!(imported.own_leaf_index(), 0);
    assert_eq!(members_of(&imported), members_of(&group));
    assert_eq!(
        imported.epoch_authenticator().unwrap(),
        group.epoch_authenticator().unwrap()
    );
    // Another device cannot take the web state as its own.
    let refused =
        bob.load_group(import_web_group_state(h(step("m3FromBob"), "receiverStateHex")).unwrap());
    assert_eq!(refused.unwrap_err(), HubsMlsError::WrongDevice);
    // A cut state is refused, not read.
    let mut cut = h(step("m3FromBob"), "receiverStateHex");
    cut.truncate(cut.len() / 2);
    assert!(import_web_group_state(cut).is_err());
}

/// Where the leaf index sits in a group state saved by the TypeScript
/// implementation: after the group context and twelve length-prefixed
/// fields (ten key schedule secrets, the secret tree, the ratchet tree).
fn leaf_index_offset(state: &[u8]) -> usize {
    use mls_rs::{
        group::GroupContext,
        mls_rs_codec::{MlsDecode, VarInt},
    };
    let mut rest = state;
    GroupContext::mls_decode(&mut rest).unwrap();
    for _ in 0..12 {
        let length = u32::from(VarInt::mls_decode(&mut rest).unwrap()) as usize;
        rest = &rest[length..];
    }
    state.len() - rest.len()
}

/// A saved state whose leaf is outside its tree is refused before the core
/// walks the leaf's path, with no panic and no endless loop.
#[test]
fn an_imported_leaf_outside_the_tree_is_refused() {
    let v = vectors();
    let m = &v["mls"];
    let steps = m["steps"].as_array().unwrap();
    let step = |name: &str| steps.iter().find(|s| s["step"] == name).unwrap();
    let state = h(step("m3FromBob"), "receiverStateHex");
    let offset = leaf_index_offset(&state);
    assert_eq!(&state[offset..offset + 4], &0u32.to_be_bytes());
    assert!(import_web_group_state(state.clone()).is_ok());
    // Two members: a tree of two leaves, so leaf 1 is the last one inside.
    let mut inside = state.clone();
    inside[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(import_web_group_state(inside).is_ok());
    for leaf in [2u32, 3, 1 << 31, u32::MAX] {
        let mut outside = state.clone();
        outside[offset..offset + 4].copy_from_slice(&leaf.to_be_bytes());
        assert_eq!(
            import_web_group_state(outside).unwrap_err(),
            HubsMlsError::Malformed {
                reason: "the web state's leaf is outside its tree".into()
            },
            "leaf {leaf}"
        );
    }
}

/// A refused message never changes the state, so the sender's
/// next message still opens (the web's bug broke every later message).
#[test]
fn refused_messages_leave_later_ones_readable() {
    let v = vectors();
    let m = &v["mls"];
    let devices = &v["hubs"]["devices"];
    let steps = m["steps"].as_array().unwrap();
    let alice = MlsDevice::new(device_keys(&devices["alice"])).unwrap();
    let group = alice
        .load_group(
            import_web_group_state(h(
                steps.iter().find(|s| s["step"] == "bobUpdate").unwrap(),
                "receiverStateHex",
            ))
            .unwrap(),
        )
        .unwrap();
    // Bob's two-identity commit, refused by the membership rule ...
    let two = steps
        .iter()
        .find(|s| s["step"] == "peerTwoIdentities")
        .unwrap();
    let before = group.snapshot().unwrap();
    group.receive(h(two, "commitHex")).unwrap();
    let kept = alice.load_group(before).unwrap();
    // ... and the state kept still takes Bob's real update and message.
    let update = steps.iter().find(|s| s["step"] == "bobUpdate").unwrap();
    assert!(matches!(
        kept.receive(h(update, "commitHex")).unwrap(),
        Incoming::Change { epoch: 5, .. }
    ));
    let m6 = steps.iter().find(|s| s["step"] == "m6FromBob").unwrap();
    let Incoming::Message { payload, .. } = kept.receive(h(m6, "mlsMessageHex")).unwrap() else {
        panic!()
    };
    assert_eq!(payload.body, "Keys refreshed on my side.");
}

#[test]
fn outgoing_payloads_follow_the_shared_rule() {
    let v = vectors();
    let devices = &v["hubs"]["devices"];
    let alice = MlsDevice::new(device_keys(&devices["alice"])).unwrap();
    let group = alice.start_group("a-conversation".into(), now(&v)).unwrap();
    let draft = |id: &str, kind: &str, body: &str, seconds: i64| MessageDraft {
        id: id.into(),
        kind: kind.into(),
        body: body.into(),
        sent_at: 1_760_000_000_000,
        expires_in_seconds: seconds,
    };
    assert!(group
        .encrypt_message(draft("m_1", "text", "hello", 86400))
        .is_ok());
    assert!(group.encrypt_message(draft("m_2", "timer", "", 0)).is_ok());
    for bad in [
        draft("notice:x", "text", "hello", 86400),
        draft("m_3", "notice", "hello", 86400),
        draft("m_4", "text", "hello", 12345),
        draft("m_5", "timer", "words", 300),
        draft("m_6", "text", &"x".repeat(4001), 300),
    ] {
        let error = group.encrypt_message(bad.clone()).unwrap_err();
        assert!(matches!(error, HubsMlsError::Payload { .. }), "{bad:?}");
    }
    // 4000 UTF-16 units of emoji is 2000 of them.
    assert!(group
        .encrypt_message(draft("m_7", "text", &"🗂".repeat(2000), 300))
        .is_ok());
    assert!(group
        .encrypt_message(draft("m_8", "text", &"🗂".repeat(2001), 300))
        .is_err());
}

fn member_of(m: &Value) -> GroupMember {
    GroupMember {
        leaf_index: 0,
        user_id: s(m, "userId").into(),
        device_id: s(m, "deviceId").into(),
        identity_public_key: b64_bytes(s(m, "identityPublicKey")),
        device_public_key: b64_bytes(s(m, "devicePublicKey")),
    }
}

/// Signed device removals: the three bodies byte for byte, their
/// signatures, which proofs verify for which member, and the removal rule.
#[test]
fn device_removals_match_the_web() {
    let v = vectors();
    let r = &v["hubs"]["deviceRemoval"];
    let alice = &v["hubs"]["devices"]["alice"];

    let ir = &r["identityRemoval"];
    let at = ir["at"].as_i64().unwrap();
    let body = device_removal_body(
        s(ir, "userId").into(),
        s(ir, "deviceId").into(),
        h(ir, "devicePublicKeyHex"),
        at,
    );
    assert_eq!(body, h(ir, "bodyHex"));
    assert_eq!(
        h(ir, "signedByIdentityKeyHex"),
        h(alice, "identityPublicKeyHex")
    );
    assert_eq!(
        sign_ed25519(h(alice, "identitySeedHex"), body.clone()).unwrap(),
        h(ir, "signatureHex")
    );
    assert!(verify_ed25519(
        h(ir, "signedByIdentityKeyHex"),
        body.clone(),
        h(ir, "signatureHex")
    ));
    // The device key did not sign it.
    assert!(!verify_ed25519(
        h(alice, "devicePublicKeyHex"),
        body,
        h(ir, "signatureHex")
    ));

    let sr = &r["selfRemoval"];
    let body = self_remove_body(
        s(sr, "userId").into(),
        s(sr, "deviceId").into(),
        sr["at"].as_i64().unwrap(),
    );
    assert_eq!(body, h(sr, "bodyHex"));
    assert_eq!(
        h(sr, "signedByDeviceKeyHex"),
        h(alice, "devicePublicKeyHex")
    );
    assert_eq!(
        sign_ed25519(h(alice, "deviceSeedHex"), body.clone()).unwrap(),
        h(sr, "signatureHex")
    );
    assert!(verify_ed25519(
        h(sr, "signedByDeviceKeyHex"),
        body,
        h(sr, "signatureHex")
    ));

    let st = &r["signedRemovalsStatement"];
    let body = signed_removals_body(s(st, "userId").into(), h(st, "identityPublicKeyHex"));
    assert_eq!(body, h(st, "bodyHex"));
    assert_eq!(
        sign_ed25519(h(alice, "identitySeedHex"), body).unwrap(),
        h(st, "signatureHex")
    );
    assert_eq!(
        verify_removal_statement(
            s(st, "userId").into(),
            h(st, "identityPublicKeyHex"),
            h(st, "signatureHex"),
        ),
        st["verifies"].as_bool().unwrap()
    );
    // The statement names its account: another user id does not verify.
    assert!(!verify_removal_statement(
        "u_bob".into(),
        h(st, "identityPublicKeyHex"),
        h(st, "signatureHex"),
    ));

    for case in r["verifyCases"].as_array().unwrap() {
        let name = s(case, "name");
        let member = member_of(&case["member"]);
        let p = &case["proof"];
        let proof = p["signature"].as_str().map(|signature| RemovalProof {
            kind: s(p, "kind").into(),
            at: p["at"].as_i64(),
            signature: b64_bytes(signature),
        });
        let valid = case["valid"].as_bool().unwrap();
        if let Some(proof) = &proof {
            assert_eq!(
                verify_removal(member.clone(), proof.clone()),
                valid,
                "{name}"
            );
        }
        // The state `removalCounts` takes: no signature is no proof.
        let expected = match (&proof, valid) {
            (None, _) => RemovalProofState::NoProof,
            (Some(_), true) => RemovalProofState::Valid,
            (Some(_), false) => RemovalProofState::Invalid,
        };
        assert_eq!(removal_proof_state(member, proof), expected, "{name}");
    }

    for case in r["rule"].as_array().unwrap() {
        let proof = match s(case, "proof") {
            "valid" => RemovalProofState::Valid,
            "invalid" => RemovalProofState::Invalid,
            "none" => RemovalProofState::NoProof,
            other => panic!("unknown proof {other}"),
        };
        assert_eq!(
            removal_counts(
                proof,
                case["startedOver"].as_bool().unwrap(),
                case["signedRemovals"].as_bool().unwrap(),
            ),
            case["removes"].as_bool().unwrap(),
            "{case}"
        );
    }
}

/// Proofs the web refuses before it checks a signature: a time that is not
/// a safe integer, a missing time, a kind without a proof, bytes of the
/// wrong size. None of them may verify, and none may panic.
#[test]
fn malformed_removal_proofs_never_verify() {
    let v = vectors();
    let r = &v["hubs"]["deviceRemoval"];
    let case = &r["verifyCases"][0];
    let member = member_of(&case["member"]);
    let good = RemovalProof {
        kind: "identity".into(),
        at: case["proof"]["at"].as_i64(),
        signature: b64_bytes(s(&case["proof"], "signature")),
    };
    assert!(verify_removal(member.clone(), good.clone()));
    let refused = [
        RemovalProof {
            at: None,
            ..good.clone()
        },
        RemovalProof {
            at: Some(1 << 53),
            ..good.clone()
        },
        RemovalProof {
            kind: "unsigned".into(),
            ..good.clone()
        },
        RemovalProof {
            kind: "reset".into(),
            ..good.clone()
        },
        RemovalProof {
            signature: Vec::new(),
            ..good.clone()
        },
        RemovalProof {
            signature: good.signature[..63].to_vec(),
            ..good.clone()
        },
    ];
    for proof in refused {
        assert!(!verify_removal(member.clone(), proof.clone()), "{proof:?}");
        assert_eq!(
            removal_proof_state(member.clone(), Some(proof)),
            RemovalProofState::Invalid
        );
    }
    let short_key = GroupMember {
        identity_public_key: member.identity_public_key[..31].to_vec(),
        ..member
    };
    assert!(!verify_removal(short_key, good));
    // The largest safe integer still formats as plain digits, as in JavaScript.
    let body = self_remove_body("u".into(), "d".into(), (1 << 53) - 1);
    assert!(body.ends_with(b"\x009007199254740991"));
    assert!(self_remove_body("u".into(), "d".into(), -5).ends_with(b"\x00-5"));
}

/// The note a commit carries once its sender's account made the statement.
#[test]
fn the_signed_removals_note_matches_the_web() {
    let v = vectors();
    let r = &v["hubs"]["deviceRemoval"]["signedRemovalsNote"];
    let signature = hex::decode(s(r, "signatureHex")).unwrap();
    let note = hex::decode(s(r, "noteHex")).unwrap();
    assert_eq!(signed_removals_note(signature.clone()), note);
    assert_eq!(
        read_signed_removals_note(note).unwrap(),
        hex::decode(s(r, "reads")).unwrap()
    );
    for case in r["notNotes"].as_array().unwrap() {
        assert_eq!(
            read_signed_removals_note(hex::decode(s(case, "hex")).unwrap()),
            None,
            "{}",
            s(case, "name"),
        );
    }
}

/// The backup counter: the sealed bundle (the same sealing as `hubs.backup`)
/// carries `counter`, and the restore rule refuses an older backup.
#[test]
fn backup_counters_match_the_web() {
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    let v = vectors();
    let bc = &v["hubs"]["backupCounter"];
    for case in bc["rule"].as_array().unwrap() {
        assert_eq!(
            backup_rollback_problem(case["counter"].as_i64(), case["seen"].as_u64().unwrap())
                .is_none(),
            case["restores"].as_bool().unwrap(),
            "{case}"
        );
    }
    assert_eq!(
        backup_rollback_problem(Some(3), 4).as_deref(),
        Some("This backup is older than one this device has already seen, so it was not used.")
    );
    assert_eq!(
        backup_rollback_problem(Some(-1), 0).as_deref(),
        Some("This backup's counter is not valid.")
    );
    assert!(backup_rollback_problem(Some(1 << 53), 0).is_some());

    let bundle: Value = serde_json::from_str(s(bc, "bundleUtf8")).unwrap();
    assert_eq!(bundle["counter"], 3);
    assert_eq!(bundle["v"], 1);
    let upload: Value = serde_json::from_str(s(bc, "uploadJson")).unwrap();
    assert_eq!(upload["counter"], 3);

    // The seal is unchanged: HKDF-SHA256 (salt, PRF output) to an
    // AES-128-GCM key, the user id in the authenticated data.
    let cs = mls_rs_crypto_rustcrypto::RustCryptoProvider::with_enabled_cipher_suites(vec![
        CIPHER_SUITE,
    ])
    .cipher_suite_provider(CIPHER_SUITE)
    .unwrap();
    let prk = cs
        .kdf_extract(&h(bc, "saltHex"), &h(bc, "prfOutputHex"))
        .unwrap();
    let key = cs
        .kdf_expand(&prk, b"hubs private dms backup v1", 16)
        .unwrap();
    assert_eq!(key.to_vec(), h(bc, "keyHex"));
    let sealed = cs
        .aead_seal(
            &key,
            s(bc, "bundleUtf8").as_bytes(),
            Some(s(bc, "aadUtf8").as_bytes()),
            &h(bc, "nonceHex"),
        )
        .unwrap();
    assert_eq!(sealed, h(bc, "ciphertextAndTagHex"));
    assert_eq!(
        b64_bytes(upload["ciphertext"].as_str().unwrap()),
        h(bc, "ciphertextAndTagHex")
    );
}

/// The missing message rule, step by step, as the web's tables say.
#[test]
fn missing_message_rule_matches_the_web() {
    let v = vectors();
    let mm = &v["hubs"]["missingMessages"];
    assert_eq!(missing_message_grace_ms(), mm["graceMs"].as_u64().unwrap());
    for case in mm["cases"].as_array().unwrap() {
        let name = s(case, "name");
        let mut track = GenerationTrack {
            user_id: "u_alice".into(),
            next: 0,
            gaps: Vec::new(),
            told: Vec::new(),
        };
        let mut notices: Vec<String> = Vec::new();
        for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            if let Some(generation) = step["arrive"].as_u64() {
                let at = step["at"].as_i64().unwrap();
                let arrival = track_generation(track, generation as u32, at, at);
                assert_eq!(
                    arrival.settled.is_some(),
                    step["settles"].as_bool().unwrap(),
                    "{name}, step {index}"
                );
                if let Some(settled) = &arrival.settled {
                    assert!(
                        notices.contains(settled),
                        "{name}: settles a notice it told"
                    );
                }
                track = arrival.track;
            } else {
                let notice = format!("notice-{index}");
                let due = due_generations(track, step["tell"].as_i64().unwrap(), notice.clone());
                let missing: Vec<u64> = step["missing"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|g| g.as_u64().unwrap())
                    .collect();
                assert_eq!(
                    due.due
                        .iter()
                        .map(|g| g.generation as u64)
                        .collect::<Vec<_>>(),
                    missing,
                    "{name}, step {index}"
                );
                if !missing.is_empty() {
                    notices.push(notice);
                }
                track = due.track;
            }
        }
    }
}

/// A last-resort key package opens more than one welcome: Bob joins both
/// conversations with the same private half and reaches the listed members.
#[test]
fn a_last_resort_key_package_opens_two_welcomes() {
    let v = vectors();
    let lr = &v["mls"]["lastResort"];
    let k = &lr["keyPackage"];
    check_key_package(h(k, "mlsMessageHex"), now(&v)).expect("the adder's checks");
    let bob = MlsDevice::new(device_keys(&v["hubs"]["devices"]["bob"])).unwrap();
    let package = import_key_package(
        s(k, "id").into(),
        h(k, "mlsMessageHex"),
        h(k, "initPrivateKeyHex"),
        h(k, "encryptionPrivateKeyHex"),
        now(&v),
    )
    .unwrap();
    let mut joined = Vec::new();
    for w in lr["welcomes"].as_array().unwrap() {
        let group = bob
            .join_from_welcome(
                h(w, "welcomeHex"),
                package.clone(),
                s(w, "conversationId").into(),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", s(w, "conversationId")));
        assert_eq!(group.conversation_id(), s(w, "conversationId"));
        assert_eq!(group.epoch(), w["epochAfter"].as_u64().unwrap());
        assert_eq!(members_of(&group), expected_members(w));
        joined.push(group);
    }
    assert_eq!(joined.len(), 2);
    // Each welcome opens only as its own conversation.
    let first = &lr["welcomes"][0];
    assert_eq!(
        bob.join_from_welcome(
            h(first, "welcomeHex"),
            package,
            s(&lr["welcomes"][1], "conversationId").into(),
        )
        .unwrap_err(),
        HubsMlsError::WrongConversation
    );
}

/// Each application message's epoch, sender leaf and generation, read from
/// its sender data before (or without) opening the content.
#[test]
fn generations_read_from_the_sender_data() {
    let v = vectors();
    let g = &v["mls"]["generations"];
    let k = &g["keyPackage"];
    let bob = MlsDevice::new(device_keys(&v["hubs"]["devices"]["bob"])).unwrap();
    let package = import_key_package(
        s(k, "id").into(),
        h(k, "mlsMessageHex"),
        h(k, "initPrivateKeyHex"),
        h(k, "encryptionPrivateKeyHex"),
        now(&v),
    )
    .unwrap();
    let group = bob
        .join_from_welcome(h(g, "welcomeHex"), package, s(g, "conversationId").into())
        .unwrap();
    let messages = g["messages"].as_array().unwrap();
    let expected = |m: &Value| MessageHeader {
        epoch: m["epoch"].as_u64().unwrap(),
        sender_leaf_index: m["senderLeafIndex"].as_u64().unwrap() as u32,
        generation: m["generation"].as_u64().unwrap() as u32,
    };
    // Every header first, without opening anything; reading changes nothing.
    let before = group.snapshot().unwrap();
    for m in messages {
        assert_eq!(
            group.message_header(h(m, "mlsMessageHex")),
            Some(expected(m))
        );
    }
    assert_eq!(group.snapshot().unwrap(), before);
    // The last one cut at the end: its sender data still reads, its content
    // does not open.
    let mut cut = h(&messages[2], "mlsMessageHex");
    let last = cut.len() - 1;
    cut[last] ^= 1;
    assert_eq!(
        group.message_header(cut.clone()),
        Some(expected(&messages[2]))
    );
    assert!(group.receive(cut).is_err());
    // Out of order, then the headers still read after opening.
    for index in [2, 0, 1] {
        let m = &messages[index];
        let Incoming::Message { sender, epoch, .. } = group.receive(h(m, "mlsMessageHex")).unwrap()
        else {
            panic!("message {index}")
        };
        assert_eq!(sender.leaf_index, expected(m).sender_leaf_index);
        assert_eq!(epoch, expected(m).epoch);
        assert_eq!(
            group.message_header(h(m, "mlsMessageHex")),
            Some(expected(m))
        );
    }
}

/// The call connection statement B for a binding (protocol 3).
fn binding_body(
    channel_id: &str,
    lease_id: &str,
    user_id: &str,
    device_id: &str,
    identity_public_key: &[u8],
    device_public_key: &[u8],
    connection_public_key: &[u8],
) -> Vec<u8> {
    let mut out = b"hubs-call-binding-v3\0".to_vec();
    for text in [channel_id, lease_id, user_id, device_id] {
        out.extend_from_slice(&(text.len() as u16).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out.extend_from_slice(identity_public_key);
    out.extend_from_slice(device_public_key);
    out.extend_from_slice(connection_public_key);
    out
}

/// What a call binding needs to pass: the device key signed B and the
/// identity key certified the device key.
fn binding_verifies(statement: &[u8], user_id: &str, json: &Value) -> bool {
    let identity = b64_bytes(s(json, "identityPublicKey"));
    let device = b64_bytes(s(json, "devicePublicKey"));
    verify_ed25519(
        device.clone(),
        statement.to_vec(),
        b64_bytes(s(json, "signature")),
    ) && verify_ed25519(
        identity,
        device_certificate_body(user_id.into(), s(json, "deviceId").into(), device),
        b64_bytes(s(json, "certificate")),
    )
}

/// The calls section: every binding signature and certificate verifies
/// strictly, every refused binding fails, and the roster statement verifies.
#[test]
fn call_bindings_verify_strictly() {
    let v = vectors();
    let c = &v["calls"];
    for (name, b) in c["bindings"].as_object().unwrap() {
        let certificate_body = device_certificate_body(
            s(b, "userId").into(),
            s(b, "deviceId").into(),
            h(b, "devicePublicKeyHex"),
        );
        assert_eq!(certificate_body, h(b, "certificateBodyHex"), "{name}");
        assert_eq!(
            sign_ed25519(h(b, "identitySeedHex"), certificate_body.clone()).unwrap(),
            h(b, "certificateHex"),
            "{name}"
        );
        let body = binding_body(
            s(b, "channelId"),
            s(b, "leaseId"),
            s(b, "userId"),
            s(b, "deviceId"),
            &h(b, "identityPublicKeyHex"),
            &h(b, "devicePublicKeyHex"),
            &h(b, "connectionPublicKeyHex"),
        );
        assert_eq!(body, h(b, "bindingBodyHex"), "{name}");
        assert_eq!(
            sign_ed25519(h(b, "deviceSeedHex"), body.clone()).unwrap(),
            h(b, "signatureHex"),
            "{name}"
        );
        assert!(verify_ed25519(
            h(b, "devicePublicKeyHex"),
            body.clone(),
            h(b, "signatureHex")
        ));
        assert!(verify_ed25519(
            h(b, "identityPublicKeyHex"),
            certificate_body,
            h(b, "certificateHex")
        ));
        // The identity key did not sign B; one changed byte fails.
        assert!(!verify_ed25519(
            h(b, "identityPublicKeyHex"),
            body.clone(),
            h(b, "signatureHex")
        ));
        let mut changed = body.clone();
        changed[30] ^= 1;
        assert!(!verify_ed25519(
            h(b, "devicePublicKeyHex"),
            changed,
            h(b, "signatureHex")
        ));
        // The wire form carries the same bytes.
        let json = &b["json"];
        assert_eq!(b64_bytes(s(json, "signature")), h(b, "signatureHex"));
        assert_eq!(b64_bytes(s(json, "certificate")), h(b, "certificateHex"));
        assert!(binding_verifies(&body, s(b, "userId"), json), "{name}");
    }

    for case in c["refusedBindings"].as_array().unwrap() {
        let name = s(case, "name");
        let json = &case["json"];
        let statement = h(case, "statementHex");
        let identity = b64_bytes(s(json, "identityPublicKey"));
        let device = b64_bytes(s(json, "devicePublicKey"));
        if identity.len() == 32 && device.len() == 32 {
            // Exact sizes: the statement is B, built from what the viewer knows.
            assert_eq!(
                binding_body(
                    s(case, "channelId"),
                    s(case, "leaseId"),
                    s(case, "userId"),
                    s(json, "deviceId"),
                    &identity,
                    &device,
                    &h(case, "connectionPublicKeyHex"),
                ),
                statement,
                "{name}"
            );
        }
        assert_eq!(
            binding_verifies(&statement, s(case, "userId"), json),
            case["valid"].as_bool().unwrap(),
            "{name}"
        );
    }

    let view = &c["view"];
    let alice = &c["bindings"]["alice"];
    assert_eq!(
        h(view, "devicePublicKeyHex"),
        h(alice, "devicePublicKeyHex")
    );
    assert_eq!(
        sign_ed25519(h(alice, "deviceSeedHex"), h(view, "bodyHex")).unwrap(),
        h(view, "signatureHex")
    );
    assert!(verify_ed25519(
        h(view, "devicePublicKeyHex"),
        h(view, "bodyHex"),
        h(view, "signatureHex")
    ));
}

/// Strict Ed25519: no small-order keys, no non-canonical signatures, and
/// wrong sizes are a plain `false`.
#[test]
fn ed25519_verification_is_strict() {
    let v = vectors();
    let p = &v["primitives"]["ed25519"];
    let message = s(p, "messageUtf8").as_bytes().to_vec();
    let key = h(p, "publicKeyHex");
    let signature = h(p, "signatureHex");
    assert!(verify_ed25519(
        key.clone(),
        message.clone(),
        signature.clone()
    ));
    // S + L, the same signature in a non-canonical form.
    let order: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut high = signature.clone();
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = high[32 + i] as u16 + order[i] as u16 + carry;
        high[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert!(!verify_ed25519(key.clone(), message.clone(), high));
    // The identity point as a key, with R the identity and S zero: a
    // signature on any message for a lax verifier.
    let mut weak_key = vec![0u8; 32];
    weak_key[0] = 1;
    let mut weak_signature = vec![0u8; 64];
    weak_signature[0] = 1;
    assert!(!verify_ed25519(weak_key, message.clone(), weak_signature));
    assert!(!verify_ed25519(
        key[..31].to_vec(),
        message.clone(),
        signature.clone()
    ));
    assert!(!verify_ed25519(
        key.clone(),
        message.clone(),
        signature[..63].to_vec()
    ));
    assert!(!verify_ed25519(Vec::new(), Vec::new(), Vec::new()));
    let mut other = message;
    other.push(b'!');
    assert!(!verify_ed25519(key, other, signature));
}
