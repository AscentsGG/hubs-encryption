//! A receiver keeps skipped message keys within the ts-mls default limits:
//! a message at most 200 generations ahead, and only the keys of the 10
//! newest skipped generations. mls-rs 0.56.0 allows 1024 ahead and keeps
//! every skipped key until the epoch is dropped; the copy in
//! `vendor/mls-rs` applies the lower limits (see its CHANGES.md).

use hubs_mls::*;
use std::sync::Arc;

const NOW: u64 = 1_760_000_000;
const CONVERSATION: &str = "3e9c1b7a-2d4f-4c6e-8a1b-5f7d9e0c2a4b";

fn device(user: &str, id: &str) -> Arc<MlsDevice> {
    MlsDevice::new(create_device(create_identity().unwrap(), user.into(), id.into()).unwrap())
        .unwrap()
}

/// Alice's group with Bob's device in it, from both sides.
fn pair() -> (Arc<MlsGroup>, Arc<MlsGroup>) {
    let alice = device("u_alice", "device_alice_1");
    let bob = device("u_bob", "device_bob_1");
    let a = alice.start_group(CONVERSATION.into(), NOW).unwrap();
    let package = bob.create_key_packages(1, NOW).unwrap().remove(0);
    let change = a
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    let b = bob
        .join_from_welcome(change.welcome.unwrap(), package, CONVERSATION.into())
        .unwrap();
    (a, b)
}

/// Generations 0 to `count - 1` from Alice's device.
fn sealed(a: &MlsGroup, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            a.encrypt_message(MessageDraft {
                id: format!("m_{index}"),
                kind: "text".into(),
                body: format!("number {index}"),
                sent_at: 1_760_000_000_000 + index as i64,
                expires_in_seconds: 86_400,
            })
            .unwrap()
            .ciphertext
        })
        .collect()
}

fn body(incoming: Incoming) -> String {
    match incoming {
        Incoming::Message { payload, .. } => payload.body,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_message_more_than_200_generations_ahead_is_refused() {
    let (a, b) = pair();
    let messages = sealed(&a, 202);
    assert!(b.receive(messages[201].clone()).is_err(), "201 ahead");
    // The refusal changed nothing: 200 ahead still opens.
    assert_eq!(
        body(b.receive(messages[200].clone()).unwrap()),
        "number 200"
    );
}

#[test]
fn only_the_10_newest_skipped_generations_are_kept() {
    let (a, b) = pair();
    let messages = sealed(&a, 12);
    assert_eq!(body(b.receive(messages[11].clone()).unwrap()), "number 11");
    // 11 generations back: its key is gone.
    assert!(b.receive(messages[0].clone()).is_err(), "11 back");
    // 10 back: kept, once.
    assert_eq!(body(b.receive(messages[1].clone()).unwrap()), "number 1");
    assert!(
        b.receive(messages[1].clone()).is_err(),
        "a key is used once"
    );
    assert_eq!(body(b.receive(messages[10].clone()).unwrap()), "number 10");
}

#[test]
fn a_long_jump_keeps_only_the_newest_skipped_keys_in_the_snapshot() {
    let (a, b) = pair();
    let messages = sealed(&a, 201);
    let before = b.snapshot().unwrap().len();
    assert_eq!(
        body(b.receive(messages[200].clone()).unwrap()),
        "number 200"
    );
    let after = b.snapshot().unwrap().len();
    // Ten skipped keys (a nonce, a key and a generation each), not 200.
    assert!(after < before + 10 * 64, "{before} then {after}");
    assert!(b.receive(messages[189].clone()).is_err(), "11 back");
    assert_eq!(
        body(b.receive(messages[190].clone()).unwrap()),
        "number 190"
    );
}
