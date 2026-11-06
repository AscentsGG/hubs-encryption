//! A message delivered late, one gap in an otherwise steady stream (RF-2 in
//! docs/reviews.md). The website keeps the 10 newest skipped keys by count,
//! and this core must open what the website opens, in the same order.
use hubs_mls::*;
use std::sync::Arc;
const NOW: u64 = 1_760_000_000;
const CONVERSATION: &str = "3e9c1b7a-2d4f-4c6e-8a1b-5f7d9e0c2a4b";
fn device(user: &str, id: &str) -> Arc<MlsDevice> {
    MlsDevice::new(create_device(create_identity().unwrap(), user.into(), id.into()).unwrap())
        .unwrap()
}
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
#[test]
fn one_late_message_opens_after_a_steady_stream() {
    let (a, b) = pair();
    let messages = sealed(&a, 30);
    for index in (0..5).chain(6..30) {
        b.receive(messages[index].clone()).unwrap();
    }
    let late = b.receive(messages[5].clone());
    assert!(
        late.is_ok(),
        "generation 5 after 24 later messages: {late:?}"
    );
}
