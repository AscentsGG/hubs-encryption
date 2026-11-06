//! Retained epochs: the core opens late messages from past epochs exactly
//! as the TypeScript implementation does.
use hubs_mls::*;
use std::sync::Arc;
const NOW: u64 = 1_760_000_000;
fn device(user: &str, id: &str) -> Arc<MlsDevice> {
    MlsDevice::new(create_device(create_identity().unwrap(), user.into(), id.into()).unwrap())
        .unwrap()
}
/// A message from each of the 6 epochs before the current one, delivered
/// after the commits, in order: which open? The same as on the website.
#[test]
fn past_epochs_open_like_the_web() {
    let alice = device("u_alice", "device_alice_1");
    let bob = device("u_bob", "device_bob_1");
    let a = alice.start_group("c".into(), NOW).unwrap();
    let package = bob.create_key_packages(1, NOW).unwrap().remove(0);
    let change = a
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    let b = bob
        .join_from_welcome(change.welcome.unwrap(), package, "c".into())
        .unwrap();
    let mut held = vec![];
    for i in 0..6 {
        held.push(
            a.encrypt_message(MessageDraft {
                id: format!("m{i}"),
                kind: "text".into(),
                body: "x".into(),
                sent_at: 1,
                expires_in_seconds: 0,
            })
            .unwrap()
            .ciphertext,
        );
        let update = a.change_devices(vec![], vec![], NOW, None).unwrap();
        a.merge_pending_commit().unwrap();
        b.receive(update.commit).unwrap();
        b.snapshot().unwrap();
    }
    let opened: Vec<bool> = held.into_iter().map(|m| b.receive(m).is_ok()).collect();
    println!("rust epochs back 6..1: {opened:?}");
    assert_eq!(opened, [false, false, true, true, true, true]);
}
