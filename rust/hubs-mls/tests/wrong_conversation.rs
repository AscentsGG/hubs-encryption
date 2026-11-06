//! RF-3 in docs/reviews.md.
//! A welcome refused for naming another conversation must leave that
//! other conversation alone.
use hubs_mls::*;
const NOW: u64 = 1_780_000_000;
fn dev(user: &str, device: &str) -> std::sync::Arc<MlsDevice> {
    MlsDevice::new(create_device(create_identity().unwrap(), user.into(), device.into()).unwrap())
        .unwrap()
}
#[test]
fn a_refused_welcome_leaves_the_other_conversation_alone() {
    let alice = dev("u_alice", "d_alice");
    let bob = dev("u_bob", "d_bob");
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let package = bob.create_key_packages(1, NOW).unwrap().pop().unwrap();
    let change = a
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    let b = bob
        .join_from_welcome(change.welcome.unwrap(), package, "c1".into())
        .unwrap();
    b.snapshot().unwrap();

    // A message at this epoch, delivered late, after a commit moves on.
    let late = a
        .encrypt_message(MessageDraft {
            id: "late".into(),
            kind: "text".into(),
            body: "hi".into(),
            sent_at: 1,
            expires_in_seconds: 0,
        })
        .unwrap();
    let update = a.change_devices(vec![], vec![], NOW, None).unwrap();
    a.merge_pending_commit().unwrap();
    b.receive(update.commit).unwrap();
    b.snapshot().unwrap();

    // Anyone with a key package of Bob's: a group under the same id,
    // delivered as a welcome for another conversation.
    let mallory = dev("u_mallory", "d_mallory");
    let m = mallory.start_group("c1".into(), NOW).unwrap();
    let package = bob.create_key_packages(1, NOW).unwrap().pop().unwrap();
    let forged = m
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    m.merge_pending_commit().unwrap();
    let refused = bob.join_from_welcome(forged.welcome.unwrap(), package, "c2".into());
    assert!(matches!(refused, Err(HubsMlsError::WrongConversation)));

    // The late message still opens from the retained epoch.
    let got = b.receive(late.ciphertext);
    assert!(got.is_ok(), "the late message no longer opens: {got:?}");
}
