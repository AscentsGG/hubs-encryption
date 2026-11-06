//! The core refuses a standalone proposal. A private message whose content
//! type says proposal (2) fails at decode, and the group is left as it was.
use hubs_mls::*;
const NOW: u64 = 1_780_000_000;
#[test]
fn a_standalone_proposal_is_refused_at_decode() {
    let dev = |u: &str, d: &str| {
        MlsDevice::new(create_device(create_identity().unwrap(), u.into(), d.into()).unwrap())
            .unwrap()
    };
    let (alice, bob) = (dev("u_a", "d_a"), dev("u_b", "d_b"));
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let package = bob.create_key_packages(1, NOW).unwrap().remove(0);
    let change = a
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    let b = bob
        .join_from_welcome(change.welcome.unwrap(), package, "c1".into())
        .unwrap();
    let mut message = a
        .encrypt_message(MessageDraft {
            id: "m".into(),
            kind: "text".into(),
            body: "x".into(),
            sent_at: 1,
            expires_in_seconds: 0,
        })
        .unwrap()
        .ciphertext;
    // version, wire format, group id (a one-byte length and "c1"), epoch.
    let at = 4 + 1 + 2 + 8;
    assert_eq!(message[at], 1, "the content type byte");
    let before = b.epoch_authenticator().unwrap();
    message[at] = 2;
    let refused = b.receive(message);
    assert!(
        matches!(refused, Err(HubsMlsError::Mls { .. })),
        "{refused:?}"
    );
    assert_eq!(b.epoch_authenticator().unwrap(), before);
}
