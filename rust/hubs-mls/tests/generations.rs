//! Message headers (epoch, sender leaf, generation) between two native
//! devices: what `MlsGroup::message_header` reads in the current and earlier
//! epochs, what it leaves alone, and a last-resort key package that opens
//! two welcomes made here.

use std::sync::Arc;

use hubs_mls::*;

const NOW: u64 = 1_760_000_000;

fn device(user_id: &str) -> Arc<MlsDevice> {
    let identity = create_identity().unwrap();
    MlsDevice::new(create_device(identity, user_id.into(), new_device_id().unwrap()).unwrap())
        .unwrap()
}

fn draft(id: &str) -> MessageDraft {
    MessageDraft {
        id: id.into(),
        kind: "text".into(),
        body: format!("Message {id}."),
        sent_at: 1_760_000_000_000,
        expires_in_seconds: 604800,
    }
}

/// Alice starts a conversation and adds Bob with one of his key packages.
fn pair(conversation_id: &str) -> (Arc<MlsGroup>, Arc<MlsGroup>) {
    let alice = device("u_alice");
    let bob = device("u_bob");
    let package = bob.create_key_packages(1, NOW).unwrap().remove(0);
    let group = alice.start_group(conversation_id.into(), NOW).unwrap();
    let change = group
        .change_devices(vec![package.public_package.clone()], Vec::new(), NOW, None)
        .unwrap();
    group.merge_pending_commit().unwrap();
    let joined = bob
        .join_from_welcome(change.welcome.unwrap(), package, conversation_id.into())
        .unwrap();
    (group, joined)
}

#[test]
fn headers_count_each_sender_per_epoch() {
    let (alice, bob) = pair("c-headers");
    let a0 = alice.encrypt_message(draft("a0")).unwrap();
    let a1 = alice.encrypt_message(draft("a1")).unwrap();
    let b0 = bob.encrypt_message(draft("b0")).unwrap();
    let header = |group: &MlsGroup, message: &EncryptedMessage| {
        group.message_header(message.ciphertext.clone()).unwrap()
    };
    assert_eq!(
        header(&bob, &a0),
        MessageHeader {
            epoch: 1,
            sender_leaf_index: 0,
            generation: 0
        }
    );
    assert_eq!(header(&bob, &a1).generation, 1);
    // Each sender counts from 0, and a device reads its own messages too.
    assert_eq!(
        header(&alice, &b0),
        MessageHeader {
            epoch: 1,
            sender_leaf_index: 1,
            generation: 0
        }
    );
    assert_eq!(header(&alice, &a1).generation, 1);

    // A commit moves on to epoch 2: its own header is none (not an
    // application message), and epoch 1's messages still read.
    let update = bob
        .change_devices(Vec::new(), Vec::new(), NOW, None)
        .unwrap();
    assert_eq!(alice.message_header(update.commit.clone()), None);
    bob.merge_pending_commit().unwrap();
    assert!(matches!(
        alice.receive(update.commit).unwrap(),
        Incoming::Change { epoch: 2, .. }
    ));
    assert_eq!(header(&bob, &a1).epoch, 1);
    assert_eq!(header(&bob, &a1).generation, 1);
    let a2 = alice.encrypt_message(draft("a2")).unwrap();
    assert_eq!(
        header(&bob, &a2),
        MessageHeader {
            epoch: 2,
            sender_leaf_index: 0,
            generation: 0
        }
    );
    // The late one from epoch 1 opens, and so does the new one.
    assert!(matches!(
        bob.receive(a1.ciphertext.clone()).unwrap(),
        Incoming::Message { epoch: 2, .. }
    ));
    assert!(bob.receive(a2.ciphertext).is_ok());
}

#[test]
fn headers_of_other_groups_and_other_bytes_are_none() {
    let (alice, bob) = pair("c-one");
    let (other, _) = pair("c-two");
    let foreign = other.encrypt_message(draft("x0")).unwrap();
    assert_eq!(bob.message_header(foreign.ciphertext), None);
    assert_eq!(bob.message_header(Vec::new()), None);
    assert_eq!(bob.message_header(vec![0, 1, 0, 2, 0xff]), None);
    // A key package is not a private message.
    let package = device("u_carol").create_key_packages(1, NOW).unwrap();
    assert_eq!(bob.message_header(package[0].public_package.clone()), None);
    // An epoch this device has not reached: Alice moved on, Bob has not
    // processed her commit yet.
    let update = alice
        .change_devices(Vec::new(), Vec::new(), NOW, None)
        .unwrap();
    alice.merge_pending_commit().unwrap();
    let ahead = alice.encrypt_message(draft("a0")).unwrap();
    assert_eq!(bob.message_header(ahead.ciphertext.clone()), None);
    // Once it has, the header reads.
    bob.receive(update.commit).unwrap();
    assert_eq!(
        bob.message_header(ahead.ciphertext),
        Some(MessageHeader {
            epoch: 2,
            sender_leaf_index: 0,
            generation: 0
        })
    );
}

#[test]
fn a_last_resort_key_package_made_here_opens_two_welcomes() {
    let alice = device("u_alice");
    let bob = device("u_bob");
    let last_resort = bob.create_key_packages(1, NOW).unwrap().remove(0);
    let mut groups = Vec::new();
    for conversation_id in ["c-first", "c-second"] {
        let group = alice.start_group(conversation_id.into(), NOW).unwrap();
        let change = group
            .change_devices(
                vec![last_resort.public_package.clone()],
                Vec::new(),
                NOW,
                None,
            )
            .unwrap();
        group.merge_pending_commit().unwrap();
        let joined = bob
            .join_from_welcome(
                change.welcome.unwrap(),
                last_resort.clone(),
                conversation_id.into(),
            )
            .unwrap();
        groups.push((group, joined));
    }
    // Both conversations work, each with its own keys.
    for (index, (group, joined)) in groups.iter().enumerate() {
        let sent = group.encrypt_message(draft(&format!("m{index}"))).unwrap();
        let Incoming::Message { payload, .. } = joined.receive(sent.ciphertext.clone()).unwrap()
        else {
            panic!("a message")
        };
        assert_eq!(payload.body, format!("Message m{index}."));
        let (_, other) = &groups[1 - index];
        assert!(other.receive(sent.ciphertext).is_err());
    }
}
