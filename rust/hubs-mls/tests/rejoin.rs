//! A device removed from a conversation and added back (RF-1 in docs/reviews.md):
//! what the store it keeps across the rejoin must and must not carry.
use hubs_mls::*;
use std::sync::Arc;

const NOW: u64 = 1_780_000_000;

fn dev(user: &str, device: &str) -> Arc<MlsDevice> {
    let identity = create_identity().unwrap();
    MlsDevice::new(create_device(identity, user.into(), device.into()).unwrap()).unwrap()
}

fn kp(d: &MlsDevice) -> DeviceKeyPackage {
    d.create_key_packages(1, NOW).unwrap().pop().unwrap()
}

/// Add `b` to `a`'s group; returns b's group.
fn add(a: &MlsGroup, b: &MlsDevice, conv: &str) -> Arc<MlsGroup> {
    let package = kp(b);
    let change = a
        .change_devices(vec![package.public_package.clone()], vec![], NOW, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    b.join_from_welcome(change.welcome.unwrap(), package, conv.into())
        .unwrap()
}

/// One key update from `a`, received by `b`, and b's state saved, as every app does.
fn refresh(a: &MlsGroup, b: &MlsGroup) -> Result<Incoming, HubsMlsError> {
    let change = a.change_devices(vec![], vec![], NOW, None).unwrap();
    a.merge_pending_commit().unwrap();
    let got = b.receive(change.commit);
    if got.is_ok() {
        b.snapshot().unwrap();
    }
    got
}

fn remove_and_rejoin(
    ref_a: &MlsGroup,
    bob: &MlsDevice,
    old: &MlsGroup,
    conv: &str,
) -> Arc<MlsGroup> {
    let leaf = old.own_leaf_index();
    let change = ref_a.change_devices(vec![], vec![leaf], NOW, None).unwrap();
    ref_a.merge_pending_commit().unwrap();
    assert!(matches!(
        old.receive(change.commit).unwrap(),
        Incoming::Removed { .. }
    ));
    // The app stores no group and lets the next welcome through, as every
    // Hubs app does for a device removed by a commit.
    let fresh = add(ref_a, bob, conv);
    fresh.snapshot().unwrap();
    fresh
}

/// Removed, then added back on the same running device. The next commit
/// must open.
#[test]
fn a_device_added_back_can_follow_the_next_commit() {
    let alice = dev("u_alice", "d_alice");
    let bob = dev("u_bob", "d_bob");
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let b = add(&a, &bob, "c1");
    b.snapshot().unwrap();
    for _ in 0..3 {
        refresh(&a, &b).unwrap();
    }
    let b2 = remove_and_rejoin(&a, &bob, &b, "c1");
    drop(b);
    let got = refresh(&a, &b2);
    assert!(
        got.is_ok(),
        "the commit after the rejoin was refused: {got:?}"
    );
}

/// The same, with the app restarted between the rejoin and the commit: the
/// snapshot it saved must not carry the problem with it.
#[test]
fn a_restart_does_not_keep_a_rejoined_device_stuck() {
    let alice = dev("u_alice", "d_alice");
    let keys = {
        let identity = create_identity().unwrap();
        create_device(identity, "u_bob".into(), "d_bob".into()).unwrap()
    };
    let bob = MlsDevice::new(keys.clone()).unwrap();
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let b = add(&a, &bob, "c1");
    b.snapshot().unwrap();
    for _ in 0..3 {
        refresh(&a, &b).unwrap();
    }
    let b2 = remove_and_rejoin(&a, &bob, &b, "c1");
    let saved = b2.snapshot().unwrap();
    drop(b);
    drop(b2);
    drop(bob);
    // A new process: a new MlsDevice, the saved snapshot.
    let restarted = MlsDevice::new(keys).unwrap();
    let b3 = restarted.load_group(saved).unwrap();
    let got = refresh(&a, &b3);
    assert!(
        got.is_ok(),
        "after a restart the commit is still refused: {got:?}"
    );
}

/// The rejoined device's own commit: the server has accepted it by the time
/// the merge runs, so a refusal here leaves this device behind its own commit.
#[test]
fn a_rejoined_device_can_merge_its_own_commit() {
    let alice = dev("u_alice", "d_alice");
    let bob = dev("u_bob", "d_bob");
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let b = add(&a, &bob, "c1");
    b.snapshot().unwrap();
    for _ in 0..3 {
        refresh(&a, &b).unwrap();
    }
    let b2 = remove_and_rejoin(&a, &bob, &b, "c1");
    let epoch = b2.epoch();
    let change = b2.change_devices(vec![], vec![], NOW, None).unwrap();
    // The server accepts the commit here.
    let merged = b2.merge_pending_commit();
    assert!(
        merged.is_ok(),
        "the merge after the server's yes failed: {merged:?}"
    );
    assert_eq!(b2.epoch(), epoch + 1);
    let _ = change;
}

/// The stale records also keep old secrets: nothing ages them out.
#[test]
fn a_new_group_starts_with_no_old_epochs_in_its_snapshot() {
    let alice = dev("u_alice", "d_alice");
    let bob = dev("u_bob", "d_bob");
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let b = add(&a, &bob, "c1");
    let first = b.snapshot().unwrap();
    for _ in 0..3 {
        refresh(&a, &b).unwrap();
    }
    let before_rejoin = b.snapshot().unwrap();
    assert!(
        before_rejoin.len() > first.len(),
        "the old group kept past epochs"
    );
    let b2 = remove_and_rejoin(&a, &bob, &b, "c1");
    // Read the epoch count from the snapshot format (storage.rs).
    let snapshot = b2.snapshot().unwrap();
    let mut at = 5usize;
    let take = |at: &mut usize| {
        let n = u32::from_be_bytes(snapshot[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4 + n;
    };
    take(&mut at); // group id
    take(&mut at); // state
    let count = u32::from_be_bytes(snapshot[at..at + 4].try_into().unwrap());
    assert_eq!(
        count, 0,
        "a group just joined carries {count} epochs of the group before it"
    );
}

/// A device that already rejoined under the old code has the old epochs in
/// the snapshot it saved. Loading it must heal it.
#[test]
fn a_snapshot_saved_with_old_epochs_heals_on_load() {
    let alice = dev("u_alice", "d_alice");
    let keys = create_device(create_identity().unwrap(), "u_bob".into(), "d_bob".into()).unwrap();
    let bob = MlsDevice::new(keys.clone()).unwrap();
    let a = alice.start_group("c1".into(), NOW).unwrap();
    let b = add(&a, &bob, "c1");
    b.snapshot().unwrap();
    for _ in 0..3 {
        refresh(&a, &b).unwrap();
    }
    let old = b.snapshot().unwrap();
    let b2 = remove_and_rejoin(&a, &bob, &b, "c1");
    let new = b2.snapshot().unwrap();
    // Build what the unfixed core saved: the new state with the old epochs.
    let split = |s: &[u8]| {
        let mut at = 5usize;
        let skip = |at: &mut usize| {
            let n = u32::from_be_bytes(s[*at..*at + 4].try_into().unwrap()) as usize;
            *at += 4 + n;
        };
        skip(&mut at);
        skip(&mut at);
        at
    };
    let mut poisoned = new[..split(&new)].to_vec();
    poisoned.extend_from_slice(&old[split(&old)..]);
    let restarted = MlsDevice::new(keys).unwrap();
    let b3 = restarted.load_group(poisoned).unwrap();
    let got = refresh(&a, &b3);
    assert!(got.is_ok(), "the saved snapshot stayed stuck: {got:?}");
}
